"""Bounded, atomic capacity admission for every runtime queue producer.

Entry caps are admission limits, not a promise about Redis memory. Redis Lua
does not roll back writes on a later OOM/error; callers retain unconfirmed work.
"""

from __future__ import annotations

from collections.abc import Mapping

from shadai.utils.operations import SOURCES

GROUP_STREAMS = {"ingest_group": tuple("events:" + source for source in SOURCES),
                 "correlate_group": ("matches",)}
STREAMS = (*GROUP_STREAMS["ingest_group"], "matches")
SCHEMA_KEY = "retention:schema"

# Kept in one place for admission, replay, ACK and retention scripts. ID
# comparison never converts the decimal timestamp/sequence to a Lua double.
QUEUE_LUA = """
local allowed = {['matches']='correlate_group'}
for _, s in ipairs({'dns','proxy','endpoint','browser','oauth','directory','instrumented','casb','network'}) do
    allowed['events:' .. s] = 'ingest_group'
end
local function kind(key)
    return redis.call('TYPE', key).ok
end
local function type_ok(key, expected)
    local t = kind(key)
    return t == 'none' or t == expected
end
local function uint(value, maximum)
    return value and (value == '0' or string.match(value, '^[1-9]%d*$')) and #value <= 15 and
           tonumber(value) <= maximum
end
local function id_valid(id)
    local ms, seq = string.match(id or '', '^(%d+)%-(%d+)$')
    return ms and #ms <= 20 and #seq <= 20
end
local function decimal_cmp(a, b)
    a = string.gsub(a, '^0+', ''); b = string.gsub(b, '^0+', '')
    if a == '' then a = '0' end; if b == '' then b = '0' end
    if #a ~= #b then return #a < #b and -1 or 1 end
    if a == b then return 0 end
    return a < b and -1 or 1
end
local function id_cmp(a, b)
    local am, as = string.match(a, '^(%d+)%-(%d+)$')
    local bm, bs = string.match(b, '^(%d+)%-(%d+)$')
    local c = decimal_cmp(am, bm)
    return c ~= 0 and c or decimal_cmp(as, bs)
end
local function same_fields(a, b)
    if #a ~= #b then return false end
    for i=1,#a do if a[i] ~= b[i] then return false end end
    return true
end
local function pointer_target(fields)
    if #fields % 2 ~= 0 or #fields > 64 then return nil end
    local seen, stream, id = {}, nil, nil
    for i=1,#fields,2 do
        if seen[fields[i]] then return nil end
        seen[fields[i]] = true
        if fields[i] == 'stream' then stream = fields[i+1] end
        if fields[i] == 'message_id' then id = fields[i+1] end
    end
    if not allowed[stream] or not id_valid(id) then return nil end
    return stream, id
end
"""

QUEUE_ADMIT = QUEUE_LUA + """
local count, cap, maxbytes = tonumber(ARGV[1]), tonumber(ARGV[2]), tonumber(ARGV[3])
if not count or count < 1 or count > 500 or count % 1 ~= 0 or
   not cap or cap < 1 or cap > 10000000 or cap % 1 ~= 0 or
   not maxbytes or maxbytes < 1 or maxbytes > 16777216 or maxbytes % 1 ~= 0 then return {'denied','bounds'} end
local destinations, totals = {}, {}
for i,key in ipairs(KEYS) do
    if not allowed[key] or destinations[key] or not type_ok(key, 'stream') then
        return {'denied','destination'}
    end
    destinations[key] = i; totals[i] = 0
end
local records, pos, size = {}, 4, 0
for i=1,count do
    local dest, pairs = tonumber(ARGV[pos]), tonumber(ARGV[pos+1]); pos = pos + 2
    if not dest or not KEYS[dest] or not pairs or pairs < 1 or pairs > 32 or pairs % 1 ~= 0 then
        return {'denied','fields'}
    end
    local fields, seen = {}, {}
    size = size + #KEYS[dest]
    for j=1,pairs do
        local f,v = ARGV[pos], ARGV[pos+1]; pos = pos + 2
        if not f or f == '' or not v or seen[f] then return {'denied','fields'} end
        seen[f] = true; size = size + #f + #v
        fields[#fields+1] = f; fields[#fields+1] = v
    end
    records[i] = {dest,fields}; totals[dest] = totals[dest] + 1
end
if pos ~= #ARGV + 1 or size > maxbytes then return {'denied','bytes'} end
for i,key in ipairs(KEYS) do
    if redis.call('XLEN', key) + totals[i] > cap then return {'denied','full'} end
end
-- First write is the first record allocation. No counters/deletes precede it.
local result = {'ok'}
for _,row in ipairs(records) do
    result[#result+1] = redis.call('XADD', KEYS[row[1]], '*', unpack(row[2]))
end
return result
"""


class QueueAdmissionError(RuntimeError):
    """Unconfirmed delivery, retryable; never expose a payload in the error."""


def queue_settings(settings=None):
    if settings is None:
        from shadai.config import get_config
        settings = get_config().redis_queue
    return settings


def record_size(record) -> int:
    return len(record["stream"].encode()) + sum(len(k.encode()) + len(v.encode())
                                              for k, v in record["fields"].items())


def admission_arguments(records, settings=None):
    settings = queue_settings(settings)
    if not 1 <= len(records) <= 500:
        raise QueueAdmissionError("Queue batch bounds")
    keys, args, size = [], [], 0
    for record in records:
        stream, fields = record.get("stream"), record.get("fields")
        if stream not in STREAMS or not isinstance(fields, Mapping) or not 1 <= len(fields) <= 32:
            raise QueueAdmissionError("Queue destination or fields")
        if any(not isinstance(k, str) or not k or not isinstance(v, str) for k, v in fields.items()):
            raise QueueAdmissionError("Queue field encoding")
        if stream not in keys:
            keys.append(stream)
        size += record_size(record)
        args.extend((str(keys.index(stream) + 1), str(len(fields))))
        for field, value in fields.items():
            args.extend((field, value))
    if size > settings.admission_max_batch_bytes:
        raise QueueAdmissionError("Queue batch bytes")
    return keys, [str(len(records)), str(settings.stream_max_entries),
                  str(settings.admission_max_batch_bytes), *args]


async def admit_records(redis, records, *, settings=None) -> list[str]:
    if not records:
        return []
    keys, args = admission_arguments(records, settings)
    response = await redis.eval(QUEUE_ADMIT, len(keys), *keys, *args)
    if not isinstance(response, (list, tuple)):
        raise QueueAdmissionError("Unconfirmed queue delivery")
    result = [item.decode() if isinstance(item, bytes) else item for item in response]
    if len(result) != len(records) + 1 or result[0] != "ok" or any(
        not isinstance(item, str) or not item.partition("-")[0].isdigit() or
        not item.partition("-")[2].isdigit() for item in result[1:]
    ):
        raise QueueAdmissionError("Unconfirmed queue delivery")
    return result[1:]


def bounded_batches(records, *, settings=None):
    """Prepare bounded chunks before enqueueing; never split an invalid record."""
    settings = queue_settings(settings)
    batch, size = [], 0
    for record in records:
        admission_arguments([record], settings)
        length = record_size(record)
        if batch and (len(batch) == 500 or size + length > settings.admission_max_batch_bytes):
            yield batch
            batch, size = [], 0
        batch.append(record)
        size += length
    if batch:
        yield batch
