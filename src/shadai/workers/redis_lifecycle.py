"""Explicit Redis retention, authenticated archives and conservative deletion.

No TTL or MAXLEN applies to source streams. Schema reconciliation is an
operator migration, after legacy writers have stopped, rather than an ACK scan.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import os
import re
import stat
from pathlib import Path

import redis.asyncio as aioredis
from cryptography.fernet import Fernet
from redis.exceptions import ResponseError

from shadai.utils.delivery_spool import _check_path, _private_ancestors, _private_directory
from shadai.utils.operations import COUNT_OPERATION
from shadai.utils.queue_admission import GROUP_STREAMS, QUEUE_LUA, SCHEMA_KEY, STREAMS, queue_settings

STREAM_ID = re.compile(r"^[0-9]{1,20}-[0-9]{1,20}$")
MAX_ARCHIVE_BYTES = 16 * 1024 * 1024
ARCHIVE_VERSION = 1


def refs_key(stream):
    if stream not in STREAMS:
        raise ValueError("Unsupported retention stream")
    return "retention:refs:v1:" + stream


RETENTION_LUA = QUEUE_LUA + COUNT_OPERATION + """
local function ref_value(key, id)
    if not type_ok(key, 'hash') then return nil end
    local value = redis.call('HGET', key, id)
    if value and not uint(value, 40000) then return nil end
    return tonumber(value or '0')
end
local function index_ready(key, schema)
    return kind(schema) == 'string' and redis.call('GET', schema) == '1' and
           kind(key) == 'hash' and redis.call('HGET', key, '__schema') == '1'
end
local function op_ok(key, field)
    if not key then return true end
    if not type_ok(key, 'hash') then return false end
    local value = redis.call('HGET', key, field)
    if value and not (value == '0' or string.match(value, '^[1-9]%d*$')) then return false end
    check_operation(key, field)
    return true
end
local function group_safe(stream, id, owner)
    if kind(stream) ~= 'stream' then return false end
    local groups = redis.call('XINFO', 'GROUPS', stream)
    if #groups > 16 or (owner and #groups == 0) then return false end
    local found = not owner
    for _,row in ipairs(groups) do
        local name, last
        for i=1,#row,2 do
            if row[i] == 'name' then name = row[i+1] end
            if row[i] == 'last-delivered-id' then last = row[i+1] end
        end
        if not name or not id_valid(last) or id_cmp(last, id) < 0 then return false end
        if #redis.call('XPENDING', stream, name, id, id, 1) > 0 then return false end
        if name == owner then found = true end
    end
    return found
end
"""

RETENTION_READY = QUEUE_LUA + """
if #KEYS ~= 11 or KEYS[1] ~= 'retention:schema' or kind(KEYS[1]) ~= 'string' or
   redis.call('GET', KEYS[1]) ~= '1' then return 0 end
local names = {'events:dns','events:proxy','events:endpoint','events:browser','events:oauth',
               'events:directory','events:instrumented','events:casb','events:network','matches'}
for i,s in ipairs(names) do
    if KEYS[i+1] ~= 'retention:refs:v1:' .. s or kind(KEYS[i+1]) ~= 'hash' or
       redis.call('HGET', KEYS[i+1], '__schema') ~= '1' then return 0 end
end
return 1
"""

ACK_SUCCESS = RETENTION_LUA + """
if allowed[KEYS[1]] ~= ARGV[1] or not id_valid(ARGV[2]) or
   KEYS[2] ~= 'retention:refs:v1:' .. KEYS[1] or KEYS[3] ~= 'retention:schema' or
   kind(KEYS[1]) ~= 'stream' or
   (KEYS[4] and KEYS[4] ~= 'operations:' .. ARGV[1] .. ':' .. KEYS[1]) or
   not op_ok(KEYS[4], 'acknowledged') then
    return redis.error_reply('Invalid ACK state')
end
local groups = redis.call('XINFO', 'GROUPS', KEYS[1])
local pending = redis.call('XPENDING', KEYS[1], ARGV[1], ARGV[2], ARGV[2], 1)
if #pending == 0 then return 0 end
-- Corrupt/missing migration state allows ACK, but never source deletion.
local refs = ref_value(KEYS[2], ARGV[2])
local removable = #groups == 1 and index_ready(KEYS[2], KEYS[3]) and refs == 0
if KEYS[4] then record_operation(KEYS[4], 'acknowledged') end
local ack = redis.call('XACK', KEYS[1], ARGV[1], ARGV[2])
if ack > 0 and removable then redis.call('XDEL', KEYS[1], ARGV[2]) end
return ack
"""

DEADLETTER = RETENTION_LUA + """
local cap = tonumber(ARGV[5])
if allowed[KEYS[1]] ~= ARGV[1] or KEYS[2] ~= 'deadletter:' .. ARGV[1] or
   KEYS[3] ~= 'retries:' .. ARGV[1] .. ':' .. KEYS[1] .. ':' .. ARGV[2] or
   KEYS[4] ~= 'retention:refs:v1:' .. KEYS[1] or KEYS[5] ~= 'retention:schema' or
   (KEYS[6] and KEYS[6] ~= 'operations:' .. ARGV[1] .. ':' .. KEYS[1]) or
   not id_valid(ARGV[2]) or not uint(ARGV[4], 65535) or
   not cap or cap < 1 or cap > 20000 or cap % 1 ~= 0 or
   kind(KEYS[1]) ~= 'stream' or not type_ok(KEYS[2], 'stream') or
   not type_ok(KEYS[3], 'hash') or not type_ok(KEYS[5], 'string') or
   not op_ok(KEYS[6], 'deadlettered') then return redis.error_reply('Invalid dead-letter state') end
local refs = ref_value(KEYS[4], ARGV[2])
if not refs or refs >= 40000 or (redis.call('GET', KEYS[5]) == '1' and not index_ready(KEYS[4], KEYS[5])) then
    return redis.error_reply('Invalid reference index')
end
for _,field in ipairs({'attempts','poison_attempts'}) do
    local v = redis.call('HGET', KEYS[3], field)
    if v and not uint(v, 65535) then return redis.error_reply('Invalid retry state') end
end
local next_at = redis.call('HGET', KEYS[3], 'next_at')
if next_at and (not tonumber(next_at) or tonumber(next_at) < 0 or tonumber(next_at) == math.huge) then
    return redis.error_reply('Invalid retry state')
end
local pending = redis.call('XPENDING', KEYS[1], ARGV[1], ARGV[2], ARGV[2], 1)
if #pending == 0 then return 0 end
if #redis.call('XRANGE', KEYS[1], ARGV[2], ARGV[2], 'COUNT', 1) == 0 then return -1 end
if redis.call('XLEN', KEYS[2]) >= cap then return -1 end
-- First write allocates the pointer. No approximate trimming can erase one.
redis.call('XADD', KEYS[2], '*', 'stream', KEYS[1], 'message_id', ARGV[2],
           'error_type', ARGV[3], 'attempts', ARGV[4])
redis.call('HINCRBY', KEYS[4], ARGV[2], 1)
if KEYS[6] then record_operation(KEYS[6], 'deadlettered') end
redis.call('XACK', KEYS[1], ARGV[1], ARGV[2])
redis.call('DEL', KEYS[3])
return 1
"""

REPLAY = RETENTION_LUA + """
local owner = allowed[KEYS[1]]
local cap, maxbytes = tonumber(ARGV[3]), tonumber(ARGV[4])
if not owner or KEYS[2] ~= 'deadletter:' .. owner or KEYS[3] ~= 'replayed:' .. owner .. ':' .. ARGV[1] or
   KEYS[4] ~= 'retention:refs:v1:' .. KEYS[1] or KEYS[5] ~= 'retention:schema' or
   (KEYS[6] and KEYS[6] ~= 'operations:' .. owner .. ':' .. KEYS[1]) or
   not id_valid(ARGV[1]) or not id_valid(ARGV[2]) or
   not cap or cap < 1 or cap > 10000000 or cap % 1 ~= 0 or
   not maxbytes or maxbytes < 1 or maxbytes > 16777216 or
   not type_ok(KEYS[1], 'stream') or not type_ok(KEYS[2], 'stream') or
   not type_ok(KEYS[3], 'string') or not type_ok(KEYS[5], 'string') or
   not op_ok(KEYS[6], 'replayed') or not ref_value(KEYS[4], ARGV[2]) then
    return {'invalid_state',''}
end
local pointer = redis.call('XRANGE', KEYS[2], ARGV[1], ARGV[1], 'COUNT', 1)
if #pointer == 0 then return {'missing_pointer',''} end
local stream, sourceid = pointer_target(pointer[1][2])
local expected = cjson.decode(ARGV[5])
if stream ~= KEYS[1] or sourceid ~= ARGV[2] or not same_fields(pointer[1][2], expected) then
    return {'changed_pointer',''}
end
local prior = redis.call('GET', KEYS[3])
if prior then
    if not id_valid(prior) then return {'invalid_state',''} end
    return {'already_replayed',prior}
end
local original = redis.call('XRANGE', KEYS[1], ARGV[2], ARGV[2], 'COUNT', 1)
if #original == 0 then return {'missing_source',''} end
local fields, size, seen = original[1][2], #KEYS[1], {}
if #fields < 2 or #fields > 64 then return {'invalid_state',''} end
for i=1,#fields,2 do
    if fields[i] == '' or seen[fields[i]] then return {'invalid_state',''} end
    seen[fields[i]] = true; size = size + #fields[i] + #fields[i+1]
end
if size > maxbytes or redis.call('XLEN', KEYS[1]) >= cap then return {'full',''} end
local id = redis.call('XADD', KEYS[1], '*', unpack(fields))
redis.call('SET', KEYS[3], id, 'EX', 31536000)
if KEYS[6] then record_operation(KEYS[6], 'replayed') end
return {'replayed',id}
"""

RECONCILE = RETENTION_LUA + """
local cap = tonumber(ARGV[1])
if #KEYS ~= 13 or KEYS[1] ~= 'retention:schema' or
   KEYS[2] ~= 'deadletter:ingest_group' or KEYS[3] ~= 'deadletter:correlate_group' or
   not cap or cap < 1 or cap > 20000 or not type_ok(KEYS[1], 'string') then
    return redis.error_reply('Invalid reconciliation state')
end
local counts, positions = {}, {}
local names = {'events:dns','events:proxy','events:endpoint','events:browser','events:oauth',
               'events:directory','events:instrumented','events:casb','events:network','matches'}
for i,s in ipairs(names) do
    if KEYS[i+3] ~= 'retention:refs:v1:' .. s or not type_ok(KEYS[i+3], 'hash') then
        return redis.error_reply('Invalid reference index')
    end
    positions[s] = i; counts[i] = {}
end
for i=2,3 do
    if not type_ok(KEYS[i], 'stream') or redis.call('XLEN', KEYS[i]) > cap then
        return redis.error_reply('Unbounded dead-letter reconciliation')
    end
    local owner = i == 2 and 'ingest_group' or 'correlate_group'
    for _,row in ipairs(redis.call('XRANGE', KEYS[i], '-', '+', 'COUNT', cap+1)) do
        local stream,id = pointer_target(row[2])
        if not stream or allowed[stream] ~= owner or not type_ok(stream, 'stream') then
            return redis.error_reply('Invalid dead-letter pointer')
        end
        local refs = counts[positions[stream]]
        refs[id] = (refs[id] or 0) + 1
    end
end
-- Interrupted rebuilding remains explicitly unusable for deletion.
redis.call('SET', KEYS[1], 'building')
for i=1,10 do
    redis.call('DEL', KEYS[i+3])
    redis.call('HSET', KEYS[i+3], '__schema', '1')
    for id,n in pairs(counts[i]) do redis.call('HSET', KEYS[i+3], id, n) end
end
redis.call('SET', KEYS[1], '1')
return 1
"""

# Source and pointer fields are compared to the durable authenticated archive,
# inside the same script as every deletion. New groups cannot slip past a scan.
PURGE = RETENTION_LUA + """
local owner, id, pointerid, cutoff = ARGV[1], ARGV[2], ARGV[3], ARGV[4]
if allowed[KEYS[1]] ~= owner or KEYS[2] ~= 'retention:refs:v1:' .. KEYS[1] or
   KEYS[3] ~= 'retention:schema' or KEYS[4] ~= 'deadletter:' .. owner or
   KEYS[5] ~= 'replayed:' .. owner .. ':' .. pointerid or
   not id_valid(id) or not id_valid(cutoff) or (pointerid ~= '' and not id_valid(pointerid)) or
   not index_ready(KEYS[2], KEYS[3]) or not type_ok(KEYS[4], 'stream') or
   not type_ok(KEYS[5], 'string') then return 'invalid_state' end
local refs = ref_value(KEYS[2], id)
if not refs or (pointerid ~= '' and refs < 1) then return 'invalid_index' end
if kind(KEYS[1]) ~= 'stream' then return 'source_in_use' end
local original = redis.call('XRANGE', KEYS[1], id, id, 'COUNT', 1)
local fields = #original > 0 and original[1][2] or {}
local ns = tonumber(ARGV[5])
if not ns or ns < 0 or ns > 64 or ns % 2 ~= 0 then return 'invalid_state' end
local archived, pos = {}, 6
for i=1,ns do archived[i] = ARGV[pos]; pos = pos + 1 end
local np = tonumber(ARGV[pos]); pos = pos + 1
if not np or np < 0 or np > 64 or np % 2 ~= 0 or #ARGV ~= pos + np - 1 then return 'invalid_state' end
local archived_pointer = {}
for i=1,np do archived_pointer[i] = ARGV[pos]; pos = pos + 1 end
if not same_fields(fields, archived) then return 'changed_source' end
if not group_safe(KEYS[1], id, owner) then return 'source_in_use' end
if pointerid == '' then
    if refs ~= 0 then return 'referenced' end
    if id_cmp(id, cutoff) >= 0 then return 'too_young' end
    if #original == 0 then return 'missing_source' end
    redis.call('XDEL', KEYS[1], id)
    return 'source_purged'
end
local pointer = redis.call('XRANGE', KEYS[4], pointerid, pointerid, 'COUNT', 1)
if #pointer == 0 then return 'missing_pointer' end
local stream, sourceid = pointer_target(pointer[1][2])
if stream ~= KEYS[1] or sourceid ~= id or not same_fields(pointer[1][2], archived_pointer) then
    return 'changed_pointer'
end
if id_cmp(pointerid, cutoff) >= 0 then return 'too_young' end
if not group_safe(KEYS[4], pointerid, nil) then return 'pointer_in_use' end
-- Every allocation/validation occurs before deletion; no metrics allocate after it.
redis.call('XDEL', KEYS[4], pointerid)
redis.call('DEL', KEYS[5])
local remaining = redis.call('HINCRBY', KEYS[2], id, -1)
if remaining == 0 then
    redis.call('HDEL', KEYS[2], id)
    if #original > 0 and id_cmp(id, cutoff) < 0 then redis.call('XDEL', KEYS[1], id) end
end
return 'pointer_purged'
"""


def validate_selection(group, stream=None, after="0-0", end="+", limit=100):
    if group not in GROUP_STREAMS or (stream is not None and stream not in GROUP_STREAMS[group]):
        raise ValueError("Invalid retention group or stream")
    if not 1 <= limit <= 500 or not STREAM_ID.fullmatch(after) or (end != "+" and not STREAM_ID.fullmatch(end)):
        raise ValueError("Invalid retention selector")


async def reconcile(redis, *, execute=False, legacy_writers_stopped=False, settings=None):
    if not execute or not legacy_writers_stopped:
        raise ValueError("Reconciliation requires execute and stopped legacy writers")
    settings = queue_settings(settings)
    keys = [SCHEMA_KEY, *("deadletter:" + group for group in GROUP_STREAMS), *(refs_key(s) for s in STREAMS)]
    return await redis.eval(RECONCILE, len(keys), *keys, settings.dlq_max_entries)


async def retention_ready(redis):
    """Fixed-key migration readiness; never initializes or deletes store state."""
    keys = [SCHEMA_KEY, *(refs_key(stream) for stream in STREAMS)]
    return await redis.eval(RETENTION_READY, len(keys), *keys) == 1


def _text(value):
    return value.decode("ascii") if isinstance(value, bytes) else value


def _raw(value):
    return value if isinstance(value, bytes) else value.encode("utf-8")


async def raw_range(redis, key, *, start="-", end="+", count=1):
    # Bypass redis-py's dict conversion: duplicate field names and order must
    # remain exact. A dedicated binary connection is used by the maintenance CLI.
    rows = await redis.eval("""
local rows = redis.call('XRANGE', KEYS[1], ARGV[1], ARGV[2], 'COUNT', ARGV[3])
local size = 0
for _,row in ipairs(rows) do
    if #row[2] > 64 then return redis.error_reply('Archive field limit') end
    for _,field in ipairs(row[2]) do size = size + #field end
    if size > 8388608 then return redis.error_reply('Archive byte limit') end
end
return rows
""",
                            1, key, start, end, count)
    return [(_text(row[0]), [_raw(item) for item in row[1]]) for row in rows]


def pack_fields(fields):
    return [base64.b64encode(item).decode("ascii") for item in fields]


def unpack_fields(fields):
    if not isinstance(fields, list) or len(fields) % 2 or len(fields) > 64:
        raise ValueError("Invalid archive fields")
    return [base64.b64decode(item, validate=True) for item in fields]


def _target(fields):
    if len(fields) % 2 or len(fields) > 64 or len(set(fields[::2])) != len(fields[::2]):
        raise ValueError("Invalid dead-letter pointer")
    pairs = dict(zip(fields[::2], fields[1::2], strict=True))
    stream, message_id = _text(pairs.get(b"stream")), _text(pairs.get(b"message_id"))
    if stream not in STREAMS or not isinstance(message_id, str) or not STREAM_ID.fullmatch(message_id):
        raise ValueError("Invalid dead-letter pointer")
    return stream, message_id


def _validate_archive(document):
    if (not isinstance(document, dict) or document.get("version") != ARCHIVE_VERSION or
            document.get("kind") != "redis-retention"):
        raise ValueError("Invalid archive schema")
    validate_selection(document.get("group"), document.get("stream"), limit=len(document.get("records", [])) or 1)
    if not STREAM_ID.fullmatch(document.get("cutoff", "")):
        raise ValueError("Invalid archive cutoff")
    seen = set()
    for row in document.get("records", []):
        stream, ident, pointer = row.get("stream"), row.get("source_id"), row.get("pointer_id", "")
        validate_selection(document["group"], stream)
        if not STREAM_ID.fullmatch(ident or "") or (pointer and not STREAM_ID.fullmatch(pointer)):
            raise ValueError("Invalid archive ID")
        unpack_fields(row["source_fields"])
        pfields = unpack_fields(row["pointer_fields"])
        if pointer and _target(pfields) != (stream, ident):
            raise ValueError("Invalid archive pointer")
        if not pointer and pfields:
            raise ValueError("Invalid archive pointer")
        identity = stream, ident, pointer
        if identity in seen:
            raise ValueError("Duplicate archive record")
        seen.add(identity)
    return document


def write_archive(path, document, key):
    """Exclusive, private, authenticated and fsynced before any Redis deletion."""
    _validate_archive(document)
    plaintext = json.dumps(document, separators=(",", ":"), sort_keys=True).encode()
    if len(plaintext) > MAX_ARCHIVE_BYTES:
        raise ValueError("Archive size limit")
    token = Fernet(key).encrypt(plaintext)
    if len(token) > MAX_ARCHIVE_BYTES:
        raise ValueError("Archive size limit")
    path = Path(os.path.abspath(Path(path).expanduser()))
    _private_directory(path.parent)
    _private_ancestors(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as output:
        _check_path(path, directory=False)
        before, current = os.fstat(output.fileno()), path.lstat()
        if not stat.S_ISREG(before.st_mode) or (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino):
            raise ValueError("Archive path changed")
        output.write(token)
        output.flush()
        os.fsync(output.fileno())
        _check_path(path, directory=False)
        current = path.lstat()
        if (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino):
            raise ValueError("Archive path changed")
    # Persist the directory entry on POSIX too. Windows FlushFileBuffers above
    # is the portable durability boundary supported by the spool contract.
    if os.name != "nt":
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    return hashlib.sha256(token).hexdigest()


def verify_archive(path, key):
    path = Path(os.path.abspath(Path(path).expanduser()))
    if not path.parent.exists():
        raise FileNotFoundError("Archive directory unavailable")
    _private_directory(path.parent)
    _private_ancestors(path)
    _check_path(path, directory=False)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as source:
        before, current = os.fstat(source.fileno()), path.lstat()
        if (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino):
            raise ValueError("Archive path changed")
        token = source.read(MAX_ARCHIVE_BYTES + 1)
    if len(token) > MAX_ARCHIVE_BYTES:
        raise ValueError("Archive size limit")
    document = _validate_archive(json.loads(Fernet(key).decrypt(token)))
    return document, hashlib.sha256(token).hexdigest()


async def inventory(redis, group, *, stream=None, after="0-0", end="+", limit=100):
    validate_selection(group, stream, after, end, limit)
    seconds, micros = await redis.time()
    rows = []
    for selected in (stream,) if stream else GROUP_STREAMS[group]:
        try:
            groups = await redis.xinfo_groups(selected)
        except ResponseError as exc:
            if "no such key" not in str(exc).lower():
                raise
            groups = []
        safe_groups = []
        for item in groups[:16]:
            name = _raw(item["name"])
            safe_groups.append({"group_sha256": hashlib.sha256(name).hexdigest(),
                                "expected_owner": name == group.encode(),
                                "pending": item.get("pending"), "last_delivered_id": _text(item["last-delivered-id"]),
                                "undelivered": item.get("lag")})
        rows.append({"stream": selected, "retained_entries": await redis.xlen(selected),
                     "group_count": len(groups), "groups": safe_groups,
                     "index_present": bool(await redis.exists(refs_key(selected)))})
    candidates = await purge(redis, group, stream=stream, after=after, end=end, limit=limit)
    schema = _text(await redis.get(SCHEMA_KEY))
    return {"status": "inventory", "redis_time": f"{seconds}.{int(micros):06d}",
            "schema": schema if schema in {None, "1", "building"} else "invalid", "sources": rows,
            "retention_ready": await retention_ready(redis),
            "deadletter_retained": await redis.xlen("deadletter:" + group), "candidates": candidates}


async def purge(redis, group, *, stream=None, after="0-0", end="+", limit=100,
                execute=False, archive=None, discard=False, encryption_key=None, settings=None):
    validate_selection(group, stream, after, end, limit)
    if execute and bool(archive) == bool(discard):
        raise ValueError("Purge requires archive OR explicit discard")
    settings = queue_settings(settings)
    seconds, micros = await redis.time()
    cutoff = f"{max(0, int(seconds) * 1000 + int(micros) // 1000 - settings.retained_days * 86400000)}-0"
    dlq = "deadletter:" + group
    records = []
    budget, cursor = 0, after
    if stream:
        for _ in range(limit):
            candidates = await raw_range(redis, stream, start="(" + cursor, end=end, count=1)
            if not candidates:
                break
            [(ident, fields)] = candidates
            budget += sum(map(len, fields))
            if budget > MAX_ARCHIVE_BYTES // 2:
                raise ValueError("Archive byte limit; request a smaller page")
            records.append({"stream": stream, "source_id": ident, "pointer_id": "",
                            "source_fields": pack_fields(fields), "pointer_fields": []})
            cursor = ident
    else:
        for _ in range(limit):
            candidates = await raw_range(redis, dlq, start="(" + cursor, end=end, count=1)
            if not candidates:
                break
            [(pointerid, fields)] = candidates
            selected, ident = _target(fields)
            validate_selection(group, selected)
            original = await raw_range(redis, selected, start=ident, end=ident)
            source_fields = original[0][1] if original else []
            budget += sum(map(len, fields)) + sum(map(len, source_fields))
            if budget > MAX_ARCHIVE_BYTES // 2:
                raise ValueError("Archive byte limit; request a smaller page")
            records.append({"stream": selected, "source_id": ident, "pointer_id": pointerid,
                            "source_fields": pack_fields(source_fields),
                            "pointer_fields": pack_fields(fields)})
            cursor = pointerid
    document = {"version": ARCHIVE_VERSION, "kind": "redis-retention", "group": group,
                "stream": stream, "cutoff": cutoff, "records": records}
    _validate_archive(document)
    digest = None
    if execute and archive:
        digest = await asyncio.to_thread(write_archive, archive, document, encryption_key)
        # Verify the actual persisted bytes, rather than trusting a writer result.
        verified, actual = await asyncio.to_thread(verify_archive, archive, encryption_key)
        if verified != document or digest != actual:
            raise ValueError("Archive verification failed")
    results = []
    for row in records:
        status = "candidate"
        if execute:
            args = [group, row["source_id"], row["pointer_id"], cutoff]
            for name in ("source_fields", "pointer_fields"):
                fields = unpack_fields(row[name])
                args.extend((len(fields), *fields))
            keys = [row["stream"], refs_key(row["stream"]), SCHEMA_KEY, dlq,
                    f"replayed:{group}:{row['pointer_id']}"]
            status = _text(await redis.eval(PURGE, len(keys), *keys, *args))
        results.append({"stream": row["stream"], "source_id": row["source_id"],
                        "pointer_id": row["pointer_id"], "status": status})
    return {"status": "purge" if execute else "inventory_candidates", "cutoff": cutoff,
            "count": len(results), "archive_sha256": digest, "results": results}


def add_arguments(parser):
    parser.add_argument("action", choices=("inventory", "reconcile", "purge", "verify-archive"))
    parser.add_argument("--group", choices=tuple(GROUP_STREAMS))
    parser.add_argument("--stream", choices=STREAMS)
    parser.add_argument("--after", default="0-0")
    parser.add_argument("--end", default="+")
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--legacy-writers-stopped", action="store_true")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--archive", type=Path)
    mode.add_argument("--discard", action="store_true")
    parser.add_argument("path", nargs="?", type=Path, help="Local archive to verify; never imported")


async def run(args):
    from shadai.config import load_config, validate_security

    config = load_config()
    if args.action == "verify-archive":
        if args.path is None:
            raise ValueError("Archive path required")
        document, digest = await asyncio.to_thread(verify_archive, args.path, config.security.encryption_key)
        return {"status": "archive_verified", "count": len(document["records"]), "archive_sha256": digest}
    validate_security(config)
    redis = aioredis.from_url(config.database.redis_url, decode_responses=False)
    try:
        if args.action == "reconcile":
            result = await reconcile(redis, execute=args.execute, legacy_writers_stopped=args.legacy_writers_stopped,
                                     settings=config.redis_queue)
            return {"status": "reconciled", "schema": result}
        if not args.group:
            raise ValueError("Retention group required")
        options = dict(stream=args.stream, after=args.after, end=args.end, limit=args.limit)
        if args.action == "inventory":
            return await inventory(redis, args.group, **options)
        return await purge(redis, args.group, **options, execute=args.execute, archive=args.archive,
                           discard=args.discard, encryption_key=config.security.encryption_key,
                           settings=config.redis_queue)
    finally:
        await redis.aclose()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    add_arguments(parser)
    args = parser.parse_args(argv)
    try:
        result = asyncio.run(run(args))
        print(json.dumps(result, separators=(",", ":")))
        return 0
    except Exception as exc:
        print(json.dumps({"status": "retention_failed", "error_type": type(exc).__name__}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
