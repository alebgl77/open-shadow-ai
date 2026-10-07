"""Atomic, installation-scoped Redis admission for the start of OIDC sign-in."""

import hashlib
import ipaddress
import secrets

from redis.exceptions import RedisError

# Read and validate everything before writing: a denied request allocates nothing.
# The first write charges the fixed installation counter; an OOM cannot create
# unbounded peer fields or leases without charging that counter first.
ADMIT = """
local function integer(value, low, high)
    if type(value) == 'string' and not string.match(value, '^%d+$') then return nil end
    local number = tonumber(value)
    if not number or number ~= math.floor(number) or number < low or number > high then return nil end
    return number
end
local function hex(value)
    return type(value) == 'string' and #value == 64 and not string.find(value, '[^0-9a-f]')
end
local peer_limit = integer(ARGV[3], 1, 1000)
local installation_limit = integer(ARGV[4], 1, 10000)
local concurrency = integer(ARGV[5], 1, 64)
local lease_ms = integer(ARGV[6], 4000, 60000)
if not peer_limit or not installation_limit or installation_limit < peer_limit or
   not concurrency or not lease_ms or not hex(ARGV[1]) or not hex(ARGV[2]) then return {-1, 0} end
for index, expected in ipairs({'hash', 'hash', 'zset'}) do
    local actual = redis.call('TYPE', KEYS[index]).ok
    if actual ~= 'none' and actual ~= expected then return {-1, 0} end
end
local meta_size = redis.call('HLEN', KEYS[1])
local peer_size = redis.call('HLEN', KEYS[2])
if (meta_size ~= 0 and meta_size ~= 2) or peer_size > installation_limit or
   redis.call('ZCARD', KEYS[3]) > 64 then return {-1, 0} end
local old_bucket, old_count = 0, 0
if meta_size ~= 0 then
    old_bucket = integer(redis.call('HGET', KEYS[1], 'bucket'), 0, 9007199254740991)
    old_count = integer(redis.call('HGET', KEYS[1], 'count'), 1, installation_limit)
    if not old_bucket or not old_count then return {-1, 0} end
elseif peer_size ~= 0 then return {-1, 0} end
local peers = redis.call('HGETALL', KEYS[2])
local peer_total = 0
for index = 1, #peers, 2 do
    local peer_count = integer(peers[index + 1], 1, peer_limit)
    if not hex(peers[index]) or not peer_count then return {-1, 0} end
    peer_total = peer_total + peer_count
end
if peer_total > old_count then return {-1, 0} end
local leases = redis.call('ZRANGE', KEYS[3], 0, -1, 'WITHSCORES')
for index = 1, #leases, 2 do
    if not hex(leases[index]) or not integer(leases[index + 1], 0, 9007199254740991) then return {-1, 0} end
end
local clock = redis.call('TIME')
local now = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
local bucket = math.floor(now / 60000)
local rollover = old_bucket ~= bucket
local count = rollover and 0 or old_count
local peer_count = rollover and 0 or tonumber(redis.call('HGET', KEYS[2], ARGV[1]) or '0')
if count >= installation_limit or peer_count >= peer_limit then
    return {1, math.max(1, math.min(60, math.ceil((60000 - now % 60000) / 1000)))}
end
local live = redis.call('ZCOUNT', KEYS[3], now, '+inf')
if live >= concurrency then
    local earliest = redis.call('ZRANGEBYSCORE', KEYS[3], now, '+inf', 'WITHSCORES', 'LIMIT', 0, 1)
    return {2, math.max(1, math.min(60, math.ceil((tonumber(earliest[2]) - now) / 1000)))}
end
redis.call('HSET', KEYS[1], 'bucket', bucket, 'count', count + 1)
if rollover then redis.call('DEL', KEYS[2]) end
redis.call('HINCRBY', KEYS[2], ARGV[1], 1)
redis.call('EXPIRE', KEYS[1], 120)
redis.call('EXPIRE', KEYS[2], 120)
redis.call('ZREMRANGEBYSCORE', KEYS[3], '-inf', now)
redis.call('ZADD', KEYS[3], now + lease_ms, ARGV[2])
redis.call('PEXPIRE', KEYS[3], lease_ms + 1000)
return {0, 0}
"""


class AdmissionDeniedError(Exception):
    def __init__(self, retry_after):
        self.retry_after = retry_after


class AdmissionUnavailableError(RedisError):
    """Admission state is invalid; no upstream details are exposed."""


def normalized_peer(request):
    """Use only the ASGI socket peer; forwarded headers never select a bucket."""
    host = request.client.host if request.client else None
    try:
        if not isinstance(host, str) or '%' in host:
            return "unknown"
        return str(ipaddress.ip_address(host))
    except ValueError:
        return "unknown"


class SSOAdmission:
    def __init__(self, redis, tenant_id, config):
        self.redis, self.config = redis, config
        prefix = "oidc:admission:" + hashlib.sha256(tenant_id.encode()).hexdigest()
        self.keys = tuple(prefix + suffix for suffix in (":meta", ":peers", ":leases"))

    async def admit(self, peer, token):
        result = await self.redis.eval(
            ADMIT, 3, *self.keys, hashlib.sha256(peer.encode()).hexdigest(), token,
            self.config.login_peer_limit, self.config.login_installation_limit,
            self.config.login_concurrency, self.config.login_lease_seconds * 1000,
        )
        if not isinstance(result, (list, tuple)) or len(result) != 2:
            raise AdmissionUnavailableError()
        status, retry = result
        if type(status) is not int or type(retry) is not int:
            raise AdmissionUnavailableError()
        if status in (1, 2) and type(retry) is int and 1 <= retry <= 60:
            raise AdmissionDeniedError(retry)
        if status != 0 or retry != 0:
            raise AdmissionUnavailableError()

    async def release(self, token):
        await self.redis.zrem(self.keys[2], token)

    @staticmethod
    def token():
        return secrets.token_hex(32)
