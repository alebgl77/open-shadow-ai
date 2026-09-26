"""Confidential OIDC authorization code flow; tokens never enter browser storage."""

import hashlib
import hmac
import json
import math
import secrets
import time
from urllib.parse import quote_plus, urlencode, urlsplit

import httpx
import jwt

from shadai.config import trusted_url

STATE_TTL = 300
HANDOFF_TTL = 60


class OIDCError(Exception):
    """Intentionally contains no upstream response, token, authorization code or URL."""


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def origin(url):
    parsed = urlsplit(url)
    if parsed.scheme not in {"https", "http"} or not parsed.hostname:
        raise ValueError("Invalid origin")
    host = parsed.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    port = parsed.port
    suffix = f":{port}" if port is not None and (parsed.scheme, port) not in {("https", 443), ("http", 80)} else ""
    return f"{parsed.scheme.lower()}://{host}{suffix}"


def endpoint(url, config):
    if not isinstance(url, str):
        raise OIDCError()
    try:
        trusted_url(url, config.allow_insecure_localhost)
        if origin(url) != origin(config.issuer):
            raise ValueError()
    except (ValueError, TypeError, AttributeError) as exc:
        raise OIDCError() from exc
    return url


async def document(client, url, **kwargs):
    """Bound response size and never follow issuer-controlled redirects."""
    method = kwargs.pop("method", "GET")
    try:
        async with client.stream(method, url, **kwargs) as response:
            if response.status_code != 200:
                raise OIDCError()
            data = bytearray()
            async for chunk in response.aiter_bytes():
                data.extend(chunk)
                if len(data) > 256 * 1024:
                    raise OIDCError()
            result = json.loads(data)
            if not isinstance(result, dict):
                raise OIDCError()
            return result
    except (httpx.HTTPError, ValueError, UnicodeError) as exc:
        raise OIDCError() from exc


class OIDCClient:
    def __init__(self, config, transport=None):
        self.config, self.transport = config, transport

    def http(self):
        return httpx.AsyncClient(
            timeout=httpx.Timeout(10),
            follow_redirects=False,
            trust_env=False,
            transport=self.transport,
        )

    async def discovery(self, client):
        cfg = self.config
        metadata = await document(client, cfg.issuer.rstrip("/") + "/.well-known/openid-configuration")
        if metadata.get("issuer") != cfg.issuer:
            raise OIDCError()
        for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
            endpoint(metadata.get(key), cfg)
        challenges = metadata.get("code_challenge_methods_supported")
        algorithms = metadata.get("id_token_signing_alg_values_supported", [])
        # Entra omits this optional discovery field while supporting S256.
        # We always send an S256 challenge and never fall back to plain PKCE.
        if "code_challenge_methods_supported" in metadata and (
            not isinstance(challenges, list) or "S256" not in challenges
        ):
            raise OIDCError()
        if not isinstance(algorithms, list) or "RS256" not in algorithms:
            raise OIDCError()
        return metadata

    async def authorization_url(self, state, nonce, verifier):
        async with self.http() as client:
            metadata = await self.discovery(client)
        challenge = jwt.utils.base64url_encode(hashlib.sha256(verifier.encode()).digest()).decode()
        return (
            metadata["authorization_endpoint"]
            + "?"
            + urlencode(
                {
                    "client_id": self.config.client_id,
                    "response_type": "code",
                    "response_mode": "query",
                    "redirect_uri": self.config.callback_url,
                    "scope": "openid profile",
                    "state": state,
                    "nonce": nonce,
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                }
            )
        )

    async def exchange(self, code, verifier, nonce):
        async with self.http() as client:
            metadata = await self.discovery(client)
            methods = metadata.get("token_endpoint_auth_methods_supported", ["client_secret_basic"])
            if not isinstance(methods, list):
                raise OIDCError()
            data = {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self.config.callback_url,
                "client_id": self.config.client_id,
                "code_verifier": verifier,
            }
            auth = None
            if "client_secret_basic" in methods:
                auth = httpx.BasicAuth(quote_plus(self.config.client_id), quote_plus(self.config.client_secret))
            elif "client_secret_post" in methods:
                data["client_secret"] = self.config.client_secret
            else:
                raise OIDCError()
            tokens = await document(client, metadata["token_endpoint"], method="POST", data=data, auth=auth)
            token = tokens.get("id_token")
            if not isinstance(token, str) or len(token) > 32768:
                raise OIDCError()
            keys = await document(client, metadata["jwks_uri"])
        return self.validate(token, keys, nonce)

    def validate(self, token, keys, nonce):
        try:
            header = jwt.get_unverified_header(token)
            if (
                header.get("alg") != "RS256"
                or not isinstance(header.get("kid"), str)
                or not 1 <= len(header["kid"]) <= 255
                or header.get("crit")
            ):
                raise OIDCError()
            if not isinstance(keys.get("keys"), list) or len(keys["keys"]) > 100:
                raise OIDCError()
            candidates = [
                key
                for key in keys["keys"]
                if isinstance(key, dict)
                and key.get("kid") == header["kid"]
                and key.get("kty") == "RSA"
                and key.get("alg", "RS256") == "RS256"
                and key.get("use", "sig") == "sig"
                and isinstance(key.get("key_ops", ["verify"]), list)
                and "verify" in key.get("key_ops", ["verify"])
            ]
            if len(candidates) != 1:
                raise OIDCError()
            key = jwt.PyJWK.from_dict(candidates[0], algorithm="RS256").key
            if key.key_size < 2048:
                raise OIDCError()
            claims = jwt.decode(
                token,
                key,
                algorithms=["RS256"],
                issuer=self.config.issuer,
                audience=self.config.client_id,
                options={
                    "require": ["iss", "sub", "aud", "exp", "iat", "nonce"],
                    "verify_exp": False,
                    "verify_iat": False,
                    "verify_nbf": False,
                },
            )
            audience = claims["aud"]
            if isinstance(audience, list) and (len(audience) > 1 and claims.get("azp") != self.config.client_id):
                raise OIDCError()
            if "azp" in claims and claims["azp"] != self.config.client_id:
                raise OIDCError()
            if not isinstance(claims["nonce"], str) or not hmac.compare_digest(claims["nonce"], nonce):
                raise OIDCError()
            now = time.time()
            for name in ("iat", "exp", "nbf"):
                if name in claims and (type(claims[name]) not in {int, float} or not math.isfinite(claims[name])):
                    raise OIDCError()
            if (
                claims["iat"] > now
                or claims["iat"] < now - STATE_TTL - 30
                or claims["exp"] <= now
                or claims["exp"] <= claims["iat"]
                or claims.get("nbf", 0) > now
            ):
                raise OIDCError()
            if not isinstance(claims["sub"], str) or not 1 <= len(claims["sub"]) <= 255:
                raise OIDCError()
            external_id = claims.get(self.config.identity_claim)
            if not isinstance(external_id, str) or not 1 <= len(external_id) <= 255:
                raise OIDCError()
            return external_id
        except (jwt.PyJWTError, ValueError, TypeError, KeyError, AttributeError, OverflowError) as exc:
            raise OIDCError() from exc


# Check browser binding and delete in one Redis operation. A wrong browser cannot
# burn the legitimate state/handoff, and simultaneous correct exchanges have one winner.
CONSUME = """
local value = redis.call('GET', KEYS[1])
if not value then return nil end
local item = cjson.decode(value)
if item.binding ~= ARGV[1] then return nil end
redis.call('DEL', KEYS[1])
return value
"""


async def store_bound(redis, namespace, payload, binding, ttl):
    for _ in range(3):
        handle = secrets.token_urlsafe(32)
        stored = await redis.set(
            f"oidc:{namespace}:{digest(handle)}",
            json.dumps({**payload, "binding": digest(binding)}),
            ex=ttl,
            nx=True,
        )
        if stored:
            return handle
    raise OIDCError()


async def consume_bound(redis, namespace, handle, binding):
    if (
        not isinstance(handle, str)
        or not isinstance(binding, str)
        or not 20 <= len(handle) <= 128
        or not 20 <= len(binding) <= 128
    ):
        raise OIDCError()
    value = await redis.eval(CONSUME, 1, f"oidc:{namespace}:{digest(handle)}", digest(binding))
    if not value:
        raise OIDCError()
    try:
        payload = json.loads(value)
        if not isinstance(payload, dict):
            raise OIDCError()
        return payload
    except (ValueError, TypeError) as exc:
        raise OIDCError() from exc
