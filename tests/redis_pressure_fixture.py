"""Required, private lab-only Redis pressure/AOF fixture prerequisites.

The host qualification orchestrator owns stop/copy/recreate. This module never
uses Docker, changes maxmemory, imports an archive, or prints credentials.
"""

import asyncio
import json
import os
from pathlib import Path

import redis.asyncio as aioredis

from shadai.utils.delivery_spool import _check_path, _private_ancestors


class PressurePrerequisiteError(RuntimeError):
    pass


async def pressure_connection():
    required = os.environ.get("SHADAI_REQUIRE_REDIS_PRESSURE") == "1"
    host = os.environ.get("SHADAI_REDIS_PRESSURE_HOST")
    port = os.environ.get("SHADAI_REDIS_PRESSURE_PORT")
    password_file = os.environ.get("SHADAI_REDIS_PRESSURE_PASSWORD_FILE")
    manifest = os.environ.get("SHADAI_REDIS_PRESSURE_MANIFEST")
    mode = os.environ.get("SHADAI_REDIS_PRESSURE_MODE")
    if not required or host != "labredis-pressure" or port != "6379" or not password_file or not manifest:
        raise PressurePrerequisiteError("Explicit pressure lab fixture required")
    if mode not in {"seed", "assert"}:
        raise PressurePrerequisiteError("Explicit pressure fixture phase required")
    try:
        secret_path = Path(password_file)
        _private_ancestors(secret_path)
        _check_path(secret_path, directory=False)
        password = secret_path.read_text(encoding="utf8").strip()
    except Exception:
        raise PressurePrerequisiteError("Private pressure fixture credential unavailable") from None
    if not password:
        raise PressurePrerequisiteError("Private pressure fixture credential unavailable")
    redis = aioredis.Redis(host=host, port=int(port), password=password, decode_responses=True,
                          single_connection_client=True, socket_connect_timeout=5, socket_timeout=10)
    try:
        settings = await redis.config_get("maxmemory", "maxmemory-policy", "appendonly")
        if (settings.get("maxmemory") != "33554432" or settings.get("maxmemory-policy") != "noeviction" or
                settings.get("appendonly") != "yes"):
            raise PressurePrerequisiteError("Pressure fixture must be 32 MiB / noeviction / AOF")
        persistence = await redis.info("persistence")
        if persistence.get("aof_enabled") != 1:
            raise PressurePrerequisiteError("Pressure fixture AOF unavailable")
    except Exception:
        await redis.aclose()
        raise PressurePrerequisiteError("Pressure fixture unavailable or configuration mismatch") from None
    return redis, mode, Path(manifest)


async def check():
    redis, mode, _ = await pressure_connection()
    await redis.aclose()
    return {"status": "pressure_fixture_ready", "mode": mode, "maxmemory_bytes": 33554432, "aof": True}


def main():
    try:
        print(json.dumps(asyncio.run(check()), separators=(",", ":")))
        return 0
    except Exception as exc:
        print(json.dumps({"status": "pressure_fixture_required", "error_type": type(exc).__name__}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
