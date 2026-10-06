"""Required, private lab-only Redis pressure/AOF fixture prerequisites.

The host qualification orchestrator owns stop/copy/recreate. Only the explicitly
validated pressure fixture receives bounded, temporary maxmemory injection.
This module never uses Docker, imports an archive, or prints credentials.
"""

import asyncio
import json
import os
import re
from contextlib import asynccontextmanager
from pathlib import Path

import redis.asyncio as aioredis
from redis.exceptions import OutOfMemoryError

from shadai.utils.delivery_spool import _check_path, _private_ancestors


class PressurePrerequisiteError(RuntimeError):
    pass


ORIGINAL_LIMIT = 32 * 1024 * 1024
PRESSURE_MARGIN = 1024 * 1024


def _injection_target(redis, prefix, chunk_bytes, max_fill):
    connection = redis.connection_pool.connection_kwargs
    if (os.environ.get("SHADAI_REQUIRE_REDIS_PRESSURE") != "1" or
            os.environ.get("SHADAI_REDIS_PRESSURE_HOST") != "labredis-pressure" or
            os.environ.get("SHADAI_REDIS_PRESSURE_PORT") != "6379" or
            (connection.get("host"), connection.get("port"), connection.get("db", 0)) !=
            ("labredis-pressure", 6379, 0)):
        raise PressurePrerequisiteError("Explicit pressure lab fixture required")
    if (type(prefix) is not str or
            prefix != "pressure:fill:" and not re.fullmatch(r"test-sso-pressure-[a-f0-9]{32}:filler:", prefix) or
            type(chunk_bytes) is not int or not 1024 <= chunk_bytes <= PRESSURE_MARGIN or
            type(max_fill) is not int or not 1 <= max_fill <= 256 or chunk_bytes * max_fill > 64 * PRESSURE_MARGIN):
        raise PressurePrerequisiteError("Invalid owned pressure filler bounds")


async def _injection_policy(redis, expected):
    policy = await redis.config_get("maxmemory", "maxmemory-policy", "appendonly")
    persistence = await redis.info("persistence")
    if (policy.get("maxmemory") != str(expected) or policy.get("maxmemory-policy") != "noeviction" or
            policy.get("appendonly") != "yes" or type(persistence.get("aof_enabled")) is not int or
            persistence.get("aof_enabled") != 1 or
            persistence.get("aof_last_write_status") != "ok"):
        raise PressurePrerequisiteError("Pressure fixture configuration mismatch")


def _heap(memory):
    used, excluded = memory.get("used_memory"), memory.get("mem_not_counted_for_evict", 0)
    if type(used) is not int or type(excluded) is not int or not 0 <= excluded <= used <= 64 * PRESSURE_MARGIN:
        raise PressurePrerequisiteError("Invalid measured pressure heap")
    return used - excluded


async def _restore_pressure(redis, fillers):
    failures = []

    async def attempt(note, operation):
        try:
            # Each safety operation gets a fresh budget outside setup/body deadlines.
            async with asyncio.timeout(5):
                await operation()
        except BaseException:
            failures.append(note)

    async def restore():
        if await redis.config_set("maxmemory", ORIGINAL_LIMIT) is not True:
            raise PressurePrerequisiteError("Pressure restore refused")

    async def release():
        if fillers:
            await redis.delete(*fillers)
            if await redis.exists(*fillers):
                raise PressurePrerequisiteError("Owned pressure cleanup refused")

    await attempt("pressure_restore_failed", restore)
    await attempt("pressure_owned_cleanup_failed", release)
    await attempt("pressure_restore_verification_failed", lambda: _injection_policy(redis, ORIGINAL_LIMIT))
    return failures


async def _finish_pressure_cleanup(redis, fillers):
    task = asyncio.create_task(_restore_pressure(redis, fillers))
    interrupted = None
    while True:
        try:
            return await asyncio.shield(task), interrupted
        except asyncio.CancelledError as exc:
            # Finish the independently bounded cleanup even if the caller is cancelled again.
            interrupted = interrupted or exc
            if task.done():
                if task.cancelled():
                    return ["pressure_cleanup_failed"], interrupted
                return task.result(), interrupted


@asynccontextmanager
async def sustained_pressure(redis, *, prefix, chunk_bytes, max_fill):
    """Controlled lab-only OOM injection; never a 32 MiB capacity certification."""
    _injection_target(redis, prefix, chunk_bytes, max_fill)
    keys = [prefix + str(index) for index in range(max_fill)]
    async with asyncio.timeout(10):
        await _injection_policy(redis, ORIGINAL_LIMIT)
        if await redis.exists(*keys):
            raise PressurePrerequisiteError("Pressure filler collision")
    fillers, primary, proof = [], None, None
    try:
        async with asyncio.timeout(30):
            for key in keys:
                fillers.append(key)  # Include a write whose reply may be lost.
                try:
                    await redis.set(key, "x" * chunk_bytes)
                except OutOfMemoryError:
                    break
            else:
                raise PressurePrerequisiteError("Bounded filler did not reach Redis OOM")
            measured = _heap(await redis.info("memory"))
            if measured < 2 * PRESSURE_MARGIN:
                raise PressurePrerequisiteError("Measured pressure heap too small")
            injected = min(ORIGINAL_LIMIT, measured - PRESSURE_MARGIN)
            if not PRESSURE_MARGIN <= injected < measured:
                raise PressurePrerequisiteError("Invalid pressure injection limit")
            if await redis.config_set("maxmemory", injected) is not True:
                raise PressurePrerequisiteError("Pressure injection refused")
            await _injection_policy(redis, injected)
            pressure_heap = _heap(await redis.info("memory"))
            if pressure_heap <= injected:
                raise PressurePrerequisiteError("Sustained pressure not observed")
            proof = {"kind": "controlled_lab_oom", "original_maxmemory_bytes": ORIGINAL_LIMIT,
                     "injected_maxmemory_bytes": injected, "post_fill_heap_bytes": measured,
                     "pressure_heap_bytes": pressure_heap, "restored_maxmemory_bytes": None}
        async with asyncio.timeout(60):
            yield proof
    except BaseException as exc:
        primary = exc
        raise
    finally:
        failures, interrupted = await _finish_pressure_cleanup(redis, fillers)
        if primary is not None:
            for note in failures:
                primary.add_note(note)
            if interrupted:
                primary.add_note("pressure_cleanup_cancelled")
        elif interrupted is not None:
            for note in failures:
                interrupted.add_note(note)
            raise interrupted
        elif failures:
            error = PressurePrerequisiteError("Pressure cleanup refused")
            for note in failures:
                error.add_note(note)
            raise error
        if proof is not None and not failures:
            proof["restored_maxmemory_bytes"] = ORIGINAL_LIMIT


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
