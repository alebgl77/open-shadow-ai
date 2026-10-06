"""Per-process, private probes: local liveness and bounded dependency readiness."""

import argparse
import asyncio
import json
import math
import os
import stat
import time
from contextlib import asynccontextmanager, suppress
from pathlib import Path
from uuid import uuid4

STAGES = {"ingest", "correlation", "purge"}
ROOT = Path("/tmp/shadai-probe")
FIELDS = {
    "schema",
    "stage",
    "pid",
    "start_ticks",
    "boot_id",
    "instance_uuid",
    "initialized",
    "heartbeat_monotonic",
    "last_poll_monotonic",
    "phase",
    "phase_started_monotonic",
    "last_successful_cycle_monotonic",
}
PHASES = {"starting", "idle", "poll", "handler", "blocked", "failed", "purge", "sleep"}


def budget(name, default, low, high):
    value = float(os.environ.get(name, default))
    if not math.isfinite(value) or not low <= value <= high:
        raise ValueError("Invalid probe budget")
    return value


def identity(pid, proc=Path("/proc")):
    raw = (proc / str(pid) / "stat").read_text()
    # The command name may contain spaces and parentheses; fields follow its last ')'.
    fields = raw[raw.rindex(")") + 2 :].split()
    if fields[0] in {"Z", "X"}:
        raise ValueError("Process has exited")
    ticks = int(fields[19])
    boot = (proc / "sys/kernel/random/boot_id").read_text().strip()
    if ticks < 0 or not boot or len(boot) > 64:
        raise ValueError("Invalid process identity")
    return ticks, boot


def private_directory(root):
    root.mkdir(mode=0o700, parents=False, exist_ok=True)
    metadata = root.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700 or metadata.st_uid != os.getuid():
        raise ValueError("Probe directory is not private")


class ProcessProbe:
    def __init__(self, stage, *, root=ROOT, proc=Path("/proc"), clock=time.monotonic):
        if stage not in STAGES:
            raise ValueError("Unknown probe stage")
        self.root, self.proc, self.clock, self.stage = Path(root), Path(proc), clock, stage
        self.task = None
        self.data = None

    async def __aenter__(self):
        private_directory(self.root)
        ticks, boot = identity(os.getpid(), self.proc)
        now = self.clock()
        self.data = {
            "schema": 1,
            "stage": self.stage,
            "pid": os.getpid(),
            "start_ticks": ticks,
            "boot_id": boot,
            "instance_uuid": str(uuid4()),
            "initialized": False,
            "heartbeat_monotonic": now,
            "last_poll_monotonic": None,
            "phase": "starting",
            "phase_started_monotonic": now,
            "last_successful_cycle_monotonic": None,
        }
        await self.publish()
        self.task = asyncio.create_task(self.heartbeat())
        return self

    async def __aexit__(self, *args):
        if self.task:
            self.task.cancel()
            with suppress(asyncio.CancelledError):
                await self.task
        # Retain the last file: identity/heartbeat age cannot make a dead PID healthy.

    def mark_initialized(self):
        self.data["initialized"] = True
        self.set_phase("idle")

    def set_phase(self, name):
        if name not in PHASES:
            raise ValueError("Unknown probe phase")
        self.data["phase"] = name
        self.data["phase_started_monotonic"] = self.clock()

    def poll(self):
        self.data["last_poll_monotonic"] = self.clock()
        self.set_phase("idle")

    def successful_cycle(self):
        self.data["last_successful_cycle_monotonic"] = self.clock()
        self.set_phase("sleep")

    @asynccontextmanager
    async def phase(self, name):
        self.set_phase(name)
        try:
            yield
        except BaseException:
            self.set_phase("failed")
            raise
        else:
            self.set_phase("idle")

    async def publish(self):
        self.data["heartbeat_monotonic"] = self.clock()
        value = json.dumps(self.data, separators=(",", ":"), allow_nan=False).encode()
        if len(value) > 4096:
            raise ValueError("Probe file exceeds byte budget")
        # An exclusive, process-owned temporary path cannot follow a substituted link.
        path = self.root / (self.stage + ".json")
        temporary = self.root / (self.stage + "." + self.data["instance_uuid"] + ".tmp")

        def write():
            private_directory(self.root)
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                with os.fdopen(descriptor, "wb") as file:
                    file.write(value)
                    file.flush()
                os.replace(temporary, path)
            finally:
                with suppress(FileNotFoundError):
                    temporary.unlink()

        async with asyncio.timeout(2):
            await asyncio.to_thread(write)

    async def heartbeat(self):
        interval = budget("SHADAI_PROBE_HEARTBEAT_SECONDS", 5, 1, 5)
        while True:
            await asyncio.sleep(interval)
            await self.publish()


def read_probe(stage, *, root=ROOT, proc=Path("/proc"), now=None):
    if stage not in STAGES:
        raise ValueError("Unknown probe stage")
    root = Path(root)
    metadata = root.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700 or metadata.st_uid != os.getuid():
        raise ValueError("Unsafe probe directory")
    descriptor = os.open(root / (stage + ".json"), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
            or info.st_uid != os.getuid()
            or info.st_size > 4096
        ):
            raise ValueError("Unsafe probe file")
        with os.fdopen(descriptor, "rb", closefd=False) as file:

            def unique(pairs):
                result = {}
                for key, item in pairs:
                    if key in result:
                        raise ValueError("Duplicate probe field")
                    result[key] = item
                return result

            value = json.loads(file.read(4097), object_pairs_hook=unique)
    finally:
        os.close(descriptor)
    return validate_probe(value, stage, proc=proc, now=now)


def validate_probe(value, stage, *, proc=Path("/proc"), now=None):
    if (
        not isinstance(value, dict)
        or set(value) != FIELDS
        or type(value["schema"]) is not int
        or value["schema"] != 1
        or value["stage"] != stage
    ):
        raise ValueError("Invalid probe schema")
    if type(value["pid"]) is not int or value["pid"] <= 0 or type(value["initialized"]) is not bool:
        raise ValueError("Invalid probe identity")
    ticks, boot = identity(value["pid"], Path(proc))
    if type(value["start_ticks"]) is not int or (value["start_ticks"], value["boot_id"]) != (ticks, boot):
        raise ValueError("Probe PID reused or host rebooted")
    from uuid import UUID

    UUID(value["instance_uuid"])
    if value["phase"] not in PHASES:
        raise ValueError("Invalid probe phase")
    now = time.monotonic() if now is None else now
    for field in (
        "heartbeat_monotonic",
        "last_poll_monotonic",
        "phase_started_monotonic",
        "last_successful_cycle_monotonic",
    ):
        moment = value[field]
        if moment is None and field in {"last_poll_monotonic", "last_successful_cycle_monotonic"}:
            continue
        if type(moment) not in {int, float} or not math.isfinite(moment) or not 0 <= moment <= now:
            raise ValueError("Invalid or future probe time")
    return value, now


def local_check(mode, stage, **kwargs):
    value, now = read_probe(stage, **kwargs)
    if not value["initialized"]:
        return False
    if mode == "startup":
        return True
    if now - value["heartbeat_monotonic"] > budget("SHADAI_PROBE_LIVE_SECONDS", 30, 10, 30):
        return False
    if mode == "liveness":
        return True
    if mode != "readiness" or value["phase"] in {"starting", "blocked", "failed"}:
        return False
    if stage == "purge":
        cycle = value["last_successful_cycle_monotonic"]
        if cycle is None or now - cycle > budget("SHADAI_PROBE_PURGE_CYCLE_SECONDS", 97200, 86400, 97200):
            return False
        maximum = 3600 if value["phase"] == "purge" else 97200
        return now - value["phase_started_monotonic"] <= maximum
    if value["phase"] == "handler":
        return now - value["phase_started_monotonic"] <= budget("SHADAI_PROBE_HANDLER_SECONDS", 300, 10, 300)
    poll = value["last_poll_monotonic"]
    return poll is not None and now - poll <= budget("SHADAI_PROBE_POLL_SECONDS", 90, 10, 90)


async def dependencies_ready(stage):
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    from shadai.config import load_config
    from shadai.database import init_clickhouse

    config = load_config()
    engine = create_async_engine(config.database.postgres_url)
    ch = None
    redis = None
    try:
        async with asyncio.timeout(4):
            async with engine.connect() as connection:
                await connection.execute(text("SELECT 1"))
            if stage != "purge":
                import redis.asyncio as aioredis

                redis = aioredis.from_url(config.database.redis_url, decode_responses=True)
                await redis.ping()
                from shadai.workers.redis_lifecycle import retention_ready

                if not await retention_ready(redis):
                    return False
                from shadai.utils.operations import STAGES, stream_snapshot

                operation = STAGES.get(stage)
                if operation is None:
                    return False
                group, streams = operation
                clock = await redis.time()
                server_now = clock[0] + clock[1] / 1000000
                for stream in streams:
                    groups = await redis.xinfo_groups(stream)
                    found = [item for item in groups if item["name"] == group]
                    if len(found) != 1 or found[0].get("lag") is None:
                        return False
                    health = await stream_snapshot(redis, group, stream, server_now)
                    if health["status"] in {"blocked", "unknown", "stale"}:
                        return False
                    # PEL is visible work, not a fictional empty queue; local
                    # handler progress governs readiness while it is being handled.
            if stage in {"ingest", "purge"}:
                ch = init_clickhouse(config.database)
                await asyncio.to_thread(ch.execute, "SELECT 1")
        return True
    except Exception:
        return False
    finally:
        if redis:
            await redis.aclose()
        if ch:
            ch.disconnect()
        await engine.dispose()


def main(argv=None):
    parser = argparse.ArgumentParser(description="Private per-process worker probe")
    parser.add_argument("mode", choices=("startup", "liveness", "readiness"))
    parser.add_argument("--stage", required=True, choices=sorted(STAGES))
    args = parser.parse_args(argv)
    import signal

    # Readiness runs in a separate exec process. Bound DNS, driver threads and
    # cleanup as well as asyncio awaits; the worker's own liveness has no I/O.
    if args.mode == "readiness" and hasattr(signal, "setitimer"):
        signal.signal(signal.SIGALRM, lambda *_: os._exit(1))
        signal.setitimer(signal.ITIMER_REAL, 5)
    try:
        healthy = local_check(args.mode, args.stage)
        if healthy and args.mode == "readiness":
            healthy = asyncio.run(dependencies_ready(args.stage))
        return 0 if healthy else 1
    except Exception:
        return 1
    finally:
        if args.mode == "readiness" and hasattr(signal, "setitimer"):
            signal.setitimer(signal.ITIMER_REAL, 0)


if __name__ == "__main__":
    raise SystemExit(main())
