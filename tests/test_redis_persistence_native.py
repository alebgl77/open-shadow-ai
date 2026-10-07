"""Required Linux proof on an exclusively owned digest-pinned Redis AOF store."""

import asyncio
import json
import os
import platform
import re
import shutil
import subprocess
import time
from uuid import uuid4

import pytest
from redis._parsers.helpers import parse_info as decode_info

from shadai.qualification.redis_persistence import parse_info, redis_persistence
from shadai.qualification.schemas import QualificationError
from shadai.workers.streams import StreamConsumer

IMAGE = "redis:7.4.11-alpine3.21@sha256:858f009f9709ce576febc734aa78b8f6d624b82571f9ddb6bda4377c833b3499"
LABEL = "shadai.redis-persistence-test"


class OwnedRedis:
    """A bounded nonce lease; no ports, foreign containers or shared store data."""

    def __init__(self):
        __tracebackhide__ = True
        self.nonce = uuid4().hex
        self.name = "shadai-redis-persistence-" + self.nonce
        self.volume = self.name + "-data"
        self.deadline = time.monotonic() + 180
        self.container_identity = self.volume_identity = None
        self.created_container = self.created_volume = False

    def call(self, *args, absent=False, readiness=False):
        __tracebackhide__ = True
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise QualificationError("Native Redis lease exhausted")
        try:
            process = subprocess.run(["docker", *args], capture_output=True, timeout=min(30, remaining), check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise QualificationError("Native Redis command unavailable") from None
        if time.monotonic() >= self.deadline:
            raise QualificationError("Native Redis lease exhausted")
        if len(process.stdout) + len(process.stderr) > 65536:
            raise QualificationError("Native Redis output budget refused")
        if process.returncode:
            # Absence is confirmed using the daemon's closed inspect error, never
            # inferred from transport failure or generic nonzero exit status.
            if absent and process.returncode == 1 and len(args) == 3 and (
                (args[:2] == ("container", "inspect") and (
                    process.stderr.strip() == f"Error: No such container: {args[-1]}".encode()
                    or process.stderr.strip() == f"Error response from daemon: No such container: {args[-1]}".encode()
                ))
                or (args[:2] == ("volume", "inspect") and
                    process.stderr.strip() == f"Error response from daemon: get {args[-1]}: no such volume".encode())
            ):
                return None
            if (readiness and process.returncode == 1 and process.stderr.strip()
                    == b"Could not connect to Redis at 127.0.0.1:6379: Connection refused"):
                return None
            raise QualificationError("Native Redis command refused")
        try:
            return process.stdout.decode("utf-8")
        except UnicodeError:
            raise QualificationError("Native Redis output refused") from None

    def inspect(self, kind, identity, *, absent=False):
        __tracebackhide__ = True
        output = self.call(kind, "inspect", identity, absent=absent)
        if output is None:
            return None
        try:
            rows = json.loads(output)
        except (ValueError, TypeError):
            raise QualificationError("Native Redis identity refused") from None
        if type(rows) is not list or len(rows) != 1 or type(rows[0]) is not dict:
            raise QualificationError("Native Redis identity refused")
        return rows[0]

    def volume_record(self, value):
        __tracebackhide__ = True
        if (value.get("Name") != self.volume or value.get("Driver") != "local"
                or value.get("Scope") != "local" or value.get("Labels") != {LABEL: self.nonce}
                or type(value.get("CreatedAt")) is not str):
            raise QualificationError("Native Redis volume lease refused")
        return {key: value[key] for key in ("Name", "Driver", "Scope", "Labels", "CreatedAt")}

    def container_record(self, value):
        __tracebackhide__ = True
        identifier, image = value.get("Id"), value.get("Image")
        if (type(identifier) is not str or re.fullmatch(r"[0-9a-f]{64}", identifier) is None
                or type(image) is not str or re.fullmatch(r"sha256:[0-9a-f]{64}", image) is None
                or value.get("Name") != "/" + self.name or type(value.get("Created")) is not str
                or value.get("Config", {}).get("Labels") != {LABEL: self.nonce}
                or value.get("Config", {}).get("Image") != IMAGE
                or value.get("HostConfig", {}).get("NetworkMode") != "none"
                or len(value.get("Mounts", [])) != 1
                or value["Mounts"][0].get("Type") != "volume"
                or value["Mounts"][0].get("Name") != self.volume
                or value["Mounts"][0].get("Destination") != "/data"
                or value["Mounts"][0].get("RW") is not True):
            raise QualificationError("Native Redis container lease refused")
        return {key: value[key] for key in ("Id", "Image", "Name", "Created")}

    def verify(self):
        __tracebackhide__ = True
        volume = self.volume_record(self.inspect("volume", self.volume))
        container = self.container_record(self.inspect("container", self.container_identity["Id"]))
        if volume != self.volume_identity or container != self.container_identity:
            raise QualificationError("Native Redis lease changed")

    def start(self):
        __tracebackhide__ = True
        if shutil.which("docker") is None:
            raise QualificationError("Required native Redis Docker prerequisite absent")
        self.call("info", "--format", "{{json .ServerVersion}}")
        if (self.inspect("container", self.name, absent=True) is not None
                or self.inspect("volume", self.volume, absent=True) is not None):
            raise QualificationError("Native Redis lease collision")
        self.created_volume = True
        self.call("volume", "create", "--label", LABEL + "=" + self.nonce, self.volume)
        self.volume_identity = self.volume_record(self.inspect("volume", self.volume))
        # Pull/create uses only this approved content digest; no image tag is mutable.
        self.created_container = True
        self.call("container", "create", "--name", self.name, "--network", "none",
                  "--label", LABEL + "=" + self.nonce, "--mount", "type=volume,src=" + self.volume + ",dst=/data",
                  IMAGE, "redis-server", "--appendonly", "yes", "--save", "", "--appendfsync", "always",
                  "--aof-use-rdb-preamble", "no", "--auto-aof-rewrite-percentage", "0")
        self.container_identity = self.container_record(self.inspect("container", self.name))
        self.verify()
        self.call("container", "start", self.container_identity["Id"])
        self.ready()

    def ready(self):
        __tracebackhide__ = True
        # exec may initially precede Redis readiness; this bounded readiness retry
        # never retries the persistence command itself.
        for _ in range(80):
            self.verify()
            output = self.call("container", "exec", self.container_identity["Id"],
                               "redis-cli", "-3", "--json", "PING", readiness=True)
            if output is not None and output.strip() == '"PONG"':
                return
            time.sleep(min(0.25, max(0, self.deadline - time.monotonic())))
        raise QualificationError("Native Redis readiness refused")

    def command(self, *args, raw=False):
        __tracebackhide__ = True
        self.verify()
        output = self.call("container", "exec", self.container_identity["Id"],
                           "redis-cli", "-3", "--raw" if raw else "--json", *map(str, args))
        if raw:
            return output
        try:
            return json.loads(output)
        except (ValueError, TypeError):
            raise QualificationError("Native Redis command response refused") from None

    async def info(self, *sections):
        __tracebackhide__ = True
        return decode_info(await asyncio.to_thread(self.command, "INFO", *sections, raw=True))

    async def bgrewriteaof(self):
        __tracebackhide__ = True
        return await asyncio.to_thread(self.command, "BGREWRITEAOF")

    async def xgroup_create(self, stream, group, *, id, mkstream):
        __tracebackhide__ = True
        assert mkstream is True
        return await asyncio.to_thread(self.command, "XGROUP", "CREATE", stream, group, id, "MKSTREAM")

    async def xgroup_createconsumer(self, stream, group, consumer):
        __tracebackhide__ = True
        return await asyncio.to_thread(self.command, "XGROUP", "CREATECONSUMER", stream, group, consumer)

    async def xautoclaim(self, stream, group, consumer, idle, *, start_id, count):
        __tracebackhide__ = True
        return await asyncio.to_thread(self.command, "XAUTOCLAIM", stream, group, consumer, idle,
                                       start_id, "COUNT", count)

    async def xreadgroup(self, group, consumer, streams, *, count, block):
        __tracebackhide__ = True
        return await asyncio.to_thread(self.command, "XREADGROUP", "GROUP", group, consumer,
                                       "COUNT", count, "BLOCK", block, "STREAMS", *streams, *streams.values())

    def groups(self):
        __tracebackhide__ = True
        return self.command("XINFO", "GROUPS", "events:dns")

    def restart(self):
        __tracebackhide__ = True
        self.verify()
        self.call("container", "stop", "--time", "5", self.container_identity["Id"])
        self.verify()
        self.call("container", "start", self.container_identity["Id"])
        self.ready()

    def close(self):
        __tracebackhide__ = True
        # Cleanup gets a bounded independent lease and must prove absence; no
        # successful native case can hide failed identity/removal/absence proof.
        self.deadline = time.monotonic() + 30
        if self.created_container:
            inspected = self.inspect("container", self.name, absent=True)
            if inspected is not None:
                current = self.container_record(inspected)
                if self.container_identity is not None and current != self.container_identity:
                    raise QualificationError("Native Redis cleanup identity refused")
                self.call("container", "rm", "--force", current["Id"])
                if self.inspect("container", current["Id"], absent=True) is not None:
                    raise QualificationError("Native Redis container cleanup unconfirmed")
        if self.created_volume:
            inspected = self.inspect("volume", self.volume, absent=True)
            if inspected is not None:
                current = self.volume_record(inspected)
                if self.volume_identity is not None and current != self.volume_identity:
                    raise QualificationError("Native Redis cleanup identity refused")
                self.call("volume", "rm", self.volume)
                if self.inspect("volume", self.volume, absent=True) is not None:
                    raise QualificationError("Native Redis volume cleanup unconfirmed")


@pytest.fixture
def native_redis():
    if platform.system() != "Linux":
        if os.environ.get("SHADAI_REQUIRE_REDIS_PERSISTENCE") == "1":
            pytest.fail("Required Redis persistence native platform absent")
        pytest.skip("Redis persistence native proof requires Linux")
    yield from _native_fixture_boundary()


def _native_refusal():
    raise QualificationError("Native Redis persistence proof refused") from None


def _private_native_redis_lifecycle():
    __tracebackhide__ = True
    owned = OwnedRedis()
    cancelled = None
    try:
        owned.start()
        yield owned
    except BaseException as error:
        if not isinstance(error, (Exception, GeneratorExit)):
            cancelled = error
        raise
    finally:
        try:
            owned.close()
        except BaseException:
            if cancelled is None:
                raise


def _native_fixture_boundary():
    lifecycle = _private_native_redis_lifecycle()
    failed = False
    try:
        try:
            yield next(lifecycle)
        finally:
            lifecycle.close()
    except Exception:
        failed = True
    finally:
        del lifecycle
    if failed:
        _native_refusal()


@pytest.mark.parametrize("repair", ["unregistered", "registered", "checkpoint"])
async def test_native_empty_consumer_aof_restart(repair, native_redis):
    failed = False
    try:
        await _private_native_empty_consumer_aof_restart(repair, native_redis)
    except Exception:
        failed = True
    finally:
        del native_redis
    if failed:
        _native_refusal()


async def _private_native_empty_consumer_aof_restart(repair, native_redis):
    __tracebackhide__ = True
    store = native_redis
    consumer = StreamConsumer(store, "group", "empty-worker", ["events:dns"])
    await consumer.initialize()
    original = parse_info(await store.info("server", "persistence"))
    enabled = original["aof_enabled"] == 1
    assert enabled is True
    snapshots_disabled = store.command("CONFIG", "GET", "save") == {"save": ""}
    assert snapshots_disabled is True
    if repair == "registered":
        await consumer.read()
    else:
        await store.xautoclaim("events:dns", "group", "empty-worker", 0, start_id="0-0", count=50)
    if repair == "checkpoint":
        complete = await redis_persistence(store)
        assert complete == {"redis_persistence_complete": True}
    before = store.groups()
    # Compare the entire private records without pytest rewriting their values.
    has_empty_consumer = len(before) == 1 and before[0]["consumers"] == 1 and before[0]["pending"] == 0
    assert has_empty_consumer is True
    store.restart()
    restored_info = parse_info(await store.info("server", "persistence"))
    new_process = original["run_id"] != restored_info["run_id"]
    assert new_process is True
    equal = before == store.groups()
    if repair == "unregistered":
        # This is an expected reproduced defect, retained alongside both repairs.
        assert equal is False, "Unregistered empty-claim restart defect must be reproduced"
    else:
        assert equal is True, "Complete private group records must survive the repaired restart"


def test_native_digest_and_lease_are_fixed_private_and_distinct():
    first, second = OwnedRedis(), OwnedRedis()
    assert first.name != second.name and first.volume != second.volume
    assert re.fullmatch(r"[0-9a-f]{32}", first.nonce)
    assert IMAGE.endswith("@sha256:858f009f9709ce576febc734aa78b8f6d624b82571f9ddb6bda4377c833b3499")


@pytest.mark.parametrize("status,stderr", [
    (1, b"private transport detail"), (2, b"Error: No such container: synthetic"),
    (1, b"Error: No such container: foreign"),
])
def test_native_absence_does_not_hide_transport_or_wrong_identity(monkeypatch, status, stderr):
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: subprocess.CompletedProcess(
        [], status, b"", stderr
    ))
    with pytest.raises(QualificationError, match="command refused") as caught:
        OwnedRedis().call("container", "inspect", "synthetic", absent=True)
    assert "private" not in str(caught.value) and "foreign" not in str(caught.value)


@pytest.mark.parametrize("kind,stderr", [
    ("container", b"Error: No such container: synthetic"),
    ("container", b"Error response from daemon: No such container: synthetic"),
    ("volume", b"Error response from daemon: get synthetic: no such volume"),
])
def test_native_absence_is_confirmed_by_closed_daemon_response(monkeypatch, kind, stderr):
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: subprocess.CompletedProcess([], 1, b"[]", stderr))
    assert OwnedRedis().inspect(kind, "synthetic", absent=True) is None


@pytest.mark.parametrize("kind,stderr", [
    ("volume", b"Error: No such container: synthetic"),
    ("volume", b"Error response from daemon: No such container: synthetic"),
    ("container", b"Error response from daemon: get synthetic: no such volume"),
])
def test_native_absence_refuses_cross_kind_response(monkeypatch, kind, stderr):
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: subprocess.CompletedProcess([], 1, b"[]", stderr))
    with pytest.raises(QualificationError, match="command refused"):
        OwnedRedis().call(kind, "inspect", "synthetic", absent=True)


@pytest.mark.parametrize("stderr", [
    b"Error: No such container: synthetic",
    b"Error response from daemon: No such container: synthetic",
    b"Error response from daemon: get synthetic: no such volume",
])
@pytest.mark.parametrize("args", [
    ("container", "rm", "synthetic"), ("volume", "rm", "synthetic"),
    ("image", "inspect", "synthetic"), ("network", "inspect", "synthetic"),
    ("inspect", "synthetic"), ("container", "inspect", "--type", "synthetic"), (),
])
def test_native_absence_refuses_other_operations(monkeypatch, args, stderr):
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: subprocess.CompletedProcess([], 1, b"[]", stderr))
    with pytest.raises(QualificationError, match="command refused"):
        OwnedRedis().call(*args, absent=True)


@pytest.mark.parametrize("failure", [OSError("private detail"), subprocess.TimeoutExpired(["private"], 1)])
def test_native_command_failure_does_not_publish_command_or_output(monkeypatch, failure):
    def runner(*args, **kwargs):
        raise failure
    monkeypatch.setattr(subprocess, "run", runner)
    with pytest.raises(QualificationError) as caught:
        OwnedRedis().call("container", "inspect", "synthetic", absent=True)
    assert str(caught.value) == "Native Redis command unavailable"


@pytest.mark.parametrize("side", ["stdout", "stderr"])
def test_native_output_is_bounded_before_decode(monkeypatch, side):
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: subprocess.CompletedProcess(
        [], 0, b"x" * 65537 if side == "stdout" else b"", b"x" * 65537 if side == "stderr" else b""
    ))
    with pytest.raises(QualificationError, match="output budget"):
        OwnedRedis().call("container", "inspect", "synthetic")


def owned_records(owned):
    volume = {"Name": owned.volume, "Driver": "local", "Scope": "local", "Labels": {LABEL: owned.nonce},
              "CreatedAt": "synthetic-created"}
    container = {"Id": "a" * 64, "Image": "sha256:" + "b" * 64, "Name": "/" + owned.name,
                 "Created": "synthetic-created", "Config": {"Image": IMAGE, "Labels": {LABEL: owned.nonce}},
                 "HostConfig": {"NetworkMode": "none"},
                 "Mounts": [{"Type": "volume", "Name": owned.volume, "Destination": "/data", "RW": True}]}
    return volume, container


@pytest.mark.parametrize("kind,field", [
    ("volume", "Name"), ("volume", "Labels"), ("volume", "Driver"), ("volume", "Scope"),
    ("container", "Id"), ("container", "Image"), ("container", "Name"), ("container", "Labels"),
    ("container", "NetworkMode"), ("container", "Mounts"), ("container", "ConfiguredImage"),
])
def test_native_lease_refuses_foreign_identity_before_mutation(kind, field):
    owned = OwnedRedis()
    volume, container = owned_records(owned)
    target = volume if kind == "volume" else container
    if field == "Labels" and kind == "container":
        target["Config"]["Labels"] = {LABEL: "foreign"}
    elif field == "NetworkMode":
        target["HostConfig"][field] = "bridge"
    elif field == "ConfiguredImage":
        target["Config"]["Image"] = "redis:latest"
    else:
        target[field] = "foreign"
    with pytest.raises(QualificationError):
        (owned.volume_record if kind == "volume" else owned.container_record)(target)


@pytest.mark.parametrize("failure", ["identity", "remove", "absence"])
@pytest.mark.parametrize("kind", ["container", "volume"])
def test_native_cleanup_failures_cannot_pass_or_touch_foreign_resources(monkeypatch, kind, failure):
    owned = OwnedRedis()
    volume, container = owned_records(owned)
    owned.volume_identity = owned.volume_record(volume)
    owned.container_identity = owned.container_record(container)
    owned.created_volume = kind == "volume"
    owned.created_container = kind == "container"
    record, calls = (volume if kind == "volume" else container), []
    if failure == "identity":
        record = {**record, "CreatedAt" if kind == "volume" else "Created": "changed"}
    monkeypatch.setattr(owned, "inspect", lambda *args, **kwargs: record)
    def call(*args, **kwargs):
        calls.append(args)
        if failure == "remove":
            raise QualificationError("Synthetic removal refused")
        return ""
    monkeypatch.setattr(owned, "call", call)
    with pytest.raises(QualificationError):
        owned.close()
    assert bool(calls) is (failure != "identity")


def test_native_partial_creation_absence_has_no_removal(monkeypatch):
    owned = OwnedRedis()
    owned.created_volume = owned.created_container = True
    calls = []
    monkeypatch.setattr(owned, "inspect", lambda *args, **kwargs: None)
    monkeypatch.setattr(owned, "call", lambda *args, **kwargs: calls.append(args))
    owned.close()
    assert calls == []


NATIVE_CANARIES = ("SYNTHETIC_INFO_CANARY", "f" * 40, "SYNTHETIC_GROUP_CANARY",
                   "SYNTHETIC_PAYLOAD_CANARY", "SYNTHETIC_STDERR_CANARY")


def refusal_format(error, boundary, style, showlocals, fulltrace):
    # Drop only this synthetic test's caller, as the real pytest invocation
    # begins at the public proof/fixture boundary and contains no test canaries.
    trace = error.__traceback__
    while trace.tb_frame.f_code.co_name != boundary:
        trace = trace.tb_next
    exception = pytest.ExceptionInfo.from_exc_info((type(error), error, trace))
    return str(exception.getrepr(style=style, showlocals=showlocals, tbfilter=not fulltrace))


def assert_sanitized_boundary(error, boundary, style, showlocals, fulltrace):
    assert error.args == ("Native Redis persistence proof refused",)
    assert error.__cause__ is error.__context__ is None
    rendered = refusal_format(error, boundary, style, showlocals, fulltrace)
    assert not any(canary in rendered for canary in NATIVE_CANARIES)
    trace = error.__traceback__
    while trace.tb_frame.f_code.co_name != boundary:
        trace = trace.tb_next
    while trace is not None:
        assert not {"native_redis", "owned", "lifecycle", "store", "consumer", "original",
                    "before", "restored_info", "error"}.intersection(trace.tb_frame.f_locals)
        trace = trace.tb_next


@pytest.mark.parametrize("style", ["short", "long"])
@pytest.mark.parametrize("showlocals", [False, True])
@pytest.mark.parametrize("fulltrace", [False, True])
async def test_native_public_proof_failure_formats_exclude_every_private_frame(
    monkeypatch, style, showlocals, fulltrace
):
    class Client:
        def __repr__(self):
            return " ".join(NATIVE_CANARIES)
    async def private_failure(repair, native_redis):
        __tracebackhide__ = True
        original = {"run_id": NATIVE_CANARIES[1], "info": NATIVE_CANARIES[0]}
        before = [{"group": NATIVE_CANARIES[2], "payload": NATIVE_CANARIES[3]}]
        stderr = NATIVE_CANARIES[4]
        raise QualificationError(str(original) + str(before) + stderr)
    monkeypatch.setitem(globals(), "_private_native_empty_consumer_aof_restart", private_failure)
    with pytest.raises(QualificationError) as caught:
        await test_native_empty_consumer_aof_restart("checkpoint", Client())
    assert_sanitized_boundary(caught.value, "test_native_empty_consumer_aof_restart", style, showlocals, fulltrace)


@pytest.mark.parametrize("during", ["startup", "cleanup"])
@pytest.mark.parametrize("style", ["short", "long"])
@pytest.mark.parametrize("showlocals", [False, True])
@pytest.mark.parametrize("fulltrace", [False, True])
def test_native_public_fixture_failure_formats_exclude_private_startup_and_cleanup(
    monkeypatch, during, style, showlocals, fulltrace
):
    calls = []
    class Client:
        def __init__(self):
            self.info = {"run_id": NATIVE_CANARIES[1], "metadata": NATIVE_CANARIES[0]}
            self.groups = [{"name": NATIVE_CANARIES[2], "payload": NATIVE_CANARIES[3]}]
            self.stderr = NATIVE_CANARIES[4]

        def __repr__(self):
            return " ".join(NATIVE_CANARIES)

        def start(self):
            __tracebackhide__ = True
            calls.append("start")
            if during == "startup":
                raise QualificationError(str(self.info) + str(self.groups) + self.stderr)

        def close(self):
            __tracebackhide__ = True
            calls.append("close")
            if during == "cleanup":
                raise QualificationError(str(self.info) + str(self.groups) + self.stderr)

    monkeypatch.setitem(globals(), "OwnedRedis", Client)
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    lifecycle = native_redis.__wrapped__()
    if during == "cleanup":
        next(lifecycle)
    with pytest.raises(QualificationError) as caught:
        next(lifecycle)
    assert calls == ["start", "close"]
    assert_sanitized_boundary(caught.value, "native_redis", style, showlocals, fulltrace)


@pytest.mark.parametrize("kind", [asyncio.CancelledError, KeyboardInterrupt, SystemExit])
async def test_native_proof_cancellation_keeps_original_identity(monkeypatch, kind):
    cancellation = kind("Synthetic cancellation")
    async def private_failure(*args):
        raise cancellation
    monkeypatch.setitem(globals(), "_private_native_empty_consumer_aof_restart", private_failure)
    with pytest.raises(kind) as caught:
        await test_native_empty_consumer_aof_restart("checkpoint", object())
    assert caught.value is cancellation


@pytest.mark.parametrize("kind", [asyncio.CancelledError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("during", ["startup", "cleanup"])
@pytest.mark.parametrize("cleanup_error", [False, True])
def test_native_fixture_cancellation_keeps_identity_and_always_cleans(monkeypatch, kind, during, cleanup_error):
    cancellation = kind("Synthetic cancellation")
    calls = []
    class Client:
        def start(self):
            calls.append("start")
            if during == "startup":
                raise cancellation

        def close(self):
            calls.append("close")
            if during == "cleanup":
                raise cancellation
            if cleanup_error:
                raise QualificationError("Synthetic cleanup error")
    monkeypatch.setitem(globals(), "OwnedRedis", Client)
    with pytest.raises(kind) as caught:
        lifecycle = _native_fixture_boundary()
        if during == "cleanup":
            next(lifecycle)
        next(lifecycle)
    assert caught.value is cancellation and calls == ["start", "close"]
    if during == "startup" and cleanup_error:
        assert not hasattr(cancellation, "__notes__")


@pytest.mark.parametrize("kind", [asyncio.CancelledError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("notes", ["malformed", "hostile"])
def test_native_fixture_cancellation_does_not_invoke_notes_protocol(monkeypatch, kind, notes):
    calls, note_reads = [], []
    if notes == "hostile":
        class Cancellation(kind):
            @property
            def __notes__(self):
                note_reads.append("__notes__")
                raise RuntimeError("Synthetic notes error")
        cancellation = Cancellation("Synthetic cancellation")
    else:
        cancellation = kind("Synthetic cancellation")
        cancellation.__notes__ = 0

    class Client:
        def start(self):
            calls.append("start")
            raise cancellation

        def close(self):
            calls.append("close")
            raise QualificationError("Synthetic cleanup error")
    monkeypatch.setitem(globals(), "OwnedRedis", Client)
    with pytest.raises(kind) as caught:
        next(_native_fixture_boundary())
    assert caught.value is cancellation
    assert calls == ["start", "close"] and note_reads == []
