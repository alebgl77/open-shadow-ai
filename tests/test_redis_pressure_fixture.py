"""Finite dedicated-lab pressure injection and cleanup, with a request-buffer model."""

import asyncio
from types import SimpleNamespace

import pytest
import redis_pressure_fixture as fixture
from redis.exceptions import OutOfMemoryError


class PressureModel:
    """Model the documented pre-command heap check, not a Redis capacity proof."""

    def __init__(self):
        self.connection_pool = SimpleNamespace(connection_kwargs={"host": "labredis-pressure", "port": 6379, "db": 0})
        self.limit = fixture.ORIGINAL_LIMIT
        self.heap = fixture.PRESSURE_MARGIN - 512
        self.values = {"foreign:sentinel": "preserve"}
        self.calls, self.failures = [], {}
        self.injected, self.restoring = False, False
        self.memory_override = None
        self.pause_restore = None
        self.pause_set = None
        self.streams = {}

    async def set(self, key, value, **kwargs):
        self.calls.append(("set", key, kwargs))
        if self.heap + len(value) + 64 > self.limit:
            raise OutOfMemoryError("synthetic query buffer exceeds maxmemory")
        self.values[key] = value
        self.heap += len(value)
        if self.pause_set:
            await self.pause_set.wait()
        if "set" in self.failures:
            raise self.failures["set"]
        return True

    async def exists(self, *keys):
        self.calls.append(("exists", keys))
        return sum(key in self.values for key in keys)

    async def config_get(self, *keys):
        self.calls.append(("config_get", keys))
        if self.restoring and "verify" in self.failures:
            raise self.failures["verify"]
        return {"maxmemory": str(self.limit), "maxmemory-policy": "noeviction", "appendonly": "yes"}

    async def config_set(self, key, value):
        self.calls.append(("config_set", key, value))
        if value == fixture.ORIGINAL_LIMIT:
            self.restoring = True
            if self.pause_restore:
                self.pause_restore[0].set()
                await self.pause_restore[1].wait()
            if "restore" in self.failures:
                raise self.failures["restore"]
        else:
            self.injected = True
        self.limit = value
        if value != fixture.ORIGINAL_LIMIT and "inject" in self.failures:
            raise self.failures["inject"]  # The write happened; the reply was lost.
        return True

    async def info(self, section):
        self.calls.append(("info", section))
        if section == "persistence":
            return {"aof_enabled": 1, "aof_last_write_status": "ok"}
        return self.memory_override or {"used_memory": self.heap, "mem_not_counted_for_evict": 0}

    async def delete(self, *keys):
        self.calls.append(("delete", keys))
        if "delete" in self.failures:
            raise self.failures["delete"]
        for key in keys:
            self.heap -= len(self.values.pop(key, ""))
            self.streams.pop(key, None)
        return len(keys)

    async def dbsize(self):
        return len(self.values) + len(self.streams)

    async def eval(self, script, numkeys, *values):
        if self.heap > self.limit:
            raise OutOfMemoryError("synthetic pre-command refusal")
        keys, arguments = values[:numkeys], values[numkeys:]
        count, position, identifiers = int(arguments[0]), 3, []
        for index in range(count):
            destination, pairs = int(arguments[position]), int(arguments[position + 1])
            position += 2
            fields = dict(zip(arguments[position:position + pairs * 2:2],
                              arguments[position + 1:position + pairs * 2:2], strict=True))
            position += pairs * 2
            ident = str(index + 1) + "-0"
            self.streams.setdefault(keys[destination - 1], []).append((ident, fields))
            identifiers.append(ident)
        return ["ok", *identifiers]

    async def xlen(self, stream):
        return len(self.streams.get(stream, []))

    async def xrange(self, stream, start, end):
        return [row for row in self.streams.get(stream, []) if row[0] == start == end]


@pytest.fixture
def model(monkeypatch):
    monkeypatch.setenv("SHADAI_REQUIRE_REDIS_PRESSURE", "1")
    monkeypatch.setenv("SHADAI_REDIS_PRESSURE_HOST", "labredis-pressure")
    monkeypatch.setenv("SHADAI_REDIS_PRESSURE_PORT", "6379")
    return PressureModel()


def pressure(model):
    return fixture.sustained_pressure(model, prefix="pressure:fill:", chunk_bytes=256 * 1024, max_fill=256)


def assert_clean(model):
    assert model.limit == fixture.ORIGINAL_LIMIT
    assert model.values == {"foreign:sentinel": "preserve"}
    assert any(call[0] == "delete" for call in model.calls)
    assert any(call[0] == "config_get" for call in model.calls if model.restoring)


async def test_request_buffer_dead_end_then_controlled_real_command_refusal_and_recovery(model):
    old = PressureModel()
    for index in range(256):
        try:
            await old.set("old-owned:" + str(index), "x" * (256 * 1024))
        except OutOfMemoryError:
            break
    stable_heap = old.heap
    assert stable_heap < old.limit
    refused = 0
    for index in range(2048):
        try:
            await old.set("old-topup:" + str(index), "x" * 512)
        except OutOfMemoryError:
            refused += 1
    assert refused == 2048 and old.heap == stable_heap

    async with pressure(model) as proof:
        assert proof["post_fill_heap_bytes"] == fixture.ORIGINAL_LIMIT - 512
        assert proof["pressure_heap_bytes"] > proof["injected_maxmemory_bytes"]
        assert proof["injected_maxmemory_bytes"] == proof["post_fill_heap_bytes"] - fixture.PRESSURE_MARGIN
        with pytest.raises(OutOfMemoryError):
            await model.set("application:new-state", "new")
        assert "application:new-state" not in model.values
        assert model.values["foreign:sentinel"] == "preserve"
        assert all(not call[2] for call in model.calls if call[0] == "set")  # No filler TTL races.
    assert proof["restored_maxmemory_bytes"] == fixture.ORIGINAL_LIMIT
    assert_clean(model)
    assert await model.set("application:new-state", "new")


@pytest.mark.parametrize("field,value", [("host", "normal-redis"), ("port", 6380), ("db", 14)])
async def test_foreign_target_refused_before_any_redis_command(model, field, value):
    model.connection_pool.connection_kwargs[field] = value
    with pytest.raises(fixture.PressurePrerequisiteError):
        async with pressure(model):
            pytest.fail("Foreign fixture admitted")
    assert not model.calls


@pytest.mark.parametrize("name", ["SHADAI_REQUIRE_REDIS_PRESSURE", "SHADAI_REDIS_PRESSURE_HOST",
                                 "SHADAI_REDIS_PRESSURE_PORT"])
async def test_missing_explicit_target_refused_before_commands(model, monkeypatch, name):
    monkeypatch.delenv(name)
    with pytest.raises(fixture.PressurePrerequisiteError):
        async with pressure(model):
            pytest.fail("Missing fixture admitted")
    assert not model.calls


@pytest.mark.parametrize("prefix,chunk,count", [("events:dns:", 1024, 1), (None, 1024, 1),
                                               ("pressure:fill:", True, 1), ("pressure:fill:", 1024, 257),
                                               ("pressure:fill:", 1024 * 1024, 65)])
async def test_unowned_or_excessive_filler_bounds_refused(model, prefix, chunk, count):
    with pytest.raises(fixture.PressurePrerequisiteError):
        async with fixture.sustained_pressure(model, prefix=prefix, chunk_bytes=chunk, max_fill=count):
            pytest.fail("Invalid filler admitted")
    assert not model.calls


async def test_collision_never_adopted_or_deleted(model):
    model.values["pressure:fill:0"] = "foreign"
    with pytest.raises(fixture.PressurePrerequisiteError, match="collision"):
        async with pressure(model):
            pytest.fail("Collision admitted")
    assert model.values["pressure:fill:0"] == "foreign"
    assert not any(call[0] in {"set", "delete", "config_set"} for call in model.calls)


async def test_wrong_original_limit_never_mutated(model):
    model.limit = 16 * 1024 * 1024
    with pytest.raises(fixture.PressurePrerequisiteError, match="configuration mismatch"):
        async with pressure(model):
            pytest.fail("Wrong policy admitted")
    assert not any(call[0] in {"set", "delete", "config_set"} for call in model.calls)


@pytest.mark.parametrize("field,value", [("maxmemory-policy", "allkeys-lru"), ("appendonly", "no"),
                                       ("aof_enabled", 0), ("aof_enabled", True), ("aof_last_write_status", "err")])
async def test_wrong_policy_or_aof_refused_before_writes(model, field, value, monkeypatch):
    original_config, original_info = model.config_get, model.info

    async def config(*keys):
        result = await original_config(*keys)
        if field in result:
            result[field] = value
        return result

    async def info(section):
        result = await original_info(section)
        if field in result:
            result[field] = value
        return result

    monkeypatch.setattr(model, "config_get", config)
    monkeypatch.setattr(model, "info", info)
    with pytest.raises(fixture.PressurePrerequisiteError):
        async with pressure(model):
            pytest.fail("Invalid policy admitted")
    assert not any(call[0] in {"set", "delete", "config_set"} for call in model.calls)


@pytest.mark.parametrize("memory", [{"used_memory": True}, {"used_memory": 0},
                                   {"used_memory": 65 * 1024 * 1024},
                                   {"used_memory": 100, "mem_not_counted_for_evict": 101}])
async def test_invalid_post_fill_heap_restores_and_cleans(model, memory):
    model.memory_override = memory
    with pytest.raises(fixture.PressurePrerequisiteError):
        async with pressure(model):
            pytest.fail("Invalid heap admitted")
    assert_clean(model)


async def test_heap_below_injected_limit_refuses_body_and_restores(model, monkeypatch):
    original = model.info

    async def info(section):
        if section == "memory" and model.injected:
            return {"used_memory": model.limit, "mem_not_counted_for_evict": 0}
        return await original(section)

    monkeypatch.setattr(model, "info", info)
    with pytest.raises(fixture.PressurePrerequisiteError, match="Sustained pressure not observed"):
        async with pressure(model):
            pytest.fail("Unconfirmed pressure admitted")
    assert_clean(model)


async def test_finite_fill_without_oom_refuses_body_and_cleans(model, monkeypatch):
    async def set_without_oom(key, value):
        model.calls.append(("set", key, {}))
        model.values[key] = value
        model.heap += len(value)
        return True

    monkeypatch.setattr(model, "set", set_without_oom)
    with pytest.raises(fixture.PressurePrerequisiteError, match="Bounded filler did not reach Redis OOM"):
        async with pressure(model):
            pytest.fail("Unbounded fill admitted")
    assert len([call for call in model.calls if call[0] == "set"]) == 256
    assert not model.injected
    assert_clean(model)


@pytest.mark.parametrize("stage", ["set", "inject"])
async def test_lost_write_reply_retains_primary_but_restores_and_cleans(model, stage):
    primary = RuntimeError("synthetic lost reply")
    model.failures[stage] = primary
    with pytest.raises(RuntimeError) as caught:
        async with pressure(model):
            pytest.fail("Lost reply admitted")
    assert caught.value is primary
    assert_clean(model)


@pytest.mark.parametrize("primary", [RuntimeError("synthetic body failure"), asyncio.CancelledError()])
async def test_body_error_or_cancellation_preserves_exact_primary_and_cleans(model, primary):
    with pytest.raises(type(primary)) as caught:
        async with pressure(model):
            raise primary
    assert caught.value is primary
    assert_clean(model)


@pytest.mark.parametrize("failure", ["restore", "delete", "verify"])
@pytest.mark.parametrize("primary", [None, RuntimeError("synthetic body error"), asyncio.CancelledError()])
async def test_cleanup_refusal_is_nonzero_and_does_not_mask_primary(model, failure, primary):
    model.failures[failure] = RuntimeError("synthetic secondary failure")
    expected = fixture.PressurePrerequisiteError if primary is None else type(primary)
    with pytest.raises(expected) as caught:
        async with pressure(model):
            if primary is not None:
                raise primary
    if primary is not None:
        assert caught.value is primary
    assert any(call[0] == "delete" for call in model.calls)
    assert any(call[:2] == ("config_set", "maxmemory") and call[2] == fixture.ORIGINAL_LIMIT for call in model.calls)
    assert getattr(caught.value, "__notes__", [])
    assert all(note.startswith("pressure_") and "synthetic" not in note for note in caught.value.__notes__)
    assert model.values["foreign:sentinel"] == "preserve"


@pytest.mark.parametrize("phase", ["setup", "body", "cleanup"])
async def test_expired_phase_has_independent_restoration_and_release_budget(model, monkeypatch, phase):
    original = asyncio.timeout
    selected = {"setup": 30, "body": 60, "cleanup": 5}[phase]
    monkeypatch.setattr(fixture.asyncio, "timeout", lambda budget: original(.01 if budget == selected else budget))
    if phase == "setup":
        model.pause_set = asyncio.Event()
    if phase == "cleanup":
        model.pause_restore = (asyncio.Event(), asyncio.Event())
    expected = fixture.PressurePrerequisiteError if phase == "cleanup" else TimeoutError
    with pytest.raises(expected):
        async with pressure(model):
            if phase == "body":
                await asyncio.Event().wait()
    assert any(call[0] == "delete" for call in model.calls)
    if phase != "cleanup":
        assert_clean(model)


async def test_cancel_during_cleanup_finishes_both_operations_before_propagating(model):
    started, release = asyncio.Event(), asyncio.Event()
    model.pause_restore = (started, release)

    async def owner():
        async with pressure(model):
            pass

    task = asyncio.create_task(owner())
    await started.wait()
    task.cancel()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert_clean(model)


async def test_actual_queue_pressure_exercise_reaches_unchanged_refusal_and_recovery_assertions(model):
    from test_redis_pressure import exercise_oom

    model.values.clear()
    proof = await exercise_oom(model)
    assert proof["restored_maxmemory_bytes"] == fixture.ORIGINAL_LIMIT
    assert not model.values and not model.streams
    assert model.limit == fixture.ORIGINAL_LIMIT


async def test_sso_outer_cleanup_cannot_mask_injection_primary(model, monkeypatch):
    from test_sso_pressure_integration import test_real_redis_oom_before_allocation_and_owned_release_recovers as run

    primary = RuntimeError("synthetic lost injection reply")
    model.failures.update(inject=primary, restore=RuntimeError("synthetic restore refusal"))
    with pytest.raises(RuntimeError) as caught:
        await run(model, monkeypatch, lambda *args: None)
    assert caught.value is primary
    assert "pressure_restore_failed" in primary.__notes__
    assert "sso_pressure_policy_verification_failed" in primary.__notes__
    assert model.values == {"foreign:sentinel": "preserve"}
