"""Private atomic INFO parsing and bounded single-generation persistence proof."""

import asyncio
import copy
import itertools
import json
from unittest.mock import AsyncMock

import pytest
from redis._parsers.helpers import parse_info as decode_info

from shadai.qualification.redis_persistence import (
    COUNTERS,
    FLAGS,
    MAX_INTEGER,
    MAX_SAMPLES,
    REWRITE_ACKS,
    STATUSES,
    parse_info,
    redis_persistence,
)
from shadai.qualification.schemas import QualificationError

RUN_ID = "a" * 40


def info(**changes):
    value = {key: 0 for key in (*FLAGS, *COUNTERS)}
    value.update(run_id=RUN_ID, aof_enabled=1, aof_rewrites=10)
    value.update({key: "ok" for key in STATUSES})
    value.update(changes)
    return value


class Model:
    def __init__(self, samples, *, ack=True):
        self.samples = iter(samples)
        self.last = info()
        self.now = 0
        self.sleeps = []
        self.info = AsyncMock(side_effect=self.sample)
        self.bgrewriteaof = AsyncMock(return_value=ack)

    def sample(self, *args):
        assert args == ("server", "persistence")
        self.last = next(self.samples, self.last)
        if isinstance(self.last, BaseException):
            raise self.last
        return self.last

    async def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds

    async def run(self):
        return await redis_persistence(self, clock=lambda: self.now, sleep=self.sleep)


def test_parser_accepts_unknown_flat_fields_without_exposing_identity():
    value = info(private_string="private", private_int=-MAX_INTEGER, private_float=0.75)
    assert parse_info(value) is value


@pytest.mark.parametrize("key", [*FLAGS, *COUNTERS, *STATUSES, "run_id"])
def test_parser_requires_all_proof_fields(key):
    value = info()
    del value[key]
    with pytest.raises(QualificationError, match="sample refused"):
        parse_info(value)


@pytest.mark.parametrize("key,bad", [
    *( (key, bad) for key in FLAGS for bad in (True, -1, 2, 0.0, "0") ),
    *( (key, bad) for key in COUNTERS for bad in (True, -1, MAX_INTEGER + 1, 0.0, "0") ),
    *( (key, bad) for key in STATUSES for bad in (True, "OK", "", 0) ),
    *( ("run_id", bad) for bad in (True, "A" * 40, "a" * 39, "a" * 41, "g" * 40) ),
])
def test_required_fields_have_exact_types_and_values(key, bad):
    with pytest.raises(QualificationError):
        parse_info(info(**{key: bad}))


@pytest.mark.parametrize("value", [True, None, (), b"private", float("nan"), float("inf"),
                                    float("-inf"), 1 << 63, -(1 << 63)])
def test_unknown_fields_still_validate_before_state(value):
    with pytest.raises(QualificationError):
        parse_info(info(private_unknown=value))


def test_parser_exact_entry_key_value_integer_and_text_limits():
    base = info()
    for index in range(256 - len(base)):
        base[str(index)] = 0
    assert parse_info(base) is base
    base["overflow"] = 0
    with pytest.raises(QualificationError):
        parse_info(base)
    for value in (info(**{"k" * 128: "v" * 4096}), info(unknown=MAX_INTEGER), info(unknown=-MAX_INTEGER)):
        assert parse_info(value) is value
    for value in (info(**{"k" * 129: 0}), info(unknown="v" * 4097)):
        with pytest.raises(QualificationError):
            parse_info(value)
    value = info()
    for index in range(15):
        value[f"text{index}"] = "v" * 4096
    length = sum(len(key) + (len(item) if type(item) is str else 0) for key, item in value.items())
    value["last"] = "v" * (65536 - length - 4)
    assert parse_info(value) is value
    value["extra"] = ""
    with pytest.raises(QualificationError):
        parse_info(value)


@pytest.mark.parametrize("producer,expected", [
    ("redis_version:7.4.11", str),
    ("listener0:name=tcp,bind=127.0.0.1,port=6379", dict),
    ("listener_aliases:tcp,unix,2,3.5", list),
    ("module:name=synthetic,ver=1,api=1,filters=0", list),
])
def test_pinned_info_decoder_structured_producers_are_retained_unchanged(producer, expected):
    wire = "\r\n".join(f"{key}:{value}" for key, value in info().items()) + "\r\n" + producer + "\r\n"
    decoded = decode_info(wire)
    key = "modules" if producer.startswith("module:") else producer.split(":", 1)[0]
    snapshot = copy.deepcopy(decoded)
    assert type(decoded[key]) is expected
    assert parse_info(decoded) is decoded and decoded == snapshot


@pytest.mark.parametrize("metadata", [[], {}, [1, 2.5, "text", {}],
                                      {"listener": {"bind": ["127.0.0.1", "::1"], "port": 6379}},
                                      [{"name": "synthetic", "version": 1}],
                                      {"str": "", "int": -MAX_INTEGER, "float": -0.0}])
def test_unknown_bounded_graph_is_valid_and_never_mutated(metadata):
    value = info(metadata=metadata)
    snapshot = copy.deepcopy(value)
    assert parse_info(value) is value and value == snapshot
    assert value["metadata"] is metadata


def nested(depth, leaf):
    for _ in range(depth):
        leaf = [leaf]
    return leaf


@pytest.mark.parametrize("leaf", [0, "", [], {}])
def test_graph_depth_root_zero_exact_eight_and_nine(leaf):
    value = info(metadata=nested(7, leaf))
    assert parse_info(value) is value
    with pytest.raises(QualificationError, match="sample refused"):
        parse_info(info(metadata=nested(8, leaf)))


def test_nested_dictionary_keys_are_nodes_with_depth_and_key_length_limits():
    value = info(metadata=nested(6, {"x" * 128: "value"}))
    assert parse_info(value) is value
    for bad in (info(metadata=nested(7, {"key": 0})), info(metadata={"x" * 129: 0})):
        with pytest.raises(QualificationError):
            parse_info(bad)


@pytest.mark.parametrize("container", [dict, list])
def test_each_nested_container_has_256_entry_limit(container):
    metadata = {str(index): index for index in range(256)} if container is dict else list(range(256))
    value = info(metadata=metadata)
    assert parse_info(value) is value
    if container is dict:
        metadata["extra"] = 0
    else:
        metadata.append(0)
    with pytest.raises(QualificationError):
        parse_info(value)


@pytest.mark.parametrize("shared", [False, True])
def test_node_occurrences_exact_4096_and_4097_including_repeated_aliases(shared):
    repeated = list(range(256))
    metadata = ([repeated] * 15 if shared else [list(range(256)) for _ in range(15)]) + [list(range(215))]
    value = info(metadata=metadata)
    # 23 existing root/key/scalar nodes + new key/list + 16 lists + 4055 scalars.
    assert parse_info(value) is value
    assert value["metadata"][0] is metadata[0]
    metadata[-1].append(0)
    with pytest.raises(QualificationError, match="sample refused"):
        parse_info(value)


def graph_text(value):
    if type(value) is str:
        return len(value)
    if type(value) is dict:
        return sum(len(key) + graph_text(item) for key, item in value.items())
    if type(value) is list:
        return sum(graph_text(item) for item in value)
    return 0


def test_graph_combined_text_exact_65536_counts_shared_aliases_every_time():
    shared = ["x" * 4096]
    value = info(metadata=[shared] * 15 + [[]])
    value["metadata"][-1].append("x" * (65536 - graph_text(value)))
    assert graph_text(value) == 65536 and parse_info(value) is value
    value["metadata"][-1].append("x")
    with pytest.raises(QualificationError, match="sample refused"):
        parse_info(value)


@pytest.mark.parametrize("leaf", [True, False, None, (), b"private", float("nan"), float("inf"),
                                   float("-inf"), 1 << 63, -(1 << 63), "x" * 4097])
def test_nested_scalar_types_and_bounds_are_not_relaxed(leaf):
    with pytest.raises(QualificationError):
        parse_info(info(metadata={"listener": [leaf]}))


@pytest.mark.parametrize("kind", ["self-list", "self-dict", "ancestor", "root"])
def test_graph_active_path_cycles_refuse(kind):
    value = info(metadata=[])
    if kind == "self-list":
        value["metadata"].append(value["metadata"])
    elif kind == "self-dict":
        value["metadata"] = {}
        value["metadata"]["cycle"] = value["metadata"]
    elif kind == "ancestor":
        value["metadata"].append({"cycle": value["metadata"]})
    else:
        value["metadata"].append(value)
    with pytest.raises(QualificationError, match="sample refused"):
        parse_info(value)


@pytest.mark.parametrize("order", list(itertools.permutations(("run_id", "aof_enabled", "metadata"))))
@pytest.mark.parametrize("location", ["key", "value", "list"])
def test_nested_hostile_objects_never_run_protocols_before_required_lookups(order, location):
    calls = []
    def refused(*args, **kwargs):
        calls.append(True)
        raise AssertionError("Private graph callback")
    class Poison(str):
        __eq__ = __ne__ = __str__ = __repr__ = __len__ = __iter__ = refused
        def __hash__(self):
            return 7
    poison = Poison("private")
    metadata = {poison: 0} if location == "key" else {"listener": poison if location == "value" else [poison]}
    Poison.__hash__ = refused
    value = info(metadata=metadata)
    ordered = {**{key: value[key] for key in order}, **{key: item for key, item in value.items() if key not in order}}
    with pytest.raises(QualificationError):
        parse_info(ordered)
    assert calls == []


def test_hostile_type_metaclass_is_not_compared():
    calls = []
    class Meta(type):
        def __eq__(cls, other):
            calls.append(True)
            raise AssertionError("Private metaclass comparison")
    class Poison(metaclass=Meta):
        pass
    with pytest.raises(QualificationError):
        parse_info(info(metadata=[Poison()]))
    assert calls == []


@pytest.mark.parametrize("key", [*FLAGS, *COUNTERS, *STATUSES, "run_id"])
@pytest.mark.parametrize("value", [[], {}, {"bounded": [0]}])
def test_required_fields_remain_scalar_with_structured_unknown_metadata(key, value):
    with pytest.raises(QualificationError):
        parse_info(info(**{key: value, "metadata": {"listener": ["tcp"]}}))


@pytest.mark.parametrize("base", [object, str, int, float, dict, list])
@pytest.mark.parametrize("location", ["root", "key", "unknown", "required"])
@pytest.mark.parametrize("order", list(itertools.permutations(("run_id", "aof_enabled", "unknown"))))
def test_poisoned_builtin_aliases_never_invoke_callbacks(base, location, order):
    calls = []

    def refused(name):
        def callback(*args, **kwargs):
            calls.append(name)
            raise AssertionError("private callback")
        return callback

    poison_type = type("Poison", (base,), {name: refused(name) for name in (
        "__eq__", "__ne__", "__hash__", "__str__", "__repr__", "__bool__", "__iter__", "items", "get",
        "__len__", "bit_length", "__float__", "__lt__", "__gt__", "__le__", "__ge__"
    )})
    poison = poison_type() if base in (object, dict, list) else poison_type("7" if base is str else 7)
    value = info(unknown=0)
    value = {**{key: value[key] for key in order}, **{key: item for key, item in value.items() if key not in order}}
    if location == "root":
        value = poison
    elif location == "key":
        # Construct safely before installing the hostile hash implementation.
        poison_type.__hash__ = lambda self: 7
        value[poison] = 0
        poison_type.__hash__ = refused("__hash__")
    else:
        value["unknown" if location == "unknown" else "aof_enabled"] = poison
    with pytest.raises(QualificationError):
        parse_info(value)
    assert calls == []


@pytest.mark.parametrize("ack", [True, *REWRITE_ACKS])
async def test_completion_can_precede_first_post_command_sample_and_is_private(ack):
    model = Model([info(), info(aof_rewrites=11)], ack=ack)
    result = await model.run()
    assert result == {"redis_persistence_complete": True}
    assert RUN_ID not in json.dumps(result)
    assert model.info.await_count == 2 and model.sleeps == []
    model.bgrewriteaof.assert_awaited_once_with()


async def test_idle_wait_and_post_command_generation_activity_share_one_budget():
    model = Model([
        info(rdb_bgsave_in_progress=1), info(aof_rewrite_in_progress=1), info(aof_rewrite_scheduled=1), info(),
        info(), info(aof_rewrite_scheduled=1), info(aof_rewrites=11, aof_rewrite_in_progress=1),
        info(aof_rewrites=11, aof_rewrite_scheduled=1), info(aof_rewrites=11, rdb_bgsave_in_progress=1),
        info(aof_rewrites=11, aof_buffer_length=1), info(aof_rewrites=11, aof_pending_bio_fsync=1),
        info(aof_rewrites=11),
    ])
    assert await model.run() == {"redis_persistence_complete": True}
    assert model.sleeps == [0.25] * 10
    model.bgrewriteaof.assert_awaited_once_with()


@pytest.mark.parametrize("ack", [False, 0, 1, None, [], {}, b"Background append only file rewriting started",
                                  "OK", "Background append only file rewriting started\n"])
async def test_bad_acknowledgement_is_not_retried(ack):
    model = Model([info()], ack=ack)
    with pytest.raises(QualificationError, match="acknowledgement"):
        await model.run()
    assert model.info.await_count == 1
    model.bgrewriteaof.assert_awaited_once_with()


@pytest.mark.parametrize("base", [int, str])
async def test_acknowledgement_aliases_refused_without_callbacks(base):
    calls = []
    def refused(*args):
        calls.append(True)
        raise AssertionError("Private acknowledgement callback")
    alias = type("Alias", (base,), {"__eq__": refused, "__bool__": refused})
    model = Model([info()], ack=alias(1 if base is int else REWRITE_ACKS[0]))
    with pytest.raises(QualificationError, match="acknowledgement"):
        await model.run()
    assert calls == []


@pytest.mark.parametrize("where", ["before", "after"])
@pytest.mark.parametrize("changes", [{"run_id": "b" * 40}, {"loading": 1}, {"aof_enabled": 0},
                                      {"aof_last_write_status": "err"}, {"unknown": [True]}])
async def test_bad_samples_refuse_before_acceptance(where, changes):
    samples = [info(**changes)] if where == "before" else [info(), info(**changes)]
    if where == "before" and "run_id" in changes:
        samples = [info(aof_rewrite_in_progress=1), info(**changes)]
    model = Model(samples)
    with pytest.raises(QualificationError):
        await model.run()
    assert model.bgrewriteaof.await_count == (where == "after")


@pytest.mark.parametrize("generation", [9, 12, MAX_INTEGER])
async def test_old_or_extra_post_command_generation_refused(generation):
    model = Model([info(), info(aof_rewrites=generation)])
    with pytest.raises(QualificationError, match="generation"):
        await model.run()
    model.bgrewriteaof.assert_awaited_once_with()


async def test_generation_overflow_refuses_before_command():
    model = Model([info(aof_rewrites=MAX_INTEGER)])
    with pytest.raises(QualificationError, match="generation"):
        await model.run()
    model.bgrewriteaof.assert_not_called()


async def test_finished_rewrite_failure_refuses():
    model = Model([info(), info(aof_rewrites=11, aof_last_bgrewrite_status="err")])
    with pytest.raises(QualificationError, match="rewrite failed"):
        await model.run()


@pytest.mark.parametrize("busy_before", [0, 1, 200, 478, 479, 480])
async def test_480_samples_is_total_before_and_after_command(busy_before):
    # Freeze the injected clock so sample exhaustion is tested independently of wall time.
    model = Model([info(aof_rewrite_in_progress=1)] * busy_before + [info()])
    async def no_time_sleep(seconds):
        assert seconds == 0.25
    model.sleep = no_time_sleep
    with pytest.raises(QualificationError, match="sample budget"):
        await model.run()
    assert model.info.await_count == MAX_SAMPLES
    assert model.bgrewriteaof.await_count == (busy_before < MAX_SAMPLES)


@pytest.mark.parametrize("during", ["info", "command", "sleep"])
async def test_deadline_checked_after_each_await(during):
    model = Model([info(aof_rewrite_in_progress=int(during == "sleep"))])
    if during == "info":
        def late_info(*args):
            model.now = 120
            return info()
        model.info.side_effect = late_info
    elif during == "command":
        def late_command():
            model.now = 120
            return True
        model.bgrewriteaof.side_effect = late_command
    else:
        async def late_sleep(seconds):
            model.now = 120
        model.sleep = late_sleep
    with pytest.raises(QualificationError, match="deadline"):
        await model.run()
    assert model.bgrewriteaof.await_count == (during == "command")


@pytest.mark.parametrize("during", ["info", "command", "sleep"])
@pytest.mark.parametrize("kind", [OSError, asyncio.CancelledError, KeyboardInterrupt])
async def test_transport_and_cancellation_preserve_original_exception(during, kind):
    error = kind("private transport detail")
    model = Model([info(aof_rewrite_in_progress=int(during == "sleep"))])
    if during == "info":
        model.info.side_effect = error
    elif during == "command":
        model.bgrewriteaof.side_effect = error
    else:
        async def failed_sleep(seconds):
            raise error
        model.sleep = failed_sleep
    with pytest.raises(kind) as caught:
        await model.run()
    assert caught.value is error
    assert model.bgrewriteaof.await_count == (during == "command")


async def test_hung_transport_is_bounded_by_outer_timeout(monkeypatch):
    import shadai.qualification.redis_persistence as persistence_module

    monkeypatch.setattr(persistence_module, "MAX_SECONDS", 0.02)
    model = Model([])
    cancelled = asyncio.Event()
    async def hung_info(*args):
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()
    model.info.side_effect = hung_info
    with pytest.raises(TimeoutError):
        await model.run()
    assert cancelled.is_set()
    model.bgrewriteaof.assert_not_called()
