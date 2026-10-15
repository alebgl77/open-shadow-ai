"""Store-free witnesses for source timestamps, pacing, and the original wall budget."""

import ast
import copy
import hashlib
import json
from concurrent.futures import Future
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest

from shadai.qualification import load
from shadai.qualification.schemas import QualificationError

RUN_ID = "6c8977c2-dfe8-4598-b134-13a2c1ef0a30"
ORIGIN = datetime(2026, 1, 1, tzinfo=UTC)


class SyntheticClock:
    def __init__(self):
        self.value = 100.0
        self.waits = []

    def __call__(self):
        return self.value

    def advance(self, seconds):
        assert seconds >= 0
        self.value += seconds

    def utc(self):
        return ORIGIN + timedelta(seconds=self.value - 100)


class SyntheticCancellation:
    def __init__(self, clock):
        self.clock = clock
        self.cancelled = False

    def is_set(self):
        return self.cancelled

    def set(self):
        self.cancelled = True

    def wait(self, seconds):
        if not self.cancelled:
            self.clock.waits.append(seconds)
            self.clock.advance(seconds)
        return self.cancelled


class InlineExecutor:
    """Keep mutable synthetic time deterministic while running the real send function."""

    def __init__(self, *, max_workers):
        assert max_workers == 2

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def submit(self, function, *args):
        future = Future()
        try:
            future.set_result(function(*args))
        except BaseException as error:
            future.set_exception(error)
        return future


class SenderWitness:
    def __init__(self, monkeypatch, directory, *, preparation=0.2, receipt_delay=0.05, materialization=0):
        self.clock = SyntheticClock()
        self.requests = []
        self.samples = []
        self.statuses = []
        self.profile = {
            "scope": "disposable_lab",
            "installation": "q-clock",
            "load": {
                "total_events": 3,
                "batch_size": 1,
                "events_per_second": 1,
                "seed": "stable-clock-witness",
                "concurrency": 2,
                "request_timeout_seconds": 1,
            },
            "limits": {
                "max_wall_seconds": 10,
                "max_requests": 9,
                "max_request_bytes": 65536,
                "max_disk_bytes": 1048576,
            },
        }

        class PairedDateTime:
            fromisoformat = staticmethod(datetime.fromisoformat)

            @staticmethod
            def now(zone):
                assert zone == UTC
                self.clock.advance(preparation)
                self.samples.append(self.clock())
                return self.clock.utc()

        original_batches = load.batched_fixtures

        def delayed_batches(*args):
            self.clock.advance(materialization)
            yield from original_batches(*args)

        def request(url, **kwargs):
            assert url == "http://127.0.0.1:9/api/v1/ingest/events"
            assert kwargs["method"] == "POST" and kwargs["credential"] == "synthetic"
            status = self.statuses.pop(0) if self.statuses else 202
            dispatch = self.clock()
            self.clock.advance(receipt_delay)
            self.requests.append({**kwargs, "dispatch": dispatch, "received": self.clock.utc(), "status": status})
            received = len(json.loads(kwargs["body"])["events"])
            return status, json.dumps({"received": received}).encode(), "none"

        monkeypatch.setattr(load, "datetime", PairedDateTime)
        monkeypatch.setattr(load, "batched_fixtures", delayed_batches)
        monkeypatch.setattr(load.concurrent.futures, "ThreadPoolExecutor", InlineExecutor)
        self.sender = load.LoadSender(self.profile, RUN_ID, "clock", directory, "scoped", clock=self.clock)
        self.sender.cancelled = SyntheticCancellation(self.clock)
        monkeypatch.setattr(self.sender.transport, "request", request)

    def run(self, *, deadline=None):
        return self.sender.run("http://127.0.0.1:9", "synthetic", deadline=deadline)


@pytest.fixture
def strict_latency():
    """Execute the original arithmetic and rejection AST without importing live stores."""
    source = Path(load.__file__).with_name("fixtures.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    guards = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.If)
        and isinstance(node.test, ast.Compare)
        and isinstance(node.test.left, ast.Name)
        and node.test.left.id == "seconds"
    ]
    calculations = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "seconds" for t in node.targets)
    ]
    assert len(guards) == len(calculations) == 1
    function = ast.parse("def strict_latency(received, event):\n    return seconds\n").body[0]
    function.body[:0] = [copy.deepcopy(calculations[0]), copy.deepcopy(guards[0])]
    module = ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[]))
    namespace = {"datetime": datetime, "QualificationError": QualificationError}
    exec(compile(module, "<original-fixtures-latency-guard>", "exec"), namespace)
    return namespace["strict_latency"]


@pytest.mark.parametrize("preparation,receipt_delay", [(0.2, 0.05), (0.4, 0.025), (0.9, 0.1)])
def test_fresh_batches_pair_source_utc_with_their_schedule(
    tmp_path, monkeypatch, strict_latency, preparation, receipt_delay
):
    witness = SenderWitness(monkeypatch, tmp_path, preparation=preparation, receipt_delay=receipt_delay)
    result = witness.run()
    assert len(witness.requests) == result["requests"] == result["accepted"] == 3
    latencies = [
        strict_latency(request["received"], json.loads(request["body"])["events"][0]) for request in witness.requests
    ]
    assert latencies == pytest.approx([receipt_delay] * 3)
    paired_start = witness.samples[0]
    dispatches = [request["dispatch"] for request in witness.requests]
    assert dispatches == pytest.approx([paired_start + index for index in range(3)])
    assert all(dispatch >= paired_start + index for index, dispatch in enumerate(dispatches))
    assert [later - earlier for earlier, later in zip(dispatches, dispatches[1:])] == pytest.approx([1, 1])
    assert result["elapsed_seconds"] == pytest.approx(preparation + 2 + receipt_delay)


def test_materialization_does_not_rebase_the_paired_schedule(tmp_path, monkeypatch, strict_latency):
    witness = SenderWitness(monkeypatch, tmp_path, materialization=0.35)
    result = witness.run()
    assert [request["dispatch"] for request in witness.requests] == pytest.approx([100.55, 101.2, 102.2])
    assert [
        strict_latency(request["received"], json.loads(request["body"])["events"][0]) for request in witness.requests
    ] == pytest.approx([0.4, 0.05, 0.05])
    assert result["elapsed_seconds"] == pytest.approx(2.25)


def test_original_latency_guard_still_rejects_a_genuine_negative(strict_latency):
    event = {"timestamp": ORIGIN.isoformat()}
    with pytest.raises(QualificationError, match="Clock ordering"):
        strict_latency(ORIGIN - timedelta(microseconds=1), event)


@pytest.mark.parametrize("parent_deadline", [False, True])
def test_preparation_still_consumes_the_original_wall_budget(tmp_path, monkeypatch, parent_deadline):
    witness = SenderWitness(monkeypatch, tmp_path)
    if not parent_deadline:
        witness.profile["limits"]["max_wall_seconds"] = 0.15
    with pytest.raises(QualificationError, match="wall budget exhausted during preparation"):
        witness.run(deadline=100.15 if parent_deadline else None)
    assert witness.requests == []


@pytest.mark.parametrize("parent_deadline", [False, True])
def test_cadence_wait_stops_at_the_original_deadline(tmp_path, monkeypatch, parent_deadline):
    witness = SenderWitness(monkeypatch, tmp_path)
    if not parent_deadline:
        witness.profile["limits"]["max_wall_seconds"] = 1.1
    result = witness.run(deadline=101.1 if parent_deadline else None)
    assert result["accepted"] == result["requests"] == len(witness.requests) == 1
    assert witness.requests[0]["deadline"] == pytest.approx(101.1)
    assert witness.clock() == pytest.approx(101.1)
    assert result["elapsed_seconds"] == pytest.approx(1.1)


def test_retained_manifest_keeps_bytes_hashes_ids_and_original_resume_epoch(tmp_path, monkeypatch):
    witness = SenderWitness(monkeypatch, tmp_path)
    first = witness.run()
    paths = sorted(tmp_path.glob("clock-batch-*.json"))
    manifest_path = tmp_path / "clock-load-manifest.json"
    frozen = {path: path.read_bytes() for path in [manifest_path, *paths]}
    manifest = json.loads(frozen[manifest_path])
    assert manifest["sha256"] == [hashlib.sha256(frozen[path]).hexdigest() for path in paths]
    identifiers = [json.loads(frozen[path])["events"][0]["event_id"] for path in paths]
    assert len({UUID(identifier) for identifier in identifiers}) == 3
    original_read = Path.read_text

    def delayed_manifest_read(path, *args, **kwargs):
        if path == manifest_path:
            witness.clock.advance(0.2)
        return original_read(path, *args, **kwargs)

    witness.clock.advance(10)
    resume_start = witness.clock()
    monkeypatch.setattr(Path, "read_text", delayed_manifest_read)
    resumed = witness.run()
    assert len(witness.samples) == 1
    assert [request["dispatch"] for request in witness.requests[3:]] == pytest.approx(
        [resume_start + 0.2, resume_start + 1, resume_start + 2]
    )
    assert {path: path.read_bytes() for path in frozen} == frozen
    assert [request["body"] for request in witness.requests[:3]] == [
        request["body"] for request in witness.requests[3:]
    ]
    assert resumed["accepted_scoped_ids"] == first["accepted_scoped_ids"]
    assert resumed["requests"] == first["requests"] + 3 == 6
    assert resumed["elapsed_seconds"] == pytest.approx(2.05)


@pytest.mark.parametrize(
    "statuses,cap,accepted", [([503, 202], 3, 1), ([503, 503, 202], 3, 1), ([503, 503, 202], 2, 0)]
)
def test_retries_keep_identical_bytes_ids_and_request_cap(tmp_path, monkeypatch, statuses, cap, accepted):
    witness = SenderWitness(monkeypatch, tmp_path)
    witness.profile["load"]["total_events"] = 1
    witness.profile["limits"]["max_requests"] = cap
    witness.statuses = statuses.copy()
    result = witness.run()
    assert result["requests"] == len(witness.requests) == min(len(statuses), cap)
    assert len({request["body"] for request in witness.requests}) == 1
    assert result["attempted"] == 1 and result["accepted"] == accepted
    assert sum(result["http_status_counts"].values()) == result["requests"]
