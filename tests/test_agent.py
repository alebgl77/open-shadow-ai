import json
from datetime import UTC, datetime
from types import SimpleNamespace

from shadai_agent import main as agent

from shadai.api.agent import TelemetryBatch

HEADER = {"hostname": "ws-042", "agent_version": "0.1.0", "timestamp": datetime.now(UTC).isoformat()}


def test_large_snapshot_is_split_into_batches_the_api_accepts():
    processes = [
        {"pid": i, "name": f"proc-{i}.exe", "path": "C:/x/" + "p" * 1500, "username": "u"} for i in range(1800)
    ]
    extensions = [{"id": f"ext{i:028d}", "name": "Extension", "browser": "chrome"} for i in range(700)]
    batches = agent.split_batches(HEADER, {"processes": processes, "extensions": extensions})
    assert len(batches) > 2
    for batch in batches:
        assert sum(len(batch[section]) for section in agent.SECTIONS) <= 500
        assert len(json.dumps(batch)) <= agent.MAX_BODY_BYTES
        assert {key: batch[key] for key in HEADER} == HEADER
        TelemetryBatch.model_validate(batch)
    assert [p for batch in batches for p in batch["processes"]] == [
        {key: p[key] for key in agent.WIRE_FIELDS["processes"] if key in p} for p in processes
    ]
    assert [e for batch in batches for e in batch["extensions"]] == extensions


def test_legacy_rechunk_preserves_headers_raw_fields_and_child_bytes():
    header = {**HEADER, "hostname": "legacy-identity"}
    parent = {**header, "processes": [{"name": f"p{i}", "parent": "same", "username": "u", "extra": "preserved"}
                                     for i in range(500)],
              "extensions": [{"id": f"ext{i}", "name": "same", "browser": "chrome"} for i in range(500)],
              "model_files": [{"name": "legacy-ignored-metadata"}]}
    payload = json.dumps(parent, ensure_ascii=False, separators=(",", ":")).encode()
    children = agent.delivery_payloads(payload)
    assert children == agent.delivery_payloads(payload) and len(children) == 3
    rows = [json.loads(child) for child in children]
    assert all(sum(len(row[section]) for section in agent.LEGACY_SECTIONS) <= 500 for row in rows)
    assert all({key: row[key] for key in header} == header for row in rows)
    for section in agent.LEGACY_SECTIONS:
        assert [item for row in rows for item in row[section]] == parent.get(section, [])
    assert json.loads(payload) == parent


def test_small_retained_parent_sends_identical_bytes_including_whitespace():
    payload = json.dumps({**HEADER, "processes": [{"name": "same"}]}, indent=3).encode()
    assert agent.delivery_payloads(payload) == [payload]


def test_empty_snapshot_still_reports_and_duplicates_collapse():
    assert agent.split_batches(HEADER, {}) == [{**HEADER, **{section: [] for section in agent.SECTIONS}}]
    processes = [{"pid": pid, "name": "chrome.exe", "parent": "explorer.exe", "username": "u"} for pid in range(80)]
    processes.append({"pid": 99, "name": "ollama", "parent": "", "username": "u", "listening_port": 11434})
    assert [p["pid"] for p in agent.unique_processes(processes)] == [0, 99]


def test_client_errors_are_not_retried_and_server_errors_are(monkeypatch):
    calls = []
    monkeypatch.setattr(agent.time, "sleep", lambda seconds: None)

    def respond(status, body=None):
        def post(*args, **kwargs):
            calls.append(status)
            return SimpleNamespace(status_code=status, json=lambda: body or {})

        return post

    monkeypatch.setattr(agent.requests, "post", respond(422))
    assert agent.send_batch("https://x", {}, {}, True) is None and calls == [422]
    calls.clear()
    monkeypatch.setattr(agent.requests, "post", respond(503))
    assert agent.send_batch("https://x", {}, {}, True) is None and calls == [503, 503, 503]
    monkeypatch.setattr(agent.requests, "post", respond(200, {"received": 12}))
    assert agent.send_batch("https://x", {"processes": [{"name": "synthetic"}] * 12}, {}, True) == 12


def test_one_nonconforming_record_cannot_sink_its_batch():
    records = [
        {"pid": 1, "name": None, "path": "C:/" + "x" * 5000, "username": None, "listening_port": 11434},
        {"pid": 2, "name": "ollama", "parent": 42, "listening_port": "8080"},
        {"pid": 3, "name": "svc", "listening_port": 70000},
        {"pid": 4, "name": "flag", "listening_port": True},
    ]
    extensions = [{"id": "abc", "name": {"unexpected": "object"}, "browser": "chrome"}]
    [batch] = agent.split_batches(HEADER, {"processes": records, "extensions": extensions})
    TelemetryBatch.model_validate(batch)
    assert len(batch["processes"]) == 4
    assert all("pid" not in p and "path" not in p for p in batch["processes"])
    assert batch["processes"][0]["name"] == ""
    assert batch["processes"][0]["listening_port"] == 11434 and batch["processes"][1]["parent"] == "42"
    assert all("listening_port" not in p for p in batch["processes"][1:])


def test_snapshot_timestamp_remains_aware_utc_on_the_wire(monkeypatch):
    instant = datetime(2026, 10, 6, 12, 34, 56, 123456, tzinfo=UTC)

    class Clock:
        @staticmethod
        def now(zone):
            assert zone is UTC
            return instant

    payloads = []
    config = SimpleNamespace(hostname='ws-042', spool_dir='unused', spool_max_bytes=1000,
                             spool_max_batches=10, spool_ttl_seconds=60, poll_interval_seconds=0,
                             collect_processes=False, collect_containers=False,
                             collect_local_ai=False, collect_extensions=False)
    spool = SimpleNamespace(enqueue=lambda payload, **kwargs: payloads.append(json.loads(payload)),
                            stats=lambda: {}, close=lambda: None)

    def finish_poll(*args):
        agent._running = False
        return None

    monkeypatch.setattr(agent, '_running', True)
    monkeypatch.setattr(agent.signal, 'signal', lambda *args: None)
    monkeypatch.setattr(agent, 'datetime', Clock)
    monkeypatch.setattr(agent, 'load_agent_config', lambda: config)
    monkeypatch.setattr(agent, 'DurableSpool', lambda *args, **kwargs: spool)
    monkeypatch.setattr(agent, 'discover_binding', finish_poll)
    agent.main()
    [batch] = payloads
    assert batch['timestamp'] == '2026-10-06T12:34:56.123456+00:00'
    assert datetime.fromisoformat(batch['timestamp']) == instant
    TelemetryBatch.model_validate(batch)
