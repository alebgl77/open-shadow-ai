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
        assert len(json.dumps(batch)) <= agent.MAX_BODY_BYTES
        assert {key: batch[key] for key in HEADER} == HEADER
        TelemetryBatch.model_validate(batch)
    assert [p for batch in batches for p in batch["processes"]] == processes
    assert [e for batch in batches for e in batch["extensions"]] == extensions


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
    assert agent.send_batch("https://x", {}, {}, True) == 12
