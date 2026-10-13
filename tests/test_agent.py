import json
import logging
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from shadai_agent import main as agent

from shadai.api import agent as server
from shadai.api.agent import ExtensionRecord, TelemetryBatch, extension_record, extension_wire_version

HEADER = {"hostname": "ws-042", "agent_version": "0.1.0", "timestamp": datetime.now(UTC).isoformat()}


def installation(index: int = 0, **state) -> dict:
    """One collected Chromium extension record with the per-installation state the collector reads."""
    return {"id": f"ext{index:028d}", "name": "Extension", "browser": "chrome", "version": "3.1.0", "enabled": True,
            "install_source": "store", "installed_at": "2026-01-15T10:30:00+00:00", "user": "alice",
            "profile": "Default", "permissions": ["tabs", "<all_urls>"], **state}


def test_large_snapshot_is_split_into_batches_the_api_accepts():
    processes = [
        {"pid": i, "name": f"proc-{i}.exe", "path": "C:/x/" + "p" * 1500, "username": "u"} for i in range(1800)
    ]
    extensions = [installation(i, profile=f"Profile {i % 7}") for i in range(700)]
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
    wire = [e for batch in batches for e in batch["extensions"]]
    assert wire == [{key: e[key] for key in agent.WIRE_FIELDS["extensions"]} for e in extensions]
    assert all("permissions" not in e for e in wire)


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


# --- Extension wire v2 ------------------------------------------------------------


def test_extension_records_are_brought_within_the_server_contract_before_sending():
    """A type the server would reject (422 for the whole batch) is coerced; an unknown token stays a record."""
    collected = [
        installation(0, enabled="yes", installed_at="2026-01-15T10:30:00", install_source="magic",
                     version="9." * 80),
        installation(1, enabled=None, installed_at=None, install_source=None, user=None, profile="P" * 300),
        installation(2, enabled=1, installed_at=1_768_473_000, install_source="policy", browser="b" * 100),
        installation(3, enabled=False, installed_at="", install_source="orphan"),
    ]
    [batch] = agent.split_batches(HEADER, {"extensions": collected})
    TelemetryBatch.model_validate(batch)
    first, second, third, fourth = batch["extensions"]
    assert first["enabled"] is None and "installed_at" not in first and first["install_source"] == "unknown"
    assert first["version"] == ("9." * 80)[:100] and len(first["version"]) == 100
    assert second["enabled"] is None and "installed_at" not in second and second["install_source"] == "unknown"
    assert second["user"] == "" and len(second["profile"]) == 255
    assert third["enabled"] is None and "installed_at" not in third and third["install_source"] == "policy"
    assert len(third["browser"]) == 64
    assert fourth["enabled"] is False and "installed_at" not in fourth and fourth["install_source"] == "orphan"
    for record in batch["extensions"]:
        assert set(record) <= set(agent.WIRE_FIELDS["extensions"]) and "permissions" not in record
        assert extension_wire_version(record) == server.EXTENSION_WIRE_VERSION
        assert extension_record(record).user in {"alice", ""}
    kept = agent.conform(installation(4))
    assert kept["installed_at"] == "2026-01-15T10:30:00+00:00" and kept["enabled"] is True
    assert extension_record(kept).installed_at == datetime(2026, 1, 15, 10, 30, tzinfo=UTC)


@pytest.mark.parametrize("record", [
    # Firefox: extensions.json carries no install date today.
    {"id": "uBlock0@raymondhill.net", "name": "uBlock Origin", "version": "1.60.0", "permissions": ["<all_urls>"],
     "enabled": True, "install_source": "store", "browser": "firefox", "profile": "abcd.default-release",
     "user": "alice"},
    # Safari: app extensions carry the host application, not an install date.
    {"id": "com.example.Tidy.Extension", "name": "Tidy", "version": "2.0", "browser": "safari",
     "permissions": [], "profile": "Default", "install_source": "store", "host_app": "Tidy.app",
     "user": "bob", "enabled": None},
])
def test_firefox_and_safari_records_without_an_install_date_validate(record):
    [batch] = agent.split_batches(HEADER, {"extensions": [record]})
    TelemetryBatch.model_validate(batch)
    [wire] = batch["extensions"]
    assert "installed_at" not in wire and "permissions" not in wire and "host_app" not in wire
    validated = extension_record(wire)
    assert validated.installed_at is None and validated.enabled is record["enabled"]
    assert (validated.user, validated.profile, validated.version) == (record["user"], record["profile"],
                                                                        record["version"])
    assert extension_wire_version(wire) == server.EXTENSION_WIRE_VERSION


def test_agent_field_contract_matches_the_server():
    """conform() mirrors the API exactly: fields, limits and the install-source tokens cannot drift apart."""
    assert set(agent.TEXT_FIELDS) == server.TELEMETRY_TEXT_FIELDS
    assert set(agent.PORT_FIELDS) == server.TELEMETRY_PORT_FIELDS
    assert agent.MAX_TEXT_LENGTH == server.MAX_TEXT_LENGTH
    assert agent.TEXT_LIMITS == server.EXTENSION_TEXT_LIMITS
    assert agent.INSTALL_SOURCES == set(server.EXTENSION_INSTALL_SOURCES)
    assert set(agent.WIRE_FIELDS["extensions"]) == set(ExtensionRecord.model_fields)
    assert set(agent.EXTENSION_TEXT_FIELDS) | set(agent.BOOL_FIELDS) | set(agent.TIMESTAMP_FIELDS) == set(
        server.EXTENSION_V2_FIELDS)
    for name, info in ExtensionRecord.model_fields.items():
        limits = [constraint.max_length for constraint in info.metadata if hasattr(constraint, "max_length")]
        if limits:
            assert name in (*agent.TEXT_FIELDS, *agent.EXTENSION_TEXT_FIELDS)
            assert limits == [agent.TEXT_LIMITS.get(name, agent.MAX_TEXT_LENGTH)], name


def test_one_record_per_installation_and_no_more_than_the_snapshot_ceiling(monkeypatch, caplog):
    found = [installation(i % 3000, user=f"user{i // 3000}") for i in range(6000)]
    found.extend(installation(i % 3000, user=f"user{i // 3000}", name="Localised") for i in range(600))
    assert len(agent.unique_records("extensions", found)) == 6000
    config = SimpleNamespace(hostname="rds-01", spool_dir="unused", spool_max_bytes=1000, spool_max_batches=10,
                             spool_ttl_seconds=60, poll_interval_seconds=0, collect_processes=False,
                             collect_containers=False, collect_local_ai=False, collect_extensions=True)
    payloads = []
    spool = SimpleNamespace(enqueue=lambda payload, **kwargs: payloads.append(json.loads(payload)),
                            stats=lambda: {}, close=lambda: None)

    def finish_poll(*args):
        agent._running = False
        return None

    monkeypatch.setattr(agent, "_running", True)
    monkeypatch.setattr(agent.signal, "signal", lambda *args: None)
    monkeypatch.setattr(agent, "load_agent_config", lambda: config)
    monkeypatch.setattr(agent, "DurableSpool", lambda *args, **kwargs: spool)
    monkeypatch.setattr(agent, "discover_binding", finish_poll)
    monkeypatch.setattr(agent, "collect_extensions", lambda: found)
    with caplog.at_level(logging.WARNING, logger="shadai-agent"):
        agent.main()
    wire = [record for batch in payloads for record in batch["extensions"]]
    assert len(wire) == agent.MAX_EXTENSION_RECORDS_PER_SNAPSHOT == 5000 and len(payloads) == 10
    assert {(r["id"], r["user"]) for r in wire} == {(f"ext{i:028d}", "user0") for i in range(3000)} | {
        (f"ext{i:028d}", "user1") for i in range(2000)}
    [warning] = [record for record in caplog.records if record.levelno == logging.WARNING]
    assert warning.getMessage() == "Extension inventory truncated: 5000 of 6000 installations kept this snapshot"
    assert "ext0000" not in warning.getMessage() and "user" not in warning.getMessage()
    for batch in payloads:
        TelemetryBatch.model_validate(batch)
