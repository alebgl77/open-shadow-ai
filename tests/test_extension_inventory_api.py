"""The inventory read API: analyst rows and history, viewer aggregates, every response bounded by the window."""

import csv
import io
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select
from test_evidence_privacy import evidence_sessions as evidence_sessions
from test_evidence_privacy import installation, item, version_change

from shadai.api.exports import ANTI_HR_WARNING, INVENTORY_EXPORT_COLUMNS
from shadai.api.extensions import (
    INVENTORY_SORT_COLUMNS,
    LIMITATIONS,
    installations_select,
    inventory_filters,
    order_inventory,
    visible_installations,
)
from shadai.config import get_config
from shadai.database import get_postgres_session
from shadai.engine.correlator import Correlator
from shadai.models.audit import AuditLogORM
from shadai.models.event import CanonicalEvent
from shadai.models.extension_inventory import (
    INVENTORY_INSTALL_SOURCES,
    ExtensionInventoryORM,
    ExtensionInventorySummary,
    ExtensionVersionChangeORM,
)
from shadai.security.auth import get_current_user
from shadai.utils.privacy import membership_basis

NOW = datetime.now(UTC).replace(microsecond=0)
SIDER = "abcdefghijklmnopabcdefghijklmnop"
HELPER = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
FIREFOX_HELPER = "firefox-helper@example.test"
NAMES = ("sider", "helper", "edge", "legacy", "expired", "stale")
KEYS = {name: format(index, "064x") for index, name in enumerate(NAMES)}
PRIVATE_VALUES = ("WS-ALICE-01", "laptop-b", "alice", "bob", "Profile 1", "Default")


@pytest.mark.parametrize("field", ["since", "until"])
@pytest.mark.parametrize("timestamp", ["0001-01-01T00:00:00+01:00", "9999-12-31T23:59:59-01:00"])
async def test_history_utc_overflow_has_sanitized_422(inventory_console, field, timestamp):
    response = await inventory_console.client.get("/api/v1/extensions/version-changes", params={field: timestamp})
    assert response.status_code == 422
    assert response.json() == {"detail": "Timestamp is outside the UTC range"}
    assert timestamp not in response.text


async def test_real_three_channel_wire_ingestion_has_independent_history_and_unknown_export(
    inventory_console, tmp_path, monkeypatch,
):
    from unittest.mock import AsyncMock

    from queue_fakes import admission_fake
    from shadai_agent import main as agent
    from shadai_agent.collectors import browser_ext
    from test_browser_ext import _install, _prefs
    from test_extension_inventory import Ingest, stored

    from shadai.api import agent as server

    monkeypatch.setattr(browser_ext.platform, "system", lambda: "Linux")
    home = tmp_path / "alice"
    roots = [".config/google-chrome", ".config/google-chrome-beta", ".config/google-chrome-unstable"]
    for root in roots:
        _install(home, root, "Default", SIDER, "1.0", {"name": "Same", "version": "1.0"})
        _prefs(home, root, "Default", {SIDER: {"location": 1}})
    redis = admission_fake(AsyncMock())
    monkeypatch.setattr(server, "get_redis", AsyncMock(return_value=redis))
    ingest = Ingest(inventory_console.sessions)
    original = {}
    for step in range(2):
        if step:
            for index, root in enumerate(roots):
                _install(home, root, "Default", SIDER, f"{index + 2}.0",
                         {"name": "Same", "version": f"{index + 2}.0"})
        batches = agent.split_batches(
            {"hostname": "host-a", "agent_version": "0.3.0", "timestamp": (NOW + timedelta(seconds=step)).isoformat()},
            {"extensions": browser_ext.collect_extensions([home])},
        )
        assert len(batches) == 1 and len(batches[0]["extensions"]) == 3
        response = await inventory_console.client.post(
            "/api/v1/agent/telemetry", headers={"X-API-Key": get_config().security.agent_api_key}, json=batches[0],
        )
        assert response.status_code == 200 and response.json()["received"] == 3
        queued = [CanonicalEvent.model_validate_json(call.args[1]["data"]) for call in redis.xadd.call_args_list]
        assert len(queued) == 3 and all(event.extension_enabled is None for event in queued)
        await ingest.deliver(*queued)
        redis.xadd.reset_mock()
        rows, changes, _ = await stored(inventory_console.sessions)
        assert len(rows) == 3 and len({row.inventory_key for row in rows}) == 3
        if not step:
            original = {row.profile: row.inventory_key for row in rows}
            assert changes == []
        else:
            assert {row.profile: row.inventory_key for row in rows} == original
            assert len(changes) == 3 and {change.to_version for change in changes} == {"2.0", "3.0", "4.0"}
            for row in rows:
                history = await inventory_console.client.get(
                    f"/api/v1/extensions/inventory/{row.inventory_key}/versions")
                assert history.status_code == 200
                assert len(history.json()["changes"]) == 1
                assert history.json()["changes"][0]["to_version"] == row.version
    response = await inventory_console.client.get("/api/v1/extensions/inventory", params={"enabled": "unknown"})
    assert response.status_code == 200 and response.json()["total"] == 3
    assert all(row["enabled"] is None for row in response.json()["items"])
    for state in ("true", "false"):
        assert (await inventory_console.client.get("/api/v1/extensions/inventory", params={"enabled": state})).json()[
            "total"] == 0
    response = await inventory_console.client.post("/api/v1/exports/extension-inventory", params={"enabled": "unknown"})
    assert response.status_code == 200
    exported = list(csv.DictReader(io.StringIO(response.text.removeprefix(ANTI_HR_WARNING))))
    assert len(exported) == 3 and {row["enabled"] for row in exported} == {"unknown"}


def utc(value: str) -> datetime:
    return datetime.fromisoformat(value).astimezone(UTC)


@pytest.fixture
async def inventory_console(evidence_sessions):
    """The console API over real transactions; the actor's role is switched per test."""
    from shadai.main import app

    async def session_dependency():
        async with evidence_sessions() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    actor = SimpleNamespace(user_id=uuid4(), username="analyst", role="analyst")

    async def current_actor():
        return actor

    previous = dict(app.dependency_overrides)
    app.dependency_overrides[get_postgres_session] = session_dependency
    app.dependency_overrides[get_current_user] = current_actor
    async with AsyncClient(
        transport=ASGITransport(app=app, raise_app_exceptions=False), base_url="https://testserver"
    ) as client:
        yield SimpleNamespace(client=client, sessions=evidence_sessions, actor=actor)
    app.dependency_overrides.clear()
    app.dependency_overrides.update(previous)


def row(name, **state):
    values = {"identity_basis": membership_basis(), "now": NOW}
    values.update(state)
    return installation(key=KEYS[name], **values)


@pytest.fixture
async def fleet(inventory_console):
    """Two visible hosts (one last seen two days ago), an expired row, a row from a previous key, and history."""
    async with inventory_console.sessions.begin() as session:
        event = CanonicalEvent(
            tenant_id="test-org", collector_id="sensor", source_type="browser", evidence_type="inventory",
            extension_id=SIDER, timestamp=NOW,
        )
        detection = Correlator(None)._create_detection(event, item("sider"), "extension_id", 0.9, NOW, NOW, None)
        session.add(detection)
        host_a = {"device_digest": "a" * 64, "host_label": "WS-ALICE-01"}
        sider = row(
            "sider", **host_a, user_digest="1" * 64, user_label="alice", browser="chrome", profile="Default",
            version="1.2.0", enabled=True, install_source="store", catalog_item_id="sider",
        )
        helper = row(
            "helper", **host_a, user_digest="1" * 64, user_label="alice", browser="chrome", profile="Default",
            extension_id=HELPER, extension_name="Unknown helper", version=None, enabled=False,
            install_source="policy", catalog_item_id=None,
        )
        edge = row(
            "edge", **host_a, user_digest="2" * 64, user_label="bob", browser="edge", profile="Profile 1",
            version="1.1.0", enabled=None, install_source="user", catalog_item_id="sider",
            installed_at=None, last_seen_at=NOW - timedelta(hours=2),
        )
        legacy = row(
            "legacy", device_digest="b" * 64, host_label="laptop-b", user_digest=None, user_label=None,
            browser="firefox", profile="", extension_id=FIREFOX_HELPER, extension_name="Firefox helper",
            version=None, enabled=None, install_source="", installed_at=None, catalog_item_id=None,
            wire_version=1, first_seen_at=NOW - timedelta(days=10), last_seen_at=NOW - timedelta(days=2),
        )
        expired = row(
            "expired", device_digest="c" * 64, host_label="old-host", last_seen_at=NOW - timedelta(days=31),
            first_seen_at=NOW - timedelta(days=40),
        )
        stale = row("stale", device_digest="d" * 64, host_label="rekeyed-host", identity_basis="s" * 64)
        session.add_all([sider, helper, edge, legacy, expired, stale])
        await session.flush()
        session.add_all(
            [
                version_change(
                    sider, from_version="1.1.0", to_version="1.2.0", observed_at=NOW - timedelta(days=3),
                    previous_observed_at=NOW - timedelta(days=8),
                ),
                version_change(
                    sider, from_version="1.0.0", to_version="1.1.0", observed_at=NOW - timedelta(days=8),
                    previous_observed_at=NOW - timedelta(days=31),
                ),
                # History older than the window expires while its installation is still reported.
                version_change(
                    sider, from_version="0.9.0", to_version="1.0.0", observed_at=NOW - timedelta(days=31),
                    previous_observed_at=NOW - timedelta(days=40),
                ),
                version_change(
                    edge, from_version="1.0.0", to_version="1.1.0", observed_at=NOW - timedelta(hours=2),
                    previous_observed_at=NOW - timedelta(days=1),
                ),
                version_change(expired, observed_at=NOW - timedelta(days=31)),
                version_change(stale, observed_at=NOW),
            ]
        )
    return SimpleNamespace(detection_id=str(detection.detection_id), **inventory_console.__dict__)


async def listed(console, **params):
    response = await console.client.get("/api/v1/extensions/inventory", params=params)
    assert response.status_code == 200, response.text
    return response.json()


async def audit_entries(console):
    async with console.sessions() as session:
        return list((await session.scalars(select(AuditLogORM).order_by(AuditLogORM.timestamp))).all())


async def test_analyst_list_is_bounded_to_the_identity_window_and_the_current_key(fleet):
    body = await listed(fleet)
    assert body["total"] == 4 and body["page"] == 1 and body["page_size"] == 25
    by_key = {entry["inventory_key"]: entry for entry in body["items"]}
    assert set(by_key) == {KEYS["sider"], KEYS["helper"], KEYS["edge"], KEYS["legacy"]}
    assert body["identity_window"]["days"] == get_config().retention.identity_days
    assert abs(utc(body["identity_window"]["as_of"]) - datetime.now(UTC)) < timedelta(minutes=1)
    assert body["identity_mode"] == "raw"
    for entry in body["items"]:
        assert not {"device_digest", "user_digest", "identity_basis"} & set(entry)
        assert utc(entry["last_seen_at"]).tzinfo is not None
    sider, edge, legacy = by_key[KEYS["sider"]], by_key[KEYS["edge"]], by_key[KEYS["legacy"]]
    assert sider["detection_id"] == fleet.detection_id and by_key[KEYS["helper"]]["detection_id"] is None
    assert (sider["host_label"], sider["user_label"], sider["profile"]) == ("WS-ALICE-01", "alice", "Default")
    assert (sider["version"], sider["enabled"], sider["install_source"]) == ("1.2.0", True, "store")
    assert utc(sider["last_seen_at"]) == NOW and utc(sider["installed_at"]) == NOW - timedelta(days=3)
    # The host reported a newer snapshot without the Edge installation; the Firefox host is up to date.
    assert sider["present_in_latest_snapshot"] and by_key[KEYS["helper"]]["present_in_latest_snapshot"]
    assert edge["present_in_latest_snapshot"] is False and edge["detection_id"] == fleet.detection_id
    assert legacy["present_in_latest_snapshot"] is True and legacy["wire_version"] == 1
    assert (legacy["user_label"], legacy["profile"], legacy["version"], legacy["enabled"]) == (None, "", None, None)
    assert legacy["install_source"] == "" and legacy["installed_at"] is None


@pytest.mark.parametrize(
    ("params", "expected"),
    [
        ({"host": "ws-alice"}, {"sider", "helper", "edge"}),
        ({"host": "laptop-b"}, {"legacy"}),
        ({"browser": "chrome"}, {"sider", "helper"}),
        ({"browser": "chrome,firefox"}, {"sider", "helper", "legacy"}),
        ({"enabled": "true"}, {"sider"}),
        ({"enabled": "false"}, {"helper"}),
        ({"enabled": "unknown"}, {"edge", "legacy"}),
        ({"install_source": "store"}, {"sider"}),
        ({"install_source": "policy,user"}, {"helper", "edge"}),
        ({"catalog_match": "matched"}, {"sider", "edge"}),
        ({"catalog_match": "unmatched"}, {"helper", "legacy"}),
        ({"extension_id": SIDER}, {"sider", "edge"}),
        ({"extension_id": SIDER[:-1]}, set()),
        ({"search": "SIDER"}, {"sider", "edge"}),
        ({"search": HELPER[:8]}, {"helper"}),
        ({"browser": "chrome", "catalog_match": "matched", "search": "sider"}, {"sider"}),
    ],
)
async def test_each_filter_selects_the_expected_installations(fleet, params, expected):
    body = await listed(fleet, **params)
    assert {entry["inventory_key"] for entry in body["items"]} == {KEYS[name] for name in expected}
    assert body["total"] == len(expected)


@pytest.mark.parametrize("sort_by", INVENTORY_SORT_COLUMNS)
@pytest.mark.parametrize("sort_order", ["asc", "desc"])
async def test_every_sort_column_orders_values_keeps_unreported_last_and_breaks_ties_by_key(fleet, sort_by, sort_order):
    items = (await listed(fleet, sort_by=sort_by, sort_order=sort_order))["items"]
    assert len(items) == 4
    by_key = sorted(items, key=lambda entry: entry["inventory_key"])
    reported = [entry for entry in by_key if entry[sort_by] is not None]
    reported = sorted(reported, key=lambda entry: entry[sort_by], reverse=sort_order == "desc")
    unreported = [entry for entry in by_key if entry[sort_by] is None]
    assert [entry["inventory_key"] for entry in items] == [entry["inventory_key"] for entry in reported + unreported]
    if sort_by in {"version", "installed_at"}:
        assert unreported, "the fleet must contain an installation without a reported value for this column"


async def test_pages_are_stable_and_bounded(fleet):
    first = await listed(fleet, page_size=3, sort_by="browser", sort_order="asc")
    second = await listed(fleet, page=2, page_size=3, sort_by="browser", sort_order="asc")
    assert first["total"] == second["total"] == 4 and len(first["items"]) == 3 and len(second["items"]) == 1
    keys = [entry["inventory_key"] for entry in first["items"] + second["items"]]
    assert keys == [KEYS["sider"], KEYS["helper"], KEYS["edge"], KEYS["legacy"]]
    assert (await listed(fleet, page=3, page_size=3))["items"] == []
    for params in ({"page": 0}, {"page_size": 0}, {"page_size": 101}):
        assert (await fleet.client.get("/api/v1/extensions/inventory", params=params)).status_code == 422


@pytest.mark.parametrize(
    ("params", "detail"),
    [
        ({"sort_by": "device_digest"}, "Invalid sort"),
        ({"sort_by": "identity_basis"}, "Invalid sort"),
        ({"sort_order": "random"}, "Invalid sort"),
        ({"enabled": "yes"}, "Invalid enabled filter"),
        ({"install_source": "store,sideload"}, "Invalid install source"),
        ({"install_source": "STORE"}, "Invalid install source"),
        ({"catalog_match": "both"}, "Invalid catalog match filter"),
    ],
)
async def test_invalid_sort_and_filter_values_are_rejected(fleet, params, detail):
    response = await fleet.client.get("/api/v1/extensions/inventory", params=params)
    assert response.status_code == 422 and response.json()["detail"] == detail
    export = await fleet.client.post("/api/v1/exports/extension-inventory", params=params)
    assert export.status_code == 422 and await audit_entries(fleet) == []


async def test_viewers_get_aggregates_only_and_never_a_host_user_or_profile_value(fleet):
    fleet.actor.role = "viewer"
    for method, path in (
        ("GET", "/api/v1/extensions/inventory"),
        ("GET", "/api/v1/extensions/version-changes"),
        ("GET", f"/api/v1/extensions/inventory/{KEYS['sider']}/versions"),
        ("POST", "/api/v1/exports/extension-inventory"),
    ):
        response = await fleet.client.request(method, path)
        assert response.status_code == 403, path
        assert not any(value in response.text for value in PRIVATE_VALUES)
    assert await audit_entries(fleet) == []
    response = await fleet.client.get("/api/v1/extensions/inventory/summary")
    assert response.status_code == 200, response.text
    assert not any(value in response.text for value in PRIVATE_VALUES)
    summary = response.json()
    assert set(summary) == set(ExtensionInventorySummary.model_fields)
    counts = (summary["installations"], summary["hosts"], summary["extensions"], summary["catalog_matched"])
    assert counts == (4, 2, 3, 2)
    assert summary["by_enabled"] == {"true": 1, "false": 1, "unknown": 2}
    assert summary["by_browser"] == {"chrome": 2, "edge": 1, "firefox": 1}
    assert summary["by_install_source"] == {
        **{source: 0 for source in INVENTORY_INSTALL_SOURCES}, "store": 1, "policy": 1, "user": 1, "": 1
    }
    # The change three days ago and the one two hours ago; not the one eight days ago, nor history of
    # the expired or re-keyed installations.
    assert summary["version_changes_7d"] == 2
    assert summary["limitations"] == LIMITATIONS and "not employee monitoring" in LIMITATIONS[0]
    assert summary["identity_window"]["days"] == 30 and summary["identity_mode"] == "raw"
    fleet.actor.role = "analyst"
    assert (await fleet.client.get("/api/v1/extensions/inventory/summary")).json()["installations"] == 4


async def test_installation_history_lists_changes_newest_first_inside_the_window(fleet):
    response = await fleet.client.get(f"/api/v1/extensions/inventory/{KEYS['sider']}/versions")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["installation"]["inventory_key"] == KEYS["sider"]
    assert body["installation"]["detection_id"] == fleet.detection_id
    assert body["installation"]["present_in_latest_snapshot"] is True
    assert [(change["from_version"], change["to_version"]) for change in body["changes"]] == [
        ("1.1.0", "1.2.0"), ("1.0.0", "1.1.0")
    ]
    assert [utc(change["observed_at"]) for change in body["changes"]] == [
        NOW - timedelta(days=3), NOW - timedelta(days=8)
    ]
    assert all(change["inventory_key"] == KEYS["sider"] for change in body["changes"])
    assert body["identity_window"]["days"] == 30 and body["identity_mode"] == "raw"
    for key, status in ((KEYS["edge"], 200), (KEYS["expired"], 404), (KEYS["stale"], 404), ("f" * 64, 404)):
        assert (await fleet.client.get(f"/api/v1/extensions/inventory/{key}/versions")).status_code == status, key
    assert (await fleet.client.get("/api/v1/extensions/inventory/not-a-key/versions")).status_code == 422
    edge = (await fleet.client.get(f"/api/v1/extensions/inventory/{KEYS['edge']}/versions")).json()
    assert edge["installation"]["present_in_latest_snapshot"] is False and len(edge["changes"]) == 1


async def test_version_change_feed_is_clamped_to_the_identity_window_and_filtered(fleet):
    async def feed(**params):
        response = await fleet.client.get("/api/v1/extensions/version-changes", params=params)
        assert response.status_code == 200, response.text
        return response.json()

    body = await feed()
    assert body["total"] == 3 and body["page"] == 1 and body["page_size"] == 25
    assert [(change["inventory_key"], change["to_version"]) for change in body["items"]] == [
        (KEYS["edge"], "1.1.0"), (KEYS["sider"], "1.2.0"), (KEYS["sider"], "1.1.0")
    ]
    as_of = utc(body["identity_window"]["as_of"])
    assert utc(body["since"]) == as_of - timedelta(days=30) and utc(body["until"]) == as_of
    for change in body["items"]:
        assert not {"device_digest", "user_digest", "identity_basis"} & set(change)
    assert (await feed(since=(NOW - timedelta(days=5)).isoformat()))["total"] == 2
    assert (await feed(until=(NOW - timedelta(days=5)).isoformat()))["total"] == 1
    clamped = await feed(since=(NOW - timedelta(days=40)).isoformat(), until=(NOW + timedelta(days=5)).isoformat())
    assert clamped["total"] == 3
    assert utc(clamped["since"]) == utc(clamped["identity_window"]["as_of"]) - timedelta(days=30)
    assert utc(clamped["until"]) == utc(clamped["identity_window"]["as_of"])
    # A naive timestamp is read as UTC; an empty window is empty, not an error.
    assert (await feed(since=(NOW - timedelta(days=5)).replace(tzinfo=None).isoformat()))["total"] == 2
    assert (await feed(since=NOW.isoformat(), until=(NOW - timedelta(days=1)).isoformat()))["total"] == 0
    assert (await feed(browser="edge"))["total"] == 1 and (await feed(browser="edge,chrome"))["total"] == 3
    assert (await feed(host="ws-alice"))["total"] == 3 and (await feed(host="laptop"))["total"] == 0
    assert (await feed(extension_id=SIDER))["total"] == 3 and (await feed(extension_id=HELPER))["total"] == 0
    page = await feed(page=2, page_size=2)
    assert page["total"] == 3 and [change["to_version"] for change in page["items"]] == ["1.1.0"]
    assert (await fleet.client.get("/api/v1/extensions/version-changes", params={"since": "soon"})).status_code == 422


async def test_export_carries_the_warning_every_filter_and_an_audit_entry_and_is_never_cached(fleet):
    response = await fleet.client.post(
        "/api/v1/exports/extension-inventory",
        params={"format": "csv", "browser": "chrome", "sort_by": "extension_name", "sort_order": "asc"},
    )
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["content-disposition"] == "attachment; filename=open-shadow-ai-extension-inventory.csv"
    assert response.text.startswith(ANTI_HR_WARNING)
    rows = list(csv.reader(io.StringIO(response.text.removeprefix(ANTI_HR_WARNING))))
    assert rows[0] == list(INVENTORY_EXPORT_COLUMNS)
    exported = [dict(zip(rows[0], values, strict=True)) for values in rows[1:]]
    assert [entry["inventory_key"] for entry in exported] == [KEYS["sider"], KEYS["helper"]]
    sider = exported[0]
    assert (sider["host_label"], sider["user_label"], sider["profile"]) == ("WS-ALICE-01", "alice", "Default")
    assert (sider["enabled"], sider["present_in_latest_snapshot"], sider["detection_id"]) == (
        "true", "true", fleet.detection_id
    )
    assert utc(sider["last_seen_at"]) == NOW and sider["wire_version"] == "2"
    assert (exported[1]["enabled"], exported[1]["version"], exported[1]["detection_id"]) == ("false", "", "")
    assert "laptop-b" not in response.text and "rekeyed-host" not in response.text and "old-host" not in response.text
    [entry] = await audit_entries(fleet)
    assert (entry.action, entry.username) == ("export_extension_inventory", "analyst")
    assert entry.user_id == fleet.actor.user_id
    assert entry.details == {"format": "csv", "count": 2, "filters": {"browser": "chrome"}}

    response = await fleet.client.post(
        "/api/v1/exports/extension-inventory", params={"format": "json", "enabled": "unknown"}
    )
    assert response.status_code == 200, response.text
    assert response.headers["content-disposition"] == "attachment; filename=open-shadow-ai-extension-inventory.json"
    body = response.json()
    assert body["warning"].startswith("WARNING: ShadAI is an IT governance tool") and body["count"] == 2
    assert {entry["inventory_key"] for entry in body["installations"]} == {KEYS["edge"], KEYS["legacy"]}
    assert body["identity_window"]["days"] == 30 and body["identity_mode"] == "raw"
    legacy = next(entry for entry in body["installations"] if entry["inventory_key"] == KEYS["legacy"])
    assert legacy["enabled"] is None and legacy["present_in_latest_snapshot"] is True
    assert [entry.details for entry in await audit_entries(fleet)][1] == {
        "format": "json", "count": 2, "filters": {"enabled": "unknown"}
    }


def test_csv_cells_that_a_spreadsheet_would_run_as_formulas_are_neutralised():
    from shadai.api.exports import _csv_value

    # Extension names come from manifests anyone can publish; labels and profiles are endpoint text.
    for hostile in ("=HYPERLINK(\"https://example.invalid\")", "+1+1", "-2+3", "@SUM(A1)", "\tx", "\rx"):
        assert _csv_value(hostile) == "'" + hostile
    assert [_csv_value(value) for value in ("Sider", "1.2.3", "", None, True, False)] == [
        "Sider", "1.2.3", "", "", "true", "false"
    ]


async def test_every_response_states_when_labels_are_pseudonyms(fleet):
    get_config().security.pseudonymize_identities = True
    for path in (
        "/api/v1/extensions/inventory",
        "/api/v1/extensions/inventory/summary",
        f"/api/v1/extensions/inventory/{KEYS['sider']}/versions",
        "/api/v1/extensions/version-changes",
    ):
        response = await fleet.client.get(path)
        assert response.status_code == 200 and response.json()["identity_mode"] == "pseudonymized", path
    export = await fleet.client.post("/api/v1/exports/extension-inventory", params={"format": "json"})
    assert export.json()["identity_mode"] == "pseudonymized"


async def test_expired_and_rekeyed_rows_are_invisible_everywhere_until_the_purge_removes_them(fleet):
    get_config().retention.identity_days = 1
    async with fleet.sessions() as session:
        assert await session.scalar(select(func.count()).select_from(ExtensionInventoryORM)) == 6
        assert await session.scalar(select(func.count()).select_from(ExtensionVersionChangeORM)) == 6
    body = await listed(fleet)
    assert body["total"] == 3 and body["identity_window"]["days"] == 1
    assert {entry["inventory_key"] for entry in body["items"]} == {KEYS["sider"], KEYS["helper"], KEYS["edge"]}
    assert (await listed(fleet, enabled="unknown"))["total"] == 1
    assert (await fleet.client.post("/api/v1/exports/extension-inventory", params={"format": "json"})).json()[
        "count"
    ] == 3
    summary = (await fleet.client.get("/api/v1/extensions/inventory/summary")).json()
    assert (summary["installations"], summary["hosts"], summary["version_changes_7d"]) == (3, 1, 1)
    assert summary["by_install_source"][""] == 0 and summary["by_browser"] == {"chrome": 2, "edge": 1}
    feed = (await fleet.client.get("/api/v1/extensions/version-changes")).json()
    assert [change["inventory_key"] for change in feed["items"]] == [KEYS["edge"]]
    history = (await fleet.client.get(f"/api/v1/extensions/inventory/{KEYS['sider']}/versions")).json()
    assert history["changes"] == []


def test_inventory_queries_always_filter_the_window_and_the_key_and_order_stably():
    now = datetime.now(UTC)
    query = order_inventory(installations_select(visible_installations(now) + inventory_filters()), "version", "desc")
    sql = str(query)
    assert "extension_inventory.last_seen_at >= :last_seen_at_1" in sql
    assert "extension_inventory.identity_basis = :identity_basis_1" in sql
    assert "LEFT OUTER JOIN detections ON detections.catalog_item_id = extension_inventory.catalog_item_id" in sql
    assert "max(extension_inventory_1.last_seen_at)" in sql
    assert "extension_inventory_1.device_digest = extension_inventory.device_digest" in sql
    assert sql.endswith("ORDER BY extension_inventory.version DESC NULLS LAST, extension_inventory.inventory_key")
    ascending = str(order_inventory(select(ExtensionInventoryORM), "host_label", "asc"))
    assert ascending.endswith("ORDER BY extension_inventory.host_label ASC, extension_inventory.inventory_key")
    assert set(INVENTORY_SORT_COLUMNS) <= set(ExtensionInventoryORM.__table__.columns.keys())
    assert not {"device_digest", "user_digest", "identity_basis"} & set(INVENTORY_SORT_COLUMNS)
