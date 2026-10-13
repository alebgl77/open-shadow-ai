"""The ingest worker keeps one inventory row per installation and records every version change."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

from cryptography.fernet import Fernet
from sqlalchemy import event as sqlalchemy_event
from sqlalchemy import select
from test_evidence_privacy import evidence_sessions as evidence_sessions
from test_evidence_privacy import installation, version_change

from shadai.api.ingestion import prepare_event
from shadai.config import get_config
from shadai.engine.catalog_loader import build_catalog_index
from shadai.engine.extension_inventory import (
    LABEL_LIMITS,
    describes_installation,
    inventory_digests,
    inventory_key,
    wire_version,
)
from shadai.engine.matcher import CatalogMatcher
from shadai.models.catalog import CatalogItemRead
from shadai.models.event import CanonicalEvent
from shadai.models.extension_inventory import ExtensionInventoryORM, ExtensionVersionChangeORM
from shadai.models.receipts import IngestReceiptORM
from shadai.utils.privacy import keyed_identity, membership_basis
from shadai.utils.queue_admission import QUEUE_ADMIT
from shadai.workers.ingest import EventProcessor

EXTENSION_ID = "abcdefghijklmnopabcdefghijklmnop"
SIDER = CatalogItemRead(
    catalog_item_id="sider", canonical_name="Sider", category="browser_extension_ai", extension_ids=[EXTENSION_ID]
)
NOW = datetime.now(UTC).replace(microsecond=0)


def inventory_event(**state) -> CanonicalEvent:
    """A browser inventory event as the agent API queues it (privacy applied at the boundary)."""
    values = {
        "source_type": "browser",
        "evidence_type": "inventory",
        "tenant_id": "test-org",
        "collector_id": "sensor",
        "hostname": "host-a",
        "device_id": "host-a",
        "username": "alice",
        "browser_name": "chrome",
        "browser_profile": "Default",
        "extension_id": EXTENSION_ID,
        "extension_name": "Sider",
        "extension_version": "1.0",
        "extension_enabled": True,
        "extension_install_source": "store",
        "extension_installed_at": NOW - timedelta(days=3),
        "timestamp": NOW,
    }
    values.update(state)
    return prepare_event(CanonicalEvent(**values), trusted_collector=True)


def utc(value: datetime) -> datetime:
    # SQLite hands timezone-aware columns back naive; every stored instant is UTC.
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


class Ingest:
    """An EventProcessor over real transactions with a recording ClickHouse and a permissive queue."""

    def __init__(self, sessions, *, catalog=(SIDER,), clickhouse=None):
        self.redis = AsyncMock()
        self.redis.hgetall.return_value = {}
        self.redis.eval.side_effect = lambda script, *args: ["ok", "1-0"] if script == QUEUE_ADMIT else 1
        self.persisted = []
        clickhouse = clickhouse or SimpleNamespace(execute=lambda query, rows: self.persisted.extend(rows))
        self.processor = EventProcessor(
            self.redis, clickhouse, sessions, CatalogMatcher(build_catalog_index(list(catalog)))
        )

    async def deliver(self, *events: CanonicalEvent) -> None:
        for event in events:
            await self.processor({"data": event.model_dump_json()})

    def admitted_matches(self) -> int:
        return sum(1 for call in self.redis.eval.call_args_list if call.args[0] == QUEUE_ADMIT)


async def stored(sessions):
    async with sessions() as session:
        rows = (
            await session.scalars(select(ExtensionInventoryORM).order_by(ExtensionInventoryORM.first_seen_at))
        ).all()
        changes = (
            await session.scalars(select(ExtensionVersionChangeORM).order_by(ExtensionVersionChangeORM.observed_at))
        ).all()
        receipts = (await session.scalars(select(IngestReceiptORM.event_id))).all()
    return rows, changes, receipts


async def test_first_inventory_event_creates_one_installation_row_and_no_change(evidence_sessions):
    ingest = Ingest(evidence_sessions, catalog=())
    event = inventory_event()
    await ingest.deliver(event)
    rows, changes, receipts = await stored(evidence_sessions)
    [row] = rows
    assert changes == [] and receipts == [event.event_id]
    assert ingest.persisted[0]["event_id"] == str(event.event_id) and ingest.admitted_matches() == 0
    assert row.inventory_key == inventory_key(event)
    assert (row.device_digest, row.user_digest) == inventory_digests(event)
    assert row.device_digest == keyed_identity("device", "host-a", field="device_id")
    assert row.user_digest == keyed_identity("user", "alice", field="username")
    assert (row.host_label, row.user_label, row.browser, row.profile) == ("host-a", "alice", "chrome", "Default")
    assert (row.extension_id, row.extension_name, row.version) == (EXTENSION_ID, "Sider", "1.0")
    assert (row.enabled, row.install_source) == (True, "store")
    assert utc(row.installed_at) == event.extension_installed_at
    assert utc(row.first_seen_at) == utc(row.last_seen_at) == event.timestamp
    assert row.catalog_item_id is None and row.collector_id == "sensor"
    assert row.identity_basis == membership_basis()
    assert row.last_event_id == event.event_id and row.wire_version == 2


async def test_redelivery_is_a_receipt_no_op_and_an_identical_snapshot_adds_no_change(evidence_sessions):
    ingest = Ingest(evidence_sessions)
    event = inventory_event()
    await ingest.deliver(event, event)
    rows, changes, receipts = await stored(evidence_sessions)
    assert len(rows) == 1 and changes == [] and receipts == [event.event_id] and len(ingest.persisted) == 1
    # A new event id for the same installation state at the same instant converges on the row.
    again = inventory_event()
    assert again.event_id != event.event_id
    await ingest.deliver(again)
    [row], changes, receipts = await stored(evidence_sessions)
    assert changes == [] and len(receipts) == 2
    assert row.last_event_id == again.event_id and utc(row.last_seen_at) == NOW and row.version == "1.0"


async def test_version_bump_records_exactly_one_change_and_older_replay_never_regresses(evidence_sessions):
    ingest = Ingest(evidence_sessions)
    first = inventory_event(extension_version="1.0", timestamp=NOW - timedelta(hours=2))
    second = inventory_event(extension_version="1.1", extension_name="Sider AI", extension_enabled=False)
    await ingest.deliver(first, second)
    [row], [change], receipts = await stored(evidence_sessions)
    assert len(receipts) == 2
    assert (row.version, row.extension_name, row.enabled, row.catalog_item_id) == ("1.1", "Sider AI", False, "sider")
    assert utc(row.first_seen_at) == first.timestamp and utc(row.last_seen_at) == second.timestamp
    assert row.last_event_id == second.event_id
    assert (change.inventory_key, change.event_id) == (row.inventory_key, second.event_id)
    assert (change.from_version, change.to_version) == ("1.0", "1.1")
    assert utc(change.previous_observed_at) == first.timestamp and utc(change.observed_at) == second.timestamp
    assert (change.extension_id, change.extension_name, change.browser) == (EXTENSION_ID, "Sider AI", "chrome")
    assert (change.host_label, change.user_label, change.profile, change.catalog_item_id) == (
        "host-a", "alice", "Default", "sider"
    )
    # A snapshot older than the current state is evidence only: no regression, no change.
    stale = inventory_event(extension_version="0.9", timestamp=NOW - timedelta(days=1))
    await ingest.deliver(stale)
    [row], changes, receipts = await stored(evidence_sessions)
    assert len(changes) == 1 and len(receipts) == 3
    assert row.version == "1.1" and row.last_event_id == second.event_id and utc(row.last_seen_at) == NOW
    # The same version at the same instant is not a change either.
    await ingest.deliver(inventory_event(extension_version="1.1"))
    [row], changes, _ = await stored(evidence_sessions)
    assert len(changes) == 1 and row.version == "1.1"
    # A later record that no longer reports a version is recorded as a change to "not reported".
    await ingest.deliver(inventory_event(extension_version="", timestamp=NOW + timedelta(minutes=1)))
    [row], changes, _ = await stored(evidence_sessions)
    assert row.version is None and (changes[-1].from_version, changes[-1].to_version) == ("1.1", None)
    assert len(changes) == 2


async def test_a_change_already_recorded_for_the_event_is_not_recorded_twice(evidence_sessions):
    ingest = Ingest(evidence_sessions)
    first = inventory_event(extension_version="1.0", timestamp=NOW - timedelta(hours=1))
    second = inventory_event(extension_version="1.1")
    await ingest.deliver(first)
    async with evidence_sessions.begin() as session:
        row = await session.get(ExtensionInventoryORM, inventory_key(first))
        session.add(version_change(row, second.event_id, from_version="1.0", to_version="1.1"))
    await ingest.deliver(second)
    [row], [change], receipts = await stored(evidence_sessions)
    assert row.version == "1.1" and change.event_id == second.event_id and len(receipts) == 2


async def test_events_outside_the_identity_window_are_evidence_but_never_inventory(evidence_sessions, monkeypatch):
    get_config().retention.identity_days = 1

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return NOW

    monkeypatch.setattr("shadai.workers.ingest.datetime", Clock)
    ingest = Ingest(evidence_sessions)
    cutoff = NOW - timedelta(days=1)
    outside = inventory_event(timestamp=cutoff - timedelta(microseconds=1))
    await ingest.deliver(outside)
    rows, changes, receipts = await stored(evidence_sessions)
    assert rows == [] and changes == [] and receipts == [outside.event_id]
    assert len(ingest.persisted) == 1 and ingest.admitted_matches() == 1
    edge = inventory_event(timestamp=cutoff)
    await ingest.deliver(edge)
    [row], _, receipts = await stored(evidence_sessions)
    assert utc(row.first_seen_at) == cutoff and len(receipts) == 2


async def test_stale_basis_row_is_wiped_and_a_new_key_starts_a_new_installation(evidence_sessions):
    ingest = Ingest(evidence_sessions)
    event = inventory_event(extension_version="1.1")
    key = inventory_key(event)
    async with evidence_sessions.begin() as session:
        row = installation(key=key, identity_basis="s" * 64, version="1.0", last_seen_at=NOW + timedelta(days=1))
        session.add(row)
        await session.flush()
        session.add(version_change(row))
    await ingest.deliver(event)
    [row], changes, _ = await stored(evidence_sessions)
    assert changes == [] and row.identity_basis == membership_basis()
    assert (row.device_digest, row.user_digest) == inventory_digests(event)
    assert utc(row.first_seen_at) == utc(row.last_seen_at) == NOW and row.version == "1.1"
    assert row.last_event_id == event.event_id
    # A new encryption key changes the digests and the key: the old row is left for retention.
    get_config().security.encryption_key = Fernet.generate_key().decode()
    rekeyed = inventory_event(extension_version="1.1", timestamp=NOW + timedelta(minutes=1))
    assert inventory_key(rekeyed) != key
    await ingest.deliver(rekeyed)
    rows, changes, _ = await stored(evidence_sessions)
    assert changes == [] and [row.inventory_key for row in rows] == [key, inventory_key(rekeyed)]
    assert rows[0].identity_basis != rows[1].identity_basis == membership_basis()
    assert rows[0].last_event_id == event.event_id


async def test_pseudonymised_and_raw_events_share_digests_and_keys_but_not_labels(evidence_sessions):
    config = get_config()
    ingest = Ingest(evidence_sessions)
    raw = inventory_event(timestamp=NOW - timedelta(hours=1))
    assert raw.privacy_stamp == "" and raw.username == "alice"
    await ingest.deliver(raw)
    config.security.pseudonymize_identities = True
    aliased = inventory_event()
    assert aliased.privacy_stamp and aliased.username.startswith("p1_") and aliased.hostname.startswith("p1_")
    assert aliased.browser_profile == "Default"
    assert inventory_digests(aliased) == inventory_digests(raw) and inventory_key(aliased) == inventory_key(raw)
    [row], _, _ = await stored(evidence_sessions)
    assert (row.host_label, row.user_label) == ("host-a", "alice")
    await ingest.deliver(aliased)
    [row], changes, receipts = await stored(evidence_sessions)
    assert changes == [] and len(receipts) == 2
    assert (row.host_label, row.user_label) == (aliased.hostname, aliased.username)
    assert (row.device_digest, row.user_digest) == inventory_digests(raw)
    for value in ("alice", "host-a"):
        assert value not in (row.host_label, row.user_label)
    # A version change observed under pseudonymisation carries the aliases, never the plaintext.
    await ingest.deliver(inventory_event(extension_version="2.0", timestamp=NOW + timedelta(minutes=1)))
    _, [change], _ = await stored(evidence_sessions)
    assert (change.host_label, change.user_label) == (aliased.hostname, aliased.username)


async def test_wire_v1_records_are_host_level_rows_apart_from_v2_installations(evidence_sessions):
    ingest = Ingest(evidence_sessions)
    legacy = inventory_event(
        username="",
        browser_profile="",
        extension_name="",
        extension_version="",
        extension_enabled=None,
        extension_install_source="",
        extension_installed_at=None,
        timestamp=NOW - timedelta(hours=1),
    )
    assert wire_version(legacy) == 1 and wire_version(inventory_event()) == 2
    await ingest.deliver(legacy)
    [row], changes, _ = await stored(evidence_sessions)
    assert changes == [] and row.wire_version == 1
    assert (row.user_digest, row.user_label, row.profile, row.extension_name) == (None, None, "", "")
    assert (row.version, row.enabled, row.install_source, row.installed_at) == (None, None, "", None)
    assert row.device_digest == keyed_identity("device", "host-a", field="device_id")
    # The upgraded agent reports the same extension per user and profile: a distinct installation.
    await ingest.deliver(inventory_event())
    rows, changes, _ = await stored(evidence_sessions)
    assert changes == [] and [row.wire_version for row in rows] == [1, 2]
    assert rows[0].inventory_key != rows[1].inventory_key and rows[0].version is None


async def test_unmatched_extensions_are_inventoried_and_matched_ones_carry_the_catalog_item(evidence_sessions):
    ingest = Ingest(evidence_sessions)
    matched = inventory_event()
    unmatched = inventory_event(extension_id="zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", extension_name="Unknown helper")
    await ingest.deliver(matched, unmatched)
    rows, changes, receipts = await stored(evidence_sessions)
    assert changes == [] and len(receipts) == 2 and ingest.admitted_matches() == 1
    by_extension = {row.extension_id: row for row in rows}
    assert by_extension[EXTENSION_ID].catalog_item_id == "sider"
    assert by_extension["zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"].catalog_item_id is None
    assert by_extension["zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"].extension_name == "Unknown helper"


async def test_only_browser_inventory_evidence_naming_an_extension_is_inventory(evidence_sessions):
    ingest = Ingest(evidence_sessions)
    observed = inventory_event(evidence_type="observation")
    nameless = inventory_event(extension_id="")
    endpoint = prepare_event(
        CanonicalEvent(
            source_type="endpoint", tenant_id="test-org", hostname="host-a", process_name="sider", timestamp=NOW
        ),
        trusted_collector=True,
    )
    assert not any(describes_installation(event) for event in (observed, nameless, endpoint))
    assert describes_installation(inventory_event())
    await ingest.deliver(observed, nameless, endpoint)
    rows, changes, receipts = await stored(evidence_sessions)
    assert rows == [] and changes == [] and len(receipts) == 3 and len(ingest.persisted) == 3


async def test_labels_from_other_collectors_are_bounded_to_the_columns(evidence_sessions):
    ingest = Ingest(evidence_sessions)
    event = inventory_event(
        browser_name="b" * 100, hostname="h" * 300, device_id="", username="u" * 300, collector_id="c" * 300
    )
    await ingest.deliver(event)
    [row], _, _ = await stored(evidence_sessions)
    assert row.inventory_key == inventory_key(event)
    assert (len(row.browser), len(row.host_label), len(row.user_label), len(row.collector_id)) == (
        LABEL_LIMITS["browser"], LABEL_LIMITS["host_label"], LABEL_LIMITS["user_label"], LABEL_LIMITS["collector_id"]
    )
    # The digests cover the full identity values, so two long hostnames never share a row.
    assert row.device_digest == keyed_identity("device", "h" * 300, field="hostname")
    assert row.user_digest == keyed_identity("user", "u" * 300, field="username")


async def test_inventory_lock_is_always_taken_after_the_event_lock(evidence_sessions):
    locks = []

    def record(connection, cursor, statement, parameters, context, executemany):
        if "pg_advisory_xact_lock" in statement:
            locks.append(str(parameters))

    sqlalchemy_event.listen(evidence_sessions.kw["bind"].sync_engine, "before_cursor_execute", record)
    event = inventory_event()
    await Ingest(evidence_sessions).deliver(event)
    assert len(locks) == 2
    assert f"event:{event.event_id}" in locks[0] and f"inventory:{inventory_key(event)}" in locks[1]
