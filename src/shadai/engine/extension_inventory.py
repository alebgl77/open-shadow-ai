"""Authoritative browser extension inventory, maintained by the ingest worker.

ClickHouse keeps every raw inventory event. PostgreSQL holds one row per installation (tenant,
device, user, browser, profile and extension) with the state it last reported, plus one row per
observed version change. Both are written inside the ingest receipt transaction, so a persisted
event and its inventory state always commit together and a redelivered event changes nothing.

A row carries keyed identity digests and the post-privacy labels the event itself already has
(plaintext in raw mode, an alias when identities are pseudonymised); never a raw identifier and
never the permissions, which stay on the agent.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from hashlib import sha256
from typing import NamedTuple

from sqlalchemy import delete, distinct, func, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert

from shadai.models.event import CanonicalEvent
from shadai.models.extension_inventory import ExtensionInventoryORM, ExtensionVersionChangeORM
from shadai.utils.privacy import (
    VERSION_EVIDENCE_LIMIT,
    identity_cutoff,
    keyed_identity,
    membership_basis,
    verified_privacy_stamp,
)

# Column widths of the inventory tables. The agent already bounds its records to these, so only
# a record from another collector is ever cut; a value the columns cannot hold must not block
# the ingest stream on endless datastore retries.
LABEL_LIMITS = {"browser": 64, "host_label": 255, "user_label": 255, "collector_id": 255}


def _label(value: str, column: str) -> str:
    return value[: LABEL_LIMITS[column]]


def describes_installation(event: CanonicalEvent) -> bool:
    """Only browser inventory evidence that names an extension on an identified device describes an installation.

    The agent API always names the host; an event from the generic ingest path without a device or
    host name cannot be keyed to a device, so it stays raw evidence and never becomes inventory.
    """
    return (
        event.source_type == "browser"
        and event.evidence_type == "inventory"
        and bool(event.extension_id)
        and bool(event.device_id or event.hostname)
    )


def inventory_digests(event: CanonicalEvent) -> tuple[str, str | None]:
    """Keyed device and user digests, derived exactly like detection identity members.

    The digest is the same whether the event arrived pseudonymised or raw, so a mode toggle
    keeps every installation under its key; only a new encryption key changes it.
    """
    pseudonymous = verified_privacy_stamp(event)
    device_field = "device_id" if event.device_id else "hostname"
    device = keyed_identity(
        "device", getattr(event, device_field), field=device_field, already_pseudonymous=pseudonymous
    )
    user = (
        keyed_identity("user", event.username, field="username", already_pseudonymous=pseudonymous)
        if event.username
        else None
    )
    return device, user


def inventory_key(event: CanonicalEvent, *, digests: tuple[str, str | None] | None = None) -> str:
    """sha256 of the JSON list [tenant_id, device_digest, user_digest or "", browser, profile, extension_id]."""
    device_digest, user_digest = digests or inventory_digests(event)
    payload = json.dumps(
        [
            event.tenant_id,
            device_digest,
            user_digest or "",
            _label(event.browser_name, "browser"),
            event.browser_profile,
            event.extension_id,
        ],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return sha256(payload.encode()).hexdigest()


def wire_version(event: CanonicalEvent) -> int:
    """1 for a record that carried no per-installation state (a wire v1 agent), else 2."""
    return 2 if event.username or event.browser_profile or event.extension_install_source else 1


async def record_inventory(session, event: CanonicalEvent, match, *, now: datetime) -> None:
    """Upsert the installation an inventory event describes and record a version change.

    Called inside the ingest receipt transaction with the event lock already held. The inventory
    lock is always taken second, so parallel workers never wait on each other in opposite order.
    An event older than the identity window is persisted as evidence but never becomes inventory,
    and an older replay never regresses the current state.
    """
    if not describes_installation(event) or event.timestamp < identity_cutoff(now):
        return
    digests = inventory_digests(event)
    key = inventory_key(event, digests=digests)
    await session.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"), {"key": "inventory:" + key}
    )
    row = await session.get(ExtensionInventoryORM, key, with_for_update=True)
    basis = membership_basis()
    if row is not None and row.identity_basis != basis:
        # Digests derived under another key mean nothing now: forget the installation and start over.
        await session.execute(
            delete(ExtensionVersionChangeORM).where(ExtensionVersionChangeORM.inventory_key == key)
        )
        await session.delete(row)
        await session.flush()
        row = None
    version = event.extension_version or None
    # Labels follow the latest event, so a privacy mode change shows on the next snapshot.
    state = {
        "host_label": _label(event.hostname, "host_label"),
        "user_label": _label(event.username, "user_label") or None,
        "extension_name": event.extension_name or (row.extension_name if row is not None else ""),
        "version": version,
        "enabled": event.extension_enabled,
        "install_source": event.extension_install_source,
        "installed_at": event.extension_installed_at,
        "catalog_item_id": match.catalog_item_id if match else None,
        "collector_id": _label(event.collector_id, "collector_id"),
        "last_seen_at": event.timestamp,
        "last_event_id": event.event_id,
        "wire_version": wire_version(event),
    }
    if row is None:
        device_digest, user_digest = digests
        session.add(
            ExtensionInventoryORM(
                inventory_key=key,
                device_digest=device_digest,
                user_digest=user_digest,
                browser=_label(event.browser_name, "browser"),
                profile=event.browser_profile,
                extension_id=event.extension_id,
                first_seen_at=event.timestamp,
                identity_basis=basis,
                **state,
            )
        )
        return
    last_seen = row.last_seen_at if row.last_seen_at.tzinfo else row.last_seen_at.replace(tzinfo=UTC)
    if event.timestamp < last_seen:
        return
    if version != row.version:
        # Agent retries reuse the event id, so a change observed twice is recorded once.
        await session.execute(
            pg_insert(ExtensionVersionChangeORM)
            .values(
                change_id=uuid.uuid4(),
                inventory_key=key,
                event_id=event.event_id,
                extension_id=row.extension_id,
                extension_name=state["extension_name"],
                browser=row.browser,
                host_label=state["host_label"],
                user_label=state["user_label"],
                profile=row.profile,
                from_version=row.version,
                to_version=version,
                previous_observed_at=last_seen,
                observed_at=event.timestamp,
                catalog_item_id=state["catalog_item_id"],
            )
            .on_conflict_do_nothing(index_elements=["event_id"])
        )
    for name, value in state.items():
        setattr(row, name, value)


def visible_installations(now: datetime, model=ExtensionInventoryORM) -> list:
    """Rows inside the identity window and written under the current encryption key.

    The purge worker runs daily, so the tables can hold rows past either bound between cycles;
    every read applies both conditions itself.
    """
    return [model.last_seen_at >= identity_cutoff(now), model.identity_basis == membership_basis()]


class CatalogVersionChange(NamedTuple):
    """A version change as a detection may show it: the browser and the versions, never a host or user."""

    browser: str
    from_version: str | None
    to_version: str | None
    observed_at: datetime


async def recent_version_changes(
    session, catalog_item_id: str, *, now: datetime, limit: int = VERSION_EVIDENCE_LIMIT
) -> list[CatalogVersionChange]:
    """The newest version changes recorded for one catalog item, newest first.

    Only changes observed inside the identity window, of installations that are still visible, are
    returned; the identity-bearing columns of the change rows are never selected.
    """
    change = ExtensionVersionChangeORM
    rows = await session.execute(
        select(change.browser, change.from_version, change.to_version, change.observed_at)
        .join(ExtensionInventoryORM, ExtensionInventoryORM.inventory_key == change.inventory_key)
        .where(
            *visible_installations(now),
            change.catalog_item_id == catalog_item_id,
            change.observed_at >= identity_cutoff(now),
        )
        .order_by(change.observed_at.desc(), change.change_id)
        .limit(limit)
    )
    # SQLite hands timezone-aware columns back naive; every stored instant is UTC.
    return [
        CatalogVersionChange(browser, from_version, to_version, observed.replace(tzinfo=observed.tzinfo or UTC))
        for browser, from_version, to_version, observed in rows
    ]


async def version_distribution(session, catalog_item_id: str, *, now: datetime) -> dict[str, int]:
    """Distinct hosts per last reported version of one catalog item's visible installations.

    "" counts installations whose agent reported no version. A host with the extension in two profiles
    at different versions counts once under each version.
    """
    rows = await session.execute(
        select(ExtensionInventoryORM.version, func.count(distinct(ExtensionInventoryORM.device_digest)))
        .where(*visible_installations(now), ExtensionInventoryORM.catalog_item_id == catalog_item_id)
        .group_by(ExtensionInventoryORM.version)
    )
    return {version or "": hosts for version, hosts in rows}
