"""Correlator: upserts detection objects by grouping multi-source signals.

v2 fixes:
- User/device counts tracked via observed, normalized SQL membership
- Strongest per-source confidence_base preserved across arrival order
- Race condition prevented via INSERT ON CONFLICT
- Risk factors wired (bytes_out, OAuth scopes, classification)
- Governance lookup integrated
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from ipaddress import ip_address

import structlog
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from sqlalchemy import delete, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from shadai.engine.governance import apply_policy
from shadai.engine.scorer import Signal, compute_confidence, compute_risk, generate_reasoning_summary
from shadai.models.catalog import CatalogItemRead
from shadai.models.detection import DetectionORM
from shadai.models.event import NETWORK_PROTOCOLS, CanonicalEvent, NetworkProtocol, network_hostname
from shadai.models.evidence_identity import EvidenceIdentityORM
from shadai.models.governance import GovernanceORM
from shadai.models.receipts import CorrelationReceiptORM
from shadai.utils.privacy import (
    current_identity_counts,
    identity_cutoff,
    keyed_identity,
    membership_basis,
    sanitize_evidence,
    verified_privacy_stamp,
)

logger = structlog.get_logger()

ENTITY_TYPE_MAP: dict[tuple[str, str], str] = {
    ("endpoint", "local_runtime"): "local_runtime",
    ("endpoint", "agent_automation"): "local_runtime",
    ("browser", "browser_extension_ai"): "browser_extension",
    ("oauth", "ai_platform"): "oauth_app",
}


def _derive_entity_type(source_type: str, category: str) -> str:
    key = (source_type, category)
    if key in ENTITY_TYPE_MAP:
        return ENTITY_TYPE_MAP[key]
    if source_type == "endpoint":
        return "local_container" if "container" in category else "desktop_app"
    if source_type == "browser":
        return "browser_extension"
    if source_type == "oauth":
        return "oauth_app"
    if source_type in ("dns", "proxy", "network"):
        return "api_service" if "api" in category or "platform" in category else "saas_app"
    return "saas_app"


class NetworkObservation(BaseModel):
    """Allowlisted evidence JSON; this model adds no canonical/ClickHouse columns."""

    model_config = ConfigDict(extra="forbid")

    timestamp: datetime
    protocol: NetworkProtocol
    domain: str
    src_ip: str
    dst_ip: str
    dst_port: int = Field(ge=0, le=65535)
    collector_id: str = Field(min_length=1, max_length=255)
    event_id: uuid.UUID

    @field_validator("timestamp")
    @classmethod
    def timestamp_utc(cls, value):
        return CanonicalEvent.timezone_required(value)

    @field_validator("domain")
    @classmethod
    def hostname_only(cls, value):
        return network_hostname(value)

    @field_validator("src_ip", "dst_ip")
    @classmethod
    def address_only(cls, value):
        if "%" in value:
            raise ValueError("Scoped addresses are not retained")
        return str(ip_address(value)) if value else ""


def _network_context(event: CanonicalEvent, previous: dict | None = None, *, now: datetime | None = None) -> dict:
    """Bounded metadata from validated canonical fields; never retain packet content."""
    now = now or datetime.now(UTC)
    previous = sanitize_evidence({"network": previous or {}}, now=now)["network"]
    counts = {
        protocol: max(0, int(previous.get("protocol_counts", {}).get(protocol, 0))) for protocol in NETWORK_PROTOCOLS
    }
    counts[event.protocol] += 1
    observation = NetworkObservation(**event.model_dump(include=set(NetworkObservation.model_fields))).model_dump(
        mode="json"
    )
    observations = []
    for value in previous.get("network_observations", [])[-9:]:
        try:
            observations.append(NetworkObservation.model_validate(value).model_dump(mode="json"))
        except ValidationError:
            # Do not propagate unknown legacy keys or malformed evidence into the allowlist.
            continue
    section = {"protocol_counts": counts, "network_observations": observations + [observation]}
    retained = sanitize_evidence({"network": section}, now=now)["network"]
    return {"protocol_counts": retained["protocol_counts"], "network_observations": retained["network_observations"]}


async def sync_identity_members(session, detection: DetectionORM, event: CanonicalEvent, now: datetime) -> None:
    """Called while the detection/catalog lock is held, in its receipt transaction."""
    cutoff = identity_cutoff(now)
    bundle = sanitize_evidence(detection.evidence_bundle, now=now)
    basis = membership_basis()
    if bundle.get("_identity_basis") != basis:
        await session.execute(
            delete(EvidenceIdentityORM).where(EvidenceIdentityORM.detection_id == detection.detection_id)
        )
        window = bundle.get("_identity_window")
        window = dict(window) if isinstance(window, dict) else {}
        reason = "key_changed" if bundle.get("_identity_basis") else "initialized"
        window.update(basis_reset_at=now.isoformat(), basis_reset_reason=reason)
        bundle["_identity_window"], bundle["_identity_basis"] = window, basis
    detection.evidence_bundle = bundle
    await session.execute(
        delete(EvidenceIdentityORM).where(
            EvidenceIdentityORM.detection_id == detection.detection_id, EvidenceIdentityORM.last_seen_at < cutoff
        )
    )
    if event.timestamp >= cutoff:
        fields = (
            ("user", "user_id" if event.user_id else "username"),
            ("device", "device_id" if event.device_id else "hostname"),
        )
        for kind, field in fields:
            value = getattr(event, field)
            if not value:
                continue
            digest = keyed_identity(kind, value, field=field, already_pseudonymous=verified_privacy_stamp(event))
            member = await session.get(EvidenceIdentityORM, (detection.detection_id, kind, digest))
            if member is None:
                session.add(
                    EvidenceIdentityORM(
                        detection_id=detection.detection_id,
                        kind=kind,
                        identity_digest=digest,
                        last_seen_at=event.timestamp,
                    )
                )
            else:
                last_seen = member.last_seen_at
                if last_seen.tzinfo is None:
                    last_seen = last_seen.replace(tzinfo=UTC)
                member.last_seen_at = max(last_seen, event.timestamp)
    await session.flush()
    counts = (await current_identity_counts(session, [detection.detection_id], now=now))[detection.detection_id]
    detection.impacted_users_count, detection.impacted_devices_count = counts["user"], counts["device"]


class Correlator:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]):
        self._session_factory = session_factory

    async def upsert_detection(
        self,
        event: CanonicalEvent,
        catalog_item: CatalogItemRead,
        match_field: str,
        match_confidence: float,
    ) -> uuid.UUID:
        async with self._session_factory() as session:
            # A catalog lock also serializes the absent-row case; row locks cannot.
            await session.execute(
                text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
                {"key": "catalog:" + catalog_item.catalog_item_id},
            )
            inserted = await session.scalar(
                pg_insert(CorrelationReceiptORM)
                .values(
                    event_id=event.event_id,
                    catalog_item_id=catalog_item.catalog_item_id,
                )
                .on_conflict_do_nothing()
                .returning(CorrelationReceiptORM.event_id)
            )
            if inserted is None:
                existing_id = await session.scalar(
                    select(DetectionORM.detection_id).where(
                        DetectionORM.catalog_item_id == catalog_item.catalog_item_id
                    )
                )
                await session.commit()
                return existing_id
            # Try to find existing detection
            result = await session.execute(
                select(DetectionORM)
                .where(DetectionORM.catalog_item_id == catalog_item.catalog_item_id)
                .with_for_update()
            )
            detection = result.scalar_one_or_none()

            now = datetime.now(UTC)
            event_ts = event.timestamp or now

            # Lookup governance for this catalog item
            gov_result = await session.execute(
                select(GovernanceORM)
                .where(
                    GovernanceORM.target_type == "catalog_item",
                    GovernanceORM.target_id == catalog_item.catalog_item_id,
                )
                .order_by(GovernanceORM.updated_at.desc())
                .limit(1)
            )
            governance = gov_result.scalar_one_or_none()
            gov_classification = (
                governance.org_classification
                if governance and governance.approval_status == "active"
                else "unknown"
                if governance
                else None
            )

            if detection is None:
                detection = self._create_detection(
                    event,
                    catalog_item,
                    match_field,
                    match_confidence,
                    event_ts,
                    now,
                    gov_classification,
                )
                if governance:
                    apply_policy(detection, governance)
                session.add(detection)
                await session.flush()
                await sync_identity_members(session, detection, event, now)
                await session.commit()
                logger.info(
                    "detection_created",
                    name=catalog_item.canonical_name,
                    confidence=detection.confidence_score,
                    risk=detection.risk_score,
                )
            else:
                await sync_identity_members(session, detection, event, now)
                if governance:
                    detection.governance_id = governance.governance_id
                    detection.classification = gov_classification
                self._update_detection(
                    detection,
                    event,
                    match_field,
                    match_confidence,
                    event_ts,
                    now,
                    gov_classification,
                )
                if governance:
                    apply_policy(detection, governance)
                await session.commit()
                logger.debug("detection_updated", name=detection.entity_name, events=detection.total_events_count)

            return detection.detection_id

    def _create_detection(
        self,
        event: CanonicalEvent,
        catalog_item: CatalogItemRead,
        match_field: str,
        match_confidence: float,
        event_ts: datetime,
        now: datetime,
        gov_classification: str | None,
    ) -> DetectionORM:
        entity_type = _derive_entity_type(event.source_type, catalog_item.category)

        signal = Signal(
            source_type=event.source_type, confidence_base=match_confidence, event_count=1, match_field=match_field
        )
        confidence, conf_factors = compute_confidence([signal])

        # Initial one-event counts are replaced by exact SQL membership in upsert.
        current_identity = event_ts >= identity_cutoff(now)
        users_count = int(current_identity and bool(event.user_id or event.username))
        devices_count = int(current_identity and bool(event.device_id or event.hostname))

        risk, risk_factors = compute_risk(
            entity_type=entity_type,
            impacted_users_count=users_count,
            total_events_count=1,
            total_bytes_out=event.bytes_out,
            classification=gov_classification or catalog_item.default_trust_level or "unknown",
            oauth_scopes=event.oauth_scopes if event.oauth_scopes else None,
            governance_classification=gov_classification,
        )
        reasoning = generate_reasoning_summary(confidence, conf_factors, risk, risk_factors)

        status = "suspected" if confidence < 0.70 else "probable" if confidence < 0.90 else "high_confidence"
        # URL paths and user agents are matched at ingestion and never retained.
        value = getattr(event, match_field, "")
        observed = f"{match_field}={value}" if value not in ("", None) else f"{match_field} matched at ingestion"

        return DetectionORM(
            entity_type=entity_type,
            entity_name=catalog_item.canonical_name,
            entity_category=catalog_item.category,
            catalog_item_id=catalog_item.catalog_item_id,
            classification=gov_classification or catalog_item.default_trust_level or "unknown",
            shadow_ai_status=status,
            confidence_score=confidence,
            risk_score=risk,
            first_seen_at=event_ts,
            last_seen_at=event_ts,
            impacted_users_count=users_count,
            impacted_devices_count=devices_count,
            total_events_count=1,
            source_types=[event.source_type],
            primary_evidence=f"{event.evidence_type} evidence via {event.source_type}: {observed}",
            evidence_bundle=sanitize_evidence(
                {
                    "_identity_window": {"days": (now - identity_cutoff(now)).days, "as_of": now.isoformat()},
                    "_risk_calculated_at": now.isoformat(),
                    "_bytes_out": event.bytes_out,
                    "_evidence_counts": {event.evidence_type: 1},
                    "_oauth_scopes": event.oauth_scopes or [],
                    event.source_type: {
                        "first_seen": event_ts.isoformat(),
                        "last_seen": event_ts.isoformat(),
                        "event_count": 1,
                        "matched_field": match_field,
                        "confidence_base": match_confidence,
                        "sample_values": [value] if value not in ("", None) else [],
                        "sample_observations": [
                            {"value": str(value), "field": match_field, "observed_at": event_ts.isoformat()}
                        ]
                        if value not in ("", None)
                        else [],
                        **(_network_context(event, now=now) if event.source_type == "network" else {}),
                    },
                    "confidence_factors": conf_factors,
                    "risk_factors": risk_factors,
                },
                now=now,
            ),
            reasoning_summary=reasoning,
            governance_id=None,
        )

    def _update_detection(
        self,
        detection: DetectionORM,
        event: CanonicalEvent,
        match_field: str,
        match_confidence: float,
        event_ts: datetime,
        now: datetime,
        gov_classification: str | None,
    ) -> None:
        if detection.first_seen_at.tzinfo is None:
            detection.first_seen_at = detection.first_seen_at.replace(tzinfo=UTC)
        if detection.last_seen_at.tzinfo is None:
            detection.last_seen_at = detection.last_seen_at.replace(tzinfo=UTC)
        detection.first_seen_at = min(detection.first_seen_at, event_ts)
        detection.last_seen_at = max(detection.last_seen_at, event_ts)
        detection.total_events_count += 1

        # Add source type if new
        current_sources = list(detection.source_types or [])
        if event.source_type not in current_sources:
            current_sources.append(event.source_type)
            detection.source_types = current_sources

        # Update evidence bundle
        bundle = sanitize_evidence(detection.evidence_bundle, now=now)
        window = bundle.get("_identity_window")
        window = dict(window) if isinstance(window, dict) else {}
        bundle["_identity_window"] = {**window, "days": (now - identity_cutoff(now)).days, "as_of": now.isoformat()}

        counts = dict(bundle.get("_evidence_counts", {}))
        counts[event.evidence_type] = counts.get(event.evidence_type, 0) + 1
        bundle["_evidence_counts"] = counts

        # Track cumulative bytes out
        bundle["_bytes_out"] = bundle.get("_bytes_out", 0) + event.bytes_out

        # Track OAuth scopes (union)
        existing_scopes = set(bundle.get("_oauth_scopes", []))
        if event.oauth_scopes:
            existing_scopes.update(event.oauth_scopes)
        bundle["_oauth_scopes"] = list(existing_scopes)

        # Update per-source evidence
        src_ev = bundle.get(
            event.source_type,
            {
                "first_seen": event_ts.isoformat(),
                "event_count": 0,
                "matched_field": match_field,
                "confidence_base": match_confidence,
                "sample_values": [],
            },
        )
        src_ev["first_seen"] = min(src_ev["first_seen"], event_ts.isoformat())
        src_ev["last_seen"] = max(src_ev.get("last_seen", event_ts.isoformat()), event_ts.isoformat())
        src_ev["event_count"] = src_ev.get("event_count", 0) + 1
        # Keep the strongest evidence per source, without adding confidence for repeats.
        if match_confidence > src_ev.get("confidence_base", -1):
            src_ev["confidence_base"] = match_confidence
            src_ev["matched_field"] = match_field
        samples = src_ev.get("sample_observations", [])
        new_val = getattr(event, match_field, "")
        if new_val not in ("", None):
            sample = {"value": str(new_val), "field": match_field, "observed_at": event_ts.isoformat()}
            samples = [
                value
                for value in samples
                if (value["field"], value["value"]) != (match_field, str(new_val))
                or value["observed_at"] > event_ts.isoformat()
            ]
            src_ev["sample_observations"] = samples + [sample]
        if event.source_type == "network":
            src_ev.update(_network_context(event, src_ev, now=now))
        bundle[event.source_type] = src_ev
        bundle = sanitize_evidence(bundle, now=now)

        # Rebuild signals from the strongest evidence for each source.
        signals = []
        for src_type, src_data in bundle.items():
            if src_type.startswith("_") or src_type in ("confidence_factors", "risk_factors"):
                continue
            if isinstance(src_data, dict) and "confidence_base" in src_data:
                signals.append(
                    Signal(
                        source_type=src_type,
                        confidence_base=src_data["confidence_base"],
                        # Repeated packets are not independent evidence of AI use.
                        event_count=0 if src_type == "network" else src_data.get("event_count", 1),
                        match_field=src_data.get("matched_field", ""),
                    )
                )

        # Recalculate scores
        confidence, conf_factors = compute_confidence(signals)
        risk, risk_factors = compute_risk(
            entity_type=detection.entity_type,
            impacted_users_count=detection.impacted_users_count,
            total_events_count=detection.total_events_count,
            total_bytes_out=bundle.get("_bytes_out", 0),
            classification=detection.classification,
            oauth_scopes=list(existing_scopes) if existing_scopes else None,
            governance_classification=gov_classification,
        )

        bundle["confidence_factors"] = conf_factors
        bundle["risk_factors"] = risk_factors
        bundle["_risk_score_stale"] = False
        bundle["_risk_calculated_at"] = now.isoformat()
        detection.evidence_bundle = bundle
        detection.confidence_score = confidence
        detection.risk_score = risk
        detection.reasoning_summary = generate_reasoning_summary(confidence, conf_factors, risk, risk_factors)

        # Update status (only upgrade, never downgrade)
        if confidence >= 0.90 and detection.shadow_ai_status not in ("confirmed", "false_positive"):
            detection.shadow_ai_status = "high_confidence"
        elif confidence >= 0.70 and detection.shadow_ai_status in ("suspected",):
            detection.shadow_ai_status = "probable"

        # Reactivate if stale
        if detection.shadow_ai_status in ("stale", "archived"):
            detection.shadow_ai_status = "probable"
