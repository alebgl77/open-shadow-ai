"""Idempotent internal pseudonymization and timestamped personal-evidence retention."""

from __future__ import annotations

import hmac
import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from hashlib import sha256

from sqlalchemy import delete, func, inspect, select

from shadai.config import get_config
from shadai.models.evidence_identity import EvidenceIdentityORM

IDENTITY_FIELDS = ("user_id", "username", "device_id", "hostname", "identity_object_id", "identity_sid")
IDENTITY_PROVIDERS = frozenset({"", "active_directory", "entra", "entra_id", "ldap", "scim", "unknown"})
SOURCE_TYPES = ("dns", "proxy", "endpoint", "browser", "oauth", "directory", "instrumented", "casb", "network")
SAMPLE_FIELDS = frozenset(
    {
        "domain",
        "sni",
        "url_host",
        "process_name",
        "parent_process",
        "extension_id",
        "extension_name",
        "oauth_app_id",
        "oauth_app_name",
        "container_name",
        "container_image",
        "local_port",
        "software_name",
        "service_name",
        "provider",
        "model",
        *IDENTITY_FIELDS,
    }
)


def derived_key(label: str, config=None) -> bytes:
    config = config or get_config()
    return hmac.digest(config.security.encryption_key.encode(), ("shadai/privacy/v1/" + label).encode(), "sha256")


def alias_for(field: str, value: str, *, config=None) -> str:
    config = config or get_config()
    payload = json.dumps([config.tenant_id, field, value], ensure_ascii=False, separators=(",", ":")).encode()
    return "p1_" + hmac.new(derived_key("field", config), payload, sha256).hexdigest()


def keyed_identity(kind: str, value: str, *, field=None, already_pseudonymous=False, config=None) -> str:
    config = config or get_config()
    field = field or ("user_id" if kind == "user" else "device_id")
    alias = value if already_pseudonymous else alias_for(field, value, config=config)
    payload = json.dumps([config.tenant_id, kind, alias], ensure_ascii=False, separators=(",", ":")).encode()
    return hmac.new(derived_key("membership", config), payload, sha256).hexdigest()


def membership_basis(config=None) -> str:
    return hmac.new(derived_key("membership", config), b"membership-basis-v1", sha256).hexdigest()


def identity_stamp(event, config=None) -> str:
    config = config or get_config()
    protected = {name: getattr(event, name) for name in (*IDENTITY_FIELDS, "src_ip", "tenant_id", "identity_provider")}
    payload = json.dumps(protected, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    return hmac.new(derived_key("stamp", config), payload, sha256).hexdigest()


def verified_privacy_stamp(event, config=None) -> bool:
    return bool(event.privacy_stamp and hmac.compare_digest(event.privacy_stamp, identity_stamp(event, config)))


def prepare_identity(event, *, trusted_internal: bool = False):
    """Only a valid server proof on a trusted queue boundary can skip HMAC.

    A client alias or copied marker at an external boundary is treated as input.
    Proof deliberately excludes event UUID, clocks and acceptance-envelope data.
    """
    config = get_config()
    if trusted_internal and verified_privacy_stamp(event, config):
        return event
    if not config.security.pseudonymize_identities:
        event.privacy_stamp = ""
        return event
    for name in IDENTITY_FIELDS:
        value = getattr(event, name)
        if value:
            setattr(event, name, alias_for(name, value, config=config))
    event.src_ip = ""
    if event.identity_provider not in IDENTITY_PROVIDERS:
        event.identity_provider = ""
    event.privacy_stamp = identity_stamp(event, config)
    return event


def observed_time(value) -> datetime | None:
    if not isinstance(value, (str, datetime)):
        return None
    try:
        parsed = datetime.fromisoformat(value) if isinstance(value, str) else value
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            return None
        return parsed.astimezone(UTC)
    except (ValueError, TypeError, OverflowError):
        return None


def identity_cutoff(now: datetime | None = None, *, config=None) -> datetime:
    return (now or datetime.now(UTC)) - timedelta(days=(config or get_config()).retention.identity_days)


def retain_samples(values, *, now: datetime, cutoff: datetime) -> list[dict]:
    retained = []
    if not isinstance(values, list):
        return retained
    for sample in values:
        if not isinstance(sample, dict) or set(sample) != {"value", "field", "observed_at"}:
            continue
        timestamp = observed_time(sample["observed_at"])
        if (
            timestamp is None
            or timestamp < cutoff
            or timestamp > now + timedelta(minutes=5)
            or not isinstance(sample["field"], str)
            or sample["field"] not in SAMPLE_FIELDS
            or not isinstance(sample["value"], str)
            or len(sample["value"]) > 2048
        ):
            continue
        retained.append({**sample, "observed_at": timestamp.isoformat()})
    # Bound by latest observed time, not arrival order; old replay cannot displace recent evidence.
    return sorted(retained, key=lambda sample: (sample["observed_at"], sample["field"], sample["value"]))[-10:]


def sanitize_evidence(bundle, *, now: datetime | None = None, config=None) -> dict:
    """Read and maintenance boundary: unknown-age shapes fail closed."""
    now = now or datetime.now(UTC)
    cutoff = identity_cutoff(now, config=config)
    allowed = {
        *SOURCE_TYPES,
        "_identity_window",
        "_identity_basis",
        "_bytes_out",
        "_evidence_counts",
        "_oauth_scopes",
        "_governance",
        "_risk_score_stale",
        "_risk_calculated_at",
        "confidence_factors",
        "risk_factors",
    }
    clean = (
        {key: deepcopy(value) for key, value in bundle.items() if key in allowed} if isinstance(bundle, dict) else {}
    )
    for source in SOURCE_TYPES:
        section = clean.get(source)
        if section is None:
            continue
        if not isinstance(section, dict):
            clean.pop(source)
            continue
        section = {
            key: value
            for key, value in section.items()
            if key
            in {
                "first_seen",
                "last_seen",
                "event_count",
                "matched_field",
                "confidence_base",
                "protocol_counts",
                "sample_values",
                "sample_observations",
                "network_observations",
            }
        }
        clean[source] = section
        matched_field = section.get("matched_field", "")
        if not isinstance(matched_field, str) or matched_field not in SAMPLE_FIELDS | {"", "url_path", "user_agent"}:
            section["matched_field"] = ""
        samples = retain_samples(section.get("sample_observations"), now=now, cutoff=cutoff)
        section["sample_observations"] = samples
        section["sample_values"] = list(dict.fromkeys(sample["value"] for sample in samples))
        if "network_observations" in section:
            from shadai.engine.correlator import NetworkObservation

            observations = []
            values = section["network_observations"]
            for value in values if isinstance(values, list) else []:
                try:
                    observation = NetworkObservation.model_validate(value)
                except (ValueError, TypeError):
                    continue
                if cutoff <= observation.timestamp <= now + timedelta(minutes=5):
                    observations.append(observation.model_dump(mode="json"))
            section["network_observations"] = sorted(observations, key=lambda observation: observation["timestamp"])[
                -10:
            ]
    # Historical free-form factor descriptions cannot carry old names forward.
    from shadai.engine.scorer import Signal, compute_confidence

    signals = []
    for source in SOURCE_TYPES:
        section = clean.get(source)
        if isinstance(section, dict):
            try:
                signal = Signal(
                    source_type=source,
                    confidence_base=section["confidence_base"],
                    event_count=0 if source == "network" else section.get("event_count", 1),
                    match_field=section.get("matched_field", ""),
                )
                if 0 <= signal.confidence_base <= 1 and 0 <= signal.event_count <= 2**63 - 1:
                    signals.append(signal)
            except (ValueError, TypeError, KeyError):
                pass
    clean["confidence_factors"] = compute_confidence(signals)[1]
    factors = clean.get("risk_factors", [])
    names = {
        "base_shadow_ai",
        "oauth_sensitive_scopes",
        "high_data_volume",
        "unsanctioned",
        "many_users",
        "extension_full_dom",
        "unverified_publisher",
        "sanctioned",
        "tolerated",
        "readonly_scopes",
        "minimal_usage",
    }
    clean["risk_factors"] = (
        [
            {"factor": factor["factor"], "value": factor["value"], "description": factor["factor"].replace("_", " ")}
            for factor in factors
            if isinstance(factor, dict)
            and isinstance(factor.get("factor"), str)
            and factor["factor"] in names
            and isinstance(factor.get("value"), int)
            and not isinstance(factor["value"], bool)
        ]
        if isinstance(factors, list)
        else []
    )
    return clean


async def current_identity_counts(session, detection_ids, *, now: datetime | None = None, config=None) -> dict:
    """Exact counts for a supplied page, independent of delayed maintenance."""
    if not detection_ids:
        return {}
    cutoff = identity_cutoff(now, config=config)
    counts = {identifier: {"user": 0, "device": 0} for identifier in detection_ids}
    for offset in range(0, len(detection_ids), 500):
        rows = await session.execute(
            select(EvidenceIdentityORM.detection_id, EvidenceIdentityORM.kind, func.count())
            .where(
                EvidenceIdentityORM.detection_id.in_(detection_ids[offset : offset + 500]),
                EvidenceIdentityORM.last_seen_at >= cutoff,
            )
            .group_by(EvidenceIdentityORM.detection_id, EvidenceIdentityORM.kind)
        )
        for identifier, kind, count in rows:
            counts[identifier][kind] = count
    return counts


async def refresh_identity_counts(
    session, detections, *, now: datetime | None = None, recalculate_risk: bool = False
) -> list:
    """Project fresh DTOs; GET/export must never mutate persistent ORM instances."""
    from shadai.engine.scorer import compute_risk, generate_reasoning_summary
    from shadai.models.detection import DetectionRead

    now = now or datetime.now(UTC)
    projected = []
    # A flush may expire server-generated timestamps. Resolve only missing scalar
    # columns asynchronously before Pydantic's synchronous attribute reads; never
    # refresh the whole row or discard loaded pending edits such as analyst notes.
    with session.no_autoflush:
        for detection in detections:
            state = inspect(detection)
            scalar_names = {attribute.key for attribute in state.mapper.column_attrs}
            missing = (state.expired_attributes | state.unloaded) & scalar_names
            if missing:
                await session.refresh(detection, attribute_names=sorted(missing))
        counts = await current_identity_counts(session, [d.detection_id for d in detections], now=now)
        for detection in detections:
            counted = counts[detection.detection_id]
            result = DetectionRead.model_validate(detection).model_copy(deep=True)
            result.impacted_users_count, result.impacted_devices_count = counted["user"], counted["device"]
            bundle = sanitize_evidence(detection.evidence_bundle, now=now)
            if recalculate_risk:
                risk, factors = compute_risk(
                    entity_type=detection.entity_type,
                    impacted_users_count=counted["user"],
                    total_events_count=detection.total_events_count,
                    total_bytes_out=bundle.get("_bytes_out", 0),
                    classification=detection.classification,
                    oauth_scopes=bundle.get("_oauth_scopes") or None,
                    governance_classification=detection.classification
                    if detection.governance_status == "active"
                    else None,
                )
                result.risk_score = risk
                result.risk_level = next(
                    (
                        label
                        for threshold, label in ((86, "critical"), (71, "high"), (51, "medium"), (26, "low"))
                        if risk >= threshold
                    ),
                    "info",
                )
                bundle["risk_factors"] = factors
                bundle["_risk_calculated_at"] = now.isoformat()
                bundle["_risk_score_stale"] = False
                result.risk_calculated_at = now
                result.risk_score_stale = False
            else:
                result.risk_score_stale = bool(
                    result.risk_score_stale
                    or result.risk_calculated_at is None
                    or counted["user"] != detection.impacted_users_count
                    or counted["device"] != detection.impacted_devices_count
                )
            result.reasoning_summary = generate_reasoning_summary(
                result.confidence_score,
                bundle.get("confidence_factors", []),
                result.risk_score,
                bundle.get("risk_factors", []),
            )
            window = bundle.get("_identity_window")
            window = dict(window) if isinstance(window, dict) else {}
            bundle["_identity_window"] = {
                **window,
                "days": get_config().retention.identity_days,
                "as_of": now.isoformat(),
            }
            result.evidence_bundle = bundle
            first_seen = observed_time(
                detection.first_seen_at.replace(tzinfo=UTC)
                if detection.first_seen_at.tzinfo is None
                else detection.first_seen_at
            )
            if first_seen is None or first_seen < identity_cutoff(now):
                result.primary_evidence = None
            projected.append(result)
    return projected


async def expire_identity_members(session, *, now: datetime, config=None) -> None:
    await session.execute(
        delete(EvidenceIdentityORM).where(EvidenceIdentityORM.last_seen_at < identity_cutoff(now, config=config))
    )
