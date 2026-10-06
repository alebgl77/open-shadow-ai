"""Trusted queue envelopes keep server acceptance time outside stable event JSON."""

from datetime import UTC, datetime

from shadai.models.event import CanonicalEvent


class PermanentMessageError(ValueError):
    """Explicit invalid queue schema/evidence; driver and programming errors are retryable."""


def queue_fields(payload: str, *, payload_field: str = "data", accepted_at: datetime | None = None) -> dict[str, str]:
    accepted_at = accepted_at or datetime.now(UTC)
    if accepted_at.tzinfo is None:
        raise ValueError("Queue acceptance time requires a timezone")
    return {payload_field: payload, "accepted_at": accepted_at.astimezone(UTC).isoformat()}


def queue_event(target, event: CanonicalEvent, *, accepted_at: datetime | None = None):
    return target.xadd(f"events:{event.source_type}", queue_fields(event.model_dump_json(), accepted_at=accepted_at))


def prepare_queued_event(data: dict, *, field: str = "data") -> CanonicalEvent:
    from shadai.api.ingestion import prepare_event

    try:
        accepted_at = datetime.fromisoformat(data["accepted_at"]) if "accepted_at" in data else None
        event = CanonicalEvent.model_validate_json(data[field])
        return prepare_event(event, trusted_collector=True, accepted_at=accepted_at)
    except (ValueError, KeyError, TypeError):
        raise PermanentMessageError("Invalid internal event envelope") from None
