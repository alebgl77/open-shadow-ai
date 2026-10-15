"""Entra inventories cross the privacy boundary before any retained delivery bytes."""

import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, Mock
from uuid import NAMESPACE_URL, uuid5

import pytest

from shadai.api import ingestion
from shadai.collectors import entra
from shadai.collectors.entra import InventoryDelivery
from shadai.config import RedisQueueSettings, get_config
from shadai.models.event import CanonicalEvent
from shadai.utils.privacy import alias_for, verified_privacy_stamp
from shadai.utils.queue_admission import QueueAdmissionError, record_size
from shadai.utils.queueing import prepare_queued_event


def inventory_event(index=0, **kwargs):
    return CanonicalEvent(
        event_id=uuid5(NAMESPACE_URL, f"synthetic-entra-snapshot:{index}"),
        source_type="oauth",
        evidence_type="inventory",
        tenant_id="test-org",
        collector_id="entra-inventory",
        identity_provider="entra",
        identity_object_id=f"raw-entra-object-{index}",
        user_id=f"raw-entra-user-{index}",
        oauth_app_id=f"app-{index}",
        **kwargs,
    )


def pending_records(delivery):
    return [record for chunk in delivery.pending for record in chunk]


@pytest.fixture
def private_config():
    config = get_config()
    config.security.pseudonymize_identities = True
    return config


async def test_pending_and_redis_arguments_are_private_and_exact_across_retries(monkeypatch, private_config):
    redis = AsyncMock()
    redis.eval.side_effect = [["denied", "full"], ["ok", "1-0", "2-0"]]
    delivery = InventoryDelivery(redis, RedisQueueSettings())
    events = [inventory_event(index, src_ip=f"192.0.2.{index + 1}") for index in range(2)]
    originals = deepcopy(events)
    real_serialize = CanonicalEvent.model_dump_json
    serialized = []

    def serialize(event, *args, **kwargs):
        assert verified_privacy_stamp(event)
        serialized.append(event.event_id)
        return real_serialize(event, *args, **kwargs)

    monkeypatch.setattr(CanonicalEvent, "model_dump_json", serialize)
    delivery.retain(events)
    assert serialized == [event.event_id for event in originals]

    before = json.dumps(delivery.pending).encode()
    for raw in originals:
        for value in (raw.user_id, raw.identity_object_id, raw.src_ip):
            assert value.encode() not in before
    for record, raw in zip(pending_records(delivery), originals, strict=True):
        prepared = CanonicalEvent.model_validate_json(record["fields"]["data"])
        assert record["stream"] == "events:oauth"
        assert prepared.user_id == alias_for("user_id", raw.user_id)
        assert prepared.identity_object_id == alias_for("identity_object_id", raw.identity_object_id)
        assert prepared.src_ip == "" and verified_privacy_stamp(prepared)
        assert prepared.event_id == raw.event_id
        assert prepared.timestamp == raw.timestamp and prepared.normalized_at == raw.normalized_at
        assert prepared.tenant_id == "test-org" and prepared.collector_id == "entra-inventory"
        assert prepared.source_type == "oauth" and prepared.evidence_type == "inventory"
        assert prepare_queued_event(record["fields"]).model_dump_json() == record["fields"]["data"]

    with pytest.raises(QueueAdmissionError):
        await delivery.flush()
    assert json.dumps(delivery.pending).encode() == before
    assert await delivery.flush() == 2 and delivery.pending == []
    assert redis.eval.call_args_list[0] == redis.eval.call_args_list[1]
    arguments = json.dumps(redis.eval.call_args.args).encode()
    for raw in originals:
        for value in (raw.user_id, raw.identity_object_id, raw.src_ip):
            assert value.encode() not in arguments


def test_one_fixed_utc_acceptance_instant_is_shared_with_preparation_and_envelopes(monkeypatch, private_config):
    clock = datetime.now(UTC) - timedelta(minutes=1)
    now = Mock(return_value=clock)
    monkeypatch.setattr(entra, "datetime", Mock(now=now))
    real_prepare = ingestion.prepare_event
    observed = []

    def prepare(event, **kwargs):
        observed.append(kwargs["accepted_at"])
        return real_prepare(event, **kwargs)

    monkeypatch.setattr(ingestion, "prepare_event", prepare)
    delivery = InventoryDelivery(AsyncMock(), RedisQueueSettings())
    delivery.retain([inventory_event(index, timestamp=clock) for index in range(501)])

    now.assert_called_once_with(UTC)
    assert len(observed) == 501 and all(instant is clock for instant in observed)
    assert [len(chunk) for chunk in delivery.pending] == [500, 1]
    assert {record["fields"]["accepted_at"] for record in pending_records(delivery)} == {clock.isoformat()}


def test_chunks_use_prepared_record_bytes_for_admission_limit(private_config):
    sample = InventoryDelivery(AsyncMock(), RedisQueueSettings())
    sample.retain([inventory_event()])
    maximum = 2 * record_size(pending_records(sample)[0]) - 1
    delivery = InventoryDelivery(AsyncMock(), RedisQueueSettings(admission_max_batch_bytes=maximum))
    delivery.retain([inventory_event(index) for index in range(3)])
    assert [len(chunk) for chunk in delivery.pending] == [1, 1, 1]
    assert all(sum(record_size(record) for record in chunk) <= maximum for chunk in delivery.pending)


def test_forged_privacy_marker_cannot_bypass_preparation(private_config):
    forged_alias = "p1_" + "0" * 64
    event = inventory_event().model_copy(update={"user_id": forged_alias, "privacy_stamp": "a" * 64})
    delivery = InventoryDelivery(AsyncMock(), RedisQueueSettings())
    delivery.retain([event])
    prepared = CanonicalEvent.model_validate_json(pending_records(delivery)[0]["fields"]["data"])
    assert prepared.user_id == alias_for("user_id", forged_alias)
    assert verified_privacy_stamp(prepared)


def test_valid_internal_stamp_remains_idempotent_on_another_retain(private_config):
    delivery = InventoryDelivery(AsyncMock(), RedisQueueSettings())
    delivery.retain([inventory_event()])
    retained = CanonicalEvent.model_validate_json(pending_records(delivery)[0]["fields"]["data"])
    another = InventoryDelivery(AsyncMock(), RedisQueueSettings())
    another.retain([retained])
    assert pending_records(another)[0]["fields"]["data"] == pending_records(delivery)[0]["fields"]["data"]


@pytest.mark.parametrize("pseudonymize", [False, True])
def test_common_boundary_discards_transient_fields_and_preserves_raw_mode(pseudonymize):
    get_config().security.pseudonymize_identities = pseudonymize
    event = inventory_event(
        src_ip="192.0.2.99", url_path="/raw-url-sentinel", process_path="raw-process-sentinel",
        raw_ref="raw-ref-sentinel", user_agent="raw-agent-sentinel",
    )
    delivery = InventoryDelivery(AsyncMock(), RedisQueueSettings())
    delivery.retain([event])
    payload = pending_records(delivery)[0]["fields"]["data"]
    prepared = CanonicalEvent.model_validate_json(payload)
    for value in ("raw-url-sentinel", "raw-process-sentinel", "raw-ref-sentinel", "raw-agent-sentinel"):
        assert value not in payload
    assert prepared.user_id == (alias_for("user_id", "raw-entra-user-0") if pseudonymize else "raw-entra-user-0")
    assert prepared.identity_object_id == (
        alias_for("identity_object_id", "raw-entra-object-0") if pseudonymize else "raw-entra-object-0"
    )
    assert prepared.src_ip == ("" if pseudonymize else "192.0.2.99")
    assert bool(prepared.privacy_stamp) is pseudonymize
    assert prepare_queued_event(pending_records(delivery)[0]["fields"]).model_dump_json() == payload


@pytest.mark.parametrize("invalid", ["tenant", "stale", "future", "domain"])
def test_preparation_failure_never_retains_a_partial_batch(private_config, invalid):
    rejected = inventory_event(501)
    if invalid == "tenant":
        rejected.tenant_id = "other-org"
    elif invalid == "stale":
        rejected.timestamp -= timedelta(days=private_config.retention.ingestion_max_age_days + 1)
    elif invalid == "future":
        rejected.timestamp += timedelta(minutes=10)
    else:
        rejected.domain = "invalid/hostname"
    redis = AsyncMock()
    delivery = InventoryDelivery(redis, RedisQueueSettings())
    events = [inventory_event(index) for index in range(501)]
    with pytest.raises(ValueError):
        delivery.retain([*events, rejected])
    assert delivery.pending == [] and delivery.total == 0
    redis.eval.assert_not_called()
    delivery.retain([inventory_event()])
    assert delivery.total == 1 and len(pending_records(delivery)) == 1


def test_existing_pending_cannot_be_lost_or_replaced_by_an_invalid_batch(private_config):
    redis = AsyncMock()
    delivery = InventoryDelivery(redis, RedisQueueSettings())
    delivery.retain([inventory_event()])
    pending = deepcopy(delivery.pending)
    event = inventory_event(1).model_copy(update={"tenant_id": "other-org"})
    with pytest.raises(RuntimeError, match="still pending"):
        delivery.retain([event])
    assert delivery.pending == pending and delivery.total == 1
    assert event.user_id == "raw-entra-user-1"
    redis.eval.assert_not_called()


def test_empty_inventory_retains_no_records(private_config):
    redis = AsyncMock()
    delivery = InventoryDelivery(redis, RedisQueueSettings())
    delivery.total = 1
    delivery.retain([])
    assert delivery.pending == [] and delivery.total == 0
    redis.eval.assert_not_called()
