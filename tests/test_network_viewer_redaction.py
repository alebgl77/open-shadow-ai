"""Detection list/detail cannot bypass the analyst-only raw network event API."""

from copy import deepcopy
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import inspect

from shadai.api import detections
from shadai.database import get_postgres_session
from shadai.engine.correlator import NetworkObservation
from shadai.models.detection import DetectionORM
from shadai.security.auth import get_current_user

RAW_EVENT_ID = "cc541e88-11f6-4a71-b2ca-abb614041859"
PRIVATE_SOURCE = "192.0.2.171"
PRIVATE_DESTINATION = "2001:db8::171"
PRIVATE_SENSOR = "sensitive-office-sensor"
RAW_OBSERVATION = {
    "event_id": RAW_EVENT_ID,
    "timestamp": datetime.now(UTC).isoformat(),
    "protocol": "TLS",
    "domain": "service.example.test",
    "src_ip": PRIVATE_SOURCE,
    "dst_ip": PRIVATE_DESTINATION,
    "dst_port": 443,
    "collector_id": PRIVATE_SENSOR,
}
RAW_OBSERVATION = NetworkObservation.model_validate(RAW_OBSERVATION).model_dump(mode="json")


def detection_record(observations=None):
    now = datetime.now(UTC)
    network = {
        "event_count": 7,
        "protocol_counts": {"DNS": 2, "TLS": 5},
        "confidence_base": 0.65,
        "matched_field": "sni",
        "sample_values": ["service.example.test"],
        "sample_observations": [{"field": "sni", "value": "service.example.test", "observed_at": now.isoformat()}],
        "first_seen": now.isoformat(),
        "last_seen": now.isoformat(),
        "network_observations": [deepcopy(RAW_OBSERVATION)] if observations is None else observations,
    }
    record = DetectionORM(
        detection_id=uuid4(),
        entity_type="saas_app",
        entity_name="Example service",
        catalog_item_id="service",
        classification="unknown",
        shadow_ai_status="suspected",
        confidence_score=0.65,
        risk_score=25,
        first_seen_at=now,
        last_seen_at=now,
        impacted_users_count=0,
        impacted_devices_count=0,
        total_events_count=7,
        source_types=["network", "endpoint"],
        analyst_status="new",
        governance_id=None,
        evidence_bundle={
            "network": network,
            "endpoint": {
                "event_count": 1,
                "sample_values": ["old-process"],
                "confidence_base": 0.9,
                "sample_observations": [
                    {"field": "process_name", "value": "old-process", "observed_at": now.isoformat()}
                ],
            },
            "confidence_factors": [{"factor": "network", "contribution": 0.65}],
            "risk_factors": [{"factor": "classification", "contribution": 25}],
        },
        created_at=now,
        updated_at=now,
    )
    # This unpersisted fixture represents a fully loaded database row.
    for name in inspect(record).unloaded:
        setattr(record, name, None)
    return record


def client_for(record, role="viewer"):
    app = FastAPI()
    app.include_router(detections.router)
    user = SimpleNamespace(role=role)
    session = AsyncMock()
    result = SimpleNamespace(
        scalars=lambda: SimpleNamespace(all=lambda: [record]),
        scalar_one_or_none=lambda: record,
    )
    session.execute.side_effect = lambda query: [] if "detection_identity_members" in str(query) else result
    session.scalar.return_value = 1
    app.dependency_overrides[get_current_user] = lambda: user
    app.dependency_overrides[get_postgres_session] = lambda: session
    return TestClient(app), user


def route(record, surface):
    return "/api/v1/detections" if surface == "list" else f"/api/v1/detections/{record.detection_id}"


def returned_detection(response, surface):
    data = response.json()
    return data["items"][0] if surface == "list" else data


@pytest.mark.parametrize("surface", ["list", "detail"])
def test_viewer_raw_network_values_absent_and_safe_summaries_preserved(surface):
    record = detection_record()
    original = deepcopy(record.evidence_bundle)
    with client_for(record)[0] as client:
        response = client.get(route(record, surface))
    assert response.status_code == 200, response.text
    data = returned_detection(response, surface)
    evidence = data["evidence_bundle"]["network"]
    assert "network_observations" not in evidence
    assert evidence["protocol_counts"] == {"DNS": 2, "TLS": 5}
    assert evidence["event_count"] == 7 and evidence["confidence_base"] == 0.65
    assert evidence["sample_values"] == ["service.example.test"]
    assert data["confidence_score"] == 0.65 and data["total_events_count"] == 7
    for sensitive in (RAW_EVENT_ID, PRIVATE_SOURCE, PRIVATE_DESTINATION, PRIVATE_SENSOR):
        assert sensitive not in response.text
    assert data["evidence_bundle"]["endpoint"] == original["endpoint"]
    assert {factor["factor"] for factor in data["evidence_bundle"]["confidence_factors"]} == {
        "base_signal",
        "multi_source",
    }
    assert not any(
        private in str(data["evidence_bundle"]["risk_factors"]) for private in (PRIVATE_SOURCE, PRIVATE_SENSOR)
    )
    assert record.evidence_bundle == original


@pytest.mark.parametrize("role", ["analyst", "admin"])
@pytest.mark.parametrize("surface", ["list", "detail"])
def test_analyst_and_admin_receive_exact_original_network_samples(role, surface):
    record = detection_record()
    original = deepcopy(record.evidence_bundle)
    with client_for(record, role)[0] as client:
        response = client.get(route(record, surface))
    assert response.status_code == 200, response.text
    assert returned_detection(response, surface)["evidence_bundle"]["network"] == original["network"]
    assert record.evidence_bundle == original


@pytest.mark.parametrize("surface", ["list", "detail"])
def test_viewer_then_analyst_keeps_shared_orm_evidence(surface):
    record = detection_record()
    original = deepcopy(record.evidence_bundle)
    client, user = client_for(record)
    with client:
        viewer = client.get(route(record, surface))
        assert "network_observations" not in returned_detection(viewer, surface)["evidence_bundle"]["network"]
        assert record.evidence_bundle == original
        user.role = "analyst"
        analyst = client.get(route(record, surface))
    assert analyst.status_code == 200
    assert returned_detection(analyst, surface)["evidence_bundle"]["network"] == original["network"]
    assert record.evidence_bundle == original


@pytest.mark.parametrize(
    "observations",
    [
        {"legacy": {"nested": [RAW_OBSERVATION]}},
        [RAW_OBSERVATION, PRIVATE_SENSOR],
        PRIVATE_SOURCE + PRIVATE_DESTINATION + PRIVATE_SENSOR + RAW_EVENT_ID,
        7,
        False,
    ],
    ids=["nested-object", "mixed-list", "raw-string", "integer", "boolean"],
)
@pytest.mark.parametrize("surface", ["list", "detail"])
def test_legacy_observation_shapes_removed_wholesale(observations, surface):
    record = detection_record(deepcopy(observations))
    original = deepcopy(record.evidence_bundle)
    with client_for(record)[0] as client:
        response = client.get(route(record, surface))
    assert response.status_code == 200, response.text
    assert "network_observations" not in response.text
    for sensitive in (RAW_EVENT_ID, PRIVATE_SOURCE, PRIVATE_DESTINATION, PRIVATE_SENSOR):
        assert sensitive not in response.text
    assert record.evidence_bundle == original


@pytest.mark.parametrize("network", [[RAW_OBSERVATION], PRIVATE_SOURCE, None])
def test_malformed_legacy_network_section_fail_closed(network):
    record = detection_record()
    record.evidence_bundle["network"] = deepcopy(network)
    original = deepcopy(record.evidence_bundle)
    result = detections.detection_for_role(record, SimpleNamespace(role="viewer"))
    assert "network" not in result.evidence_bundle and result.evidence_bundle["endpoint"] == original["endpoint"]
    assert record.evidence_bundle == original


def test_missing_network_and_unknown_role_are_safe_without_mutation():
    record = detection_record()
    result = detections.detection_for_role(record, SimpleNamespace(role="unknown"))
    assert "network_observations" not in result.evidence_bundle["network"]
    result.evidence_bundle["endpoint"]["sample_values"].append("response-only")
    assert record.evidence_bundle["endpoint"]["sample_values"] == ["old-process"]
    del record.evidence_bundle["network"]
    assert detections.detection_for_role(record, None).evidence_bundle["endpoint"] == record.evidence_bundle["endpoint"]
