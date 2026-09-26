import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import pytest
from pydantic import ValidationError
from starlette.requests import Request

from shadai.api.governance import create_governance, update_governance
from shadai.engine.correlator import Correlator
from shadai.engine.governance import apply_policy, rescore_classification
from shadai.models.catalog import CatalogItemRead
from shadai.models.event import CanonicalEvent
from shadai.models.governance import GovernanceCreate, GovernanceORM, GovernanceUpdate


@pytest.mark.parametrize("operation", ["create", "update"])
async def test_governance_date_audit_is_json_serializable_and_cascade_uses_catalog(operation, monkeypatch):
    now = datetime.now(UTC)
    admin = SimpleNamespace(user_id=uuid4(), username="admin")
    session = AsyncMock()
    added = []
    session.add = Mock(side_effect=added.append)
    policy = GovernanceORM(
        governance_id=uuid4(),
        target_type="catalog_item",
        target_id="ai-tool",
        org_classification="sanctioned",
        enforcement_mode="monitor",
        created_by=admin.user_id,
        created_at=now,
        updated_at=now,
    )
    detection = sample_detection()
    session.execute.return_value = SimpleNamespace(
        scalar_one_or_none=lambda: policy, scalars=lambda: SimpleNamespace(all=lambda: [detection])
    )

    async def flush():
        for row in added:
            row.governance_id = uuid4()
            row.created_at = row.updated_at = now

    session.flush.side_effect = flush
    audit = []

    async def record(*args, **kwargs):
        audit.append(json.loads(json.dumps(kwargs["details"])))

    monkeypatch.setattr("shadai.api.governance.log_audit", record)
    request = Request({"type": "http", "headers": [], "client": ("127.0.0.1", 1)})
    if operation == "create":
        body = GovernanceCreate(
            target_type="catalog_item",
            target_id="ai-tool",
            org_classification="sanctioned",
            approved_at=now,
            approved_until=now,
        )
        await create_governance(body, request, admin, session)
    else:
        body = GovernanceUpdate(org_classification="tolerated", approved_until=now)
        await update_governance(policy.governance_id, body, request, admin, session)
    assert audit[0]["approved_until"] == now.isoformat().replace("+00:00", "Z")
    statements = [str(call.args[0]) for call in session.execute.call_args_list]
    assert any("pg_advisory_xact_lock" in sql for sql in statements)
    assert any(
        "SELECT detections" in sql and "detections.catalog_item_id" in sql and "FOR UPDATE" in sql for sql in statements
    )


def sample_detection():
    now = datetime.now(UTC)
    item = CatalogItemRead(catalog_item_id="sample", canonical_name="Sample", category="ai_platform")
    event = CanonicalEvent(
        source_type="oauth", evidence_type="inventory", oauth_scopes=["Mail.Read"], bytes_out=12_000_000, timestamp=now
    )
    return Correlator(None)._create_detection(event, item, "oauth_app_id", 0.95, now, now, None)


def test_policy_rescore_preserves_all_observations_and_unrelated_factors():
    detection = sample_detection()
    before = deepcopy(detection.evidence_bundle)
    original = (
        detection.total_events_count,
        detection.first_seen_at,
        detection.last_seen_at,
        detection.confidence_score,
    )
    policy = GovernanceORM(
        governance_id=uuid4(), org_classification="sanctioned", approved_until=datetime.now(UTC) + timedelta(days=1)
    )
    apply_policy(detection, policy)
    sanctioned = detection.risk_score
    policy.org_classification = "unsanctioned"
    apply_policy(detection, policy)
    assert detection.risk_score > sanctioned and not detection.risk_score_stale
    assert (
        detection.total_events_count,
        detection.first_seen_at,
        detection.last_seen_at,
        detection.confidence_score,
    ) == original
    assert detection.evidence_bundle["oauth"] == before["oauth"]
    untouched = {"oauth_sensitive_scopes", "high_data_volume", "readonly_scopes", "minimal_usage", "base_shadow_ai"}
    assert [factor for factor in detection.evidence_bundle["risk_factors"] if factor["factor"] in untouched] == [
        factor for factor in before["risk_factors"] if factor["factor"] in untouched
    ]


def test_legacy_missing_factors_marks_score_stale_without_guessing():
    detection = sample_detection()
    detection.evidence_bundle = {}
    score = detection.risk_score
    detection.classification = "sanctioned"
    rescore_classification(detection)
    assert detection.risk_score == score and detection.risk_score_stale


def test_expiry_between_events_is_visible_as_stale_until_resolved():
    detection = sample_detection()
    now = datetime.now(UTC)
    policy = GovernanceORM(
        governance_id=uuid4(), org_classification="sanctioned", approved_until=now + timedelta(days=1)
    )
    apply_policy(detection, policy)
    assert detection.governance_status == "active" and not detection.risk_score_stale
    bundle = deepcopy(detection.evidence_bundle)
    bundle["_governance"]["approved_until"] = (now - timedelta(seconds=1)).isoformat()
    detection.evidence_bundle = bundle
    assert detection.governance_status == "expired" and detection.risk_score_stale
    policy.approved_until = now - timedelta(seconds=1)
    apply_policy(detection, policy)
    assert detection.classification == "unknown" and not detection.risk_score_stale


@pytest.mark.parametrize("expired", [False, True])
async def test_new_detection_respects_active_and_expired_approval(expired):
    now = datetime.now(UTC)
    policy = GovernanceORM(
        governance_id=uuid4(),
        org_classification="sanctioned",
        approved_until=now + timedelta(days=-1 if expired else 1),
    )
    session = AsyncMock()
    session.__aenter__.return_value = session
    session.scalar.return_value = uuid4()
    session.execute.side_effect = [
        None,
        SimpleNamespace(scalar_one_or_none=lambda: None),
        SimpleNamespace(scalar_one_or_none=lambda: policy),
    ]
    added = []
    session.add = Mock(side_effect=added.append)
    item = CatalogItemRead(
        catalog_item_id="sample", canonical_name="Sample", category="ai_platform", default_trust_level="sanctioned"
    )
    await Correlator(lambda: session).upsert_detection(CanonicalEvent(timestamp=now), item, "domain", 0.6)
    detection = added[0]
    assert detection.classification == ("unknown" if expired else "sanctioned")
    assert detection.governance_status == ("expired" if expired else "active")
    assert not detection.risk_score_stale
    assert detection.total_events_count == 1


def test_approval_dates_require_timezone():
    with pytest.raises(ValidationError):
        GovernanceUpdate(approved_until=datetime(2030, 1, 1))


async def test_detection_classification_patch_rescores_without_new_event(monkeypatch):
    from shadai.api.detections import update_detection
    from shadai.models.detection import DetectionUpdate

    detection = sample_detection()
    detection.detection_id = uuid4()
    detection.analyst_status = "new"
    detection.created_at = detection.updated_at = datetime.now(UTC)
    before_score = detection.risk_score
    before_seen = detection.last_seen_at
    session = AsyncMock()
    session.execute.return_value = SimpleNamespace(scalar_one_or_none=lambda: detection)
    monkeypatch.setattr("shadai.api.detections.log_audit", AsyncMock())
    actor = SimpleNamespace(user_id=uuid4(), username="analyst")
    request = Request({"type": "http", "headers": [], "client": ("127.0.0.1", 1)})
    result = await update_detection(
        detection.detection_id, DetectionUpdate(classification="sanctioned"), request, actor, session
    )
    assert result.risk_score < before_score and not result.risk_score_stale
    assert result.total_events_count == 1 and result.last_seen_at == before_seen


def test_legacy_governance_link_without_snapshot_is_explicitly_stale():
    detection = sample_detection()
    detection.governance_id = uuid4()
    assert detection.risk_score_stale


async def test_csv_export_carries_score_freshness(monkeypatch):
    import csv

    from shadai.api.exports import export_detections

    detection = sample_detection()
    detection.detection_id = uuid4()
    detection.analyst_status = "new"
    detection.created_at = detection.updated_at = datetime.now(UTC)
    detection.governance_id = uuid4()
    session = AsyncMock()
    session.execute.return_value = SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: [detection]))
    monkeypatch.setattr("shadai.api.exports.log_audit", AsyncMock())
    actor = SimpleNamespace(user_id=uuid4(), username="analyst")
    request = Request({"type": "http", "headers": [], "client": ("127.0.0.1", 1)})
    response = await export_detections(format="csv", request=request, current_user=actor, session=session)
    output = "".join([chunk async for chunk in response.body_iterator])
    rows = list(csv.reader(line for line in output.splitlines() if not line.startswith("#")))
    assert "risk_score_stale" in rows[0] and "governance_status" in rows[0]
    assert len(rows[0]) == len(rows[1])
    assert rows[1][rows[0].index("risk_score_stale")] == "True"


async def test_date_only_update_reloads_concurrent_classification_under_lock(monkeypatch):
    import asyncio

    now = datetime.now(UTC)
    policy = GovernanceORM(
        governance_id=uuid4(),
        target_type="catalog_item",
        target_id="sample",
        org_classification="sanctioned",
        enforcement_mode="monitor",
        created_by=uuid4(),
        created_at=now,
        updated_at=now,
    )
    detection = sample_detection()
    initially_read, other_writer_committed = asyncio.Event(), asyncio.Event()
    database = {"classification": "sanctioned"}
    calls = []
    session = AsyncMock()

    async def execute(statement, *args):
        sql = str(statement)
        if "FROM governance" in sql:
            calls.append("initial_read")
            initially_read.set()
            return SimpleNamespace(scalar_one_or_none=lambda: policy)
        if "pg_advisory_xact_lock" in sql:
            await other_writer_committed.wait()
            calls.append("lock_acquired")
            return None
        assert "FROM detections" in sql
        calls.append("select_detections")
        return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: [detection]))

    async def refresh(row):
        assert calls.index("lock_acquired") < len(calls)
        calls.append("refresh")
        row.org_classification = database["classification"]

    async def concurrent_classification_writer():
        await initially_read.wait()
        database["classification"] = "unsanctioned"
        other_writer_committed.set()

    session.execute.side_effect = execute
    session.refresh.side_effect = refresh
    monkeypatch.setattr("shadai.api.governance.log_audit", AsyncMock())
    actor = SimpleNamespace(user_id=uuid4(), username="admin")
    request = Request({"type": "http", "headers": [], "client": ("127.0.0.1", 1)})
    response, _ = await asyncio.gather(
        update_governance(
            policy.governance_id, GovernanceUpdate(approved_until=now + timedelta(days=1)), request, actor, session
        ),
        concurrent_classification_writer(),
    )
    assert response.org_classification == detection.classification == "unsanctioned"
    assert calls.index("lock_acquired") < calls.index("refresh") < calls.index("select_detections")
    assert detection.total_events_count == 1


def test_nonempty_inconsistent_legacy_factors_keep_last_score_stale():
    detection = sample_detection()
    factors = [{"factor": "base_shadow_ai", "value": 30, "description": "base"}]
    detection.evidence_bundle = {"risk_factors": factors}
    detection.risk_score = 85
    detection.classification = "sanctioned"
    rescore_classification(detection)
    assert detection.risk_score == 85 and detection.risk_score_stale
    assert detection.evidence_bundle["risk_factors"] == factors


@pytest.mark.parametrize(
    "score,extra,classification,expected",
    [
        (0, [("minimal_usage", -10), ("sanctioned", -40)], "unsanctioned", 40),
        (100, [("other_evidence", 90)], "sanctioned", 80),
    ],
)
def test_consistent_clamped_factor_history_can_be_rescored(score, extra, classification, expected):
    detection = sample_detection()
    detection.evidence_bundle = {
        "risk_factors": [
            {"factor": name, "value": value, "description": name} for name, value in [("base_shadow_ai", 30), *extra]
        ]
    }
    detection.risk_score = score
    detection.classification = classification
    rescore_classification(detection)
    assert detection.risk_score == expected and not detection.risk_score_stale
