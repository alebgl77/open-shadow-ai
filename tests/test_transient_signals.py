"""URL paths and user agents are matched at the ingestion boundary and never retained."""

import json
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, Mock
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from shadai.api import ingestion
from shadai.api.ingestion import prepare_event
from shadai.collectors.syslog_receiver import SyslogCollector
from shadai.config import get_config
from shadai.engine.catalog_cache import CatalogCache
from shadai.engine.catalog_loader import build_catalog_index
from shadai.engine.matcher import CatalogMatcher
from shadai.models.catalog import CatalogItemRead
from shadai.models.event import CanonicalEvent
from shadai.parsers.proxy.fortigate import FortiGateWebFilterParser
from shadai.workers.ingest import EventProcessor

SECRET_PATH = "/chat/conversation/6f1c?access_token=very-secret"


class Session:
    """Receipt store for one worker transaction."""

    def __init__(self):
        self.receipts = set()
        self.execute = AsyncMock()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    def begin(self):
        return self

    async def get(self, model, key):
        return key in self.receipts

    def add(self, receipt):
        self.receipts.add(receipt.event_id)


ITEMS = [
    CatalogItemRead(
        catalog_item_id="huggingface", canonical_name="Hugging Face", category="ai_platform", domains=["huggingface.co"]
    ),
    CatalogItemRead(
        catalog_item_id="huggingchat",
        canonical_name="HuggingChat",
        category="llm_chat",
        url_patterns=["huggingface.co/chat", "huggingface.co/chat/*"],
    ),
]


def index():
    return build_catalog_index(ITEMS)


def chat_event(**fields):
    return CanonicalEvent(
        tenant_id="test-org",
        source_type="proxy",
        url_host="huggingface.co",
        domain="huggingface.co",
        url_path=SECRET_PATH,
        user_agent="Mozilla/5.0 (X11; private-device-name)",
        **fields,
    )


def assert_nothing_retained(serialized: str):
    assert "/chat" not in serialized and "very-secret" not in serialized and "private-device-name" not in serialized


def test_boundary_keeps_the_match_and_discards_the_path_and_user_agent():
    prepared = prepare_event(chat_event(), matcher=CatalogMatcher(index()))
    assert (prepared.catalog_match_id, prepared.match_field) == ("huggingchat", "url_pattern")
    assert prepared.url_path == prepared.user_agent == ""
    assert_nothing_retained(prepared.model_dump_json())


def test_untrusted_match_claims_are_replaced_and_the_switch_disables_evaluation(monkeypatch):
    forged = chat_event(catalog_match_id="claude", match_field="domain", match_confidence=1)
    assert prepare_event(forged, matcher=None).catalog_match_id == ""
    monkeypatch.setattr(get_config().privacy, "match_transient_signals", False)
    prepared = prepare_event(chat_event(), matcher=CatalogMatcher(index()))
    assert prepared.catalog_match_id == "" and prepared.url_path == ""


def test_ingest_api_enqueues_only_the_match(monkeypatch):
    from shadai.main import app

    pipe = SimpleNamespace(xadd=Mock(), execute=AsyncMock())
    monkeypatch.setattr(
        "shadai.api.ingestion.get_redis", AsyncMock(return_value=SimpleNamespace(pipeline=Mock(return_value=pipe)))
    )
    monkeypatch.setattr(ingestion, "boundary_catalog", CatalogCache())
    monkeypatch.setattr(ingestion, "load_boundary_catalog", AsyncMock(return_value=index()))
    event = chat_event().model_dump(mode="json")
    event.update(event_id=str(uuid4()), timestamp=datetime.now(UTC).isoformat(), collector_id="custom-proxy")
    response = TestClient(app).post(
        "/api/v1/ingest/events",
        json={"events": [event]},
        headers={"X-API-Key": get_config().security.agent_api_key},
    )
    assert response.status_code == 202, response.text
    stream, payload = pipe.xadd.call_args.args
    assert stream == "events:proxy"
    assert json.loads(payload["data"])["catalog_match_id"] == "huggingchat"
    assert_nothing_retained(payload["data"])


async def test_syslog_collector_matches_a_fortigate_line_before_discarding_its_path(monkeypatch):
    pipe = MagicMock()
    pipe.execute = AsyncMock()
    redis = MagicMock()
    redis.pipeline.return_value = pipe
    collector = SyslogCollector(
        "fortigate", FortiGateWebFilterParser(), redis, catalog_loader=AsyncMock(return_value=index())
    )
    monkeypatch.setattr(ingestion, "boundary_catalog", CatalogCache())
    now = datetime.now(UTC)
    line = (
        f'date={now:%Y-%m-%d} time={now:%H:%M:%S} tz="+0000" hostname="huggingface.co" '
        f'url="{SECRET_PATH}" srcip=10.0.0.5 agent="Mozilla/5.0 (X11; private-device-name)"'
    )
    assert await collector.push_events([collector.parser.parse(line)]) == 1
    payload = pipe.xadd.call_args.args[1]["data"]
    assert json.loads(payload)["catalog_match_id"] == "huggingchat"
    assert_nothing_retained(payload)


@pytest.mark.parametrize(("upstream", "expected"), [("huggingchat", "huggingchat"), ("retired-item", "huggingface")])
async def test_worker_keeps_an_active_boundary_match_and_recomputes_a_stale_one(upstream, expected):
    rows = []
    redis = AsyncMock()
    session = Session()
    clickhouse = SimpleNamespace(execute=lambda query, values: rows.extend(values))
    processor = EventProcessor(redis, clickhouse, lambda: session, CatalogMatcher(index()))
    event = CanonicalEvent(
        tenant_id="test-org",
        source_type="proxy",
        domain="huggingface.co",
        catalog_match_id=upstream,
        match_field="url_pattern",
        match_confidence=0.9,
    )
    await processor({"data": event.model_dump_json()})
    assert rows[0]["catalog_match_id"] == expected
    assert redis.xadd.call_args.args[1]["catalog_item_id"] == expected


async def test_catalog_cache_reloads_on_interval_and_survives_a_failed_reload(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr("shadai.engine.catalog_cache.time.monotonic", lambda: clock[0])
    cache = CatalogCache()
    load = AsyncMock(side_effect=[index(), RuntimeError("database unavailable")])
    first = await cache.get(load)
    assert isinstance(first, CatalogMatcher) and await cache.get(load) is first and load.await_count == 1
    clock[0] += get_config().catalog.reload_interval_seconds
    assert await cache.get(load) is first and load.await_count == 2
