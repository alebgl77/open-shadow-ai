"""Operational data comes from current Redis/tenant rows, never local counters."""

import json
import logging
import traceback
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException
from httpx import ASGITransport, AsyncClient
from pydantic import ValidationError

from shadai.api import operations
from shadai.config import SecuritySettings, get_config, load_config, validate_security
from shadai.database import get_postgres_session
from shadai.models.base import Base
from shadai.models.collector import CollectorORM
from shadai.security.auth import get_current_user
from shadai.utils import operations as state
from shadai.utils.metrics import operational_metrics


class QueueState:
    def __init__(self, now=1800000000):
        self.now = now
        self.hashes = {}
        self.groups = {}
        self.lengths = {}
        self.pending = {}

    async def hgetall(self, key):
        return self.hashes.get(key, {})

    async def xinfo_groups(self, stream):
        return self.groups.get(stream, [])

    async def xlen(self, stream):
        return self.lengths.get(stream, 0)

    async def xpending_range(self, stream, group, minimum, maximum, count):
        assert count == 1
        return self.pending.get(stream, [])

    def fresh(self, stream='events:dns', group='ingest_group', lag=0, pending=0):
        self.groups[stream] = [{'name': group, 'pending': pending, 'lag': lag}]
        self.hashes[state.operation_key(group, stream)] = {
            'since': str(self.now - 600), 'last_seen_at': str(self.now - 2),
            'last_poll_at': str(self.now - 3), 'last_progress_at': str(self.now - 4)}


async def test_unknown_lag_and_missing_groups_are_not_xlen_backlog_or_zero_health():
    redis = QueueState()
    redis.fresh(lag=None, pending=3)
    redis.lengths['events:dns'] = 99
    redis.pending['events:dns'] = [{'message_id': str((redis.now - 60) * 1000) + '-0'}]
    body = await state.pipeline_snapshot(redis, now=redis.now)
    row = body['stages'][0]['streams'][0]
    assert row['retained_entries'] == 99 and row['pending'] == 3 and row['undelivered'] is None
    assert row['status'] == 'unknown' and row['oldest_pending_age_seconds'] == 60
    missing = body['stages'][0]['streams'][1]
    assert not missing['group_present'] and missing['pending'] is None and missing['undelivered'] is None
    scrape = operational_metrics(body).decode()
    assert 'shadai_group_undelivered_known{stage="ingest",stream="events:dns"} 0.0' in scrape
    assert 'shadai_group_undelivered_messages{stage="ingest",stream="events:dns"}' not in scrape
    assert 'shadai_queue_depth' not in scrape and 'shadai_events_ingested_total' not in scrape


async def test_retrying_stalled_queue_vs_idle_and_expired_publication():
    redis = QueueState()
    redis.fresh(lag=2, pending=1)
    key = state.operation_key('ingest_group', 'events:dns')
    redis.hashes[key].update(last_progress_at=str(redis.now - 400), last_failure_at=str(redis.now - 1),
                             retryable_failures='100')
    row = await state.stream_snapshot(redis, 'ingest_group', 'events:dns', redis.now)
    assert row['status'] == 'blocked' and row['counters']['retryable_failures'] == 100
    assert row['last_failure_at'] != row['last_progress_at']
    redis.fresh(lag=0, pending=0)
    assert (await state.stream_snapshot(redis, 'ingest_group', 'events:dns', redis.now))['status'] == 'idle'
    redis.hashes[key]['last_seen_at'] = str(redis.now - 91)
    stale = await state.stream_snapshot(redis, 'ingest_group', 'events:dns', redis.now)
    assert stale['status'] == 'stale' and stale['counters']['acknowledged'] is None
    redis.hashes.clear()
    missing = await state.stream_snapshot(redis, 'ingest_group', 'events:dns', redis.now)
    assert missing['status'] == 'unknown' and all(value is None for value in missing['counters'].values())


async def test_outage_has_only_availability_flags_and_never_cached_zero_green():
    redis = QueueState()
    redis.hgetall = AsyncMock(side_effect=OSError('private backend location'))
    body = await state.read_pipeline(redis)
    assert not body['backend_available'] and body['stages'] == [] and body['capture_loss'] is None
    scrape = operational_metrics(body).decode()
    assert 'shadai_operations_redis_available 0.0' in scrape
    assert 'shadai_group_pending_messages{' not in scrape and 'private' not in scrape


@pytest.mark.parametrize('group,stream', [('untrusted', 'events:dns'), ('ingest_group', 'events:private-user'),
                                        ('ingest_group', 'matches')])
def test_publishing_keys_cannot_invent_unbounded_or_cross_stage_labels(group, stream):
    with pytest.raises(ValueError):
        state.operation_key(group, stream)


@pytest.fixture
async def console(identity_sessions, monkeypatch):
    sessions = identity_sessions
    async with sessions().bind.begin() as connection:
        await connection.run_sync(lambda conn: Base.metadata.create_all(conn, tables=[CollectorORM.__table__]))
    from shadai.main import app

    async def session_dependency():
        async with sessions() as session:
            yield session
            await session.commit()

    actor = SimpleNamespace(role='admin', tenant_id='test-org')

    async def principal():
        return actor

    previous = dict(app.dependency_overrides)
    app.dependency_overrides[get_postgres_session] = session_dependency
    app.dependency_overrides[get_current_user] = principal
    async with AsyncClient(transport=ASGITransport(app=app, raise_app_exceptions=False),
                           base_url='https://example.test') as client:
        yield SimpleNamespace(client=client, sessions=sessions, actor=actor, app=app)
    app.dependency_overrides.clear()
    app.dependency_overrides.update(previous)


async def test_health_read_is_tenant_filtered_advisory_secret_free_and_quiet_is_not_failure(console):
    now = datetime.now(UTC)
    async with console.sessions() as session:
        session.add_all([
            CollectorORM(collector_id='mine', tenant_id='test-org', display_name='Own collector',
                         allowed_source_types=['network'], is_active=True, last_contact_at=now,
                         last_heartbeat_at=now, last_observed_at=now - timedelta(days=2),
                         client_counters={'queue_events': 12, 'dropped_events': 4, 'api_key': 'hidden-key',
                                          'secret_digest': 'hidden-digest', 'ip': 'private-address'}),
            CollectorORM(collector_id='other', tenant_id='another-org', display_name='Other tenant',
                         allowed_source_types=['dns'], is_active=True, client_counters={}),
        ])
        await session.commit()
    console.actor.role = 'analyst'
    response = await console.client.get('/api/v1/operations/collectors?limit=1')
    assert response.status_code == 200
    body = response.json()
    assert body['total'] == 1 and len(body['items']) == 1
    row = body['items'][0]
    assert row['status'] == 'quiet' and row['server_contact_fresh']
    assert row['client_reported']['provenance'] == 'client_reported' and row['client_reported']['fresh']
    assert row['client_reported']['queue_events'] == 12 and row['capture_loss'] is None
    assert row['last_observed_at'] != row['last_heartbeat_at']
    for hidden in ('hidden', 'Other tenant', 'another-org', 'credential', 'api_key', 'digest', 'private-address'):
        assert hidden not in response.text
    assert (await console.client.get('/api/v1/collectors')).status_code == 403
    assert (await console.client.get('/api/v1/operations/pipeline')).status_code == 403
    assert (await console.client.get('/api/v1/operations/collectors?limit=501')).status_code == 422
    console.actor.role = 'viewer'
    assert (await console.client.get('/api/v1/operations/collectors')).status_code == 403
    console.actor.role, console.actor.tenant_id = 'admin', 'another-org'
    assert (await console.client.get('/api/v1/operations/pipeline')).status_code == 403


def test_collector_stale_unknown_and_revoked_are_distinct():
    now = datetime.now(UTC)
    row = SimpleNamespace(collector_id='fixture', display_name='Fixture', allowed_source_types=['dns'],
                          last_contact_at=None, last_heartbeat_at=None, last_observed_at=None,
                          is_active=True, revoked_at=None, client_counters={}, client_last_success_at=None)
    assert operations.collector_health(row, now)['status'] == 'unknown'
    row.last_contact_at, row.last_heartbeat_at = now - timedelta(hours=2), now - timedelta(hours=2)
    stale = operations.collector_health(row, now)
    assert stale['status'] == 'stale' and not stale['client_reported']['fresh']
    assert stale['client_reported']['queue_events'] is None
    row.is_active = False
    assert operations.collector_health(row, now)['status'] == 'revoked'


async def test_pipeline_outage_is_503_without_old_stage_data(console, monkeypatch):
    monkeypatch.setattr(operations, 'get_redis', AsyncMock(side_effect=OSError('private location')))
    response = await console.client.get('/api/v1/operations/pipeline')
    assert response.status_code == 503 and response.json()['stages'] == []
    assert response.json()['scope'] == 'deployment' and not response.json()['backend_available']
    assert 'private' not in response.text


async def test_metrics_requires_dedicated_scrape_key_or_admin_not_agent_or_management(console, monkeypatch):
    key = 'metrics-distinct-secret-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    monkeypatch.setenv('METRICS_API_KEY', key)
    get_config.cache_clear()
    monkeypatch.setattr(operations, 'get_redis', AsyncMock(side_effect=OSError('synthetic offline')))
    lookup = AsyncMock(side_effect=HTTPException(401, 'Invalid or expired token'))
    monkeypatch.setattr(operations, 'get_current_user', lookup)
    for headers in ({}, {'Authorization': 'Bearer incorrect'}, {'X-API-Key': get_config().security.agent_api_key},
                    {'Authorization': 'Bearer ' + get_config().security.agent_api_key}):
        response = await console.client.get('/metrics', headers=headers)
        assert response.status_code == 401 and key not in response.text
    lookup.reset_mock()
    response = await console.client.get('/metrics', headers={'Authorization': 'Bearer ' + key})
    assert response.status_code == 200 and 'shadai_operations_redis_available 0.0' in response.text
    lookup.assert_not_called()
    lookup.side_effect = None
    lookup.return_value = SimpleNamespace(role='analyst', tenant_id='test-org')
    assert (await console.client.get('/metrics', headers={'Authorization': 'Bearer console-jwt'})).status_code == 403
    lookup.return_value.role = 'admin'
    assert (await console.client.get('/metrics', headers={'Authorization': 'Bearer console-jwt'})).status_code == 200
    # Scrape token has no console/management privilege (real JWT validator).
    previous = console.app.dependency_overrides.pop(get_current_user)
    try:
        response = await console.client.get('/api/v1/collectors', headers={'Authorization': 'Bearer ' + key})
        assert response.status_code == 401
    finally:
        console.app.dependency_overrides[get_current_user] = previous


def test_optional_metrics_key_env_file_secret_repr_and_short_validation(tmp_path, monkeypatch):
    monkeypatch.delenv('METRICS_API_KEY_FILE', raising=False)
    monkeypatch.setenv('METRICS_API_KEY', '')
    assert load_config().security.metrics_api_key is None
    for key in ('short', 'x' * 31, 'x' * 32 + ' '):
        with pytest.raises(ValidationError):
            SecuritySettings(metrics_api_key=key)
    secret = 'metrics-secret-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    path = tmp_path / 'synthetic-metrics-key'
    path.write_text(secret + '\n')
    monkeypatch.setenv('METRICS_API_KEY_FILE', str(path))
    monkeypatch.setenv('METRICS_API_KEY', 'other-secret-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ')
    config = load_config()
    assert config.security.metrics_api_key.get_secret_value() == secret
    assert secret not in str(config.security) and secret not in config.model_dump_json()
    validate_security(config)  # No optional scrape key required for normal startup.
    config.security.metrics_api_key = SecuritySettings(metrics_api_key=config.security.agent_api_key).metrics_api_key
    with pytest.raises(ValueError, match='distinct'):
        validate_security(config)


@pytest.mark.parametrize('source', ['env', 'yaml', 'file'])
def test_malformed_metrics_secret_stays_out_of_loader_errors_tracebacks_and_logs(
    tmp_path, monkeypatch, caplog, source,
):
    secret = 'malformed-metrics-secret-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ '
    monkeypatch.delenv('METRICS_API_KEY', raising=False)
    monkeypatch.delenv('METRICS_API_KEY_FILE', raising=False)
    path = tmp_path / 'synthetic-settings.yaml'
    if source == 'env':
        monkeypatch.setenv('METRICS_API_KEY', secret)
    elif source == 'file':
        # File loader strips trailing whitespace, so use an internal whitespace.
        secret = 'malformed-metrics secret-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        key_file = tmp_path / 'synthetic-invalid-secret'
        key_file.write_text(secret)
        monkeypatch.setenv('METRICS_API_KEY_FILE', str(key_file))
    else:
        path.write_text('security:\n  metrics_api_key: ' + json.dumps(secret) + '\n')
    with pytest.raises(ValidationError) as failure:
        try:
            load_config(str(path))
        except ValidationError:
            logging.getLogger('synthetic-config-test').exception('Invalid configuration')
            raise
    error = failure.value
    for surface in (str(error), repr(error), ''.join(traceback.format_exception(error)), caplog.text):
        assert secret not in surface
        assert 'metrics_api_key' in surface
    # Config loading/logging does not serialize errors() inputs. Setting location
    # remains useful without including a submitted secret in formatted output.
    assert error.errors(include_input=False)[0]['loc'][-1] == 'metrics_api_key'
