"""Quiet capture stays alive without packet fixtures or a real capture process."""

from datetime import UTC, datetime

import httpx
import pytest

from shadai.collectors import network
from shadai.utils import delivery_spool


@pytest.mark.parametrize('first_offline', [False, True])
def test_quiet_capture_publishes_periodic_heartbeats_without_observations(tmp_path, monkeypatch, first_offline):
    # SQLite/transport semantics only; full ancestor/owner proof is native CI.
    monkeypatch.setattr(delivery_spool, '_private_ancestors', lambda path: None)
    source = tmp_path / 'empty-synthetic-metadata'
    source.write_bytes(b'')
    clock, heartbeats, posts, discovery = [0.0], [], [], []
    online = [not first_offline]

    def response(request):
        if request.method == 'GET':
            discovery.append(online[0])
            if not online[0]:
                return httpx.Response(503)
            return httpx.Response(200, json={'collector_id': 'quiet-sensor', 'legacy': False,
                                            'allowed_source_types': ['network'], 'ingestion_max_age_days': 90})
        if request.url.path.endswith('/heartbeat'):
            heartbeats.append((clock[0], request.content))
            return httpx.Response(200, json={'received_at': datetime.now(UTC).isoformat()})
        posts.append(request)
        return httpx.Response(202)

    class SparseQueue:
        def __init__(self, *args, **kwargs):
            self.attempt = 0

        def get(self, **kwargs):
            self.attempt += 1
            clock[0] += 61
            online[0] = True
            if self.attempt <= 3:
                raise network.queue.Empty()
            return None

    wire_class = network.EventTransport
    with httpx.Client(transport=httpx.MockTransport(response)) as client:
        monkeypatch.setattr(network, 'EventTransport', lambda *args, **kwargs:
                            wire_class(*args, **kwargs, client=client))
        monkeypatch.setattr(network, '_read_lines', lambda *args: None)
        monkeypatch.setattr(network.queue, 'Queue', SparseQueue)
        monkeypatch.setattr(network.time, 'monotonic', lambda: clock[0])
        assert network.main(['--input', str(source), '--format', 'zeek-tls', '--sensor-id', 'quiet-sensor',
                             '--api-url', 'https://api.test', '--spool-dir', str(tmp_path / 'private')]) == 0
    assert len(heartbeats) >= 3 and heartbeats[0][0] < heartbeats[-1][0]
    assert posts == []
    assert all(b'"queue_events":0' in body and b'quiet-sensor' in body for _, body in heartbeats)
    if first_offline:
        assert discovery == [False, True]
    with delivery_spool.DurableSpool(tmp_path / 'private') as restarted:
        assert restarted.has_binding('collector')


@pytest.fixture
def private_spool(tmp_path, monkeypatch):
    # SQLite/transport semantics only; native CI checks all ancestors unpatched.
    monkeypatch.setattr(delivery_spool, '_private_ancestors', lambda path: None)
    with delivery_spool.DurableSpool(tmp_path / 'private') as spool:
        yield spool


def scoped_binding(**changes):
    return {'collector_id': 'quiet-sensor', 'legacy': False, 'allowed_source_types': ['network'],
            'ingestion_max_age_days': 90, **changes}


def test_quiet_heartbeat_reloads_actual_private_key_file_before_verified_post(private_spool):
    key_path = private_spool.directory / 'synthetic-private-key'
    old_key, new_key = 'a' * 32, 'b' * 32
    key_path.write_text(old_key)
    key_path.chmod(0o600)
    requests = []

    def answer(request):
        requests.append((request.method, request.headers['X-API-Key']))
        if request.method == 'GET':
            return httpx.Response(200, json=scoped_binding())
        assert private_spool.has_binding('collector')
        return httpx.Response(200)

    with httpx.Client(transport=httpx.MockTransport(answer)) as client:
        wire = network.EventTransport('https://api.test', old_key, client=client,
                                      key_loader=lambda: network.read_api_key(str(key_path)))
        network.DurableEventTransport(wire, private_spool)
        wire.heartbeat('quiet-sensor', private_spool.stats())
        key_path.write_text(new_key)
        wire.heartbeat('quiet-sensor', private_spool.stats())
    assert requests == [('GET', old_key), ('POST', old_key), ('GET', new_key), ('POST', new_key)]
    assert private_spool.stats()['batches'] == 0


@pytest.mark.parametrize('new_binding', [scoped_binding(collector_id='different'), scoped_binding(legacy=True)])
def test_quiet_rotated_principal_cannot_post_heartbeat_or_data_and_retains_backlog(private_spool, new_binding):
    payload = b'{"events":[{"event_id":"stable-quiet-backlog"}]}'
    batch_id = private_spool.enqueue(payload, event_count=1)
    key, posts = ['a' * 32], []

    def answer(request):
        if request.method == 'GET':
            return httpx.Response(200, json=scoped_binding() if request.headers['X-API-Key'] == 'a' * 32
                                  else new_binding)
        posts.append(request)
        return httpx.Response(200)

    with httpx.Client(transport=httpx.MockTransport(answer)) as client:
        wire = network.EventTransport('https://api.test', key[0], client=client, key_loader=lambda: key[0])
        durable = network.DurableEventTransport(wire, private_spool)
        assert wire.discover_binding('quiet-sensor')
        key[0] = 'b' * 32
        with pytest.raises(network.DeliveryError, match='collector_binding_mismatch'):
            wire.heartbeat('quiet-sensor', private_spool.stats())
        with pytest.raises(network.DeliveryError, match='collector_binding_mismatch'):
            durable.drain()
    assert posts == []
    assert private_spool.db.execute('SELECT id,payload FROM batches').fetchone() == (batch_id, payload)
    assert private_spool.stats()['queued_events'] == 1


def test_quiet_late_discovery_enforces_server_ttl_before_any_post(private_spool):
    requests = []
    statuses = iter([503, 200])

    def answer(request):
        requests.append(request.method)
        return httpx.Response(next(statuses), json=scoped_binding(ingestion_max_age_days=1))

    with httpx.Client(transport=httpx.MockTransport(answer)) as client:
        wire = network.EventTransport('https://api.test', 'a' * 32, client=client)
        network.DurableEventTransport(wire, private_spool)
        assert not wire.discover_binding('quiet-sensor')
        with pytest.raises(network.DeliveryError, match='spool_ttl_exceeds_server_age'):
            wire.heartbeat('quiet-sensor', private_spool.stats())
    assert requests == ['GET', 'GET']
    assert private_spool.stats()['batches'] == 0


def test_heartbeat_401_invalidates_verification_for_rediscovery_without_acknowledging_backlog(private_spool):
    payload = b'{"events":[{"event_id":"not-acknowledged-by-health"}]}'
    batch_id = private_spool.enqueue(payload, event_count=1)
    requests, statuses = [], iter([401, 200])

    def answer(request):
        requests.append(request.method)
        if request.method == 'GET':
            return httpx.Response(200, json=scoped_binding())
        assert private_spool.has_binding('collector')
        return httpx.Response(next(statuses))

    with httpx.Client(transport=httpx.MockTransport(answer)) as client:
        wire = network.EventTransport('https://api.test', 'a' * 32, client=client)
        network.DurableEventTransport(wire, private_spool)
        wire.heartbeat('quiet-sensor', private_spool.stats())
        assert wire.verified_key is None
        wire.heartbeat('quiet-sensor', private_spool.stats())
        assert wire.verified_key == 'a' * 32
        with pytest.raises(network.DeliveryError, match='collector_binding_mismatch'):
            wire.heartbeat('wrong-sensor', private_spool.stats())
    assert requests == ['GET', 'POST', 'GET', 'POST']
    assert private_spool.db.execute('SELECT id,payload FROM batches').fetchone() == (batch_id, payload)
