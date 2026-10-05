"""Exercise Requests redirect handling without opening a network connection."""

import json
from unittest.mock import Mock

import pytest
import requests
from requests.adapters import BaseAdapter
from shadai_agent import main as agent


class RecordingAdapter(BaseAdapter):
    def __init__(self, statuses, location=""):
        self.statuses = iter(statuses)
        self.location = location
        self.requests = []

    def send(self, request, **kwargs):
        self.requests.append(request)
        result = next(self.statuses)
        if isinstance(result, Exception):
            raise result
        response = requests.Response()
        response.status_code = result
        response.url = request.url
        response.request = request
        response._content = b'{"received": 3}'
        if self.location:
            response.headers["Location"] = self.location
        return response

    def close(self):
        pass


@pytest.fixture
def send_through_adapter(monkeypatch):
    session = requests.Session()
    session.trust_env = False
    sleeps = Mock()
    monkeypatch.setattr(agent.time, "sleep", sleeps)
    monkeypatch.setattr(agent.requests, "post", session.post)

    def install(statuses, location=""):
        adapter = RecordingAdapter(statuses, location)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return adapter, sleeps

    yield install
    session.close()


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
@pytest.mark.parametrize(
    "target",
    [
        "https://second.example.test/collect",
        "http://second.example.test/collect",
        "http://first.example.test/collect",
        "/other-path",
    ],
)
def test_redirect_never_receives_telemetry_or_api_key(send_through_adapter, status, target):
    adapter, sleeps = send_through_adapter([status, 200], target)
    url = "https://first.example.test/telemetry"
    batch = {"hostname": "private-host", "processes": [{"username": "alice"}]}
    assert agent.send_batch(url, batch, {"X-API-Key": "private-key"}, True) is None
    assert len(adapter.requests) == 1
    [request] = adapter.requests
    assert request.url == url and request.method == "POST"
    assert request.headers["X-API-Key"] == "private-key"
    assert json.loads(request.body) == batch
    sleeps.assert_not_called()


@pytest.mark.parametrize("status", [400, 401, 403, 404, 413, 422])
def test_permanent_client_errors_stop_immediately(send_through_adapter, status):
    adapter, sleeps = send_through_adapter([status])
    assert agent.send_batch("https://first.example.test/telemetry", {}, {}, True) is None
    assert len(adapter.requests) == 1
    sleeps.assert_not_called()


@pytest.mark.parametrize("failure", [408, 429, 503, requests.Timeout("timeout"), requests.ConnectionError("reset")])
def test_transient_failure_retries_identical_batch_with_bounded_backoff(send_through_adapter, failure):
    adapter, sleeps = send_through_adapter([failure, failure, 200])
    batch = {"hostname": "host"}
    assert agent.send_batch("https://first.example.test/telemetry", batch, {"X-API-Key": "key"}, True) == 3
    assert len(adapter.requests) == 3
    assert all(json.loads(request.body) == batch for request in adapter.requests)
    assert [call.args for call in sleeps.call_args_list] == [(1,), (2,)]


def test_persistent_transient_failure_stops_after_three_attempts(send_through_adapter):
    adapter, sleeps = send_through_adapter([503, 503, 503])
    assert agent.send_batch("https://first.example.test/telemetry", {}, {}, True) is None
    assert len(adapter.requests) == 3 and sleeps.call_count == 2
