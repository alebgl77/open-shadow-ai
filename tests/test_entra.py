from datetime import UTC, datetime
from unittest.mock import AsyncMock
from uuid import uuid4

import httpx
import pytest

from shadai.collectors.entra import EntraInventory, EntraSettings, retry_delay, validate_graph_url


@pytest.mark.parametrize(
    "url",
    [
        "http://graph.microsoft.com/v1.0/servicePrincipals",
        "https://evil.test/v1.0/servicePrincipals",
        "https://graph.microsoft.com@evil.test/v1.0/servicePrincipals",
        "https://graph.microsoft.com:443/v1.0/servicePrincipals",
        "https://graph.microsoft.com/v1.0/users",
        "https://graph.microsoft.com/v1.0/servicePrincipals#fragment",
    ],
)
def test_hostile_nextlink_rejected(url):
    with pytest.raises(ValueError):
        validate_graph_url(url)


async def test_pagination_throttling_grants_and_inventory_provenance():
    calls = []
    throttled = False
    settings = EntraSettings(tenant_id=uuid4(), client_id=uuid4(), client_secret="private", collect_grants=True)

    def handler(request):
        nonlocal throttled
        calls.append(request)
        if "login.microsoftonline.com" in str(request.url):
            return httpx.Response(200, json={"access_token": "access-secret"})
        assert request.headers["Authorization"] == "Bearer access-secret"
        if "servicePrincipals" in str(request.url):
            if not throttled:
                throttled = True
                return httpx.Response(429, headers={"Retry-After": "2"})
            if "skiptoken" not in str(request.url):
                return httpx.Response(
                    200,
                    json={
                        "value": [{"id": "sp1", "appId": "app1", "displayName": "AI"}],
                        "@odata.nextLink": "https://graph.microsoft.com/v1.0/servicePrincipals?$skiptoken=abc",
                    },
                )
            return httpx.Response(200, json={"value": [{"id": "sp2", "appId": "app2"}]})
        return httpx.Response(
            200,
            json={
                "value": [{"id": "grant1", "clientId": "sp1", "principalId": "user1", "scope": "User.Read Mail.Read"}]
            },
        )

    sleep = AsyncMock()
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        inventory = EntraInventory(settings, client, sleep=sleep)
        timestamp = datetime(2026, 1, 1, tzinfo=UTC)
        events = await inventory.collect("org", timestamp)
        again = await inventory.collect("org", timestamp)
    assert len(events) == 3
    assert [e.event_id for e in events] == [e.event_id for e in again]
    assert all(e.evidence_type == "inventory" and e.model == "" and e.input_tokens is None for e in events)
    assert events[2].oauth_app_id == "app1" and events[2].user_id == "user1"
    assert events[2].oauth_scopes == ["User.Read", "Mail.Read"]
    sleep.assert_awaited_once_with(2.0)


async def test_graph_redirect_and_nextlink_never_receive_token():
    calls = []

    def handler(request):
        calls.append(str(request.url))
        return httpx.Response(200, json={"value": [], "@odata.nextLink": "https://evil.test/token"})

    settings = EntraSettings(tenant_id=uuid4(), client_id=uuid4(), client_secret="private")
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        inventory = EntraInventory(settings, client)
        inventory.token = "secret"
        with pytest.raises(ValueError):
            async for _ in inventory.pages("servicePrincipals"):
                pass
    assert len(calls) == 1 and "evil" not in calls[0]


async def test_retries_bounded_and_error_does_not_include_secrets():
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(503, json={"error": "private secret"})

    settings = EntraSettings(tenant_id=uuid4(), client_id=uuid4(), client_secret="private")
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        inventory = EntraInventory(settings, client, sleep=AsyncMock())
        with pytest.raises(RuntimeError) as error:
            await inventory.authenticate()
    assert len(calls) == 5 and "private" not in str(error.value)
    with pytest.raises(RuntimeError):
        retry_delay("301", 0)


async def test_pagination_cycle_rejected():
    settings = EntraSettings(tenant_id=uuid4(), client_id=uuid4(), client_secret="private")

    def handler(request):
        return httpx.Response(200, json={"value": [], "@odata.nextLink": str(request.url)})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(ValueError, match="cycle"):
            async for _ in EntraInventory(settings, client).pages("servicePrincipals"):
                pass
