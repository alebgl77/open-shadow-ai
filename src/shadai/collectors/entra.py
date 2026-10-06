"""Microsoft Entra application/grant inventory via Graph, not usage or SSO.

Global commercial cloud only. Application.Read.All lists service principals.
Optional delegated-grant inventory additionally requires Directory.Read.All.
"""

import asyncio
import os
import uuid
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import urlsplit

import httpx
import redis.asyncio as aioredis
import structlog
from pydantic import BaseModel, Field

from shadai.config import load_config, validate_security
from shadai.models.event import CanonicalEvent

logger = structlog.get_logger()
GRAPH = "https://graph.microsoft.com/v1.0/"


class EntraSettings(BaseModel):
    tenant_id: uuid.UUID
    client_id: uuid.UUID
    client_secret: str = Field(min_length=1, repr=False)
    collect_grants: bool = False
    poll_interval_seconds: int = Field(default=3600, ge=60)

    @classmethod
    def from_env(cls):
        secret_file = os.environ.get("ENTRA_CLIENT_SECRET_FILE")
        secret = Path(secret_file).read_text().strip() if secret_file else os.environ.get("ENTRA_CLIENT_SECRET", "")
        return cls(
            tenant_id=os.environ.get("ENTRA_TENANT_ID"),
            client_id=os.environ.get("ENTRA_CLIENT_ID"),
            client_secret=secret,
            collect_grants=os.environ.get("ENTRA_COLLECT_GRANTS", "false").lower() == "true",
            poll_interval_seconds=int(os.environ.get("ENTRA_POLL_INTERVAL_SECONDS", "3600")),
        )


def validate_graph_url(url: str) -> str:
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.netloc != "graph.microsoft.com"
        or parsed.fragment
        or parsed.path not in {"/v1.0/servicePrincipals", "/v1.0/oauth2PermissionGrants"}
    ):
        raise ValueError("Graph pagination URL is not an approved endpoint")
    return url


def retry_delay(value: str | None, attempt: int) -> float:
    if value:
        try:
            delay = float(value)
        except ValueError:
            try:
                delay = (parsedate_to_datetime(value) - datetime.now(UTC)).total_seconds()
            except (ValueError, TypeError):
                delay = 2**attempt
        # Abort overly long Retry-After instead of violating it with an early retry.
        if delay > 300:
            raise RuntimeError("Graph requested backoff longer than this poll; retry next poll")
        return max(0, delay)
    return min(2**attempt, 60)


class EntraInventory:
    def __init__(self, settings, client, *, sleep=asyncio.sleep):
        self.settings, self.client, self.sleep = settings, client, sleep
        self.token = ""

    async def _request(self, method, url, **kwargs):
        for attempt in range(5):
            try:
                response = await self.client.request(method, url, timeout=30, follow_redirects=False, **kwargs)
            except httpx.TransportError:
                if attempt == 4:
                    raise RuntimeError("Graph transport retries exhausted") from None
                await self.sleep(min(2**attempt, 60))
                continue
            if response.status_code in {429, 500, 502, 503, 504} and attempt < 4:
                await self.sleep(retry_delay(response.headers.get("Retry-After"), attempt))
                continue
            if response.status_code != 200:
                # Do not log token bodies, client secrets, URLs, or Graph error descriptions.
                raise RuntimeError(f"Graph request failed with HTTP {response.status_code}")
            return response.json()
        raise RuntimeError("Graph request retries exhausted")

    async def authenticate(self):
        data = await self._request(
            "POST",
            f"https://login.microsoftonline.com/{self.settings.tenant_id}/oauth2/v2.0/token",
            data={
                "client_id": str(self.settings.client_id),
                "client_secret": self.settings.client_secret,
                "scope": "https://graph.microsoft.com/.default",
                "grant_type": "client_credentials",
            },
        )
        token = data.get("access_token")
        if not isinstance(token, str) or not token:
            raise RuntimeError("Graph token response is invalid")
        self.token = token

    async def pages(self, endpoint):
        url = GRAPH + endpoint
        seen = set()
        for _ in range(10000):
            validate_graph_url(url)
            if url in seen:
                raise ValueError("Graph pagination cycle")
            seen.add(url)
            data = await self._request("GET", url, headers={"Authorization": f"Bearer {self.token}"})
            values = data.get("value")
            if not isinstance(values, list) or any(not isinstance(item, dict) for item in values):
                raise ValueError("Invalid Graph collection response")
            yield values
            url = data.get("@odata.nextLink")
            if not url:
                return
            if not isinstance(url, str):
                raise ValueError("Invalid Graph nextLink")
        raise ValueError("Graph pagination limit reached")

    async def collect(self, organization: str, timestamp=None):
        await self.authenticate()
        timestamp = timestamp or datetime.now(UTC)
        interval = self.settings.poll_interval_seconds
        # Stable IDs within a scheduled snapshot (including partial-poll retries).
        snapshot = int(timestamp.timestamp()) // interval
        timestamp = datetime.fromtimestamp(snapshot * interval, UTC)
        principals = {}
        events = []

        def event(kind, object_id, **kwargs):
            return CanonicalEvent(
                event_id=uuid.uuid5(
                    uuid.NAMESPACE_URL, f"entra:{self.settings.tenant_id}:{kind}:{object_id}:{snapshot}"
                ),
                timestamp=timestamp,
                normalized_at=timestamp,
                source_type="oauth",
                evidence_type="inventory",
                tenant_id=organization,
                collector_id="entra-inventory",
                identity_provider="entra",
                identity_object_id=object_id,
                **kwargs,
            )

        async for page in self.pages("servicePrincipals?$select=id,appId,displayName,servicePrincipalNames&$top=100"):
            for item in page:
                object_id = str(item["id"])
                principals[object_id] = item
                if len(principals) > 100000:
                    raise ValueError("Entra inventory size limit exceeded")
                events.append(
                    event(
                        "servicePrincipal",
                        object_id,
                        oauth_app_id=str(item.get("appId") or ""),
                        oauth_app_name=str(item.get("displayName") or ""),
                    )
                )
        if self.settings.collect_grants:
            async for page in self.pages("oauth2PermissionGrants"):
                for grant in page:
                    principal = principals.get(grant.get("clientId"), {})
                    events.append(
                        event(
                            "grant",
                            str(grant["id"]),
                            oauth_app_id=str(principal.get("appId") or ""),
                            oauth_app_name=str(principal.get("displayName") or ""),
                            user_id=str(grant.get("principalId") or ""),
                            oauth_scopes=str(grant.get("scope") or "").split(),
                        )
                    )
                    if len(events) > 200000:
                        raise ValueError("Entra grant inventory size limit exceeded")
        return events


class InventoryDelivery:
    """Retry the exact rejected chunks before fetching another inventory.

    Pending bytes live in this process; restarting it loses this buffer. Stable
    snapshot IDs permit a subsequent inventory to overlap uncertain delivery.
    """

    def __init__(self, redis, settings):
        self.redis, self.settings = redis, settings
        self.pending = []
        self.total = 0

    def retain(self, events):
        from shadai.utils.queue_admission import record_size
        from shadai.utils.queueing import queue_fields

        if self.pending:
            raise RuntimeError("Inventory delivery still pending")
        records = [{"stream": "events:oauth", "fields": queue_fields(event.model_dump_json())}
                   for event in events]
        self.pending = []
        chunk, size = [], 0
        for record in records:
            length = record_size(record)
            if chunk and (len(chunk) == 500 or size + length > self.settings.admission_max_batch_bytes):
                self.pending.append(chunk)
                chunk, size = [], 0
            chunk.append(record)
            size += length
        if chunk:
            self.pending.append(chunk)
        self.total = len(events)

    async def flush(self):
        from shadai.utils.queue_admission import admit_records

        while self.pending:
            await admit_records(self.redis, self.pending[0], settings=self.settings)
            self.pending.pop(0)
        return self.total


async def main():
    config = load_config()
    validate_security(config)
    settings = EntraSettings.from_env()
    redis = aioredis.from_url(config.database.redis_url, decode_responses=True)
    try:
        async with httpx.AsyncClient(trust_env=False, follow_redirects=False) as client:
            collector = EntraInventory(settings, client)
            delivery = InventoryDelivery(redis, config.redis_queue)
            while True:
                try:
                    if not delivery.pending:
                        delivery.retain(await collector.collect(config.tenant_id))
                    count = await delivery.flush()
                    logger.info("entra_inventory_collected", records=count)
                except Exception as exc:
                    logger.error("entra_inventory_failed", error_type=type(exc).__name__)
                await asyncio.sleep(settings.poll_interval_seconds)
    finally:
        await redis.aclose()


if __name__ == "__main__":
    asyncio.run(main())
