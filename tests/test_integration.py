"""Live dialect/transaction acceptance against disposable local/CI services.

Run SHADAI_INTEGRATION=1 pytest -q -m integration after setting DATABASE_URL,
REDIS_URL and CLICKHOUSE_HOST/PORT/DATABASE/USER/PASSWORD. Never use production.
"""

import asyncio
import os
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

import pytest
import redis.asyncio as aioredis
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from shadai.config import CatalogSettings, get_config, load_config
from shadai.database import init_clickhouse
from shadai.engine.catalog_loader import load_database_catalog, sync_catalog
from shadai.engine.correlator import Correlator
from shadai.engine.matcher import CatalogMatcher
from shadai.models.catalog import CatalogItemORM
from shadai.models.detection import DetectionORM
from shadai.models.event import CanonicalEvent
from shadai.models.receipts import CorrelationReceiptORM, IngestReceiptORM
from shadai.workers.ingest import EventProcessor
from shadai.workers.streams import StreamConsumer

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.environ.get("SHADAI_INTEGRATION") != "1",
        reason="Disposable PostgreSQL/Redis/ClickHouse services not requested",
    ),
]


async def test_live_migration_catalog_ingestion_concurrency_and_reclaim():
    subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], check=True, capture_output=True, text=True)
    config = load_config()
    get_config.cache_clear()
    engine = create_async_engine(config.database.postgres_url, pool_pre_ping=True)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    redis = aioredis.from_url(config.database.redis_url, decode_responses=True)
    ch = init_clickhouse(config.database)
    # Execute the same fresh-install schema files as container initialization.
    for path in ("docker/clickhouse-init/001_create_database.sql", "migrations/clickhouse/002_event_metadata.sql"):
        for statement in Path(path).read_text().split(";"):
            if statement.strip():
                await asyncio.to_thread(ch.execute, statement)
    unique = uuid4().hex
    item_id, domain = "test-" + unique, unique + ".example.test"
    stream = "test-events:" + unique
    group = "test-ingest:" + unique
    events = [
        CanonicalEvent(
            tenant_id=config.tenant_id,
            domain=domain,
            user_id="test-user",
            device_id="test-device",
            collector_id="integration",
        )
        for _ in range(2)
    ]
    try:
        async with sessions.begin() as session:
            count = await sync_catalog(
                session, CatalogSettings(builtin_path="catalog/builtin", local_path="catalog/local")
            )
            assert count > 0
            session.add(
                CatalogItemORM(
                    catalog_item_id=item_id,
                    canonical_name="Integration fixture",
                    category="ai_platform",
                    domains=[domain],
                    status="active",
                    source_of_truth="local",
                    local_override=True,
                )
            )
        async with sessions() as session:
            catalog = await load_database_catalog(session)
        processor = EventProcessor(redis, ch, sessions, CatalogMatcher(catalog))
        consumer = StreamConsumer(redis, group, "worker-a", [stream], reclaim_ms=0)
        await consumer.initialize()
        message_id = await redis.xadd(stream, {"data": events[0].model_dump_json()})
        await redis.xreadgroup(group, "crashed-worker", {stream: ">"}, count=1)
        recovered = await consumer.read()
        assert recovered[0][1][0][0] == message_id
        await consumer.process(stream, message_id, recovered[0][1][0][1], processor)
        assert (await redis.xpending(stream, group))["pending"] == 0
        assert await redis.xlen(stream) == 0
        # An extra consumer group prevents deletion of its unread work.
        await redis.xgroup_create(stream, "other-group", id="0")
        shared_id = await redis.xadd(stream, {"data": events[0].model_dump_json()})
        shared = await redis.xreadgroup(group, "worker-a", {stream: ">"}, count=1)
        await consumer.process(stream, shared_id, shared[0][1][0][1], processor)
        assert await redis.xlen(stream) == 1
        # Same event concurrently retried must not persist/enqueue again after success.
        await asyncio.gather(
            processor({"data": events[0].model_dump_json()}), processor({"data": events[0].model_dump_json()})
        )
        await processor({"data": events[1].model_dump_json()})
        raw_count = (
            await asyncio.to_thread(
                ch.execute, "SELECT count() FROM events WHERE catalog_match_id=%(item)s", {"item": item_id}
            )
        )[0][0]
        assert raw_count == 2
        correlator = Correlator(sessions)
        item = catalog.items[item_id]
        await asyncio.gather(
            *[
                correlator.upsert_detection(event, item, "domain", 0.6)
                for event in [events[0], events[0], events[1], events[1]]
            ]
        )
        async with sessions() as session:
            rows = (
                (await session.execute(select(DetectionORM).where(DetectionORM.catalog_item_id == item_id)))
                .scalars()
                .all()
            )
            assert len(rows) == 1
            assert rows[0].total_events_count == 2
            assert rows[0].impacted_users_count == rows[0].impacted_devices_count == 1
            receipts = (
                (
                    await session.execute(
                        select(CorrelationReceiptORM).where(CorrelationReceiptORM.catalog_item_id == item_id)
                    )
                )
                .scalars()
                .all()
            )
            assert len(receipts) == 2
        # Administrator changes are visible in the next database index refresh.
        async with sessions.begin() as session:
            row = await session.get(CatalogItemORM, item_id)
            row.status = "disabled"
        async with sessions() as session:
            assert item_id not in (await load_database_catalog(session)).items
    finally:
        await redis.delete(stream)
        async with sessions.begin() as session:
            for model in (CorrelationReceiptORM, IngestReceiptORM):
                await session.execute(delete(model).where(model.event_id.in_([event.event_id for event in events])))
            await session.execute(delete(DetectionORM).where(DetectionORM.catalog_item_id == item_id))
            await session.execute(delete(CatalogItemORM).where(CatalogItemORM.catalog_item_id == item_id))
        await asyncio.to_thread(
            ch.execute,
            "ALTER TABLE events DELETE WHERE catalog_match_id=%(item)s SETTINGS mutations_sync=1",
            {"item": item_id},
        )
        # Match records may remain in the disposable test queue; no live workers run in this test.
        ch.disconnect()
        await redis.aclose()
        await engine.dispose()


async def test_live_identity_migration_lifecycle_and_concurrent_provisioning(monkeypatch):
    """A separate disposable schema verifies pre-existing users and real row/advisory locks."""
    import importlib.util

    from alembic.migration import MigrationContext
    from alembic.operations import Operations
    from sqlalchemy import text

    from shadai.models.identity import MembershipORM
    from shadai.models.user import UserORM
    from shadai.security.auth import effective_role, hash_password, verify_password
    from shadai.security.scim import PATCH_SCHEMA, SCIMError, SCIMService

    config = load_config()
    config.oidc.issuer = "https://idp.example.test/" + uuid4().hex
    config.scim.group_role_map = {"admins-group": "admin"}
    monkeypatch.setattr("shadai.security.scim.get_config", lambda: config)
    monkeypatch.setattr("shadai.security.auth.get_config", lambda: config)
    schema = "identity_test_" + uuid4().hex
    admin_engine = create_async_engine(config.database.postgres_url)
    async with admin_engine.begin() as connection:
        await connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_async_engine(
        config.database.postgres_url, connect_args={"server_settings": {"search_path": schema}}
    )
    sessions = async_sessionmaker(engine, expire_on_commit=False)

    def migration(filename):
        spec = importlib.util.spec_from_file_location("live_" + filename, Path("migrations/versions") / filename)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    first, second, identity = [
        migration(name) for name in ("001_initial_schema.py", "002_reliable_ingest.py", "003_external_identity.py")
    ]

    def run(connection, operation):
        with Operations.context(MigrationContext.configure(connection)):
            operation()

    local_id, conflict_id = uuid4(), uuid4()
    password = hash_password("local-breakglass-password")
    try:
        async with engine.begin() as connection:
            await connection.run_sync(run, first.upgrade)
            await connection.run_sync(run, second.upgrade)
            await connection.execute(
                text("INSERT INTO users(user_id,username,password_hash) VALUES (:id,:name,:password)"),
                [
                    {"id": local_id, "name": "ExistingUser", "password": password},
                    {"id": conflict_id, "name": "EXISTINGUSER", "password": password},
                ],
            )
        with pytest.raises(RuntimeError, match="Rename conflicting local accounts"):
            async with engine.begin() as connection:
                await connection.run_sync(run, identity.upgrade)
        async with engine.begin() as connection:
            assert (
                await connection.execute(
                    text(
                        "SELECT count(*) FROM information_schema.columns WHERE table_schema=:schema "
                        "AND table_name='users' AND column_name='username_key'"
                    ),
                    {"schema": schema},
                )
            ).scalar_one() == 0
            await connection.execute(text("DELETE FROM users WHERE user_id=:id"), {"id": conflict_id})
            await connection.run_sync(run, identity.upgrade)
            # Empty identity deployment can be downgraded safely, then upgraded again.
            await connection.run_sync(run, identity.downgrade)
            await connection.run_sync(run, identity.upgrade)
        async with sessions() as session:
            local = await session.get(UserORM, local_id)
            assert local.username_key == "existinguser" and local.identity_kind == "local"
            assert local.session_version == 0 and verify_password("local-breakglass-password", local.password_hash)

        async def create_identity(external_id):
            try:
                async with sessions.begin() as session:
                    row = await SCIMService(session).create_user({"userName": "Concurrent", "externalId": external_id})
                    return row.user_id
            except SCIMError as exc:
                assert exc.status == 409
                return None

        created = await asyncio.gather(create_identity("first"), create_identity("second"))
        assert sum(item is not None for item in created) == 1
        user_id = next(item for item in created if item is not None)
        locked, release, second_started = asyncio.Event(), asyncio.Event(), asyncio.Event()

        async def deactivate():
            async with sessions.begin() as session:
                row = await SCIMService(session).update_user(
                    user_id,
                    {"schemas": [PATCH_SCHEMA], "Operations": [{"op": "replace", "path": "active", "value": False}]},
                    patch=True,
                )
                assert row.session_version == 1
                locked.set()
                await release.wait()

        async def rename_display():
            await locked.wait()
            async with sessions.begin() as session:
                second_started.set()
                await SCIMService(session).update_user(
                    user_id,
                    {
                        "schemas": [PATCH_SCHEMA],
                        "Operations": [{"op": "replace", "path": "displayName", "value": "Renamed"}],
                    },
                    patch=True,
                )

        first_task, second_task = asyncio.create_task(deactivate()), asyncio.create_task(rename_display())
        await asyncio.wait_for(second_started.wait(), 5)
        release.set()
        await asyncio.wait_for(asyncio.gather(first_task, second_task), 15)
        async with sessions.begin() as session:
            service = SCIMService(session)
            user = await service.get("Users", user_id)
            # The rename ran after the deactivation and, as a profile edit, kept its revocation version.
            assert not user.is_active and user.display_name == "Renamed" and user.session_version == 1
            group = await service.create_group(
                {"externalId": "admins-group", "displayName": "Admins", "members": [{"value": str(user_id)}]}
            )
            group_id = group.group_id
            assert not user.is_active and user.role == "admin"
        with pytest.raises(SCIMError):
            async with sessions.begin() as session:
                await SCIMService(session).update_group(
                    group_id,
                    {
                        "schemas": [PATCH_SCHEMA],
                        "Operations": [
                            {"op": "remove", "path": "members", "value": [{"value": str(user_id)}]},
                            {"op": "add", "path": "members", "value": [{"value": str(uuid4())}]},
                        ],
                    },
                    patch=True,
                )
        async with sessions() as session:
            assert (await session.execute(select(MembershipORM).where(MembershipORM.user_id == user_id))).scalar_one()
            user = await session.get(UserORM, user_id)
            assert user.role == "admin" and not user.is_active
            config.scim.group_role_map = {}
            assert await effective_role(session, user) == "viewer"
        with pytest.raises(RuntimeError, match="Downgrade blocked"):
            async with engine.begin() as connection:
                await connection.run_sync(run, identity.downgrade)
        async with sessions.begin() as session:
            service = SCIMService(session)
            user = await service.get("Users", user_id)
            external_id, old_version = user.external_id, user.session_version
            await service.delete_user(user_id)
            restored = await service.create_user({"externalId": external_id, "userName": "Concurrent"})
            assert restored.user_id == user_id and restored.session_version >= old_version + 2
            assert (await service.represent("Users", restored))["groups"] == []
    finally:
        await engine.dispose()
        async with admin_engine.begin() as connection:
            await connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        await admin_engine.dispose()
