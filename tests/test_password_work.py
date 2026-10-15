"""Deterministic barriers prove native ownership, cancellation, and auth branches."""

import asyncio
import json
import threading
from concurrent.futures import Future
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import anyio
import httpx
import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from shadai.api import auth
from shadai.database import get_postgres_session
from shadai.models.audit import AuditLogORM
from shadai.models.user import UserORM
from shadai.security import password_work as module
from shadai.security.auth import create_access_token
from shadai.security.password_work import DUMMY_HASH, PasswordWork, PasswordWorkBusyError, PasswordWorkUnavailableError

PASSWORD = "correct-password12"
LOCAL_HASH = "$2b$04$abcdefghijklmnopqrstuuWG29KuyeAicPCJODk1zjyGvyQUU2awu"


class Barrier:
    def __init__(self, count=1):
        self.count = count
        self.started = asyncio.Event()
        self.release = threading.Event()
        self.loop = asyncio.get_running_loop()
        self.threads = []
        self.lock = threading.Lock()

    def __call__(self, *args):
        assert all(isinstance(arg, (str, bytes)) for arg in args)
        with self.lock:
            self.threads.append(threading.get_ident())
            if len(self.threads) == self.count:
                self.loop.call_soon_threadsafe(self.started.set)
        if not self.release.wait(10):
            raise AssertionError("Native test barrier was not released")
        return True


async def started(barrier):
    await asyncio.wait_for(barrier.started.wait(), 10)


async def turns(count=10):
    for _ in range(count):
        await asyncio.sleep(0)


async def capacity_restored(service, expected=1):
    for _ in range(10000):
        if service._slots._value == expected:
            return
        await asyncio.sleep(0)
    raise AssertionError("Native completion did not restore capacity")


@pytest.mark.parametrize("workers", [0, 17, True, 1.5, "4"])
def test_worker_count_is_explicit_and_bounded(workers):
    with pytest.raises(ValueError):
        PasswordWork(workers)


async def test_native_work_is_off_loop_and_admission_has_no_waiting_queue(monkeypatch):
    barrier = Barrier(2)
    monkeypatch.setattr(module, "_verify_password", barrier)
    service = PasswordWork(2)
    submit = Mock(wraps=service._executor.submit)
    monkeypatch.setattr(service._executor, "submit", submit)
    tasks = [asyncio.create_task(service.verify(PASSWORD, LOCAL_HASH)) for _ in range(2)]
    try:
        await started(barrier)
        ticks = 0

        async def heartbeat():
            nonlocal ticks
            while True:
                ticks += 1
                await asyncio.sleep(0)

        pulse = asyncio.create_task(heartbeat())
        try:
            await turns()
            assert ticks > 0
            assert all(thread != threading.get_ident() for thread in barrier.threads)
            with pytest.raises(PasswordWorkBusyError):
                await service.verify(PASSWORD, LOCAL_HASH)
            with pytest.raises(PasswordWorkBusyError):
                await service.hash(PASSWORD)
            assert submit.call_count == 2
        finally:
            pulse.cancel()
            with pytest.raises(asyncio.CancelledError):
                await pulse
    finally:
        barrier.release.set()
        assert await asyncio.gather(*tasks) == [True, True]
        await service.aclose()
    assert service._slots._value == 2


@pytest.mark.parametrize("cancellation", ["raw", "anyio"])
async def test_request_cancellation_retains_native_permit(monkeypatch, cancellation):
    barrier = Barrier()
    monkeypatch.setattr(module, "_verify_password", barrier)
    service = PasswordWork(1)
    scopes = []

    async def request():
        if cancellation == "raw":
            return await service.verify(PASSWORD, LOCAL_HASH)
        with anyio.CancelScope() as scope:
            scopes.append(scope)
            await service.verify(PASSWORD, LOCAL_HASH)

    task = asyncio.create_task(request())
    try:
        await started(barrier)
        if cancellation == "raw":
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        else:
            scopes[0].cancel()
            await task
        with pytest.raises(PasswordWorkBusyError):
            await service.verify(PASSWORD, LOCAL_HASH)
        assert service._slots._value == 0
        barrier.release.set()
        await capacity_restored(service)
        assert await service.verify(PASSWORD, LOCAL_HASH) is True
    finally:
        barrier.release.set()
        await service.aclose()


@pytest.mark.parametrize("failure", ["enqueue_then_raise", "thread_start"])
async def test_submit_failure_after_enqueue_poison_closes_and_drains(monkeypatch, failure):
    service = PasswordWork(1)
    native_call = Mock(return_value=True)
    monkeypatch.setattr(module, "_verify_password", native_call)

    def fail_start():
        raise RuntimeError("synthetic private startup detail")

    if failure == "thread_start":
        monkeypatch.setattr(service._executor, "_adjust_thread_count", fail_start)
    else:
        monkeypatch.setattr(service._executor, "_adjust_thread_count", lambda: None)
        original_submit = service._executor.submit

        def enqueue_then_raise(operation):
            original_submit(operation)
            raise RuntimeError("synthetic private submission detail")

        monkeypatch.setattr(service._executor, "submit", enqueue_then_raise)
    try:
        with pytest.raises(PasswordWorkUnavailableError) as error:
            await service.verify(PASSWORD, LOCAL_HASH)
        assert "private" not in str(error.value)
        with pytest.raises(PasswordWorkUnavailableError):
            await service.verify(PASSWORD, LOCAL_HASH)
        native_call.assert_not_called()
        assert service._slots._value == 1
        queued = service._executor._work_queue.get_nowait()
        assert queued is None  # shutdown sentinel; the aborted work item was drained.
    finally:
        await service.aclose()


async def test_submit_failure_after_native_start_keeps_its_permit(monkeypatch):
    service = PasswordWork(1)
    entered = threading.Event()
    release = threading.Event()
    native_finished = threading.Event()

    def operation(*args):
        entered.set()
        assert release.wait(10)
        native_finished.set()
        return True

    monkeypatch.setattr(module, "_verify_password", operation)
    original = service._executor.submit

    def submit_then_raise(operation):
        original(operation)
        assert entered.wait(10)
        raise RuntimeError("synthetic failure after native start")

    monkeypatch.setattr(service._executor, "submit", submit_then_raise)
    try:
        with pytest.raises(PasswordWorkUnavailableError):
            await service.verify(PASSWORD, LOCAL_HASH)
        assert service._slots._value == 0 and not native_finished.is_set()
        with pytest.raises(PasswordWorkUnavailableError):
            await service.verify(PASSWORD, LOCAL_HASH)
        release.set()
        await capacity_restored(service)
    finally:
        release.set()
        await service.aclose()
    assert all(not worker.is_alive() for worker in service._executor._threads)


@pytest.mark.parametrize("outcome", ["cancelled", "failed"])
async def test_executor_future_settles_unstarted_job_once(monkeypatch, outcome):
    service = PasswordWork(1)
    native = Future()
    if outcome == "cancelled":
        native.cancel()
        expected = PasswordWorkUnavailableError
    else:
        native.set_exception(RuntimeError("synthetic executor failure"))
        expected = RuntimeError
    monkeypatch.setattr(service._executor, "submit", Mock(return_value=native))
    try:
        with pytest.raises(expected):
            await service.verify(PASSWORD, LOCAL_HASH)
        assert service._slots._value == 1
    finally:
        await service.aclose()


async def test_native_exception_releases_exactly_once_and_workers_accept_only_values(monkeypatch):
    service = PasswordWork(1)
    try:
        monkeypatch.setattr(module, "_verify_password", Mock(side_effect=ValueError("synthetic native failure")))
        with pytest.raises(ValueError):
            await service.verify(PASSWORD, LOCAL_HASH)
        assert service._slots._value == 1
        with pytest.raises(TypeError):
            await service.verify(SimpleNamespace(password=PASSWORD), LOCAL_HASH)
        assert service._slots._value == 1
        monkeypatch.setattr(module, "_verify_password", Mock(return_value=True))
        assert await service.verify(PASSWORD, LOCAL_HASH) is True
        assert service._slots._value == 1
    finally:
        await service.aclose()


@pytest.mark.parametrize("cancel_shutdown", [False, True])
async def test_shutdown_stops_admission_and_drains_off_loop_even_after_raw_cancel(monkeypatch, cancel_shutdown):
    barrier = Barrier()
    monkeypatch.setattr(module, "_verify_password", barrier)
    service = PasswordWork(1)
    task = asyncio.create_task(service.verify(PASSWORD, LOCAL_HASH))
    await started(barrier)
    loop = asyncio.get_running_loop()
    submit_join = Mock(wraps=loop.run_in_executor)
    monkeypatch.setattr(loop, "run_in_executor", submit_join)
    shutdown = asyncio.create_task(service.aclose())
    try:
        await turns()
        with pytest.raises(PasswordWorkUnavailableError):
            await service.verify(PASSWORD, LOCAL_HASH)
        if cancel_shutdown:
            shutdown.cancel()
        await turns()
        assert not shutdown.done()
        assert any(worker.is_alive() for worker in service._executor._threads)
    finally:
        barrier.release.set()
        assert await task is True
        if cancel_shutdown:
            with pytest.raises(asyncio.CancelledError):
                await shutdown
        else:
            await shutdown
    assert service._slots._value == 1
    assert submit_join.call_count == 1
    assert all(not worker.is_alive() for worker in service._executor._threads)


async def test_anyio_cancelled_shutdown_scope_still_drains_native_work(monkeypatch):
    barrier = Barrier()
    monkeypatch.setattr(module, "_verify_password", barrier)
    service = PasswordWork(1)
    task = asyncio.create_task(service.verify(PASSWORD, LOCAL_HASH))
    scopes = []
    await started(barrier)

    async def shutdown():
        with anyio.CancelScope() as scope:
            scopes.append(scope)
            await service.aclose()

    draining = asyncio.create_task(shutdown())
    try:
        await turns()
        scopes[0].cancel()
        await turns()
        assert not draining.done()
    finally:
        barrier.release.set()
        assert await task is True
        await draining
    assert service._slots._value == 1
    assert all(not worker.is_alive() for worker in service._executor._threads)


async def test_shutdown_cancelled_join_future_is_not_retried_forever(monkeypatch):
    service = PasswordWork(1)
    loop = asyncio.get_running_loop()
    cancelled = loop.create_future()
    cancelled.cancel()
    submit = Mock(return_value=cancelled)
    monkeypatch.setattr(loop, "run_in_executor", submit)
    with pytest.raises(asyncio.CancelledError):
        await service.aclose()
    assert submit.call_count == 1


async def test_shutdown_joins_synchronously_when_default_executor_is_unavailable(monkeypatch):
    service = PasswordWork(1)
    monkeypatch.setattr(module, "_verify_password", Mock(return_value=True))
    assert await service.verify(PASSWORD, LOCAL_HASH)
    loop = asyncio.get_running_loop()
    monkeypatch.setattr(loop, "run_in_executor", Mock(side_effect=RuntimeError("default executor shut down")))
    await service.aclose()
    assert all(not worker.is_alive() for worker in service._executor._threads)


def test_native_completion_after_originating_loop_closed_does_not_touch_another_pool(monkeypatch):
    loop = asyncio.new_event_loop()
    service = PasswordWork(1)
    release = threading.Event()
    started_on_loop = asyncio.Event()

    def operation(*args):
        loop.call_soon_threadsafe(started_on_loop.set)
        assert release.wait(10)
        return True

    monkeypatch.setattr(module, "_verify_password", operation)

    async def abandon():
        task = asyncio.create_task(service.verify(PASSWORD, LOCAL_HASH))
        await asyncio.wait_for(started_on_loop.wait(), 10)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    try:
        loop.run_until_complete(abandon())
        loop.close()
        new_pool = Mock(side_effect=AssertionError("Completion must not create a new pool"))
        monkeypatch.setattr(module, "ThreadPoolExecutor", new_pool)
    finally:
        release.set()
        service.close()
        service._executor.shutdown(wait=True)
        if not loop.is_closed():
            loop.close()
    assert service._slots._value == 1
    assert all(not worker.is_alive() for worker in service._executor._threads)
    new_pool.assert_not_called()


@pytest.fixture
async def password_api(identity_sessions, monkeypatch):
    app = FastAPI()
    app.include_router(auth.router)
    app.include_router(auth.users_router)
    passwords = PasswordWork(1)
    app.state.password_work = passwords

    async def database():
        async with identity_sessions.begin() as session:
            yield session

    app.dependency_overrides[get_postgres_session] = database
    redis = AsyncMock()
    redis.incr.return_value = 1
    redis.exists.return_value = 0
    monkeypatch.setattr(auth, "get_redis", AsyncMock(return_value=redis))
    monkeypatch.setattr("shadai.security.auth.get_redis", AsyncMock(return_value=redis))
    async with identity_sessions.begin() as session:
        for name, active, kind, hashed, role in (
            ("local", True, "local", LOCAL_HASH, "viewer"),
            ("inactive", False, "local", LOCAL_HASH, "viewer"),
            ("external", True, "scim", "!", "viewer"),
            ("malformed", True, "local", "invalid-bcrypt", "viewer"),
            ("admin", True, "local", LOCAL_HASH, "admin"),
        ):
            user = UserORM(username=name, is_active=active, identity_kind=kind, password_hash=hashed, role=role)
            session.add(user)
            await session.flush()
            if name == "admin":
                admin_token = create_access_token(str(user.user_id), user.role, user.session_version)
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app), base_url="https://console.example.test"
        ) as client:
            yield SimpleNamespace(
                app=app, client=client, passwords=passwords, redis=redis,
                sessions=identity_sessions, admin_token=admin_token,
            )
    finally:
        await passwords.aclose()


@pytest.mark.parametrize(
    "username,match,expected,hashes",
    [
        ("local", True, 200, [LOCAL_HASH]),
        ("local", False, 401, [LOCAL_HASH]),
        ("inactive", True, 403, [LOCAL_HASH]),
        ("inactive", False, 401, [LOCAL_HASH]),
        ("missing", True, 401, [DUMMY_HASH]),
        ("external", True, 401, [DUMMY_HASH]),
        ("malformed", True, 401, ["invalid-bcrypt", DUMMY_HASH]),
    ],
)
async def test_login_branches_always_check_and_dummy_cannot_authorize(
    password_api, monkeypatch, username, match, expected, hashes
):
    calls = []

    def checkpw(plain, hashed):
        assert threading.get_ident() != loop_thread
        calls.append((plain, hashed.decode()))
        if hashed == b"invalid-bcrypt":
            raise ValueError("Invalid salt")
        return match

    loop_thread = threading.get_ident()
    monkeypatch.setattr(module.bcrypt, "checkpw", checkpw)
    response = await password_api.client.post("/api/v1/auth/login", json={"username": username, "password": PASSWORD})
    assert response.status_code == expected, response.text
    assert [hashed for _, hashed in calls] == hashes
    assert all(plain == PASSWORD.encode() for plain, _ in calls)
    if expected == 200:
        assert response.json()["access_token"] and "set-cookie" not in response.headers
    else:
        assert "set-cookie" not in response.headers


async def test_over_72_utf8_bytes_uses_fixed_dummy_input_and_returns_401(password_api, monkeypatch):
    calls = []
    monkeypatch.setattr(module.bcrypt, "checkpw", lambda plain, hashed: calls.append((plain, hashed)) or True)
    response = await password_api.client.post(
        "/api/v1/auth/login", content=json.dumps({"username": "local", "password": "é" * 40}),
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 401
    assert calls == [(module._DUMMY_PASSWORD, DUMMY_HASH.encode())]


async def test_worker_handles_encoding_failure_with_a_fixed_dummy_input(monkeypatch):
    # Pydantic rejects lone surrogates before routing; the worker also fails closed
    # if a directly constructed request ever supplies an unencodable string.
    calls = []
    monkeypatch.setattr(module.bcrypt, "checkpw", lambda plain, hashed: calls.append((plain, hashed)) or True)
    service = PasswordWork(1)
    try:
        assert await service.verify("\ud800", LOCAL_HASH) is False
        assert calls == [(module._DUMMY_PASSWORD, DUMMY_HASH.encode())]
    finally:
        await service.aclose()


async def test_more_than_72_characters_retains_schema_422_without_native_work(password_api, monkeypatch):
    checkpw = Mock()
    monkeypatch.setattr(module.bcrypt, "checkpw", checkpw)
    response = await password_api.client.post(
        "/api/v1/auth/login", json={"username": "local", "password": "x" * 73}
    )
    assert response.status_code == 422
    checkpw.assert_not_called()


@pytest.mark.parametrize("state", ["missing", "closed"])
async def test_missing_or_closed_lifespan_service_fails_closed(password_api, state):
    if state == "missing":
        del password_api.app.state.password_work
    else:
        password_api.passwords.close()
    response = await password_api.client.post(
        "/api/v1/auth/login", json={"username": "local", "password": PASSWORD}
    )
    assert response.status_code == 503
    assert response.headers["retry-after"] == "1"
    assert response.json() == {"detail": "Password service is unavailable"}


async def test_login_and_admin_hash_share_capacity_without_partial_user_or_audit(password_api, monkeypatch):
    barrier = Barrier()
    monkeypatch.setattr(module, "_verify_password", barrier)
    login = asyncio.create_task(password_api.client.post(
        "/api/v1/auth/login", json={"username": "missing", "password": PASSWORD}
    ))
    try:
        await started(barrier)
        response = await password_api.client.post(
            "/api/v1/settings/users", json={"username": "new-user", "password": PASSWORD},
            headers={"Authorization": "Bearer " + password_api.admin_token},
        )
        assert response.status_code == 429 and response.headers["retry-after"] == "1"
        assert response.json() == {"detail": "Password service is busy"}
        async with password_api.sessions() as session:
            assert await session.scalar(select(func.count()).select_from(UserORM)) == 5
            assert await session.scalar(select(func.count()).select_from(AuditLogORM)) == 0
        password_api.redis.incr.return_value = 21
        response = await password_api.client.post(
            "/api/v1/auth/login", json={"username": "missing", "password": PASSWORD}
        )
        assert response.status_code == 429 and response.headers["retry-after"] == "60"
        assert response.json() == {"detail": "Too many login attempts"}
    finally:
        barrier.release.set()
        assert (await login).status_code == 401


async def test_admin_hash_is_off_loop_and_precedes_user_and_success_audit(password_api, monkeypatch):
    barrier = Barrier()

    def hashed(*args):
        barrier(*args)
        return LOCAL_HASH

    monkeypatch.setattr(module, "hash_password", hashed)
    creation = asyncio.create_task(password_api.client.post(
        "/api/v1/settings/users", json={"username": "new-user", "password": PASSWORD},
        headers={"Authorization": "Bearer " + password_api.admin_token},
    ))
    try:
        await started(barrier)
        await turns()
        assert barrier.threads[0] != threading.get_ident()
        async with password_api.sessions() as session:
            assert await session.scalar(select(func.count()).select_from(UserORM)) == 5
            assert await session.scalar(select(func.count()).select_from(AuditLogORM)) == 0
        response = await password_api.client.post(
            "/api/v1/auth/login", json={"username": "missing", "password": PASSWORD}
        )
        assert response.status_code == 429 and response.headers["retry-after"] == "1"
    finally:
        barrier.release.set()
        assert (await creation).status_code == 201
    async with password_api.sessions() as session:
        assert await session.scalar(select(func.count()).select_from(UserORM)) == 6
        assert await session.scalar(select(func.count()).select_from(AuditLogORM)) == 1


async def test_failed_admin_hash_cannot_create_a_user_or_success_audit(password_api, monkeypatch):
    monkeypatch.setattr(module, "hash_password", Mock(side_effect=ValueError("synthetic hash failure")))
    with pytest.raises(ValueError, match="synthetic hash failure"):
        await password_api.client.post(
            "/api/v1/settings/users", json={"username": "new-user", "password": PASSWORD},
            headers={"Authorization": "Bearer " + password_api.admin_token},
        )
    async with password_api.sessions() as session:
        assert await session.scalar(select(func.count()).select_from(UserORM)) == 5
        assert await session.scalar(select(func.count()).select_from(AuditLogORM)) == 0
    assert password_api.passwords._slots._value == 1


async def test_disconnected_asgi_request_cancellation_does_not_release_native_capacity(password_api, monkeypatch):
    barrier = Barrier()
    monkeypatch.setattr(module, "_verify_password", barrier)
    disconnected = asyncio.Event()
    body = json.dumps({"username": "missing", "password": PASSWORD}).encode()
    request_sent = False

    async def receive():
        nonlocal request_sent
        if not request_sent:
            request_sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        await disconnected.wait()
        return {"type": "http.disconnect"}

    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "POST",
        "scheme": "https", "path": "/api/v1/auth/login", "raw_path": b"/api/v1/auth/login",
        "root_path": "", "query_string": b"", "server": ("console.example.test", 443),
        "client": ("127.0.0.1", 1234), "headers": [(b"content-type", b"application/json")],
    }
    task = asyncio.create_task(password_api.app(scope, receive, AsyncMock()))
    try:
        await started(barrier)
        disconnected.set()
        assert (await receive())["type"] == "http.disconnect"
        # Model the ASGI server cancelling its handler when the connection closes.
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        response = await password_api.client.post(
            "/api/v1/auth/login", json={"username": "missing", "password": PASSWORD}
        )
        assert response.status_code == 429 and response.headers["retry-after"] == "1"
    finally:
        barrier.release.set()
        await capacity_restored(password_api.passwords)


def stub_lifespan_dependencies(monkeypatch):
    from shadai import main

    monkeypatch.setattr(main, "setup_logging", Mock())
    monkeypatch.setattr(main, "init_postgres", AsyncMock())
    monkeypatch.setattr(main, "init_clickhouse", Mock())
    monkeypatch.setattr(main, "init_redis", AsyncMock())
    monkeypatch.setattr(main, "init_crypto", Mock())
    monkeypatch.setattr(main, "close_all", AsyncMock())
    monkeypatch.setattr("shadai.engine.catalog_loader.sync_catalog", AsyncMock())

    async def sessions():
        yield SimpleNamespace()

    monkeypatch.setattr("shadai.database.get_postgres_session", sessions)
    return main


def test_repeated_testclient_lifespans_own_distinct_pools_and_join_every_worker(monkeypatch):
    main = stub_lifespan_dependencies(monkeypatch)
    monkeypatch.setattr(module, "_verify_password", Mock(return_value=True))
    app = FastAPI(lifespan=main.lifespan)
    services = []

    @app.get("/work")
    async def work(request: Request):
        service = request.app.state.password_work
        services.append(service)
        return await service.verify(PASSWORD, LOCAL_HASH)

    for _ in range(3):
        with TestClient(app) as client:
            assert client.get("/work").json() is True
            assert app.state.password_work is services[-1]
        assert app.state.password_work is None
        assert services[-1]._closed and services[-1]._slots._value == 4
        assert all(not worker.is_alive() for worker in services[-1]._executor._threads)
    assert len({id(service) for service in services}) == 3
    assert main.close_all.await_count == 3


async def test_lifespan_closes_service_when_initialization_fails(monkeypatch):
    main = stub_lifespan_dependencies(monkeypatch)
    monkeypatch.setattr(main, "init_postgres", AsyncMock(side_effect=ValueError("synthetic startup failure")))
    app = FastAPI()
    with pytest.raises(ValueError):
        async with main.lifespan(app):
            pytest.fail("Startup failure must not reach yield")
    assert app.state.password_work is None
    main.close_all.assert_awaited_once()


async def test_database_cleanup_runs_even_if_password_join_fails(monkeypatch):
    main = stub_lifespan_dependencies(monkeypatch)
    failed = SimpleNamespace(aclose=AsyncMock(side_effect=ValueError("synthetic join failure")))
    monkeypatch.setattr(main, "PasswordWork", Mock(return_value=failed))
    app = FastAPI()
    with pytest.raises(ValueError):
        async with main.lifespan(app):
            assert app.state.password_work is failed
    assert app.state.password_work is None
    main.close_all.assert_awaited_once()


async def test_cancelled_lifespan_join_falls_back_joins_workers_then_closes_resources(monkeypatch):
    main = stub_lifespan_dependencies(monkeypatch)
    barrier = Barrier()
    monkeypatch.setattr(module, "_verify_password", barrier)
    app = FastAPI()
    loop = asyncio.get_running_loop()
    joined = loop.create_future()
    joined.cancel()
    task = None
    service = None
    synchronous_joins = []

    async def closed_resources():
        assert app.state.password_work is None
        assert service._slots._value == 4
        assert all(not worker.is_alive() for worker in service._executor._threads)

    monkeypatch.setattr(main, "close_all", AsyncMock(side_effect=closed_resources))
    try:
        with pytest.raises(asyncio.CancelledError):
            async with main.lifespan(app):
                service = app.state.password_work
                task = asyncio.create_task(service.verify(PASSWORD, LOCAL_HASH))
                await started(barrier)
                original = service._executor.shutdown

                def shutdown(wait=True, *, cancel_futures=False):
                    if wait:
                        assert cancel_futures is True
                        assert any(worker.is_alive() for worker in service._executor._threads)
                        synchronous_joins.append(True)
                        barrier.release.set()
                    original(wait=wait, cancel_futures=cancel_futures)

                monkeypatch.setattr(service._executor, "shutdown", shutdown)
                monkeypatch.setattr(loop, "run_in_executor", Mock(return_value=joined))
    finally:
        barrier.release.set()
        if task is not None:
            assert await task is True
    assert synchronous_joins == [True]
    main.close_all.assert_awaited_once()
