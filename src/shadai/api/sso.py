"""Browser-bound OIDC sign-in for accounts provisioned explicitly through SCIM."""

import asyncio
import secrets
import time
from datetime import UTC, datetime
from urllib.parse import urlsplit
from uuid import UUID

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, RedirectResponse
from redis.exceptions import RedisError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import set_committed_value

from shadai.config import get_config
from shadai.database import get_postgres_session, get_redis
from shadai.models.user import LoginResponse, UserORM, UserRead
from shadai.security.audit import log_audit
from shadai.security.auth import create_access_token, csrf_token_for, effective_role, set_session_cookie
from shadai.security.oidc import HANDOFF_TTL, STATE_TTL, OIDCClient, OIDCError, consume_bound, origin, store_bound
from shadai.security.sso_admission import AdmissionDeniedError, SSOAdmission, normalized_peer

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])
HEADERS = {"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"}


def cookie_names(config):
    prefix = "__Host-" if config.secure_cookies else ""
    return prefix + "shadai-sso-browser", prefix + "shadai-sso-handoff"


def clear_cookies(response, config):
    for name in cookie_names(config):
        response.delete_cookie(name, path="/", secure=config.secure_cookies, httponly=True, samesite="lax")
    return response


def set_cookie(response, config, name, value, ttl):
    response.set_cookie(
        name,
        value,
        max_age=ttl,
        path="/",
        secure=config.secure_cookies,
        httponly=True,
        samesite="lax",
    )


def failure(config, *, redirect=False, status=401):
    if redirect and config.enabled:
        response = RedirectResponse(
            config.public_base_url + "/login?sso_error=failed", status_code=303, headers=HEADERS
        )
    else:
        response = JSONResponse(
            {"detail": "Single sign-on could not be completed"}, status_code=status, headers=HEADERS
        )
    return clear_cookies(response, config)


def same_origin(request, config):
    """Require a single serialized Origin, allowing equivalent default ports."""
    values = request.headers.getlist("origin")
    if len(values) != 1:
        return False
    value = values[0]
    try:
        parsed = urlsplit(value)
        if (
            parsed.path
            or parsed.query
            or parsed.fragment
            or parsed.username is not None
            or parsed.password is not None
            or "\\" in value
            or any(character.isspace() or ord(character) < 32 for character in value)
        ):
            return False
        return origin(value) == origin(config.public_base_url)
    except (ValueError, TypeError, AttributeError):
        return False


@router.get("/providers")
async def providers():
    config = get_config().oidc
    return JSONResponse(
        {
            "local_enabled": True,
            "sso": {"enabled": config.enabled, "label": config.label, "login_url": "/api/v1/auth/sso/login"},
        },
        headers=HEADERS,
    )


@router.get("/sso/login")
async def login(request: Request):
    installation = get_config()
    config = installation.oidc
    if not config.enabled:
        return failure(config, status=404)
    deadline = time.monotonic() + config.login_timeout_seconds
    admission, token, state, binding = None, None, None, None
    release, completed, phase = False, False, "admission"

    def remaining():
        budget = deadline - time.monotonic()
        if budget <= 0:
            raise TimeoutError()
        return budget

    try:
        async with asyncio.timeout(remaining()):
            redis = await get_redis()
            admission = SSOAdmission(redis, installation.tenant_id, config)
            token = admission.token()
            remaining()
            # The reply can be lost after Redis admits us; release this owned token
            # even in that case. A definite denial owns no lease.
            release = True
            await admission.admit(normalized_peer(request), token)
        phase = "state"
        remaining()
        binding, nonce, verifier = (secrets.token_urlsafe(32) for _ in range(3))
        async with asyncio.timeout(remaining()):
            state = await store_bound(redis, "state", {"nonce": nonce, "verifier": verifier}, binding, STATE_TTL)
        phase = "provider"
        async with asyncio.timeout(remaining()):
            remaining()
            url = await OIDCClient(config).authorization_url(state, nonce, verifier)
        remaining()
        response = RedirectResponse(url, status_code=303, headers=HEADERS)
        clear_cookies(response, config)
        set_cookie(response, config, cookie_names(config)[0], binding, STATE_TTL + HANDOFF_TTL)
        completed = True
        return response
    except AdmissionDeniedError as exc:
        release = False
        response = failure(config, status=429)
        response.headers["Retry-After"] = str(exc.retry_after)
        return response
    except RedisError:
        return failure(config, status=503)
    except (OIDCError, TimeoutError):
        return failure(config, redirect=phase == "provider", status=503)
    finally:
        operations = []
        if state is not None and not completed:
            operations.append(consume_bound(redis, "state", state, binding))
        if release and admission is not None:
            operations.append(admission.release(token))
        if operations:
            cleanup = asyncio.gather(*(_bounded_cleanup(operation) for operation in operations))
            try:
                await asyncio.shield(cleanup)
            except asyncio.CancelledError:
                # A second cancellation does not cancel the bounded cleanup task.
                # Redis TTLs remain the fallback when cleanup cannot complete.
                raise


async def _bounded_cleanup(operation):
    try:
        async with asyncio.timeout(2):
            await operation
    except Exception:
        # Best effort only: never replace the sanitized response with Redis data.
        pass


@router.get("/sso/callback")
async def callback(request: Request, session: AsyncSession = Depends(get_postgres_session, scope="function")):
    config = get_config().oidc
    if not config.enabled:
        return failure(config, status=404)
    browser_cookie, handoff_cookie = cookie_names(config)
    binding = request.cookies.get(browser_cookie)
    try:
        redis = await get_redis()
        state = await consume_bound(redis, "state", request.query_params.get("state"), binding)
        code = request.query_params.get("code")
        if (
            request.query_params.get("error")
            or not code
            or len(code) > 4096
            or len(request.query_params.getlist("code")) != 1
            or len(request.query_params.getlist("state")) != 1
        ):
            raise OIDCError()
        external_id = await OIDCClient(config).exchange(code, state["verifier"], state["nonce"])
        result = await session.execute(
            select(UserORM)
            .where(
                UserORM.identity_kind == "scim",
                UserORM.oidc_issuer == config.issuer,
                UserORM.external_id == external_id,
                UserORM.is_active.is_(True),
                UserORM.scim_deleted.is_(False),
            )
            .with_for_update()
        )
        user = result.scalar_one_or_none()
        if user is None:
            raise OIDCError()
        handoff = await store_bound(
            redis,
            "handoff",
            {
                "user_id": str(user.user_id),
                "session_version": user.session_version,
                "issuer": config.issuer,
            },
            binding,
            HANDOFF_TTL,
        )
        await session.commit()
    except (OIDCError, RedisError, KeyError):
        return failure(config, redirect=True)
    response = RedirectResponse(config.public_base_url + "/auth/callback", status_code=303, headers=HEADERS)
    set_cookie(response, config, browser_cookie, binding, HANDOFF_TTL)
    set_cookie(response, config, handoff_cookie, handoff, HANDOFF_TTL)
    return response


@router.post("/sso/session", response_model=LoginResponse)
async def exchange_session(request: Request, session: AsyncSession = Depends(get_postgres_session, scope="function")):
    config = get_config().oidc
    if not config.enabled:
        return failure(config, status=404)
    if request.headers.getlist("x-sso-csrf") != ["1"] or not same_origin(request, config):
        # Do not consume or delete another request's browser-bound credentials.
        return JSONResponse({"detail": "Single sign-on could not be completed"}, status_code=403, headers=HEADERS)
    browser_cookie, handoff_cookie = cookie_names(config)
    try:
        redis = await get_redis()
        ticket = await consume_bound(
            redis,
            "handoff",
            request.cookies.get(handoff_cookie),
            request.cookies.get(browser_cookie),
        )
        user_id = UUID(ticket["user_id"])
        result = await session.execute(select(UserORM).where(UserORM.user_id == user_id).with_for_update())
        user = result.scalar_one_or_none()
        if (
            user is None
            or not user.is_active
            or user.scim_deleted
            or user.identity_kind != "scim"
            or user.oidc_issuer != config.issuer
            or ticket["issuer"] != config.issuer
            or ticket["session_version"] != user.session_version
        ):
            raise OIDCError()
        role = await effective_role(session, user)
        set_committed_value(user, "role", role)
        user.last_login_at = datetime.now(UTC)
        await log_audit(
            session,
            user.user_id,
            user.username,
            "login",
            details={"method": "oidc"},
            ip_address=request.client.host if request.client else None,
        )
        await session.flush()
        await session.refresh(user, attribute_names=["last_login_at", "updated_at"])
        token = create_access_token(str(user.user_id), role, user.session_version)
        result = LoginResponse(
            token_type="cookie", csrf_token=csrf_token_for(token), user=UserRead.model_validate(user)
        )
        # Dependency cleanup can run after response delivery; persist the audit
        # and release the user lock before exposing a usable session token.
        await session.commit()
    except (OIDCError, RedisError, ValueError, KeyError, TypeError):
        return failure(config)
    response = clear_cookies(JSONResponse(result.model_dump(mode="json"), headers=HEADERS), config)
    # The browser receives the session as an HttpOnly cookie, never as a readable token.
    set_session_cookie(response, request, token)
    return response
