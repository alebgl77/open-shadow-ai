"""Authentication API routes."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from shadai.database import get_postgres_session, get_redis
from shadai.models.user import LoginRequest, LoginResponse, UserCreate, UserORM, UserRead, UserUpdate
from shadai.security.audit import log_audit
from shadai.security.auth import (
    clear_session_cookie,
    create_access_token,
    csrf_token_for,
    decode_access_token,
    effective_roles,
    get_current_user,
    hash_password,
    request_token,
    set_session_cookie,
    verify_password,
)
from shadai.security.rbac import require_role

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@router.post("/login", response_model=LoginResponse)
async def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    session: AsyncSession = Depends(get_postgres_session, scope="function"),
):
    """Authenticate. Browsers ask for an HttpOnly session cookie; API clients get a bearer token."""
    redis = await get_redis()
    peer = request.client.host if request.client else "unknown"
    bucket = int(datetime.now(UTC).timestamp()) // 60
    key = f"login-limit:{hashlib.sha256(peer.encode()).hexdigest()}:{bucket}"
    count = await redis.incr(key)
    if count == 1:
        await redis.expire(key, 120)
    if count > 20:
        raise HTTPException(status_code=429, detail="Too many login attempts", headers={"Retry-After": "60"})
    result = await session.execute(select(UserORM).where(UserORM.username_key == body.username.strip().casefold()))
    user = result.scalar_one_or_none()

    if user is None or user.identity_kind != "local" or not verify_password(body.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated",
        )

    token = create_access_token(str(user.user_id), user.role, user.session_version)
    user.last_login_at = datetime.now(UTC)

    await log_audit(
        session,
        user.user_id,
        user.username,
        "login",
        ip_address=request.client.host if request.client else None,
    )

    response.headers["Cache-Control"] = "no-store"
    if request.headers.get("X-Session-Mode", "").lower() == "cookie":
        set_session_cookie(response, request, token)
        return LoginResponse(token_type="cookie", csrf_token=csrf_token_for(token), user=UserRead.model_validate(user))
    return LoginResponse(access_token=token, user=UserRead.model_validate(user))


@router.get("/session", response_model=LoginResponse)
async def current_session(
    response: Response,
    token: str = Depends(request_token),
    current_user: UserORM = Depends(get_current_user),
):
    """Restore a browser session after a reload: the user and the session's CSRF token."""
    response.headers["Cache-Control"] = "no-store"
    return LoginResponse(
        token_type="cookie", csrf_token=csrf_token_for(token), user=UserRead.model_validate(current_user)
    )


@router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    token: str = Depends(request_token),
    current_user: UserORM = Depends(get_current_user),
    session: AsyncSession = Depends(get_postgres_session, scope="function"),
):
    """Revoke the presented token until expiration and drop the cookie; Redis errors fail closed."""
    payload = decode_access_token(token)
    redis = await get_redis()
    ttl = max(1, payload.exp - int(datetime.now(UTC).timestamp()))
    await redis.set(f"revoked:{payload.jti}", "1", ex=ttl)
    await log_audit(
        session,
        current_user.user_id,
        current_user.username,
        "logout",
        ip_address=request.client.host if request.client else None,
    )
    clear_session_cookie(response, request)
    return {"message": "logged out"}


@router.get("/me", response_model=UserRead)
async def get_me(current_user: UserORM = Depends(get_current_user)):
    """Return the current authenticated user's profile."""
    return UserRead.model_validate(current_user)


# ── Admin user management ────────────────────────────────────────
users_router = APIRouter(prefix="/api/v1/settings/users", tags=["users"])


# Also served without the trailing slash: a redirect breaks behind TLS-terminating proxies.
@users_router.get("", response_model=list[UserRead], include_in_schema=False)
@users_router.get("/", response_model=list[UserRead])
async def list_users(
    _admin: UserORM = Depends(require_role("admin")),
    session: AsyncSession = Depends(get_postgres_session, scope="function"),
):
    result = await session.execute(select(UserORM).where(UserORM.scim_deleted.is_(False)).order_by(UserORM.username))
    users = list(result.scalars().all())
    roles = await effective_roles(session, users)
    return [UserRead.model_validate(user).model_copy(update={"role": roles[user.user_id]}) for user in users]


# Also served without the trailing slash: a redirect breaks behind TLS-terminating proxies.
@users_router.post("", response_model=UserRead, status_code=201, include_in_schema=False)
@users_router.post("/", response_model=UserRead, status_code=201)
async def create_user(
    body: UserCreate,
    request: Request,
    admin: UserORM = Depends(require_role("admin")),
    session: AsyncSession = Depends(get_postgres_session, scope="function"),
):
    user = UserORM(
        username=body.username,
        email=body.email,
        password_hash=hash_password(body.password),
        role=body.role,
    )
    session.add(user)
    try:
        await session.flush()
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(status_code=409, detail="Username already exists") from exc

    await log_audit(
        session,
        admin.user_id,
        admin.username,
        "create_user",
        resource_type="user",
        resource_id=str(user.user_id),
        ip_address=request.client.host if request.client else None,
    )

    return UserRead.model_validate(user)


@users_router.put("/{user_id}", response_model=UserRead)
async def update_user(
    user_id: UUID,
    body: UserUpdate,
    request: Request,
    admin: UserORM = Depends(require_role("admin")),
    session: AsyncSession = Depends(get_postgres_session, scope="function"),
):
    result = await session.execute(select(UserORM).where(UserORM.user_id == user_id).with_for_update())
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.identity_kind != "local":
        raise HTTPException(status_code=403, detail="External accounts are managed through SCIM")
    if body.is_active is not None and body.is_active != user.is_active:
        user.session_version += 1
    if body.email is not None:
        user.email = body.email
    if body.role is not None:
        user.role = body.role
    if body.is_active is not None:
        user.is_active = body.is_active

    await log_audit(
        session,
        admin.user_id,
        admin.username,
        "update_user",
        resource_type="user",
        resource_id=str(user.user_id),
        details=body.model_dump(exclude_none=True),
        ip_address=request.client.host if request.client else None,
    )

    return UserRead.model_validate(user)
