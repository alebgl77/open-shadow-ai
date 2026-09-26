"""Authentication API routes."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from shadai.database import get_postgres_session, get_redis
from shadai.models.user import LoginRequest, LoginResponse, UserCreate, UserORM, UserRead, UserUpdate
from shadai.security.audit import log_audit
from shadai.security.auth import (
    create_access_token,
    decode_access_token,
    get_current_user,
    hash_password,
    oauth2_scheme,
    verify_password,
)
from shadai.security.rbac import require_role

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@router.post("/login", response_model=LoginResponse)
async def login(
    body: LoginRequest,
    request: Request,
    session: AsyncSession = Depends(get_postgres_session),
):
    """Authenticate and return a JWT access token."""
    redis = await get_redis()
    peer = request.client.host if request.client else "unknown"
    bucket = int(datetime.now(UTC).timestamp()) // 60
    key = f"login-limit:{hashlib.sha256(peer.encode()).hexdigest()}:{bucket}"
    count = await redis.incr(key)
    if count == 1:
        await redis.expire(key, 120)
    if count > 20:
        raise HTTPException(status_code=429, detail="Too many login attempts", headers={"Retry-After": "60"})
    result = await session.execute(select(UserORM).where(UserORM.username == body.username))
    user = result.scalar_one_or_none()

    if user is None or not verify_password(body.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated",
        )

    token = create_access_token(str(user.user_id), user.role)
    user.last_login_at = datetime.now(UTC)

    await log_audit(
        session,
        user.user_id,
        user.username,
        "login",
        ip_address=request.client.host if request.client else None,
    )

    return LoginResponse(
        access_token=token,
        user=UserRead.model_validate(user),
    )


@router.post("/logout")
async def logout(
    request: Request,
    current_user: UserORM = Depends(get_current_user),
    session: AsyncSession = Depends(get_postgres_session),
):
    """Revoke the presented token until expiration; Redis errors fail closed."""
    token = await oauth2_scheme(request)
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
    return {"message": "logged out"}


@router.get("/me", response_model=UserRead)
async def get_me(current_user: UserORM = Depends(get_current_user)):
    """Return the current authenticated user's profile."""
    return UserRead.model_validate(current_user)


# ── Admin user management ────────────────────────────────────────
users_router = APIRouter(prefix="/api/v1/settings/users", tags=["users"])


@users_router.get("/", response_model=list[UserRead])
async def list_users(
    _admin: UserORM = Depends(require_role("admin")),
    session: AsyncSession = Depends(get_postgres_session),
):
    result = await session.execute(select(UserORM).order_by(UserORM.username))
    return [UserRead.model_validate(u) for u in result.scalars().all()]


@users_router.post("/", response_model=UserRead, status_code=201)
async def create_user(
    body: UserCreate,
    request: Request,
    admin: UserORM = Depends(require_role("admin")),
    session: AsyncSession = Depends(get_postgres_session),
):
    user = UserORM(
        username=body.username,
        email=body.email,
        password_hash=hash_password(body.password),
        role=body.role,
    )
    session.add(user)
    await session.flush()

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
    user_id: str,
    body: UserUpdate,
    request: Request,
    admin: UserORM = Depends(require_role("admin")),
    session: AsyncSession = Depends(get_postgres_session),
):
    result = await session.execute(select(UserORM).where(UserORM.user_id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

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
