"""Authentication: bcrypt password hashing and JWT token management."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import bcrypt
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jwt import InvalidTokenError
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import set_committed_value

from shadai.config import get_config
from shadai.database import get_postgres_session, get_redis
from shadai.models.user import TokenPayload, UserORM

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")
ROLE_RANKS = {"viewer": 0, "analyst": 1, "admin": 2}


def hash_password(plain: str) -> str:
    """Hash a plaintext password with bcrypt."""
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a plaintext password against a bcrypt hash."""
    try:
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    except ValueError:
        return False


def create_access_token(user_id: str, role: str, session_version: int = 0) -> str:
    """Create a signed JWT access token."""
    config = get_config()
    expire = datetime.now(UTC) + timedelta(hours=config.security.jwt_expiration_hours)
    payload = {
        "sub": user_id,
        "jti": str(uuid.uuid4()),
        "tenant_id": config.tenant_id,
        "role": role,
        "session_version": session_version,
        "exp": int(expire.timestamp()),
        "iat": int(datetime.now(UTC).timestamp()),
    }
    return jwt.encode(payload, config.security.jwt_secret, algorithm=config.security.jwt_algorithm)


def decode_access_token(token: str) -> TokenPayload:
    """Decode and validate a JWT token."""
    config = get_config()
    try:
        payload = jwt.decode(
            token,
            config.security.jwt_secret,
            algorithms=["HS256"],
            options={"require": ["sub", "exp", "iat", "jti", "tenant_id"]},
        )
        parsed = TokenPayload(**payload)
        if parsed.tenant_id != config.tenant_id:
            raise ValueError("Wrong organization")
        return parsed
    except (InvalidTokenError, ValidationError, ValueError) as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from e


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    session: AsyncSession = Depends(get_postgres_session, scope="function"),
) -> UserORM:
    """FastAPI dependency: extract and validate current user from JWT."""
    payload = decode_access_token(token)
    redis = await get_redis()
    if await redis.exists(f"revoked:{payload.jti}"):
        raise HTTPException(status_code=401, detail="Token revoked")

    result = await session.execute(select(UserORM).where(UserORM.user_id == payload.sub))
    user = result.scalar_one_or_none()

    if (
        user is None
        or not user.is_active
        or user.scim_deleted
        or payload.session_version != user.session_version
        or (user.identity_kind == "scim" and user.oidc_issuer != get_config().oidc.issuer)
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    set_committed_value(user, "role", await effective_role(session, user))
    return user


async def effective_roles(session: AsyncSession, users: list[UserORM]) -> dict[uuid.UUID, str]:
    """Batch-resolve group grants under the current operator-controlled map."""
    from shadai.models.identity import GroupORM, MembershipORM

    roles = {user.user_id: user.role if user.identity_kind == "local" else "viewer" for user in users}
    external_ids = [
        user.user_id
        for user in users
        if user.identity_kind == "scim" and user.oidc_issuer == get_config().oidc.issuer and not user.scim_deleted
    ]
    role_map = get_config().scim.group_role_map
    for offset in range(0, len(external_ids), 1000):
        rows = await session.execute(
            select(MembershipORM.user_id, GroupORM.external_id)
            .join(GroupORM, GroupORM.group_id == MembershipORM.group_id)
            .where(MembershipORM.user_id.in_(external_ids[offset : offset + 1000]), GroupORM.deleted.is_(False))
        )
        for user_id, group_id in rows:
            candidate = role_map.get(group_id, "viewer")
            if ROLE_RANKS[candidate] > ROLE_RANKS[roles[user_id]]:
                roles[user_id] = candidate
    return roles


async def effective_role(session: AsyncSession, user: UserORM) -> str:
    """Resolve external roles from current configuration, never a stale stored grant."""
    return (await effective_roles(session, [user]))[user.user_id]
