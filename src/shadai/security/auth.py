"""Authentication: bcrypt password hashing and JWT token management."""

from __future__ import annotations

import base64
import hashlib
import hmac
import uuid
from datetime import UTC, datetime, timedelta

import bcrypt
import jwt
from fastapi import Depends, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordBearer
from jwt import InvalidTokenError
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import set_committed_value

from shadai.config import get_config
from shadai.database import get_postgres_session, get_redis
from shadai.models.user import TokenPayload, UserORM

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)
ROLE_RANKS = {"viewer": 0, "analyst": 1, "admin": 2}

# Browser sessions: the JWT lives in an HttpOnly SameSite=Strict cookie that scripts cannot
# read. Cookie-authenticated writes must echo a CSRF token derived from that session.
SESSION_COOKIE = "shadai-session"
CSRF_HEADER = "X-CSRF-Token"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "[::1]"})


def session_cookie_secure(request: Request) -> bool:
    configured = get_config().server.session_cookie_secure
    if configured is not None:
        return configured
    host = (request.url.hostname or "").lower()
    return host not in LOOPBACK_HOSTS and not host.endswith(".localhost")


def session_cookie_name(secure: bool) -> str:
    # __Host- cookies are Secure, Path=/ and host-only: a sibling subdomain cannot plant one.
    return ("__Host-" if secure else "") + SESSION_COOKIE


def csrf_token_for(token: str) -> str:
    digest = hmac.new(get_config().security.jwt_secret.encode(), b"csrf:" + token.encode(), hashlib.sha256)
    return base64.urlsafe_b64encode(digest.digest()).rstrip(b"=").decode()


def set_session_cookie(response: Response, request: Request, token: str) -> None:
    secure = session_cookie_secure(request)
    response.set_cookie(
        session_cookie_name(secure),
        token,
        max_age=get_config().security.jwt_expiration_hours * 3600,
        path="/",
        secure=secure,
        httponly=True,
        samesite="strict",
    )


def clear_session_cookie(response: Response, request: Request) -> None:
    secure = session_cookie_secure(request)
    response.delete_cookie(session_cookie_name(secure), path="/", secure=secure, httponly=True, samesite="strict")


async def request_token(request: Request, bearer: str | None = Depends(oauth2_scheme)) -> str:
    """Bearer for API clients; otherwise the session cookie, with CSRF proof for unsafe methods."""
    if bearer:
        return bearer
    token = request.cookies.get(session_cookie_name(session_cookie_secure(request)))
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if request.method not in SAFE_METHODS:
        supplied = request.headers.get(CSRF_HEADER, "")
        if not hmac.compare_digest(supplied.encode(), csrf_token_for(token).encode()):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Missing or invalid CSRF token")
    return token


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
    token: str = Depends(request_token),
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
