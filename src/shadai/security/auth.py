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

from shadai.config import get_config
from shadai.database import get_postgres_session, get_redis
from shadai.models.user import TokenPayload, UserORM

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


def hash_password(plain: str) -> str:
    """Hash a plaintext password with bcrypt."""
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a plaintext password against a bcrypt hash."""
    try:
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    except ValueError:
        return False


def create_access_token(user_id: str, role: str) -> str:
    """Create a signed JWT access token."""
    config = get_config()
    expire = datetime.now(UTC) + timedelta(hours=config.security.jwt_expiration_hours)
    payload = {
        "sub": user_id,
        "jti": str(uuid.uuid4()),
        "tenant_id": config.tenant_id,
        "role": role,
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
    session: AsyncSession = Depends(get_postgres_session),
) -> UserORM:
    """FastAPI dependency: extract and validate current user from JWT."""
    payload = decode_access_token(token)
    redis = await get_redis()
    if await redis.exists(f"revoked:{payload.jti}"):
        raise HTTPException(status_code=401, detail="Token revoked")

    result = await session.execute(select(UserORM).where(UserORM.user_id == payload.sub))
    user = result.scalar_one_or_none()

    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    return user
