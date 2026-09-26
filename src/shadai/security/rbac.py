"""Role-Based Access Control middleware for FastAPI."""

from __future__ import annotations

from collections.abc import Callable

from fastapi import Depends, HTTPException, status

from shadai.models.user import UserORM
from shadai.security.auth import get_current_user

ROLE_HIERARCHY: dict[str, int] = {
    "viewer": 1,
    "analyst": 2,
    "admin": 3,
}


def require_role(minimum_role: str) -> Callable:
    """FastAPI dependency factory that enforces minimum role level.

    Usage:
        @router.get("/admin-only", dependencies=[Depends(require_role("admin"))])
        async def admin_endpoint(): ...
    """
    min_level = ROLE_HIERARCHY.get(minimum_role, 0)

    async def _check_role(current_user: UserORM = Depends(get_current_user)) -> UserORM:
        user_level = ROLE_HIERARCHY.get(current_user.role, 0)
        if user_level < min_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires {minimum_role} role or higher",
            )
        return current_user

    return _check_role
