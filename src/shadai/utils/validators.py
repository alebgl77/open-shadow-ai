"""Shared validation utilities."""

from __future__ import annotations

import re

VALID_ROLES = {"admin", "analyst", "viewer"}
VALID_CLASSIFICATIONS = {"sanctioned", "tolerated", "unsanctioned", "unknown"}
VALID_ANALYST_STATUSES = {"new", "investigating", "classified", "false_positive", "escalated"}
VALID_ENTITY_TYPES = {
    "saas_app",
    "api_service",
    "browser_extension",
    "oauth_app",
    "local_runtime",
    "local_container",
    "desktop_app",
}
VALID_RISK_LEVELS = {"info", "low", "medium", "high", "critical"}
VALID_CONFIDENCE_LEVELS = {"low", "medium", "high", "very_high"}

# Strip control characters from raw log input (keep printable + newlines)
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
MAX_LOG_LINE_LENGTH = 16384


def validate_role(role: str) -> str:
    if role not in VALID_ROLES:
        raise ValueError(f"Invalid role: {role}. Must be one of {VALID_ROLES}")
    return role


def validate_classification(cls: str) -> str:
    if cls not in VALID_CLASSIFICATIONS:
        raise ValueError(f"Invalid classification: {cls}. Must be one of {VALID_CLASSIFICATIONS}")
    return cls


def validate_analyst_status(status: str) -> str:
    if status not in VALID_ANALYST_STATUSES:
        raise ValueError(f"Invalid analyst status: {status}. Must be one of {VALID_ANALYST_STATUSES}")
    return status


def sanitize_log_input(raw: str) -> str:
    """Strip control characters and limit length for safe processing."""
    cleaned = _CONTROL_CHAR_RE.sub("", raw)
    return cleaned[:MAX_LOG_LINE_LENGTH]
