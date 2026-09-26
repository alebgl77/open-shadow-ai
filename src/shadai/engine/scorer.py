"""Confidence and risk scoring — deterministic, explainable, no ML."""

from __future__ import annotations

from pydantic import BaseModel


class Signal(BaseModel):
    """A single detection signal from one source."""

    source_type: str
    confidence_base: float
    event_count: int = 1
    match_field: str = ""


def compute_confidence(signals: list[Signal]) -> tuple[float, list[dict]]:
    """Compute confidence score (0.0–1.0) with explainable factors.

    Formula from PRD section 4.8:
      confidence = min(1.0, max(signal_scores) + 0.10 * (n_distinct_sources - 1) + volume_bonus + penalty)
    """
    if not signals:
        return 0.0, []

    factors: list[dict] = []

    # Base: strongest signal
    best_signal = max(signals, key=lambda s: s.confidence_base)
    base = best_signal.confidence_base
    factors.append(
        {
            "factor": "base_signal",
            "value": round(base, 2),
            "description": f"Strongest signal: {best_signal.source_type} ({best_signal.match_field})",
        }
    )

    # Multi-source bonus: +0.10 per additional distinct source
    distinct_sources = len({s.source_type for s in signals})
    multi_source_bonus = 0.10 * (distinct_sources - 1)
    if multi_source_bonus > 0:
        factors.append(
            {
                "factor": "multi_source",
                "value": round(multi_source_bonus, 2),
                "description": f"{distinct_sources} distinct sources corroborate",
            }
        )

    # Volume bonus: +0.05 if >100 total events
    total_events = sum(s.event_count for s in signals)
    volume_bonus = 0.05 if total_events > 100 else 0.0
    if volume_bonus > 0:
        factors.append(
            {
                "factor": "high_volume",
                "value": volume_bonus,
                "description": f"{total_events} total events (>100)",
            }
        )

    # Penalty: single weak signal
    penalty = 0.0
    if len(signals) == 1 and signals[0].confidence_base < 0.5:
        penalty = -0.10
        factors.append(
            {
                "factor": "weak_single_signal",
                "value": penalty,
                "description": "Single weak signal penalty",
            }
        )

    confidence = max(0.0, min(1.0, base + multi_source_bonus + volume_bonus + penalty))
    return round(confidence, 2), factors


# Sensitive OAuth scopes that trigger risk escalation
SENSITIVE_OAUTH_SCOPES = {
    "mail.read",
    "mail.readwrite",
    "mail.send",
    "files.read.all",
    "files.readwrite.all",
    "sites.read.all",
    "sites.readwrite.all",
    "user.read.all",
    "directory.read.all",
    "calendars.read",
    "contacts.read",
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/drive",
    "https://www.googleapis.com/auth/calendar.readonly",
}


def has_sensitive_scopes(scopes: list[str]) -> bool:
    """Check if OAuth scopes contain sensitive permissions."""
    return any(s.lower() in SENSITIVE_OAUTH_SCOPES for s in scopes)


def has_readonly_scopes_only(scopes: list[str]) -> bool:
    """Check if all OAuth scopes are read-only."""
    if not scopes:
        return False
    return all("read" in s.lower() and "write" not in s.lower() for s in scopes)


def compute_risk(
    entity_type: str,
    impacted_users_count: int,
    total_events_count: int,
    total_bytes_out: int = 0,
    classification: str = "unknown",
    oauth_scopes: list[str] | None = None,
    has_full_dom_access: bool = False,
    is_unverified_publisher: bool = False,
    governance_classification: str | None = None,
) -> tuple[int, list[dict]]:
    """Compute risk score (0–100) with explainable factors.

    Formula from PRD section 4.8, with all factors wired.
    """
    score = 30  # Base: all unclassified shadow AI starts at 30
    factors: list[dict] = [
        {
            "factor": "base_shadow_ai",
            "value": 30,
            "description": "Base score for unclassified shadow AI",
        }
    ]

    # Hausse factors
    _scopes = oauth_scopes or []
    if has_sensitive_scopes(_scopes):
        score += 30
        factors.append(
            {
                "factor": "oauth_sensitive_scopes",
                "value": 30,
                "description": "Sensitive OAuth scopes (Mail.Read, Files.ReadWrite, etc.)",
            }
        )

    if total_bytes_out > 10_000_000:
        score += 15
        factors.append(
            {"factor": "high_data_volume", "value": 15, "description": f">{total_bytes_out // 1_000_000}MB data sent"}
        )

    if classification == "unsanctioned":
        score += 20
        factors.append({"factor": "unsanctioned", "value": 20, "description": "Tool is explicitly unsanctioned"})

    if impacted_users_count > 10:
        score += 10
        factors.append({"factor": "many_users", "value": 10, "description": f"{impacted_users_count} impacted users"})

    if entity_type == "browser_extension" and has_full_dom_access:
        score += 20
        factors.append({"factor": "extension_full_dom", "value": 20, "description": "Extension with full DOM access"})

    if entity_type == "oauth_app" and is_unverified_publisher:
        score += 15
        factors.append({"factor": "unverified_publisher", "value": 15, "description": "Unverified OAuth app publisher"})

    # Baisse factors
    gov_class = governance_classification or classification
    if gov_class == "sanctioned":
        score -= 40
        factors.append({"factor": "sanctioned", "value": -40, "description": "Tool is sanctioned by organization"})
    elif gov_class == "tolerated":
        score -= 20
        factors.append({"factor": "tolerated", "value": -20, "description": "Tool is tolerated by organization"})

    if has_readonly_scopes_only(_scopes):
        score -= 10
        factors.append({"factor": "readonly_scopes", "value": -10, "description": "Read-only OAuth scopes"})

    if total_events_count <= 3:
        score -= 10
        factors.append(
            {"factor": "minimal_usage", "value": -10, "description": f"Minimal usage ({total_events_count} events)"}
        )

    score = max(0, min(100, score))
    return score, factors


def generate_reasoning_summary(
    confidence: float,
    conf_factors: list[dict],
    risk: int,
    risk_factors: list[dict],
) -> str:
    """Generate human-readable scoring explanation."""
    conf_parts = [f"{f['description']} ({f['value']:+.2f})" for f in conf_factors]
    risk_parts = [f"{f['description']} ({f['value']:+d})" for f in risk_factors]

    conf_level = (
        "very high"
        if confidence >= 0.90
        else "high"
        if confidence >= 0.70
        else "medium"
        if confidence >= 0.40
        else "low"
    )
    risk_level = (
        "critical"
        if risk >= 86
        else "high"
        if risk >= 71
        else "medium"
        if risk >= 51
        else "low"
        if risk >= 26
        else "info"
    )

    return (
        f"Confidence {confidence:.2f} ({conf_level}): {'; '.join(conf_parts)}. "
        f"Risk {risk} ({risk_level}): {'; '.join(risk_parts)}."
    )
