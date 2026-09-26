"""Policy application without inventing evidence or altering confidence."""

from datetime import UTC

from shadai.engine.scorer import generate_reasoning_summary

CLASSIFICATION_FACTORS = {"sanctioned", "tolerated", "unsanctioned"}
CLASSIFICATION_ADJUSTMENTS = {
    "sanctioned": (-40, "Tool is sanctioned by organization"),
    "tolerated": (-20, "Tool is tolerated by organization"),
    "unsanctioned": (20, "Tool is explicitly unsanctioned"),
}


def rescore_classification(detection):
    """Rebuild only policy factors; preserve the original, unclamped evidence sum.

    Legacy rows without a complete persisted factor list cannot be reconstructed
    safely. Keep their score and explicitly mark it stale instead of guessing.
    """
    bundle = dict(detection.evidence_bundle or {})
    factors = bundle.get("risk_factors")
    complete = isinstance(factors, list) and any(
        isinstance(factor, dict) and factor.get("factor") == "base_shadow_ai" for factor in factors
    )
    if not complete or any(
        not isinstance(factor, dict)
        or not isinstance(factor.get("value"), int)
        or isinstance(factor.get("value"), bool)
        or not isinstance(factor.get("description"), str)
        for factor in factors or []
    ):
        bundle["_risk_score_stale"] = True
        detection.evidence_bundle = bundle
        return
    # A nonempty legacy list may still be truncated. Its original bounded sum
    # must explain the stored score before we can safely remove policy factors.
    if detection.risk_score != max(0, min(100, sum(factor["value"] for factor in factors))):
        bundle["_risk_score_stale"] = True
        detection.evidence_bundle = bundle
        return
    updated = [dict(factor) for factor in factors if factor.get("factor") not in CLASSIFICATION_FACTORS]
    adjustment = CLASSIFICATION_ADJUSTMENTS.get(detection.classification)
    if adjustment:
        updated.append({"factor": detection.classification, "value": adjustment[0], "description": adjustment[1]})
    detection.risk_score = max(0, min(100, sum(factor["value"] for factor in updated)))
    bundle["risk_factors"] = updated
    bundle["_risk_score_stale"] = False
    detection.evidence_bundle = bundle
    detection.reasoning_summary = generate_reasoning_summary(
        detection.confidence_score,
        bundle.get("confidence_factors", []),
        detection.risk_score,
        updated,
    )


def apply_policy(detection, policy):
    """The latest policy wins; expiration removes approval rather than reviving older policy."""
    detection.classification = policy.org_classification if policy.approval_status == "active" else "unknown"
    detection.governance_id = policy.governance_id
    bundle = dict(detection.evidence_bundle or {})
    expiry = policy.approved_until
    if expiry is not None and expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=UTC)
    bundle["_governance"] = {
        "approved_until": expiry.isoformat() if expiry else None,
        "applied_status": policy.approval_status,
    }
    detection.evidence_bundle = bundle
    rescore_classification(detection)
