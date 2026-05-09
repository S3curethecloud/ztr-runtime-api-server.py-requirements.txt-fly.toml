from __future__ import annotations

from typing import Any, Dict, Optional

from core.aegis_identity.schemas import (
    AegisIdentityAssessmentRequest,
    AegisIdentityFeatureVector,
    AegisIdentitySignal,
)


_NEGATIVE_VALUES = {
    "blocked",
    "deny",
    "denied",
    "failed",
    "invalid",
    "rejected",
    "revoked",
    "suspicious",
    "untrusted",
}

_POSITIVE_VALUES = {
    "accepted",
    "allow",
    "allowed",
    "trusted",
    "valid",
    "verified",
}


def _coerce_risk_score(value: Any) -> Optional[int]:
    if value is None:
        return None

    try:
        score = int(str(value))
    except (TypeError, ValueError):
        return None

    if score < 0:
        return 0
    if score > 100:
        return 100

    return score


def _extract_risk_score(context: Dict[str, Any]) -> Optional[int]:
    direct_score = _coerce_risk_score(context.get("risk_score"))
    if direct_score is not None:
        return direct_score

    riskdna = context.get("riskdna")
    if isinstance(riskdna, dict):
        riskdna_score = _coerce_risk_score(riskdna.get("risk_score"))
        if riskdna_score is not None:
            return riskdna_score

        return _coerce_risk_score(riskdna.get("final_score"))

    return None


def _signal_polarity(signal: AegisIdentitySignal) -> str:
    polarity = str(signal.metadata.get("polarity", "")).strip().lower()
    if polarity in {"positive", "negative", "neutral"}:
        return polarity

    value = str(signal.value).strip().lower()

    if value in _NEGATIVE_VALUES:
        return "negative"
    if value in _POSITIVE_VALUES:
        return "positive"

    return "neutral"


def build_identity_features(
    request: AegisIdentityAssessmentRequest,
) -> AegisIdentityFeatureVector:
    """Build a deterministic identity feature vector from signal evidence."""

    signal_count = len(request.signals)
    weighted_signal_total = sum(signal.weight for signal in request.signals)
    max_signal_weight = max((signal.weight for signal in request.signals), default=0)

    positive_signal_count = 0
    negative_signal_count = 0
    confidence_total = 0.0

    for signal in request.signals:
        confidence_total += signal.confidence

        polarity = _signal_polarity(signal)
        if polarity == "positive":
            positive_signal_count += 1
        elif polarity == "negative":
            negative_signal_count += 1

    confidence_average = confidence_total / signal_count if signal_count else 0.0

    return AegisIdentityFeatureVector(
        tenant_id=request.tenant_id,
        principal=request.principal,
        intent=request.intent,
        signal_count=signal_count,
        weighted_signal_total=weighted_signal_total,
        positive_signal_count=positive_signal_count,
        negative_signal_count=negative_signal_count,
        max_signal_weight=max_signal_weight,
        confidence_average=round(confidence_average, 4),
        risk_score=_extract_risk_score(request.context),
        recent_denials=request.recent_denials,
        policy_drift=request.policy_drift,
        context_keys=sorted(str(key) for key in request.context.keys()),
    )
