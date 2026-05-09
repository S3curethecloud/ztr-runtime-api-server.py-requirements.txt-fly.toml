from __future__ import annotations

from typing import List

from core.aegis_identity.schemas import (
    AegisIdentityFeatureVector,
    AegisIdentityScore,
    AegisIdentityTier,
)


def _clamp_score(value: int) -> int:
    if value < 0:
        return 0
    if value > 100:
        return 100
    return value


def _tier_for_score(score: int) -> AegisIdentityTier:
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


def _signal_for_score(score: int, signal_count: int) -> str:
    if signal_count == 0 and score == 0:
        return "INSUFFICIENT_DATA"

    if score >= 35:
        return "IDENTITY_DRIFT_DETECTED"

    return "IDENTITY_STABLE"


def _risk_modifier_for_score(score: int) -> int:
    if score >= 85:
        return 35
    if score >= 65:
        return 25
    if score >= 35:
        return 15
    return 0


def _confidence_for_features(features: AegisIdentityFeatureVector) -> float:
    if features.signal_count:
        return features.confidence_average

    if features.recent_denials > 0 or features.policy_drift or features.risk_score:
        return 0.85

    return 0.5


def score_identity_features(features: AegisIdentityFeatureVector) -> AegisIdentityScore:
    """Score identity evidence deterministically.

    This score is evidence only. It does not authorize access, create a session,
    issue a token, or bypass local OPA/runtime governance.
    """

    score = 0
    reasons: List[str] = []

    if features.risk_score is not None:
        risk_contribution = min(features.risk_score // 2, 40)
        score += risk_contribution
        reasons.append(f"risk_score:{features.risk_score}")

    if features.recent_denials:
        denial_penalty = min(features.recent_denials * 10, 30)
        score += denial_penalty
        reasons.append(f"recent_denials:{features.recent_denials}")

    if features.policy_drift:
        score += 20
        reasons.append("policy_drift:true")

    if features.negative_signal_count:
        penalty = min(features.negative_signal_count * 15, 45)
        score += penalty
        reasons.append(f"negative_signals:{features.negative_signal_count}")

    if features.positive_signal_count:
        reduction = min(features.positive_signal_count * 5, 20)
        score -= reduction
        reasons.append(f"positive_signals:{features.positive_signal_count}")

    if features.max_signal_weight >= 50:
        score += 10
        reasons.append(f"high_weight_signal:{features.max_signal_weight}")

    if features.confidence_average < 0.5 and features.signal_count:
        score += 10
        reasons.append(f"low_confidence_average:{features.confidence_average}")

    normalized_score = _clamp_score(score)

    return AegisIdentityScore(
        score=normalized_score,
        tier=_tier_for_score(normalized_score),
        signal=_signal_for_score(normalized_score, features.signal_count),
        confidence=round(_confidence_for_features(features), 4),
        risk_modifier=_risk_modifier_for_score(normalized_score),
        reasons=reasons or ["no_risk_evidence"],
        evidence={
            "signal_count": features.signal_count,
            "weighted_signal_total": features.weighted_signal_total,
            "positive_signal_count": features.positive_signal_count,
            "negative_signal_count": features.negative_signal_count,
            "confidence_average": features.confidence_average,
            "risk_score": features.risk_score,
            "recent_denials": features.recent_denials,
            "policy_drift": features.policy_drift,
        },
    )
