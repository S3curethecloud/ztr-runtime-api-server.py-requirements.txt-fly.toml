from __future__ import annotations

from typing import Any, Mapping, Sequence

from core.aegis_identity.features import build_identity_features
from core.aegis_identity.scoring import score_identity_features
from core.aegis_identity.schemas import (
    AegisIdentityAssessmentRequest,
    AegisIdentityAssessmentResponse,
)


class AegisIdentityService:
    """Local Aegis Identity signal assessment service.

    This service has no runtime side effects. It does not register routes, issue
    tokens, create sessions, mutate trust registries, or grant authorization.
    """

    def assess(
        self,
        request: AegisIdentityAssessmentRequest,
    ) -> AegisIdentityAssessmentResponse:
        features = build_identity_features(request)
        score = score_identity_features(features)

        return AegisIdentityAssessmentResponse(
            tenant_id=request.tenant_id,
            principal=request.principal,
            intent=request.intent,
            features=features,
            score=score,
        )


def assess_identity(
    request: AegisIdentityAssessmentRequest,
) -> AegisIdentityAssessmentResponse:
    """Assess Aegis Identity evidence with the default local service."""

    return AegisIdentityService().assess(request)


def evaluate_identity_integrity(
    *,
    redis_client: Any,
    tenant_id: str,
    principal: str,
    intent: str,
    scopes: Sequence[str],
    context: Mapping[str, Any] | None = None,
    recent_denials: int = 0,
    policy_drift: bool = False,
) -> dict:
    """Return a bounded Aegis Identity signal for runtime policy input.

    This function is intentionally signal-only. It does not authorize, deny,
    issue tokens, create sessions, mutate runtime truth, or override OPA.
    """

    request = AegisIdentityAssessmentRequest(
        tenant_id=tenant_id,
        principal=principal,
        intent=intent,
        scopes=list(scopes or []),
        context=dict(context or {}),
        recent_denials=int(recent_denials or 0),
        policy_drift=bool(policy_drift),
    )

    assessment = assess_identity(request)

    return {
        "signal": assessment.score.signal,
        "confidence": assessment.score.confidence,
        "risk_modifier": assessment.score.risk_modifier,
        "reasons": assessment.score.reasons,
        "decision_authority": "OPA",
        "model": "aegis-identity-v0.1",
    }
