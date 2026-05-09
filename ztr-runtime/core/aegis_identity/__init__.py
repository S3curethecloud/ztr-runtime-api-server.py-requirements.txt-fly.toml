"""Aegis Identity signal contract package.

This package defines identity-signal schemas, feature extraction, scoring, and a
local service facade. It has no runtime wiring, no route registration, no token
issuance, and no session creation side effects.
"""

from core.aegis_identity.features import build_identity_features
from core.aegis_identity.scoring import score_identity_features
from core.aegis_identity.service import (
    AegisIdentityService,
    assess_identity,
    evaluate_identity_integrity,
)
from core.aegis_identity.schemas import (
    AEGIS_IDENTITY_SIGNAL_VERSION,
    AegisIdentityAssessmentRequest,
    AegisIdentityAssessmentResponse,
    AegisIdentityFeatureVector,
    AegisIdentityScore,
    AegisIdentitySignal,
)

__all__ = [
    "AEGIS_IDENTITY_SIGNAL_VERSION",
    "AegisIdentityAssessmentRequest",
    "AegisIdentityAssessmentResponse",
    "AegisIdentityFeatureVector",
    "AegisIdentityScore",
    "AegisIdentityService",
    "AegisIdentitySignal",
    "assess_identity",
    "build_identity_features",
    "evaluate_identity_integrity",
    "score_identity_features",
]
