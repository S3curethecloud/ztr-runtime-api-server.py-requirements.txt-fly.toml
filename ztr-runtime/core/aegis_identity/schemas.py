from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, field_validator


AEGIS_IDENTITY_SIGNAL_VERSION = "aegis.identity.signals/v1alpha1"

AegisIdentitySignalType = Literal[
    "principal",
    "workload",
    "network",
    "behavior",
    "asz",
    "riskdna",
    "runtime",
    "custom",
]

AegisIdentityTier = Literal["low", "medium", "high", "critical"]

AegisIdentitySignalState = Literal[
    "IDENTITY_STABLE",
    "IDENTITY_DRIFT_DETECTED",
    "INSUFFICIENT_DATA",
]


class AegisIdentitySignal(BaseModel):
    """Single identity signal used as evidence for scoring.

    Signals are evidence only. They must not grant authorization, issue tokens,
    create runtime sessions, or override local policy authority.
    """

    signal_id: str = Field(..., min_length=1)
    signal_type: AegisIdentitySignalType
    name: str = Field(..., min_length=1)
    value: Any
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    weight: int = Field(default=1, ge=0, le=100)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("signal_id", "name")
    @classmethod
    def _strip_required_strings(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("must not be empty")
        return cleaned


class AegisIdentityAssessmentRequest(BaseModel):
    """Input contract for Aegis Identity scoring.

    This request describes local identity evidence only. It does not represent
    an authorization decision and must still be evaluated by the governing
    runtime and local policy layer before execution.
    """

    tenant_id: Optional[str] = None
    principal: str = Field(..., min_length=1)
    intent: Optional[str] = None
    scopes: List[str] = Field(default_factory=list)
    context: Dict[str, Any] = Field(default_factory=dict)
    signals: List[AegisIdentitySignal] = Field(default_factory=list)
    recent_denials: int = Field(default=0, ge=0)
    policy_drift: bool = False
    source: Literal["aegis_identity"] = "aegis_identity"

    @field_validator("principal")
    @classmethod
    def _strip_principal(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("must not be empty")
        return cleaned


class AegisIdentityFeatureVector(BaseModel):
    """Deterministic feature vector derived from identity evidence."""

    tenant_id: Optional[str] = None
    principal: str
    intent: Optional[str] = None
    signal_count: int = Field(ge=0)
    weighted_signal_total: int = Field(ge=0)
    positive_signal_count: int = Field(ge=0)
    negative_signal_count: int = Field(ge=0)
    max_signal_weight: int = Field(ge=0)
    confidence_average: float = Field(ge=0.0, le=1.0)
    risk_score: Optional[int] = Field(default=None, ge=0, le=100)
    recent_denials: int = Field(default=0, ge=0)
    policy_drift: bool = False
    context_keys: List[str] = Field(default_factory=list)


class AegisIdentityScore(BaseModel):
    """Risk score result for identity evidence.

    This score is advisory evidence only. It is not an authorization grant.
    """

    score: int = Field(ge=0, le=100)
    tier: AegisIdentityTier
    signal: AegisIdentitySignalState
    confidence: float = Field(default=0.95, ge=0.0, le=1.0)
    risk_modifier: int = Field(default=0, ge=0, le=100)
    reasons: List[str] = Field(default_factory=list)
    evidence: Dict[str, Any] = Field(default_factory=dict)


class AegisIdentityAssessmentResponse(BaseModel):
    """Complete Aegis Identity assessment response."""

    version: Literal["aegis.identity.signals/v1alpha1"] = AEGIS_IDENTITY_SIGNAL_VERSION
    tenant_id: Optional[str] = None
    principal: str
    intent: Optional[str] = None
    features: AegisIdentityFeatureVector
    score: AegisIdentityScore
    runtime_authorization_granted: Literal[False] = False
    token_issued: Literal[False] = False
    session_created: Literal[False] = False
