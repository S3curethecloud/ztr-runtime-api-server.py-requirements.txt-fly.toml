from __future__ import annotations

from core.aegis_identity.features import build_identity_features
from core.aegis_identity.scoring import score_identity_features
from core.aegis_identity.service import assess_identity, evaluate_identity_integrity
from core.aegis_identity.schemas import (
    AegisIdentityAssessmentRequest,
    AegisIdentitySignal,
)


def _policy_denies_identity_integrity(signal: dict) -> bool:
    """Mirror the bounded OPA deny_identity_integrity rule.

    This does not replace OPA. It validates that the runtime signal shape
    produced by Aegis Identity can satisfy the deployed issue.rego condition:

        signal == IDENTITY_DRIFT_DETECTED
        risk_modifier >= 20
    """

    return (
        signal.get("signal") == "IDENTITY_DRIFT_DETECTED"
        and int(signal.get("risk_modifier") or 0) >= 20
    )


def test_normal_identity_returns_stable_signal() -> None:
    request = AegisIdentityAssessmentRequest(
        tenant_id="tenant-beta",
        principal="agent-demo",
        intent="refund:create",
        scopes=["refund:create"],
        signals=[
            AegisIdentitySignal(
                signal_id="principal-known",
                signal_type="principal",
                name="principal_trust",
                value="verified",
                confidence=0.95,
                weight=10,
            )
        ],
        context={
            "device_trust": True,
            "session_binding": "device-aegis-test",
            "risk_score": 10,
            "after_hours": False,
        },
    )

    assessment = assess_identity(request)

    assert assessment.principal == "agent-demo"
    assert assessment.intent == "refund:create"
    assert assessment.score.signal == "IDENTITY_STABLE"
    assert assessment.score.risk_modifier == 0
    assert assessment.runtime_authorization_granted is False
    assert assessment.token_issued is False
    assert assessment.session_created is False


def test_negative_signals_increase_identity_score() -> None:
    request = AegisIdentityAssessmentRequest(
        tenant_id="tenant-beta",
        principal="agent-demo",
        intent="refund:create",
        scopes=["refund:create"],
        signals=[
            AegisIdentitySignal(
                signal_id="signature-rejected",
                signal_type="asz",
                name="cross_zone_signature",
                value="rejected",
                confidence=0.95,
                weight=20,
            ),
            AegisIdentitySignal(
                signal_id="runtime-suspicious",
                signal_type="behavior",
                name="behavioral_posture",
                value="suspicious",
                confidence=0.90,
                weight=20,
            ),
        ],
        context={
            "risk_score": 10,
        },
    )

    features = build_identity_features(request)
    score = score_identity_features(features)

    assert features.negative_signal_count == 2
    assert score.score >= 35
    assert score.signal == "IDENTITY_DRIFT_DETECTED"
    assert "negative_signals:2" in score.reasons


def test_policy_drift_adds_bounded_risk_evidence() -> None:
    request = AegisIdentityAssessmentRequest(
        tenant_id="tenant-beta",
        principal="agent-demo",
        intent="refund:create",
        scopes=["refund:create"],
        policy_drift=True,
        context={
            "risk_score": 10,
        },
    )

    assessment = assess_identity(request)

    assert assessment.features.policy_drift is True
    assert "policy_drift:true" in assessment.score.reasons
    assert assessment.score.score >= 20
    assert assessment.runtime_authorization_granted is False


def test_recent_denials_raise_identity_risk() -> None:
    request = AegisIdentityAssessmentRequest(
        tenant_id="tenant-beta",
        principal="agent-demo",
        intent="refund:create",
        scopes=["refund:create"],
        recent_denials=4,
        context={
            "risk_score": 10,
        },
    )

    assessment = assess_identity(request)

    assert assessment.features.recent_denials == 4
    assert "recent_denials:4" in assessment.score.reasons
    assert assessment.score.signal == "IDENTITY_DRIFT_DETECTED"
    assert assessment.score.risk_modifier >= 15


def test_high_modifier_signal_is_produced_for_elevated_identity_risk() -> None:
    signal = evaluate_identity_integrity(
        redis_client=None,
        tenant_id="tenant-beta",
        principal="agent-demo",
        intent="refund:create",
        scopes=["refund:create"],
        context={
            "risk_score": 80,
            "device_trust": True,
            "session_binding": "device-aegis-test",
        },
        recent_denials=3,
        policy_drift=False,
    )

    assert signal["signal"] == "IDENTITY_DRIFT_DETECTED"
    assert signal["risk_modifier"] >= 20
    assert signal["decision_authority"] == "OPA"
    assert "allow" not in signal
    assert "deny" not in signal
    assert "authorized" not in signal


def test_critical_tier_is_reached_for_correlated_identity_risk() -> None:
    request = AegisIdentityAssessmentRequest(
        tenant_id="tenant-beta",
        principal="agent-demo",
        intent="refund:create",
        scopes=["refund:create"],
        policy_drift=True,
        signals=[
            AegisIdentitySignal(
                signal_id="deny-1",
                signal_type="behavior",
                name="recent_behavior_1",
                value="denied",
                confidence=0.95,
                weight=50,
            ),
            AegisIdentitySignal(
                signal_id="deny-2",
                signal_type="runtime",
                name="recent_behavior_2",
                value="suspicious",
                confidence=0.95,
                weight=50,
            ),
            AegisIdentitySignal(
                signal_id="deny-3",
                signal_type="asz",
                name="cross_zone_evidence",
                value="rejected",
                confidence=0.95,
                weight=50,
            ),
        ],
        context={
            "risk_score": 100,
        },
    )

    assessment = assess_identity(request)

    assert assessment.score.tier == "critical"
    assert assessment.score.score == 100
    assert assessment.score.risk_modifier == 35
    assert assessment.score.signal == "IDENTITY_DRIFT_DETECTED"


def test_identity_drift_detection_threshold() -> None:
    request = AegisIdentityAssessmentRequest(
        tenant_id="tenant-beta",
        principal="agent-demo",
        intent="refund:create",
        scopes=["refund:create"],
        recent_denials=3,
        policy_drift=True,
        context={
            "risk_score": 20,
        },
    )

    assessment = assess_identity(request)

    assert assessment.score.score >= 35
    assert assessment.score.signal == "IDENTITY_DRIFT_DETECTED"


def test_identity_signal_matches_issue_policy_deny_shape() -> None:
    signal = evaluate_identity_integrity(
        redis_client=None,
        tenant_id="tenant-beta",
        principal="agent-demo",
        intent="refund:create",
        scopes=["refund:create"],
        context={
            "risk_score": 80,
            "device_trust": True,
            "session_binding": "device-aegis-test",
        },
        recent_denials=3,
        policy_drift=True,
    )

    assert signal["signal"] == "IDENTITY_DRIFT_DETECTED"
    assert signal["risk_modifier"] >= 20
    assert _policy_denies_identity_integrity(signal) is True


def test_opa_does_not_deny_stable_identity_signal() -> None:
    signal = evaluate_identity_integrity(
        redis_client=None,
        tenant_id="tenant-beta",
        principal="agent-demo",
        intent="refund:create",
        scopes=["refund:create"],
        context={
            "risk_score": 10,
            "device_trust": True,
            "session_binding": "device-aegis-test",
        },
        recent_denials=0,
        policy_drift=False,
    )

    assert signal["risk_modifier"] == 0
    assert _policy_denies_identity_integrity(signal) is False


def test_passrole_lab_maps_to_aegis_identity_drift_signal() -> None:
    signal = evaluate_identity_integrity(
        redis_client=None,
        tenant_id="tenant-beta",
        principal="passrole-lab-principal",
        intent="iam:PassRole",
        scopes=["iam:PassRole"],
        context={
            "risk_score": 80,
            "device_trust": True,
            "session_binding": "passrole-lab-session",
            "lab_id": "aws-privilege-escalation-passrole",
            "linked_shield_finding": "shield-passrole-001",
        },
        recent_denials=3,
        policy_drift=False,
    )

    assert signal["signal"] == "IDENTITY_DRIFT_DETECTED"
    assert signal["risk_modifier"] >= 20
    assert signal["decision_authority"] == "OPA"
    assert signal["model"] == "aegis-identity-v0.1"
    assert "risk_score:80" in signal["reasons"]
    assert "recent_denials:3" in signal["reasons"]

    # Aegis remains signal-only.
    assert "allow" not in signal
    assert "deny" not in signal
    assert "authorized" not in signal
    assert "token" not in signal
    assert "session" not in signal

