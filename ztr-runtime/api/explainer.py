# FILE: api/explainer.py
# Deterministic DDR Explainer (Phase 1)
# Zero-Trust Runtime — SecureTheCloud

from typing import Any, Dict, List


def explain(ddr: Dict[str, Any]) -> Dict[str, Any]:
    """
    Deterministic decision explainer.

    Rules:
    - NEVER recompute decision
    - ONLY explain final_decision
    - FAIL CLOSED if invalid input
    """

    decision = ddr.get("final_decision")

    if not isinstance(decision, str):
        return build_invalid(ddr, "missing_final_decision")

    decision = decision.upper()

    if decision == "ALLOW":
        return build_allow(ddr)

    if decision == "DENY":
        return build_denial(ddr)

    return build_invalid(ddr, f"unsupported_final_decision:{decision}")


# ---------------------------------------------------------
# ALLOW
# ---------------------------------------------------------
def build_allow(ddr: Dict[str, Any]) -> Dict[str, Any]:
    principal = _str(ddr.get("principal"), "unknown")
    intent = _str(ddr.get("intent"), "unknown")
    obligations = _list(ddr.get("obligations"))
    risk_score = _num(ddr.get("risk_score"))
    policy_revision = _str(ddr.get("policy_revision"), "unknown")

    explanation_parts: List[str] = []

    explanation_parts.append(
        f"Decision ALLOW for {principal} performing {intent}."
    )

    if risk_score is not None:
        explanation_parts.append(f"Risk score evaluated at {risk_score}.")

    if obligations:
        explanation_parts.append(
            f"Policy obligations satisfied: {', '.join(obligations)}."
        )
    else:
        explanation_parts.append("No policy obligations required.")

    return {
        "decision": "ALLOW",
        "summary": f"{principal} is allowed to perform {intent}.",
        "explanation": " ".join(explanation_parts),
        "risk": {
            "score": risk_score,
            "tier": _risk_tier(risk_score)
        },
        "policy_basis": {
            "obligations": obligations,
            "policy_revision": policy_revision
        },
        "operator_action": "No immediate action required.",
        "metadata": _metadata(ddr)
    }


# ---------------------------------------------------------
# DENY
# ---------------------------------------------------------
def build_denial(ddr: Dict[str, Any]) -> Dict[str, Any]:
    principal = _str(ddr.get("principal"), "unknown")
    intent = _str(ddr.get("intent"), "unknown")
    obligations = _list(ddr.get("obligations"))
    risk_score = _num(ddr.get("risk_score"))
    policy_revision = _str(ddr.get("policy_revision"), "unknown")

    explanation_parts: List[str] = []

    explanation_parts.append(
        f"Decision DENY for {principal} attempting {intent}."
    )

    if risk_score is not None:
        explanation_parts.append(f"Risk score evaluated at {risk_score}.")

    if obligations:
        explanation_parts.append(
            f"Policy constraints not satisfied: {', '.join(obligations)}."
        )
    else:
        explanation_parts.append("No explicit policy obligations provided.")

    return {
        "decision": "DENY",
        "summary": f"{principal} is denied for {intent}.",
        "explanation": " ".join(explanation_parts),
        "risk": {
            "score": risk_score,
            "tier": _risk_tier(risk_score)
        },
        "policy_basis": {
            "obligations": obligations,
            "policy_revision": policy_revision
        },
        "operator_action": "Review policy conditions and risk signals.",
        "metadata": _metadata(ddr)
    }


# ---------------------------------------------------------
# INVALID
# ---------------------------------------------------------
def build_invalid(ddr: Dict[str, Any], reason: str) -> Dict[str, Any]:
    return {
        "decision": "INVALID",
        "summary": "Decision cannot be explained.",
        "explanation": f"Invalid DDR payload: {reason}.",
        "risk": {
            "score": _num(ddr.get("risk_score")),
            "tier": "UNKNOWN"
        },
        "policy_basis": {
            "obligations": _list(ddr.get("obligations")),
            "policy_revision": _str(ddr.get("policy_revision"), "unknown")
        },
        "operator_action": "Validate upstream decision pipeline.",
        "metadata": _metadata(ddr)
    }


# ---------------------------------------------------------
# HELPERS
# ---------------------------------------------------------
def _metadata(ddr: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "tenant_id": _str(ddr.get("tenant_id"), "unknown"),
        "session_id": _str(ddr.get("session_id"), "unknown"),
        "principal": _str(ddr.get("principal"), "unknown"),
        "intent": _str(ddr.get("intent"), "unknown"),
        "policy_revision": _str(ddr.get("policy_revision"), "unknown"),
        "timestamp": ddr.get("timestamp")
    }


def _str(value: Any, default: str = "") -> str:
    return value if isinstance(value, str) and value else default


def _list(value: Any) -> List[str]:
    if not isinstance(value, list):
        return []
    return [v for v in value if isinstance(v, str)]


def _num(value: Any):
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value
    return None


def _risk_tier(score: Any) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"
