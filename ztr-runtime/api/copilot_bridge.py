from fastapi import APIRouter, Depends
from api.auth import require_tenant_api_key
from api.explainer import explain
import httpx

router = APIRouter(prefix="/v1/copilot", tags=["copilot"])

ENGINE_URL = "https://stc-intelligence-core.fly.dev"

def _normalize_decision_payload(payload: dict) -> dict:
    source = payload if isinstance(payload, dict) else {}

    nested = source.get("decision")
    if isinstance(nested, dict):
        merged = dict(nested)

        for key in [
            "risk_score",
            "principal",
            "intent",
            "obligations",
            "policy_revision",
            "timestamp",
            "tenant_id",
            "session_id",
            "risk",
            "final_decision",
        ]:
            if merged.get(key) is None and source.get(key) is not None:
                merged[key] = source.get(key)

        source = merged

    final_decision = source.get("final_decision")

    if not final_decision:
        raw_decision = source.get("decision")
        if isinstance(raw_decision, str):
            final_decision = raw_decision

    risk_score = source.get("risk_score")
    if risk_score is None:
        risk_obj = source.get("risk")
        if isinstance(risk_obj, dict):
            risk_score = risk_obj.get("final_score")

    return {
        "final_decision": final_decision,
        "risk_score": risk_score,
        "principal": source.get("principal"),
        "intent": source.get("intent"),
        "obligations": source.get("obligations", []),
        "policy_revision": source.get("policy_revision", "unknown"),
        "timestamp": source.get("timestamp"),
        "tenant_id": source.get("tenant_id"),
        "session_id": source.get("session_id"),
    }


def _normalize_explainer_response(result: dict) -> dict:
    risk = result.get("risk") if isinstance(result.get("risk"), dict) else {}
    policy_basis = result.get("policy_basis") if isinstance(result.get("policy_basis"), dict) else {}

    obligations = policy_basis.get("obligations", [])
    policy_revision = policy_basis.get("policy_revision", "unknown")

    if isinstance(obligations, list) and obligations:
        policy_basis_text = f"{policy_revision} | obligations: {', '.join(obligations)}"
    else:
        policy_basis_text = policy_revision

    return {
        "decision": result.get("decision", "INVALID"),
        "risk_level": risk.get("tier", "UNKNOWN"),
        "risk_score": risk.get("score", 0),
        "policy_basis": policy_basis_text,
        "impact": result.get("summary", "No impact summary returned."),
        "recommendation": result.get("operator_action", "No recommendation returned."),
        "explanation": result.get("explanation", "No explanation returned."),
        "metadata": result.get("metadata", {}),
    }


def _build_decision_explanation(payload: dict) -> dict:
    ddr = _normalize_decision_payload(payload)
    explained = explain(ddr)
    return _normalize_explainer_response(explained)

@router.post("/platform")
def copilot_platform_bridge(payload: dict, tenant_id: str = Depends(require_tenant_api_key)):
    try:
        context = payload or {}

        res = httpx.post(
            f"{ENGINE_URL}/copilot/bridge/platform",
            json={
                "question": "Generate executive platform summary",
                "mode": "copilot",
                "context": context
            },
            timeout=5
        )

        return _normalize_platform_summary(res.json(), context)

    except Exception as e:
        return {
            "error": "engine_unavailable",
            "message": str(e)
        }


def _safe_str(value, default: str = "unknown") -> str:
    return value if isinstance(value, str) and value else default


def _safe_num(value, default: int = 0) -> int:
    try:
        if isinstance(value, bool):
            return default
        if value is None or value == "":
            return default
        return int(value)
    except Exception:
        return default


def _normalize_operator_notes(notes) -> list:
    if not isinstance(notes, list):
        return []

    normalized = []

    for item in notes:
        if not isinstance(item, dict):
            continue

        label = _safe_str(item.get("label"), "")
        raw_value = item.get("value")

        if not label:
            continue

        if isinstance(raw_value, str):
            value = raw_value
        elif isinstance(raw_value, (int, float)) and not isinstance(raw_value, bool):
            value = str(raw_value)
        elif raw_value is None:
            value = ""
        else:
            value = str(raw_value)

        normalized.append({
            "label": label,
            "value": value
        })

    return normalized


def _build_platform_ddr_explainer(summary: dict, context: dict) -> dict:
    metrics = context.get("metrics") if isinstance(context.get("metrics"), dict) else {}
    highest = summary.get("highest_risk_tenant") if isinstance(summary.get("highest_risk_tenant"), dict) else {}
    recommended_action = summary.get("recommended_action") if isinstance(summary.get("recommended_action"), dict) else {}

    platform_status = _safe_str(summary.get("platform_status"), "UNKNOWN").upper()
    audit_status = _safe_str(summary.get("audit_status"), "UNKNOWN").upper()

    tenant_id = _safe_str(highest.get("tenant_id"), "unknown")
    policy_denied = _safe_num(metrics.get("policy_denied"), 0)
    sessions_revoked = _safe_num(metrics.get("sessions_revoked"), 0)
    active_sessions = _safe_num(metrics.get("active_sessions"), 0)

    action_detail = _safe_str(
        recommended_action.get("detail"),
        "Continue routine monitoring."
    )

    if policy_denied > 0 and tenant_id != "unknown":
        detection = f"Denied decision pressure is above the expected baseline and is concentrated in {tenant_id}."
    elif sessions_revoked > 0 and tenant_id != "unknown":
        detection = f"Recent session control activity is elevated and is currently concentrated in {tenant_id}."
    elif active_sessions > 0:
        detection = "Runtime telemetry is active and current session activity remains within the normal operating range."
    else:
        detection = "No material session or policy pressure is currently visible in runtime telemetry."

    if platform_status == "HEALTHY" and audit_status == "VALID":
        decision = "Platform health is stable and audit integrity remains valid."
    elif audit_status != "VALID":
        decision = "Platform telemetry is present, but audit integrity requires review before relying on this control narrative."
    else:
        decision = "Runtime controls remain active, but platform health is degraded and requires attention."

    if _safe_str(recommended_action.get("title"), "MONITOR").upper() == "MONITOR":
        response = "The system continued controlled enforcement while monitoring the current condition."
    else:
        response = "The system continued controlled enforcement and flagged the affected control path for review."

    if audit_status != "VALID" or platform_status != "HEALTHY":
        executive_meaning = "This should be treated as a platform control issue and assigned for leadership review."
    elif policy_denied > 0 or sessions_revoked > 0:
        executive_meaning = f"This appears localized rather than platform-wide. {action_detail}"
    else:
        executive_meaning = "No platform-wide instability is present. Continue routine monitoring."

    return {
        "detection": detection,
        "decision": decision,
        "response": response,
        "executive_meaning": executive_meaning
    }


def _normalize_platform_summary(result: dict, context: dict) -> dict:
    source = result if isinstance(result, dict) else {}

    tenant_usage = context.get("tenant_usage") if isinstance(context.get("tenant_usage"), list) else []
    fallback_tenant = tenant_usage[0] if tenant_usage and isinstance(tenant_usage[0], dict) else {}

    highest = source.get("highest_risk_tenant") if isinstance(source.get("highest_risk_tenant"), dict) else {}
    recommended_action = source.get("recommended_action") if isinstance(source.get("recommended_action"), dict) else {}

    normalized = {
        "platform_status": _safe_str(source.get("platform_status"), "UNKNOWN").upper(),
        "audit_status": _safe_str(source.get("audit_status"), "UNKNOWN").upper(),
        "highest_risk_tenant": {
            "tenant_id": _safe_str(
                highest.get("tenant_id"),
                _safe_str(fallback_tenant.get("tenant_id"), "unknown")
            ),
            "risk_score": _safe_num(
                highest.get("risk_score"),
                _safe_num(fallback_tenant.get("risk_score"), 0)
            )
        },
        "recommended_action": {
            "title": _safe_str(recommended_action.get("title"), "MONITOR").upper(),
            "detail": _safe_str(
                recommended_action.get("detail"),
                "System operating within expected parameters."
            )
        },
        "executive_brief": _safe_str(
            source.get("executive_brief"),
            "Awaiting executive summary."
        ),
        "operator_notes": _normalize_operator_notes(source.get("operator_notes"))
    }

    normalized["ddr_explainer"] = _build_platform_ddr_explainer(normalized, context)

    return normalized

@router.post("/decision")
def copilot_decision_legacy(payload: dict, tenant_id: str = Depends(require_tenant_api_key)):
    try:
        return _build_decision_explanation(payload)
    except Exception as e:
        return {"error": "explainer_failed", "message": str(e)}

@router.post("/bridge/decision")
def copilot_decision_bridge(payload: dict, tenant_id: str = Depends(require_tenant_api_key)):
    try:
        return _build_decision_explanation(payload)
    except Exception as e:
        return {
            "error": "explainer_failed",
            "message": str(e)
        }
