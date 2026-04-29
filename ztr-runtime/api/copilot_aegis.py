from fastapi import APIRouter, Depends
from pydantic import BaseModel
from typing import Optional, Dict, Any

from api.auth import require_tenant_api_key

copilot_aegis_router = APIRouter()

# -----------------------------
# Request Model
# -----------------------------
class AegisSimulateRequest(BaseModel):
    risk: Dict[str, Any]
    decision: Optional[Dict[str, Any]] = None
    context: Optional[Dict[str, Any]] = None


# -----------------------------
# Deterministic Simulation Engine
# -----------------------------
def simulate_aegis_signal(risk: Dict[str, Any]) -> Dict[str, Any]:
    final_score = risk.get("final_score", 0)
    identity = risk.get("identity_risk", 0)
    topology = risk.get("topology_risk", 0)
    behavior = risk.get("behavior_risk", 0)
    policy = risk.get("policy_risk", 0)

    anomaly = False
    velocity = 1
    confidence = 0.95
    risk_delta = 0

    # --- Deterministic rules ---
    if final_score >= 70:
        anomaly = True
        risk_delta += 15

    if topology > 25:
        risk_delta += 10

    if identity > 15:
        risk_delta += 5

    if behavior > 10:
        anomaly = True
        velocity += 1

    if policy > 0:
        risk_delta += 5

    # Normalize velocity bounds
    velocity = min(max(velocity, 1), 5)

    return {
        "anomaly": anomaly,
        "velocity": velocity,
        "confidence": confidence,
        "risk_delta": risk_delta
    }


# -----------------------------
# Human-readable explanation (Copilot layer)
# -----------------------------
def build_explanation(signal: Dict[str, Any], risk: Dict[str, Any]):
    explanation = []

    if signal["anomaly"]:
        explanation.append("Anomalous pattern detected based on risk composition")

    explanation.append(f"Risk delta projected at {signal['risk_delta']}")
    explanation.append(f"Signal velocity estimated at {signal['velocity']}")
    explanation.append(f"Confidence level {signal['confidence']}")

    if risk.get("topology_risk", 0) > 25:
        explanation.append("Topology risk indicates expanding blast radius")

    if risk.get("identity_risk", 0) > 10:
        explanation.append("Identity risk contributing to elevated exposure")

    if risk.get("policy_risk", 0) > 0:
        explanation.append("Policy instability contributing to future risk")

    return explanation


# -----------------------------
# Endpoint
# -----------------------------
@copilot_aegis_router.post("/copilot/aegis/simulate")
async def simulate_aegis(
    payload: AegisSimulateRequest,
    _: str = Depends(require_tenant_api_key)
):
    risk = payload.risk or {}

    signal = simulate_aegis_signal(risk)
    explanation = build_explanation(signal, risk)

    return {
        "status": "ok",
        "aegis_signal": signal,
        "explanation": explanation
    }
