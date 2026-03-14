# =========================================================
# control_plane_dashboard.py
# Stable UI contract for SecureTheCloud dashboard
# =========================================================

import os
import httpx
from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/v1/dashboard", tags=["dashboard"])

RUNTIME_URL = os.getenv("RUNTIME_URL", "https://ztr-runtime.fly.dev")


async def runtime_get(path: str):
    async with httpx.AsyncClient(timeout=5) as client:
        resp = await client.get(f"{RUNTIME_URL}{path}")
        if resp.status_code != 200:
            raise HTTPException(status_code=resp.status_code, detail="runtime_error")
        return resp.json()


# ---------------------------------------------------------
# Decisions (normalized for UI)
# ---------------------------------------------------------
@router.get("/decisions")
async def dashboard_decisions(limit: int = 25):

    data = await runtime_get(f"/v1/decisions?limit={limit}")

    events = data.get("events", [])

    return {
        "events": events,
        "total": len(events)
    }


# ---------------------------------------------------------
# Sessions
# ---------------------------------------------------------
@router.get("/sessions")
async def dashboard_sessions():

    data = await runtime_get("/v1/sessions")

    sessions = data.get("sessions", [])

    return {
        "sessions": sessions,
        "active": len(sessions)
    }


# ---------------------------------------------------------
# Intelligence
# ---------------------------------------------------------
@router.get("/intelligence")
async def dashboard_intelligence():

    data = await runtime_get("/v1/intelligence/risk")

    return {
        "top_risky_tenants": data.get("top_risky_tenants", []),
        "principals": data.get("suspicious_principals", []),
        "policy_drift": data.get("policy_drift", False),
        "timestamp": data.get("timestamp")
    }
