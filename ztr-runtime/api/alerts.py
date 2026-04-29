# api/alerts.py

import os
import time
import redis

from fastapi import APIRouter, Depends

from api.auth import require_tenant_api_key
from audit_chain import emit_event, get_latest_event


router = APIRouter()

r = redis.from_url(
    os.environ["REDIS_URL"],
    decode_responses=True
)

STALE_AFTER_SECONDS = int(os.getenv("RISKDNA_STALE_AFTER_SECONDS", "300"))


def _status_key(tenant_id: str) -> str:
    return f"ztr:alerts:riskdna:{tenant_id}:status"


def _opened_at_key(tenant_id: str) -> str:
    return f"ztr:alerts:riskdna:{tenant_id}:opened_at"


def _last_seen_key(tenant_id: str) -> str:
    return f"ztr:alerts:riskdna:{tenant_id}:last_seen"


def _latest_runtime_event(tenant_id: str):
    latest_issued = get_latest_event(
        tenant_id=tenant_id,
        event_type="runtime.token_issued"
    )

    latest_denied = get_latest_event(
        tenant_id=tenant_id,
        event_type="runtime.token_denied"
    )

    candidates = [event for event in [latest_issued, latest_denied] if event]

    if not candidates:
        return None

    return max(candidates, key=lambda event: int(event.get("ts_ms") or 0))


def _latest_runtime_decision(tenant_id: str):
    latest_issued = get_latest_event(
        tenant_id=tenant_id,
        event_type="runtime.token_issued"
    )

    latest_denied = get_latest_event(
        tenant_id=tenant_id,
        event_type="runtime.token_denied"
    )

    candidates = [event for event in [latest_issued, latest_denied] if event]

    if not candidates:
        return None

    latest = max(candidates, key=lambda event: int(event.get("ts_ms") or 0))
    payload = latest.get("payload") or {}

    risk_score = int(payload.get("risk_score") or 0)

    if risk_score <= 30:
        risk_tier = "LOW"
    elif risk_score <= 60:
        risk_tier = "MEDIUM"
    elif risk_score <= 90:
        risk_tier = "HIGH"
    else:
        risk_tier = "CRITICAL"

    return {
        "status": "ok",
        "tenant_id": tenant_id,
        "decision": str(payload.get("decision") or "allow").lower(),
        "risk_score": risk_score,
        "risk_tier": risk_tier,
        "policy_revision": payload.get("policy_revision") or "--",
        "reason": payload.get("reason") or None,
        "timestamp": int(latest.get("ts_ms") or 0)
    }


@router.get("/v1/alerts/riskdna")
def get_riskdna_alert(
    tenant_id: str = Depends(require_tenant_api_key)
):
    now_ms = int(time.time() * 1000)

    latest_runtime_event = _latest_runtime_event(tenant_id)

    if not latest_runtime_event:
        r.set(_status_key(tenant_id), "unavailable")

        return {
            "status": "unavailable",
            "alert_type": "riskdna_stale",
            "tenant_id": tenant_id,
            "opened_at": None,
            "last_seen": None,
            "stale_minutes": None,
            "message": "No RiskDNA runtime telemetry available."
        }

    last_seen = int(latest_runtime_event.get("ts_ms") or 0)
    r.set(_last_seen_key(tenant_id), str(last_seen))

    previous_status = (r.get(_status_key(tenant_id)) or "healthy").strip().lower()

    age_seconds = max(0, int((now_ms - last_seen) / 1000))
    stale_minutes = int(age_seconds / 60)

    if age_seconds > STALE_AFTER_SECONDS:
        opened_at_raw = r.get(_opened_at_key(tenant_id))
        opened_at = int(opened_at_raw) if opened_at_raw else now_ms

        if previous_status != "stale":
            r.set(_opened_at_key(tenant_id), str(opened_at))
            r.set(_status_key(tenant_id), "stale")

            emit_event(
                tenant_id=tenant_id,
                event_type="runtime.riskdna_stale_opened",
                service="riskdna-alerts",
                payload={
                    "last_seen": last_seen,
                    "opened_at": opened_at,
                    "stale_seconds": age_seconds,
                    "threshold_seconds": STALE_AFTER_SECONDS
                }
            )

        return {
            "status": "stale",
            "alert_type": "riskdna_stale",
            "tenant_id": tenant_id,
            "opened_at": opened_at,
            "last_seen": last_seen,
            "stale_minutes": stale_minutes,
            "message": f"No RiskDNA updates for {stale_minutes} minutes."
        }

    if previous_status == "stale":
        r.set(_status_key(tenant_id), "recovering")
        r.delete(_opened_at_key(tenant_id))

        emit_event(
            tenant_id=tenant_id,
            event_type="runtime.riskdna_stale_resolved",
            service="riskdna-alerts",
            payload={
                "last_seen": last_seen,
                "resolved_at": now_ms,
                "threshold_seconds": STALE_AFTER_SECONDS
            }
        )

        return {
            "status": "recovering",
            "alert_type": "riskdna_stale",
            "tenant_id": tenant_id,
            "opened_at": None,
            "last_seen": last_seen,
            "stale_minutes": 0,
            "message": "RiskDNA stream resumed. Recovery in progress."
        }

    if previous_status == "recovering":
        r.set(_status_key(tenant_id), "healthy")
    else:
        r.set(_status_key(tenant_id), "healthy")

    return {
        "status": "healthy",
        "alert_type": "riskdna_stale",
        "tenant_id": tenant_id,
        "opened_at": None,
        "last_seen": last_seen,
        "stale_minutes": 0,
        "message": "RiskDNA stream healthy."
    }


@router.get("/v1/alerts/riskdna/latest-decision")
def get_latest_riskdna_decision(
    tenant_id: str = Depends(require_tenant_api_key)
):
    latest = _latest_runtime_decision(tenant_id)

    if not latest:
        return {
            "status": "unavailable",
            "tenant_id": tenant_id,
            "decision": None,
            "risk_score": None,
            "risk_tier": None,
            "policy_revision": None,
            "reason": None,
            "timestamp": None
        }

    return latest
