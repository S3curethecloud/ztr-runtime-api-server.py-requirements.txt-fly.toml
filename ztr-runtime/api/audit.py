# =========================================================
# SecureTheCloud — Audit API Layer
# Exposes deterministic audit chain (read-only)
# GOVERNANCE: MGF — AUTHORITY-ALL
#
# Purpose:
#   - Provide query access to audit chain
#   - Preserve immutability and integrity
#   - Tenant-safe access
#
# ZERO MODIFICATION to audit_chain.py
# =========================================================

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, HTTPException
from typing import List, Dict, Any

from api.auth import require_tenant_api_key
from audit_chain import (
    list_index,
    get_entry,
    verify_chain,
    get_latest_event,
)

router = APIRouter(prefix="/v1")


# =========================================================
# GET /v1/audit/events
# =========================================================
@router.get("/audit/events")
def get_audit_events(
    limit: int = Query(50, ge=1, le=500),
    event_type: str = Query("all"),
    tenant_id: str = Depends(require_tenant_api_key)
) -> Dict[str, Any]:
    """
    Returns full audit events (NOT just hashes)
    Deterministic, tenant-scoped, SOC2-safe
    """

    hashes = list_index(
        tenant_id=tenant_id,
        event_type=event_type,
        limit=limit
    )

    events: List[Dict[str, Any]] = []

    for h in hashes:
        entry = get_entry(h, tenant_id=tenant_id)
        if entry:
            events.append(entry)

    return {
        "events": events,
        "count": len(events),
        "tenant_id": tenant_id,
        "event_type": event_type
    }


# =========================================================
# GET /v1/audit/verify
# =========================================================
@router.get("/audit/verify")
def verify_audit_chain(
    limit: int = Query(5000, ge=1, le=10000),
    tenant_id: str = Depends(require_tenant_api_key)
) -> Dict[str, Any]:
    """
    Verifies hash chain integrity
    SOC2 critical control
    """

    result = verify_chain(
        tenant_id=tenant_id,
        limit=limit
    )

    return result


# =========================================================
# GET /v1/audit/latest
# =========================================================
@router.get("/audit/latest")
def get_latest_audit_event(
    event_type: str,
    tenant_id: str = Depends(require_tenant_api_key)
) -> Dict[str, Any]:
    """
    Returns latest event by type
    Useful for UI summaries / dashboards
    """

    event = get_latest_event(
        tenant_id=tenant_id,
        event_type=event_type
    )

    if not event:
        raise HTTPException(status_code=404, detail="No event found")

    return event


# =========================================================
# GET /v1/audit/metrics (LIGHTWEIGHT SUMMARY)
# =========================================================
@router.get("/audit/metrics")
def get_audit_metrics(
    tenant_id: str = Depends(require_tenant_api_key)
) -> Dict[str, Any]:
    """
    Lightweight audit summary for dashboards
    Does NOT scan entire dataset
    """

    verification = verify_chain(tenant_id=tenant_id, limit=1000)

    latest_decision = get_latest_event(
        tenant_id=tenant_id,
        event_type="decision"
    )

    return {
        "status": verification.get("status", "unknown"),
        "events_verified": verification.get("events_verified", 0),
        "chain_head": verification.get("chain_head"),
        "latest_decision_ts": latest_decision.get("ts_ms") if latest_decision else None,
        "tenant_id": tenant_id
    }
