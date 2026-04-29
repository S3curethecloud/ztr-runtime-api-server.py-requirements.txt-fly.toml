# =========================================================
# sessions.py — Session Lifecycle Control
# SecureTheCloud — Phase 8
#
# Endpoints
#   GET  /v1/sessions/active
#   GET  /v1/sessions/admin/active
#   POST /v1/sessions/revoke
#
# Behavior
#   - Lists active runtime sessions
#   - Lists platform-wide active runtime sessions
#   - Lazily cleans expired session index entries
#   - Allows operator-driven session revocation
#
# Redis Model
#   ztr:{tenant}:session:{sid}        -> HASH (TTL)
#   ztr:{tenant}:sessions             -> SET  (index)
# =========================================================

import os
import redis
import time
import json
import datetime

from fastapi import APIRouter, Depends, HTTPException, Body, Header

from api.auth import require_tenant_api_key
from api.redis_keys import (
    tenant_session_key,
    tenant_session_index_key,
    tenant_usage_key
)

from audit_chain import emit_event
from api.streaming import publish_decision


sessions_router = APIRouter(prefix="/v1/sessions", tags=["sessions"])

r = redis.from_url(
    os.environ["REDIS_URL"],
    decode_responses=True
)

ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "")


def _require_admin(x_stc_admin_secret: str = Header(None)) -> None:
    if not ADMIN_SECRET:
        raise HTTPException(status_code=503, detail="admin_not_configured")

    if not x_stc_admin_secret or x_stc_admin_secret != ADMIN_SECRET:
        raise HTTPException(status_code=403, detail="forbidden")


def fetch_aegis_signal(tenant_id: str, principal: str):
    try:
        key = f"ztr:aegis:{tenant_id}:{principal}"
        data = r.get(key)

        if not data:
            return None

        return json.loads(data)

    except Exception:
        return None


def current_period() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m")


def increment_tenant_usage(tenant_id: str, field: str, amount: int = 1):
    usage_key = tenant_usage_key(tenant_id, current_period())

    pipe = r.pipeline()
    pipe.hincrby(usage_key, field, amount)
    pipe.execute()


def _list_sessions_for_tenant(tenant_id: str):
    index_key = tenant_session_index_key(tenant_id)
    sids = r.smembers(index_key)

    sessions = []

    for sid in list(sids):
        key = tenant_session_key(tenant_id, sid)

        data = r.hgetall(key)
        ttl = r.ttl(key)

        if not data or ttl <= 0:
            r.srem(index_key, sid)
            continue

        issued_at = int(data.get("issued_at", 0))

        raw_scopes = data.get("scopes", "[]")
        try:
            scopes = json.loads(raw_scopes)
        except Exception:
            scopes = raw_scopes.split(",") if raw_scopes else []

        raw_obligations = data.get("obligations", "[]")
        try:
            obligations = json.loads(raw_obligations)
        except Exception:
            obligations = []

        if not isinstance(obligations, list):
            obligations = []

        policy_revision = data.get("policy_revision", "unknown")
        decision = data.get("decision", "allow")

        principal = data.get("principal")
        aegis = fetch_aegis_signal(tenant_id, principal)

        sessions.append({
            "session_id": sid,
            "tenant_id": tenant_id,
            "principal": principal,
            "intent": data.get("intent"),
            "scopes": scopes,
            "issued_at": issued_at,
            "ttl": ttl,
            "risk": json.loads(data.get("risk", "null")),
            "aegis": aegis,
            "policy_revision": policy_revision,
            "obligations": obligations,
            "decision": decision
        })

    return sessions


def _discover_session_tenant_ids():
    tenant_ids = set()

    # Authoritative discovery path: tenant inventory/meta keys.
    for key in r.scan_iter("ztr:tenant:*:meta"):
        raw = r.get(key)
        if not raw:
            continue

        try:
            meta = json.loads(raw)
        except Exception:
            continue

        tenant_id = meta.get("tenant_id")
        if tenant_id:
            tenant_ids.add(tenant_id)

    # Defensive fallback: discover tenants from live session hashes too.
    for key in r.scan_iter("ztr:*:session:*"):
        parts = key.split(":")
        if len(parts) == 4 and parts[0] == "ztr" and parts[2] == "session":
            tenant_ids.add(parts[1])

    return sorted(tenant_ids)


@sessions_router.get("/active")
def list_active_sessions(
    tenant_id: str = Depends(require_tenant_api_key)
):
    sessions = _list_sessions_for_tenant(tenant_id)

    return {
        "tenant_id": tenant_id,
        "active_sessions": len(sessions),
        "sessions": sessions
    }


@sessions_router.get("/admin/active")
def list_platform_active_sessions(
    x_stc_admin_secret: str = Header(None)
):
    _require_admin(x_stc_admin_secret)

    sessions = []

    for tenant_id in _discover_session_tenant_ids():
        sessions.extend(_list_sessions_for_tenant(tenant_id))

    sessions.sort(key=lambda s: s.get("issued_at") or 0, reverse=True)

    return {
        "active_sessions": len(sessions),
        "sessions": sessions
    }

def _revoke_session_for_tenant(tenant_id: str, sid: str):
    key = tenant_session_key(tenant_id, sid)
    index_key = tenant_session_index_key(tenant_id)

    if not r.exists(key):
        raise HTTPException(
            status_code=404,
            detail="session_not_found"
        )

    session_data = r.hgetall(key) or {}
    principal = session_data.get("principal") or "unknown"
    intent = session_data.get("intent") or "session:revoke"

    pipe = r.pipeline()
    pipe.delete(key)
    pipe.srem(index_key, sid)
    pipe.execute()

    r.incr("metric:sessions_revoked")
    r.decr("ztr:sessions:active")

    increment_tenant_usage(tenant_id, "sessions_revoked")
    revoked_at = int(time.time())

    emit_event(
        tenant_id=tenant_id,
        event_type="runtime.session_revoked",
        service="ztr-runtime",
        payload={
            "session_id": sid,
            "principal": principal,
            "intent": intent,
            "revoked_at": revoked_at
        }
    )

    publish_decision({
        "event_type": "decision",
        "timestamp": revoked_at,
        "tenant_id": tenant_id,
        "session_id": sid,
        "principal": principal,
        "intent": intent,
        "decision": "deny",
        "risk_score": 0,
        "policy_revision": "runtime-revoke",
        "metadata": {
            "source": "sessions",
            "stage": "revoke"
        }
    })

    return {
        "status": "revoked",
        "tenant_id": tenant_id,
        "session_id": sid,
        "revoked_at": revoked_at
    }


@sessions_router.post("/revoke")
async def revoke_session(
    body: dict = Body(...),
    tenant_id: str = Depends(require_tenant_api_key)
):
    sid = body.get("session_id")

    if not sid:
        raise HTTPException(
            status_code=400,
            detail="session_id required"
        )

    return _revoke_session_for_tenant(tenant_id, sid)


@sessions_router.post("/admin/revoke")
async def revoke_platform_session(
    body: dict = Body(...),
    x_stc_admin_secret: str = Header(None)
):
    _require_admin(x_stc_admin_secret)

    tenant_id = body.get("tenant_id")
    sid = body.get("session_id")

    if not tenant_id:
        raise HTTPException(
            status_code=400,
            detail="tenant_id required"
        )

    if not sid:
        raise HTTPException(
            status_code=400,
            detail="session_id required"
        )

    return _revoke_session_for_tenant(tenant_id, sid)
