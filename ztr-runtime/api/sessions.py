# =========================================================
# sessions.py — Session Lifecycle Control
# SecureTheCloud — Phase 8
#
# Endpoints
#   GET  /v1/sessions/active
#   POST /v1/sessions/revoke
#
# Uses canonical Redis keys from redis_keys.py
# =========================================================

import os
import redis
import time

from fastapi import APIRouter, HTTPException, Body, Depends

from api.auth import require_tenant_api_key
from api.redis_keys import (
    tenant_session_key,
    tenant_session_index_key
)

from audit_chain import emit_event


sessions_router = APIRouter(prefix="/v1/sessions", tags=["sessions"])

r = redis.from_url(
    os.environ["REDIS_URL"],
    decode_responses=True
)


# ---------------------------------------------------------
# List Active Sessions
# ---------------------------------------------------------

@sessions_router.get("/active")
def list_active_sessions(
    tenant_id: str = Depends(require_tenant_api_key)
):

    index_key = tenant_session_index_key(tenant_id)

    sids = r.smembers(index_key)

    sessions = []

    for sid in list(sids):

        key = tenant_session_key(tenant_id, sid)

        data = r.hgetall(key)

        # cleanup stale index entries
        if not data:
            r.srem(index_key, sid)
            continue

        ttl = r.ttl(key)

        sessions.append({
            "session_id": sid,
            "principal": data.get("principal"),
            "intent": data.get("intent"),
            "issued_at": data.get("issued_at"),
            "ttl": ttl,
            "risk": data.get("risk")
        })

    return {
        "tenant_id": tenant_id,
        "active_sessions": len(sessions),
        "sessions": sessions
    }


# ---------------------------------------------------------
# Revoke Session
# ---------------------------------------------------------

@sessions_router.post("/revoke")
def revoke_session(
    body: dict = Body(...),
    tenant_id: str = Depends(require_tenant_api_key)
):

    sid = body.get("session_id")

    if not sid:
        raise HTTPException(
            status_code=400,
            detail="session_id required"
        )

    key = tenant_session_key(tenant_id, sid)
    index_key = tenant_session_index_key(tenant_id)

    if not r.exists(key):
        raise HTTPException(
            status_code=404,
            detail="session_not_found"
        )

    pipe = r.pipeline()

    pipe.delete(key)
    pipe.srem(index_key, sid)

    pipe.execute()

    emit_event(
        tenant_id=tenant_id,
        event_type="session_revoked",
        payload={
            "session_id": sid,
            "revoked_at": int(time.time())
        },
        service="runtime"
    )

    return {
        "status": "revoked",
        "tenant_id": tenant_id,
        "session_id": sid,
        "revoked_at": int(time.time())
    }
