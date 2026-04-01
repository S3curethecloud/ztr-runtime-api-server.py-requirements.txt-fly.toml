# =========================================================
# sessions.py — Session Lifecycle Control
# SecureTheCloud — Phase 8
#
# Endpoints
#   GET  /v1/sessions/active
#   POST /v1/sessions/revoke
#
# Behavior
#   - Lists active runtime sessions
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

from fastapi import APIRouter, Depends, HTTPException, Body

from api.auth import require_tenant_api_key
from api.redis_keys import (
    tenant_session_key,
    tenant_session_index_key,
    tenant_usage_key
)

from audit_chain import emit_event


sessions_router = APIRouter(prefix="/v1/sessions", tags=["sessions"])

r = redis.from_url(
    os.environ["REDIS_URL"],
    decode_responses=True
)


def current_period() -> str:
    return datetime.datetime.utcnow().strftime("%Y-%m")


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

        if not data:
            r.srem(index_key, sid)
            continue

        issued_at = int(data.get("issued_at", 0))
        ttl = r.ttl(key)

        raw_scopes = data.get("scopes", "[]")

        try:
            scopes = json.loads(raw_scopes)
        except:
            scopes = raw_scopes.split(",") if raw_scopes else []

        sessions.append({
            "session_id": sid,
            "tenant_id": tenant_id,
            "principal": data.get("principal"),
            "intent": data.get("intent"),
            "scopes": scopes,
            "issued_at": issued_at,
            "ttl": ttl,
            "risk": json.loads(data.get("risk", "null"))
        })

    return {
        "tenant_id": tenant_id,
        "active_sessions": len(sessions),
        "sessions": sessions
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

    r.incr("metrics:sessions_revoked")
    r.decr("ztr:sessions:active")

    period = current_period()
    r.incr(tenant_usage_key(tenant_id, period, "sessions_revoked"))

    emit_event(
        tenant_id=tenant_id,
        event_type="runtime.session_revoked",
        service="ztr-runtime",
        payload={
            "session_id": sid,
            "revoked_at": int(time.time())
        }
    )

    return {
        "status": "revoked",
        "tenant_id": tenant_id,
        "session_id": sid,
        "revoked_at": int(time.time())
    }
