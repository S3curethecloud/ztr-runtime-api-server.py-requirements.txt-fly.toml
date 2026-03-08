# =========================================================
# sessions.py — Session Revocation Engine
# SecureTheCloud — Phase 8 Step 3
#
# Purpose:
#   Terminate active runtime sessions.
#
# Behavior:
#   1. Validate tenant API key
#   2. Locate session key
#   3. Delete session record
#   4. Remove sid from session index
#   5. Emit audit-chain event
# =========================================================

import os
import redis
import time
import json

from fastapi import APIRouter, HTTPException, Body, Depends

from api.auth import require_tenant_api_key
from api.redis_keys import (
    tenant_session_key,
    tenant_session_index_key,
    session_index_key,
    session_key
)

from audit_chain import emit_event

sessions_router = APIRouter()

r = redis.from_url(
    os.environ["REDIS_URL"],
    decode_responses=True
)


@sessions_router.post("/v1/sessions/revoke")
def revoke_session(
    body: dict = Body(...),
    tenant_id: str = Depends(require_tenant_api_key)
):
    """
    Revoke an active session.
    """

    sid = body.get("session_id")

    if not sid:
        raise HTTPException(
            status_code=400,
            detail="session_id required"
        )

    redis_session_key = tenant_session_key(tenant_id, sid)
    session_index = tenant_session_index_key(tenant_id)

    if not r.exists(redis_session_key):
        raise HTTPException(
            status_code=404,
            detail="session_not_found"
        )

    pipe = r.pipeline()

    pipe.delete(redis_session_key)
    pipe.srem(session_index, sid)

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
        "session_id": sid
    }


@sessions_router.get("/v1/sessions/active")
def list_active_sessions(
    tenant_id: str = Depends(require_tenant_api_key)
):

    index_key = session_index_key(tenant_id)

    cursor = 0
    session_ids = []

    while True:
        cursor, batch = r.sscan(index_key, cursor, count=100)
        session_ids.extend(batch)
        if cursor == 0:
            break

    active_sessions = []

    for sid in list(session_ids):

        key = session_key(tenant_id, sid)

        data = r.hgetall(key)

        if not data:
            r.srem(index_key, sid)
            continue

        session = data

        ttl = r.ttl(key)

        active_sessions.append({
            "session_id": sid,
            "principal": session.get("principal"),
            "intent": session.get("intent"),
            "issued_at": session.get("issued_at"),
            "ttl": ttl,
            "risk": session.get("risk")
        })

    return {
        "tenant_id": tenant_id,
        "active_sessions": len(active_sessions),
        "sessions": active_sessions
    }
