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

from fastapi import APIRouter, HTTPException, Body, Depends

from api.auth import require_tenant_api_key
from api.redis_keys import tenant_session_key, tenant_session_index_key
from audit_chain import emit_event

sessions_router = APIRouter(tags=["sessions"])

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

    session_key = tenant_session_key(tenant_id, sid)
    session_index = tenant_session_index_key(tenant_id)

    if not r.exists(session_key):
        raise HTTPException(
            status_code=404,
            detail="session_not_found"
        )

    pipe = r.pipeline()

    pipe.delete(session_key)
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
