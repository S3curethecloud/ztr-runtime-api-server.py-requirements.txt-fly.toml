# =========================================================
# tokens.py — Token Issuance + Session Creation
# SecureTheCloud — Phase 6
#
# Endpoint
#   POST /v1/tokens/issue
#
# Flow
#   1. Validate tenant API key
#   2. Evaluate OPA issuance policy
#   3. Create session record in Redis
#   4. Index session ID
# =========================================================

from fastapi import APIRouter, Depends, HTTPException

from api.models import TokenIssueRequest
from api.auth import require_tenant_api_key
from opa_bridge import evaluate_issue_policy

from api.redis_keys import (
    tenant_session_key,
    tenant_session_index_key,
    tenant_usage_key
)

import uuid
import redis
import os
import time
import json
import hashlib
import datetime


tokens_router = APIRouter(prefix="/v1", tags=["tokens"])

REDIS_URL = os.environ["REDIS_URL"]

r = redis.from_url(
    REDIS_URL,
    decode_responses=True
)


# ---------------------------------------------------------
# Helper to get the current period (Year-Month)
# ---------------------------------------------------------

def current_period() -> str:
    return datetime.datetime.utcnow().strftime("%Y-%m")


# ---------------------------------------------------------
# POST /v1/tokens/issue
# ---------------------------------------------------------

@tokens_router.post("/tokens/issue")
def issue_token(
    req: TokenIssueRequest,
    tenant_id: str = Depends(require_tenant_api_key),
):

    now = int(time.time())

    # -------------------------------------------------
    # Phase 6 — OPA issuance enforcement
    # -------------------------------------------------

    policy_input = {
        "tenant_id": tenant_id,
        "principal": req.principal,
        "intent": req.intent,
        "scopes": req.scopes,
        "ttl_seconds": req.ttl_seconds,
        "context": req.context or {},
        "ts": now,
        "policy_revision": "dev-1",
    }

    input_hash = hashlib.sha256(
        json.dumps(policy_input, sort_keys=True).encode()
    ).hexdigest()

    opa_result = evaluate_issue_policy(policy_input)

    if not opa_result.get("allow"):
        # Increment the policy_denied counter for the current period
        period = current_period()
        r.incr(tenant_usage_key(tenant_id, period, "policy_denied"))
        raise HTTPException(
            status_code=403,
            detail="policy_denied"
        )

    # ---------------------------------------------------------
    # Create session record
    # ---------------------------------------------------------

    sid = str(uuid.uuid4())

    session_key = tenant_session_key(tenant_id, sid)
    session_index = tenant_session_index_key(tenant_id)

    session_record = {
        "sid": sid,
        "principal": req.principal,
        "intent": req.intent,
        "scopes": json.dumps(req.scopes),
        "issued_at": now,
        "ttl": req.ttl_seconds
    }

    pipe = r.pipeline()

    pipe.hset(session_key, mapping=session_record)
    pipe.expire(session_key, req.ttl_seconds)
    pipe.sadd(session_index, sid)

    pipe.execute()

    # Increment the tokens_issued counter for the current period
    period = current_period()
    r.incr(tenant_usage_key(tenant_id, period, "tokens_issued"))

    # ---------------------------------------------------------
    # Response
    # ---------------------------------------------------------

    return {
        "status": "issued",
        "tenant_id": tenant_id,
        "session_id": sid,
        "principal": req.principal,
        "intent": req.intent,
        "expires_in": req.ttl_seconds,
        "issued_at": now,
    }
