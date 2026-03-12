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
#   5. Sign JWT token
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

from api.streaming import publish_decision

import uuid
import redis
import os
import time
import json
import hashlib
import datetime
import jwt


tokens_router = APIRouter(prefix="/v1", tags=["tokens"])

REDIS_URL = os.environ["REDIS_URL"]

r = redis.from_url(
    REDIS_URL,
    decode_responses=True
)

# ---------------------------------------------------------
# JWT Configuration
# ---------------------------------------------------------

JWT_SECRET = os.environ["ZTR_JWT_SECRET"]
JWT_ISSUER = "ztr-runtime"
JWT_AUDIENCE = "securethecloud"
JWT_VERSION = "1.0"


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

        period = current_period()
        r.incr(tenant_usage_key(tenant_id, period, "policy_denied"))

        event = {
            "timestamp": int(time.time()),
            "tenant": tenant_id,
            "principal": req.principal,
            "intent": req.intent,
            "decision": "deny",
            "risk_score": (req.context or {}).get("risk_score"),
            "policy_revision": policy_input["policy_revision"]
        }

        publish_decision(event)

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

    # ---------------------------------------------------------
    # Active session counter
    # ---------------------------------------------------------

    r.incr("ztr:sessions:active")

    period = current_period()
    r.incr(tenant_usage_key(tenant_id, period, "tokens_issued"))

    # ---------------------------------------------------------
    # JWT Signing
    # ---------------------------------------------------------

    exp = now + req.ttl_seconds

    token_payload = {
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "tid": tenant_id,
        "sid": sid,
        "sub": req.principal,
        "intent": req.intent,
        "scopes": req.scopes,
        "ver": JWT_VERSION,
        "iat": now,
        "exp": exp,
    }

    signed_token = jwt.encode(
        token_payload,
        JWT_SECRET,
        algorithm="HS256"
    )

    # ---------------------------------------------------------
    # Publish Decision Telemetry
    # ---------------------------------------------------------

    event = {
        "timestamp": int(time.time()),
        "tenant": tenant_id,
        "principal": req.principal,
        "intent": req.intent,
        "decision": "allow",
        "risk_score": (req.context or {}).get("risk_score"),
        "policy_revision": policy_input["policy_revision"]
    }

    publish_decision(event)

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
        "token": signed_token,
    }
