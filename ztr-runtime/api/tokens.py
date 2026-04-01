# 🔒 MGF – GOVERNANCE AUTHORITY (ALL)
# ZERO-TOLERANCE EXECUTION DIRECTIVE
# NO DRIFT. NO GUESSING. NO HALLUCINATION.

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
from audit_chain import emit_event

from runtime_identity import get_node_id
from api.blast_simulator import simulate_blast_radius, compute_riskdna

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

NODE_ID = get_node_id()

JWT_SECRET = os.environ["ZTR_JWT_SECRET"]
JWT_ISSUER = "ztr-runtime"
JWT_AUDIENCE = "securethecloud"
JWT_VERSION = "1.0"


def current_period() -> str:
    return datetime.datetime.utcnow().strftime("%Y-%m")


def enforce_obligations(decision, request):
    obligations = decision.get("obligations", [])
    context = request.get("context", {})

    if "ROLE_MATCHED" in obligations:
        if request.get("principal") != "agent-demo":
            raise HTTPException(status_code=403)

    if "AMOUNT_OK" in obligations:
        if context.get("amount", 0) > 1000:
            raise HTTPException(status_code=403)

    if "RISK_OK" in obligations:
        if context.get("risk_score", 0) > 50:
            raise HTTPException(status_code=403)


@tokens_router.post("/tokens/issue")
async def issue_token(
    req: TokenIssueRequest,
    tenant_id: str = Depends(require_tenant_api_key),
):
    try:

        now = int(time.time())

        graph = {
            "refund:create": ["payment_db", "audit_ledger"],
            "payment_db": ["ledger_backup"],
            "audit_ledger": [],
            "ledger_backup": []
        }

        nodes = simulate_blast_radius(req.principal, req.intent, graph)

        riskdna = compute_riskdna(
            principal=req.principal,
            intent=req.intent,
            nodes=nodes,
            context=req.context or {},
            recent_denials=0,
            policy_drift=False
        )

        context = req.context or {}
        context["risk_score"] = riskdna["final_score"]

        policy_input = {
            "tenant_id": tenant_id,
            "principal": req.principal,
            "intent": req.intent,
            "scopes": req.scopes,
            "ttl_seconds": req.ttl_seconds,
            "context": context,
            "policy_revision": "dev-1",
        }

        opa_result = evaluate_issue_policy(policy_input)

        if not opa_result.get("allow"):
            raise HTTPException(status_code=403, detail="policy_denied")

        # ✅ FIX 1
        effective_ttl = opa_result.get("ttl_seconds") or req.ttl_seconds

        # ✅ FIX 2
        if not isinstance(effective_ttl, int) or effective_ttl <= 0:
            raise HTTPException(
                status_code=500,
                detail="invalid_ttl_from_policy"
            )

        sid = str(uuid.uuid4())

        session_key = tenant_session_key(tenant_id, sid)
        session_index = tenant_session_index_key(tenant_id)

        session_record = {
            "sid": sid,
            "tid": tenant_id,
            "ver": JWT_VERSION,
            "principal": req.principal,
            "intent": req.intent,
            "scopes": json.dumps(req.scopes),
            "issued_at": now,
            "ttl": effective_ttl,
            "risk": json.dumps(riskdna)
        }

        pipe = r.pipeline()
        pipe.hset(session_key, mapping=session_record)
        pipe.expire(session_key, effective_ttl)
        pipe.sadd(session_index, sid)
        pipe.execute()

        exp = now + effective_ttl

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

        return {
            "status": "issued",
            "tenant_id": tenant_id,
            "session_id": sid,
            "token": signed_token,
        }

    except Exception as e:
        print("🔥 ISSUE TOKEN FAILURE:", str(e))
        raise HTTPException(status_code=500, detail=str(e))
