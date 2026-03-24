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


def enforce_obligations(decision, request):
    obligations = decision.get("obligations", [])

    context = request.get("context", {})

    if "ROLE_MATCHED" in obligations:
        if request.get("principal") != "agent-demo":
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "ROLE_ENFORCEMENT_FAILED",
                    "control": "ROLE_MATCHED",
                    "layer": "runtime_enforcement"
                }
            )

    if "AMOUNT_OK" in obligations:
        amount = context.get("amount", 0)
        if amount > 1000:
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "AMOUNT_ENFORCEMENT_FAILED",
                    "control": "AMOUNT_OK",
                    "layer": "runtime_enforcement"
                }
            )

    if "RISK_OK" in obligations:
        risk = context.get("risk_score", 0)
        if risk > 50:
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "RISK_ENFORCEMENT_FAILED",
                    "control": "RISK_OK",
                    "layer": "runtime_enforcement"
                }
            )


# ---------------------------------------------------------
# POST /v1/tokens/issue
# ---------------------------------------------------------

@tokens_router.post("/tokens/issue")
async def issue_token(
    req: TokenIssueRequest,
    tenant_id: str = Depends(require_tenant_api_key),
):

    now = int(time.time())

    # ----------------------------------------
    # Predictive Authorization (Blast Radius)
    # ----------------------------------------

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

    risk_score = riskdna["final_score"]

    # ----------------------------------------
    # Step 5 — Store simulation telemetry
    # ----------------------------------------

    try:

        ts = int(time.time())
        blast_id = str(uuid.uuid4())

        redis_key = f"metrics:blast:{ts}:{tenant_id}:{req.principal}:{req.intent}:{blast_id}"

        r.set(
            redis_key,
            json.dumps({
                "tenant_id": tenant_id,
                "principal": req.principal,
                "intent": req.intent,
                "risk_score": risk_score,
                "riskdna": riskdna
            }),
            ex=86400
        )

    except Exception:
        pass

    # -------------------------------------------------
    # Phase 6 — OPA issuance enforcement
    # -------------------------------------------------

    context = req.context or {}

    context["risk_score"] = risk_score

    policy_input = {
        "tenant_id": tenant_id,
        "principal": req.principal,
        "intent": req.intent,
        "scopes": req.scopes,
        "ttl_seconds": req.ttl_seconds,
        "context": context,
        "risk_score": risk_score,
        "riskdna": riskdna,
        "ts": now,
        "policy_revision": "dev-1",
    }

    # --------------------------------------------------
    # PHASE 8.1 — AEGIS SIGNAL INGESTION (SAFE + CORRECT)
    # --------------------------------------------------

    try:
        from aegis_engine import get_latest_signal

        aegis_signal = get_latest_signal(
            tenant_id=tenant_id,
            principal=req.principal
        )

        if aegis_signal:
            policy_input["context"]["aegis"] = {
                "anomaly": bool(aegis_signal.get("anomaly", False)),
                "velocity": int(aegis_signal.get("velocity", 0)),
                "confidence": float(aegis_signal.get("confidence", 0.0)),
                "risk_delta": int(aegis_signal.get("risk_delta", 0))
            }

    except Exception as e:
        print(f"[AEGIS WARNING] {e}")

    input_hash = hashlib.sha256(
        json.dumps(policy_input, sort_keys=True).encode()
    ).hexdigest()

    opa_result = evaluate_issue_policy(policy_input)

    if not opa_result.get("allow"):

        r.incr("metrics:policy_denied")

        period = current_period()
        r.incr(tenant_usage_key(tenant_id, period, "policy_denied"))

        event = {
            "timestamp": int(time.time()),
            "tenant_id": tenant_id,
            "principal": req.principal,
            "intent": req.intent,
            "decision": "deny",
            "risk_score": context.get("risk_score"),
            "policy_revision": policy_input["policy_revision"]
        }

        publish_decision(event)

        raise HTTPException(
            status_code=403,
            detail="policy_denied"
        )

    effective_ttl = opa_result.get("ttl_seconds")

    if not isinstance(effective_ttl, int) or effective_ttl <= 0:
        raise HTTPException(
            status_code=500,
            detail="invalid_policy_ttl"
        )

    request_context = dict(context)
    request_amount = getattr(req, "amount", None)

    if request_amount is not None:
        request_context["amount"] = request_amount

    request_data = {
        "principal": req.principal,
        "context": request_context
    }

    enforce_obligations(opa_result, request_data)

    sid = str(uuid.uuid4())

    session_key = tenant_session_key(tenant_id, sid)
    session_index = tenant_session_index_key(tenant_id)

    session_record = {
        "sid": sid,
        "principal": req.principal,
        "intent": req.intent,
        "scopes": json.dumps(req.scopes),
        "issued_at": now,
        "ttl": effective_ttl
    }

    pipe = r.pipeline()

    pipe.hset(session_key, mapping=session_record)
    pipe.expire(session_key, effective_ttl)
    pipe.sadd(session_index, sid)

    pipe.execute()

    r.incr("ztr:sessions:active")

    period = current_period()
    r.incr(tenant_usage_key(tenant_id, period, "tokens_issued"))

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

    r.incr("metrics:tokens_issued")
    r.incr("metrics:policy_allowed")

    event = {
        "timestamp": int(time.time()),
        "tenant_id": tenant_id,
        "principal": req.principal,
        "intent": req.intent,
        "decision": "allow",
        "risk_score": context.get("risk_score"),
        "policy_revision": policy_input["policy_revision"]
    }

    publish_decision(event)

    emit_event(
        tenant_id=tenant_id,
        event_type="runtime.token_issued",
        service="ztr-runtime",
        payload={
            "principal": req.principal,
            "intent": req.intent,
            "node_id": NODE_ID,
            "result": "allow",
            "policy_revision": policy_input["policy_revision"]
        }
    )

    return {
        "status": "issued",
        "tenant_id": tenant_id,
        "session_id": sid,
        "principal": req.principal,
        "intent": req.intent,
        "expires_in": effective_ttl,
        "issued_at": now,
        "token": signed_token,
    }


# ---------------------------------------------------------
# POST /v1/tokens/introspect
# ---------------------------------------------------------

@tokens_router.post("/tokens/introspect")
async def introspect_token(
    body: dict,
    tenant_id: str = Depends(require_tenant_api_key),
):

    token = body.get("token")

    if not token:
        raise HTTPException(
            status_code=400,
            detail="token_required"
        )

    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=["HS256"],
            audience=JWT_AUDIENCE,
        )

    except jwt.ExpiredSignatureError:
        return {"active": False}

    except jwt.InvalidTokenError:
        return {"active": False}

    sid = payload.get("sid")

    if not sid:
        return {"active": False}

    session_key = tenant_session_key(tenant_id, sid)

    if not r.exists(session_key):
        return {"active": False}

    return {
        "active": True,
        "tenant_id": tenant_id,
        "principal": payload.get("sub"),
        "intent": payload.get("intent"),
        "scopes": payload.get("scopes"),
        "expires_at": payload.get("exp"),
    }
