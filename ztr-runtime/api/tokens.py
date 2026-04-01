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


def validate_decision_event(event: dict):
    required_fields = [
        "event_type",
        "timestamp",
        "tenant_id",
        "session_id",
        "principal",
        "intent",
        "decision",
        "risk_score",
        "policy_revision",
        "metadata"
    ]

    for field in required_fields:
        if field not in event:
            raise ValueError(f"Decision event missing required field: {field}")

    if event["event_type"] != "decision":
        raise ValueError("Invalid event_type")

    if event["decision"] not in ("allow", "deny"):
        raise ValueError("Invalid decision value")

    if not isinstance(event["timestamp"], int):
        raise ValueError("timestamp must be int")

    if not isinstance(event["metadata"], dict):
        raise ValueError("metadata must be object")

    forbidden_aliases = ["tenant", "risk", "policy"]
    for alias in forbidden_aliases:
        if alias in event:
            raise ValueError(f"Forbidden field detected: {alias}")

    return True


@tokens_router.post("/tokens/issue")
async def issue_token(
    req: TokenIssueRequest,
    tenant_id: str = Depends(require_tenant_api_key),
):

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

    risk_score = riskdna["final_score"]

    context = req.context or {}
    context["risk_score"] = risk_score
    context["risk_tier"] = riskdna["risk_tier"]
    context["risk_breakdown"] = riskdna

    policy_input = {
        "tenant_id": tenant_id,
        "principal": req.principal,
        "intent": req.intent,
        "scopes": req.scopes,
        "ttl_seconds": req.ttl_seconds,
        "context": context,
        "policy_revision": "dev-1",
    }

    input_hash = hashlib.sha256(
        json.dumps(policy_input, sort_keys=True).encode()
    ).hexdigest()

    print("OPA INPUT →", json.dumps(policy_input, indent=2))

    policy_key = f"ztr:tenant:{tenant_id}:policy"
    anchor_key = f"ztr:tenant:{tenant_id}:policy_anchor"

    policy = r.hgetall(policy_key)
    anchor = r.get(anchor_key)

    digest = policy.get("digest")

    if digest != anchor:
        emit_event({
            "event_type": "control_plane_violation",
            "tenant_id": tenant_id,
            "digest": digest,
            "anchor": anchor,
            "timestamp": int(time.time()),
            "node_id": NODE_ID
        })

        publish_decision({
            "type": "AEGIS_SIGNAL",
            "signal": "CONTROL_PLANE_MISMATCH",
            "tenant_id": tenant_id,
            "severity": "HIGH",
            "action": "ISSUANCE_BLOCKED"
        })

        raise HTTPException(
            status_code=403,
            detail={
                "error": "CONTROL_PLANE_MISMATCH",
                "tenant_id": tenant_id,
                "digest": digest,
                "anchor": anchor,
                "layer": "control_plane_enforcement"
            }
        )

    opa_result = evaluate_issue_policy(policy_input)

    if not opa_result.get("allow"):

        event = {
            "event_type": "decision",
            "timestamp": int(time.time()),
            "tenant_id": tenant_id,
            "session_id": "N/A",
            "principal": req.principal,
            "intent": req.intent,
            "decision": "deny",
            "risk_score": context.get("risk_score"),
            "policy_revision": policy_input.get("policy_revision"),
            "metadata": {
                "source": "runtime",
                "stage": "issue"
            }
        }

        validate_decision_event(event)

        publish_decision(event)

        raise HTTPException(
            status_code=403,
            detail={
                "error": "policy_denied",
                "opa_result": opa_result,
                "risk_score": context.get("risk_score")
            }
        )

    effective_ttl = opa_result.get("ttl_seconds")

    # 🔧 FIX 3 — TTL CONSISTENCY CHECK
    if effective_ttl <= 0:
        raise HTTPException(
            status_code=500,
            detail="invalid_ttl_from_policy"
        )

    sid = str(uuid.uuid4())

    session_key = tenant_session_key(tenant_id, sid)
    session_index = tenant_session_index_key(tenant_id)

    # 🔧 FIX 1 + FIX 2 — SESSION STRUCTURE
    session_record = {
        "sid": sid,
        "tid": tenant_id,
        "ver": JWT_VERSION,
        "principal": req.principal,
        "intent": req.intent,
        "scopes": ",".join(req.scopes),
        "issued_at": now,
        "ttl": effective_ttl,
        "risk": json.dumps(riskdna)
    }

    pipe = r.pipeline()
    pipe.hset(session_key, mapping=session_record)
    pipe.expire(session_key, effective_ttl)
    pipe.sadd(session_index, sid)
    pipe.execute()

    # 🔧 FIX 4 — SESSION WRITE VALIDATION
    if not r.exists(session_key):
        raise HTTPException(
            status_code=500,
            detail="session_write_failed"
        )

    # 🔒 FIX 7 — INDEX CONSISTENCY CHECK
    if sid not in r.smembers(session_index):
        raise HTTPException(
            status_code=500,
            detail="session_index_inconsistency"
        )

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

    event = {
        "event_type": "decision",
        "timestamp": int(time.time()),
        "tenant_id": tenant_id,
        "session_id": sid,
        "principal": req.principal,
        "intent": req.intent,
        "decision": "allow",
        "risk_score": context.get("risk_score"),
        "policy_revision": policy_input.get("policy_revision"),
        "metadata": {
            "source": "runtime",
            "stage": "issue"
        }
    }

    validate_decision_event(event)

    publish_decision(event)

    return {
        "status": "issued",
        "tenant_id": tenant_id,
        "session_id": sid,
        "token": signed_token,
    }

# =========================================================
# 🔒 INTROSPECTION ENDPOINT — TELEMETRY + HASHING + CAE HOOK
# =========================================================

@tokens_router.post("/tokens/introspect")
async def introspect_token(payload: dict):

    token = payload.get("token")

    if not token:
        raise HTTPException(status_code=400, detail="missing_token")

    now = int(time.time())

    # -----------------------------------------------------
    # 🔐 TOKEN HASHING (NO RAW TOKEN EXPOSURE)
    # -----------------------------------------------------
    token_hash = hashlib.sha256(token.encode()).hexdigest()

    try:
        decoded = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=["HS256"],
            audience=JWT_AUDIENCE,
            issuer=JWT_ISSUER
        )
    except jwt.ExpiredSignatureError:

        publish_decision({
            "event_type": "introspection",
            "timestamp": now,
            "tenant_id": "unknown",
            "session_id": "unknown",
            "principal": "unknown",
            "intent": "token:introspect",
            "decision": "deny",
            "risk_score": 0,
            "policy_revision": "introspection",
            "metadata": {
                "stage": "introspect",
                "reason": "expired",
                "token_hash": token_hash
            }
        })

        return {"active": False, "reason": "expired"}

    except jwt.InvalidTokenError:

        publish_decision({
            "event_type": "introspection",
            "timestamp": now,
            "tenant_id": "unknown",
            "session_id": "unknown",
            "principal": "unknown",
            "intent": "token:introspect",
            "decision": "deny",
            "risk_score": 0,
            "policy_revision": "introspection",
            "metadata": {
                "stage": "introspect",
                "reason": "invalid",
                "token_hash": token_hash
            }
        })

        return {"active": False, "reason": "invalid"}

    tenant_id = decoded.get("tid")
    sid = decoded.get("sid")
    principal = decoded.get("sub")
    intent = decoded.get("intent")
    version = decoded.get("ver")

    if not tenant_id or not sid:

        publish_decision({
            "event_type": "introspection",
            "timestamp": now,
            "tenant_id": tenant_id or "unknown",
            "session_id": sid or "unknown",
            "principal": principal or "unknown",
            "intent": intent or "token:introspect",
            "decision": "deny",
            "risk_score": 0,
            "policy_revision": "introspection",
            "metadata": {
                "stage": "introspect",
                "reason": "malformed",
                "token_hash": token_hash
            }
        })

        return {"active": False, "reason": "malformed"}

    session_key = tenant_session_key(tenant_id, sid)
    session = r.hgetall(session_key)

    if not session:

        publish_decision({
            "event_type": "introspection",
            "timestamp": now,
            "tenant_id": tenant_id,
            "session_id": sid,
            "principal": principal,
            "intent": intent,
            "decision": "deny",
            "risk_score": 0,
            "policy_revision": "introspection",
            "metadata": {
                "stage": "introspect",
                "reason": "session_not_found",
                "token_hash": token_hash
            }
        })

        return {"active": False, "reason": "session_not_found"}

    if version != JWT_VERSION:

        publish_decision({
            "event_type": "introspection",
            "timestamp": now,
            "tenant_id": tenant_id,
            "session_id": sid,
            "principal": principal,
            "intent": intent,
            "decision": "deny",
            "risk_score": 0,
            "policy_revision": "introspection",
            "metadata": {
                "stage": "introspect",
                "reason": "version_mismatch",
                "token_hash": token_hash
            }
        })

        return {"active": False, "reason": "version_mismatch"}

    # -----------------------------------------------------
    # 🔒 CAE HOOK POINT (FUTURE REVOCATION / SIGNAL ENGINE)
    # -----------------------------------------------------
    # NOTE: DO NOT MODIFY — placeholder for CAE trigger integration
    cae_trigger = False

    # -----------------------------------------------------
    # ✅ SUCCESS PATH
    # -----------------------------------------------------
    publish_decision({
        "event_type": "introspection",
        "timestamp": now,
        "tenant_id": tenant_id,
        "session_id": sid,
        "principal": principal,
        "intent": intent,
        "decision": "allow",
        "risk_score": 0,
        "policy_revision": "introspection",
        "metadata": {
            "stage": "introspect",
            "token_hash": token_hash,
            "cae_trigger": cae_trigger
        }
    })

    return {
        "active": True,
        "tenant_id": tenant_id,
        "session_id": sid,
        "principal": principal,
        "scopes": decoded.get("scopes"),
        "intent": intent,
        "exp": decoded.get("exp")
    }
