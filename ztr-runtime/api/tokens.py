from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel

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

from core.schema import prepare_decision_event, SchemaValidationError
from core.aegis_identity.service import evaluate_identity_integrity

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

ZTR_JWT_SECRET = os.environ["ZTR_JWT_SECRET"]
if len(ZTR_JWT_SECRET.encode("utf-8")) < 32:
    raise RuntimeError("ZTR_JWT_SECRET must be at least 32 bytes for HS256 signing")
JWT_ISSUER = "ztr-runtime"
JWT_AUDIENCE = "securethecloud"
JWT_VERSION = "1.0"

POLICY_REVISION = os.getenv("POLICY_REVISION", "unknown")


class TokenIntrospectRequest(BaseModel):
    token: str


INTROSPECTION_WINDOW_RETENTION_SECONDS = int(
    os.getenv("INTROSPECTION_WINDOW_RETENTION_SECONDS", "86400")
)


def rolling_introspection_key(outcome: str) -> str:
    return f"metric:introspection_window:{outcome}"


def record_rolling_introspection_outcome(
    outcome: str,
    timestamp: int = None,
) -> None:
    ts = timestamp or int(time.time())
    key = rolling_introspection_key(outcome)
    member = f"{ts}:{uuid.uuid4()}"
    cutoff = ts - INTROSPECTION_WINDOW_RETENTION_SECONDS

    pipe = r.pipeline()
    pipe.zadd(key, {member: ts})
    pipe.zremrangebyscore(key, 0, cutoff)
    pipe.execute()


@tokens_router.post("/tokens/introspect")
async def introspect_token(
    req: TokenIntrospectRequest,
    tenant_id: str = Depends(require_tenant_api_key),
):
    now = int(time.time())

    try:
        payload = jwt.decode(
            req.token,
            ZTR_JWT_SECRET,
            algorithms=["HS256"],
            audience=JWT_AUDIENCE,
            issuer=JWT_ISSUER,
        )
    except jwt.ExpiredSignatureError:
        r.incr("metric:token_expired")
        r.incr("metric:introspect_inactive")
        record_rolling_introspection_outcome("expired", now)
        return {
            "active": False,
            "reason": "expired",
        }
    except jwt.InvalidTokenError:
        r.incr("metric:token_invalid")
        r.incr("metric:introspection_failure")
        record_rolling_introspection_outcome("invalid", now)
        raise HTTPException(status_code=401, detail="invalid_token")

    token_tenant_id = payload.get("tid")
    session_id = payload.get("sid")

    if token_tenant_id != tenant_id:
        r.incr("metric:introspect_inactive")
        record_rolling_introspection_outcome("inactive", now)
        return {
            "active": False,
            "reason": "tenant_mismatch",
        }

    if not session_id:
        r.incr("metric:introspection_failure")
        record_rolling_introspection_outcome("failure", now)
        raise HTTPException(status_code=401, detail="invalid_token")

    session_key = tenant_session_key(tenant_id, session_id)
    session_index = tenant_session_index_key(tenant_id)

    session_data = r.hgetall(session_key)
    ttl = r.ttl(session_key)

    if not session_data or ttl <= 0:
        r.srem(session_index, session_id)
        r.incr("metric:introspect_inactive")
        record_rolling_introspection_outcome("inactive", now)
        return {
            "active": False,
            "reason": "inactive",
            "tenant_id": tenant_id,
            "session_id": session_id,
        }

    scopes = _parse_json_list(session_data.get("scopes"))
    obligations = _parse_json_list(session_data.get("obligations"))

    r.incr("metric:introspect_success")
    record_rolling_introspection_outcome("success", now)

    return {
        "active": True,
        "tenant_id": tenant_id,
        "session_id": session_id,
        "principal": session_data.get("principal") or payload.get("sub"),
        "intent": session_data.get("intent") or payload.get("intent"),
        "scopes": scopes,
        "policy_revision": session_data.get("policy_revision") or POLICY_REVISION,
        "obligations": obligations,
        "decision": session_data.get("decision") or "allow",
        "expires_in": ttl,
        "issued_at": int(session_data.get("issued_at") or payload.get("iat") or 0),
        "exp": int(payload.get("exp") or 0),
        "ver": payload.get("ver") or JWT_VERSION,
    }


def current_period() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m")


def _build_runtime_actor_context(operator_id: str, principal: str) -> dict:
    normalized_operator = (operator_id or "").strip()

    if normalized_operator:
        return {
            "actor_type": "operator",
            "actor_id": normalized_operator,
            "actor_origin": "runtime_console",
        }

    return {
        "actor_type": "principal",
        "actor_id": principal or "unknown",
        "actor_origin": "runtime_api",
    }


def increment_tenant_usage(tenant_id: str, field: str, amount: int = 1):
    usage_key = tenant_usage_key(tenant_id, current_period())

    pipe = r.pipeline()
    pipe.hincrby(usage_key, field, amount)
    pipe.execute()


def _parse_json_list(raw_value):
    if not raw_value:
        return []

    try:
        value = json.loads(raw_value)
    except Exception:
        return []

    return value if isinstance(value, list) else []


def enforce_obligations(decision, request):
    obligations = decision.get("obligations", [])
    context = request.get("context", {})

    if "ROLE_MATCHED" in obligations:
        if request.get("principal") != "agent-demo":
            raise HTTPException(status_code=403, detail="obligation_denied")

    if "AMOUNT_OK" in obligations:
        if context.get("amount", 0) > 1000:
            raise HTTPException(status_code=403, detail="obligation_denied")

    if "RISK_OK" in obligations:
        if context.get("risk_score", 0) > 50:
            raise HTTPException(status_code=403, detail="obligation_denied")


def apply_policy_override(tenant_id, principal, policy_input):
    key = f"ztr:{tenant_id}:policy_override:{principal}"

    raw = r.get(key)
    if not raw:
        return policy_input

    try:
        data = json.loads(raw)
        override = data.get("override", {})
    except Exception:
        return policy_input

    action = override.get("action")

    if action == "INCREASE_RISK":
        policy_input["context"]["risk_score"] += override.get("risk_boost", 0)

    elif action == "REDUCE_TTL":
        policy_input["ttl_seconds"] = min(policy_input["ttl_seconds"], override.get("ttl_override", 120))

    elif action == "FORCE_DENY":
        policy_input["context"]["force_deny"] = True

    return policy_input


def get_recent_tenant_denials(tenant_id: str, window_seconds: int = 900) -> int:
    cutoff_ms = (int(time.time()) - window_seconds) * 1000
    count = 0

    pattern = f"ztr:{tenant_id}:audit:entry:*"

    for key in r.scan_iter(pattern):
        try:
            raw = r.get(key)
            if not raw:
                continue

            entry = json.loads(raw)
            ts_ms = int(entry.get("ts_ms") or 0)
            if ts_ms < cutoff_ms:
                continue

            event_type = str(entry.get("event_type") or "").lower()
            payload = entry.get("payload") if isinstance(entry.get("payload"), dict) else {}
            reason = str(payload.get("reason") or entry.get("reason") or "").lower()
            decision = str(payload.get("decision") or entry.get("decision") or "").lower()

            if (
                event_type == "runtime.token_denied"
                or decision == "deny"
                or reason == "policy_denied"
                or reason == "obligation_denied"
            ):
                count += 1
        except Exception:
            continue

    return count


def has_policy_drift(tenant_id: str, principal: str) -> bool:
    key = f"ztr:{tenant_id}:policy_override:{principal}"
    return bool(r.get(key))


@tokens_router.post("/tokens/issue")
async def issue_token(
    req: TokenIssueRequest,
    tenant_id: str = Depends(require_tenant_api_key),
    x_stc_operator: str = Header(None),
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

        recent_denials = get_recent_tenant_denials(tenant_id, window_seconds=900)
        policy_drift = has_policy_drift(tenant_id, req.principal)

        riskdna = compute_riskdna(
            principal=req.principal,
            intent=req.intent,
            nodes=nodes,
            context=req.context or {},
            recent_denials=recent_denials,
            policy_drift=policy_drift
        )

        context = req.context or {}

        identity_signal = evaluate_identity_integrity(
            redis_client=r,
            tenant_id=tenant_id,
            principal=req.principal,
            intent=req.intent,
            scopes=req.scopes,
            context=context,
            recent_denials=recent_denials,
            policy_drift=policy_drift,
        )

        context["aegis_identity"] = identity_signal
        context["risk_score"] = riskdna["final_score"] + int(
            identity_signal.get("risk_modifier", 0)
        )

        policy_input = {
            "tenant_id": tenant_id,
            "principal": req.principal,
            "intent": req.intent,
            "scopes": req.scopes,
            "ttl_seconds": req.ttl_seconds,
            "context": context,
            "policy_revision": POLICY_REVISION,
        }

        policy_input = apply_policy_override(tenant_id, req.principal, policy_input)

        opa_result = evaluate_issue_policy(policy_input)

        # ✅ REQUIRED DEBUG (OPA VISIBILITY)
        print("OPA RESULT:", opa_result)
        print("POLICY INPUT:", policy_input)

        if not opa_result.get("allow"):

            decision_event = {
                "event_type": "decision",
                "timestamp": now,
                "tenant_id": tenant_id,
                "session_id": None,
                "principal": req.principal,
                "intent": req.intent,
                "decision": "deny",
                "risk_score": context["risk_score"],
                "policy_revision": POLICY_REVISION,
                "metadata": {
                    "source": "tokens",
                    "stage": "deny"
                }
            }

            try:
                decision_event = prepare_decision_event(decision_event)
            except SchemaValidationError as e:
                raise HTTPException(status_code=500, detail=str(e))

            print("decision_event", decision_event)
            r.incr("metric:policy_denied")
            increment_tenant_usage(tenant_id, "policy_denied")
            publish_decision(decision_event)

            emit_event(
                event_type="runtime.token_denied",
                service="tokens",
                tenant_id=tenant_id,
                correlation_id=str(now),
                payload={
                    "principal": req.principal,
                    "intent": req.intent,
                    "risk_score": context["risk_score"],
                    "policy_revision": POLICY_REVISION,
                    "node_id": NODE_ID,
                    "decision": "deny",
                    "reason": "policy_denied",
                    **_build_runtime_actor_context(x_stc_operator, req.principal),
                }
            )

            raise HTTPException(status_code=403, detail="policy_denied")

        try:
            enforce_obligations(opa_result, policy_input)
        except HTTPException:
            r.incr("metric:policy_denied")
            increment_tenant_usage(tenant_id, "policy_denied")

            decision_event = {
                "event_type": "decision",
                "timestamp": now,
                "tenant_id": tenant_id,
                "session_id": None,
                "principal": req.principal,
                "intent": req.intent,
                "decision": "deny",
                "risk_score": context["risk_score"],
                "policy_revision": POLICY_REVISION,
                "metadata": {
                    "source": "tokens",
                    "stage": "obligation_deny"
                }
            }

            try:
                decision_event = prepare_decision_event(decision_event)
            except SchemaValidationError as e:
                raise HTTPException(status_code=500, detail=str(e))

            print("decision_event", decision_event)
            publish_decision(decision_event)

            emit_event(
                event_type="runtime.token_denied",
                service="tokens",
                tenant_id=tenant_id,
                correlation_id=str(now),
                payload={
                    "principal": req.principal,
                    "intent": req.intent,
                    "risk_score": context["risk_score"],
                    "policy_revision": POLICY_REVISION,
                    "node_id": NODE_ID,
                    "decision": "deny",
                    "reason": "obligation_denied",
                    **_build_runtime_actor_context(x_stc_operator, req.principal),
                }
            )

            raise HTTPException(status_code=403, detail="obligation_denied")

        effective_ttl = opa_result.get("ttl_seconds") or req.ttl_seconds
        obligations = opa_result.get("obligations", [])
        if not isinstance(obligations, list):
            obligations = []

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
            "issued_at": str(now),
            "ttl": str(effective_ttl),
            "risk": json.dumps({
                **riskdna,
                "identity_integrity": identity_signal,
                "final_score": context["risk_score"],
            }),
            "policy_revision": POLICY_REVISION,
            "obligations": json.dumps(obligations),
            "decision": "allow"
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
            ZTR_JWT_SECRET,
            algorithm="HS256"
        )

        decision_event = {
            "event_type": "decision",
            "timestamp": now,
            "tenant_id": tenant_id,
            "session_id": sid,
            "principal": req.principal,
            "intent": req.intent,
            "decision": "allow",
            "risk_score": context["risk_score"],
            "policy_revision": POLICY_REVISION,
            "metadata": {
                "source": "tokens",
                "stage": "issue"
            }
        }

        try:
            decision_event = prepare_decision_event(decision_event)
        except SchemaValidationError as e:
            raise HTTPException(status_code=500, detail=str(e))

        print("decision_event", decision_event)
        publish_decision(decision_event)

        r.incr("metric:tokens_issued")
        r.incr("metric:policy_allowed")
        increment_tenant_usage(tenant_id, "tokens_issued")
        emit_event(
            event_type="runtime.token_issued",
            service="tokens",
            tenant_id=tenant_id,
            correlation_id=sid,
            payload={
                "principal": req.principal,
                "intent": req.intent,
                "session_id": sid,
                "scopes": req.scopes,
                "risk_score": context["risk_score"],
                "policy_revision": POLICY_REVISION,
                "node_id": NODE_ID,
                "decision": "allow",
                **_build_runtime_actor_context(x_stc_operator, req.principal),
            }
        )

        return {
            "status": "issued",
            "tenant_id": tenant_id,
            "session_id": sid,
            "token": signed_token,
            "expires_in": effective_ttl,
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
