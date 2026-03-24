# =========================================================
# opa_bridge.py — OPA Policy Re-Evaluation Bridge
# SecureTheCloud — Phase 5B-01 / Phase 7.5-03
#
# Called at Layer 5 of runtime policy evaluation.
# Fail-closed on every error path — never fail-open.
#
# Env vars:
#   OPA_URL         = http://localhost:8181
#   OPA_POLICY_PATH = /v1/data/ztr/introspect/allow
# =========================================================

import os
import time
import redis
from typing import Any

import httpx
import json

from fastapi import HTTPException
from policy_subscriber import get_cached_policy
from audit_chain import emit_event
from api.risk_engine import compute_risk_score

r = redis.from_url(
    os.environ["REDIS_URL"],
    decode_responses=True,
)

OPA_URL         = os.getenv("OPA_URL", "http://localhost:8181")
OPA_POLICY_PATH = os.getenv("OPA_POLICY_PATH", "/v1/data/ztr/introspect/allow")
OPA_TIMEOUT_S   = float(os.getenv("OPA_TIMEOUT_S", "2.0"))


def verify_projected_state(tenant_id: str):

    policy_ptr = r.hgetall(f"ztr:tenant:{tenant_id}:policy")
    redis_digest = policy_ptr.get("digest")

    if not redis_digest:
        emit_event(
            tenant_id=tenant_id,
            event_type="runtime.policy_missing",
            service="ztr-runtime",
            payload={"tenant_id": tenant_id}
        )
        raise HTTPException(
            status_code=500,
            detail="policy_state_missing"
        )

    anchor_key = f"ztr:tenant:{tenant_id}:policy_anchor"
    anchor_digest = r.get(anchor_key)

    if not anchor_digest:
        emit_event(
            tenant_id=tenant_id,
            event_type="runtime.anchor_missing",
            service="ztr-runtime",
            payload={"tenant_id": tenant_id}
        )
        raise HTTPException(
            status_code=500,
            detail="policy_anchor_missing"
        )

    if redis_digest != anchor_digest:

        emit_event(
            tenant_id=tenant_id,
            event_type="runtime.policy_tamper_detected",
            service="ztr-runtime",
            payload={
                "redis_digest": redis_digest,
                "anchor_digest": anchor_digest
            }
        )

        raise HTTPException(
            status_code=500,
            detail="policy_state_tampered"
        )


def evaluate_introspect_policy(
    *,
    principal: str,
    scopes: list[str],
    intent: str,
    tenant_id: str,
    policy_revision: str,
    context: dict[str, Any],
) -> dict[str, Any]:

    verify_projected_state(tenant_id)

    cached_policy = get_cached_policy(tenant_id) or {}

    merged_context = dict(context or {})
    if cached_policy:
        merged_context["cached_policy_version"] = cached_policy.get("version")
        merged_context["cached_policy_digest"] = cached_policy.get("digest")

    risk = compute_risk_score(
        tenant_id=tenant_id,
        principal=principal
    )

    input_payload = {
        "input": {
            "principal":       principal or "",
            "scopes":          scopes or [],
            "intent":          intent or "",
            "tenant_id":       tenant_id or "",
            "policy_revision": policy_revision or "",
            "context":         merged_context,
            "risk":            risk,
            "ts":              int(time.time()),
        }
    }

    url = OPA_URL.rstrip("/") + OPA_POLICY_PATH

    try:
        resp = httpx.post(
            url,
            json=input_payload,
            timeout=OPA_TIMEOUT_S,
        )
        resp.raise_for_status()
        body = resp.json()

    except httpx.TimeoutException:
        return {
            "allow":           False,
            "reason":          "opa_unavailable",
            "policy_revision": policy_revision,
            "cached_policy":   cached_policy or None,
        }

    except httpx.HTTPStatusError as exc:
        return {
            "allow":           False,
            "reason":          "opa_unavailable",
            "policy_revision": policy_revision,
            "detail":          str(exc),
            "cached_policy":   cached_policy or None,
        }

    except Exception as exc:
        return {
            "allow":           False,
            "reason":          "opa_error",
            "policy_revision": policy_revision,
            "detail":          str(exc),
            "cached_policy":   cached_policy or None,
        }

    if not isinstance(body, dict) or "result" not in body:
        return {
            "allow":           False,
            "reason":          "opa_bad_response",
            "policy_revision": policy_revision,
            "detail":          f"unexpected body: {str(body)[:200]}",
            "cached_policy":   cached_policy or None,
        }

    allowed = bool(body["result"])
    return {
        "allow":           allowed,
        "reason":          "opa_allow" if allowed else "opa_deny",
        "policy_revision": policy_revision,
        "cached_policy":   cached_policy or None,
    }


def evaluate_issue_policy(input_payload: dict) -> dict:
    tenant_id = str(input_payload.get("tenant_id", "")).strip()

    verify_projected_state(tenant_id)

    cached_policy = get_cached_policy(tenant_id) if tenant_id else None

    enriched_input = dict(input_payload)

    if "context" not in enriched_input:
        enriched_input["context"] = {}

    if cached_policy:
        enriched_input["cached_policy_version"] = cached_policy.get("version")
        enriched_input["cached_policy_digest"] = cached_policy.get("digest")

    principal = enriched_input.get("principal")

    risk = compute_risk_score(
        tenant_id=tenant_id,
        principal=principal
    )

    enriched_input["context"] = dict(enriched_input.get("context", {}))
    enriched_input["context"]["risk_score"] = risk

    print("OPA INPUT:", json.dumps(enriched_input, indent=2))

    url = OPA_URL.rstrip("/") + "/v1/data/ztr/issue/decision"

    try:
        resp = httpx.post(
            url,
            json={"input": enriched_input},
            timeout=OPA_TIMEOUT_S,
        )
        resp.raise_for_status()
        body = resp.json()

    except httpx.TimeoutException:
        return {
            "allow": False,
            "reason": "opa_unavailable",
            "cached_policy": cached_policy or None,
        }

    except httpx.HTTPStatusError as exc:
        return {
            "allow": False,
            "reason": "opa_unavailable",
            "detail": str(exc),
            "cached_policy": cached_policy or None,
        }

    except Exception as exc:
        return {
            "allow": False,
            "reason": "opa_error",
            "detail": str(exc),
            "cached_policy": cached_policy or None,
        }

    if not isinstance(body, dict) or "result" not in body:
        return {
            "allow": False,
            "reason": "opa_bad_response",
            "detail": f"unexpected body: {str(body)[:200]}",
            "cached_policy": cached_policy or None,
        }

    result = body.get("result", {})

    return {
        "allow": result.get("allow", False),
        "reason": "opa_allow" if result.get("allow") else "opa_deny",
        "obligations": result.get("obligations", []),
        "ttl_seconds": result.get("ttl_seconds"),
        "policy_revision": result.get("policy_revision"),
        "cached_policy": cached_policy or None,
    }
