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

from fastapi import HTTPException
from policy_subscriber import get_cached_policy
from audit_chain import emit_event

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
        return

    # fetch last mgmt anchor event for tenant
    anchor = r.get(f"ztr:tenant:{tenant_id}:last_anchor_digest")

    if anchor and anchor != redis_digest:

        emit_event(
            tenant_id=tenant_id,
            event_type="runtime.tamper_suspected",
            service="ztr-runtime",
            payload={
                "redis_digest": redis_digest,
                "anchor_digest": anchor
            }
        )

        raise HTTPException(
            status_code=500,
            detail="policy_state_tamper_detected"
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
    """
    Re-evaluate the OPA policy at every introspection boundary.

    Fail-closed table — every non-allow path returns allow=False:
      OPA allow=true   → { allow: True,  reason: "opa_allow" }
      OPA allow=false  → { allow: False, reason: "opa_deny" }
      Timeout          → { allow: False, reason: "opa_unavailable" }
      Connection error → { allow: False, reason: "opa_unavailable" }
      Any exception    → { allow: False, reason: "opa_error" }
      Unexpected shape → { allow: False, reason: "opa_bad_response" }

    This function MUST NOT raise. It always returns a dict.
    """

    verify_projected_state(tenant_id)

    cached_policy = get_cached_policy(tenant_id) or {}

    merged_context = dict(context or {})
    if cached_policy:
        merged_context["cached_policy_version"] = cached_policy.get("version")
        merged_context["cached_policy_digest"] = cached_policy.get("digest")

    input_payload = {
        "input": {
            "principal":       principal or "",
            "scopes":          scopes or [],
            "intent":          intent or "",
            "tenant_id":       tenant_id or "",
            "policy_revision": policy_revision or "",
            "context":         merged_context,
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
    """
    Evaluate token issuance policy through OPA.

    Fail-closed rules:
      OPA allow=true   → allow issuance
      OPA allow=false  → deny issuance
      OPA unavailable  → deny issuance
      Any exception    → deny issuance
    """

    tenant_id = str(input_payload.get("tenant_id", "")).strip()

    verify_projected_state(tenant_id)

    cached_policy = get_cached_policy(tenant_id) if tenant_id else None

    enriched_input = dict(input_payload)
    if cached_policy:
        enriched_input["cached_policy_version"] = cached_policy.get("version")
        enriched_input["cached_policy_digest"] = cached_policy.get("digest")

    url = OPA_URL.rstrip("/") + "/v1/data/ztr/issue/allow"

    try:
        resp = httpx.post(
            url,
            json={"input": enriched_input},
            timeout=OPA_TIMEOUT_S,
        )
        resp.raise_for_status()
        body = resp.json()

    except Exception:
        return {
            "allow": False,
            "reason": "opa_unavailable",
            "cached_policy": cached_policy or None,
        }

    if not isinstance(body, dict) or "result" not in body:
        return {
            "allow": False,
            "reason": "opa_bad_response",
            "cached_policy": cached_policy or None,
        }

    allowed = bool(body["result"])

    return {
        "allow": allowed,
        "reason": "opa_allow" if allowed else "opa_deny",
        "cached_policy": cached_policy or None,
    }
