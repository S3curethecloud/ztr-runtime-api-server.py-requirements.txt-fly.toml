# =========================================================
# opa_bridge.py — OPA Policy Re-Evaluation Bridge
# SecureTheCloud — Phase 5B-01
#
# Called at Layer 5 of /v1/introspect.
# Fail-closed on every error path — never fail-open.
#
# Env vars:
#   OPA_URL         = http://localhost:8181
#   OPA_POLICY_PATH = /v1/data/ztr/introspect/allow
# =========================================================

import os
import time
from typing import Any

import httpx

OPA_URL         = os.getenv("OPA_URL", "http://localhost:8181")
OPA_POLICY_PATH = os.getenv("OPA_POLICY_PATH", "/v1/data/ztr/introspect/allow")
OPA_TIMEOUT_S   = float(os.getenv("OPA_TIMEOUT_S", "2.0"))


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
    The caller (introspect) reads allow and raises HTTPException if False.
    """
    input_payload = {
        "input": {
            "principal":       principal       or "",
            "scopes":          scopes          or [],
            "intent":          intent          or "",
            "tenant_id":       tenant_id       or "",
            "policy_revision": policy_revision or "",
            "context":         context         or {},
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
        }

    except httpx.HTTPStatusError as exc:
        return {
            "allow":           False,
            "reason":          "opa_unavailable",
            "policy_revision": policy_revision,
            "detail":          str(exc),
        }

    except Exception as exc:
        return {
            "allow":           False,
            "reason":          "opa_error",
            "policy_revision": policy_revision,
            "detail":          str(exc),
        }

    # OPA response shape: { "result": true } or { "result": false }
    if not isinstance(body, dict) or "result" not in body:
        return {
            "allow":           False,
            "reason":          "opa_bad_response",
            "policy_revision": policy_revision,
            "detail":          f"unexpected body: {str(body)[:200]}",
        }

    allowed = bool(body["result"])
    return {
        "allow":           allowed,
        "reason":          "opa_allow" if allowed else "opa_deny",
        "policy_revision": policy_revision,
    }


def evaluate_issue_policy(input_payload: dict) -> dict:
    """
    Evaluate token issuance policy through OPA.

    Fail-closed rules:
      OPA allow=true   → allow issuance
      OPA allow=false  → deny issuance
      OPA unavailable  → deny issuance
      Any exception    → deny issuance

    This function MUST NOT raise.
    """

    url = OPA_URL.rstrip("/") + "/v1/data/ztr/issue/allow"

    try:
        resp = httpx.post(
            url,
            json={"input": input_payload},
            timeout=OPA_TIMEOUT_S,
        )
        resp.raise_for_status()
        body = resp.json()

    except Exception:
        return {
            "allow": False,
            "reason": "opa_unavailable",
        }

    if not isinstance(body, dict) or "result" not in body:
        return {
            "allow": False,
            "reason": "opa_bad_response",
        }

    allowed = bool(body["result"])

    return {
        "allow": allowed,
        "reason": "opa_allow" if allowed else "opa_deny",
    }
