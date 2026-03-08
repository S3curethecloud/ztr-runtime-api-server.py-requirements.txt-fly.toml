# =========================================================
# admin.py — Tenant + API Key Management
# SecureTheCloud — Phase 7.5
#
# Phase 5A-05: original tenant/key CRUD
# Phase 7 deltas:
#   7-01: Management Chain namespace (tenant_id="mgmt")
#   7-02: Dual-write sequencer — mgmt ledger first,
#         Redis mutation only if ledger write succeeds
#   7-03: Cross-link anchor emitted after Redis write
#
# Phase 7.5 deltas:
#   7.5-01: Projected state keys written on tenant creation
#           ztr:tenant:{id}:config  — versioned JSON blob
#           ztr:tenant:{id}:policy  — {version, digest}
#           ztr:tenant:{id}:status  — active|disabled
#   7.5-02: PUT /v1/admin/tenants/{tenant_id}/policy
#           Updates policy pointer, invalidates all tenant
#           tokens (TTL=0), publishes to policy_updates channel
#   7.5-02: PUT /v1/admin/tenants/{tenant_id}/status
#           Kill-switch: sets ztr:tenant:{id}:status = disabled
#
# Key naming convention — LOCKED:
#   All projected state keys use ztr:tenant:{id}:... prefix
#   consistent with existing runtime key namespace.
#
# Redis connection: LOCKED BASELINE
#   redis.from_url(os.environ["REDIS_URL"])
#   redis.from_url(os.environ["REDIS_AUDIT_URL"])  ← audit chain
#
# Pub/Sub channel: policy_updates
#   Payload: {"tenant_id": ..., "policy_version": ...,
#             "policy_digest": ..., "ts": ...}
# =========================================================

import hashlib
import json
import os
import secrets
import time
from typing import Optional

import redis
from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

from audit_chain import emit_event

# ---------------------------------------------------------
# Redis client — LOCKED BASELINE
# ---------------------------------------------------------
_r = redis.from_url(
    os.environ["REDIS_URL"],
    decode_responses=True,
)

# ---------------------------------------------------------
# Admin secret
# ---------------------------------------------------------
ADMIN_SECRET    = os.environ.get("ADMIN_SECRET", "")
POLICY_REVISION = os.getenv("POLICY_REVISION", "dev-1")

admin_router = APIRouter(prefix="/v1/admin", tags=["admin"])

MGMT_TENANT = "mgmt"


# ---------------------------------------------------------
# Auth dependency
# ---------------------------------------------------------
def _require_admin(x_stc_admin_secret: str = Header(None)) -> None:
    if not ADMIN_SECRET:
        raise HTTPException(status_code=503, detail="admin_not_configured")
    if not x_stc_admin_secret or x_stc_admin_secret != ADMIN_SECRET:
        raise HTTPException(status_code=403, detail="forbidden")


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


# ---------------------------------------------------------
# Phase 7-02 — Sequencer helper
# ---------------------------------------------------------
def _mgmt_emit(event_type: str, payload: dict) -> dict:
    return emit_event(
        tenant_id=MGMT_TENANT,
        event_type=event_type,
        service="ztr-admin",
        payload=payload,
    )


# ---------------------------------------------------------
# Phase 7-03 / 7.5 — Anchor helper
#
# Accepts explicit policy_version and policy_digest so the
# anchor always records the EFFECTIVE policy state for that
# specific mutation — not the static env POLICY_REVISION.
#
# Callers must pass the version/digest that was actually
# applied during the operation.
#
# Non-fatal: swallows exceptions, never rolls back Redis.
# ---------------------------------------------------------
def _tenant_anchor(
    tenant_id: str,
    mgmt_event_hash: str,
    operation: str,
    policy_version: str,
    policy_digest: str,
) -> None:
    try:
        emit_event(
            tenant_id=tenant_id,
            event_type="runtime.mgmt_anchor_observed",
            service="ztr-admin",
            payload={
                "mgmt_event_hash": mgmt_event_hash,
                "policy_version":  policy_version,
                "policy_digest":   policy_digest,
                "operation":       operation,
                "effective_ts":    int(time.time()),
            },
        )
    except Exception as exc:
        print(f"[WARN] mgmt_anchor emit failed for {tenant_id}: {exc}", flush=True)


# ---------------------------------------------------------
# Phase 7.5-02 — Token invalidation helper
#
# Scans all session/token keys for this tenant and sets
# TTL=0 (expires immediately). Global Revocation step.
# Non-fatal: logs on error.
# ---------------------------------------------------------
def _invalidate_tenant_tokens(tenant_id: str) -> int:
    count = 0
    try:
        for key in _r.scan_iter(f"ztr:{tenant_id}:session:*"):
            _r.expire(key, 0)
            count += 1
        for key in _r.scan_iter("auth:token:*"):
            raw = _r.get(key)
            if raw:
                try:
                    data = json.loads(raw)
                    if data.get("tenant_id") == tenant_id:
                        _r.expire(key, 0)
                        count += 1
                except Exception:
                    pass
    except Exception as exc:
        print(f"[WARN] token invalidation failed for {tenant_id}: {exc}", flush=True)
    return count


# ---------------------------------------------------------
# Phase 7.5-02 — Publish policy_updates notification
# Non-fatal.
# ---------------------------------------------------------
def _publish_policy_update(tenant_id: str, policy_version: str, policy_digest: str) -> None:
    try:
        message = json.dumps({
            "tenant_id":      tenant_id,
            "policy_version": policy_version,
            "policy_digest":  policy_digest,
            "ts":             int(time.time()),
        })
        _r.publish("policy_updates", message)
    except Exception as exc:
        print(f"[WARN] policy_updates publish failed for {tenant_id}: {exc}", flush=True)


# ---------------------------------------------------------
# Models
# ---------------------------------------------------------
class CreateTenantRequest(BaseModel):
    tenant_id: str
    label: str


class IssueKeyRequest(BaseModel):
    label: str


class UpdatePolicyRequest(BaseModel):
    policy_version: str
    policy_digest:  Optional[str] = None  # auto-computed if omitted


# ---------------------------------------------------------
# POST /v1/admin/tenants
#
# Phase 7.5-01: also writes projected state keys:
#   ztr:tenant:{id}:config  — full config blob
#   ztr:tenant:{id}:policy  — policy pointer hash
#   ztr:tenant:{id}:status  — "active"
#
# Anchor records POLICY_REVISION as the effective policy
# at creation time (correct — no tenant-specific policy
# exists yet at creation).
# ---------------------------------------------------------
@admin_router.post("/tenants", status_code=201)
def create_tenant(
    req: CreateTenantRequest,
    x_stc_admin_secret: str = Header(None),
):
    _require_admin(x_stc_admin_secret)

    tenant_id = req.tenant_id.strip().lower()
    if not tenant_id:
        raise HTTPException(status_code=400, detail="tenant_id required")

    meta_key = f"ztr:tenant:{tenant_id}:meta"

    if _r.exists(meta_key):
        raise HTTPException(status_code=409, detail="tenant_already_exists")

    now            = int(time.time())
    policy_version = POLICY_REVISION
    policy_digest  = _sha256(POLICY_REVISION)

    meta = {
        "tenant_id":  tenant_id,
        "label":      req.label,
        "created_at": now,
    }

    # 7-02: mgmt ledger FIRST — fail-closed
    try:
        mgmt_event = _mgmt_emit(
            event_type="admin.tenant_created",
            payload={
                "tenant_id":      tenant_id,
                "label":          req.label,
                "created_at":     now,
                "policy_version": policy_version,
                "policy_digest":  policy_digest,
            },
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"mgmt_ledger_write_failed: {exc}")

    # 7-02: Redis mutations only after ledger succeeds
    _r.set(meta_key, json.dumps(meta))

    # 7.5-01: Projected state keys — ztr:tenant:{id}:... namespace
    _r.set(
        f"ztr:tenant:{tenant_id}:config",
        json.dumps({
            "tenant_id":      tenant_id,
            "label":          req.label,
            "created_at":     now,
            "policy_version": policy_version,
            "version":        1,
        }),
    )
    _r.hset(
        f"ztr:tenant:{tenant_id}:policy",
        mapping={
            "version": policy_version,
            "digest":  policy_digest,
        },
    )
    _r.set(f"ztr:tenant:{tenant_id}:status", "active")

    # 7-03 / 7.5: Anchor records effective policy at creation
    _tenant_anchor(
        tenant_id,
        mgmt_event["event_hash"],
        "tenant_created",
        policy_version,
        policy_digest,
    )

    return {
        "status":          "created",
        "tenant_id":       tenant_id,
        "label":           req.label,
        "policy_version":  policy_version,
        "mgmt_event_hash": mgmt_event["event_hash"],
    }


# ---------------------------------------------------------
# GET /v1/admin/tenants/{tenant_id}/usage
#
# Retrieve tenant's usage stats for the current period
# ---------------------------------------------------------
@admin_router.get("/tenants/{tenant_id}/usage")
def get_tenant_usage(
    tenant_id: str,
    x_stc_admin_secret: str = Header(None),
):
    _require_admin(x_stc_admin_secret)

    tenant_id = tenant_id.strip().lower()
    period = current_period()

    usage = {
        "tokens_issued": int(_r.get(tenant_usage_key(tenant_id, period, "tokens_issued")) or 0),
        "policy_denied": int(_r.get(tenant_usage_key(tenant_id, period, "policy_denied")) or 0),
        "sessions_revoked": int(_r.get(tenant_usage_key(tenant_id, period, "sessions_revoked")) or 0),
    }

    return {
        "tenant_id": tenant_id,
        "period": period,
        "usage": usage
    }
