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
# PUT /v1/admin/tenants/{tenant_id}/policy
#
# Phase 7.5-02: Policy update flow:
#   1. mgmt ledger write
#   2. update ztr:tenant:{id}:policy hash
#   3. invalidate all tenant tokens (TTL=0)
#   4. publish to policy_updates channel
#   5. tenant anchor — records the ACTUAL updated version/digest
# ---------------------------------------------------------
@admin_router.put("/tenants/{tenant_id}/policy", status_code=200)
def update_tenant_policy(
    tenant_id: str,
    req: UpdatePolicyRequest,
    x_stc_admin_secret: str = Header(None),
):
    _require_admin(x_stc_admin_secret)

    tenant_id = tenant_id.strip().lower()
    meta_key  = f"ztr:tenant:{tenant_id}:meta"

    if not _r.exists(meta_key):
        raise HTTPException(status_code=404, detail="tenant_not_found")

    # Use provided digest or compute from version
    policy_version = req.policy_version
    policy_digest  = req.policy_digest or _sha256(req.policy_version)

    # 7-02 sequencer: mgmt ledger FIRST
    try:
        mgmt_event = _mgmt_emit(
            event_type="admin.policy_updated",
            payload={
                "tenant_id":      tenant_id,
                "policy_version": policy_version,
                "policy_digest":  policy_digest,
                "updated_at":     int(time.time()),
            },
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"mgmt_ledger_write_failed: {exc}")

    # Update projected policy pointer
    _r.hset(
        f"ztr:tenant:{tenant_id}:policy",
        mapping={
            "version": policy_version,
            "digest":  policy_digest,
        },
    )

    # 7.5-02: Invalidate all tokens for this tenant
    invalidated = _invalidate_tenant_tokens(tenant_id)

    # 7.5-02: Publish to policy_updates channel
    _publish_policy_update(tenant_id, policy_version, policy_digest)

    # 7.5: Anchor records the ACTUAL updated policy version/digest
    _tenant_anchor(
        tenant_id,
        mgmt_event["event_hash"],
        "policy_updated",
        policy_version,
        policy_digest,
    )

    return {
        "status":             "policy_updated",
        "tenant_id":          tenant_id,
        "policy_version":     policy_version,
        "policy_digest":      policy_digest,
        "tokens_invalidated": invalidated,
        "mgmt_event_hash":    mgmt_event["event_hash"],
    }


# ---------------------------------------------------------
# PUT /v1/admin/tenants/{tenant_id}/status
#
# Kill-switch: enable or disable a tenant.
# Sets ztr:tenant:{id}:status = active|disabled
# If disabling: also invalidates all tokens and publishes.
#
# Anchor records the current effective tenant policy pointer
# so auditors can prove which policy was active at the moment
# of the status change.
# ---------------------------------------------------------
@admin_router.put("/tenants/{tenant_id}/status", status_code=200)
def update_tenant_status(
    tenant_id: str,
    status: str,  # query param: ?status=active|disabled
    x_stc_admin_secret: str = Header(None),
):
    _require_admin(x_stc_admin_secret)

    tenant_id = tenant_id.strip().lower()

    if status not in ("active", "disabled"):
        raise HTTPException(status_code=400, detail="status must be active or disabled")

    meta_key = f"ztr:tenant:{tenant_id}:meta"
    if not _r.exists(meta_key):
        raise HTTPException(status_code=404, detail="tenant_not_found")

    # Read current effective policy pointer for this tenant
    policy_ptr    = _r.hgetall(f"ztr:tenant:{tenant_id}:policy")
    policy_version = policy_ptr.get("version", POLICY_REVISION)
    policy_digest  = policy_ptr.get("digest", _sha256(POLICY_REVISION))

    # mgmt ledger FIRST
    try:
        mgmt_event = _mgmt_emit(
            event_type="admin.tenant_status_changed",
            payload={
                "tenant_id":      tenant_id,
                "status":         status,
                "policy_version": policy_version,
                "policy_digest":  policy_digest,
                "changed_at":     int(time.time()),
            },
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"mgmt_ledger_write_failed: {exc}")

    _r.set(f"ztr:tenant:{tenant_id}:status", status)

    invalidated = 0
    if status == "disabled":
        invalidated = _invalidate_tenant_tokens(tenant_id)
        _publish_policy_update(tenant_id, policy_version, policy_digest)

    # Anchor records effective policy version at moment of status change
    _tenant_anchor(
        tenant_id,
        mgmt_event["event_hash"],
        f"status_{status}",
        policy_version,
        policy_digest,
    )

    return {
        "status":             "updated",
        "tenant_id":          tenant_id,
        "tenant_status":      status,
        "tokens_invalidated": invalidated,
        "mgmt_event_hash":    mgmt_event["event_hash"],
    }


# ---------------------------------------------------------
# POST /v1/admin/tenants/{tenant_id}/keys
# ---------------------------------------------------------
@admin_router.post("/tenants/{tenant_id}/keys", status_code=201)
def issue_api_key(
    tenant_id: str,
    req: IssueKeyRequest,
    x_stc_admin_secret: str = Header(None),
):
    _require_admin(x_stc_admin_secret)

    tenant_id = tenant_id.strip().lower()
    meta_key  = f"ztr:tenant:{tenant_id}:meta"

    if not _r.exists(meta_key):
        raise HTTPException(status_code=404, detail="tenant_not_found")

    api_key   = secrets.token_urlsafe(32)
    key_hash  = _sha256(api_key)
    issued_at = int(time.time())
    key_record = {
        "tenant_id": tenant_id,
        "label":     req.label,
        "issued_at": issued_at,
        "key_hash":  key_hash,
    }

    # Read current effective policy pointer for anchor
    policy_ptr     = _r.hgetall(f"ztr:tenant:{tenant_id}:policy")
    policy_version = policy_ptr.get("version", POLICY_REVISION)
    policy_digest  = policy_ptr.get("digest", _sha256(POLICY_REVISION))

    try:
        mgmt_event = _mgmt_emit(
            event_type="admin.api_key_issued",
            payload={
                "tenant_id":      tenant_id,
                "label":          req.label,
                "key_hash":       key_hash,
                "issued_at":      issued_at,
                "policy_version": policy_version,
            },
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"mgmt_ledger_write_failed: {exc}")

    _r.set(f"ztr:apikey:{key_hash}", tenant_id)
    _r.set(f"ztr:tenant:{tenant_id}:key:{key_hash}", json.dumps(key_record))
    _r.rpush(f"ztr:tenant:{tenant_id}:keys", key_hash)

    _tenant_anchor(
        tenant_id,
        mgmt_event["event_hash"],
        "api_key_issued",
        policy_version,
        policy_digest,
    )

    return {
        "status":          "issued",
        "tenant_id":       tenant_id,
        "label":           req.label,
        "key_hash":        key_hash,
        "api_key":         api_key,
        "mgmt_event_hash": mgmt_event["event_hash"],
    }


# ---------------------------------------------------------
# DELETE /v1/admin/tenants/{tenant_id}/keys/{key_hash}
# ---------------------------------------------------------
@admin_router.delete("/tenants/{tenant_id}/keys/{key_hash}", status_code=200)
def revoke_api_key(
    tenant_id: str,
    key_hash: str,
    x_stc_admin_secret: str = Header(None),
):
    _require_admin(x_stc_admin_secret)

    tenant_id  = tenant_id.strip().lower()
    apikey_key = f"ztr:apikey:{key_hash}"
    meta_key   = f"ztr:tenant:{tenant_id}:key:{key_hash}"

    if not _r.exists(apikey_key):
        raise HTTPException(status_code=404, detail="key_not_found")

    stored_tenant = _r.get(apikey_key)
    if stored_tenant != tenant_id:
        raise HTTPException(status_code=403, detail="key_tenant_mismatch")

    # Read current effective policy pointer for anchor
    policy_ptr     = _r.hgetall(f"ztr:tenant:{tenant_id}:policy")
    policy_version = policy_ptr.get("version", POLICY_REVISION)
    policy_digest  = policy_ptr.get("digest", _sha256(POLICY_REVISION))

    try:
        mgmt_event = _mgmt_emit(
            event_type="admin.api_key_revoked",
            payload={
                "tenant_id":  tenant_id,
                "key_hash":   key_hash,
                "revoked_at": int(time.time()),
            },
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"mgmt_ledger_write_failed: {exc}")

    _r.delete(apikey_key)
    _r.delete(meta_key)
    _r.lrem(f"ztr:tenant:{tenant_id}:keys", 0, key_hash)

    _tenant_anchor(
        tenant_id,
        mgmt_event["event_hash"],
        "api_key_revoked",
        policy_version,
        policy_digest,
    )

    return {
        "status":          "revoked",
        "tenant_id":       tenant_id,
        "key_hash":        key_hash,
        "mgmt_event_hash": mgmt_event["event_hash"],
    }


# ---------------------------------------------------------
# GET /v1/admin/tenants/{tenant_id}/keys
# Read-only — no sequencer needed
# ---------------------------------------------------------
@admin_router.get("/tenants/{tenant_id}/keys")
def list_api_keys(
    tenant_id: str,
    x_stc_admin_secret: str = Header(None),
):
    _require_admin(x_stc_admin_secret)

    tenant_id = tenant_id.strip().lower()
    hashes    = _r.lrange(f"ztr:tenant:{tenant_id}:keys", 0, -1)

    keys = []
    for kh in hashes:
        if _r.exists(f"ztr:apikey:{kh}"):
            raw = _r.get(f"ztr:tenant:{tenant_id}:key:{kh}")
            if raw:
                keys.append(json.loads(raw))

    return {
        "tenant_id":   tenant_id,
        "active_keys": keys,
        "count":       len(keys),
    }


# ---------------------------------------------------------
# GET /v1/admin/tenants/{tenant_id}/state
#
# Returns projected state for Bridge/Shield consumption.
# Read-only — no sequencer needed.
# Keys returned use locked ztr:tenant:{id}:... namespace.
# ---------------------------------------------------------
@admin_router.get("/tenants/{tenant_id}/state")
def get_tenant_state(
    tenant_id: str,
    x_stc_admin_secret: str = Header(None),
):
    _require_admin(x_stc_admin_secret)

    tenant_id = tenant_id.strip().lower()

    config = _r.get(f"ztr:tenant:{tenant_id}:config")
    policy = _r.hgetall(f"ztr:tenant:{tenant_id}:policy")
    status = _r.get(f"ztr:tenant:{tenant_id}:status")

    if not config and not policy and not status:
        raise HTTPException(status_code=404, detail="tenant_not_found")

    return {
        "tenant_id": tenant_id,
        "config":    json.loads(config) if config else None,
        "policy":    policy or None,
        "status":    status or None,
    }
