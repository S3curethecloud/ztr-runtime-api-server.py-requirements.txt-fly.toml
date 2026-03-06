# =========================================================
# admin.py — Tenant + API Key Management
# SecureTheCloud — Phase 7
#
# Phase 5A-05: original tenant/key CRUD
# Phase 7 deltas:
#   7-01: Management Chain namespace (tenant_id="mgmt")
#   7-02: Dual-write sequencer — mgmt ledger first,
#         Redis mutation only if ledger write succeeds
#   7-03: Cross-link anchor emitted after Redis write
#
# Sequencer pattern per mutation:
#   1. emit_event(tenant_id="mgmt", event_type=...)  ← ledger first
#   2. Apply Redis mutation
#   3. emit_event(tenant_id=tenant_id,
#                 event_type="runtime.mgmt_anchor_observed")
#
# Fail-closed: if mgmt ledger write raises, Redis write is
# skipped and HTTP 500 is returned.
# =========================================================

import hashlib
import json
import os
import secrets
import time

import redis
from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

from audit_chain import emit_event

# ---------------------------------------------------------
# Redis client
# ---------------------------------------------------------
REDIS_HOST     = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT     = int(os.getenv("REDIS_PORT", 6379))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", None)

_r = redis.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    username="default",
    password=REDIS_PASSWORD,
    decode_responses=True,
)

# ---------------------------------------------------------
# Admin secret
# ---------------------------------------------------------
ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "")

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
# Phase 7-03 — Anchor helper
# Non-fatal: swallows exceptions, never rolls back Redis.
# ---------------------------------------------------------
def _tenant_anchor(tenant_id: str, mgmt_event_hash: str, operation: str) -> None:
    try:
        emit_event(
            tenant_id=tenant_id,
            event_type="runtime.mgmt_anchor_observed",
            service="ztr-admin",
            payload={
                "mgmt_event_hash": mgmt_event_hash,
                "policy_version":  POLICY_REVISION,
                "policy_digest":   _sha256(POLICY_REVISION),
                "operation":       operation,
                "effective_ts":    int(time.time()),
            },
        )
    except Exception as exc:
        print(f"[WARN] mgmt_anchor emit failed for {tenant_id}: {exc}", flush=True)


# ---------------------------------------------------------
# Models
# ---------------------------------------------------------
class CreateTenantRequest(BaseModel):
    tenant_id: str
    label: str


class IssueKeyRequest(BaseModel):
    label: str


# ---------------------------------------------------------
# POST /v1/admin/tenants
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

    meta = {
        "tenant_id":  tenant_id,
        "label":      req.label,
        "created_at": int(time.time()),
    }

    try:
        mgmt_event = _mgmt_emit(
            event_type="admin.tenant_created",
            payload={"tenant_id": tenant_id, "label": req.label, "created_at": meta["created_at"]},
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"mgmt_ledger_write_failed: {exc}")

    _r.set(meta_key, json.dumps(meta))

    _tenant_anchor(tenant_id, mgmt_event["event_hash"], "tenant_created")

    return {
        "status":          "created",
        "tenant_id":       tenant_id,
        "label":           req.label,
        "mgmt_event_hash": mgmt_event["event_hash"],
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

    try:
        mgmt_event = _mgmt_emit(
            event_type="admin.api_key_issued",
            payload={"tenant_id": tenant_id, "label": req.label, "key_hash": key_hash, "issued_at": issued_at},
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"mgmt_ledger_write_failed: {exc}")

    _r.set(f"ztr:apikey:{key_hash}", tenant_id)
    _r.set(f"ztr:tenant:{tenant_id}:key:{key_hash}", json.dumps(key_record))
    _r.rpush(f"ztr:tenant:{tenant_id}:keys", key_hash)

    _tenant_anchor(tenant_id, mgmt_event["event_hash"], "api_key_issued")

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

    try:
        mgmt_event = _mgmt_emit(
            event_type="admin.api_key_revoked",
            payload={"tenant_id": tenant_id, "key_hash": key_hash, "revoked_at": int(time.time())},
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"mgmt_ledger_write_failed: {exc}")

    _r.delete(apikey_key)
    _r.delete(meta_key)
    _r.lrem(f"ztr:tenant:{tenant_id}:keys", 0, key_hash)

    _tenant_anchor(tenant_id, mgmt_event["event_hash"], "api_key_revoked")

    return {
        "status":          "revoked",
        "tenant_id":       tenant_id,
        "key_hash":        key_hash,
        "mgmt_event_hash": mgmt_event["event_hash"],
    }


# ---------------------------------------------------------
# GET /v1/admin/tenants/{tenant_id}/keys
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
