# =========================================================
# admin.py — Tenant + API Key Management
# SecureTheCloud — Phase 5A-05
#
# Mounted in server.py:
#   from admin import admin_router
#   app.include_router(admin_router)
#
# Protected by X-STC-Admin-Secret header.
# Completely separate from tenant API keys.
# ADMIN_SECRET env var must be set before deploy.
# =========================================================

import hashlib
import json
import os
import secrets
import time

import redis
from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

# ---------------------------------------------------------
# Redis client (shared connection config with server.py)
# ---------------------------------------------------------
REDIS_HOST     = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT     = int(os.getenv("REDIS_PORT", 6379))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", None)

_r = redis.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    password=REDIS_PASSWORD,
    decode_responses=True,
)

# ---------------------------------------------------------
# Admin secret (never an API key)
# ---------------------------------------------------------
ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "")

admin_router = APIRouter(prefix="/v1/admin", tags=["admin"])


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
# Models
# ---------------------------------------------------------
class CreateTenantRequest(BaseModel):
    tenant_id: str
    label: str


class IssueKeyRequest(BaseModel):
    label: str


# ---------------------------------------------------------
# POST /v1/admin/tenants — create tenant
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
    _r.set(meta_key, json.dumps(meta))

    return {
        "status":    "created",
        "tenant_id": tenant_id,
        "label":     req.label,
    }


# ---------------------------------------------------------
# POST /v1/admin/tenants/{tenant_id}/keys — issue API key
# The raw api_key is returned exactly once.
# Only the SHA-256 hash is stored.
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

    api_key    = secrets.token_urlsafe(32)
    key_hash   = _sha256(api_key)
    key_record = {
        "tenant_id":  tenant_id,
        "label":      req.label,
        "issued_at":  int(time.time()),
        "key_hash":   key_hash,
    }

    # Store hash → tenant_id (used by require_tenant_api_key in server.py)
    _r.set(f"ztr:apikey:{key_hash}", tenant_id)

    # Store key metadata (for listing/revocation)
    _r.set(f"ztr:tenant:{tenant_id}:key:{key_hash}", json.dumps(key_record))

    # Add to tenant's key index
    _r.rpush(f"ztr:tenant:{tenant_id}:keys", key_hash)

    return {
        "status":    "issued",
        "tenant_id": tenant_id,
        "label":     req.label,
        "key_hash":  key_hash,
        "api_key":   api_key,   # shown exactly once — not stored in plaintext
    }


# ---------------------------------------------------------
# DELETE /v1/admin/tenants/{tenant_id}/keys/{key_hash}
# Revoke an API key by its SHA-256 hash
# ---------------------------------------------------------
@admin_router.delete("/tenants/{tenant_id}/keys/{key_hash}", status_code=200)
def revoke_api_key(
    tenant_id: str,
    key_hash: str,
    x_stc_admin_secret: str = Header(None),
):
    _require_admin(x_stc_admin_secret)

    tenant_id = tenant_id.strip().lower()

    apikey_key = f"ztr:apikey:{key_hash}"
    meta_key   = f"ztr:tenant:{tenant_id}:key:{key_hash}"

    if not _r.exists(apikey_key):
        raise HTTPException(status_code=404, detail="key_not_found")

    # Verify the key belongs to this tenant
    stored_tenant = _r.get(apikey_key)
    if stored_tenant != tenant_id:
        raise HTTPException(status_code=403, detail="key_tenant_mismatch")

    _r.delete(apikey_key)
    _r.delete(meta_key)
    _r.lrem(f"ztr:tenant:{tenant_id}:keys", 0, key_hash)

    return {
        "status":    "revoked",
        "tenant_id": tenant_id,
        "key_hash":  key_hash,
    }


# ---------------------------------------------------------
# GET /v1/admin/tenants/{tenant_id}/keys — list key hashes
# Never returns raw api_key values — hashes only
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
        # Only include if still active (not revoked)
        if _r.exists(f"ztr:apikey:{kh}"):
            raw = _r.get(f"ztr:tenant:{tenant_id}:key:{kh}")
            if raw:
                keys.append(json.loads(raw))

    return {
        "tenant_id":  tenant_id,
        "active_keys": keys,
        "count":       len(keys),
    }
