# =========================================================
# admin.py — Tenant + API Key Management
# SecureTheCloud — Phase 8
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
#
# Phase 8 delta:
#   One-call tenant provisioning endpoint
# =========================================================

import hashlib
import json
import os
import secrets
import time
import datetime
from typing import Optional

import redis
from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

from audit_chain import emit_event
from api.redis_keys import tenant_usage_key


# ---------------------------------------------------------
# Redis client
# ---------------------------------------------------------
_r = redis.from_url(
    os.environ["REDIS_URL"],
    decode_responses=True,
)


# ---------------------------------------------------------
# Billing configuration
# ---------------------------------------------------------
TOKEN_PRICE_CENTS = int(os.getenv("TOKEN_PRICE_CENTS", "1"))


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
# Helper to get current billing period
# ---------------------------------------------------------
def current_period() -> str:
    return datetime.datetime.utcnow().strftime("%Y-%m")


# ---------------------------------------------------------
# Management ledger emit
# ---------------------------------------------------------
def _mgmt_emit(event_type: str, payload: dict) -> dict:

    return emit_event(
        tenant_id=MGMT_TENANT,
        event_type=event_type,
        service="ztr-admin",
        payload=payload,
    )


# ---------------------------------------------------------
# Anchor helper
# ---------------------------------------------------------
def _tenant_anchor(
    tenant_id: str,
    mgmt_event_hash: str,
    operation: str,
    policy_version: str = "",
    policy_digest: str = "",
) -> None:

    emit_event(
        tenant_id=tenant_id,
        event_type="runtime.mgmt_anchor_observed",
        service="ztr-admin",
        payload={
            "mgmt_event_hash": mgmt_event_hash,
            "policy_version": policy_version,
            "policy_digest": policy_digest,
            "operation": operation,
            "effective_ts": int(time.time()),
        },
    )


# ---------------------------------------------------------
# Models
# ---------------------------------------------------------
class CreateTenantRequest(BaseModel):
    tenant_id: str
    label: str


class ProvisionTenantRequest(BaseModel):
    tenant_id: str
    label: str
    key_label: str = "root"


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

    meta_key = f"ztr:tenant:{tenant_id}:meta"

    if _r.exists(meta_key):
        raise HTTPException(status_code=409, detail="tenant_already_exists")

    now = int(time.time())

    policy_version = POLICY_REVISION
    policy_digest = _sha256(policy_version)

    meta = {
        "tenant_id": tenant_id,
        "label": req.label,
        "created_at": now,
    }

    mgmt_event = _mgmt_emit(
        "admin.tenant_created",
        {
            "tenant_id": tenant_id,
            "label": req.label,
            "created_at": now,
            "policy_version": policy_version,
            "policy_digest": policy_digest,
        },
    )

    _r.set(meta_key, json.dumps(meta))

    _tenant_anchor(
        tenant_id,
        mgmt_event["event_hash"],
        "tenant_created",
        policy_version,
        policy_digest,
    )

    return {
        "status": "created",
        "tenant_id": tenant_id,
        "label": req.label,
        "policy_version": policy_version,
        "mgmt_event_hash": mgmt_event["event_hash"],
    }


# ---------------------------------------------------------
# POST /v1/admin/provision
# ---------------------------------------------------------
@admin_router.post("/provision", status_code=201)
def provision_tenant(
    req: ProvisionTenantRequest,
    x_stc_admin_secret: str = Header(None),
):

    _require_admin(x_stc_admin_secret)

    tenant_id = req.tenant_id.strip().lower()

    meta_key = f"ztr:tenant:{tenant_id}:meta"

    if _r.exists(meta_key):
        raise HTTPException(status_code=409, detail="tenant_already_exists")

    created_at = int(time.time())

    meta = {
        "tenant_id": tenant_id,
        "label": req.label,
        "created_at": created_at,
    }

    api_key = secrets.token_urlsafe(32)

    key_hash = _sha256(api_key)

    key_record = {
        "tenant_id": tenant_id,
        "label": req.key_label,
        "issued_at": created_at,
        "key_hash": key_hash,
    }

    mgmt_event = _mgmt_emit(
        "admin.tenant_provisioned",
        {
            "tenant_id": tenant_id,
            "label": req.label,
            "key_label": req.key_label,
            "key_hash": key_hash,
            "created_at": created_at,
        },
    )

    pipe = _r.pipeline()

    pipe.set(meta_key, json.dumps(meta))
    pipe.set(f"ztr:apikey:{key_hash}", tenant_id)
    pipe.set(f"ztr:tenant:{tenant_id}:key:{key_hash}", json.dumps(key_record))
    pipe.rpush(f"ztr:tenant:{tenant_id}:keys", key_hash)

    pipe.execute()

    _tenant_anchor(
        tenant_id,
        mgmt_event["event_hash"],
        "tenant_provisioned",
    )

    return {
        "status": "provisioned",
        "tenant_id": tenant_id,
        "api_key": api_key,
        "key_hash": key_hash,
        "mgmt_event_hash": mgmt_event["event_hash"],
    }


# ---------------------------------------------------------
# GET /v1/admin/tenants/{tenant_id}/usage
# ---------------------------------------------------------
@admin_router.get("/tenants/{tenant_id}/usage")
def get_tenant_usage(
    tenant_id: str,
    x_stc_admin_secret: str = Header(None),
):

    _require_admin(x_stc_admin_secret)

    period = current_period()

    return {
        "tenant_id": tenant_id,
        "period": period,
        "tokens_issued": int(_r.get(tenant_usage_key(tenant_id, period, "tokens_issued")) or 0),
        "policy_denied": int(_r.get(tenant_usage_key(tenant_id, period, "policy_denied")) or 0),
        "sessions_revoked": int(_r.get(tenant_usage_key(tenant_id, period, "sessions_revoked")) or 0),
    }


# ---------------------------------------------------------
# GET /v1/admin/tenants/{tenant_id}/billing
# ---------------------------------------------------------
@admin_router.get("/tenants/{tenant_id}/billing")
def get_tenant_billing(
    tenant_id: str,
    x_stc_admin_secret: str = Header(None),
):

    _require_admin(x_stc_admin_secret)

    period = current_period()

    tokens = int(_r.get(tenant_usage_key(tenant_id, period, "tokens_issued")) or 0)

    amount = tokens * TOKEN_PRICE_CENTS

    return {
        "tenant_id": tenant_id,
        "period": period,
        "tokens_issued": tokens,
        "unit_price_cents": TOKEN_PRICE_CENTS,
        "amount_cents": amount,
    }


# ---------------------------------------------------------
# GET /v1/admin/tenants/{tenant_id}/summary
# ---------------------------------------------------------
@admin_router.get("/tenants/{tenant_id}/summary")
def get_tenant_summary(
    tenant_id: str,
    x_stc_admin_secret: str = Header(None),
):

    _require_admin(x_stc_admin_secret)

    period = current_period()

    policy = _r.hgetall(f"ztr:tenant:{tenant_id}:policy")

    tokens = int(_r.get(tenant_usage_key(tenant_id, period, "tokens_issued")) or 0)

    amount = tokens * TOKEN_PRICE_CENTS

    return {
        "tenant_id": tenant_id,
        "policy_version": policy.get("version"),
        "policy_digest": policy.get("digest"),
        "tokens_issued": tokens,
        "amount_cents": amount,
    }


# ---------------------------------------------------------
# GET /v1/admin/tenants
# ---------------------------------------------------------
@admin_router.get("/tenants")
def list_tenants(
    x_stc_admin_secret: str = Header(None),
):

    _require_admin(x_stc_admin_secret)

    tenants = []

    for key in _r.scan_iter("ztr:tenant:*:meta"):

        raw = _r.get(key)

        if not raw:
            continue

        data = json.loads(raw)

        tenant_id = data.get("tenant_id")

        tenants.append({
            "tenant_id": tenant_id,
            "label": data.get("label"),
            "created_at": data.get("created_at"),
        })

    return {
        "count": len(tenants),
        "tenants": tenants,
    }


# ---------------------------------------------------------
# GET /v1/admin/tenants/{tenant_id}/sessions
# ---------------------------------------------------------
@admin_router.get("/tenants/{tenant_id}/sessions")
def list_tenant_sessions(
    tenant_id: str,
    x_stc_admin_secret: str = Header(None),
):

    _require_admin(x_stc_admin_secret)

    tenant_id = tenant_id.strip().lower()

    index_key = f"ztr:tenant:{tenant_id}:session_index"

    sids = _r.smembers(index_key)

    sessions = []

    for sid in sids:

        key = f"ztr:tenant:{tenant_id}:session:{sid}"

        data = _r.hgetall(key)

        if not data:
            continue

        ttl = _r.ttl(key)

        sessions.append({
            "session_id": sid,
            "principal": data.get("principal"),
            "intent": data.get("intent"),
            "scopes": data.get("scopes"),
            "issued_at": data.get("issued_at"),
            "ttl": ttl
        })

    return {
        "tenant_id": tenant_id,
        "active_sessions": len(sessions),
        "sessions": sessions
    }


# ---------------------------------------------------------
# GET /v1/admin/runtime
#
# Runtime health snapshot for operators.
#
# Read-only. No state mutation.
# ---------------------------------------------------------
@admin_router.get("/runtime")
def runtime_health(
    x_stc_admin_secret: str = Header(None),
):

    _require_admin(x_stc_admin_secret)

    redis_status = "ok"

    try:
        _r.ping()
    except Exception:
        redis_status = "error"

    tenant_count = 0
    for _ in _r.scan_iter("ztr:tenant:*:meta"):
        tenant_count += 1

    active_sessions = 0

    for key in _r.scan_iter("ztr:tenant:*:session_index"):
        sids = _r.smembers(key)
        active_sessions += len(sids)

    return {
        "status": "ok" if redis_status == "ok" else "degraded",
        "redis": redis_status,
        "policy_revision": POLICY_REVISION,
        "tenant_count": tenant_count,
        "active_sessions": active_sessions,
        "period": current_period()
    }


# ---------------------------------------------------------
# GET /v1/admin/metrics
#
# Platform-wide metrics aggregation across all tenants.
# Read-only control-plane endpoint.
# ---------------------------------------------------------
@admin_router.get("/metrics")
def platform_metrics(
    x_stc_admin_secret: str = Header(None),
):
    _require_admin(x_stc_admin_secret)

    period = current_period()

    tokens_issued = 0
    policy_denied = 0
    sessions_revoked = 0

    # Aggregate counters across all tenants
    for key in _r.scan_iter(f"ztr:tenant:*:usage:{period}:tokens_issued"):
        tokens_issued += int(_r.get(key) or 0)

    for key in _r.scan_iter(f"ztr:tenant:*:usage:{period}:policy_denied"):
        policy_denied += int(_r.get(key) or 0)

    for key in _r.scan_iter(f"ztr:tenant:*:usage:{period}:sessions_revoked"):
        sessions_revoked += int(_r.get(key) or 0)

    # Active sessions across platform
    active_sessions = 0
    for key in _r.scan_iter("ztr:tenant:*:session_index"):
        active_sessions += len(_r.smembers(key))

    # Tenant count
    tenant_count = 0
    for _ in _r.scan_iter("ztr:tenant:*:meta"):
        tenant_count += 1

    return {
        "period": period,
        "metrics": {
            "tokens_issued": tokens_issued,
            "policy_denied": policy_denied,
            "sessions_revoked": sessions_revoked,
        },
        "platform": {
            "tenant_count": tenant_count,
            "active_sessions": active_sessions
        }
    }
