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


_r = redis.from_url(
    os.environ["REDIS_URL"],
    decode_responses=True,
)

TOKEN_PRICE_CENTS = int(os.getenv("TOKEN_PRICE_CENTS", "1"))

ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "")
POLICY_REVISION = os.getenv("POLICY_REVISION", "dev-1")

admin_router = APIRouter(prefix="/v1/admin", tags=["admin"])

MGMT_TENANT = "mgmt"


# ---------------------------------------------------------
# Governance Policy Anchor Helper
# ---------------------------------------------------------

def _write_policy_anchor(tenant_id: str, policy_version: str):

    policy_digest = hashlib.sha256(policy_version.encode()).hexdigest()

    anchor_key = f"ztr:tenant:{tenant_id}:policy_anchor"

    _r.set(anchor_key, policy_digest)

    emit_event(
        tenant_id=tenant_id,
        event_type="runtime.policy_anchor_written",
        service="ztr-admin",
        payload={
            "policy_version": policy_version,
            "policy_digest": policy_digest,
            "ts": int(time.time())
        }
    )


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


def current_period() -> str:
    return datetime.datetime.utcnow().strftime("%Y-%m")


def _mgmt_emit(event_type: str, payload: dict) -> dict:

    return emit_event(
        tenant_id=MGMT_TENANT,
        event_type=event_type,
        service="ztr-admin",
        payload=payload,
    )


class CreateTenantRequest(BaseModel):
    tenant_id: str
    label: str


class ProvisionTenantRequest(BaseModel):
    tenant_id: str
    label: str
    key_label: str = "root"


# ---------------------------------------------------------
# GET /v1/admin/metrics
# Platform metrics for dashboard
# ---------------------------------------------------------

@admin_router.get("/metrics")
def admin_metrics(
    x_stc_admin_secret: str = Header(None),
):

    _require_admin(x_stc_admin_secret)

    tenants = list(_r.scan_iter("ztr:tenant:*:meta"))
    sessions = list(_r.scan_iter("ztr:*:session:*"))

    return {
        "tenant_count": len(tenants),
        "active_sessions": len(sessions),
        "tokens_issued": 0,
        "policy_denied": 0,
        "sessions_revoked": 0
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

        try:

            raw = _r.get(key)

            if not raw:
                continue

            data = json.loads(raw)

            tenants.append({
                "tenant_id": data.get("tenant_id"),
                "label": data.get("label"),
                "created_at": data.get("created_at")
            })

        except Exception:
            continue

    tenants.sort(key=lambda t: t.get("created_at") or 0)

    return {"tenants": tenants}


# ---------------------------------------------------------
# GET /v1/admin/tenants/summary
# ---------------------------------------------------------

@admin_router.get("/tenants/summary")
def list_tenant_summaries(
    x_stc_admin_secret: str = Header(None),
):

    _require_admin(x_stc_admin_secret)

    tenants = []

    cursor = 0

    while True:

        cursor, keys = _r.scan(cursor=cursor, match="ztr:tenant:*:meta")

        for key in keys:

            raw = _r.get(key)

            if raw is None:
                continue

            meta = json.loads(raw)

            tenant_id = meta.get("tenant_id")

            anchor_key = f"ztr:tenant:{tenant_id}:policy_anchor"

            policy_anchor = None

            try:
                if _r.type(anchor_key) == "string":
                    policy_anchor = _r.get(anchor_key)
            except Exception:
                policy_anchor = None

            tenants.append({
                "tenant_id": tenant_id,
                "label": meta.get("label"),
                "status": "active",
                "policy_version": POLICY_REVISION,
                "policy_anchor": policy_anchor,
                "created_at": meta.get("created_at")
            })

        if cursor == 0:
            break

    tenants.sort(key=lambda t: t["created_at"] or 0)

    return {"tenants": tenants}


# ---------------------------------------------------------
# GET /v1/admin/tenants/{tenant_id}/summary
# ---------------------------------------------------------

@admin_router.get("/tenants/{tenant_id}/summary")
def tenant_summary(
    tenant_id: str,
    x_stc_admin_secret: str = Header(None),
):

    _require_admin(x_stc_admin_secret)

    meta_key = f"ztr:tenant:{tenant_id}:meta"

    raw = _r.get(meta_key)

    if raw is None:
        raise HTTPException(status_code=404, detail="tenant_not_found")

    meta = json.loads(raw)

    policy_anchor = None

    anchor_key = f"ztr:tenant:{tenant_id}:policy_anchor"

    try:
        if _r.exists(anchor_key):
            policy_anchor = _r.get(anchor_key)
    except Exception:
        policy_anchor = None

    return {
        "tenant_id": tenant_id,
        "status": "active",
        "policy_version": POLICY_REVISION,
        "policy_anchor": policy_anchor,
        "created_at": meta.get("created_at")
    }


# ---------------------------------------------------------
# GET /v1/admin/tenants/{tenant_id}/sessions
# ---------------------------------------------------------

@admin_router.get("/tenants/{tenant_id}/sessions")
def tenant_sessions(
    tenant_id: str,
    x_stc_admin_secret: str = Header(None),
):

    _require_admin(x_stc_admin_secret)

    sessions = []

    for key in _r.scan_iter(f"ztr:{tenant_id}:session:*"):

        sid = key.split(":")[-1]
        data = _r.hgetall(key)

        sessions.append({
            "session_id": sid,
            "principal": data.get("principal"),
            "intent": data.get("intent"),
            "issued": data.get("issued_at"),
            "ttl": data.get("ttl")
        })

    return {"sessions": sessions}


# ---------------------------------------------------------
# GET /v1/admin/tenants/{tenant_id}/usage
# Tenant usage metrics
# ---------------------------------------------------------

@admin_router.get("/tenants/{tenant_id}/usage")
def tenant_usage(
    tenant_id: str,
    x_stc_admin_secret: str = Header(None),
):

    _require_admin(x_stc_admin_secret)

    tokens_issued = 0
    policy_denied = 0
    sessions_revoked = 0

    for key in _r.scan_iter("metrics:decision:*"):

        data = _r.hgetall(key)

        if not data:
            continue

        if data.get("tenant_id") != tenant_id:
            continue

        tokens_issued += 1

        if data.get("decision") == "deny":
            policy_denied += 1

    for key in _r.scan_iter(f"ztr:{tenant_id}:session:*"):

        data = _r.hgetall(key)

        if data.get("revoked") == "true":
            sessions_revoked += 1

    return {
        "tenant_id": tenant_id,
        "tokens_issued": tokens_issued,
        "policy_denied": policy_denied,
        "sessions_revoked": sessions_revoked,
        "period": current_period()
    }
