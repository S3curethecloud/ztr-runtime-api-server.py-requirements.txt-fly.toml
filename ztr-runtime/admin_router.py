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
        },
    )

    _r.set(meta_key, json.dumps(meta))

    _write_policy_anchor(
        tenant_id,
        policy_version
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

    _write_policy_anchor(
        tenant_id,
        POLICY_REVISION
    )

    return {
        "status": "provisioned",
        "tenant_id": tenant_id,
        "api_key": api_key,
        "key_hash": key_hash,
        "mgmt_event_hash": mgmt_event["event_hash"],
    }
