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
from api.redis_keys import (
    tenant_session_key,
    tenant_session_index_key,
    tenant_usage_key,
    apikey_lookup_key
)


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

    tenant_count = 0
    active_sessions = 0
    tokens_issued = 0
    policy_denied = 0
    sessions_revoked = 0

    for _ in _r.scan_iter("ztr:tenant:*:meta"):
        tenant_count += 1

    for key in _r.scan_iter("ztr:*:session:*"):
        active_sessions += 1

        data = _r.hgetall(key)
        if data.get("revoked") == "true":
            sessions_revoked += 1

    for key in _r.scan_iter("metrics:decision:*"):
        data = _r.hgetall(key)

        if not data:
            continue

        tokens_issued += 1

        if data.get("decision") == "deny":
            policy_denied += 1

    return {
        "tenant_count": tenant_count,
        "active_sessions": active_sessions,
        "tokens_issued": tokens_issued,
        "policy_denied": policy_denied,
        "sessions_revoked": sessions_revoked
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
# Tenant detail helpers
# ---------------------------------------------------------


def _get_tenant_meta_or_404(tenant_id: str) -> dict:
    meta_key = f"ztr:tenant:{tenant_id}:meta"

    raw = _r.get(meta_key)

    if raw is None:
        raise HTTPException(status_code=404, detail="tenant_not_found")

    try:
        meta = json.loads(raw)
    except Exception:
        raise HTTPException(status_code=500, detail="tenant_meta_invalid")

    return meta


def _parse_scopes(raw_scopes):
    if isinstance(raw_scopes, list):
        return raw_scopes

    if raw_scopes is None:
        return []

    try:
        scopes = json.loads(raw_scopes)
    except Exception:
        scopes = str(raw_scopes).split(",") if raw_scopes else []

    if not isinstance(scopes, list):
        return []

    return scopes


def _read_policy_anchor(tenant_id: str):
    anchor_key = f"ztr:tenant:{tenant_id}:policy_anchor"

    try:
        if _r.type(anchor_key) == "string":
            return _r.get(anchor_key)
    except Exception:
        return None

    return None


def _read_policy_version(tenant_id: str):
    policy_key = f"ztr:tenant:{tenant_id}:policy"

    try:
        if _r.type(policy_key) == "hash":
            policy = _r.hgetall(policy_key) or {}
            return policy.get("version") or POLICY_REVISION
    except Exception:
        return POLICY_REVISION

    return POLICY_REVISION


# ---------------------------------------------------------
# GET /v1/admin/tenants/{tenant_id}/summary
# ---------------------------------------------------------


@admin_router.get("/tenants/{tenant_id}/summary")
def get_tenant_summary(
    tenant_id: str,
    x_stc_admin_secret: str = Header(None),
):
    _require_admin(x_stc_admin_secret)

    _get_tenant_meta_or_404(tenant_id)

    status = _r.get(f"ztr:tenant:{tenant_id}:status") or "active"
    policy_version = _read_policy_version(tenant_id)
    policy_anchor = _read_policy_anchor(tenant_id)

    return {
        "tenant_id": tenant_id,
        "status": status,
        "policy_version": policy_version,
        "policy_anchor": policy_anchor,
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

    _get_tenant_meta_or_404(tenant_id)

    period = current_period()
    usage_key = tenant_usage_key(tenant_id, period)
    usage = _r.hgetall(usage_key) or {}

    index_key = tenant_session_index_key(tenant_id)
    sids = _r.smembers(index_key)

    risk_score = 0

    for sid in list(sids):
        session_key = tenant_session_key(tenant_id, sid)

        data = _r.hgetall(session_key)
        ttl = _r.ttl(session_key)

        if not data or ttl <= 0:
            _r.srem(index_key, sid)
            continue

        raw_risk = data.get("risk", "null")

        try:
            risk = json.loads(raw_risk)
        except Exception:
            risk = {}

        if not isinstance(risk, dict):
            risk = {}

        try:
            score = int(float(risk.get("final_score") or 0))
        except Exception:
            score = 0

        if score > risk_score:
            risk_score = score

    return {
        "tenant_id": tenant_id,
        "tokens_issued": int(usage.get("tokens_issued") or 0),
        "policy_denied": int(usage.get("policy_denied") or 0),
        "sessions_revoked": int(usage.get("sessions_revoked") or 0),
        "risk_score": risk_score,
        "period": period,
    }

# ---------------------------------------------------------
# GET /v1/admin/tenants/{tenant_id}/sessions
# ---------------------------------------------------------


@admin_router.get("/tenants/{tenant_id}/sessions")
def get_tenant_sessions(
    tenant_id: str,
    x_stc_admin_secret: str = Header(None),
):
    _require_admin(x_stc_admin_secret)

    _get_tenant_meta_or_404(tenant_id)

    index_key = tenant_session_index_key(tenant_id)
    sids = _r.smembers(index_key)

    sessions = []

    for sid in list(sids):
        session_key = tenant_session_key(tenant_id, sid)

        data = _r.hgetall(session_key)
        ttl = _r.ttl(session_key)

        if not data or ttl <= 0:
            _r.srem(index_key, sid)
            continue

        issued_at = int(data.get("issued_at", 0) or 0)
        scopes = _parse_scopes(data.get("scopes", "[]"))

        sessions.append({
            "session_id": sid,
            "principal": data.get("principal"),
            "intent": data.get("intent"),
            "scopes": scopes,
            "issued_at": issued_at,
            "ttl": ttl,
        })

    sessions.sort(key=lambda s: s.get("issued_at") or 0, reverse=True)

    return {
        "tenant_id": tenant_id,
        "sessions": sessions,
    }


# ---------------------------------------------------------
# GET /v1/admin/tenants/{tenant_id}/billing
# Runtime-derived deterministic billing preview
# ---------------------------------------------------------


@admin_router.get("/tenants/{tenant_id}/billing")
def get_tenant_billing(
    tenant_id: str,
    x_stc_admin_secret: str = Header(None),
):
    _require_admin(x_stc_admin_secret)

    _get_tenant_meta_or_404(tenant_id)

    period = current_period()
    usage_key = tenant_usage_key(tenant_id, period)

    usage = _r.hgetall(usage_key) or {}

    quantity = int(usage.get("tokens_issued") or 0)
    unit_price_cents = TOKEN_PRICE_CENTS
    amount_cents = quantity * unit_price_cents

    return {
        "tenant_id": tenant_id,
        "period": period,
        "billable_metric": "tokens_issued",
        "unit_price_cents": unit_price_cents,
        "quantity": quantity,
        "amount_cents": amount_cents,
    }

# ---------------------------------------------------------
# POST /v1/admin/tenants/{tenant_id}/repair
# Backfill missing control-plane registry + projected state
# for legacy tenants created before registry sync enforcement
# ---------------------------------------------------------


@admin_router.post("/tenants/{tenant_id}/repair")
def repair_tenant_registry(
    tenant_id: str,
    x_stc_admin_secret: str = Header(None),
):
    _require_admin(x_stc_admin_secret)

    meta = _get_tenant_meta_or_404(tenant_id)

    now = int(time.time())
    created_at = int(meta.get("created_at") or now)
    label = meta.get("label") or tenant_id

    status_key = f"ztr:tenant:{tenant_id}:status"
    config_key = f"ztr:tenant:{tenant_id}:config"
    policy_key = f"ztr:tenant:{tenant_id}:policy"
    registry_key = f"ztr:control:tenant:{tenant_id}"

    status = _r.get(status_key) or "active"
    policy_version = _read_policy_version(tenant_id)
    policy_digest = hashlib.sha256(policy_version.encode()).hexdigest()

    # Backfill / refresh control-plane registry
    _r.hset(registry_key, mapping={
        "tenant_id": tenant_id,
        "status": status,
        "created_at": created_at,
        "policy_version": policy_version,
        "policy_digest": policy_digest,
        "last_updated": now
    })

    # Ensure projected state exists without disturbing existing usage/sessions
    if not _r.exists(status_key):
        _r.set(status_key, status)

    if not _r.exists(config_key):
        _r.set(
            config_key,
            json.dumps({
                "version": policy_version,
                "created_at": created_at
            })
        )

    if _r.type(policy_key) != "hash":
        _r.hset(
            policy_key,
            mapping={
                "version": policy_version,
                "digest": policy_digest
            }
        )

    _write_policy_anchor(tenant_id, policy_version)

    usage_key = tenant_usage_key(tenant_id, current_period())
    if not _r.exists(usage_key):
        _r.hset(
            usage_key,
            mapping={
                "tokens_issued": 0,
                "policy_denied": 0,
                "sessions_revoked": 0
            }
        )

    emit_event(
        tenant_id=tenant_id,
        event_type="control_plane.tenant_registry_repaired",
        service="ztr-admin",
        payload={
            "tenant_id": tenant_id,
            "label": label,
            "status": status,
            "policy_version": policy_version,
            "policy_digest": policy_digest,
            "timestamp": now
        }
    )

    return {
        "tenant_id": tenant_id,
        "status": "repaired",
        "registry_status": "synced",
        "policy_version": policy_version,
        "policy_digest": policy_digest
    }

# ---------------------------------------------------------
# POST /v1/admin/tenants
# One-call tenant provisioning endpoint
# ---------------------------------------------------------


@admin_router.post("/tenants")
def create_tenant(
    payload: ProvisionTenantRequest,
    x_stc_admin_secret: str = Header(None),
):
    _require_admin(x_stc_admin_secret)

    tenant_id = payload.tenant_id
    label = payload.label
    key_label = payload.key_label

    meta_key = f"ztr:tenant:{tenant_id}:meta"

    if _r.exists(meta_key):
        raise HTTPException(status_code=409, detail="tenant_already_exists")

    now = int(time.time())

    _r.set(meta_key, json.dumps({
        "tenant_id": tenant_id,
        "label": label,
        "created_at": now
    }))

    # 🔒 CONTROL PLANE REGISTRY SYNC (CRITICAL FIX)
    registry_key = f"ztr:control:tenant:{tenant_id}"

    _r.hset(registry_key, mapping={
        "tenant_id": tenant_id,
        "status": "active",
        "created_at": now,
        "policy_version": POLICY_REVISION,
        "policy_digest": hashlib.sha256(POLICY_REVISION.encode()).hexdigest(),
        "last_updated": now
    })

    _r.set(f"ztr:tenant:{tenant_id}:status", "active")

    _r.set(
        f"ztr:tenant:{tenant_id}:config",
        json.dumps({
            "version": POLICY_REVISION,
            "created_at": now
        })
    )

    _r.hset(
        f"ztr:tenant:{tenant_id}:policy",
        mapping={
            "version": POLICY_REVISION,
            "digest": hashlib.sha256(POLICY_REVISION.encode()).hexdigest()
        }
    )

    _write_policy_anchor(tenant_id, POLICY_REVISION)

    _r.hset(
        tenant_usage_key(tenant_id, current_period()),
        mapping={
            "tokens_issued": 0,
            "policy_denied": 0,
            "sessions_revoked": 0
        }
    )

    _mgmt_emit(
        "tenant.created",
        {
            "tenant_id": tenant_id,
            "label": label,
            "key_label": key_label,
            "timestamp": now
        }
    )

    return {
        "tenant_id": tenant_id,
        "status": "created"
    }


# =========================================================
# 🔒 PHASE 8 — API KEY PROVISIONING (TENANT BINDING)
# =========================================================

@admin_router.post("/api-keys/create")
def create_api_key(
    payload: dict,
    x_stc_admin_secret: str = Header(None),
):
    _require_admin(x_stc_admin_secret)

    tenant_id = payload.get("tenant_id")

    if not tenant_id:
        raise HTTPException(status_code=400, detail="missing_tenant_id")

    # 🔒 VERIFY TENANT EXISTS (CONTROL PLANE SOURCE)
    registry_key = f"ztr:control:tenant:{tenant_id}"

    if not _r.exists(registry_key):
        raise HTTPException(status_code=404, detail="tenant_not_found")

    # 🔒 GENERATE SECURE API KEY
    raw_key = f"stc_{secrets.token_urlsafe(32)}"

    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

    lookup_key = apikey_lookup_key(key_hash)

    # 🔒 STORE HASH → TENANT MAPPING
    _r.set(lookup_key, tenant_id)

    # 🔒 AUDIT EVENT (SOC2)
    emit_event(
        tenant_id=tenant_id,
        event_type="control_plane.api_key_created",
        service="admin",
        payload={
            "key_hash": key_hash[:12],
            "timestamp": int(time.time())
        }
    )

    return {
        "tenant_id": tenant_id,
        "api_key": raw_key
    }

# =========================================================
# 🔒 PHASE 8 — API KEY REVOCATION
# =========================================================

@admin_router.post("/api-keys/revoke")
def revoke_api_key(
    payload: dict,
    x_stc_admin_secret: str = Header(None),
):
    _require_admin(x_stc_admin_secret)

    key = payload.get("api_key")

    if not key:
        raise HTTPException(status_code=400, detail="missing_api_key")

    key_hash = hashlib.sha256(key.encode()).hexdigest()
    lookup_key = apikey_lookup_key(key_hash)

    tenant_id = _r.get(lookup_key)

    if not tenant_id:
        raise HTTPException(status_code=404, detail="api_key_not_found")

    _r.delete(lookup_key)

    # 🔒 AUDIT EVENT
    emit_event(
        tenant_id=tenant_id,
        event_type="control_plane.api_key_revoked",
        service="admin",
        payload={
            "key_hash": key_hash[:12],
            "timestamp": int(time.time())
        }
    )

    return {
        "status": "revoked",
        "tenant_id": tenant_id
    }

# =========================================================
# 🔒 PHASE 8 — API KEY ROTATION
# =========================================================

@admin_router.post("/api-keys/rotate")
def rotate_api_key(
    payload: dict,
    x_stc_admin_secret: str = Header(None),
):
    _require_admin(x_stc_admin_secret)

    old_key = payload.get("api_key")

    if not old_key:
        raise HTTPException(status_code=400, detail="missing_api_key")

    old_hash = hashlib.sha256(old_key.encode()).hexdigest()
    old_lookup = apikey_lookup_key(old_hash)

    tenant_id = _r.get(old_lookup)

    if not tenant_id:
        raise HTTPException(status_code=404, detail="api_key_not_found")

    # 🔒 REVOKE OLD KEY
    _r.delete(old_lookup)

    # 🔒 CREATE NEW KEY
    new_key = f"stc_{secrets.token_urlsafe(32)}"
    new_hash = hashlib.sha256(new_key.encode()).hexdigest()
    new_lookup = apikey_lookup_key(new_hash)

    _r.set(new_lookup, tenant_id)

    # 🔒 AUDIT EVENT
    emit_event(
        tenant_id=tenant_id,
        event_type="control_plane.api_key_rotated",
        service="admin",
        payload={
            "old_key_hash": old_hash[:12],
            "new_key_hash": new_hash[:12],
            "timestamp": int(time.time())
        }
    )

    return {
        "tenant_id": tenant_id,
        "api_key": new_key
    }
