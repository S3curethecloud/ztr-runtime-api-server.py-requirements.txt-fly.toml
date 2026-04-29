from fastapi import APIRouter, HTTPException, Query, Header
import redis
import os
import json
import time
import hashlib

from audit_chain import emit_event
from api.redis_keys import tenant_session_key, tenant_session_index_key

router = APIRouter(prefix="/v1/admin", tags=["control-plane"])

REDIS_URL = os.environ["REDIS_URL"]

r = redis.from_url(
    REDIS_URL,
    decode_responses=True
)

ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "")


def _require_admin(x_stc_admin_secret: str = Header(None)) -> None:
    if not ADMIN_SECRET:
        raise HTTPException(status_code=503, detail="admin_not_configured")

    if not x_stc_admin_secret or x_stc_admin_secret != ADMIN_SECRET:
        raise HTTPException(status_code=403, detail="forbidden")


@router.post("/policy/publish")
async def publish_policy_update(
    payload: dict,
    x_stc_admin_secret: str = Header(None),
):
    _require_admin(x_stc_admin_secret)

    tenant_id = payload.get("tenant_id")
    policy_text = payload.get("bundle")
    version = payload.get("policy_revision")

    print("🔥 PUBLISH HIT", tenant_id, version)

    if not tenant_id or not policy_text or not version:
        raise HTTPException(
            status_code=400,
            detail="missing_required_fields"
        )

    policy_revision = version

    policy_key = f"ztr:tenant:{tenant_id}:policy"

    policy_digest = hashlib.sha256(
        policy_text.encode()
    ).hexdigest()

    # 🔒 STEP 7.3 — GLOBAL POLICY AUTHORITY WRITE
    global_policy_key = f"ztr:policy:global:{policy_digest}"

    if not r.exists(global_policy_key):
        r.hset(global_policy_key, mapping={
            "digest": policy_digest,
            "version": version,
            "created_at": int(time.time())
        })

    r.set(f"ztr:policy:version:{version}", policy_digest)

    r.hset(policy_key, mapping={
        "version": policy_revision,
        "digest": policy_digest
    })

    print("🔥 REDIS WRITE EXECUTED", policy_key)

    result = update_policy_and_revoke(
        tenant_id,
        policy_text,
        version
    )

    timestamp = int(time.time())

    event_id = f"{tenant_id}:{policy_revision}:{policy_digest[:16]}:{timestamp}"

    r.hset(
        f"ztr:tenant:{tenant_id}:propagation",
        mapping={
            "last_updated_timestamp": timestamp,
            "last_event_id": event_id
        }
    )

    message = {
        "tenant_id": tenant_id,
        "policy_version": version,
        "policy_digest": policy_digest,
        "timestamp": timestamp,
        "event_id": event_id
    }

    r.publish("policy_updates", json.dumps(message))

    # 🔒 STEP 7.4 — MANAGEMENT AUDIT EVENT
    emit_event(
        tenant_id=tenant_id,
        event_type="control_plane.policy_published",
        service="control-plane",
        payload={
            "policy_version": version,
            "policy_digest": policy_digest,
            "event_id": event_id,
            "timestamp": timestamp
        }
    )

    return {
        "status": "published",
        "policy": result["policy"],
        "revocation": result["revocation"]
    }


def update_policy(tenant_id: str, policy_text: str, version: str):
    digest = hashlib.sha256(policy_text.encode()).hexdigest()

    print("🔥 UPDATE_POLICY WRITE", tenant_id)

    r.hset(f"ztr:tenant:{tenant_id}:policy", mapping={
        "version": version,
        "digest": digest
    })

    r.set(f"ztr:tenant:{tenant_id}:policy_anchor", digest)

    # 🔒 CONTROL PLANE REGISTRY SYNC (STEP 7.2)
    registry_key = f"ztr:control:tenant:{tenant_id}"

    if r.exists(registry_key):
        r.hset(registry_key, mapping={
            "policy_version": version,
            "policy_digest": digest,
            "last_updated": int(time.time())
        })

    return {
        "status": "policy_updated",
        "version": version,
        "digest": digest
    }


def revoke_all_sessions(tenant_id: str):
    session_index = tenant_session_index_key(tenant_id)
    sids = r.smembers(session_index)

    revoked = 0

    for sid in list(sids):
        session_key = tenant_session_key(tenant_id, sid)

        pipe = r.pipeline()
        pipe.delete(session_key)
        pipe.srem(session_index, sid)
        pipe.execute()

        revoked += 1

    return {
        "status": "revoked",
        "count": revoked
    }


def update_policy_and_revoke(tenant_id: str, policy_text: str, version: str):
    result = update_policy(tenant_id, policy_text, version)

    revoke = revoke_all_sessions(tenant_id)

    return {
        "policy": result,
        "revocation": revoke
    }


# ---------------------------------------------------------
# 🔒 CONTROL-PLANE POLICY READ (INTEGRITY ONLY — NO DRIFT)
# ---------------------------------------------------------

def _decode(value):
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.decode("utf-8")
    return str(value)


@router.get("/control-plane/policy")
def get_control_plane_policy(
    tenant_id: str = Query(...),
    x_stc_admin_secret: str = Header(None),
):
    _require_admin(x_stc_admin_secret)
    policy_key = f"ztr:tenant:{tenant_id}:policy"
    anchor_key = f"ztr:tenant:{tenant_id}:policy_anchor"

    policy_raw = r.hgetall(policy_key)
    if not policy_raw:
        raise HTTPException(status_code=404, detail=f"policy not found for tenant {tenant_id}")

    policy = {
        _decode(k): _decode(v)
        for k, v in policy_raw.items()
    }

    digest = policy.get("digest") or ""
    version = policy.get("version") or "--"
    anchor = _decode(r.get(anchor_key)) or ""

    integrity = "valid" if policy["digest"] == anchor else "mismatch"

    return {
        "tenant_id": tenant_id,
        "policy": {
            "version": version,
            "digest": digest
        },
        "anchor": anchor,
        "integrity": integrity
    }


# =========================================================
# 🔧 PHASE 7.2 — STEP 1 (BACKEND)
# =========================================================

@router.get("/control-plane/tenants")
def get_control_plane_tenants(
    x_stc_admin_secret: str = Header(None),
):
    _require_admin(x_stc_admin_secret)
    pattern = "ztr:tenant:*:policy"
    keys = r.keys(pattern)

    tenants = []

    for key in keys:
        tenant_id = key.split(":")[2]

        policy_raw = r.hgetall(key)
        anchor_raw = r.get(f"ztr:tenant:{tenant_id}:policy_anchor")
        propagation_raw = r.hgetall(f"ztr:tenant:{tenant_id}:propagation")

        policy = {
            _decode(k): _decode(v)
            for k, v in policy_raw.items()
        }

        propagation = {
            _decode(k): _decode(v)
            for k, v in propagation_raw.items()
        }

        digest = policy.get("digest") or ""
        version = policy.get("version") or "--"
        anchor = _decode(anchor_raw) or ""

        integrity = "valid" if digest == anchor else "mismatch"

        last_updated = propagation.get("last_updated_timestamp")
        last_event_id = propagation.get("last_event_id")

        propagation_status = "SYNCED" if integrity == "valid" else "STALE"

        tenants.append({
            "tenant_id": tenant_id,
            "policy": {
                "version": version,
                "digest": digest
            },
            "anchor": anchor,
            "integrity": integrity,
            "last_updated_timestamp": last_updated,
            "last_event_id": last_event_id,
            "propagation_status": propagation_status
        })

    tenants.sort(key=lambda t: t["tenant_id"])

    return {
        "count": len(tenants),
        "tenants": tenants
    }


# =========================================================
# 🔧 CONTROL-PLANE TENANT SESSION REVOCATION (UPDATED)
# =========================================================

@router.post("/control-plane/revoke-tenant")
def revoke_tenant_sessions(
    payload: dict,
    x_stc_admin_secret: str = Header(None),
):
    _require_admin(x_stc_admin_secret)
    tenant_id = payload.get("tenant_id")

    if not tenant_id:
        raise HTTPException(status_code=400, detail="missing_tenant_id")

    session_index = tenant_session_index_key(tenant_id)
    sids = r.smembers(session_index)

    count = 0

    for sid in list(sids):
        session_key = tenant_session_key(tenant_id, sid)

        pipe = r.pipeline()
        pipe.delete(session_key)
        pipe.srem(session_index, sid)
        pipe.execute()

        r.publish("decision_events", json.dumps({
            "event_type": "decision",
            "timestamp": int(time.time()),
            "tenant_id": tenant_id,
            "session_id": sid,
            "principal": "system",
            "intent": "session:revoke",
            "decision": "deny",
            "risk_score": 0,
            "policy_revision": "control-plane",
            "metadata": {
                "source": "control-plane",
                "stage": "revoke"
            }
        }))

        count += 1

    return {
        "tenant_id": tenant_id,
        "revoked_sessions": count,
        "status": "completed"
    }


# =========================================================
# 🔧 CONTROL-PLANE FIX TENANT (ANCHOR REALIGNMENT)
# =========================================================

@router.post("/control-plane/fix-tenant")
def fix_tenant(
    payload: dict,
    x_stc_admin_secret: str = Header(None),
):
    _require_admin(x_stc_admin_secret)
    tenant_id = payload.get("tenant_id")

    if not tenant_id:
        raise HTTPException(status_code=400, detail="missing_tenant_id")

    policy_key = f"ztr:tenant:{tenant_id}:policy"
    anchor_key = f"ztr:tenant:{tenant_id}:policy_anchor"

    policy_raw = r.hgetall(policy_key)
    if not policy_raw:
        raise HTTPException(status_code=404, detail="policy_not_found")

    policy = {
        _decode(k): _decode(v)
        for k, v in policy_raw.items()
    }

    version = policy.get("version")
    digest = policy.get("digest")

    if not digest:
        raise HTTPException(status_code=500, detail="missing_digest")

    r.set(anchor_key, digest)

    timestamp = int(time.time())
    event_id = f"{tenant_id}:{version}:{digest[:16]}:{timestamp}"

    r.hset(
        f"ztr:tenant:{tenant_id}:propagation",
        mapping={
            "last_updated_timestamp": timestamp,
            "last_event_id": event_id
        }
    )

    return {
        "tenant_id": tenant_id,
        "status": "fixed",
        "digest": digest,
        "anchor": digest
    }
