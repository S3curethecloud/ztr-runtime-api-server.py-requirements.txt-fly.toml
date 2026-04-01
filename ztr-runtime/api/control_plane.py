from fastapi import APIRouter, HTTPException, Query
import redis
import os
import json
import time
import hashlib

router = APIRouter(prefix="/v1/admin", tags=["control-plane"])

REDIS_URL = os.environ["REDIS_URL"]

r = redis.from_url(
    REDIS_URL,
    decode_responses=True
)


@router.post("/policy/publish")
async def publish_policy_update(payload: dict):

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

    return {
        "status": "policy_updated",
        "version": version,
        "digest": digest
    }


def revoke_all_sessions(tenant_id: str):
    pattern = f"ztr:{tenant_id}:session:*"

    revoked = 0

    for key in r.scan_iter(pattern):
        r.delete(key)
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
def get_control_plane_policy(tenant_id: str = Query(...)):
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
def get_control_plane_tenants():
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
def revoke_tenant_sessions(payload: dict):
    tenant_id = payload.get("tenant_id")

    if not tenant_id:
        raise HTTPException(status_code=400, detail="missing_tenant_id")

    pattern = f"ztr:{tenant_id}:session:*"
    keys = r.keys(pattern)

    count = 0

    import re
    session_index = f"ztr:{tenant_id}:sessions"

    for key in keys:
        match = re.match(rf"ztr:{tenant_id}:session:(.+)", key)
        sid = match.group(1) if match else None

        pipe = r.pipeline()

        pipe.delete(key)

        if sid:
            pipe.srem(session_index, sid)

            r.publish("decision_events", json.dumps({
                "event_type": "revocation",
                "timestamp": int(time.time()),
                "tenant_id": tenant_id,
                "session_id": sid,
                "principal": "system",
                "intent": "session:revoke",
                "decision": "allow",
                "risk_score": 0,
                "policy_revision": "control-plane",
                "metadata": {
                    "source": "control-plane",
                    "stage": "revoke"
                }
            }))

        pipe.execute()

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
def fix_tenant(payload: dict):
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
