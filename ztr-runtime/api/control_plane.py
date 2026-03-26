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

    message = {
        "tenant_id": tenant_id,
        "policy_version": version,
        "policy_digest": policy_digest,
        "timestamp": int(time.time())
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


@router.get("/v1/control-plane/policy")
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
