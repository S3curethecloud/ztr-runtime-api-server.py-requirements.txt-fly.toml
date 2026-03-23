from fastapi import APIRouter, HTTPException
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

    if not tenant_id or not policy_text or not version:
        raise HTTPException(
            status_code=400,
            detail="missing_required_fields"
        )

    # --------------------------------------------------
    # REQUIRED FIX — POLICY DIGEST PROJECTION (MANDATORY)
    # --------------------------------------------------
    policy_revision = version

    policy_key = f"ztr:tenant:{tenant_id}:policy"

    policy_digest = hashlib.sha256(
        policy_revision.encode()
    ).hexdigest()

    r.hset(policy_key, mapping={
        "version": policy_revision,
        "digest": policy_digest
    })

    # 1️⃣ STATE + ENFORCEMENT (CRITICAL)
    result = update_policy_and_revoke(
        tenant_id,
        policy_text,
        version
    )

    # 2️⃣ DISTRIBUTION EVENT
    message = {
        "tenant_id": tenant_id,
        "policy_version": version,
        "timestamp": int(time.time())
    }

    r.publish("policy_updates", json.dumps(message))

    return {
        "status": "published",
        "policy": result["policy"],
        "revocation": result["revocation"]
    }


# --------------------------------------------------
# 🔒 PHASE 7.1 — POLICY VERSION CONTROL
# --------------------------------------------------

def update_policy(tenant_id: str, policy_text: str, version: str):
    digest = hashlib.sha256(policy_text.encode()).hexdigest()

    # write new policy (FIXED — ztr namespace)
    r.hset(f"ztr:tenant:{tenant_id}:policy", mapping={
        "version": version,
        "digest": digest
    })

    # update anchor (authoritative) (FIXED — ztr namespace)
    r.set(f"ztr:tenant:{tenant_id}:policy_anchor", digest)

    return {
        "status": "policy_updated",
        "version": version,
        "digest": digest
    }


# --------------------------------------------------
# 🔒 PHASE 7.1 — CAE TOKEN REVOCATION
# --------------------------------------------------

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


# --------------------------------------------------
# 🔒 COMBINED OPERATION (CRITICAL)
# --------------------------------------------------

def update_policy_and_revoke(tenant_id: str, policy_text: str, version: str):
    result = update_policy(tenant_id, policy_text, version)

    revoke = revoke_all_sessions(tenant_id)

    return {
        "policy": result,
        "revocation": revoke
    }
