# FILE: api/policy_registry.py
# Phase 7.3 — Global Policy Authority Registry

from fastapi import APIRouter, HTTPException
import redis
import os
import time
import hashlib
import json

router = APIRouter(prefix="/v1/admin", tags=["policy-registry"])

REDIS_URL = os.environ["REDIS_URL"]

r = redis.from_url(
    REDIS_URL,
    decode_responses=True
)


def global_policy_key(digest: str) -> str:
    return f"ztr:policy:global:{digest}"


def policy_version_index(version: str) -> str:
    return f"ztr:policy:version:{version}"


@router.post("/policy/register")
def register_policy(payload: dict):

    policy_text = payload.get("bundle")
    version = payload.get("policy_revision")

    if not policy_text or not version:
        raise HTTPException(status_code=400, detail="missing_fields")

    digest = hashlib.sha256(policy_text.encode()).hexdigest()

    key = global_policy_key(digest)

    if r.exists(key):
        return {
            "status": "exists",
            "digest": digest,
            "version": version
        }

    timestamp = int(time.time())

    r.hset(key, mapping={
        "digest": digest,
        "version": version,
        "created_at": timestamp
    })

    r.set(policy_version_index(version), digest)

    return {
        "status": "registered",
        "digest": digest,
        "version": version
    }


@router.get("/policy/global")
def list_global_policies():

    pattern = "ztr:policy:global:*"

    policies = []

    for key in r.scan_iter(pattern):

        data = r.hgetall(key)

        if data:
            policies.append(data)

    return {
        "count": len(policies),
        "policies": policies
    }
