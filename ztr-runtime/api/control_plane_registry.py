# FILE: api/control_plane_registry.py
# Phase 7 — Tenant Registry (Control Plane Authority)

from fastapi import APIRouter, HTTPException
import redis
import os
import time
import json

router = APIRouter(prefix="/v1/admin", tags=["control-plane-registry"])

REDIS_URL = os.environ["REDIS_URL"]

r = redis.from_url(
    REDIS_URL,
    decode_responses=True
)


def tenant_registry_key(tenant_id: str) -> str:
    return f"ztr:control:tenant:{tenant_id}"


@router.post("/registry/create")
def create_tenant_registry(payload: dict):

    tenant_id = payload.get("tenant_id")

    if not tenant_id:
        raise HTTPException(status_code=400, detail="missing_tenant_id")

    key = tenant_registry_key(tenant_id)

    if r.exists(key):
        raise HTTPException(status_code=409, detail="tenant_already_exists")

    timestamp = int(time.time())

    record = {
        "tenant_id": tenant_id,
        "created_at": timestamp,
        "status": "active",
        "policy_version": "unassigned",
        "policy_digest": "",
        "last_updated": timestamp
    }

    r.hset(key, mapping=record)

    return {
        "status": "created",
        "tenant": record
    }


@router.get("/registry/list")
def list_tenants():

    pattern = "ztr:control:tenant:*"

    tenants = []

    for key in r.scan_iter(pattern):

        data = r.hgetall(key)

        if data:
            tenants.append(data)

    return {
        "count": len(tenants),
        "tenants": tenants
    }


@router.get("/registry/get")
def get_tenant(tenant_id: str):

    key = tenant_registry_key(tenant_id)

    data = r.hgetall(key)

    if not data:
        raise HTTPException(status_code=404, detail="tenant_not_found")

    return {
        "tenant": data
    }
