from fastapi import APIRouter, HTTPException
import redis
import os
import json
import time

router = APIRouter(prefix="/v1/admin", tags=["control-plane"])

REDIS_URL = os.environ["REDIS_URL"]

r = redis.from_url(
    REDIS_URL,
    decode_responses=True
)


@router.post("/policy/publish")
async def publish_policy_update(payload: dict):

    message = {
        "timestamp": int(time.time()),
        "policy_revision": payload.get("policy_revision"),
        "policy_bundle": payload.get("bundle")
    }

    r.publish("policy_updates", json.dumps(message))

    return {
        "status": "published",
        "revision": payload.get("policy_revision")
    }
