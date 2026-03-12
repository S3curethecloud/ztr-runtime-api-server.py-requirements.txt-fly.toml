# api/metrics.py

from fastapi import APIRouter
import time
import os

router = APIRouter()

NODE_ID = os.getenv("NODE_ID", "runtime-node")

@router.get("/v1/audit/metrics")
async def runtime_metrics():

    return {
        "node_id": NODE_ID,
        "tokens_issued": 0,
        "policy_allowed": 0,
        "policy_denied": 0,
        "sessions_revoked": 0,
        "decision_latency_ms": 0,
        "opa_latency_ms": 0,
        "redis_latency_ms": 0,
        "timestamp": int(time.time())
    }
