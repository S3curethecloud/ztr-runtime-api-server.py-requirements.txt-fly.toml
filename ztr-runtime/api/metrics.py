# api/metrics.py

from fastapi import APIRouter
import time
import os
import redis

router = APIRouter()

NODE_ID = os.getenv("NODE_ID", "runtime-node")

redis_client = redis.from_url(
    os.environ["REDIS_URL"],
    decode_responses=True
)


@router.get("/v1/audit/metrics")
async def runtime_metrics():

    tokens = int(redis_client.get("metrics:tokens_issued") or 0)
    allowed = int(redis_client.get("metrics:policy_allowed") or 0)
    denied = int(redis_client.get("metrics:policy_denied") or 0)
    revoked = int(redis_client.get("metrics:sessions_revoked") or 0)

    introspect_success = int(redis_client.get("metric:introspect_success") or 0)
    introspect_inactive = int(redis_client.get("metric:introspect_inactive") or 0)
    token_invalid = int(redis_client.get("metric:token_invalid") or 0)
    token_expired = int(redis_client.get("metric:token_expired") or 0)
    introspection_failure = int(redis_client.get("metric:introspection_failure") or 0)

    return {
        "node_id": NODE_ID,
        "tokens_issued": tokens,
        "policy_allowed": allowed,
        "policy_denied": denied,
        "sessions_revoked": revoked,
        "introspect_success": introspect_success,
        "introspect_inactive": introspect_inactive,
        "token_invalid": token_invalid,
        "token_expired": token_expired,
        "introspection_failure": introspection_failure,
        "timestamp": int(time.time())
    }
