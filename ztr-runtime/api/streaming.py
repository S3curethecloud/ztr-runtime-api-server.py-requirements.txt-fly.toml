import json
import asyncio
import redis
from fastapi import APIRouter, Request, Query
from fastapi.responses import StreamingResponse
import os
import logging

from api.auth import require_tenant_api_key

router = APIRouter(prefix="/v1")

REDIS_URL = os.environ["REDIS_URL"]

r = redis.from_url(
    REDIS_URL,
    decode_responses=True
)

CHANNEL = "stc:decisions"

logger = logging.getLogger("stc.runtime")


# --------------------------------------------------
# Publish decision events
# --------------------------------------------------

def publish_decision(event: dict):

    # --------------------------------------------------
    # Publish real-time event (SSE stream)
    # --------------------------------------------------

    r.publish(CHANNEL, json.dumps(event))

    # --------------------------------------------------
    # Persist decision for intelligence analytics
    # --------------------------------------------------

    try:

        ts = int(event.get("timestamp") or 0)

        tenant = event.get("tenant_id", "unknown")
        principal = event.get("principal", "unknown")
        intent = event.get("intent", "unknown")
        decision = event.get("decision", "unknown")

        risk_score = int(event.get("risk_score") or 0)

        decision_key = f"metrics:decision:{ts}:{tenant}:{principal}:{intent}:{decision}"

        r.hset(
            decision_key,
            mapping={
                "tenant_id": tenant,
                "principal": principal,
                "intent": intent,
                "decision": decision,
                "risk_score": risk_score,
                "policy_revision": event.get("policy_revision")
            }
        )

        # retain decision history for 24 hours
        r.expire(decision_key, 86400)

    except Exception as exc:

        logger.error(
            "decision persistence failure",
            extra={"error": str(exc), "event": event}
        )


# --------------------------------------------------
# Stream events (FIXED: disconnect-safe generator)
# --------------------------------------------------

async def event_generator(request: Request):

    pubsub = r.pubsub()
    pubsub.subscribe(CHANNEL)

    loop = asyncio.get_event_loop()

    while True:

        # 🔴 CRITICAL: stop when client disconnects
        if await request.is_disconnected():
            break

        message = await loop.run_in_executor(
            None,
            pubsub.get_message,
            True,
            None
        )

        if message and message["type"] == "message":
            yield f"data: {message['data']}\n\n"


# --------------------------------------------------
# Endpoint (FIXED: dual-mode auth)
# --------------------------------------------------

@router.get("/decisions/stream")
async def stream_decisions(
    request: Request,
    api_key: str = Query(None)
):
    # 🔐 Support BOTH header auth (future) and query auth (EventSource)

    if api_key:
        tenant_id = require_tenant_api_key(api_key)
    else:
        # fallback to header-based auth
        tenant_id = require_tenant_api_key(request)

    return StreamingResponse(
        event_generator(request),
        media_type="text/event-stream"
    )
