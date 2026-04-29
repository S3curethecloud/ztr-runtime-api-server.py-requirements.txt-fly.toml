import json
import asyncio
import redis
from fastapi import APIRouter, Request, Depends, Query, HTTPException
from fastapi.responses import StreamingResponse
import os
import logging
import time
import uuid

from api.auth import require_tenant_api_key, derive_tenant_from_api_key

router = APIRouter(prefix="/v1")

REDIS_URL = os.environ["REDIS_URL"]

r = redis.from_url(
    REDIS_URL,
    decode_responses=True
)

CHANNEL = "decision_events"

logger = logging.getLogger("stc.runtime")


def publish_decision(event: dict):
    try:
        now = int(time.time() * 1000)

        payload = {
            "event_type": "decision",
            "timestamp": event.get("timestamp") or now,
            "tenant_id": event.get("tenant_id"),
            "principal": event.get("principal"),
            "intent": event.get("intent"),
            "decision": event.get("decision") or "unknown",
            "risk_score": event.get("risk_score") if event.get("risk_score") is not None else 0,
            "policy_revision": event.get("policy_revision") or "unknown",
            "event_id": event.get("event_id") or str(uuid.uuid4()),
            "metadata": event.get("metadata", {})
        }

        r.publish(CHANNEL, json.dumps(payload))

    except Exception as e:
        logger.error(
            "publish_decision error",
            extra={"error": str(e), "event": event}
        )
        return

    try:
        tenant_id = payload.get("tenant_id") or "unknown"
        key = f"ztr:{tenant_id}:decisions"

        r.lpush(key, json.dumps(payload))
        r.ltrim(key, 0, 49)

    except Exception as exc:
        logger.error(
            "decision replay persistence failure",
            extra={"error": str(exc), "event": event}
        )

    try:
        ts = int(payload.get("timestamp") or 0)

        tenant = payload.get("tenant_id") or "unknown"
        principal = payload.get("principal") or "unknown"
        intent = payload.get("intent") or "unknown"
        decision = payload.get("decision") or "unknown"
        risk_score = payload.get("risk_score") if payload.get("risk_score") is not None else 0

        decision_key = f"metrics:decision:{ts}:{tenant}:{principal}:{intent}:{decision}"

        r.hset(
            decision_key,
            mapping={
                "tenant_id": tenant,
                "principal": principal,
                "intent": intent,
                "decision": decision,
                "risk_score": risk_score,
                "policy_revision": payload.get("policy_revision")
            }
        )

        r.expire(decision_key, 86400)

    except Exception as exc:
        logger.error(
            "decision persistence failure",
            extra={"error": str(exc), "event": event}
        )

    # 🔒 AEGIS TIMELINE WRITE (CRITICAL)
    try:
        tenant_id = payload.get("tenant_id")
        principal = payload.get("principal")

        if tenant_id and principal:
            timeline_key = f"ztr:aegis:timeline:{tenant_id}:{principal}"

            r.lpush(timeline_key, json.dumps({
                "timestamp": payload.get("timestamp"),
                "decision": payload.get("decision"),
                "risk_score": payload.get("risk_score") if payload.get("risk_score") is not None else 0,
                "policy_revision": payload.get("policy_revision"),
                "event_id": payload.get("event_id")
            }))

            r.ltrim(timeline_key, 0, 50)

    except Exception as exc:
        logger.error(
            "aegis timeline write failure",
            extra={"error": str(exc), "event": event}
        )

    # 🔒 AEGIS CURRENT SIGNAL (REAL-TIME)
    try:
        tenant_id = payload.get("tenant_id")
        principal = payload.get("principal")

        if tenant_id and principal:
            current_key = f"ztr:aegis:{tenant_id}:{principal}"

            r.set(
                current_key,
                json.dumps({
                    "anomaly": 1 if payload.get("decision") == "deny" else 0,
                    "risk_delta": payload.get("risk_score") if payload.get("risk_score") is not None else 0,
                    "confidence": 0.9,
                    "ts": payload.get("timestamp")
                }),
                ex=300
            )

    except Exception as exc:
        logger.error(
            "aegis current signal failure",
            extra={"error": str(exc), "event": event}
        )


@router.get("/decisions/recent")
def get_recent_decisions(
    limit: int = 20,
    tenant_id: str = Depends(require_tenant_api_key)
):
    limit = min(max(limit, 1), 100)

    events = r.lrange(f"ztr:{tenant_id}:decisions", 0, limit - 1)

    return {
        "events": [json.loads(e) for e in events]
    }


async def event_generator(request: Request, tenant_id: str):
    pubsub = r.pubsub()
    pubsub.subscribe(CHANNEL)

    loop = asyncio.get_running_loop()
    last_keepalive = time.time()

    try:
        while True:
            if await request.is_disconnected():
                break

            message = await loop.run_in_executor(
                None,
                lambda: pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
            )

            if message and message.get("type") == "message":
                try:
                    event = json.loads(message["data"])
                except Exception as exc:
                    logger.error("decision stream json decode failure", extra={"error": str(exc)})
                    continue

                if event.get("tenant_id") != tenant_id:
                    continue

                yield f"data: {json.dumps(event)}\n\n"
                last_keepalive = time.time()
                continue

            if time.time() - last_keepalive >= 15:
                yield ": keepalive\n\n"
                last_keepalive = time.time()

    except Exception:
        logger.exception("decision stream generator failure")
        raise

    finally:
        try:
            pubsub.unsubscribe(CHANNEL)
        finally:
            pubsub.close()


@router.get("/decisions/stream")
async def stream_decisions(
    request: Request,
    api_key: str = Query(None)
):
    if not api_key:
        raise HTTPException(status_code=401, detail="Missing API key")

    tenant_id = derive_tenant_from_api_key(api_key)

    return StreamingResponse(
        event_generator(request, tenant_id),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )
