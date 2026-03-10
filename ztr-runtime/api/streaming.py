import json
import asyncio
import redis
from fastapi import APIRouter
from fastapi.responses import StreamingResponse
import os

router = APIRouter()

REDIS_URL = os.environ["REDIS_URL"]

r = redis.from_url(
    REDIS_URL,
    decode_responses=True
)

CHANNEL = "stc_decisions"

# --------------------------------------------------
# Publish decision events
# --------------------------------------------------

def publish_decision(event: dict):

    r.publish(CHANNEL, json.dumps(event))

# --------------------------------------------------
# Stream events
# --------------------------------------------------

async def event_generator():

    pubsub = r.pubsub()

    pubsub.subscribe(CHANNEL)

    loop = asyncio.get_event_loop()

    while True:

        message = await loop.run_in_executor(
            None,
            pubsub.get_message,
            True,
            None
        )

        if message and message["type"] == "message":

            yield f"data: {message['data']}\n\n"

# --------------------------------------------------
# Endpoint
# --------------------------------------------------

@router.get("/decisions/stream")
async def stream_decisions():

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream"
    )
