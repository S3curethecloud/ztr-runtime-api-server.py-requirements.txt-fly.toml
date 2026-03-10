import json
import asyncio
from fastapi import APIRouter
from fastapi.responses import StreamingResponse

router = APIRouter()

# --------------------------------------------------
# Subscriber registry
# --------------------------------------------------

subscribers = set()

# --------------------------------------------------
# Publish decision events
# --------------------------------------------------

async def publish_decision(event: dict):

    dead = []

    for queue in subscribers:
        try:
            queue.put_nowait(event)
        except asyncio.QueueFull:
            dead.append(queue)

    for q in dead:
        subscribers.discard(q)

# --------------------------------------------------
# Event generator for each subscriber
# --------------------------------------------------

async def event_generator(queue):

    try:
        while True:
            event = await queue.get()
            yield f"data: {json.dumps(event)}\n\n"
    finally:
        subscribers.discard(queue)

# --------------------------------------------------
# Streaming endpoint
# --------------------------------------------------

@router.get("/decisions/stream")
async def stream_decisions():

    queue = asyncio.Queue(maxsize=100)

    subscribers.add(queue)

    return StreamingResponse(
        event_generator(queue),
        media_type="text/event-stream"
    )
