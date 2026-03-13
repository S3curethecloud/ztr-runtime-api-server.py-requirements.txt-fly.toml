from fastapi import APIRouter
import redis
import os

router = APIRouter()

r = redis.from_url(os.environ["REDIS_URL"], decode_responses=True)

@router.get("/v1/runtime/topology")
async def topology():

    nodes = r.smembers("runtime:nodes")

    return {
        "nodes": list(nodes),
        "timestamp": int(time.time())
    }
