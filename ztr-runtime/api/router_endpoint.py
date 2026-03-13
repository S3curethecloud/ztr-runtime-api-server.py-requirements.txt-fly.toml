from fastapi import APIRouter
from api.runtime_router import select_runtime_node

router = APIRouter()


@router.get("/v1/runtime/route")
async def route_request(key: str):

    node = select_runtime_node(key)

    return {
        "route_key": key,
        "target_node": node
    }
