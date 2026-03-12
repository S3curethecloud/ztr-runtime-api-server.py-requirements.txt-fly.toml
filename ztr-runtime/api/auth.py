import hashlib
import redis
import os
from fastapi import Header, HTTPException, Request

r = redis.from_url(
    os.environ["REDIS_URL"],
    decode_responses=True
)

def sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()

def derive_tenant_from_api_key(api_key: str) -> str:

    hashed = sha256(api_key)

    tenant_id = r.get(f"ztr:apikey:{hashed}")
    if not tenant_id:
        raise HTTPException(status_code=401, detail="Invalid API key")

    tenant_status = r.get(f"ztr:tenant:{tenant_id}:status")

    if tenant_status == "disabled":
        raise HTTPException(status_code=401, detail="tenant_disabled")

    return tenant_id


def require_tenant_api_key(
    request: Request,
    x_stc_api_key: str = Header(None)
) -> str:

    api_key = x_stc_api_key

    if not api_key:
        api_key = request.query_params.get("api_key")

    if not api_key:
        raise HTTPException(status_code=401, detail="Missing API key")

    return derive_tenant_from_api_key(api_key)
