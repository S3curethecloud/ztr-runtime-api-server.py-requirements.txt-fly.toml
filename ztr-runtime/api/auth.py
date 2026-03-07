import hashlib
import redis
import os
from fastapi import Header, HTTPException

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
    return tenant_id

def require_tenant_api_key(x_stc_api_key: str = Header(None)) -> str:
    if not x_stc_api_key:
        raise HTTPException(status_code=401, detail="Missing API key")
    return derive_tenant_from_api_key(x_stc_api_key)
