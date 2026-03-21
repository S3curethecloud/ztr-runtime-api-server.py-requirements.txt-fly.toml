import time
import hashlib
import json
import redis

r = redis.from_url("redis://localhost:6379/0", decode_responses=True)


def register_tenant(tenant_id: str):
    key = f"tenant:{tenant_id}:config"

    if r.exists(key):
        return {"status": "exists"}

    r.hset(key, mapping={
        "status": "active",
        "created_at": int(time.time())
    })

    return {"status": "created"}


def set_policy(tenant_id: str, policy_text: str):
    digest = hashlib.sha256(policy_text.encode()).hexdigest()

    r.hset(f"tenant:{tenant_id}:policy", mapping={
        "version": "v1.0.0",
        "digest": digest
    })

    r.set(f"tenant:{tenant_id}:policy_anchor", digest)

    return {
        "status": "policy_set",
        "digest": digest
    }


def get_policy(tenant_id: str):
    return r.hgetall(f"tenant:{tenant_id}:policy")
