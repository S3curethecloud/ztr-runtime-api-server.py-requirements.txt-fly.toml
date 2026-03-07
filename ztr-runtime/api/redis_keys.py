# =========================================================
# redis_keys.py — Canonical Redis Key Builder
# SecureTheCloud — Phase 8 Foundation
#
# Purpose:
#   Enforce deterministic tenant-scoped Redis key structure.
#
# Required format:
#   ztr:tenant:{tenant_id}:{resource}
#   ztr:tenant:{tenant_id}:{resource}:{suffix}
# =========================================================

def tenant_base(tenant_id: str) -> str:
    return f"ztr:tenant:{tenant_id}"

def tenant_key(tenant_id: str, resource: str, suffix: str | None = None) -> str:
    base = f"{tenant_base(tenant_id)}:{resource}"
    return f"{base}:{suffix}" if suffix else base

def apikey_lookup_key(key_hash: str) -> str:
    return f"ztr:apikey:{key_hash}"

def tenant_session_key(tenant_id: str, sid: str) -> str:
    return tenant_key(tenant_id, "session", sid)

def tenant_session_index_key(tenant_id: str) -> str:
    return tenant_key(tenant_id, "session_index")

def tenant_usage_key(tenant_id: str, period: str, metric: str | None = None) -> str:
    base = tenant_key(tenant_id, "usage", period)
    return f"{base}:{metric}" if metric else base
