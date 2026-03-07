# =========================================================
# redis_keys.py — Canonical Redis Key Builder
# SecureTheCloud — Runtime Safety Control
#
# Purpose:
#   Enforce deterministic tenant-scoped Redis key structure.
#
# Required format:
#   ztr:{tenant_id}:{resource}:{suffix}
#
# Guarantees:
#   - No cross-tenant key collisions
#   - Safe Redis SCAN patterns
#   - Deterministic key generation across the runtime
# =========================================================

def tenant_key(tenant_id: str, resource: str, suffix: str | None = None) -> str:
    base = f"ztr:{tenant_id}:{resource}"
    return f"{base}:{suffix}" if suffix else base
