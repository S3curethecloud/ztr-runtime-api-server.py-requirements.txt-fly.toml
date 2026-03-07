# =========================================================
# SecureTheCloud — Deterministic Audit Chain
# Schema: stc.audit.v1
# GOVERNANCE: MGF — AUTHORITY-ALL
#
# Phase 4: Hash-chained ledger (FROZEN — do not touch)
# Phase 5: Tenant-scoped namespaces (5A-01)
#
# DELTA from Phase 4:
#   - Removed global AUDIT_HEAD_KEY / AUDIT_INDEX_ALL /
#     AUDIT_INDEX_PREFIX / AUDIT_ENTRY_PREFIX constants
#   - Added _keys(tenant_id) helper
#   - Added tenant_id param to: emit_event, get_entry,
#     list_index, verify_chain
#   - Zero changes to hashing logic, WatchError loop,
#     _canonical, _sha256 — all frozen
# =========================================================

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
import uuid
from typing import Any, Dict, Optional

import redis
from redis.exceptions import WatchError

# ---------------------------------------------------------
# Configuration (frozen)
# ---------------------------------------------------------
SCHEMA_VERSION = "stc.audit.v1"
DEFAULT_ENV    = os.getenv("APP_ENV", "prod")
GENESIS_HASH   = os.getenv("AUDIT_CHAIN_GENESIS", "0" * 64)
REDIS_URL      = os.environ["REDIS_URL"]

# ---------------------------------------------------------
# Redis client (frozen)
# ---------------------------------------------------------
_audit_redis = redis.from_url(REDIS_URL, decode_responses=True)
_LOCK = threading.Lock()


# ---------------------------------------------------------
# Phase 5A-01 — tenant-scoped key builder
# Replaces the four global key constants from Phase 4.
# ---------------------------------------------------------
def _keys(tenant_id: str) -> dict:
    """Return all Redis key strings scoped to this tenant."""
    return {
        "head":         f"ztr:{tenant_id}:audit:head",
        "index_all":    f"ztr:{tenant_id}:audit:index:all",
        "index_prefix": f"ztr:{tenant_id}:audit:index:",
        "entry_prefix": f"ztr:{tenant_id}:audit:entry:",
    }


# ---------------------------------------------------------
# Hashing helpers (frozen — Phase 4)
# ---------------------------------------------------------
def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


# ---------------------------------------------------------
# emit_event — Phase 5A-01: added tenant_id param
# Everything else frozen (WatchError loop, envelope shape,
# hash computation order).
# ---------------------------------------------------------
def emit_event(
    *,
    event_type: str,
    service: str,
    payload: Dict[str, Any],
    tenant_id: str,
    correlation_id: Optional[str] = None,
    env: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Append an audit event to the tenant-scoped tamper-evident hash chain.
    """

    if not event_type:
        raise ValueError("event_type required")
    if not service:
        raise ValueError("service required")
    if not isinstance(payload, dict):
        raise ValueError("payload must be dict")
    if not tenant_id:
        raise ValueError("tenant_id required")

    env = env or DEFAULT_ENV
    k   = _keys(tenant_id)

    base_event = {
        "schema":         SCHEMA_VERSION,
        "event_id":       str(uuid.uuid4()),
        "event_type":     event_type,
        "ts_ms":          int(time.time() * 1000),
        "service":        service,
        "env":            env,
        "correlation_id": correlation_id,
        "payload":        payload,
    }

    for _ in range(5):
        try:
            with _audit_redis.pipeline() as pipe:
                pipe.watch(k["head"])

                prev_hash = pipe.get(k["head"]) or GENESIS_HASH

                envelope              = dict(base_event)
                envelope["prev_hash"] = prev_hash

                event_hash             = _sha256(_canonical(envelope) + prev_hash)
                envelope["event_hash"] = event_hash

                pipe.multi()
                pipe.set(k["head"], event_hash)
                pipe.rpush(k["index_all"], event_hash)
                pipe.rpush(k["index_prefix"] + event_type, event_hash)
                pipe.set(k["entry_prefix"] + event_hash, _canonical(envelope))
                pipe.execute()

                print(_canonical(envelope), flush=True)
                return envelope

        except WatchError:
            continue

    raise RuntimeError("audit_chain_append_failed")


# ---------------------------------------------------------
# get_entry — Phase 5A-01: added tenant_id param
# ---------------------------------------------------------
def get_entry(
    event_hash: str,
    tenant_id: str,
) -> Optional[Dict[str, Any]]:

    k   = _keys(tenant_id)
    raw = _audit_redis.get(k["entry_prefix"] + event_hash)

    if not raw:
        return None

    return json.loads(raw)


# ---------------------------------------------------------
# list_index — Phase 5A-01: added tenant_id param
# ---------------------------------------------------------
def list_index(
    tenant_id: str,
    event_type: str = "all",
    limit: int = 50,
) -> list[str]:

    k = _keys(tenant_id)

    if event_type == "all":
        key = k["index_all"]
    else:
        key = k["index_prefix"] + event_type

    total = _audit_redis.llen(key)

    if total <= 0:
        return []

    start  = max(0, total - limit)
    hashes = _audit_redis.lrange(key, start, -1)

    return list(reversed(hashes))


# ---------------------------------------------------------
# verify_chain — Phase 5A-01: added tenant_id param
# Hash verification logic frozen (Phase 4).
# ---------------------------------------------------------
def verify_chain(
    tenant_id: str,
    limit: int = 5000,
) -> Dict[str, Any]:

    k     = _keys(tenant_id)
    total = _audit_redis.llen(k["index_all"])

    if total == 0:
        return {"status": "valid", "events_verified": 0, "reason": "empty"}

    start  = max(0, total - limit)
    hashes = _audit_redis.lrange(k["index_all"], start, -1)

    prev_hash = GENESIS_HASH

    for h in hashes:

        entry = get_entry(h, tenant_id=tenant_id)

        if not entry:
            return {
                "status": "broken",
                "reason": "missing_entry",
                "event_hash": h,
            }

        if entry.get("prev_hash") != prev_hash:
            return {
                "status": "broken",
                "reason": "prev_hash_mismatch",
                "event_hash": h,
                "expected_prev": prev_hash,
                "found_prev": entry.get("prev_hash"),
            }

        candidate = dict(entry)
        candidate.pop("event_hash", None)

        recalculated = _sha256(_canonical(candidate) + prev_hash)

        if recalculated != entry.get("event_hash"):
            return {
                "status": "broken",
                "reason": "hash_mismatch",
                "event_hash": h,
                "expected": recalculated,
                "found": entry.get("event_hash"),
            }

        prev_hash = entry["event_hash"]

    return {
        "status": "valid",
        "events_verified": len(hashes),
        "chain_head": prev_hash,
    }


def get_latest_event(tenant_id: str, event_type: str):
    """
    Return the most recent event of a given type for a tenant.
    Used by runtime integrity checks.
    """

    pattern = f"audit:{tenant_id}:*"

    latest = None
    latest_ts = 0

    for key in _audit_redis.scan_iter(pattern):
        raw = _audit_redis.get(key)
        if not raw:
            continue

        try:
            event = json.loads(raw)
        except Exception:
            continue

        if event.get("event_type") != event_type:
            continue

        ts = event.get("ts_ms", 0)

        if ts > latest_ts:
            latest = event
            latest_ts = ts

    return latest
