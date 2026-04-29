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

SCHEMA_VERSION = "stc.audit.v1"
DEFAULT_ENV    = os.getenv("APP_ENV", "prod")
GENESIS_HASH   = os.getenv("AUDIT_CHAIN_GENESIS", "0" * 64)
REDIS_URL      = os.environ["REDIS_URL"]

_audit_redis = redis.from_url(REDIS_URL, decode_responses=True)
_LOCK = threading.Lock()

STRICT_SCHEMA = True


def _keys(tenant_id: str) -> dict:
    return {
        "head":         f"ztr:{tenant_id}:audit:head",
        "index_all":    f"ztr:{tenant_id}:audit:index:all",
        "index_prefix": f"ztr:{tenant_id}:audit:index:",
        "entry_prefix": f"ztr:{tenant_id}:audit:entry:",
    }


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def emit_event(
    *,
    event_type: str,
    service: str,
    payload: Dict[str, Any],
    tenant_id: str,
    correlation_id: Optional[str] = None,
    env: Optional[str] = None,
) -> Dict[str, Any]:

    print("AUDIT_CHAIN_VERSION: TENANT MODE ACTIVE", flush=True)

    if not event_type:
        raise ValueError("event_type required")
    if not service:
        raise ValueError("service required")
    if not isinstance(payload, dict):
        raise ValueError("payload must be dict")
    if not tenant_id:
        raise ValueError("tenant_id required")

    if not isinstance(tenant_id, str) or not tenant_id.strip():
        raise ValueError("tenant_id must be non-empty string")

    env = env or DEFAULT_ENV
    k   = _keys(tenant_id)

    base_event = {
        "schema": SCHEMA_VERSION,
        "event_id": str(uuid.uuid4()),
        "tenant_id": tenant_id,
        "event_type": event_type,
        "ts_ms": int(time.time() * 1000),
        "service": service,
        "env": env,
        "correlation_id": correlation_id,
        "payload": payload,
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


def get_entry(event_hash: str, tenant_id: str) -> Optional[Dict[str, Any]]:

    k   = _keys(tenant_id)
    raw = _audit_redis.get(k["entry_prefix"] + event_hash)

    if not raw:
        return None

    return json.loads(raw)


def list_index(tenant_id: str, event_type: str = "all", limit: int = 50) -> list[str]:

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


def verify_chain(tenant_id: str, limit: int = 5000) -> Dict[str, Any]:

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

        if entry.get("tenant_id") != tenant_id:
            return {
                "status": "broken",
                "reason": "tenant_mismatch",
                "event_hash": h,
                "expected_tenant": tenant_id,
                "found_tenant": entry.get("tenant_id"),
            }

        if STRICT_SCHEMA and entry.get("schema") != SCHEMA_VERSION:
            return {
                "status": "broken",
                "reason": "schema_mismatch",
                "event_hash": h,
                "expected_schema": SCHEMA_VERSION,
                "found_schema": entry.get("schema"),
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
        "tenant_id": tenant_id,
        "schema": SCHEMA_VERSION,
        "events_verified": len(hashes),
        "chain_head": prev_hash,
        "verified_at": int(time.time() * 1000),
    }


def get_latest_event(tenant_id: str, event_type: str):

    pattern = f"ztr:{tenant_id}:audit:entry:*"

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
