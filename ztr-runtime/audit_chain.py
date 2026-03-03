# =========================================================
# SecureTheCloud — Deterministic Audit Chain (Phase 4)
# Schema: stc.audit.v1
# GOVERNANCE: MGF — AUTHORITY-ALL
#
# Upgrade (Phase 4):
#   - Store every event entry in Redis (replayable)
#   - Maintain indexes for retrieval
#   - Maintain hash-chain head (tamper-evident)
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
# Configuration
# ---------------------------------------------------------
SCHEMA_VERSION = "stc.audit.v1"
DEFAULT_ENV = os.getenv("APP_ENV", "prod")
GENESIS_HASH = os.getenv("AUDIT_CHAIN_GENESIS", "0" * 64)

REDIS_URL = os.environ["REDIS_URL"]

# ---------------------------------------------------------
# Redis keys
# ---------------------------------------------------------
AUDIT_HEAD_KEY = "ztr:audit:head"
AUDIT_INDEX_ALL = "ztr:audit:index:all"
AUDIT_INDEX_PREFIX = "ztr:audit:index:"          # ztr:audit:index:<event_type>
AUDIT_ENTRY_PREFIX = "ztr:audit:entry:"          # ztr:audit:entry:<event_hash>

# ---------------------------------------------------------
# Redis client
# ---------------------------------------------------------
_audit_redis = redis.from_url(
    REDIS_URL,
    decode_responses=True,
)

_LOCK = threading.Lock()


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def emit_event(
    *,
    event_type: str,
    service: str,
    payload: Dict[str, Any],
    correlation_id: Optional[str] = None,
    env: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Append an audit event using a tamper-evident hash chain.
    Stores:
      - head hash
      - entry record (by hash)
      - indexes (all + per event_type)
    Returns the full envelope (incl hashes).
    """

    if not event_type:
        raise ValueError("event_type required")
    if not service:
        raise ValueError("service required")
    if not isinstance(payload, dict):
        raise ValueError("payload must be dict")

    env = env or DEFAULT_ENV

    base_event = {
        "schema": SCHEMA_VERSION,
        "event_id": str(uuid.uuid4()),
        "event_type": event_type,
        "ts_ms": int(time.time() * 1000),
        "service": service,
        "env": env,
        "correlation_id": correlation_id,
        "payload": payload,
    }

    # -----------------------------------------------------
    # Multi-machine safe: WATCH head, compute, commit
    # -----------------------------------------------------
    for _ in range(5):
        try:
            with _audit_redis.pipeline() as pipe:
                pipe.watch(AUDIT_HEAD_KEY)

                prev_hash = pipe.get(AUDIT_HEAD_KEY) or GENESIS_HASH

                # IMPORTANT: keep deterministic ordering
                envelope = dict(base_event)
                envelope["prev_hash"] = prev_hash

                # Deterministic hash
                event_hash = _sha256(_canonical(envelope) + prev_hash)
                envelope["event_hash"] = event_hash

                pipe.multi()
                pipe.set(AUDIT_HEAD_KEY, event_hash)
                pipe.rpush(AUDIT_INDEX_ALL, event_hash)
                pipe.rpush(AUDIT_INDEX_PREFIX + event_type, event_hash)
                pipe.set(AUDIT_ENTRY_PREFIX + event_hash, _canonical(envelope))
                pipe.execute()

                print(_canonical(envelope), flush=True)

                return envelope

        except WatchError:
            continue

    raise RuntimeError("audit_chain_append_failed")


def get_entry(event_hash: str) -> Optional[Dict[str, Any]]:
    raw = _audit_redis.get(AUDIT_ENTRY_PREFIX + event_hash)
    if not raw:
        return None
    return json.loads(raw)


def list_index(event_type: str = "all", limit: int = 50) -> list[str]:
    if event_type == "all":
        key = AUDIT_INDEX_ALL
    else:
        key = AUDIT_INDEX_PREFIX + event_type

    total = _audit_redis.llen(key)
    if total <= 0:
        return []

    start = max(0, total - limit)
    hashes = _audit_redis.lrange(key, start, -1)
    return list(reversed(hashes))


def verify_chain(limit: int = 5000) -> Dict[str, Any]:
    total = _audit_redis.llen(AUDIT_INDEX_ALL)
    if total == 0:
        return {"status": "valid", "events_verified": 0, "reason": "empty"}

    start = max(0, total - limit)
    hashes = _audit_redis.lrange(AUDIT_INDEX_ALL, start, -1)

    prev_hash = GENESIS_HASH
    for h in hashes:
        entry = get_entry(h)
        if not entry:
            return {"status": "broken", "reason": "missing_entry", "event_hash": h}

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

    return {"status": "valid", "events_verified": len(hashes), "chain_head": prev_hash}
