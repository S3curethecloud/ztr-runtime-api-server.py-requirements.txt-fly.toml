# =========================================================
# FILE: audit_chain.py
# PURPOSE: Governance-grade tamper-evident audit log (hash chain)
# GOVERNANCE: MGF — AUTHORITY-ALL
#
# DESIGN:
#  - Canonical JSON (sort_keys + compact separators)
#  - Hash chain: entry_hash = sha256(prev_hash + canonical_entry_json)
#  - Store:
#      - ztr:audit:chain_head -> latest entry_hash
#      - ztr:audit:index:all -> list of entry_hash in append order
#      - ztr:audit:index:<event_type> -> per-type index
#      - ztr:audit:entry:<entry_hash> -> full entry record
# =========================================================

from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from typing import Any, Dict, Optional

import redis
from redis.exceptions import WatchError


# ---------------------------------------------------------
# Redis client (same env contract as runtime)
# ---------------------------------------------------------
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", None)

_r = redis.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    password=REDIS_PASSWORD,
    decode_responses=True,
)


# ---------------------------------------------------------
# Keys
# ---------------------------------------------------------
CHAIN_HEAD_KEY = "ztr:audit:chain_head"
INDEX_ALL_KEY = "ztr:audit:index:all"
ENTRY_KEY_PREFIX = "ztr:audit:entry:"          # ztr:audit:entry:<hash>
INDEX_TYPE_PREFIX = "ztr:audit:index:"         # ztr:audit:index:<event_type>

GENESIS_HASH = ""  # deterministic genesis


def _canonical_json(obj: Dict[str, Any]) -> str:
    # stable ordering + compact output
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def emit_event(
    *,
    event_type: str,
    service: str,
    correlation_id: str,
    payload: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Append an audit event using a tamper-evident hash chain.

    Returns:
      {
        "entry_hash": ...,
        "prev_hash": ...,
        "chain_head": ...,
        "timestamp_ms": ...
      }
    """

    ts_ms = int(time.time() * 1000)

    base_entry: Dict[str, Any] = {
        "event_id": str(uuid.uuid4()),
        "event_type": event_type,
        "service": service,
        "correlation_id": correlation_id,
        "timestamp_ms": ts_ms,
        "payload": payload,
        # prev_hash added inside atomic loop
    }

    # -----------------------------------------------------
    # Best-effort atomic append with WATCH (single-tenant safe)
    # -----------------------------------------------------
    for _ in range(5):
        try:
            with _r.pipeline() as pipe:
                pipe.watch(CHAIN_HEAD_KEY)

                prev_hash = pipe.get(CHAIN_HEAD_KEY) or GENESIS_HASH

                entry_for_hash = dict(base_entry)
                entry_for_hash["prev_hash"] = prev_hash

                canonical = _canonical_json(entry_for_hash)
                entry_hash = _sha256_hex(prev_hash + canonical)

                full_entry = dict(entry_for_hash)
                full_entry["entry_hash"] = entry_hash

                # Store entry + update head + indexes
                pipe.multi()
                pipe.set(CHAIN_HEAD_KEY, entry_hash)
                pipe.rpush(INDEX_ALL_KEY, entry_hash)
                pipe.rpush(INDEX_TYPE_PREFIX + event_type, entry_hash)
                pipe.set(ENTRY_KEY_PREFIX + entry_hash, _canonical_json(full_entry))
                pipe.execute()

                return {
                    "entry_hash": entry_hash,
                    "prev_hash": prev_hash,
                    "chain_head": entry_hash,
                    "timestamp_ms": ts_ms,
                }

        except WatchError:
            continue

    # If contention persists (unlikely single-tenant), fail deterministically
    raise RuntimeError("audit_chain_append_failed")


def get_entry(entry_hash: str) -> Optional[Dict[str, Any]]:
    raw = _r.get(ENTRY_KEY_PREFIX + entry_hash)
    if not raw:
        return None
    return json.loads(raw)


def list_index(event_type: str = "all", limit: int = 50) -> list[str]:
    if event_type == "all":
        key = INDEX_ALL_KEY
    else:
        key = INDEX_TYPE_PREFIX + event_type

    # newest first (right side)
    hashes = _r.lrange(key, max(0, _r.llen(key) - limit), -1)
    return list(reversed(hashes))


def verify_chain(limit: int = 5000) -> Dict[str, Any]:
    """
    Verify the audit hash chain for the last N entries (default: 5000).
    """
    total = _r.llen(INDEX_ALL_KEY)
    if total == 0:
        return {"status": "valid", "events_verified": 0, "reason": "empty"}

    start = max(0, total - limit)
    hashes = _r.lrange(INDEX_ALL_KEY, start, -1)

    prev_hash = GENESIS_HASH
    for h in hashes:
        entry = get_entry(h)
        if not entry:
            return {"status": "broken", "reason": "missing_entry", "entry_hash": h}

        if entry.get("prev_hash") != prev_hash:
            return {
                "status": "broken",
                "reason": "prev_hash_mismatch",
                "entry_hash": h,
                "expected_prev": prev_hash,
                "found_prev": entry.get("prev_hash"),
            }

        # recompute hash
        entry_for_hash = {
            "event_id": entry["event_id"],
            "event_type": entry["event_type"],
            "service": entry["service"],
            "correlation_id": entry["correlation_id"],
            "timestamp_ms": entry["timestamp_ms"],
            "payload": entry["payload"],
            "prev_hash": entry["prev_hash"],
        }
        canonical = _canonical_json(entry_for_hash)
        recalculated = _sha256_hex(prev_hash + canonical)

        if recalculated != entry.get("entry_hash"):
            return {
                "status": "broken",
                "reason": "hash_mismatch",
                "entry_hash": h,
                "expected": recalculated,
                "found": entry.get("entry_hash"),
            }

        prev_hash = entry["entry_hash"]

    return {"status": "valid", "events_verified": len(hashes), "chain_head": prev_hash}
