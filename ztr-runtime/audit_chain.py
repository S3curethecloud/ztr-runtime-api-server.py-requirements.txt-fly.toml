# =========================================================
# SecureTheCloud — Deterministic Audit Chain (Phase 4)
# Schema: stc.audit.v1
# =========================================================

import hashlib
import json
import os
import threading
import time
import redis
from typing import Any, Dict, Optional

# ---------------------------------------------------------
# Configuration
# ---------------------------------------------------------
SCHEMA_VERSION = "stc.audit.v1"
DEFAULT_ENV = os.getenv("APP_ENV", "prod")
GENESIS_HASH = os.getenv("AUDIT_CHAIN_GENESIS", "0" * 64)

AUDIT_REDIS_URL = os.getenv("REDIS_AUDIT_URL")
AUDIT_HEAD_KEY = "ztr:audit:head"

_audit_redis = None
_FALLBACK_BUFFER = []

# ---------------------------------------------------------
# In-Memory Chain State (per process)
# ---------------------------------------------------------
_LOCK = threading.Lock()
_PREVIOUS_HASH = GENESIS_HASH


# ---------------------------------------------------------
# Deterministic JSON Canonicalizer
# ---------------------------------------------------------
def _canonical(obj: Any) -> str:
    """
    Deterministic JSON:
    - Sorted keys
    - No whitespace
    - UTF-8 safe
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


# ---------------------------------------------------------
# Redis Initialization
# ---------------------------------------------------------
def _init_audit_redis():
    global _audit_redis, _PREVIOUS_HASH

    if not AUDIT_REDIS_URL:
        print(
            _canonical({
                "event_type": "audit.redis_not_configured",
                "severity": "WARNING",
                "ts_ms": int(time.time() * 1000)
            }),
            flush=True
        )
        return

    try:
        _audit_redis = redis.from_url(AUDIT_REDIS_URL, decode_responses=True)
        stored_head = _audit_redis.get(AUDIT_HEAD_KEY)
        if stored_head:
            _PREVIOUS_HASH = stored_head
    except Exception:
        print(
            _canonical({
                "event_type": "audit.redis_connection_failed",
                "severity": "CRITICAL",
                "ts_ms": int(time.time() * 1000)
            }),
            flush=True
        )


_init_audit_redis()


# ---------------------------------------------------------
# SHA256 Helper
# ---------------------------------------------------------
def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


# ---------------------------------------------------------
# Core Emit Function
# ---------------------------------------------------------
def emit_event(
    *,
    event_type: str,
    service: str,
    payload: Dict[str, Any],
    correlation_id: Optional[str] = None,
    env: Optional[str] = None,
) -> Dict[str, Any]:

    global _PREVIOUS_HASH

    if not event_type:
        raise ValueError("event_type required")

    if not service:
        raise ValueError("service required")

    if not isinstance(payload, dict):
        raise ValueError("payload must be dict")

    env = env or DEFAULT_ENV

    base_event = {
        "schema": SCHEMA_VERSION,
        "event_type": event_type,
        "ts_ms": int(time.time() * 1000),
        "service": service,
        "env": env,
        "correlation_id": correlation_id,
        "payload": payload,
    }

    with _LOCK:
        prev_hash = _PREVIOUS_HASH
        event_hash = _sha256(_canonical(base_event) + prev_hash)

        _PREVIOUS_HASH = event_hash

        if _audit_redis:
            try:
                _audit_redis.set(AUDIT_HEAD_KEY, event_hash)
            except Exception:
                _FALLBACK_BUFFER.append(event_hash)
                print(
                    _canonical({
                        "event_type": "audit_chain_unavailable",
                        "severity": "CRITICAL",
                        "event_hash": event_hash,
                        "ts_ms": int(time.time() * 1000)
                    }),
                    flush=True
                )

    envelope = {
        **base_event,
        "prev_hash": prev_hash,
        "event_hash": event_hash,
    }

    print(_canonical(envelope), flush=True)

    return envelope


# ---------------------------------------------------------
# Optional: Chain State Introspection (Debug Only)
# ---------------------------------------------------------
def get_current_chain_head() -> str:
    return _PREVIOUS_HASH


def reset_chain(genesis: Optional[str] = None) -> None:
    global _PREVIOUS_HASH
    with _LOCK:
        _PREVIOUS_HASH = genesis or GENESIS_HASH
