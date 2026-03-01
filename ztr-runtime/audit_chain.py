# =========================================================
# SecureTheCloud — Deterministic Audit Chain (Phase 4)
# Schema: stc.audit.v1
# =========================================================

import hashlib
import json
import os
import threading
import time
from typing import Any, Dict, Optional

# ---------------------------------------------------------
# Configuration
# ---------------------------------------------------------
SCHEMA_VERSION = "stc.audit.v1"
DEFAULT_ENV = os.getenv("APP_ENV", "prod")
GENESIS_HASH = os.getenv("AUDIT_CHAIN_GENESIS", "0" * 64)

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
    """
    Emits a structured audit event and advances the hash chain.

    Rules:
    - No mutation after hashing
    - event_hash = sha256(canonical(base_event) + previous_hash)
    - previous_hash updated atomically
    - Output is single-line JSON
    """

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

    envelope = {
        **base_event,
        "prev_hash": prev_hash,
        "event_hash": event_hash,
    }

    # Single-line structured log output
    print(_canonical(envelope), flush=True)

    return envelope


# ---------------------------------------------------------
# Optional: Chain State Introspection (Debug Only)
# ---------------------------------------------------------
def get_current_chain_head() -> str:
    """
    Returns current head hash (useful for debugging / tests).
    Not intended for runtime logic decisions.
    """
    return _PREVIOUS_HASH


def reset_chain(genesis: Optional[str] = None) -> None:
    """
    Resets chain head (ONLY for testing environments).
    """
    global _PREVIOUS_HASH
    with _LOCK:
        _PREVIOUS_HASH = genesis or GENESIS_HASH
