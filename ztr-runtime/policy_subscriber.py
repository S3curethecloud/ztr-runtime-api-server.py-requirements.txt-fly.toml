# =========================================================
# policy_subscriber.py — Policy Update Subscriber
# SecureTheCloud — Phase 7.5-03
#
# Purpose:
#   Subscribe to Redis policy_updates and keep the local
#   runtime view of tenant policy state fresh.
#
# Behavior on policy update:
#   1. Parse and validate pub/sub message
#   2. Flush stale local cache for tenant
#   3. Store fresh policy pointer in in-memory cache
#   4. Invoke optional callback for runtime-specific refresh
#   5. Best-effort OPA probe/log (not a forced reload)
#
# Design:
#   - Runs as a daemon thread started from server.py lifespan
#   - Fail-open on subscriber errors: runtime continues using
#     last-known-good policy behavior
#   - Reconnects with exponential backoff up to 30s
#
# Env vars:
#   REDIS_URL  — canonical Redis connection
#   OPA_URL    — OPA server address (default http://localhost:8181)
# =========================================================

from __future__ import annotations

import json
import os
import threading
import time
from typing import Callable, Optional

import httpx
import redis

REDIS_URL = os.environ["REDIS_URL"]
OPA_URL = os.getenv("OPA_URL", "http://localhost:8181")

CHANNEL = "policy_updates"

# ---------------------------------------------------------
# In-memory policy pointer cache
#
# Shape:
#   {
#     tenant_id: {
#       "version": str,
#       "digest": str,
#       "cached_at": int
#     }
#   }
# ---------------------------------------------------------
_policy_cache: dict[str, dict] = {}
_cache_lock = threading.Lock()

# Guard against duplicate subscriber threads
_subscriber_thread: Optional[threading.Thread] = None
_subscriber_lock = threading.Lock()


def get_cached_policy(tenant_id: str) -> Optional[dict]:
    """Return cached policy pointer for tenant, or None."""
    with _cache_lock:
        return _policy_cache.get(tenant_id)


def set_cached_policy(tenant_id: str, version: str, digest: str) -> None:
    """Set cached policy pointer for tenant."""
    with _cache_lock:
        _policy_cache[tenant_id] = {
            "version": version,
            "digest": digest,
            "cached_at": int(time.time()),
        }


def flush_cached_policy(tenant_id: str) -> None:
    """Remove cached policy pointer for tenant, if present."""
    with _cache_lock:
        _policy_cache.pop(tenant_id, None)


def flush_all_cache() -> None:
    """Clear all cached tenant policy pointers."""
    with _cache_lock:
        _policy_cache.clear()


# ---------------------------------------------------------
# OPA probe
#
# OPA does not expose a universal "reload now" endpoint for
# bundle polling mode. This probe is a best-effort signal
# that OPA is reachable and may prompt near-term re-evaluation
# paths in sidecar-style deployments.
#
# This is NOT a guaranteed forced reload.
# ---------------------------------------------------------
def _probe_opa(tenant_id: str) -> None:
    try:
        resp = httpx.get(
            f"{OPA_URL}/v1/data/ztr",
            timeout=2.0,
        )
        print(
            f"[policy_subscriber] OPA probe after policy update "
            f"for tenant={tenant_id} status={resp.status_code}",
            flush=True,
        )
    except Exception as exc:
        print(
            f"[policy_subscriber][WARN] OPA probe failed for "
            f"tenant={tenant_id}: {exc}",
            flush=True,
        )


# ---------------------------------------------------------
# Message parsing / handling
# ---------------------------------------------------------
def _handle_message(
    message: dict,
    on_update: Optional[Callable[[str, str, str], None]] = None,
) -> None:
    """
    Handle a single Redis pub/sub message.

    Expected payload:
      {
        "tenant_id": "...",
        "policy_version": "...",
        "policy_digest": "...",
        "ts": 1234567890
      }
    """
    if message.get("type") != "message":
        return

    raw = message.get("data", "")
    try:
        data = json.loads(raw)
    except Exception:
        print(
            f"[policy_subscriber][WARN] unparseable message: {raw}",
            flush=True,
        )
        return

    tenant_id = str(data.get("tenant_id", "")).strip().lower()
    policy_version = str(data.get("policy_version", "")).strip()
    policy_digest = str(data.get("policy_digest", "")).strip()

    if not tenant_id or not policy_version or not policy_digest:
        print(
            "[policy_subscriber][WARN] incomplete policy_updates "
            f"message: {data}",
            flush=True,
        )
        return

    print(
        "[policy_subscriber] policy_update received: "
        f"tenant={tenant_id} version={policy_version}",
        flush=True,
    )

    # Flush stale cache first, then store fresh pointer
    flush_cached_policy(tenant_id)
    set_cached_policy(tenant_id, policy_version, policy_digest)

    # Optional runtime callback hook
    if on_update is not None:
        try:
            on_update(tenant_id, policy_version, policy_digest)
        except Exception as exc:
            print(
                f"[policy_subscriber][WARN] on_update callback failed "
                f"for tenant={tenant_id}: {exc}",
                flush=True,
            )

    # Best-effort OPA reachability check / wake-up probe
    _probe_opa(tenant_id)


# ---------------------------------------------------------
# Subscriber loop
#
# Reconnects on error with exponential backoff up to 30 sec.
# ---------------------------------------------------------
def _subscriber_loop(
    on_update: Optional[Callable[[str, str, str], None]] = None,
) -> None:
    backoff = 1

    while True:
        pubsub = None
        try:
            client = redis.from_url(REDIS_URL, decode_responses=True)
            pubsub = client.pubsub()
            pubsub.subscribe(CHANNEL)

            print(
                f"[policy_subscriber] subscribed to {CHANNEL}",
                flush=True,
            )
            backoff = 1

            for message in pubsub.listen():
                _handle_message(message, on_update=on_update)

        except Exception as exc:
            print(
                f"[policy_subscriber][WARN] subscriber error: {exc} "
                f"— reconnecting in {backoff}s",
                flush=True,
            )
            time.sleep(backoff)
            backoff = min(backoff * 2, 30)

        finally:
            try:
                if pubsub is not None:
                    pubsub.close()
            except Exception:
                pass


# ---------------------------------------------------------
# Public API
#
# Call from server.py lifespan:
#
#   from contextlib import asynccontextmanager
#   from policy_subscriber import start_subscriber
#
#   @asynccontextmanager
#   async def lifespan(app):
#       start_subscriber()
#       yield
#
#   app = FastAPI(lifespan=lifespan)
# ---------------------------------------------------------
def start_subscriber(
    on_update: Optional[Callable[[str, str, str], None]] = None,
) -> threading.Thread:
    """
    Start the policy_updates subscriber as a background daemon thread.

    Returns the running thread. If already started, returns the
    existing thread instead of creating a duplicate.
    """
    global _subscriber_thread

    with _subscriber_lock:
        if _subscriber_thread is not None and _subscriber_thread.is_alive():
            return _subscriber_thread

        t = threading.Thread(
            target=_subscriber_loop,
            kwargs={"on_update": on_update},
            daemon=True,
            name="policy-subscriber",
        )
        t.start()
        _subscriber_thread = t

    print("[policy_subscriber] daemon thread started", flush=True)
    return t
