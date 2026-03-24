from __future__ import annotations

import json
import os
import threading
import time
from typing import Callable, Optional

import httpx
import redis
import socket

REDIS_URL = os.environ["REDIS_URL"]
OPA_URL = os.getenv("OPA_URL", "http://localhost:8181")

NODE_ID = os.getenv("NODE_ID", socket.gethostname())

CHANNEL = "policy_updates"

# ---------------------------------------------------------
# In-memory policy pointer cache
# ---------------------------------------------------------
_policy_cache: dict[str, dict] = {}
_cache_lock = threading.Lock()

# Guard against duplicate subscriber threads
_subscriber_thread: Optional[threading.Thread] = None
_subscriber_lock = threading.Lock()


def get_cached_policy(tenant_id: str) -> Optional[dict]:
    with _cache_lock:
        return _policy_cache.get(tenant_id)


def set_cached_policy(tenant_id: str, version: str, digest: str) -> None:
    with _cache_lock:
        _policy_cache[tenant_id] = {
            "version": version,
            "digest": digest,
            "cached_at": int(time.time()),
        }


def flush_cached_policy(tenant_id: str) -> None:
    with _cache_lock:
        _policy_cache.pop(tenant_id, None)


def flush_all_cache() -> None:
    with _cache_lock:
        _policy_cache.clear()


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


def _handle_message(
    message: dict,
    on_update: Optional[Callable[[str, str, str], None]] = None,
) -> None:

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

    tenant_id = data.get("tenant_id")

    policy_version = (
        data.get("policy_version")
        or data.get("policy_revision")
    )

    policy_bundle = data.get("policy_bundle")

    if not tenant_id or not policy_version:
        print(
            "[policy_subscriber][WARN] incomplete policy_updates message:",
            data,
            flush=True
        )
        return

    tenant_id = str(tenant_id).strip().lower()
    policy_version = str(policy_version).strip()

    policy_digest = str(data.get("policy_digest") or "").strip()

    if not policy_digest:
        print("[policy_subscriber][WARN] missing digest — skipping update")
        return

    print(
        "[policy_subscriber][node="
        f"{NODE_ID}] policy_update received: "
        f"tenant={tenant_id} version={policy_version}",
        flush=True,
    )

    flush_cached_policy(tenant_id)
    set_cached_policy(tenant_id, policy_version, policy_digest)

    client = redis.from_url(REDIS_URL, decode_responses=True)

    client.set(
        f"ztr:tenant:{tenant_id}:policy_anchor",
        policy_digest
    )

    if on_update is not None:
        try:
            on_update(tenant_id, policy_version, policy_digest)
        except Exception as exc:
            print(
                f"[policy_subscriber][WARN] on_update callback failed "
                f"for tenant={tenant_id}: {exc}",
                flush=True,
            )

    _probe_opa(tenant_id)


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


def start_subscriber(
    on_update: Optional[Callable[[str, str, str], None]] = None,
) -> threading.Thread:

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
