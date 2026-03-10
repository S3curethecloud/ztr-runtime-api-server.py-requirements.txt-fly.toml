# FILE: api/observability.py
# Phase 9 Runtime Observability Layer
# Deterministic telemetry endpoints

from fastapi import APIRouter, Depends, Response
from redis import Redis
from typing import Dict, Any
import os
import time

router = APIRouter(prefix="/v1")

REDIS_URL = os.getenv("REDIS_URL")
redis_client = Redis.from_url(REDIS_URL, decode_responses=True)


def get_runtime_revision() -> str:
    return os.getenv("RUNTIME_REVISION", "unknown")


def get_policy_revision() -> str:
    return os.getenv("POLICY_REVISION", "unknown")


def read_counter(name: str) -> int:
    value = redis_client.get(name)
    return int(value) if value else 0


def read_latency(name: str) -> float:
    value = redis_client.get(name)
    return float(value) if value else 0.0


@router.get("/runtime/activity")
def runtime_activity() -> Dict[str, Any]:
    """
    Returns activity counters for the runtime.
    """

    return {
        "tokens_issued": read_counter("metric:tokens_issued"),
        "policy_allowed": read_counter("metric:policy_allowed"),
        "policy_denied": read_counter("metric:policy_denied"),
        "sessions_revoked": read_counter("metric:sessions_revoked"),
        "timestamp": int(time.time())
    }


@router.get("/runtime/integrity")
def runtime_integrity() -> Dict[str, Any]:
    """
    Returns integrity signals for runtime verification.
    """

    return {
        "runtime_revision": get_runtime_revision(),
        "policy_revision": get_policy_revision(),
        "ledger_anchor": redis_client.get("ledger:anchor"),
        "redis_ok": redis_client.ping(),
        "timestamp": int(time.time())
    }


@router.get("/metrics")
def runtime_metrics() -> Dict[str, Any]:
    """
    Returns latency metrics snapshot.
    """

    return {
        "tokens_issued_total": read_counter("metric:tokens_issued"),
        "policy_denied_total": read_counter("metric:policy_denied"),
        "sessions_revoked_total": read_counter("metric:sessions_revoked"),
        "decision_latency_ms": read_latency("metric:decision_latency_ms"),
        "opa_latency_ms": read_latency("metric:opa_latency_ms"),
        "redis_latency_ms": read_latency("metric:redis_latency_ms"),
        "timestamp": int(time.time())
    }


@router.get("/metrics/prometheus")
def prometheus_metrics():

    tokens = read_counter("metric:tokens_issued")
    denied = read_counter("metric:policy_denied")
    revoked = read_counter("metric:sessions_revoked")

    decision_latency = read_latency("metric:decision_latency_ms")
    opa_latency = read_latency("metric:opa_latency_ms")
    redis_latency = read_latency("metric:redis_latency_ms")

    output = f"""
# TYPE stc_tokens_issued counter
stc_tokens_issued {tokens}

# TYPE stc_policy_denied counter
stc_policy_denied {denied}

# TYPE stc_sessions_revoked counter
stc_sessions_revoked {revoked}

# TYPE stc_decision_latency_ms gauge
stc_decision_latency_ms {decision_latency}

# TYPE stc_opa_latency_ms gauge
stc_opa_latency_ms {opa_latency}

# TYPE stc_redis_latency_ms gauge
stc_redis_latency_ms {redis_latency}
"""

    return Response(content=output, media_type="text/plain")
