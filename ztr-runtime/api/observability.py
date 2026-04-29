# FILE: api/observability.py
# Phase 9 Runtime Observability Layer
# Deterministic telemetry endpoints

from fastapi import APIRouter, Response, Depends
from redis import Redis
from typing import Dict, Any
import os
import time
import json

from api.auth import require_tenant_api_key
from api.redis_keys import tenant_usage_key
from audit_chain import verify_chain

router = APIRouter(prefix="/v1")

REDIS_URL = os.getenv("REDIS_URL")
redis_client = Redis.from_url(REDIS_URL, decode_responses=True)

r = redis_client
_r = redis_client


def read_counter(name: str) -> int:
    value = redis_client.get(name)
    return int(value) if value else 0


def read_latency(name: str) -> float:
    value = redis_client.get(name)
    return float(value) if value else 0.0


def current_period() -> str:
    return time.strftime("%Y-%m")


def read_runtime_revision(tenant_id: str) -> str:
    runtime_revision = _r.get("runtime:revision")
    if runtime_revision:
        return runtime_revision

    config_key = f"ztr:tenant:{tenant_id}:config"
    config_data = _r.get(config_key)

    if config_data:
        try:
            return json.loads(config_data).get("version", "unknown")
        except Exception:
            return "unknown"

    return "unknown"


DECISION_HEALTH_WINDOW_SECONDS = int(
    os.getenv("DECISION_HEALTH_WINDOW_SECONDS", "900")
)


def read_rolling_introspection_count(
    outcome: str,
    start_ts: int,
    end_ts: int,
) -> int:
    key = f"metric:introspection_window:{outcome}"
    value = r.zcount(key, start_ts, end_ts)
    return int(value or 0)


@router.get("/runtime/integrity")
async def runtime_integrity(
    tenant_id: str = Depends(require_tenant_api_key),
):

    timestamp = int(time.time())

    try:
        redis_ok = r.ping()
    except:
        redis_ok = False

    active_sessions = 0
    for key in r.scan_iter("ztr:*:session:*"):
        if r.ttl(key) > 0:
            active_sessions += 1

    policy_key = f"ztr:tenant:{tenant_id}:policy"
    policy_data = r.hgetall(policy_key)
    policy_revision = policy_data.get("version") if policy_data else "unknown"

    runtime_revision = read_runtime_revision(tenant_id)

    try:
        result = verify_chain(tenant_id=tenant_id)

        chain_status = result.get("status", "unknown")
        chain_valid = chain_status == "valid"
        chain_head = result.get("chain_head")
        events_verified = result.get("events_verified", 0)

    except Exception:
        chain_status = "unknown"
        chain_valid = False
        chain_head = None
        events_verified = 0

    window_end = timestamp
    window_start = window_end - DECISION_HEALTH_WINDOW_SECONDS

    rolling_success = read_rolling_introspection_count(
        "success",
        window_start,
        window_end
    )
    rolling_inactive = read_rolling_introspection_count(
        "inactive",
        window_start,
        window_end
    )
    rolling_invalid = read_rolling_introspection_count(
        "invalid",
        window_start,
        window_end
    )
    rolling_expired = read_rolling_introspection_count(
        "expired",
        window_start,
        window_end
    )
    rolling_failure = read_rolling_introspection_count(
        "failure",
        window_start,
        window_end
    )

    introspect_success = int(r.get("metric:introspect_success") or 0)
    introspect_inactive = int(r.get("metric:introspect_inactive") or 0)
    token_invalid = int(r.get("metric:token_invalid") or 0)
    token_expired = int(r.get("metric:token_expired") or 0)
    introspection_failure = int(r.get("metric:introspection_failure") or 0)

    rolling_total_events = (
        rolling_success +
        rolling_inactive +
        rolling_invalid +
        rolling_expired +
        rolling_failure
    )

    rolling_failure_events = (
        rolling_invalid +
        rolling_expired +
        rolling_failure
    )

    decision_health = 100

    if rolling_total_events > 0:
        failure_ratio = rolling_failure_events / rolling_total_events
        decision_health = int((1 - failure_ratio) * 100)

    degraded = []

    if not redis_ok:
        degraded.append("redis")

    if chain_status in ("broken", "empty", "unknown"):
        degraded.append("ledger")

    # idle runtime is neutral, not degraded

    if policy_revision == "unknown":
        degraded.append("policy")

    if runtime_revision == "unknown":
        degraded.append("runtime")

    if decision_health < 80:
        degraded.append("decision_engine")

    score = 100

    if not redis_ok:
        score -= 40

    if chain_status == "broken":
        score -= 40

    # idle runtime is neutral, not degraded

    if policy_revision == "unknown":
        score -= 10

    score -= int((100 - decision_health) * 0.5)
    score = max(score, 0)

    if not redis_ok or chain_status == "broken":
        overall = "CRITICAL"
    elif score >= 90:
        overall = "HEALTHY"
    elif score >= 70:
        overall = "DEGRADED"
    else:
        overall = "CRITICAL"

    r.set("runtime:integrity_score", score)

    return {
        "status": overall,
        "integrity_score": score,
        "degraded_domains": degraded,
        "tenant_id": tenant_id,
        "redis_ok": redis_ok,
        "active_sessions": active_sessions,
        "runtime_revision": runtime_revision,
        "policy_revision": policy_revision,
        "ledger_status": chain_status,
        "ledger_valid": chain_valid,
        "ledger_anchor": chain_head,
        "events_verified": events_verified,
        "runtime_status": "healthy" if decision_health >= 80 else "degraded",
        "redis_status": "healthy" if redis_ok else "degraded",
        "opa_status": "healthy",
        "decision_health_score": decision_health,
        "decision_window_seconds": DECISION_HEALTH_WINDOW_SECONDS,
        "decision_window_metrics": {
            "success": rolling_success,
            "inactive": rolling_inactive,
            "invalid": rolling_invalid,
            "expired": rolling_expired,
            "failures": rolling_failure
        },
        "decision_metrics": {
            "success": introspect_success,
            "inactive": introspect_inactive,
            "invalid": token_invalid,
            "expired": token_expired,
            "failures": introspection_failure
        },
        "timestamp": timestamp
    }


# =========================================================
# 🔧 SURGICAL FIX — RUNTIME ACTIVITY (TENANT-SCOPED)
# =========================================================
@router.get("/runtime/activity")
async def runtime_activity(
    tenant_id: str = Depends(require_tenant_api_key),
):
    events = []

    pattern = f"ztr:{tenant_id}:audit:entry:*"

    for key in r.scan_iter(pattern):
        try:
            raw = r.get(key)
            if not raw:
                continue

            entry = json.loads(raw)

            events.append({
                "timestamp": entry.get("ts_ms"),
                "tenant_id": entry.get("tenant_id"),
                "principal": entry.get("payload", {}).get("principal"),
                "intent": entry.get("payload", {}).get("intent"),
                "decision": entry.get("payload", {}).get("decision"),
                "risk_score": entry.get("payload", {}).get("risk_score"),
                "policy_revision": entry.get("payload", {}).get("policy_revision"),
                "event_id": entry.get("event_id")
            })

        except Exception:
            continue

    events.sort(key=lambda x: x.get("timestamp") or 0, reverse=True)

    return {
        "events": events[:50]
    }


@router.get("/metrics")
def runtime_metrics() -> Dict[str, Any]:
    active_sessions = 0

    for key in r.scan_iter("ztr:*:session:*"):
        if r.ttl(key) > 0:
            active_sessions += 1

    return {
        "tokens_issued": read_counter("metric:tokens_issued"),
        "policy_allowed": read_counter("metric:policy_allowed"),
        "policy_denied": read_counter("metric:policy_denied"),
        "sessions_revoked": read_counter("metric:sessions_revoked"),
        "active_sessions": active_sessions,
        "decision_latency_ms": read_latency("metric:decision_latency_ms"),
        "opa_latency_ms": read_latency("metric:opa_latency_ms"),
        "redis_latency_ms": read_latency("metric:redis_latency_ms"),
        "metrics_source": "redis:runtime",
        "metrics_last_updated": int(time.time()),
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

    period = current_period()

    for key in _r.scan_iter("ztr:tenant:*:meta"):

        try:
            tenant_id = key.split(":")[2]
            usage_key = tenant_usage_key(tenant_id, period)
            usage = _r.hgetall(usage_key) or {}

            issued = int(usage.get("tokens_issued") or 0)
            denied = int(usage.get("policy_denied") or 0)
            revoked = int(usage.get("sessions_revoked") or 0)

            output += f"""
stc_tokens_issued{{tenant="{tenant_id}"}} {issued}
stc_policy_denied{{tenant="{tenant_id}"}} {denied}
stc_sessions_revoked{{tenant="{tenant_id}"}} {revoked}
"""

        except Exception:
            continue

    return Response(content=output, media_type="text/plain")
