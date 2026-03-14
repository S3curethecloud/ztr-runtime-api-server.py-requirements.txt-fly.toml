# =========================================================
# intelligence.py — Intelligence / Risk Analytics API v2
# SecureTheCloud — Intelligence Layer
#
# Endpoint
#   GET /v1/intelligence/risk
#
# Purpose
#   Provide aggregated platform intelligence signals:
#     - Top risky tenants
#     - Most active principals (v1 heuristic)
#     - Policy drift detection
#
# Safe: read-only endpoint. No runtime mutation.
# =========================================================

import os
import time
import redis
from fastapi import APIRouter

r = redis.from_url(os.environ["REDIS_URL"], decode_responses=True)

intelligence_router = APIRouter(prefix="/v1/intelligence", tags=["intelligence"])

WINDOW_CURRENT = 900     # 15 min
WINDOW_PREVIOUS = 900
BASELINE_WINDOW = 86400  # 24h


@intelligence_router.get("/risk")
def intelligence_risk():

    now = int(time.time())

    tenants = {}
    tenants_prev = {}

    principals = {}
    principal_denies = {}

    current_denies = 0
    baseline_denies = 0

    for key in r.scan_iter("metrics:decision:*"):

        data = r.hgetall(key)
        if not data:
            continue

        tenant = data.get("tenant_id")
        principal = data.get("principal")

        risk = int(data.get("risk_score") or 0)
        decision = data.get("decision")

        ts = int(key.split(":")[2])

        # tenant risk current
        if tenant:
            tenants.setdefault(tenant, 0)
            tenants[tenant] += risk

        # principal activity
        if principal:
            principals.setdefault(principal, 0)
            principals[principal] += 1

        # deny spike detection
        if decision == "deny":
            if now - ts <= WINDOW_CURRENT:
                current_denies += 1
            if now - ts <= BASELINE_WINDOW:
                baseline_denies += 1

        # principal deny tracking
        if decision == "deny" and principal:
            principal_denies.setdefault(principal, 0)
            principal_denies[principal] += 1

        # previous window risk
        if tenant and WINDOW_CURRENT < (now - ts) <= (WINDOW_CURRENT + WINDOW_PREVIOUS):
            tenants_prev.setdefault(tenant, 0)
            tenants_prev[tenant] += risk

    # -------------------------------
    # Top risky tenants
    # -------------------------------
    top_risky = sorted(
        [{"tenant": t, "risk": v} for t, v in tenants.items()],
        key=lambda x: x["risk"],
        reverse=True
    )[:5]

    # -------------------------------
    # Tenant trend
    # -------------------------------
    trends = []

    for tenant, risk in tenants.items():

        prev = tenants_prev.get(tenant, 0)

        if risk > prev * 1.2:
            direction = "up"
        elif risk < prev * 0.8:
            direction = "down"
        else:
            direction = "flat"

        trends.append({
            "tenant": tenant,
            "current": risk,
            "previous": prev,
            "trend": direction
        })

    # -------------------------------
    # Suspicious principals
    # -------------------------------
    most_active = sorted(
        [{"principal": p, "events": v} for p, v in principals.items()],
        key=lambda x: x["events"],
        reverse=True
    )[:5]

    # -------------------------------
    # Principal escalation
    # -------------------------------
    escalations = []

    for p, events in principals.items():

        denies = principal_denies.get(p, 0)

        if denies >= 5:
            level = "critical"
        elif events >= 10:
            level = "elevated"
        elif events >= 5:
            level = "watch"
        else:
            level = "normal"

        escalations.append({
            "principal": p,
            "events": events,
            "denies": denies,
            "level": level
        })

    # -------------------------------
    # Deny spike detection
    # -------------------------------
    baseline_avg = baseline_denies / 96 if baseline_denies else 0
    threshold = max(baseline_avg * 2, baseline_avg + 5)

    deny_spike = {
        "current": current_denies,
        "baseline": int(baseline_avg),
        "threshold": int(threshold),
        "detected": current_denies > threshold
    }

    # -------------------------------
    # Policy drift
    # -------------------------------
    policy_drift = False
    revisions = set()

    for key in r.scan_iter("ztr:tenant:*:policy"):

        policy = r.hgetall(key)
        if not policy:
            continue

        rev = policy.get("version")
        if rev:
            revisions.add(rev)

    if len(revisions) > 1:
        policy_drift = True

    return {
        "top_risky_tenants": top_risky,
        "tenant_risk_trend": trends,
        "suspicious_principals": most_active,
        "principal_escalations": escalations,
        "deny_spike": deny_spike,
        "policy_drift": policy_drift,
        "timestamp": int(time.time())
    }
