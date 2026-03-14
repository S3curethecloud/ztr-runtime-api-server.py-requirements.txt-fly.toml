import os
import time
import redis
from fastapi import APIRouter

r = redis.from_url(
    os.environ["REDIS_URL"],
    decode_responses=True
)

intelligence_router = APIRouter(
    prefix="/v1/intelligence",
    tags=["intelligence"]
)

DENY_SPIKE_THRESHOLD = 5


@intelligence_router.get("/risk")
def intelligence_risk():

    tenants = {}
    principals = {}

    deny_count = 0
    total_events = 0

    for key in r.scan_iter("metrics:decision:*"):

        try:

            data = r.hgetall(key)

            if not data:
                continue

            tenant = data.get("tenant_id")
            principal = data.get("principal")

            decision = data.get("decision")
            risk = int(data.get("risk_score") or 0)

            total_events += 1

            if decision == "deny":
                deny_count += 1

            if tenant:
                tenants.setdefault(tenant, 0)
                tenants[tenant] += risk

            if principal:
                principals.setdefault(principal, 0)
                principals[principal] += 1

        except Exception:
            continue


    # --------------------------------------------------
    # Top risky tenants
    # --------------------------------------------------

    top_risky = sorted(
        [{"tenant": t, "risk": v} for t, v in tenants.items()],
        key=lambda x: x["risk"],
        reverse=True
    )[:5]


    # --------------------------------------------------
    # Tenant risk trend (simple baseline heuristic)
    # --------------------------------------------------

    tenant_trend = []

    for t, risk in tenants.items():

        trend = "flat"

        if risk > 20:
            trend = "up"

        if risk == 0:
            trend = "down"

        tenant_trend.append({
            "tenant": t,
            "trend": trend,
            "risk": risk
        })


    # --------------------------------------------------
    # Principal activity
    # --------------------------------------------------

    most_active = sorted(
        [{"principal": p, "events": v} for p, v in principals.items()],
        key=lambda x: x["events"],
        reverse=True
    )[:5]


    # --------------------------------------------------
    # Principal escalation logic
    # --------------------------------------------------

    escalations = []

    for p, events in principals.items():

        level = "normal"

        if events > 10:
            level = "elevated"

        if events > 25:
            level = "critical"

        escalations.append({
            "principal": p,
            "events": events,
            "level": level
        })


    # --------------------------------------------------
    # Deny spike detection
    # --------------------------------------------------

    deny_spike = False

    if deny_count >= DENY_SPIKE_THRESHOLD:
        deny_spike = True


    # --------------------------------------------------
    # Policy drift detection
    # --------------------------------------------------

    policy_drift = False

    try:

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

    except Exception:
        policy_drift = False


    return {

        "top_risky_tenants": top_risky,

        "tenant_risk_trend": tenant_trend,

        "suspicious_principals": most_active,

        "principal_escalations": escalations,

        "deny_spike": {
            "detected": deny_spike,
            "denies": deny_count,
            "threshold": DENY_SPIKE_THRESHOLD
        },

        "policy_drift": policy_drift,

        "timestamp": int(time.time())
    }
