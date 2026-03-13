# =========================================================
# intelligence.py — Intelligence / Risk Analytics API
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

r = redis.from_url(
    os.environ["REDIS_URL"],
    decode_responses=True
)

intelligence_router = APIRouter(
    prefix="/v1/intelligence",
    tags=["intelligence"]
)


# ---------------------------------------------------------
# GET /v1/intelligence/risk
# ---------------------------------------------------------
@intelligence_router.get("/risk")
def intelligence_risk():

    tenants = {}
    principals = {}

    # -----------------------------------------------------
    # Scan persisted decision records
    # -----------------------------------------------------
    for key in r.scan_iter("metrics:decision:*"):

        try:

            data = r.hgetall(key)

            if not data:
                continue

            tenant = data.get("tenant_id")
            principal = data.get("principal")

            risk = int(data.get("risk_score") or 0)

            if tenant:
                tenants.setdefault(tenant, 0)
                tenants[tenant] += risk

            if principal:
                principals.setdefault(principal, 0)
                principals[principal] += 1

        except Exception:
            continue

    # -----------------------------------------------------
    # Top risky tenants
    # -----------------------------------------------------
    top_risky = sorted(
        [
            {"tenant": t, "risk": v}
            for t, v in tenants.items()
        ],
        key=lambda x: x["risk"],
        reverse=True
    )[:5]

    # -----------------------------------------------------
    # Most active principals (v1 intelligence heuristic)
    # -----------------------------------------------------
    most_active = sorted(
        [
            {"principal": p, "events": v}
            for p, v in principals.items()
        ],
        key=lambda x: x["events"],
        reverse=True
    )[:5]

    # -----------------------------------------------------
    # Policy drift check
    # -----------------------------------------------------
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

    # -----------------------------------------------------
    # Response
    # -----------------------------------------------------
    return {
        "top_risky_tenants": top_risky,
        "suspicious_principals": most_active,
        "policy_drift": policy_drift,
        "timestamp": int(time.time())
    }
