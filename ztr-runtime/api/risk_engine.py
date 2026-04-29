import hashlib
import json
import os
import redis

r = redis.from_url(
    os.environ["REDIS_URL"],
    decode_responses=True
)


PRINCIPAL_ACTIVITY_WEIGHT = 1
TENANT_RISK_WEIGHT = 1
DENY_PENALTY = 5


def compute_risk_score(tenant_id: str, principal: str):

    tenant_risk = 0
    principal_events = 0
    deny_events = 0

    for key in r.scan_iter("metrics:decision:*"):

        data = r.hgetall(key)

        if not data:
            continue

        if data.get("tenant_id") == tenant_id:
            tenant_risk += int(data.get("risk_score") or 0)

        if data.get("principal") == principal:
            principal_events += 1

        if (
            data.get("principal") == principal
            and data.get("decision") == "deny"
        ):
            deny_events += 1

    score = (
        tenant_risk * TENANT_RISK_WEIGHT
        + principal_events * PRINCIPAL_ACTIVITY_WEIGHT
        + deny_events * DENY_PENALTY
    )

    # 🔒 INTEGRITY PENALTY
    try:
        integrity_score = int(r.get("runtime:integrity_score") or 100)
    except:
        integrity_score = 100

    if integrity_score < 80:
        score += (80 - integrity_score)

    return {
        "risk_score": score,
        "tenant_risk": tenant_risk,
        "principal_activity": principal_events,
        "deny_events": deny_events
    }
