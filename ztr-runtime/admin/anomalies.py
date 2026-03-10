from fastapi import APIRouter
import redis
import os

router = APIRouter(prefix="/v1/admin")

r = redis.from_url(
    os.environ["REDIS_URL"],
    decode_responses=True,
)

SPIKE_MULTIPLIER = 5


def read_metric(key):
    value = r.get(key)
    return int(value) if value else 0


@router.get("/anomalies")
def detect_anomalies():

    tenants = list(r.scan_iter("usage:*:tokens_issued"))

    anomalies = []

    for key in tenants:

        tenant_id = key.split(":")[1]

        issued = read_metric(f"usage:{tenant_id}:tokens_issued")
        denied = read_metric(f"usage:{tenant_id}:policy_denied")

        baseline = max(1, issued // 100)

        if denied > baseline * SPIKE_MULTIPLIER:

            anomalies.append({
                "tenant_id": tenant_id,
                "type": "deny_spike",
                "baseline": baseline,
                "current": denied,
                "threshold": baseline * SPIKE_MULTIPLIER
            })

    return {
        "anomalies": anomalies
    }
