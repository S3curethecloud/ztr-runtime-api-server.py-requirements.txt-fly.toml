from fastapi import APIRouter, Depends
import json
import redis
import os

from api.auth import require_tenant_api_key

router = APIRouter()

r = redis.from_url(os.environ["REDIS_URL"], decode_responses=True)


def analyze_trend(events):
    if len(events) < 3:
        return {"trend": "INSUFFICIENT_DATA"}

    first = events[-1]
    last = events[0]

    anomaly_delta = last.get("anomaly", 0) - first.get("anomaly", 0)
    risk_delta = last.get("risk_delta", 0) - first.get("risk_delta", 0)

    if risk_delta > 2 or anomaly_delta > 0:
        return {"trend": "RISING"}

    if risk_delta < -2:
        return {"trend": "FALLING"}

    return {"trend": "STABLE"}


@router.get("/aegis/temporal")
def get_temporal(tenant_id: str = Depends(require_tenant_api_key)):

    pattern = f"ztr:aegis:timeline:{tenant_id}:*"
    keys = list(r.scan_iter(pattern, count=100))

    print({
        "event": "aegis_temporal_access",
        "tenant_id": tenant_id,
        "keys_found": len(keys)
    })

    all_events = []

    for key in keys:
        entries = r.lrange(key, 0, 20)

        parsed = []
        for e in entries:
            try:
                parsed.append(json.loads(e))
            except Exception:
                continue

        if parsed:
            trend = analyze_trend(parsed)

            parts = key.split(":")
            principal = parts[-1] if len(parts) >= 5 else "unknown"

            all_events.append({
                "principal": principal,
                "events": parsed,
                "trend": trend
            })

    return {
        "status": "ok",
        "temporal": all_events
    }


@router.get("/aegis/temporal/{principal}")
def get_temporal_by_principal(
    principal: str,
    tenant_id: str = Depends(require_tenant_api_key)
):

    key = f"ztr:aegis:timeline:{tenant_id}:{principal}"

    entries = r.lrange(key, 0, 50)

    print({
        "event": "aegis_temporal_principal_access",
        "tenant_id": tenant_id,
        "principal": principal,
        "events_found": len(entries)
    })

    parsed = []
    for e in entries:
        try:
            parsed.append(json.loads(e))
        except Exception:
            continue

    if not parsed:
        return {
            "status": "ok",
            "principal": principal,
            "events": [],
            "trend": {"trend": "NO_DATA"}
        }

    trend = analyze_trend(parsed)

    return {
        "status": "ok",
        "principal": principal,
        "events": parsed,
        "trend": trend
    }
