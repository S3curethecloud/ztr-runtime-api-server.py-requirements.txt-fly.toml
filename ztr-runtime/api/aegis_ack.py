from fastapi import APIRouter, Depends
import redis
import os
import json
import time

from api.auth import require_tenant_api_key
from audit_chain import emit_event  # 🔒 FIXED — CANONICAL AUDIT CHAIN

router = APIRouter()

r = redis.from_url(os.environ["REDIS_URL"], decode_responses=True)


# ✅ ACKNOWLEDGE ALERT (IDEMPOTENT + AUDITED)
@router.post("/aegis/ack")
def acknowledge_alert(payload: dict, tenant_id: str = Depends(require_tenant_api_key)):

    principal = payload.get("principal")
    if not principal:
        return {"status": "error", "message": "principal required"}

    key = f"ztr:aegis:ack:{tenant_id}:{principal}"

    existing = r.get(key)

    previous_record = None
    if existing:
        try:
            previous_record = json.loads(existing)
        except Exception:
            previous_record = None

    now_ts = int(time.time())
    prior_count = int((previous_record or {}).get("ack_count", 0))
    first_ack_at = (
        (previous_record or {}).get("first_acknowledged_at")
        or (previous_record or {}).get("acknowledged_at")
        or now_ts
    )

    ack_record = {
        "principal": principal,
        "tenant_id": tenant_id,
        "first_acknowledged_at": first_ack_at,
        "acknowledged_at": now_ts,
        "acknowledged_by": "operator",
        "note": payload.get("note", ""),
        "ack_count": prior_count + 1
    }

    r.set(key, json.dumps(ack_record))

    # 🔐 SOC2 AUDIT EVENT (CHAINED, VERIFIABLE)
    emit_event(
        event_type="aegis_acknowledged",
        service="aegis-ack",
        tenant_id=tenant_id,
        payload=ack_record
    )

    return {
        "status": "ok" if ack_record["ack_count"] == 1 else "already_acknowledged",
        "acknowledged": ack_record
    }


# ✅ GET ACK STATUS
@router.get("/aegis/ack/{principal}")
def get_ack_status(principal: str, tenant_id: str = Depends(require_tenant_api_key)):

    key = f"ztr:aegis:ack:{tenant_id}:{principal}"

    data = r.get(key)

    if not data:
        return {
            "status": "ok",
            "acknowledged": False
        }

    return {
        "status": "ok",
        "acknowledged": True,
        "record": json.loads(data)
    }
