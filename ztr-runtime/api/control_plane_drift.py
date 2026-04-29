import json
import os
import time
import redis

from audit_chain import list_index, get_entry

r = redis.from_url(os.environ["REDIS_URL"], decode_responses=True)


# 🔒 PHASE 9 — DRIFT → POLICY OVERRIDE ENGINE
def map_drift_to_policy(drift_event):
    drift = drift_event.get("drift")

    if drift == "DRIFT_UP":
        return {
            "action": "INCREASE_RISK",
            "risk_boost": 10
        }

    if drift == "DRIFT_SPIKE":
        return {
            "action": "REDUCE_TTL",
            "ttl_override": 120
        }

    if drift == "DRIFT_ANOMALY":
        return {
            "action": "FORCE_DENY",
            "deny": True
        }

    return {
        "action": "NONE"
    }


# 🔒 WRITE POLICY OVERRIDE (CONTROL PLANE AUTHORITY)
def write_policy_override(tenant_id, principal, override):
    key = f"ztr:{tenant_id}:policy_override:{principal}"

    payload = {
        "override": override,
        "ts": int(time.time())
    }

    r.set(key, json.dumps(payload))

    print({
        "event": "policy_override_written",
        "tenant_id": tenant_id,
        "principal": principal,
        "override": override
    })


# 🔒 PROCESS DRIFT EVENTS FROM AUDIT CHAIN
def process_drift_events(tenant_id):
    hashes = list_index(
        tenant_id=tenant_id,
        event_type="aegis_drift",
        limit=20
    )

    for h in hashes:
        entry = get_entry(h, tenant_id=tenant_id)

        if not entry:
            continue

        payload = entry.get("payload", {})

        principal = payload.get("principal")
        drift = payload.get("drift")

        if not principal or not drift:
            continue

        override = map_drift_to_policy(payload)

        if override.get("action") == "NONE":
            continue

        write_policy_override(tenant_id, principal, override)


# 🔒 MAIN LOOP (CONTROL PLANE WORKER)
def run_control_plane_worker(tenant_id, interval=5):
    print(f"[CONTROL PLANE] Drift processor started for tenant: {tenant_id}")

    while True:
        try:
            process_drift_events(tenant_id)
        except Exception as e:
            print("[CONTROL PLANE ERROR]", str(e))

        time.sleep(interval)


# 🔒 TEST ENTRYPOINT
def main():
    tenant_id = "tenant-launch"

    run_control_plane_worker(tenant_id)


if __name__ == "__main__":
    main()
