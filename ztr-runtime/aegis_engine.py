import sys
sys.path.append("/app")

import requests
import json
import hashlib
from datetime import datetime, UTC
import time
import os

from audit_chain import emit_event


# 🔒 PHASE 8 — DRIFT ANALYSIS ENGINE
def analyze_drift(events):
    if len(events) < 5:
        return {"drift": "INSUFFICIENT_DATA", "escalation": "NONE"}

    risk_values = [e.get("risk_delta", 0) for e in events[:5]]
    anomaly_flags = [e.get("anomaly", False) for e in events[:5]]
    velocity_values = [e.get("velocity", 0) for e in events[:5]]

    # DRIFT UP (monotonic increase)
    if all(risk_values[i] <= risk_values[i-1] for i in range(1, len(risk_values))):
        return {"drift": "DRIFT_UP", "escalation": "INCREASE_RISK"}

    # VELOCITY SPIKE
    if max(velocity_values) > 5:
        return {"drift": "DRIFT_SPIKE", "escalation": "REDUCE_TTL"}

    # ANOMALY DETECTED
    if any(anomaly_flags):
        return {"drift": "DRIFT_ANOMALY", "escalation": "FORCE_DENY"}

    return {"drift": "STABLE", "escalation": "NONE"}


# ⚙️ STEP 1 — Persist Aegis Signals to Redis (Time-Series)
def store_aegis_temporal(r, tenant_id, principal, signal):
    key = f"ztr:aegis:timeline:{tenant_id}:{principal}"

    entry = {
        "ts": int(time.time()),
        "anomaly": bool(signal.get("anomaly", False)),
        "velocity": int(signal.get("velocity", 1)),
        "confidence": float(signal.get("confidence", 0.95)),
        "risk_delta": int(signal.get("risk_delta", 0))
    }

    # 🔒 STEP 2 — HASH BINDING (AUDIT INTEGRITY)
    entry_hash = hashlib.sha256(
        json.dumps(entry, sort_keys=True).encode()
    ).hexdigest()

    entry["hash"] = entry_hash

    # 🔄 STORE EVENT
    r.lpush(key, json.dumps(entry))
    r.ltrim(key, 0, 49)

    # 🔍 PHASE 8 — DRIFT DETECTION
    try:
        events = r.lrange(key, 0, 5)
        parsed = []

        for e in events:
            try:
                parsed.append(json.loads(e))
            except Exception:
                continue

        drift_result = analyze_drift(parsed)

        entry["drift"] = drift_result["drift"]
        entry["escalation"] = drift_result["escalation"]

    except Exception:
        entry["drift"] = "UNKNOWN"
        entry["escalation"] = "NONE"

    # 🔒 STEP 3 — EMIT AUDIT EVENT (CHAIN LINK)
    try:
        emit_event(
            event_type="aegis_temporal",
            service="aegis-core",
            tenant_id=tenant_id,
            payload=entry
        )

        # 🔒 PHASE 8 — DRIFT AUDIT EVENT
        emit_event(
            event_type="aegis_drift",
            service="aegis-core",
            tenant_id=tenant_id,
            payload={
                "principal": principal,
                "drift": entry.get("drift"),
                "escalation": entry.get("escalation"),
                "ts": entry.get("ts")
            }
        )

    except Exception:
        pass


def generate_riskdna(event):
    return {
        "principal": event.get("principal"),
        "action": event.get("action"),
        "amount": event.get("amount"),
        "risk_score": event.get("risk_score"),
        "timestamp": event.get("timestamp")
    }


def build_policy_input(riskdna, event):
    signals = event.get("signals", {})

    policy_input = {
        "tenant_id": event.get("tenant_id"),
        "principal": riskdna["principal"],
        "intent": riskdna["action"],
        "scopes": ["refund:create"],
        "ttl_seconds": 300,
        "context": {
            "risk_score": signals.get("risk_score", riskdna["risk_score"]),
            "device_trust": True,
            "session_binding": "device-demo-123",
            "after_hours": False,
            "anomaly": signals.get("anomaly", False),
            "velocity": signals.get("velocity", 0),
            "confidence": signals.get("confidence", 0.95),
            "risk_delta": signals.get("risk_delta", 0)
        },
        "policy_revision": "local-dev",
        "timestamp": riskdna["timestamp"]
    }

    input_hash = hashlib.sha256(
        json.dumps(policy_input, sort_keys=True).encode()
    ).hexdigest()

    policy_input["input_hash"] = input_hash

    return policy_input


def call_opa(policy_input):
    try:
        response = requests.post(
            "http://localhost:8181/v1/data/ztr/issue/decision",
            json={"input": policy_input},
            timeout=2
        )

        if response.status_code != 200:
            return {
                "allow": False,
                "reason": "opa_http_error"
            }

        result = response.json()
        decision = result.get("result")

        if isinstance(decision, bool):
            return {
                "allow": decision,
                "obligations": [],
                "ttl_seconds": 300,
                "policy_revision": policy_input.get("policy_revision", "unknown")
            }

        if isinstance(decision, dict):
            return {
                "allow": decision.get("allow", False),
                "obligations": decision.get("obligations", []),
                "ttl_seconds": decision.get("ttl_seconds", 0),
                "policy_revision": decision.get("policy_revision", "unknown")
            }

        return {"allow": False}

    except Exception:
        return {"allow": False}


def emit_signal(riskdna, decision, policy_input):
    signal = {
        "input": riskdna,
        "policy_input": policy_input,
        "decision": decision,
        "engine": "aegis-core",
        "mode": "deterministic"
    }

    print(json.dumps(signal, indent=2))


def enforce_obligations(decision, policy_input):
    obligations = decision.get("obligations", [])

    for obligation in obligations:

        if obligation == "ROLE_MATCHED":
            pass

        elif obligation == "AMOUNT_OK":
            amount = policy_input.get("amount") or policy_input.get("input", {}).get("amount")
            if amount and amount > 1000:
                return False

        elif obligation == "RISK_OK":
            risk = policy_input["context"].get("risk_score", 0)
            if risk > 80:
                return False

        elif obligation == "REVIEW_REQUIRED":
            return False

    return True


def process_event(event):
    riskdna = generate_riskdna(event)
    policy_input = build_policy_input(riskdna, event)
    decision = call_opa(policy_input)

    if not decision.get("allow"):
        return

    emit_signal(riskdna, decision, policy_input)

    allowed = enforce_obligations(decision, policy_input)

    if not allowed:
        return

    try:
        import redis

        r = redis.from_url(os.environ["REDIS_URL"], decode_responses=True)

        tenant_id = policy_input.get("tenant_id")
        principal = policy_input.get("principal")

        key = f"ztr:aegis:{tenant_id}:{principal}"

        signal = {
            "anomaly": bool(policy_input["context"].get("anomaly", False)),
            "velocity": int(policy_input["context"].get("velocity", 1)),
            "confidence": float(policy_input["context"].get("confidence", 0.95)),
            "risk_delta": int(policy_input["context"].get("risk_delta", 0))
        }

        r.set(key, json.dumps({
            **signal,
            "ts": int(time.time())
        }))

        # 🔒 Temporal + Audit + Drift Binding
        store_aegis_temporal(r, tenant_id, principal, signal)

    except Exception:
        pass


def main():
    print("Aegis Engine Starting...")

    event = {
        "principal": "agent-demo",
        "tenant_id": "tenant-launch",
        "action": "refund:create",
        "amount": 120,
        "risk_score": 42,
        "timestamp": datetime.now(UTC).isoformat(),
        "signals": {
            "risk_score": 42,
            "anomaly": False,
            "velocity": 1
        }
    }

    process_event(event)

    print("Aegis Engine Completed")


if __name__ == "__main__":
    main()
