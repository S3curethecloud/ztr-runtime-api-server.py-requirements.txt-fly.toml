import requests
import json
import hashlib
from datetime import datetime, UTC


def get_latest_signal(tenant_id: str, principal: str) -> dict:
    """
    Phase 8.1 — deterministic signal fetch

    Returns last known Aegis signal for principal.
    Fail-safe: return None if not available.
    """

    try:
        import redis, os

        r = redis.from_url(os.environ["REDIS_URL"], decode_responses=True)

        key = f"ztr:aegis:{tenant_id}:{principal}"

        data = r.get(key)

        if not data:
            return None

        import json
        return json.loads(data)

    except Exception:
        return None


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
        "tenant_id": "tenant-demo",
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
            "velocity": signals.get("velocity", 0)
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
    """
    Deterministic OPA evaluation (FAIL-CLOSED, observable, normalized)
    """
    try:
        response = requests.post(
            "http://localhost:8181/v1/data/ztr/issue/decision",
            json={"input": policy_input},
            timeout=2
        )

        if response.status_code != 200:
            print("[AEGIS][OPA ERROR] HTTP", response.status_code)

            return {
                "allow": False,
                "reason": "opa_http_error",
                "status_code": response.status_code
            }

        result = response.json()
        decision = result.get("result")

        if isinstance(decision, bool):
            return {
                "allow": decision,
                "reason": "opa_eval_boolean",
                "obligations": [],
                "ttl_seconds": 300,
                "policy_revision": policy_input.get("policy_revision", "unknown")
            }

        if isinstance(decision, dict):
            return {
                "allow": decision.get("allow", False),
                "reason": "opa_eval_object",
                "obligations": decision.get("obligations", []),
                "ttl_seconds": decision.get("ttl_seconds", 0),
                "policy_revision": decision.get("policy_revision", "unknown")
            }

        return {
            "allow": False,
            "reason": "opa_invalid_response"
        }

    except Exception as e:
        print("[AEGIS][OPA DOWN]", str(e))

        return {
            "allow": False,
            "reason": "opa_unavailable",
            "error": str(e)
        }


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

    print("[ENFORCEMENT] Evaluating obligations...")

    for obligation in obligations:

        if obligation == "ROLE_MATCHED":
            print("[ENFORCEMENT] Role verified ✔")

        elif obligation == "AMOUNT_OK":
            amount = policy_input.get("amount") or policy_input.get("input", {}).get("amount")
            if amount and amount > 1000:
                print("[ENFORCEMENT] Amount exceeds limit ❌")
                return False
            print("[ENFORCEMENT] Amount within limit ✔")

        elif obligation == "RISK_OK":
            risk = policy_input["context"].get("risk_score", 0)
            if risk > 80:
                print("[ENFORCEMENT] High risk detected ❌")
                return False
            print("[ENFORCEMENT] Risk acceptable ✔")

        elif obligation == "REVIEW_REQUIRED":
            print("[ENFORCEMENT] Manual review required ⚠")
            return False

    return True


def process_event(event):
    riskdna = generate_riskdna(event)
    policy_input = build_policy_input(riskdna, event)
    decision = call_opa(policy_input)

    if not decision.get("allow"):
        print(json.dumps({
            "status": "DENY",
            "reason": decision.get("reason"),
            "engine": "aegis-core"
        }, indent=2))
        return

    emit_signal(riskdna, decision, policy_input)

    # 🔒 Enforcement layer
    allowed = enforce_obligations(decision, policy_input)

    if not allowed:
        print({
            "status": "BLOCKED_BY_ENFORCEMENT",
            "engine": "aegis-core"
        })
        return

    # --------------------------------------------------
    # OPTIONAL — STORE SIGNAL (RECOMMENDED)
    # --------------------------------------------------

    try:
        import redis, os

        r = redis.from_url(os.environ["REDIS_URL"], decode_responses=True)

        tenant_id = policy_input.get("tenant_id")
        principal = policy_input.get("principal")

        key = f"ztr:aegis:{tenant_id}:{principal}"

        r.set(key, json.dumps({
            "anomaly": False,
            "velocity": 1,
            "confidence": 0.95
        }))

    except Exception:
        pass


def main():
    print("Aegis Engine Starting...")

    event = {
        "principal": "agent_007",
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
