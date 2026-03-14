import os
import time
import redis
from fastapi.testclient import TestClient

from api.server import app

client = TestClient(app)

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
r = redis.from_url(REDIS_URL, decode_responses=True)


def clear_decisions():
    for key in r.scan_iter("metrics:decision:*"):
        r.delete(key)


def write_decision(ts, tenant, principal, intent, decision, risk):
    key = f"metrics:decision:{ts}:{tenant}:{principal}:{intent}:{decision}"

    r.hset(
        key,
        mapping={
            "tenant_id": tenant,
            "principal": principal,
            "intent": intent,
            "decision": decision,
            "risk_score": risk,
            "policy_revision": "test-v1"
        }
    )


def test_decision_pipeline_single_event():

    clear_decisions()

    ts = int(time.time())

    write_decision(
        ts,
        "tenant-test",
        "agent-1",
        "refund:create",
        "allow",
        5
    )

    resp = client.get("/v1/intelligence/risk")

    assert resp.status_code == 200

    data = resp.json()

    assert len(data["top_risky_tenants"]) == 1
    assert data["top_risky_tenants"][0]["tenant"] == "tenant-test"
    assert data["top_risky_tenants"][0]["risk"] == 5


def test_multiple_decisions_aggregate_risk():

    clear_decisions()

    ts = int(time.time())

    write_decision(ts, "tenant-a", "agent-1", "refund", "allow", 2)
    write_decision(ts+1, "tenant-a", "agent-2", "refund", "allow", 3)

    resp = client.get("/v1/intelligence/risk")

    data = resp.json()

    assert data["top_risky_tenants"][0]["risk"] == 5


def test_principal_activity_count():

    clear_decisions()

    ts = int(time.time())

    write_decision(ts, "tenant-x", "agent-1", "refund", "allow", 0)
    write_decision(ts+1, "tenant-x", "agent-1", "refund", "allow", 0)
    write_decision(ts+2, "tenant-x", "agent-1", "refund", "deny", 1)

    resp = client.get("/v1/intelligence/risk")

    data = resp.json()

    principals = data["suspicious_principals"]

    assert principals[0]["principal"] == "agent-1"
    assert principals[0]["events"] == 3
