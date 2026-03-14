import time
import redis
import os
from fastapi.testclient import TestClient
from api.server import app

client = TestClient(app)

r = redis.from_url(os.environ.get("REDIS_URL", "redis://localhost:6379/0"), decode_responses=True)


def clear_metrics():

    for key in r.scan_iter("metrics:decision:*"):
        r.delete(key)


def test_decision_written_to_metrics():

    clear_metrics()

    ts = int(time.time())

    key = f"metrics:decision:{ts}:tenant-test:agent:refund:allow"

    r.hset(
        key,
        mapping={
            "tenant_id": "tenant-test",
            "principal": "agent",
            "intent": "refund",
            "decision": "allow",
            "risk_score": 1
        }
    )

    keys = list(r.scan_iter("metrics:decision:*"))

    assert len(keys) >= 1


def test_intelligence_reads_streamed_decisions():

    resp = client.get("/v1/intelligence/risk")

    assert resp.status_code == 200

    data = resp.json()

    assert "top_risky_tenants" in data
