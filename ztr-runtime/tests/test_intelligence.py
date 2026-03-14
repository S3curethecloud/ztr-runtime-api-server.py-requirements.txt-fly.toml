import time
import redis
from fastapi.testclient import TestClient
from api.server import app

client = TestClient(app)

# use local redis test instance
r = redis.Redis(host="localhost", port=6379, decode_responses=True)


def clear_test_data():
    for key in r.scan_iter("metrics:decision:*"):
        r.delete(key)

    for key in r.scan_iter("ztr:tenant:*:policy"):
        r.delete(key)


def test_empty_dataset():
    clear_test_data()

    response = client.get("/v1/intelligence/risk")
    data = response.json()

    assert response.status_code == 200
    assert data["top_risky_tenants"] == []
    assert data["suspicious_principals"] == []


def test_single_tenant_events():

    clear_test_data()

    ts = int(time.time())

    key = f"metrics:decision:{ts}:tenant-a:user1"

    r.hset(key, mapping={
        "tenant_id": "tenant-a",
        "principal": "user1",
        "risk_score": "10",
        "decision": "allow"
    })

    response = client.get("/v1/intelligence/risk")
    data = response.json()

    assert data["top_risky_tenants"][0]["tenant"] == "tenant-a"
    assert data["top_risky_tenants"][0]["risk"] == 10


def test_deny_spike_detection():

    clear_test_data()

    now = int(time.time())

    for i in range(10):
        key = f"metrics:decision:{now+i}:tenant-x:user{i}"

        r.hset(key, mapping={
            "tenant_id": "tenant-x",
            "principal": f"user{i}",
            "risk_score": "5",
            "decision": "deny"
        })

    response = client.get("/v1/intelligence/risk")
    data = response.json()

    assert "deny_spike" in data


def test_principal_escalation():

    clear_test_data()

    now = int(time.time())

    for i in range(12):

        key = f"metrics:decision:{now+i}:tenant-a:user1"

        r.hset(key, mapping={
            "tenant_id": "tenant-a",
            "principal": "user1",
            "risk_score": "2",
            "decision": "allow"
        })

    response = client.get("/v1/intelligence/risk")
    data = response.json()

    escalations = data["principal_escalations"]

    assert any(p["principal"] == "user1" for p in escalations)


def test_policy_drift_detection():

    clear_test_data()

    r.hset("ztr:tenant:a:policy", mapping={"version": "v1"})
    r.hset("ztr:tenant:b:policy", mapping={"version": "v2"})

    response = client.get("/v1/intelligence/risk")
    data = response.json()

    assert data["policy_drift"] is True
