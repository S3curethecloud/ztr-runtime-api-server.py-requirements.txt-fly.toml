import redis
import os
from fastapi.testclient import TestClient
from api.server import app

client = TestClient(app)

r = redis.from_url(os.environ.get("REDIS_URL", "redis://localhost:6379/0"), decode_responses=True)


def test_session_created():

    payload = {
        "principal": "agent-demo",
        "intent": "controlplane:access",
        "context": {
            "tenant_id": "tenant-test"
        }
    }

    resp = client.post("/v1/tokens/issue", json=payload)

    data = resp.json()

    sid = data["session_id"]

    key = f"ztr:tenant:tenant-test:session:{sid}"

    assert r.exists(key)


def test_session_revocation():

    payload = {
        "principal": "agent-demo",
        "intent": "controlplane:access",
        "context": {
            "tenant_id": "tenant-test"
        }
    }

    issue = client.post("/v1/tokens/issue", json=payload).json()

    sid = issue["session_id"]

    revoke = client.post("/v1/sessions/revoke", json={"session_id": sid})

    assert revoke.status_code == 200


def test_session_index_exists():

    keys = list(r.scan_iter("ztr:tenant:*:session:*"))

    assert isinstance(keys, list)
