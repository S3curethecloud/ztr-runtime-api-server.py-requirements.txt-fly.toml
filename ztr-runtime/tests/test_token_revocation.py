import time
from fastapi.testclient import TestClient
from api.server import app

client = TestClient(app)


def test_token_issue():

    payload = {
        "principal": "agent-demo",
        "intent": "refund:create",
        "context": {
            "tenant_id": "tenant-test"
        }
    }

    resp = client.post("/v1/tokens/issue", json=payload)

    assert resp.status_code == 200

    data = resp.json()

    assert "token" in data
    assert "expires_in" in data
    assert data["expires_in"] > 0


def test_token_revocation():

    payload = {
        "principal": "agent-demo",
        "intent": "refund:create",
        "context": {
            "tenant_id": "tenant-test"
        }
    }

    issue = client.post("/v1/tokens/issue", json=payload).json()

    sid = issue["session_id"]

    revoke = client.post(
        "/v1/sessions/revoke",
        json={"session_id": sid}
    )

    assert revoke.status_code == 200


def test_revoked_token_rejected():

    payload = {
        "principal": "agent-demo",
        "intent": "refund:create",
        "context": {
            "tenant_id": "tenant-test"
        }
    }

    issue = client.post("/v1/tokens/issue", json=payload).json()

    sid = issue["session_id"]

    client.post("/v1/sessions/revoke", json={"session_id": sid})

    check = client.post(
        "/v1/tokens/introspect",
        json={"token": issue["token"]}
    )

    assert check.status_code == 401
