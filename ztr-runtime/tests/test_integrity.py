from fastapi.testclient import TestClient
from api.server import app

client = TestClient(app)


def test_integrity_endpoint_available():

    resp = client.get("/v1/runtime/integrity")

    assert resp.status_code == 200

    data = resp.json()

    assert "runtime_status" in data
    assert "redis_status" in data
    assert "opa_status" in data


def test_integrity_returns_timestamp():

    resp = client.get("/v1/runtime/integrity")

    data = resp.json()

    assert "timestamp" in data


def test_integrity_response_structure():

    resp = client.get("/v1/runtime/integrity")

    data = resp.json()

    assert isinstance(data, dict)
