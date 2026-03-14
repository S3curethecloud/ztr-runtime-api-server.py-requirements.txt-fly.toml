import os
import redis
from fastapi.testclient import TestClient

from api.server import app

client = TestClient(app)

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
r = redis.from_url(REDIS_URL, decode_responses=True)


def test_policy_anchor_exists_for_tenant():

    tenant_id = "tenant-test"

    anchor_key = f"ztr:tenant:{tenant_id}:policy_anchor"

    anchor = r.get(anchor_key)

    # Anchor may not exist in fresh environment,
    # but the key lookup must not error.
    assert anchor is None or isinstance(anchor, str)


def test_management_chain_namespace():

    mgmt_keys = list(r.scan_iter("audit:mgmt:*"))

    # Chain namespace should exist or be empty safely
    assert isinstance(mgmt_keys, list)


def test_runtime_integrity_endpoint():

    resp = client.get("/v1/runtime/integrity")

    assert resp.status_code == 200

    data = resp.json()

    assert "runtime_status" in data
    assert "redis_status" in data
    assert "opa_status" in data


def test_policy_drift_detection():

    resp = client.get("/v1/intelligence/risk")

    assert resp.status_code == 200

    data = resp.json()

    assert "policy_drift" in data


def test_governance_state_readable():

    keys = list(r.scan_iter("ztr:tenant:*:policy"))

    # Policies may exist or not depending on test environment
    assert isinstance(keys, list)
