import hashlib
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from api.auth import r, require_tenant_api_key
from api.server import app
import api.tokens as tokens_api


TEST_TENANT_ID = "tenant-test"
TEST_POLICY_REVISION = "test-policy-rev"
TEST_POLICY_TEXT = """
package securethecloud

default allow = true

allow {
  input.principal != ""
  input.intent != ""
}
""".strip()
TEST_POLICY_DIGEST = hashlib.sha256(TEST_POLICY_TEXT.encode()).hexdigest()


def test_tenant_api_key_override() -> str:
    return TEST_TENANT_ID


def test_evaluate_issue_policy_override(policy_input=None, **kwargs):
    payload = policy_input if isinstance(policy_input, dict) else kwargs

    return {
        "allow": True,
        "decision": "allow",
        "reason": "test_policy_allow",
        "policy_revision": TEST_POLICY_REVISION,
        "obligations": [],
        "risk_score": payload.get("context", {}).get("risk_score", 0),
    }


@pytest.fixture(autouse=True)
def override_tenant_api_key_dependency(monkeypatch):
    app.dependency_overrides[require_tenant_api_key] = test_tenant_api_key_override

    r.set(f"ztr:tenant:{TEST_TENANT_ID}:status", "active")
    r.hset(
        f"ztr:tenant:{TEST_TENANT_ID}:policy",
        mapping={
            "version": TEST_POLICY_REVISION,
            "digest": TEST_POLICY_DIGEST,
            "policy": TEST_POLICY_TEXT,
        },
    )
    r.set(f"ztr:tenant:{TEST_TENANT_ID}:policy_anchor", TEST_POLICY_DIGEST)

    monkeypatch.setattr(
        tokens_api,
        "evaluate_issue_policy",
        test_evaluate_issue_policy_override,
    )

    yield

    app.dependency_overrides.pop(require_tenant_api_key, None)
