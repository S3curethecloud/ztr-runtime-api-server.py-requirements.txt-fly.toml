from fastapi import APIRouter, Depends, HTTPException
from api.models import TokenIssueRequest
from api.auth import require_tenant_api_key
from opa_bridge import evaluate_issue_policy

import uuid
import time
import json
import hashlib

tokens_router = APIRouter(prefix="/v1", tags=["tokens"])


@tokens_router.post("/tokens:issue")
def issue_token(
    req: TokenIssueRequest,
    tenant_id: str = Depends(require_tenant_api_key),
):
    sid = f"SID-{uuid.uuid4().hex}"
    now = int(time.time())

    # -------------------------------------------------
    # Phase 6 — OPA issuance enforcement
    # -------------------------------------------------

    policy_input = {
        "tenant_id": tenant_id,
        "principal": req.principal,
        "intent": req.intent,
        "scopes": req.scopes,
        "ttl_seconds": req.ttl_seconds,
        "context": req.context or {},
        "ts": now,
        "policy_revision": "dev-1",
    }

    input_hash = hashlib.sha256(
        json.dumps(policy_input, sort_keys=True).encode()
    ).hexdigest()

    opa_result = evaluate_issue_policy(policy_input)

    if not opa_result.get("allow"):
        raise HTTPException(status_code=403, detail="policy_denied")

    # -------------------------------------------------
    # Continue with existing issuance logic
    # -------------------------------------------------

    return {
        "status": "issued",
        "tenant_id": tenant_id,
        "session_id": sid,
        "principal": req.principal,
        "intent": req.intent,
        "expires_in": req.ttl_seconds,
        "issued_at": now,
    }
