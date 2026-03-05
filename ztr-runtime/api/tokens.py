from fastapi import APIRouter, Depends
from api.models import TokenIssueRequest
from api.auth import require_tenant_api_key
import uuid, time

tokens_router = APIRouter(prefix="/v1", tags=["tokens"])

@tokens_router.post("/tokens:issue")
def issue_token(
    req: TokenIssueRequest,
    tenant_id: str = Depends(require_tenant_api_key),
):
    sid = f"SID-{uuid.uuid4().hex}"
    now = int(time.time())

    return {
        "status": "issued",
        "tenant_id": tenant_id,
        "session_id": sid,
        "principal": req.principal,
        "intent": req.intent,
        "expires_in": req.ttl_seconds,
        "issued_at": now,
    }
