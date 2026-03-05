from fastapi import APIRouter, Depends
from api.models import TenantRevokeRequest
from api.auth import require_tenant_api_key

sessions_router = APIRouter(prefix="/v1", tags=["sessions"])

@sessions_router.post("/sessions/revoke")
def revoke_session(
    req: TenantRevokeRequest,
    tenant_id: str = Depends(require_tenant_api_key),
):
    return {
        "status": "ok",
        "revoked_session": req.session_id,
        "tenant_id": tenant_id
    }
