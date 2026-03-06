from fastapi import APIRouter
from fastapi.responses import FileResponse

router = APIRouter()

@router.get("/v1/policy/bundle")
def get_policy_bundle():
    return FileResponse(
        "bundle.tar.gz",
        media_type="application/gzip",
        filename="bundle.tar.gz"
    )
