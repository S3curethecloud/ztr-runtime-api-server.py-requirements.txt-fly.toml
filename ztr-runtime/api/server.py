from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import redis
import time
import os

app = FastAPI(title="Zero Trust Runtime")

# ---------------------------------------------------------
# Redis Configuration (via environment variables)
# ---------------------------------------------------------
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", None)

r = redis.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    password=REDIS_PASSWORD,
    decode_responses=True
)

# ---------------------------------------------------------
# Models
# ---------------------------------------------------------
class RevocationRequest(BaseModel):
    source: str
    event_type: str
    incident_id: str
    session_id: str | None = None
    decision: dict
    decision_hash: str
    timestamp_ms: int


class IntrospectionRequest(BaseModel):
    session_id: str


# ---------------------------------------------------------
# Health Check
# ---------------------------------------------------------
@app.get("/health")
def health():
    return {"status": "ok"}


# ---------------------------------------------------------
# /v1/revocations/propagate
# ---------------------------------------------------------
@app.post("/v1/revocations/propagate")
def propagate_revocation(req: RevocationRequest):

    if not req.session_id:
        return {
            "status": "ignored",
            "reason": "No session_id provided"
        }

    redis_key = f"ztr:session:{req.session_id}"

    # Delete session key
    deleted = r.delete(redis_key)

    # Write audit log entry
    audit_entry = {
        "source": req.source,
        "incident_id": req.incident_id,
        "decision_hash": req.decision_hash,
        "revocation_reason": req.decision.get("reason"),
        "confidence": req.decision.get("confidence"),
        "timestamp_ms": int(time.time() * 1000),
    }

    r.rpush("ztr:audit:revocations", str(audit_entry))

    return {
        "status": "ok",
        "deleted": bool(deleted),
        "redis_key": redis_key,
    }


# ---------------------------------------------------------
# /v1/introspect  (Enforcement Boundary)
# ---------------------------------------------------------
@app.post("/v1/introspect")
def introspect(req: IntrospectionRequest):

    session_key = f"ztr:session:{req.session_id}"

    if not r.exists(session_key):
        raise HTTPException(
            status_code=401,
            detail="Session revoked"
        )

    return {
        "status": "active",
        "session_id": req.session_id
    }
