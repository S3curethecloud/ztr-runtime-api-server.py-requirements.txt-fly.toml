from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import redis
import time
import os
import uuid
import jwt

from audit_chain import emit_event

app = FastAPI(title="Zero Trust Runtime")

# ---------------------------------------------------------
# Configuration
# ---------------------------------------------------------
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", None)

JWT_SECRET = os.environ["ZTR_JWT_SECRET"]
JWT_ISSUER = "ztr-runtime"
JWT_AUDIENCE = "securethecloud"
JWT_VERSION = "1.0"

r = redis.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    password=REDIS_PASSWORD,
    decode_responses=True
)

# ---------------------------------------------------------
# Models
# ---------------------------------------------------------

class TokenIssueRequest(BaseModel):
    principal: str
    intent: str
    scopes: list[str]
    ttl_seconds: int
    context: dict


class IntrospectionRequest(BaseModel):
    token: str


class RevocationRequest(BaseModel):
    source: str
    event_type: str
    incident_id: str
    session_id: str
    decision: dict
    decision_hash: str
    timestamp_ms: int


# ---------------------------------------------------------
# Health
# ---------------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok"}


# ---------------------------------------------------------
# /v1/tokens:issue
# ---------------------------------------------------------

@app.post("/v1/tokens:issue")
def issue_token(req: TokenIssueRequest):

    sid = f"SID-{uuid.uuid4().hex}"
    jti = uuid.uuid4().hex

    now = int(time.time())
    exp = now + req.ttl_seconds

    payload = {
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "sub": req.principal,
        "sid": sid,
        "jti": jti,
        "iat": now,
        "exp": exp,
        "ver": JWT_VERSION,
        "intent": req.intent,
        "scopes": req.scopes
    }

    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")

    # Authority store (Redis is truth)
    session_key = f"ztr:session:{sid}"
    r.set(
        session_key,
        str({
            "principal": req.principal,
            "intent": req.intent,
            "scopes": req.scopes,
            "context": req.context,
            "issued_at": now,
            "expires_at": exp,
            "jti": jti
        }),
        ex=req.ttl_seconds
    )

    emit_event(
        event="token_issued",
        session_id=sid,
        principal=req.principal,
        scopes=req.scopes,
        graph_version="controlplane.v1.1",
        timestamp=int(time.time() * 1000)
    )

    return {
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": req.ttl_seconds,
        "session_id": sid,
        "jti": jti
    }


# ---------------------------------------------------------
# /v1/introspect  (Enforcement Boundary)
# ---------------------------------------------------------

@app.post("/v1/introspect")
def introspect(req: IntrospectionRequest):

    try:
        decoded = jwt.decode(
            req.token,
            JWT_SECRET,
            algorithms=["HS256"],
            issuer=JWT_ISSUER,
            audience=JWT_AUDIENCE
        )
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

    if decoded.get("ver") != JWT_VERSION:
        raise HTTPException(status_code=401, detail="Invalid token version")

    sid = decoded.get("sid")
    session_key = f"ztr:session:{sid}"

    if not r.exists(session_key):
        raise HTTPException(status_code=401, detail="Session revoked")

    emit_event(
        event="token_introspected",
        session_id=sid,
        principal=decoded.get("sub"),
        timestamp=int(time.time() * 1000)
    )

    return {
        "status": "active",
        "session_id": sid,
        "principal": decoded.get("sub"),
        "scopes": decoded.get("scopes"),
        "intent": decoded.get("intent"),
        "expires_at": decoded.get("exp")
    }


# ---------------------------------------------------------
# /v1/revocations/propagate
# ---------------------------------------------------------

@app.post("/v1/revocations/propagate")
def propagate_revocation(req: RevocationRequest):

    redis_key = f"ztr:session:{req.session_id}"
    deleted = r.delete(redis_key)

    emit_event(
        event="session_revoked",
        session_id=req.session_id,
        decision_hash=req.decision_hash,
        reason=req.decision.get("reason"),
        confidence=req.decision.get("confidence"),
        timestamp=int(time.time() * 1000)
    )

    return {
        "status": "ok",
        "deleted": bool(deleted),
        "redis_key": redis_key
    }
