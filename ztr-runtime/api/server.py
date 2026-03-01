from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from redis import Redis
import os, time, json, uuid
import jwt

app = FastAPI(title="Zero Trust Runtime")

# ---------------------------------------------------------
# Redis Client (Fly secrets)
# ---------------------------------------------------------
REDIS_HOST = os.environ["REDIS_HOST"]
REDIS_PORT = int(os.environ.get("REDIS_PORT", "6379"))
REDIS_PASSWORD = os.environ["REDIS_PASSWORD"]

r = Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    password=REDIS_PASSWORD,
    decode_responses=True,
    ssl=False,  # important: internal/private wiring
)

# ---------------------------------------------------------
# JWT config
# ---------------------------------------------------------
JWT_SIGNING_KEY = os.environ["JWT_SIGNING_KEY"]
JWT_ISSUER = os.environ.get("JWT_ISSUER", "ztr-runtime")
JWT_AUDIENCE = os.environ.get("JWT_AUDIENCE", "stc")

DEFAULT_TTL_SECONDS = 300

# ---------------------------------------------------------
# Models
# ---------------------------------------------------------
class TokenIssueRequest(BaseModel):
    principal: str
    intent: str
    scopes: list[str] = []
    ttl_seconds: int | None = None
    context: dict = {}

class TokenIssueResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    session_id: str
    jti: str

class IntrospectRequest(BaseModel):
    token: str | None = None
    session_id: str | None = None

class RevocationRequest(BaseModel):
    source: str
    event_type: str
    incident_id: str
    session_id: str | None = None
    decision: dict
    decision_hash: str
    timestamp_ms: int

# ---------------------------------------------------------
# Health
# ---------------------------------------------------------
@app.get("/healthth")
def healthth():
    return {"status": "ok"}

# ---------------------------------------------------------
# /v1/tokens:issue
# ---------------------------------------------------------
@app.post("/v1/tokens:issue", response_model=TokenIssueResponse)
def issue_token(req: TokenIssueRequest):
    ttl = int(req.ttl_seconds or DEFAULT_TTL_SECONDS)
    now = int(time.time())

    session_id = f"SID-{uuid.uuid4().hex}"
    jti = uuid.uuid4().hex

    session_key = f"ztr:session:{session_id}"

    session_value = {
        "principal": req.principal,
        "intent": req.intent,
        "scopes": req.scopes,
        "context": req.context,
        "issued_at": now,
        "expires_at": now + ttl,
        "jti": jti,
    }

    # Store authority in Redis with TTL
    r.set(session_key, json.dumps(session_value))
    r.expire(session_key, ttl)

    # Mint JWT that references the Redis session_id (authority source)
    claims = {
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "sub": req.principal,
        "sid": session_id,
        "jti": jti,
        "iat": now,
        "exp": now + ttl,
        "scopes": req.scopes,
        "intent": req.intent,
    }

    token = jwt.encode(claims, JWT_SIGNING_KEY, algorithm="HS256")

    return TokenIssueResponse(
        access_token=token,
        expires_in=ttl,
        session_id=session_id,
        jti=jti,
    )

# ---------------------------------------------------------
# /v1/introspect (enforcement boundary)
# ---------------------------------------------------------
@app.post("/v1/introspect")
def introspect(req: IntrospectRequest):
    session_id = req.session_id

    if req.token:
        try:
            claims = jwt.decode(
                req.token,
                JWT_SIGNING_KEY,
                algorithms=["HS256"],
                audience=JWT_AUDIENCE,
                issuer=JWT_ISSUER,
            )
            session_id = claims.get("sid")
        except Exception:
            raise HTTPException(status_code=401, detail="Invalid token")

    if not session_id:
        raise HTTPException(status_code=400, detail="token or session_id required")

    session_key = f"ztr:session:{session_id}"

    # ✅ Enforcement boundary
    if not r.exists(session_key):
        raise HTTPException(status_code=401, detail="Session revoked")

    raw = r.get(session_key)
    return {
        "status": "active",
        "session_id": session_id,
        "session": json.loads(raw) if raw else None,
    }

# ---------------------------------------------------------
# /v1/revocations/propagate
# ---------------------------------------------------------
@app.post("/v1/revocations/propagate")
def propagate_revocation(req: RevocationRequest):
    if not req.session_id:
        return {"status": "ignored", "reason": "No session_id provided"}

    redis_key = f"ztr:session:{req.session_id}"
    deleted = r.delete(redis_key)

    audit_entry = {
        "source": req.source,
        "incident_id": req.incident_id,
        "decision_hash": req.decision_hash,
        "revocation_reason": req.decision.get("reason"),
        "confidence": req.decision.get("confidence"),
        "timestamp_ms": int(time.time() * 1000),
    }

    r.rpush("ztr:audit:revocations", json.dumps(audit_entry))

    return {
        "status": "ok",
        "deleted": bool(deleted),
        "redis_key": redis_key
    }
