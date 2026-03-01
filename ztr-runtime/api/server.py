from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict
import redis
import time
import os
import uuid
import jwt

from audit_chain import emit_event, verify_chain, list_index, get_entry

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

POLICY_REVISION = os.environ["POLICY_REVISION"]
JWT_SECRET_VERSION = os.environ["JWT_SECRET_VERSION"]

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
    model_config = ConfigDict(extra="forbid")

    principal: str
    intent: str
    scopes: list[str]
    ttl_seconds: int
    context: dict


class IntrospectionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token: str


class RevocationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

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
# Phase 4 — Audit endpoints (read-only)
# ---------------------------------------------------------

@app.get("/v1/audit/verify")
def audit_verify(limit: int = 5000):
    return verify_chain(limit=limit)


@app.get("/v1/audit/index/{event_type}")
def audit_index(event_type: str, limit: int = 50):
    return {
        "event_type": event_type,
        "limit": limit,
        "hashes": list_index(event_type=event_type, limit=limit),
    }


@app.get("/v1/audit/entry/{event_hash}")
def audit_entry(event_hash: str):
    entry = get_entry(event_hash)
    if not entry:
        raise HTTPException(status_code=404, detail="audit_entry_not_found")
    return entry


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

    audit = emit_event(
        event_type="runtime.token_issued",
        service="ztr-runtime",
        correlation_id=sid,
        payload={
            "sid": sid,
            "jti": jti,
            "principal": req.principal,
            "intent": req.intent,
            "scopes": req.scopes,
            "ttl_seconds": req.ttl_seconds,
            "jwt_ver": JWT_VERSION,
            "policy_revision": POLICY_REVISION,
            "secret_version": JWT_SECRET_VERSION,
            "issued_at": now,
            "expires_at": exp,
            "authority_store": "redis",
        },
    )

    return {
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": req.ttl_seconds,
        "session_id": sid,
        "jti": jti,
        "audit": audit,
    }


# ---------------------------------------------------------
# /v1/introspect
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
        audit = emit_event(
            event_type="runtime.token_introspected",
            service="ztr-runtime",
            correlation_id=sid,
            payload={
                "sid": sid,
                "principal": decoded.get("sub"),
                "result": "revoked",
                "jwt_ver": decoded.get("ver"),
                "redis_present": False,
            },
        )
        raise HTTPException(status_code=401, detail="Session revoked")

    audit = emit_event(
        event_type="runtime.token_introspected",
        service="ztr-runtime",
        correlation_id=sid,
        payload={
            "sid": sid,
            "principal": decoded.get("sub"),
            "result": "active",
            "jwt_ver": decoded.get("ver"),
            "redis_present": True,
        },
    )

    return {
        "status": "active",
        "session_id": sid,
        "principal": decoded.get("sub"),
        "scopes": decoded.get("scopes"),
        "intent": decoded.get("intent"),
        "expires_at": decoded.get("exp"),
        "audit": audit,
    }


# ---------------------------------------------------------
# /v1/revocations/propagate
# ---------------------------------------------------------

@app.post("/v1/revocations/propagate")
def propagate_revocation(req: RevocationRequest):

    redis_key = f"ztr:session:{req.session_id}"
    deleted = r.delete(redis_key)

    audit = emit_event(
        event_type="runtime.session_revoked",
        service="ztr-runtime",
        correlation_id=req.session_id,
        payload={
            "sid": req.session_id,
            "incident_id": req.incident_id,
            "decision_hash": req.decision_hash,
            "deleted": bool(deleted),
            "redis_key": redis_key,
            "reason": req.decision.get("reason"),
            "confidence": req.decision.get("confidence"),
        },
    )

    return {
        "status": "ok",
        "deleted": bool(deleted),
        "redis_key": redis_key,
        "audit": audit,
    }
