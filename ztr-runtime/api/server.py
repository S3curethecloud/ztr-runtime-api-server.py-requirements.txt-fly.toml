# FILE: api/server.py

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict
import redis
import time
import os
import uuid
import jwt
import hashlib
import json

from audit_chain import emit_event, verify_chain, list_index, get_entry

app = FastAPI(title="Zero Trust Runtime")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8080",
        "https://securethecloud.dev",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "X-STC-API-Key", "Authorization"],
)

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
# Tenant API Key Enforcement (Phase 5)
# ---------------------------------------------------------

def sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def derive_tenant_from_api_key(api_key: str) -> str:
    hashed = sha256(api_key)
    tenant_id = r.get(f"ztr:apikey:{hashed}")

    if not tenant_id:
        raise HTTPException(status_code=401, detail="Invalid API key")

    return tenant_id


def require_tenant_api_key(x_stc_api_key: str = Header(None)) -> str:
    if not x_stc_api_key:
        raise HTTPException(status_code=401, detail="Missing API key")

    return derive_tenant_from_api_key(x_stc_api_key)

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


class TenantRevokeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    session_id: str

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
def issue_token(
    req: TokenIssueRequest,
    tenant_id: str = Depends(require_tenant_api_key)
):

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
        "scopes": req.scopes,
        "tid": tenant_id,
        "policy_revision": POLICY_REVISION,
    }

    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")

    session_key = f"ztr:{tenant_id}:session:{sid}"

    r.set(
        session_key,
        json.dumps({
            "principal": req.principal,
            "intent": req.intent,
            "scopes": req.scopes,
            "context": req.context,
            "issued_at": now,
            "expires_at": exp,
            "jti": jti,
            "policy_revision": POLICY_REVISION,
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
            "tenant_id": tenant_id,
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
def introspect(
    req: IntrospectionRequest,
    tenant_id: str = Depends(require_tenant_api_key)
):

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

    if decoded.get("tid") != tenant_id:
        raise HTTPException(status_code=401, detail="Tenant mismatch")

    token_rev = decoded.get("policy_revision")
    if token_rev != POLICY_REVISION:
        audit = emit_event(
            event_type="runtime.token_introspected",
            service="ztr-runtime",
            correlation_id=decoded.get("sid"),
            payload={
                "sid": decoded.get("sid"),
                "principal": decoded.get("sub"),
                "result": "policy_mismatch",
                "jwt_ver": decoded.get("ver"),
                "redis_present": None,
                "tenant_id": tenant_id,
                "token_policy_revision": token_rev,
                "runtime_policy_revision": POLICY_REVISION,
            },
        )
        raise HTTPException(status_code=401, detail="policy_revision_mismatch")

    sid = decoded.get("sid")
    session_key = f"ztr:{tenant_id}:session:{sid}"

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
                "tenant_id": tenant_id,
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
            "tenant_id": tenant_id,
        },
    )

    return {
        "status": "active",
        "session_id": sid,
        "principal": decoded.get("sub"),
        "scopes": decoded.get("scopes"),
        "intent": decoded.get("intent"),
        "expires_at": decoded.get("exp"),
        "policy_revision": decoded.get("policy_revision"),
        "audit": audit,
    }

# ---------------------------------------------------------
# /v1/revocations/propagate
# ---------------------------------------------------------

@app.post("/v1/revocations/propagate")
def propagate_revocation(req: RevocationRequest):

    tenant_id = req.decision.get("tenant_id")
    if not tenant_id:
        raise HTTPException(status_code=400, detail="Missing tenant_id in decision")

    redis_key = f"ztr:{tenant_id}:session:{req.session_id}"
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
            "tenant_id": tenant_id,
        },
    )

    return {
        "status": "ok",
        "deleted": bool(deleted),
        "redis_key": redis_key,
        "audit": audit,
    }

# ---------------------------------------------------------
# /v1/sessions/revoke
# ---------------------------------------------------------

@app.post("/v1/sessions/revoke")
def tenant_revoke(
    req: TenantRevokeRequest,
    tenant_id: str = Depends(require_tenant_api_key)
):

    redis_key = f"ztr:{tenant_id}:session:{req.session_id}"
    deleted = r.delete(redis_key)

    audit = emit_event(
        event_type="runtime.session_revoked",
        service="ztr-runtime",
        correlation_id=req.session_id,
        payload={
            "sid": req.session_id,
            "deleted": bool(deleted),
            "redis_key": redis_key,
            "source": "tenant_api",
            "tenant_id": tenant_id,
        },
    )

    return {
        "status": "ok",
        "deleted": bool(deleted),
        "audit": audit,
    }

# ---------------------------------------------------------
# /v1/sessions/active
# ---------------------------------------------------------

@app.get("/v1/sessions/active")
def list_active_sessions(tenant_id: str = Depends(require_tenant_api_key)):

    sessions = []

    for key in r.scan_iter(f"ztr:{tenant_id}:session:*"):
        data_raw = r.get(key)

        if not data_raw:
            continue

        data = json.loads(data_raw)

        ttl_remaining = r.ttl(key)
        sid = key.split(":")[-1]

        sessions.append({
            "sid": sid,
            "principal": data.get("principal"),
            "intent": data.get("intent"),
            "scopes": data.get("scopes"),
            "issued_at": data.get("issued_at"),
            "expires_at": data.get("expires_at"),
            "ttl_remaining": ttl_remaining
        })

    return {
        "tenant_id": tenant_id,
        "active_sessions": sessions,
        "count": len(sessions)
    }
