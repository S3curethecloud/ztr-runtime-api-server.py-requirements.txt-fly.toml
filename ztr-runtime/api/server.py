# =========================================================
# FILE: api/server.py  (ztr-runtime)
# SecureTheCloud — Zero Trust Runtime
#
# Phase 1–4: FROZEN (token issuance, introspection,
#            revocation, audit chain)
#
# Phase 5A deltas applied:
#   5A-02: tenant_id passed to all emit_event() calls
#   5A-03: propagate_revocation derives tenant from API key
#   5A-04: audit read endpoints locked behind API key
#   5A-05: admin router mounted
#   5A-06: CORS fixed to production origins
#   5A-07: /health enriched with active_sessions + policy_rev
#
# Phase 5B deltas applied:
#   5B-02: OPA Layer 5 wired into introspect()
#   5B-03: policy_revision + opa_result in introspect audit
# =========================================================

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
from opa_bridge import evaluate_introspect_policy
from admin import admin_router

app = FastAPI(title="Zero Trust Runtime")

# Phase 5A-05 — mount admin router
app.include_router(admin_router)

# ---------------------------------------------------------
# Phase 5A-06 — CORS: production origins only
# ---------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://securethecloud.dev",
        "https://stc-intelligence-core.pages.dev",
        "https://shield.securethecloud.dev",
        "https://console.securethecloud.dev",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------
# Configuration (frozen)
# ---------------------------------------------------------
REDIS_HOST     = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT     = int(os.getenv("REDIS_PORT", 6379))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", None)

JWT_SECRET         = os.environ["ZTR_JWT_SECRET"]
JWT_ISSUER         = "ztr-runtime"
JWT_AUDIENCE       = "securethecloud"
JWT_VERSION        = "1.0"
POLICY_REVISION    = os.environ["POLICY_REVISION"]
JWT_SECRET_VERSION = os.environ["JWT_SECRET_VERSION"]

r = redis.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    password=REDIS_PASSWORD,
    decode_responses=True,
)

# ---------------------------------------------------------
# Tenant API Key Enforcement (frozen — Phase 5 scaffold)
# ---------------------------------------------------------

def sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def derive_tenant_from_api_key(api_key: str) -> str:
    hashed    = sha256(api_key)
    tenant_id = r.get(f"ztr:apikey:{hashed}")
    if not tenant_id:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return tenant_id


def require_tenant_api_key(x_stc_api_key: str = Header(None)) -> str:
    if not x_stc_api_key:
        raise HTTPException(status_code=401, detail="Missing API key")
    return derive_tenant_from_api_key(x_stc_api_key)

# ---------------------------------------------------------
# Models (frozen)
# ---------------------------------------------------------

class TokenIssueRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    principal:   str
    intent:      str
    scopes:      list[str]
    ttl_seconds: int
    context:     dict


class IntrospectionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: str


class RevocationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source:        str
    event_type:    str
    incident_id:   str
    session_id:    str
    decision:      dict
    decision_hash: str
    timestamp_ms:  int


class TenantRevokeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    session_id: str

# ---------------------------------------------------------
# Phase 5A-07 — /health enriched
# ---------------------------------------------------------

@app.get("/health")
def health():
    try:
        session_count = sum(1 for _ in r.scan_iter("ztr:*:session:*"))
    except Exception:
        session_count = None
    return {
        "status":          "ok",
        "active_sessions": session_count,
        "policy_rev":      POLICY_REVISION,
    }

# ---------------------------------------------------------
# Phase 5A-04 — Audit endpoints locked behind API key
# ---------------------------------------------------------

@app.get("/v1/audit/verify")
def audit_verify(
    limit: int = 5000,
    tenant_id: str = Depends(require_tenant_api_key),
):
    return verify_chain(tenant_id=tenant_id, limit=limit)


@app.get("/v1/audit/index/{event_type}")
def audit_index(
    event_type: str,
    limit: int = 50,
    tenant_id: str = Depends(require_tenant_api_key),
):
    return {
        "event_type": event_type,
        "limit":      limit,
        "hashes":     list_index(tenant_id=tenant_id, event_type=event_type, limit=limit),
    }


@app.get("/v1/audit/entry/{event_hash}")
def audit_entry(
    event_hash: str,
    tenant_id: str = Depends(require_tenant_api_key),
):
    entry = get_entry(event_hash=event_hash, tenant_id=tenant_id)
    if not entry:
        raise HTTPException(status_code=404, detail="audit_entry_not_found")
    return entry

# ---------------------------------------------------------
# /v1/tokens:issue (frozen — Phase 3)
# ---------------------------------------------------------

@app.post("/v1/tokens:issue")
def issue_token(
    req: TokenIssueRequest,
    tenant_id: str = Depends(require_tenant_api_key),
):
    sid = f"SID-{uuid.uuid4().hex}"
    jti = uuid.uuid4().hex

    now = int(time.time())
    exp = now + req.ttl_seconds

    payload = {
        "iss":    JWT_ISSUER,
        "aud":    JWT_AUDIENCE,
        "sub":    req.principal,
        "sid":    sid,
        "jti":    jti,
        "iat":    now,
        "exp":    exp,
        "ver":    JWT_VERSION,
        "intent": req.intent,
        "scopes": req.scopes,
        "tid":    tenant_id,
    }

    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")

    session_key = f"ztr:{tenant_id}:session:{sid}"

    r.set(
        session_key,
        json.dumps({
            "principal": req.principal,
            "intent":    req.intent,
            "scopes":    req.scopes,
            "context":   req.context,
            "issued_at": now,
            "expires_at": exp,
            "jti":       jti,
        }),
        ex=req.ttl_seconds,
    )

    audit = emit_event(
        event_type="runtime.token_issued",
        service="ztr-runtime",
        correlation_id=sid,
        tenant_id=tenant_id,
        payload={
            "sid":             sid,
            "jti":             jti,
            "principal":       req.principal,
            "intent":          req.intent,
            "scopes":          req.scopes,
            "ttl_seconds":     req.ttl_seconds,
            "jwt_ver":         JWT_VERSION,
            "policy_revision": POLICY_REVISION,
            "secret_version":  JWT_SECRET_VERSION,
            "issued_at":       now,
            "expires_at":      exp,
            "authority_store": "redis",
            "tenant_id":       tenant_id,
        },
    )

    return {
        "access_token": token,
        "token_type":   "Bearer",
        "expires_in":   req.ttl_seconds,
        "session_id":   sid,
        "jti":          jti,
        "audit":        audit,
    }

# ---------------------------------------------------------
# /v1/introspect
# ---------------------------------------------------------

@app.post("/v1/introspect")
def introspect(
    req: IntrospectionRequest,
    tenant_id: str = Depends(require_tenant_api_key),
):

    try:
        decoded = jwt.decode(
            req.token,
            JWT_SECRET,
            algorithms=["HS256"],
            issuer=JWT_ISSUER,
            audience=JWT_AUDIENCE,
        )
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

    if decoded.get("ver") != JWT_VERSION:
        raise HTTPException(status_code=401, detail="Invalid token version")

    if decoded.get("tid") != tenant_id:
        raise HTTPException(status_code=401, detail="Tenant mismatch")

    sid         = decoded.get("sid")
    session_key = f"ztr:{tenant_id}:session:{sid}"

    if not r.exists(session_key):
        emit_event(
            event_type="runtime.token_introspected",
            service="ztr-runtime",
            correlation_id=sid,
            tenant_id=tenant_id,
            payload={
                "sid":       sid,
                "principal": decoded.get("sub"),
                "result":    "revoked",
                "jwt_ver":   decoded.get("ver"),
                "redis_present": False,
                "tenant_id": tenant_id,
            },
        )
        raise HTTPException(status_code=401, detail="Session revoked")

    session_data = json.loads(r.get(session_key) or "{}")

    opa_result = evaluate_introspect_policy(
        principal=decoded.get("sub"),
        scopes=decoded.get("scopes", []),
        intent=decoded.get("intent"),
        tenant_id=tenant_id,
        policy_revision=POLICY_REVISION,
        context=session_data.get("context", {}),
    )

    if not opa_result["allow"]:
        emit_event(
            event_type="runtime.policy_denied",
            service="ztr-runtime",
            correlation_id=sid,
            tenant_id=tenant_id,
            payload={
                "sid":             sid,
                "principal":       decoded.get("sub"),
                "reason":          opa_result["reason"],
                "policy_revision": opa_result["policy_revision"],
                "tenant_id":       tenant_id,
            },
        )
        raise HTTPException(status_code=401, detail="policy_denied")

    audit = emit_event(
        event_type="runtime.token_introspected",
        service="ztr-runtime",
        correlation_id=sid,
        tenant_id=tenant_id,
        payload={
            "sid":             sid,
            "principal":       decoded.get("sub"),
            "result":          "active",
            "jwt_ver":         decoded.get("ver"),
            "redis_present":   True,
            "tenant_id":       tenant_id,
            "policy_revision": POLICY_REVISION,
            "opa_result":      opa_result.get("reason"),
        },
    )

    return {
        "status":     "active",
        "session_id": sid,
        "principal":  decoded.get("sub"),
        "scopes":     decoded.get("scopes"),
        "intent":     decoded.get("intent"),
        "expires_at": decoded.get("exp"),
        "audit":      audit,
    }

# ---------------------------------------------------------
# /v1/revocations/propagate
# ---------------------------------------------------------

@app.post("/v1/revocations/propagate")
def propagate_revocation(
    req: RevocationRequest,
    tenant_id: str = Depends(require_tenant_api_key),
):

    redis_key = f"ztr:{tenant_id}:session:{req.session_id}"
    deleted   = r.delete(redis_key)

    audit = emit_event(
        event_type="runtime.session_revoked",
        service="ztr-runtime",
        correlation_id=req.session_id,
        tenant_id=tenant_id,
        payload={
            "sid":          req.session_id,
            "incident_id":  req.incident_id,
            "decision_hash": req.decision_hash,
            "deleted":      bool(deleted),
            "redis_key":    redis_key,
            "reason":       req.decision.get("reason"),
            "confidence":   req.decision.get("confidence"),
            "tenant_id":    tenant_id,
        },
    )

    return {
        "status":    "ok",
        "deleted":   bool(deleted),
        "redis_key": redis_key,
        "audit":     audit,
    }

# ---------------------------------------------------------
# /v1/sessions/revoke
# ---------------------------------------------------------

@app.post("/v1/sessions/revoke")
def tenant_revoke(
    req: TenantRevokeRequest,
    tenant_id: str = Depends(require_tenant_api_key),
):

    redis_key = f"ztr:{tenant_id}:session:{req.session_id}"
    deleted   = r.delete(redis_key)

    audit = emit_event(
        event_type="runtime.session_revoked",
        service="ztr-runtime",
        correlation_id=req.session_id,
        tenant_id=tenant_id,
        payload={
            "sid":       req.session_id,
            "deleted":   bool(deleted),
            "redis_key": redis_key,
            "source":    "tenant_api",
            "tenant_id": tenant_id,
        },
    )

    return {
        "status":  "ok",
        "deleted": bool(deleted),
        "audit":   audit,
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

        data          = json.loads(data_raw)
        ttl_remaining = r.ttl(key)
        sid           = key.split(":")[-1]

        sessions.append({
            "sid":           sid,
            "principal":     data.get("principal"),
            "intent":        data.get("intent"),
            "scopes":        data.get("scopes"),
            "issued_at":     data.get("issued_at"),
            "expires_at":    data.get("expires_at"),
            "ttl_remaining": ttl_remaining,
        })

    return {
        "tenant_id":       tenant_id,
        "active_sessions": sessions,
        "count":           len(sessions),
    }
