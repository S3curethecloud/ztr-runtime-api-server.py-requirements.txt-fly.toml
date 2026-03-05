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

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
import redis
import time
import os
import uuid
import jwt
import hashlib
import json

from api.models import TokenIssueRequest, IntrospectionRequest, TenantRevokeRequest
from api.auth import require_tenant_api_key

from audit_chain import emit_event, verify_chain, list_index, get_entry
from opa_bridge import evaluate_introspect_policy

from admin import admin_router
from api.tokens import tokens_router
from api.sessions import sessions_router
# from audit import audit_router
# from revocations import revocations_router

app = FastAPI(title="Zero Trust Runtime")

# ---------------------------------------------------------
# ROUTER REGISTRATION
# ---------------------------------------------------------

app.include_router(admin_router)
app.include_router(tokens_router)
app.include_router(sessions_router)
# app.include_router(audit_router)
# app.include_router(revocations_router)

# ---------------------------------------------------------
# CORS
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

def sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()

class RevocationRequest(TokenIssueRequest.__class__):
    source:        str
    event_type:    str
    incident_id:   str
    session_id:    str
    decision:      dict
    decision_hash: str
    timestamp_ms:  int

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
# SAFE READ-ONLY DECISION STREAM
# ---------------------------------------------------------

@app.get("/v1/decisions")
def list_recent_decisions(
    limit: int = 25,
    tenant_id: str = Depends(require_tenant_api_key),
):

    decision_event_types = [
        "runtime.token_introspected",
        "runtime.policy_denied",
        "runtime.session_revoked",
    ]

    events = []

    for event_type in decision_event_types:

        hashes = list_index(
            tenant_id=tenant_id,
            event_type=event_type,
            limit=limit,
        )

        for h in hashes:

            entry = get_entry(h, tenant_id=tenant_id)
            if not entry:
                continue

            payload = entry.get("payload", {})

            events.append({
                "id": entry.get("event_hash"),
                "type": entry.get("event_type"),
                "time": entry.get("ts_ms"),
                "principal": payload.get("principal"),
                "intent": payload.get("intent"),
                "result": payload.get("result"),
                "policy_revision": payload.get("policy_revision"),
            })

    events.sort(key=lambda e: e["time"], reverse=True)

    return {"events": events[:limit]}

# ---------------------------------------------------------
# DECISION EXPLANATION ENDPOINT
# ---------------------------------------------------------

@app.get("/v1/decisions/{event_hash}")
def explain_decision(
    event_hash: str,
    tenant_id: str = Depends(require_tenant_api_key),
):

    entry = get_entry(event_hash=event_hash, tenant_id=tenant_id)

    if not entry:
        raise HTTPException(status_code=404, detail="decision_not_found")

    payload = entry.get("payload", {})

    return {
        "event_hash": entry.get("event_hash"),
        "event_type": entry.get("event_type"),
        "timestamp": entry.get("ts_ms"),
        "principal": payload.get("principal"),
        "intent": payload.get("intent"),
        "result": payload.get("result"),
        "policy_revision": payload.get("policy_revision"),
        "reason": payload.get("reason") or payload.get("opa_result"),
        "correlation_id": entry.get("correlation_id"),
    }

# ---------------------------------------------------------
# SSE DECISION STREAM
# ---------------------------------------------------------

@app.get("/v1/decisions/stream")
def stream_decisions(
    tenant_id: str = Depends(require_tenant_api_key),
):

    decision_event_types = [
        "runtime.token_introspected",
        "runtime.policy_denied",
        "runtime.session_revoked",
    ]

    def event_stream():

        last_seen = set()

        while True:

            events = []

            for event_type in decision_event_types:

                hashes = list_index(
                    tenant_id=tenant_id,
                    event_type=event_type,
                    limit=20,
                )

                for h in hashes:

                    if h in last_seen:
                        continue

                    entry = get_entry(h, tenant_id=tenant_id)
                    if not entry:
                        continue

                    payload = entry.get("payload", {})

                    event = {
                        "id": entry.get("event_hash"),
                        "type": entry.get("event_type"),
                        "time": entry.get("ts_ms"),
                        "principal": payload.get("principal"),
                        "intent": payload.get("intent"),
                        "result": payload.get("result"),
                        "policy_revision": payload.get("policy_revision"),
                    }

                    last_seen.add(h)
                    events.append(event)

            for e in events:
                yield f"data: {json.dumps(e)}\n\n"

            time.sleep(2)

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
    )
