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

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, Response
import redis
import time
import os
import uuid
import jwt
import hashlib
import json

from runtime_identity import get_node_id
from api.risk_engine import compute_risk_score

from api.models import TokenIssueRequest, IntrospectionRequest, TenantRevokeRequest
from api.auth import require_tenant_api_key
from api.intelligence import intelligence_router

from audit_chain import emit_event, verify_chain, list_index, get_entry
from opa_bridge import evaluate_introspect_policy
from policy_subscriber import start_subscriber
from policy_listener import start_listener_thread

from admin_router import admin_router
from admin.anomalies import router as anomalies_router
from api.tokens import tokens_router
from api.sessions import sessions_router
from api.policy import router as policy_router
from api.observability import router as observability_router
from api.streaming import router as streaming_router
from api.metrics import router as metrics_router
from api.control_plane import router as control_router
from api.topology import router as topology_router
from api.router_endpoint import router as routing_router
# from revocations import revocations_router


@asynccontextmanager
async def lifespan(app):
    start_subscriber()
    start_listener_thread()
    yield


app = FastAPI(title="Zero Trust Runtime", lifespan=lifespan)

# ---------------------------------------------------------
# CORS (MOVED ABOVE ROUTERS — CRITICAL FIX)
# ---------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://securethecloud.dev",
        "https://app.securethecloud.dev",
        "https://stc-intelligence-core.pages.dev",
        "https://shield.securethecloud.dev",
        "https://console.securethecloud.dev",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------
# 🔧 PRE-FLIGHT HANDLER (CORS HARD FIX)
# ---------------------------------------------------------

@app.options("/{full_path:path}")
async def preflight_handler(full_path: str):
    return Response(status_code=200)

# ---------------------------------------------------------
# ROUTER REGISTRATION
# ---------------------------------------------------------

app.include_router(admin_router)
app.include_router(anomalies_router)
app.include_router(tokens_router)
app.include_router(sessions_router)
app.include_router(policy_router)
app.include_router(observability_router)
app.include_router(streaming_router)
app.include_router(metrics_router)
app.include_router(control_router)
app.include_router(topology_router)
app.include_router(routing_router)
app.include_router(intelligence_router)
# app.include_router(revocations_router)


JWT_SECRET         = os.environ["ZTR_JWT_SECRET"]
JWT_ISSUER         = "ztr-runtime"
JWT_AUDIENCE       = "securethecloud"
JWT_VERSION        = "1.0"
POLICY_REVISION    = os.environ["POLICY_REVISION"]
JWT_SECRET_VERSION = os.environ["JWT_SECRET_VERSION"]

r = redis.from_url(os.environ["REDIS_URL"], decode_responses=True)

NODE_ID = get_node_id()

r.sadd("runtime:nodes", NODE_ID)

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
        session_count = int(r.get("ztr:sessions:active") or 0)
    except Exception:
        session_count = None

    return {
        "status": "ok",
        "active_sessions": session_count,
        "policy_rev": POLICY_REVISION,
    }


@app.get("/v1/runtime/integrity")
def runtime_integrity():

    checks = {}

    try:
        r.ping()
        checks["redis"] = True
    except Exception:
        checks["redis"] = False

    policy_rev = POLICY_REVISION
    runtime_rev = os.getenv("RUNTIME_REVISION", "unknown")

    try:
        result = verify_chain(limit=1)
        audit_status = result.get("status")
    except Exception:
        audit_status = "failed"

    return {
        "runtime_revision": runtime_rev,
        "policy_revision": policy_rev,
        "redis_ok": checks["redis"],
        "audit_chain": audit_status,
        "timestamp": int(time.time())
    }


@app.get("/v1/audit/verify")
def audit_verify(
    tenant_id: str = Depends(require_tenant_api_key)
):

    try:
        result = verify_chain(tenant_id=tenant_id)

        return result

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail="audit_verification_failed"
        )
