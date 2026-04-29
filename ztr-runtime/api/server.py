# =========================================================
# FILE: api/server.py  (ztr-runtime)
# SecureTheCloud — Zero Trust Runtime
# =========================================================

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
import redis
import os
import hashlib
import requests
import time

from runtime_identity import get_node_id

from api.auth import require_tenant_api_key
from api.intelligence import intelligence_router
from api.copilot_bridge import router as copilot_router
from api.copilot_aegis import copilot_aegis_router
from api.aegis_ack import router as aegis_ack_router

from audit_chain import emit_event, verify_chain, list_index, get_entry, SCHEMA_VERSION
from policy_subscriber import start_subscriber
from policy_listener import start_listener_thread

from admin_router import admin_router
from api.audit import router as audit_router
from admin.anomalies import router as anomalies_router
from api.tokens import tokens_router
from api.sessions import sessions_router
from api.alerts import router as alerts_router
from api.policy import router as policy_router
from api.observability import router as observability_router
from api.streaming import router as streaming_router
from api.metrics import router as metrics_router
from api.control_plane import router as control_router
from api.control_plane_registry import router as registry_router
from api.policy_registry import router as policy_registry_router
from api.topology import router as topology_router
from api.router_endpoint import router as routing_router
from api.aegis_temporal import router as aegis_temporal_router


@asynccontextmanager
async def lifespan(app):
    start_subscriber()
    start_listener_thread()
    yield


app = FastAPI(title="Zero Trust Runtime", lifespan=lifespan)

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

@app.options("/{full_path:path}")
async def preflight_handler(full_path: str):
    return Response(status_code=200)

app.include_router(admin_router)
app.include_router(audit_router)
app.include_router(anomalies_router)
app.include_router(tokens_router)
app.include_router(sessions_router)
app.include_router(alerts_router)
app.include_router(policy_router)
app.include_router(observability_router)
app.include_router(streaming_router)
app.include_router(metrics_router)
app.include_router(control_router)
app.include_router(registry_router)
app.include_router(policy_registry_router)
app.include_router(topology_router)
app.include_router(routing_router)
app.include_router(intelligence_router)
app.include_router(copilot_router)
app.include_router(copilot_aegis_router, prefix="/v1")
app.include_router(aegis_temporal_router, prefix="/v1")
app.include_router(aegis_ack_router, prefix="/v1")

POLICY_REVISION = os.environ["POLICY_REVISION"]

r = redis.from_url(os.environ["REDIS_URL"], decode_responses=True)

NODE_ID = get_node_id()
r.sadd("runtime:nodes", NODE_ID)

ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "")


def _require_admin(x_stc_admin_secret: str = Header(None)) -> None:
    if not ADMIN_SECRET:
        raise HTTPException(status_code=503, detail="admin_not_configured")

    if not x_stc_admin_secret or x_stc_admin_secret != ADMIN_SECRET:
        raise HTTPException(status_code=403, detail="forbidden")


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _discover_audit_tenant_ids():
    tenant_ids = set()

    for key in r.scan_iter("ztr:tenant:*:meta"):
        raw = r.get(key)
        if not raw:
            continue

        try:
            import json
            meta = json.loads(raw)
        except Exception:
            continue

        tenant_id = meta.get("tenant_id")
        if tenant_id:
            tenant_ids.add(tenant_id)

    return sorted(tenant_ids)


@app.get("/health")
def health():
    try:
        # 🔒 OPA HEALTH CHECK
        opa = requests.get("http://127.0.0.1:8181/health", timeout=1)
        if opa.status_code != 200:
            raise Exception("OPA unhealthy")

        # 🔒 REDIS HEALTH CHECK
        if not r.ping():
            raise Exception("Redis unhealthy")

        # 🔒 AUDIT CHAIN INTEGRITY CHECK (CORRECTED)
        tenant_id = r.get("control_plane:tenant") or "tenant-launch"

        start_audit = time.time()
        integrity = verify_chain(tenant_id=tenant_id)
        audit_latency = int((time.time() - start_audit) * 1000)
        r.set("metric:audit_latency_ms", audit_latency)

        if integrity.get("status") != "valid":
            raise Exception("Audit chain invalid")

        session_count = int(r.get("ztr:sessions:active") or 0)

        return {
            "status": "ok",
            "opa": "healthy",
            "redis": "healthy",
            "audit_chain": "valid",
            "active_sessions": session_count,
            "policy_rev": POLICY_REVISION,
        }

    except Exception:
        raise HTTPException(
            status_code=503,
            detail="zero_trust_health_failure"
        )


@app.get("/v1/audit/verify")
def audit_verify(
    tenant_id: str = Depends(require_tenant_api_key)
):
    try:
        return verify_chain(tenant_id=tenant_id)

    except Exception:
        raise HTTPException(
            status_code=500,
            detail="audit_verification_failed"
        )


@app.get("/v1/audit/events")
def audit_events(tenant_id: str = Depends(require_tenant_api_key)):

    try:
        integrity = verify_chain(tenant_id=tenant_id)

        index = list_index(tenant_id=tenant_id, limit=50)

        events = []

        for entry_id in index:
            entry = get_entry(entry_id, tenant_id=tenant_id)

            if not entry:
                continue

            if entry.get("tenant_id") and entry.get("tenant_id") != tenant_id:
                continue

            events.append({
                "ts_ms": entry.get("ts_ms"),
                "event_type": entry.get("event_type"),
                "tenant_id": entry.get("tenant_id"),
                "payload": entry.get("payload"),
                "event_hash": entry.get("event_hash"),
                "prev_hash": entry.get("prev_hash"),
                "schema": entry.get("schema")
            })

        return {
            "status": "ok",
            "tenant_id": tenant_id,
            "schema": SCHEMA_VERSION,
            "events": list(reversed(events)),
            "integrity": integrity
        }

    except Exception as e:
        return {
            "status": "error",
            "debug": str(e)
        }


@app.get("/v1/audit/admin/events")
def audit_admin_events(
    limit: int = 50,
    x_stc_admin_secret: str = Header(None)
):
    _require_admin(x_stc_admin_secret)

    try:
        limit = max(1, min(int(limit or 50), 500))
        events = []

        for tenant_id in _discover_audit_tenant_ids():
            try:
                index = list_index(tenant_id=tenant_id, limit=limit)
            except Exception:
                continue

            for entry_id in index:
                entry = get_entry(entry_id, tenant_id=tenant_id)

                if not entry:
                    continue

                if entry.get("tenant_id") and entry.get("tenant_id") != tenant_id:
                    continue

                events.append({
                    "ts_ms": entry.get("ts_ms"),
                    "event_type": entry.get("event_type"),
                    "tenant_id": entry.get("tenant_id"),
                    "payload": entry.get("payload"),
                    "event_hash": entry.get("event_hash"),
                    "prev_hash": entry.get("prev_hash"),
                    "schema": entry.get("schema")
                })

        events.sort(key=lambda e: e.get("ts_ms") or 0)

        if len(events) > limit:
            events = events[-limit:]

        return {
            "status": "ok",
            "scope": "platform",
            "schema": SCHEMA_VERSION,
            "events": events
        }

    except Exception as e:
        return {
            "status": "error",
            "debug": str(e)
        }
