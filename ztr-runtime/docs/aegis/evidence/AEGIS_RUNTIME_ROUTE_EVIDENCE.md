# Aegis Runtime Route Evidence

Generated: 2026-05-27T01:07:58Z

## Router declarations
api/aegis_ack.py:1:from fastapi import APIRouter, Depends
api/aegis_ack.py:10:router = APIRouter()
api/sessions.py:27:from fastapi import APIRouter, Depends, HTTPException, Body, Header
api/sessions.py:40:sessions_router = APIRouter(prefix="/v1/sessions", tags=["sessions"])
api/alerts.py:7:from fastapi import APIRouter, Depends
api/alerts.py:13:router = APIRouter()
api/aegis_temporal.py:1:from fastapi import APIRouter, Depends
api/aegis_temporal.py:8:router = APIRouter()
api/metrics.py:3:from fastapi import APIRouter
api/metrics.py:8:router = APIRouter()
api/control_plane.py:1:from fastapi import APIRouter, HTTPException, Query, Header
api/control_plane.py:11:router = APIRouter(prefix="/v1/admin", tags=["control-plane"])
api/copilot_bridge.py:1:from fastapi import APIRouter, Depends
api/copilot_bridge.py:6:router = APIRouter(prefix="/v1/copilot", tags=["copilot"])
api/observability.py:5:from fastapi import APIRouter, Response, Depends
api/observability.py:16:router = APIRouter(prefix="/v1")
api/router_endpoint.py:1:from fastapi import APIRouter
api/router_endpoint.py:4:router = APIRouter()
api/tokens.py:1:from fastapi import APIRouter, Depends, Header, HTTPException
api/tokens.py:33:tokens_router = APIRouter(prefix="/v1", tags=["tokens"])
api/policy_registry.py:4:from fastapi import APIRouter, HTTPException
api/policy_registry.py:11:router = APIRouter(prefix="/v1/admin", tags=["policy-registry"])
api/copilot_aegis.py:1:from fastapi import APIRouter, Depends
api/copilot_aegis.py:7:copilot_aegis_router = APIRouter()
api/intelligence.py:4:from fastapi import APIRouter
api/intelligence.py:11:intelligence_router = APIRouter(
api/policy.py:1:from fastapi import APIRouter
api/policy.py:4:router = APIRouter()
api/topology.py:1:from fastapi import APIRouter
api/topology.py:5:router = APIRouter()
api/control_plane_registry.py:4:from fastapi import APIRouter, HTTPException
api/control_plane_registry.py:10:router = APIRouter(prefix="/v1/admin", tags=["control-plane-registry"])
api/server.py:54:app = FastAPI(title="Zero Trust Runtime", lifespan=lifespan)
api/streaming.py:4:from fastapi import APIRouter, Request, Depends, Query, HTTPException
api/streaming.py:13:router = APIRouter(prefix="/v1")
api/audit.py:16:from fastapi import APIRouter, Depends, Query, HTTPException
api/audit.py:27:router = APIRouter(prefix="/v1")
admin_router.py:31:from fastapi import APIRouter, Header, HTTPException
admin_router.py:53:admin_router = APIRouter(prefix="/v1/admin", tags=["admin"])

## Route decorators
api/aegis_ack.py:16:@router.post("/aegis/ack")
api/aegis_ack.py:69:@router.get("/aegis/ack/{principal}")
api/sessions.py:168:@sessions_router.get("/active")
api/sessions.py:181:@sessions_router.get("/admin/active")
api/sessions.py:260:@sessions_router.post("/revoke")
api/sessions.py:276:@sessions_router.post("/admin/revoke")
api/alerts.py:96:@router.get("/v1/alerts/riskdna")
api/alerts.py:196:@router.get("/v1/alerts/riskdna/latest-decision")
api/aegis_temporal.py:32:@router.get("/aegis/temporal")
api/aegis_temporal.py:74:@router.get("/aegis/temporal/{principal}")
api/metrics.py:18:@router.get("/v1/audit/metrics")
api/control_plane.py:31:@router.post("/policy/publish")
api/control_plane.py:199:@router.get("/control-plane/policy")
api/control_plane.py:238:@router.get("/control-plane/tenants")
api/control_plane.py:301:@router.post("/control-plane/revoke-tenant")
api/control_plane.py:354:@router.post("/control-plane/fix-tenant")
api/copilot_bridge.py:89:@router.post("/platform")
api/copilot_bridge.py:255:@router.post("/decision")
api/copilot_bridge.py:262:@router.post("/bridge/decision")
api/observability.py:71:@router.get("/runtime/integrity")
api/observability.py:248:@router.get("/runtime/activity")
api/observability.py:285:@router.get("/metrics")
api/observability.py:308:@router.get("/metrics/prometheus")
api/router_endpoint.py:7:@router.get("/v1/runtime/route")
api/tokens.py:82:@tokens_router.post("/tokens/introspect")
api/tokens.py:292:@tokens_router.post("/tokens/issue")
api/policy_registry.py:29:@router.post("/policy/register")
api/policy_registry.py:66:@router.get("/policy/global")
api/copilot_aegis.py:90:@copilot_aegis_router.post("/copilot/aegis/simulate")
api/intelligence.py:19:@intelligence_router.get("/risk")
api/policy.py:6:@router.get("/v1/policy/bundle")
api/topology.py:9:@router.get("/v1/runtime/topology")
api/control_plane_registry.py:24:@router.post("/registry/create")
api/control_plane_registry.py:56:@router.get("/registry/list")
api/control_plane_registry.py:76:@router.get("/registry/get")
api/server.py:138:@app.get("/health")
api/server.py:179:@app.get("/v1/audit/verify")
api/server.py:193:@app.get("/v1/audit/events")
api/server.py:237:@app.get("/v1/audit/admin/events")
api/streaming.py:147:@router.get("/decisions/recent")
api/streaming.py:207:@router.get("/decisions/stream")
api/audit.py:33:@router.get("/audit/events")
api/audit.py:68:@router.get("/audit/verify")
api/audit.py:89:@router.get("/audit/latest")
api/audit.py:113:@router.get("/audit/metrics")
admin_router.py:137:@admin_router.get("/metrics")
admin_router.py:184:@admin_router.get("/tenants")
admin_router.py:220:@admin_router.get("/tenants/summary")
admin_router.py:339:@admin_router.get("/tenants/{tenant_id}/summary")
admin_router.py:411:@admin_router.get("/tenants/{tenant_id}/usage")
admin_router.py:438:@admin_router.get("/tenants/{tenant_id}/sessions")
admin_router.py:488:@admin_router.get("/tenants/{tenant_id}/billing")
admin_router.py:522:@admin_router.post("/tenants/{tenant_id}/repair")
admin_router.py:619:@admin_router.post("/tenants")
admin_router.py:706:@admin_router.post("/api-keys/create")
admin_router.py:756:@admin_router.post("/api-keys/revoke")
admin_router.py:800:@admin_router.post("/api-keys/rotate")

## Server/router includes
api/server.py:19:from api.auth import require_tenant_api_key
api/server.py:20:from api.intelligence import intelligence_router
api/server.py:21:from api.copilot_bridge import router as copilot_router
api/server.py:22:from api.copilot_aegis import copilot_aegis_router
api/server.py:23:from api.aegis_ack import router as aegis_ack_router
api/server.py:29:from admin_router import admin_router
api/server.py:30:from api.audit import router as audit_router
api/server.py:31:from admin.anomalies import router as anomalies_router
api/server.py:32:from api.tokens import tokens_router
api/server.py:33:from api.sessions import sessions_router
api/server.py:34:from api.alerts import router as alerts_router
api/server.py:35:from api.policy import router as policy_router
api/server.py:36:from api.observability import router as observability_router
api/server.py:37:from api.streaming import router as streaming_router
api/server.py:38:from api.metrics import router as metrics_router
api/server.py:39:from api.control_plane import router as control_router
api/server.py:40:from api.control_plane_registry import router as registry_router
api/server.py:41:from api.policy_registry import router as policy_registry_router
api/server.py:42:from api.topology import router as topology_router
api/server.py:43:from api.router_endpoint import router as routing_router
api/server.py:44:from api.aegis_temporal import router as aegis_temporal_router
api/server.py:74:app.include_router(admin_router)
api/server.py:75:app.include_router(audit_router)
api/server.py:76:app.include_router(anomalies_router)
api/server.py:77:app.include_router(tokens_router)
api/server.py:78:app.include_router(sessions_router)
api/server.py:79:app.include_router(alerts_router)
api/server.py:80:app.include_router(policy_router)
api/server.py:81:app.include_router(observability_router)
api/server.py:82:app.include_router(streaming_router)
api/server.py:83:app.include_router(metrics_router)
api/server.py:84:app.include_router(control_router)
api/server.py:85:app.include_router(registry_router)
api/server.py:86:app.include_router(policy_registry_router)
api/server.py:87:app.include_router(topology_router)
api/server.py:88:app.include_router(routing_router)
api/server.py:89:app.include_router(intelligence_router)
api/server.py:90:app.include_router(copilot_router)
api/server.py:91:app.include_router(copilot_aegis_router, prefix="/v1")
api/server.py:92:app.include_router(aegis_temporal_router, prefix="/v1")
api/server.py:93:app.include_router(aegis_ack_router, prefix="/v1")
api/router_endpoint.py:2:from api.runtime_router import select_runtime_node
admin_router.py:35:from api.redis_keys import (
