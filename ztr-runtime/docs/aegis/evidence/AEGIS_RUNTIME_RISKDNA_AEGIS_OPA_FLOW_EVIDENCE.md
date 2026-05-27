# Aegis Runtime RiskDNA Aegis OPA Flow Evidence

Generated: 2026-05-27T01:08:24Z

api/aegis_ack.py:8:from audit_chain import emit_event  # 🔒 FIXED — CANONICAL AUDIT CHAIN
api/risk_engine.py:17:def compute_risk_score(tenant_id: str, principal: str):
api/risk_engine.py:31:            tenant_risk += int(data.get("risk_score") or 0)
api/risk_engine.py:58:        "risk_score": score,
api/sessions.py:2:# sessions.py — Session Lifecycle Control
api/sessions.py:6:#   GET  /v1/sessions/active
api/sessions.py:7:#   GET  /v1/sessions/admin/active
api/sessions.py:8:#   POST /v1/sessions/revoke
api/sessions.py:11:#   - Lists active runtime sessions
api/sessions.py:12:#   - Lists platform-wide active runtime sessions
api/sessions.py:13:#   - Lazily cleans expired session index entries
api/sessions.py:14:#   - Allows operator-driven session revocation
api/sessions.py:17:#   ztr:{tenant}:session:{sid}        -> HASH (TTL)
api/sessions.py:18:#   ztr:{tenant}:sessions             -> SET  (index)
api/sessions.py:31:    tenant_session_key,
api/sessions.py:32:    tenant_session_index_key,
api/sessions.py:36:from audit_chain import emit_event
api/sessions.py:40:sessions_router = APIRouter(prefix="/v1/sessions", tags=["sessions"])
api/sessions.py:84:def _list_sessions_for_tenant(tenant_id: str):
api/sessions.py:85:    index_key = tenant_session_index_key(tenant_id)
api/sessions.py:88:    sessions = []
api/sessions.py:91:        key = tenant_session_key(tenant_id, sid)
api/sessions.py:117:        policy_revision = data.get("policy_revision", "unknown")
api/sessions.py:123:        sessions.append({
api/sessions.py:124:            "session_id": sid,
api/sessions.py:133:            "policy_revision": policy_revision,
api/sessions.py:138:    return sessions
api/sessions.py:141:def _discover_session_tenant_ids():
api/sessions.py:159:    # Defensive fallback: discover tenants from live session hashes too.
api/sessions.py:160:    for key in r.scan_iter("ztr:*:session:*"):
api/sessions.py:162:        if len(parts) == 4 and parts[0] == "ztr" and parts[2] == "session":
api/sessions.py:168:@sessions_router.get("/active")
api/sessions.py:169:def list_active_sessions(
api/sessions.py:172:    sessions = _list_sessions_for_tenant(tenant_id)
api/sessions.py:176:        "active_sessions": len(sessions),
api/sessions.py:177:        "sessions": sessions
api/sessions.py:181:@sessions_router.get("/admin/active")
api/sessions.py:182:def list_platform_active_sessions(
api/sessions.py:187:    sessions = []
api/sessions.py:189:    for tenant_id in _discover_session_tenant_ids():
api/sessions.py:190:        sessions.extend(_list_sessions_for_tenant(tenant_id))
api/sessions.py:192:    sessions.sort(key=lambda s: s.get("issued_at") or 0, reverse=True)
api/sessions.py:195:        "active_sessions": len(sessions),
api/sessions.py:196:        "sessions": sessions
api/sessions.py:199:def _revoke_session_for_tenant(tenant_id: str, sid: str):
api/sessions.py:200:    key = tenant_session_key(tenant_id, sid)
api/sessions.py:201:    index_key = tenant_session_index_key(tenant_id)
api/sessions.py:206:            detail="session_not_found"
api/sessions.py:209:    session_data = r.hgetall(key) or {}
api/sessions.py:210:    principal = session_data.get("principal") or "unknown"
api/sessions.py:211:    intent = session_data.get("intent") or "session:revoke"
api/sessions.py:218:    r.incr("metric:sessions_revoked")
api/sessions.py:219:    r.decr("ztr:sessions:active")
api/sessions.py:221:    increment_tenant_usage(tenant_id, "sessions_revoked")
api/sessions.py:226:        event_type="runtime.session_revoked",
api/sessions.py:229:            "session_id": sid,
api/sessions.py:240:        "session_id": sid,
api/sessions.py:244:        "risk_score": 0,
api/sessions.py:245:        "policy_revision": "runtime-revoke",
api/sessions.py:247:            "source": "sessions",
api/sessions.py:255:        "session_id": sid,
api/sessions.py:260:@sessions_router.post("/revoke")
api/sessions.py:261:async def revoke_session(
api/sessions.py:265:    sid = body.get("session_id")
api/sessions.py:270:            detail="session_id required"
api/sessions.py:273:    return _revoke_session_for_tenant(tenant_id, sid)
api/sessions.py:276:@sessions_router.post("/admin/revoke")
api/sessions.py:277:async def revoke_platform_session(
api/sessions.py:284:    sid = body.get("session_id")
api/sessions.py:295:            detail="session_id required"
api/sessions.py:298:    return _revoke_session_for_tenant(tenant_id, sid)
api/alerts.py:10:from audit_chain import emit_event, get_latest_event
api/alerts.py:73:    risk_score = int(payload.get("risk_score") or 0)
api/alerts.py:75:    if risk_score <= 30:
api/alerts.py:77:    elif risk_score <= 60:
api/alerts.py:79:    elif risk_score <= 90:
api/alerts.py:88:        "risk_score": risk_score,
api/alerts.py:90:        "policy_revision": payload.get("policy_revision") or "--",
api/alerts.py:207:            "risk_score": None,
api/alerts.py:209:            "policy_revision": None,
api/metrics.py:18:@router.get("/v1/audit/metrics")
api/metrics.py:22:    allowed = int(redis_client.get("metrics:policy_allowed") or 0)
api/metrics.py:23:    denied = int(redis_client.get("metrics:policy_denied") or 0)
api/metrics.py:24:    revoked = int(redis_client.get("metrics:sessions_revoked") or 0)
api/metrics.py:35:        "policy_allowed": allowed,
api/metrics.py:36:        "policy_denied": denied,
api/metrics.py:37:        "sessions_revoked": revoked,
api/control_plane_drift.py:6:from audit_chain import list_index, get_entry
api/control_plane_drift.py:12:def map_drift_to_policy(drift_event):
api/control_plane_drift.py:39:def write_policy_override(tenant_id, principal, override):
api/control_plane_drift.py:40:    key = f"ztr:{tenant_id}:policy_override:{principal}"
api/control_plane_drift.py:50:        "event": "policy_override_written",
api/control_plane_drift.py:79:        override = map_drift_to_policy(payload)
api/control_plane_drift.py:84:        write_policy_override(tenant_id, principal, override)
api/control_plane.py:8:from audit_chain import emit_event
api/control_plane.py:9:from api.redis_keys import tenant_session_key, tenant_session_index_key
api/control_plane.py:31:@router.post("/policy/publish")
api/control_plane.py:32:async def publish_policy_update(
api/control_plane.py:39:    policy_text = payload.get("bundle")
api/control_plane.py:40:    version = payload.get("policy_revision")
api/control_plane.py:44:    if not tenant_id or not policy_text or not version:
api/control_plane.py:50:    policy_revision = version
api/control_plane.py:52:    policy_key = f"ztr:tenant:{tenant_id}:policy"
api/control_plane.py:54:    policy_digest = hashlib.sha256(
api/control_plane.py:55:        policy_text.encode()
api/control_plane.py:59:    global_policy_key = f"ztr:policy:global:{policy_digest}"
api/control_plane.py:61:    if not r.exists(global_policy_key):
api/control_plane.py:62:        r.hset(global_policy_key, mapping={
api/control_plane.py:63:            "digest": policy_digest,
api/control_plane.py:68:    r.set(f"ztr:policy:version:{version}", policy_digest)
api/control_plane.py:70:    r.hset(policy_key, mapping={
api/control_plane.py:71:        "version": policy_revision,
api/control_plane.py:72:        "digest": policy_digest
api/control_plane.py:75:    print("🔥 REDIS WRITE EXECUTED", policy_key)
api/control_plane.py:77:    result = update_policy_and_revoke(
api/control_plane.py:79:        policy_text,
api/control_plane.py:85:    event_id = f"{tenant_id}:{policy_revision}:{policy_digest[:16]}:{timestamp}"
api/control_plane.py:88:        f"ztr:tenant:{tenant_id}:propagation",
api/control_plane.py:97:        "policy_version": version,
api/control_plane.py:98:        "policy_digest": policy_digest,
api/control_plane.py:103:    r.publish("policy_updates", json.dumps(message))
api/control_plane.py:108:        event_type="control_plane.policy_published",
api/control_plane.py:111:            "policy_version": version,
api/control_plane.py:112:            "policy_digest": policy_digest,
api/control_plane.py:120:        "policy": result["policy"],
api/control_plane.py:125:def update_policy(tenant_id: str, policy_text: str, version: str):
api/control_plane.py:126:    digest = hashlib.sha256(policy_text.encode()).hexdigest()
api/control_plane.py:130:    r.hset(f"ztr:tenant:{tenant_id}:policy", mapping={
api/control_plane.py:135:    r.set(f"ztr:tenant:{tenant_id}:policy_anchor", digest)
api/control_plane.py:142:            "policy_version": version,
api/control_plane.py:143:            "policy_digest": digest,
api/control_plane.py:148:        "status": "policy_updated",
api/control_plane.py:154:def revoke_all_sessions(tenant_id: str):
api/control_plane.py:155:    session_index = tenant_session_index_key(tenant_id)
api/control_plane.py:156:    sids = r.smembers(session_index)
api/control_plane.py:161:        session_key = tenant_session_key(tenant_id, sid)
api/control_plane.py:164:        pipe.delete(session_key)
api/control_plane.py:165:        pipe.srem(session_index, sid)
api/control_plane.py:176:def update_policy_and_revoke(tenant_id: str, policy_text: str, version: str):
api/control_plane.py:177:    result = update_policy(tenant_id, policy_text, version)
api/control_plane.py:179:    revoke = revoke_all_sessions(tenant_id)
api/control_plane.py:182:        "policy": result,
api/control_plane.py:199:@router.get("/control-plane/policy")
api/control_plane.py:200:def get_control_plane_policy(
api/control_plane.py:205:    policy_key = f"ztr:tenant:{tenant_id}:policy"
api/control_plane.py:206:    anchor_key = f"ztr:tenant:{tenant_id}:policy_anchor"
api/control_plane.py:208:    policy_raw = r.hgetall(policy_key)
api/control_plane.py:209:    if not policy_raw:
api/control_plane.py:210:        raise HTTPException(status_code=404, detail=f"policy not found for tenant {tenant_id}")
api/control_plane.py:212:    policy = {
api/control_plane.py:214:        for k, v in policy_raw.items()
api/control_plane.py:217:    digest = policy.get("digest") or ""
api/control_plane.py:218:    version = policy.get("version") or "--"
api/control_plane.py:221:    integrity = "valid" if policy["digest"] == anchor else "mismatch"
api/control_plane.py:225:        "policy": {
api/control_plane.py:243:    pattern = "ztr:tenant:*:policy"
api/control_plane.py:251:        policy_raw = r.hgetall(key)
api/control_plane.py:252:        anchor_raw = r.get(f"ztr:tenant:{tenant_id}:policy_anchor")
api/control_plane.py:253:        propagation_raw = r.hgetall(f"ztr:tenant:{tenant_id}:propagation")
api/control_plane.py:255:        policy = {
api/control_plane.py:257:            for k, v in policy_raw.items()
api/control_plane.py:260:        propagation = {
api/control_plane.py:262:            for k, v in propagation_raw.items()
api/control_plane.py:265:        digest = policy.get("digest") or ""
api/control_plane.py:266:        version = policy.get("version") or "--"
api/control_plane.py:271:        last_updated = propagation.get("last_updated_timestamp")
api/control_plane.py:272:        last_event_id = propagation.get("last_event_id")
api/control_plane.py:274:        propagation_status = "SYNCED" if integrity == "valid" else "STALE"
api/control_plane.py:278:            "policy": {
api/control_plane.py:286:            "propagation_status": propagation_status
api/control_plane.py:302:def revoke_tenant_sessions(
api/control_plane.py:312:    session_index = tenant_session_index_key(tenant_id)
api/control_plane.py:313:    sids = r.smembers(session_index)
api/control_plane.py:318:        session_key = tenant_session_key(tenant_id, sid)
api/control_plane.py:321:        pipe.delete(session_key)
api/control_plane.py:322:        pipe.srem(session_index, sid)
api/control_plane.py:329:            "session_id": sid,
api/control_plane.py:331:            "intent": "session:revoke",
api/control_plane.py:333:            "risk_score": 0,
api/control_plane.py:334:            "policy_revision": "control-plane",
api/control_plane.py:345:        "revoked_sessions": count,
api/control_plane.py:365:    policy_key = f"ztr:tenant:{tenant_id}:policy"
api/control_plane.py:366:    anchor_key = f"ztr:tenant:{tenant_id}:policy_anchor"
api/control_plane.py:368:    policy_raw = r.hgetall(policy_key)
api/control_plane.py:369:    if not policy_raw:
api/control_plane.py:370:        raise HTTPException(status_code=404, detail="policy_not_found")
api/control_plane.py:372:    policy = {
api/control_plane.py:374:        for k, v in policy_raw.items()
api/control_plane.py:377:    version = policy.get("version")
api/control_plane.py:378:    digest = policy.get("digest")
api/control_plane.py:389:        f"ztr:tenant:{tenant_id}:propagation",
api/models.py:17:    session_id: str
api/copilot_bridge.py:18:            "risk_score",
api/copilot_bridge.py:22:            "policy_revision",
api/copilot_bridge.py:25:            "session_id",
api/copilot_bridge.py:41:    risk_score = source.get("risk_score")
api/copilot_bridge.py:42:    if risk_score is None:
api/copilot_bridge.py:45:            risk_score = risk_obj.get("final_score")
api/copilot_bridge.py:49:        "risk_score": risk_score,
api/copilot_bridge.py:53:        "policy_revision": source.get("policy_revision", "unknown"),
api/copilot_bridge.py:56:        "session_id": source.get("session_id"),
api/copilot_bridge.py:62:    policy_basis = result.get("policy_basis") if isinstance(result.get("policy_basis"), dict) else {}
api/copilot_bridge.py:64:    obligations = policy_basis.get("obligations", [])
api/copilot_bridge.py:65:    policy_revision = policy_basis.get("policy_revision", "unknown")
api/copilot_bridge.py:68:        policy_basis_text = f"{policy_revision} | obligations: {', '.join(obligations)}"
api/copilot_bridge.py:70:        policy_basis_text = policy_revision
api/copilot_bridge.py:75:        "risk_score": risk.get("score", 0),
api/copilot_bridge.py:76:        "policy_basis": policy_basis_text,
api/copilot_bridge.py:167:    audit_status = _safe_str(summary.get("audit_status"), "UNKNOWN").upper()
api/copilot_bridge.py:170:    policy_denied = _safe_num(metrics.get("policy_denied"), 0)
api/copilot_bridge.py:171:    sessions_revoked = _safe_num(metrics.get("sessions_revoked"), 0)
api/copilot_bridge.py:172:    active_sessions = _safe_num(metrics.get("active_sessions"), 0)
api/copilot_bridge.py:179:    if policy_denied > 0 and tenant_id != "unknown":
api/copilot_bridge.py:181:    elif sessions_revoked > 0 and tenant_id != "unknown":
api/copilot_bridge.py:182:        detection = f"Recent session control activity is elevated and is currently concentrated in {tenant_id}."
api/copilot_bridge.py:183:    elif active_sessions > 0:
api/copilot_bridge.py:184:        detection = "Runtime telemetry is active and current session activity remains within the normal operating range."
api/copilot_bridge.py:186:        detection = "No material session or policy pressure is currently visible in runtime telemetry."
api/copilot_bridge.py:188:    if platform_status == "HEALTHY" and audit_status == "VALID":
api/copilot_bridge.py:189:        decision = "Platform health is stable and audit integrity remains valid."
api/copilot_bridge.py:190:    elif audit_status != "VALID":
api/copilot_bridge.py:191:        decision = "Platform telemetry is present, but audit integrity requires review before relying on this control narrative."
api/copilot_bridge.py:200:    if audit_status != "VALID" or platform_status != "HEALTHY":
api/copilot_bridge.py:202:    elif policy_denied > 0 or sessions_revoked > 0:
api/copilot_bridge.py:226:        "audit_status": _safe_str(source.get("audit_status"), "UNKNOWN").upper(),
api/copilot_bridge.py:232:            "risk_score": _safe_num(
api/copilot_bridge.py:233:                highest.get("risk_score"),
api/copilot_bridge.py:234:                _safe_num(fallback_tenant.get("risk_score"), 0)
api/observability.py:14:from audit_chain import verify_chain
api/observability.py:83:    active_sessions = 0
api/observability.py:84:    for key in r.scan_iter("ztr:*:session:*"):
api/observability.py:86:            active_sessions += 1
api/observability.py:88:    policy_key = f"ztr:tenant:{tenant_id}:policy"
api/observability.py:89:    policy_data = r.hgetall(policy_key)
api/observability.py:90:    policy_revision = policy_data.get("version") if policy_data else "unknown"
api/observability.py:173:    if policy_revision == "unknown":
api/observability.py:174:        degraded.append("policy")
api/observability.py:192:    if policy_revision == "unknown":
api/observability.py:215:        "active_sessions": active_sessions,
api/observability.py:217:        "policy_revision": policy_revision,
api/observability.py:224:        "opa_status": "healthy",
api/observability.py:254:    pattern = f"ztr:{tenant_id}:audit:entry:*"
api/observability.py:270:                "risk_score": entry.get("payload", {}).get("risk_score"),
api/observability.py:271:                "policy_revision": entry.get("payload", {}).get("policy_revision"),
api/observability.py:287:    active_sessions = 0
api/observability.py:289:    for key in r.scan_iter("ztr:*:session:*"):
api/observability.py:291:            active_sessions += 1
api/observability.py:295:        "policy_allowed": read_counter("metric:policy_allowed"),
api/observability.py:296:        "policy_denied": read_counter("metric:policy_denied"),
api/observability.py:297:        "sessions_revoked": read_counter("metric:sessions_revoked"),
api/observability.py:298:        "active_sessions": active_sessions,
api/observability.py:300:        "opa_latency_ms": read_latency("metric:opa_latency_ms"),
api/observability.py:312:    denied = read_counter("metric:policy_denied")
api/observability.py:313:    revoked = read_counter("metric:sessions_revoked")
api/observability.py:316:    opa_latency = read_latency("metric:opa_latency_ms")
api/observability.py:323:# TYPE stc_policy_denied counter
api/observability.py:324:stc_policy_denied {denied}
api/observability.py:326:# TYPE stc_sessions_revoked counter
api/observability.py:327:stc_sessions_revoked {revoked}
api/observability.py:332:# TYPE stc_opa_latency_ms gauge
api/observability.py:333:stc_opa_latency_ms {opa_latency}
api/observability.py:349:            denied = int(usage.get("policy_denied") or 0)
api/observability.py:350:            revoked = int(usage.get("sessions_revoked") or 0)
api/observability.py:354:stc_policy_denied{{tenant="{tenant_id}"}} {denied}
api/observability.py:355:stc_sessions_revoked{{tenant="{tenant_id}"}} {revoked}
api/tokens.py:6:from opa_bridge import evaluate_issue_policy
api/tokens.py:9:    tenant_session_key,
api/tokens.py:10:    tenant_session_index_key,
api/tokens.py:15:from audit_chain import emit_event
api/tokens.py:18:from api.blast_simulator import simulate_blast_radius, compute_riskdna
api/tokens.py:21:from core.aegis_identity.service import evaluate_identity_integrity
api/tokens.py:112:    session_id = payload.get("sid")
api/tokens.py:122:    if not session_id:
api/tokens.py:127:    session_key = tenant_session_key(tenant_id, session_id)
api/tokens.py:128:    session_index = tenant_session_index_key(tenant_id)
api/tokens.py:130:    session_data = r.hgetall(session_key)
api/tokens.py:131:    ttl = r.ttl(session_key)
api/tokens.py:133:    if not session_data or ttl <= 0:
api/tokens.py:134:        r.srem(session_index, session_id)
api/tokens.py:141:            "session_id": session_id,
api/tokens.py:144:    scopes = _parse_json_list(session_data.get("scopes"))
api/tokens.py:145:    obligations = _parse_json_list(session_data.get("obligations"))
api/tokens.py:153:        "session_id": session_id,
api/tokens.py:154:        "principal": session_data.get("principal") or payload.get("sub"),
api/tokens.py:155:        "intent": session_data.get("intent") or payload.get("intent"),
api/tokens.py:157:        "policy_revision": session_data.get("policy_revision") or POLICY_REVISION,
api/tokens.py:159:        "decision": session_data.get("decision") or "allow",
api/tokens.py:161:        "issued_at": int(session_data.get("issued_at") or payload.get("iat") or 0),
api/tokens.py:221:        if context.get("risk_score", 0) > 50:
api/tokens.py:225:def apply_policy_override(tenant_id, principal, policy_input):
api/tokens.py:226:    key = f"ztr:{tenant_id}:policy_override:{principal}"
api/tokens.py:230:        return policy_input
api/tokens.py:236:        return policy_input
api/tokens.py:241:        policy_input["context"]["risk_score"] += override.get("risk_boost", 0)
api/tokens.py:244:        policy_input["ttl_seconds"] = min(policy_input["ttl_seconds"], override.get("ttl_override", 120))
api/tokens.py:247:        policy_input["context"]["force_deny"] = True
api/tokens.py:249:    return policy_input
api/tokens.py:256:    pattern = f"ztr:{tenant_id}:audit:entry:*"
api/tokens.py:277:                or reason == "policy_denied"
api/tokens.py:287:def has_policy_drift(tenant_id: str, principal: str) -> bool:
api/tokens.py:288:    key = f"ztr:{tenant_id}:policy_override:{principal}"
api/tokens.py:302:            "refund:create": ["payment_db", "audit_ledger"],
api/tokens.py:304:            "audit_ledger": [],
api/tokens.py:308:        nodes = simulate_blast_radius(req.principal, req.intent, graph)
api/tokens.py:311:        policy_drift = has_policy_drift(tenant_id, req.principal)
api/tokens.py:313:        riskdna = compute_riskdna(
api/tokens.py:319:            policy_drift=policy_drift
api/tokens.py:324:        identity_signal = evaluate_identity_integrity(
api/tokens.py:332:            policy_drift=policy_drift,
api/tokens.py:335:        context["aegis_identity"] = identity_signal
api/tokens.py:336:        context["risk_score"] = riskdna["final_score"] + int(
api/tokens.py:340:        policy_input = {
api/tokens.py:347:            "policy_revision": POLICY_REVISION,
api/tokens.py:350:        policy_input = apply_policy_override(tenant_id, req.principal, policy_input)
api/tokens.py:352:        opa_result = evaluate_issue_policy(policy_input)
api/tokens.py:354:        # ✅ REQUIRED DEBUG (OPA VISIBILITY)
api/tokens.py:355:        print("OPA RESULT:", opa_result)
api/tokens.py:356:        print("POLICY INPUT:", policy_input)
api/tokens.py:358:        if not opa_result.get("allow"):
api/tokens.py:364:                "session_id": None,
api/tokens.py:368:                "risk_score": context["risk_score"],
api/tokens.py:369:                "policy_revision": POLICY_REVISION,
api/tokens.py:382:            r.incr("metric:policy_denied")
api/tokens.py:383:            increment_tenant_usage(tenant_id, "policy_denied")
api/tokens.py:394:                    "risk_score": context["risk_score"],
api/tokens.py:395:                    "policy_revision": POLICY_REVISION,
api/tokens.py:398:                    "reason": "policy_denied",
api/tokens.py:403:            raise HTTPException(status_code=403, detail="policy_denied")
api/tokens.py:406:            enforce_obligations(opa_result, policy_input)
api/tokens.py:408:            r.incr("metric:policy_denied")
api/tokens.py:409:            increment_tenant_usage(tenant_id, "policy_denied")
api/tokens.py:415:                "session_id": None,
api/tokens.py:419:                "risk_score": context["risk_score"],
api/tokens.py:420:                "policy_revision": POLICY_REVISION,
api/tokens.py:443:                    "risk_score": context["risk_score"],
api/tokens.py:444:                    "policy_revision": POLICY_REVISION,
api/tokens.py:454:        effective_ttl = opa_result.get("ttl_seconds") or req.ttl_seconds
api/tokens.py:455:        obligations = opa_result.get("obligations", [])
api/tokens.py:461:        session_key = tenant_session_key(tenant_id, sid)
api/tokens.py:462:        session_index = tenant_session_index_key(tenant_id)
api/tokens.py:464:        session_record = {
api/tokens.py:476:                "final_score": context["risk_score"],
api/tokens.py:478:            "policy_revision": POLICY_REVISION,
api/tokens.py:484:        pipe.hset(session_key, mapping=session_record)
api/tokens.py:485:        pipe.expire(session_key, effective_ttl)
api/tokens.py:486:        pipe.sadd(session_index, sid)
api/tokens.py:514:            "session_id": sid,
api/tokens.py:518:            "risk_score": context["risk_score"],
api/tokens.py:519:            "policy_revision": POLICY_REVISION,
api/tokens.py:535:        r.incr("metric:policy_allowed")
api/tokens.py:545:                "session_id": sid,
api/tokens.py:547:                "risk_score": context["risk_score"],
api/tokens.py:548:                "policy_revision": POLICY_REVISION,
api/tokens.py:558:            "session_id": sid,
api/policy_registry.py:1:# FILE: api/policy_registry.py
api/policy_registry.py:11:router = APIRouter(prefix="/v1/admin", tags=["policy-registry"])
api/policy_registry.py:21:def global_policy_key(digest: str) -> str:
api/policy_registry.py:22:    return f"ztr:policy:global:{digest}"
api/policy_registry.py:25:def policy_version_index(version: str) -> str:
api/policy_registry.py:26:    return f"ztr:policy:version:{version}"
api/policy_registry.py:29:@router.post("/policy/register")
api/policy_registry.py:30:def register_policy(payload: dict):
api/policy_registry.py:32:    policy_text = payload.get("bundle")
api/policy_registry.py:33:    version = payload.get("policy_revision")
api/policy_registry.py:35:    if not policy_text or not version:
api/policy_registry.py:38:    digest = hashlib.sha256(policy_text.encode()).hexdigest()
api/policy_registry.py:40:    key = global_policy_key(digest)
api/policy_registry.py:57:    r.set(policy_version_index(version), digest)
api/policy_registry.py:66:@router.get("/policy/global")
api/policy_registry.py:69:    pattern = "ztr:policy:global:*"
api/explainer.py:41:    risk_score = _num(ddr.get("risk_score"))
api/explainer.py:42:    policy_revision = _str(ddr.get("policy_revision"), "unknown")
api/explainer.py:50:    if risk_score is not None:
api/explainer.py:51:        explanation_parts.append(f"Risk score evaluated at {risk_score}.")
api/explainer.py:58:        explanation_parts.append("No policy obligations required.")
api/explainer.py:65:            "score": risk_score,
api/explainer.py:66:            "tier": _risk_tier(risk_score)
api/explainer.py:68:        "policy_basis": {
api/explainer.py:70:            "policy_revision": policy_revision
api/explainer.py:84:    risk_score = _num(ddr.get("risk_score"))
api/explainer.py:85:    policy_revision = _str(ddr.get("policy_revision"), "unknown")
api/explainer.py:93:    if risk_score is not None:
api/explainer.py:94:        explanation_parts.append(f"Risk score evaluated at {risk_score}.")
api/explainer.py:101:        explanation_parts.append("No explicit policy obligations provided.")
api/explainer.py:108:            "score": risk_score,
api/explainer.py:109:            "tier": _risk_tier(risk_score)
api/explainer.py:111:        "policy_basis": {
api/explainer.py:113:            "policy_revision": policy_revision
api/explainer.py:115:        "operator_action": "Review policy conditions and risk signals.",
api/explainer.py:129:            "score": _num(ddr.get("risk_score")),
api/explainer.py:132:        "policy_basis": {
api/explainer.py:134:            "policy_revision": _str(ddr.get("policy_revision"), "unknown")
api/explainer.py:147:        "session_id": _str(ddr.get("session_id"), "unknown"),
api/explainer.py:150:        "policy_revision": _str(ddr.get("policy_revision"), "unknown"),
api/copilot_aegis.py:26:    policy = risk.get("policy_risk", 0)
api/copilot_aegis.py:48:    if policy > 0:
api/copilot_aegis.py:81:    if risk.get("policy_risk", 0) > 0:
api/blast_simulator.py:9:Used by: api/tokens.py before OPA policy evaluation
api/blast_simulator.py:19:def simulate_blast_radius(principal: str, intent: str, graph: Dict[str, List[str]]) -> Set[str]:
api/blast_simulator.py:57:def compute_riskdna(
api/blast_simulator.py:63:    policy_drift: bool
api/blast_simulator.py:68:        "audit_ledger",
api/blast_simulator.py:98:    policy_risk = 15 if policy_drift else 0
api/blast_simulator.py:103:    submitted_risk_score = context.get("risk_score", 0)
api/blast_simulator.py:106:        submitted_risk_score = int(float(submitted_risk_score))
api/blast_simulator.py:108:        submitted_risk_score = 0
api/blast_simulator.py:110:    if submitted_risk_score < 0:
api/blast_simulator.py:111:        submitted_risk_score = 0
api/blast_simulator.py:113:    input_risk = min(submitted_risk_score, 30)
api/blast_simulator.py:135:    session_binding = context.get("session_binding")
api/blast_simulator.py:136:    if session_binding is False or session_binding in ("", None):
api/blast_simulator.py:146:        policy_risk +
api/blast_simulator.py:166:        "policy_risk": policy_risk,
api/blast_simulator.py:169:        "submitted_risk_score": submitted_risk_score,
api/intelligence.py:41:            risk = int(data.get("risk_score") or 0)
api/intelligence.py:142:    policy_drift = False
api/intelligence.py:148:        for key in r.scan_iter("ztr:tenant:*:policy"):
api/intelligence.py:150:            policy = r.hgetall(key)
api/intelligence.py:152:            if not policy:
api/intelligence.py:155:            rev = policy.get("version")
api/intelligence.py:161:            policy_drift = True
api/intelligence.py:164:        policy_drift = False
api/intelligence.py:183:        "policy_drift": policy_drift,
api/policy.py:6:@router.get("/v1/policy/bundle")
api/policy.py:7:def get_policy_bundle():
api/control_plane_registry.py:43:        "policy_version": "unassigned",
api/control_plane_registry.py:44:        "policy_digest": "",
api/server.py:25:from audit_chain import emit_event, verify_chain, list_index, get_entry, SCHEMA_VERSION
api/server.py:26:from policy_subscriber import start_subscriber
api/server.py:27:from policy_listener import start_listener_thread
api/server.py:30:from api.audit import router as audit_router
api/server.py:33:from api.sessions import sessions_router
api/server.py:35:from api.policy import router as policy_router
api/server.py:41:from api.policy_registry import router as policy_registry_router
api/server.py:75:app.include_router(audit_router)
api/server.py:78:app.include_router(sessions_router)
api/server.py:80:app.include_router(policy_router)
api/server.py:86:app.include_router(policy_registry_router)
api/server.py:117:def _discover_audit_tenant_ids():
api/server.py:141:        # 🔒 OPA HEALTH CHECK
api/server.py:142:        opa = requests.get("http://127.0.0.1:8181/health", timeout=1)
api/server.py:143:        if opa.status_code != 200:
api/server.py:144:            raise Exception("OPA unhealthy")
api/server.py:153:        start_audit = time.time()
api/server.py:155:        audit_latency = int((time.time() - start_audit) * 1000)
api/server.py:156:        r.set("metric:audit_latency_ms", audit_latency)
api/server.py:161:        session_count = int(r.get("ztr:sessions:active") or 0)
api/server.py:165:            "opa": "healthy",
api/server.py:167:            "audit_chain": "valid",
api/server.py:168:            "active_sessions": session_count,
api/server.py:169:            "policy_rev": POLICY_REVISION,
api/server.py:179:@app.get("/v1/audit/verify")
api/server.py:180:def audit_verify(
api/server.py:189:            detail="audit_verification_failed"
api/server.py:193:@app.get("/v1/audit/events")
api/server.py:194:def audit_events(tenant_id: str = Depends(require_tenant_api_key)):
api/server.py:237:@app.get("/v1/audit/admin/events")
api/server.py:238:def audit_admin_events(
api/server.py:248:        for tenant_id in _discover_audit_tenant_ids():
api/streaming.py:38:            "risk_score": event.get("risk_score") if event.get("risk_score") is not None else 0,
api/streaming.py:39:            "policy_revision": event.get("policy_revision") or "unknown",
api/streaming.py:73:        risk_score = payload.get("risk_score") if payload.get("risk_score") is not None else 0
api/streaming.py:84:                "risk_score": risk_score,
api/streaming.py:85:                "policy_revision": payload.get("policy_revision")
api/streaming.py:108:                "risk_score": payload.get("risk_score") if payload.get("risk_score") is not None else 0,
api/streaming.py:109:                "policy_revision": payload.get("policy_revision"),
api/streaming.py:133:                    "risk_delta": payload.get("risk_score") if payload.get("risk_score") is not None else 0,
api/audit.py:3:# Exposes deterministic audit chain (read-only)
api/audit.py:7:#   - Provide query access to audit chain
api/audit.py:11:# ZERO MODIFICATION to audit_chain.py
api/audit.py:20:from audit_chain import (
api/audit.py:31:# GET /v1/audit/events
api/audit.py:33:@router.get("/audit/events")
api/audit.py:34:def get_audit_events(
api/audit.py:40:    Returns full audit events (NOT just hashes)
api/audit.py:66:# GET /v1/audit/verify
api/audit.py:68:@router.get("/audit/verify")
api/audit.py:69:def verify_audit_chain(
api/audit.py:87:# GET /v1/audit/latest
api/audit.py:89:@router.get("/audit/latest")
api/audit.py:90:def get_latest_audit_event(
api/audit.py:111:# GET /v1/audit/metrics (LIGHTWEIGHT SUMMARY)
api/audit.py:113:@router.get("/audit/metrics")
api/audit.py:114:def get_audit_metrics(
api/audit.py:118:    Lightweight audit summary for dashboards
api/redis_keys.py:26:def tenant_session_key(tenant_id: str, sid: str) -> str:
api/redis_keys.py:27:    return tenant_key(tenant_id, "session", sid)
api/redis_keys.py:30:def tenant_session_index_key(tenant_id: str) -> str:
api/redis_keys.py:31:    return tenant_key(tenant_id, "session_index")
api/redis_keys.py:49:def session_index_key(tenant_id: str) -> str:
api/redis_keys.py:50:    return tenant_session_index_key(tenant_id)
api/redis_keys.py:53:def session_key(tenant_id: str, sid: str) -> str:
api/redis_keys.py:54:    return tenant_session_key(tenant_id, sid)
core/aegis_identity/__init__.py:5:issuance, and no session creation side effects.
core/aegis_identity/__init__.py:8:from core.aegis_identity.features import build_identity_features
core/aegis_identity/__init__.py:9:from core.aegis_identity.scoring import score_identity_features
core/aegis_identity/__init__.py:10:from core.aegis_identity.service import (
core/aegis_identity/__init__.py:13:    evaluate_identity_integrity,
core/aegis_identity/__init__.py:15:from core.aegis_identity.schemas import (
core/aegis_identity/__init__.py:34:    "evaluate_identity_integrity",
core/aegis_identity/schemas.py:34:    create runtime sessions, or override local policy authority.
core/aegis_identity/schemas.py:59:    runtime and local policy layer before execution.
core/aegis_identity/schemas.py:69:    policy_drift: bool = False
core/aegis_identity/schemas.py:70:    source: Literal["aegis_identity"] = "aegis_identity"
core/aegis_identity/schemas.py:93:    risk_score: Optional[int] = Field(default=None, ge=0, le=100)
core/aegis_identity/schemas.py:95:    policy_drift: bool = False
core/aegis_identity/schemas.py:125:    session_created: Literal[False] = False
core/aegis_identity/scoring.py:5:from core.aegis_identity.schemas import (
core/aegis_identity/scoring.py:54:    if features.recent_denials > 0 or features.policy_drift or features.risk_score:
core/aegis_identity/scoring.py:63:    This score is evidence only. It does not authorize access, create a session,
core/aegis_identity/scoring.py:64:    issue a token, or bypass local OPA/runtime governance.
core/aegis_identity/scoring.py:70:    if features.risk_score is not None:
core/aegis_identity/scoring.py:71:        risk_contribution = min(features.risk_score // 2, 40)
core/aegis_identity/scoring.py:73:        reasons.append(f"risk_score:{features.risk_score}")
core/aegis_identity/scoring.py:80:    if features.policy_drift:
core/aegis_identity/scoring.py:82:        reasons.append("policy_drift:true")
core/aegis_identity/scoring.py:117:            "risk_score": features.risk_score,
core/aegis_identity/scoring.py:119:            "policy_drift": features.policy_drift,
core/aegis_identity/features.py:5:from core.aegis_identity.schemas import (
core/aegis_identity/features.py:34:def _coerce_risk_score(value: Any) -> Optional[int]:
core/aegis_identity/features.py:51:def _extract_risk_score(context: Dict[str, Any]) -> Optional[int]:
core/aegis_identity/features.py:52:    direct_score = _coerce_risk_score(context.get("risk_score"))
core/aegis_identity/features.py:58:        riskdna_score = _coerce_risk_score(riskdna.get("risk_score"))
core/aegis_identity/features.py:62:        return _coerce_risk_score(riskdna.get("final_score"))
core/aegis_identity/features.py:116:        risk_score=_extract_risk_score(request.context),
core/aegis_identity/features.py:118:        policy_drift=request.policy_drift,
core/aegis_identity/service.py:5:from core.aegis_identity.features import build_identity_features
core/aegis_identity/service.py:6:from core.aegis_identity.scoring import score_identity_features
core/aegis_identity/service.py:7:from core.aegis_identity.schemas import (
core/aegis_identity/service.py:17:    tokens, create sessions, mutate trust registries, or grant authorization.
core/aegis_identity/service.py:44:def evaluate_identity_integrity(
core/aegis_identity/service.py:53:    policy_drift: bool = False,
core/aegis_identity/service.py:55:    """Return a bounded Aegis Identity signal for runtime policy input.
core/aegis_identity/service.py:58:    issue tokens, create sessions, mutate runtime truth, or override OPA.
core/aegis_identity/service.py:68:        policy_drift=bool(policy_drift),
core/aegis_identity/service.py:78:        "decision_authority": "OPA",
policies/issue.rego:37:	adjusted := input.context.risk_score + input.context.aegis.risk_delta
policies/issue.rego:38:} else := input.context.risk_score
policies/issue.rego:49:aegis_identity_present if {
policies/issue.rego:50:	input.context.aegis_identity
policies/issue.rego:54:	aegis_identity_present
policies/issue.rego:55:	input.context.aegis_identity.signal == "IDENTITY_DRIFT_DETECTED"
policies/issue.rego:59:	aegis_identity_present
policies/issue.rego:60:	input.context.aegis_identity.risk_modifier >= 20
policies/issue.rego:96:valid_policy_revision if {
policies/issue.rego:97:	input.policy_revision != ""
policies/issue.rego:101:	input.context.session_binding != ""
policies/issue.rego:109:	input.context.risk_score >= 80
policies/issue.rego:114:	input.context.risk_score >= 60
policies/issue.rego:122:	input.context.risk_score >= 30
policies/issue.rego:123:	input.context.risk_score < 60
policies/issue.rego:127:	input.context.risk_score >= 60
policies/issue.rego:143:	valid_policy_revision
policies/issue.rego:184:	"policy_revision": input.policy_revision,
policies/issue_identity_test.rego:4:# AEGIS IDENTITY INTEGRITY — OPA POLICY TESTS
policies/issue_identity_test.rego:7:# These tests validate real OPA policy behavior for issue.rego.
policies/issue_identity_test.rego:8:# They do not replace OPA and do not bypass OPA.
policies/issue_identity_test.rego:11:# OPA remains final decision authority.
policies/issue_identity_test.rego:21:		"policy_revision": "test-policy",
policies/issue_identity_test.rego:24:			"session_binding": "device-aegis-test",
policies/issue_identity_test.rego:25:			"risk_score": 10,
policies/issue_identity_test.rego:27:			"aegis_identity": {
policies/issue_identity_test.rego:32:				"decision_authority": "OPA",
policies/issue_identity_test.rego:40:	result.policy_revision == "test-policy"
policies/issue_identity_test.rego:50:		"policy_revision": "test-policy",
policies/issue_identity_test.rego:53:			"session_binding": "device-aegis-test",
policies/issue_identity_test.rego:54:			"risk_score": 10,
policies/issue_identity_test.rego:56:			"aegis_identity": {
policies/issue_identity_test.rego:61:				"decision_authority": "OPA",
policies/issue_identity_test.rego:78:		"policy_revision": "test-policy",
policies/issue_identity_test.rego:81:			"session_binding": "device-aegis-test",
policies/issue_identity_test.rego:82:			"risk_score": 10,
policies/issue_identity_test.rego:84:			"aegis_identity": {
policies/issue_identity_test.rego:89:				"decision_authority": "OPA",
policies/issue_identity_test.rego:105:		"policy_revision": "test-policy",
policies/issue_identity_test.rego:108:			"session_binding": "device-aegis-test",
policies/issue_identity_test.rego:109:			"risk_score": 10,
policies/issue_identity_test.rego:111:			"aegis_identity": {
policies/issue_identity_test.rego:116:				"decision_authority": "OPA",
policies/issue_identity_test.rego:125:test_missing_aegis_identity_context_preserves_existing_allow_path if {
policies/issue_identity_test.rego:132:		"policy_revision": "test-policy",
policies/issue_identity_test.rego:135:			"session_binding": "device-aegis-test",
policies/issue_identity_test.rego:136:			"risk_score": 10,
policies/issue_identity_test.rego:151:		"policy_revision": "test-policy",
policies/issue_identity_test.rego:154:			"session_binding": "device-aegis-test",
policies/issue_identity_test.rego:155:			"risk_score": 10,
policies/issue_identity_test.rego:162:			"aegis_identity": {
policies/issue_identity_test.rego:167:				"decision_authority": "OPA",
policies/issue_identity_test.rego:184:		"policy_revision": "test-policy",
policies/issue_identity_test.rego:187:			"session_binding": "device-aegis-test",
policies/issue_identity_test.rego:188:			"risk_score": 10,
policies/issue_identity_test.rego:190:			"aegis_identity": {
policies/issue_identity_test.rego:195:				"decision_authority": "OPA",
policies/issue_identity_test.rego:209:		"policy_revision": "test-policy",
policies/issue_identity_test.rego:212:			"session_binding": "device-aegis-test",
policies/issue_identity_test.rego:213:			"risk_score": 10,
policies/issue_identity_test.rego:215:			"aegis_identity": {
policies/issue_identity_test.rego:220:				"decision_authority": "OPA",
policies/ztr_introspect.rego:9:    valid_policy_revision
policies/ztr_introspect.rego:25:valid_policy_revision if {
policies/ztr_introspect.rego:26:    input.policy_revision == current_policy_revision
policies/ztr_introspect.rego:29:current_policy_revision := "dev-1"
policy-bundle/policies/issue.rego:37:    adjusted := input.context.risk_score + input.context.aegis.risk_delta
policy-bundle/policies/issue.rego:38:} else := input.context.risk_score
policy-bundle/policies/issue.rego:49:aegis_identity_present if {
policy-bundle/policies/issue.rego:50:    input.context.aegis_identity
policy-bundle/policies/issue.rego:54:    aegis_identity_present
policy-bundle/policies/issue.rego:55:    input.context.aegis_identity.signal == "IDENTITY_DRIFT_DETECTED"
policy-bundle/policies/issue.rego:59:    aegis_identity_present
policy-bundle/policies/issue.rego:60:    input.context.aegis_identity.risk_modifier >= 20
policy-bundle/policies/issue.rego:96:valid_policy_revision if {
policy-bundle/policies/issue.rego:97:    input.policy_revision != ""
policy-bundle/policies/issue.rego:101:    input.context.session_binding != ""
policy-bundle/policies/issue.rego:109:    input.context.risk_score >= 80
policy-bundle/policies/issue.rego:114:    input.context.risk_score >= 60
policy-bundle/policies/issue.rego:122:    input.context.risk_score >= 30
policy-bundle/policies/issue.rego:123:    input.context.risk_score < 60
policy-bundle/policies/issue.rego:127:    input.context.risk_score >= 60
policy-bundle/policies/issue.rego:143:    valid_policy_revision
policy-bundle/policies/issue.rego:186:    "policy_revision": input.policy_revision
tests/test_policy_governance_chain.py:13:def test_policy_anchor_exists_for_tenant():
tests/test_policy_governance_chain.py:17:    anchor_key = f"ztr:tenant:{tenant_id}:policy_anchor"
tests/test_policy_governance_chain.py:28:    mgmt_keys = list(r.scan_iter("audit:mgmt:*"))
tests/test_policy_governance_chain.py:44:    assert "opa_status" in data
tests/test_policy_governance_chain.py:47:def test_policy_drift_detection():
tests/test_policy_governance_chain.py:55:    assert "policy_drift" in data
tests/test_policy_governance_chain.py:60:    keys = list(r.scan_iter("ztr:tenant:*:policy"))
tests/test_token_revocation.py:45:    sid = issue["session_id"]
tests/test_token_revocation.py:48:        "/v1/sessions/revoke",
tests/test_token_revocation.py:49:        json={"session_id": sid}
tests/test_token_revocation.py:69:    sid = issue["session_id"]
tests/test_token_revocation.py:71:    client.post("/v1/sessions/revoke", json={"session_id": sid})
tests/test_integrity.py:17:    assert "opa_status" in data
tests/test_intelligence.py:16:    for key in r.scan_iter("ztr:tenant:*:policy"):
tests/test_intelligence.py:42:        "risk_score": "10",
tests/test_intelligence.py:65:            "risk_score": "5",
tests/test_intelligence.py:88:            "risk_score": "2",
tests/test_intelligence.py:100:def test_policy_drift_detection():
tests/test_intelligence.py:104:    r.hset("ztr:tenant:a:policy", mapping={"version": "v1"})
tests/test_intelligence.py:105:    r.hset("ztr:tenant:b:policy", mapping={"version": "v2"})
tests/test_intelligence.py:110:    assert data["policy_drift"] is True
tests/test_decision_pipeline.py:29:            "risk_score": risk,
tests/test_decision_pipeline.py:30:            "policy_revision": "test-v1"
tests/test_sessions.py:11:def test_session_created():
tests/test_sessions.py:27:    sid = data["session_id"]
tests/test_sessions.py:29:    key = f"ztr:tenant:tenant-test:session:{sid}"
tests/test_sessions.py:34:def test_session_revocation():
tests/test_sessions.py:48:    sid = issue["session_id"]
tests/test_sessions.py:50:    revoke = client.post("/v1/sessions/revoke", json={"session_id": sid})
tests/test_sessions.py:55:def test_session_index_exists():
tests/test_sessions.py:57:    keys = list(r.scan_iter("ztr:tenant:*:session:*"))
tests/test_aegis_identity.py:3:from core.aegis_identity.features import build_identity_features
tests/test_aegis_identity.py:4:from core.aegis_identity.scoring import score_identity_features
tests/test_aegis_identity.py:5:from core.aegis_identity.service import assess_identity, evaluate_identity_integrity
tests/test_aegis_identity.py:6:from core.aegis_identity.schemas import (
tests/test_aegis_identity.py:12:def _policy_denies_identity_integrity(signal: dict) -> bool:
tests/test_aegis_identity.py:13:    """Mirror the bounded OPA deny_identity_integrity rule.
tests/test_aegis_identity.py:15:    This does not replace OPA. It validates that the runtime signal shape
tests/test_aegis_identity.py:46:            "session_binding": "device-aegis-test",
tests/test_aegis_identity.py:47:            "risk_score": 10,
tests/test_aegis_identity.py:60:    assert assessment.session_created is False
tests/test_aegis_identity.py:88:            "risk_score": 10,
tests/test_aegis_identity.py:101:def test_policy_drift_adds_bounded_risk_evidence() -> None:
tests/test_aegis_identity.py:107:        policy_drift=True,
tests/test_aegis_identity.py:109:            "risk_score": 10,
tests/test_aegis_identity.py:115:    assert assessment.features.policy_drift is True
tests/test_aegis_identity.py:116:    assert "policy_drift:true" in assessment.score.reasons
tests/test_aegis_identity.py:129:            "risk_score": 10,
tests/test_aegis_identity.py:142:    signal = evaluate_identity_integrity(
tests/test_aegis_identity.py:149:            "risk_score": 80,
tests/test_aegis_identity.py:151:            "session_binding": "device-aegis-test",
tests/test_aegis_identity.py:154:        policy_drift=False,
tests/test_aegis_identity.py:159:    assert signal["decision_authority"] == "OPA"
tests/test_aegis_identity.py:171:        policy_drift=True,
tests/test_aegis_identity.py:199:            "risk_score": 100,
tests/test_aegis_identity.py:218:        policy_drift=True,
tests/test_aegis_identity.py:220:            "risk_score": 20,
tests/test_aegis_identity.py:230:def test_identity_signal_matches_issue_policy_deny_shape() -> None:
tests/test_aegis_identity.py:231:    signal = evaluate_identity_integrity(
tests/test_aegis_identity.py:238:            "risk_score": 80,
tests/test_aegis_identity.py:240:            "session_binding": "device-aegis-test",
tests/test_aegis_identity.py:243:        policy_drift=True,
tests/test_aegis_identity.py:248:    assert _policy_denies_identity_integrity(signal) is True
tests/test_aegis_identity.py:251:def test_opa_does_not_deny_stable_identity_signal() -> None:
tests/test_aegis_identity.py:252:    signal = evaluate_identity_integrity(
tests/test_aegis_identity.py:259:            "risk_score": 10,
tests/test_aegis_identity.py:261:            "session_binding": "device-aegis-test",
tests/test_aegis_identity.py:264:        policy_drift=False,
tests/test_aegis_identity.py:268:    assert _policy_denies_identity_integrity(signal) is False
tests/test_aegis_identity.py:271:def test_passrole_lab_maps_to_aegis_identity_drift_signal() -> None:
tests/test_aegis_identity.py:272:    signal = evaluate_identity_integrity(
tests/test_aegis_identity.py:279:            "risk_score": 80,
tests/test_aegis_identity.py:281:            "session_binding": "passrole-lab-session",
tests/test_aegis_identity.py:286:        policy_drift=False,
tests/test_aegis_identity.py:291:    assert signal["decision_authority"] == "OPA"
tests/test_aegis_identity.py:293:    assert "risk_score:80" in signal["reasons"]
tests/test_aegis_identity.py:301:    assert "session" not in signal
tests/test_aegis_identity.py:304:def test_cross_account_lab_maps_to_aegis_identity_drift_signal() -> None:
tests/test_aegis_identity.py:305:    signal = evaluate_identity_integrity(
tests/test_aegis_identity.py:312:            "risk_score": 80,
tests/test_aegis_identity.py:314:            "session_binding": "cross-account-lab-session",
tests/test_aegis_identity.py:319:        policy_drift=False,
tests/test_aegis_identity.py:324:    assert signal["decision_authority"] == "OPA"
tests/test_aegis_identity.py:326:    assert "risk_score:80" in signal["reasons"]
tests/test_aegis_identity.py:334:    assert "session" not in signal
tests/test_aegis_identity.py:337:def test_role_chaining_lab_maps_to_aegis_identity_drift_signal() -> None:
tests/test_aegis_identity.py:338:    signal = evaluate_identity_integrity(
tests/test_aegis_identity.py:345:            "risk_score": 80,
tests/test_aegis_identity.py:347:            "session_binding": "rolechain-lab-session",
tests/test_aegis_identity.py:352:        policy_drift=False,
tests/test_aegis_identity.py:357:    assert signal["decision_authority"] == "OPA"
tests/test_aegis_identity.py:359:    assert "risk_score:80" in signal["reasons"]
tests/test_aegis_identity.py:367:    assert "session" not in signal
tests/conftest.py:17:TEST_POLICY_REVISION = "test-policy-rev"
tests/conftest.py:35:def test_evaluate_issue_policy_override(policy_input=None, **kwargs):
tests/conftest.py:36:    payload = policy_input if isinstance(policy_input, dict) else kwargs
tests/conftest.py:41:        "reason": "test_policy_allow",
tests/conftest.py:42:        "policy_revision": TEST_POLICY_REVISION,
tests/conftest.py:44:        "risk_score": payload.get("context", {}).get("risk_score", 0),
tests/conftest.py:54:        f"ztr:tenant:{TEST_TENANT_ID}:policy",
tests/conftest.py:58:            "policy": TEST_POLICY_TEXT,
tests/conftest.py:61:    r.set(f"ztr:tenant:{TEST_TENANT_ID}:policy_anchor", TEST_POLICY_DIGEST)
tests/conftest.py:65:        "evaluate_issue_policy",
tests/conftest.py:66:        test_evaluate_issue_policy_override,
tests/test_streaming_pipeline.py:33:            "risk_score": 1
