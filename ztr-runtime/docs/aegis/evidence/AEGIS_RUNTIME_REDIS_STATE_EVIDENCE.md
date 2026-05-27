# Aegis Runtime Redis and State Evidence

Generated: 2026-05-27T01:08:08Z

api/aegis_ack.py:2:import redis
api/aegis_ack.py:12:r = redis.from_url(os.environ["REDIS_URL"], decode_responses=True)
api/aegis_ack.py:23:    key = f"ztr:aegis:ack:{tenant_id}:{principal}"
api/aegis_ack.py:25:    existing = r.get(key)
api/aegis_ack.py:52:    r.set(key, json.dumps(ack_record))
api/aegis_ack.py:69:@router.get("/aegis/ack/{principal}")
api/aegis_ack.py:72:    key = f"ztr:aegis:ack:{tenant_id}:{principal}"
api/aegis_ack.py:74:    data = r.get(key)
api/risk_engine.py:4:import redis
api/risk_engine.py:6:r = redis.from_url(
api/risk_engine.py:25:        data = r.hgetall(key)
api/risk_engine.py:50:        integrity_score = int(r.get("runtime:integrity_score") or 100)
api/sessions.py:16:# Redis Model
api/sessions.py:17:#   ztr:{tenant}:session:{sid}        -> HASH (TTL)
api/sessions.py:18:#   ztr:{tenant}:sessions             -> SET  (index)
api/sessions.py:22:import redis
api/sessions.py:30:from api.redis_keys import (
api/sessions.py:42:r = redis.from_url(
api/sessions.py:60:        key = f"ztr:aegis:{tenant_id}:{principal}"
api/sessions.py:61:        data = r.get(key)
api/sessions.py:76:def increment_tenant_usage(tenant_id: str, field: str, amount: int = 1):
api/sessions.py:80:    pipe.hincrby(usage_key, field, amount)
api/sessions.py:86:    sids = r.smembers(index_key)
api/sessions.py:93:        data = r.hgetall(key)
api/sessions.py:145:    for key in r.scan_iter("ztr:tenant:*:meta"):
api/sessions.py:146:        raw = r.get(key)
api/sessions.py:160:    for key in r.scan_iter("ztr:*:session:*"):
api/sessions.py:168:@sessions_router.get("/active")
api/sessions.py:181:@sessions_router.get("/admin/active")
api/sessions.py:209:    session_data = r.hgetall(key) or {}
api/sessions.py:218:    r.incr("metric:sessions_revoked")
api/sessions.py:219:    r.decr("ztr:sessions:active")
api/sessions.py:221:    increment_tenant_usage(tenant_id, "sessions_revoked")
api/alerts.py:5:import redis
api/alerts.py:15:r = redis.from_url(
api/alerts.py:24:    return f"ztr:alerts:riskdna:{tenant_id}:status"
api/alerts.py:28:    return f"ztr:alerts:riskdna:{tenant_id}:opened_at"
api/alerts.py:32:    return f"ztr:alerts:riskdna:{tenant_id}:last_seen"
api/alerts.py:96:@router.get("/v1/alerts/riskdna")
api/alerts.py:105:        r.set(_status_key(tenant_id), "unavailable")
api/alerts.py:118:    r.set(_last_seen_key(tenant_id), str(last_seen))
api/alerts.py:120:    previous_status = (r.get(_status_key(tenant_id)) or "healthy").strip().lower()
api/alerts.py:126:        opened_at_raw = r.get(_opened_at_key(tenant_id))
api/alerts.py:130:            r.set(_opened_at_key(tenant_id), str(opened_at))
api/alerts.py:131:            r.set(_status_key(tenant_id), "stale")
api/alerts.py:156:        r.set(_status_key(tenant_id), "recovering")
api/alerts.py:181:        r.set(_status_key(tenant_id), "healthy")
api/alerts.py:183:        r.set(_status_key(tenant_id), "healthy")
api/alerts.py:196:@router.get("/v1/alerts/riskdna/latest-decision")
api/aegis_temporal.py:3:import redis
api/aegis_temporal.py:10:r = redis.from_url(os.environ["REDIS_URL"], decode_responses=True)
api/aegis_temporal.py:32:@router.get("/aegis/temporal")
api/aegis_temporal.py:35:    pattern = f"ztr:aegis:timeline:{tenant_id}:*"
api/aegis_temporal.py:74:@router.get("/aegis/temporal/{principal}")
api/aegis_temporal.py:80:    key = f"ztr:aegis:timeline:{tenant_id}:{principal}"
api/metrics.py:6:import redis
api/metrics.py:12:redis_client = redis.from_url(
api/metrics.py:18:@router.get("/v1/audit/metrics")
api/metrics.py:21:    tokens = int(redis_client.get("metrics:tokens_issued") or 0)
api/metrics.py:22:    allowed = int(redis_client.get("metrics:policy_allowed") or 0)
api/metrics.py:23:    denied = int(redis_client.get("metrics:policy_denied") or 0)
api/metrics.py:24:    revoked = int(redis_client.get("metrics:sessions_revoked") or 0)
api/metrics.py:26:    introspect_success = int(redis_client.get("metric:introspect_success") or 0)
api/metrics.py:27:    introspect_inactive = int(redis_client.get("metric:introspect_inactive") or 0)
api/metrics.py:28:    token_invalid = int(redis_client.get("metric:token_invalid") or 0)
api/metrics.py:29:    token_expired = int(redis_client.get("metric:token_expired") or 0)
api/metrics.py:30:    introspection_failure = int(redis_client.get("metric:introspection_failure") or 0)
api/control_plane_drift.py:4:import redis
api/control_plane_drift.py:8:r = redis.from_url(os.environ["REDIS_URL"], decode_responses=True)
api/control_plane_drift.py:40:    key = f"ztr:{tenant_id}:policy_override:{principal}"
api/control_plane_drift.py:47:    r.set(key, json.dumps(payload))
api/control_plane.py:2:import redis
api/control_plane.py:9:from api.redis_keys import tenant_session_key, tenant_session_index_key
api/control_plane.py:15:r = redis.from_url(
api/control_plane.py:52:    policy_key = f"ztr:tenant:{tenant_id}:policy"
api/control_plane.py:59:    global_policy_key = f"ztr:policy:global:{policy_digest}"
api/control_plane.py:62:        r.hset(global_policy_key, mapping={
api/control_plane.py:68:    r.set(f"ztr:policy:version:{version}", policy_digest)
api/control_plane.py:70:    r.hset(policy_key, mapping={
api/control_plane.py:87:    r.hset(
api/control_plane.py:88:        f"ztr:tenant:{tenant_id}:propagation",
api/control_plane.py:130:    r.hset(f"ztr:tenant:{tenant_id}:policy", mapping={
api/control_plane.py:135:    r.set(f"ztr:tenant:{tenant_id}:policy_anchor", digest)
api/control_plane.py:138:    registry_key = f"ztr:control:tenant:{tenant_id}"
api/control_plane.py:141:        r.hset(registry_key, mapping={
api/control_plane.py:156:    sids = r.smembers(session_index)
api/control_plane.py:199:@router.get("/control-plane/policy")
api/control_plane.py:205:    policy_key = f"ztr:tenant:{tenant_id}:policy"
api/control_plane.py:206:    anchor_key = f"ztr:tenant:{tenant_id}:policy_anchor"
api/control_plane.py:208:    policy_raw = r.hgetall(policy_key)
api/control_plane.py:219:    anchor = _decode(r.get(anchor_key)) or ""
api/control_plane.py:238:@router.get("/control-plane/tenants")
api/control_plane.py:243:    pattern = "ztr:tenant:*:policy"
api/control_plane.py:251:        policy_raw = r.hgetall(key)
api/control_plane.py:252:        anchor_raw = r.get(f"ztr:tenant:{tenant_id}:policy_anchor")
api/control_plane.py:253:        propagation_raw = r.hgetall(f"ztr:tenant:{tenant_id}:propagation")
api/control_plane.py:313:    sids = r.smembers(session_index)
api/control_plane.py:365:    policy_key = f"ztr:tenant:{tenant_id}:policy"
api/control_plane.py:366:    anchor_key = f"ztr:tenant:{tenant_id}:policy_anchor"
api/control_plane.py:368:    policy_raw = r.hgetall(policy_key)
api/control_plane.py:383:    r.set(anchor_key, digest)
api/control_plane.py:388:    r.hset(
api/control_plane.py:389:        f"ztr:tenant:{tenant_id}:propagation",
api/observability.py:6:from redis import Redis
api/observability.py:13:from api.redis_keys import tenant_usage_key
api/observability.py:19:redis_client = Redis.from_url(REDIS_URL, decode_responses=True)
api/observability.py:21:r = redis_client
api/observability.py:22:_r = redis_client
api/observability.py:26:    value = redis_client.get(name)
api/observability.py:31:    value = redis_client.get(name)
api/observability.py:40:    runtime_revision = _r.get("runtime:revision")
api/observability.py:44:    config_key = f"ztr:tenant:{tenant_id}:config"
api/observability.py:45:    config_data = _r.get(config_key)
api/observability.py:71:@router.get("/runtime/integrity")
api/observability.py:79:        redis_ok = r.ping()
api/observability.py:81:        redis_ok = False
api/observability.py:84:    for key in r.scan_iter("ztr:*:session:*"):
api/observability.py:88:    policy_key = f"ztr:tenant:{tenant_id}:policy"
api/observability.py:89:    policy_data = r.hgetall(policy_key)
api/observability.py:137:    introspect_success = int(r.get("metric:introspect_success") or 0)
api/observability.py:138:    introspect_inactive = int(r.get("metric:introspect_inactive") or 0)
api/observability.py:139:    token_invalid = int(r.get("metric:token_invalid") or 0)
api/observability.py:140:    token_expired = int(r.get("metric:token_expired") or 0)
api/observability.py:141:    introspection_failure = int(r.get("metric:introspection_failure") or 0)
api/observability.py:165:    if not redis_ok:
api/observability.py:166:        degraded.append("redis")
api/observability.py:184:    if not redis_ok:
api/observability.py:198:    if not redis_ok or chain_status == "broken":
api/observability.py:207:    r.set("runtime:integrity_score", score)
api/observability.py:214:        "redis_ok": redis_ok,
api/observability.py:223:        "redis_status": "healthy" if redis_ok else "degraded",
api/observability.py:248:@router.get("/runtime/activity")
api/observability.py:254:    pattern = f"ztr:{tenant_id}:audit:entry:*"
api/observability.py:258:            raw = r.get(key)
api/observability.py:285:@router.get("/metrics")
api/observability.py:289:    for key in r.scan_iter("ztr:*:session:*"):
api/observability.py:301:        "redis_latency_ms": read_latency("metric:redis_latency_ms"),
api/observability.py:302:        "metrics_source": "redis:runtime",
api/observability.py:308:@router.get("/metrics/prometheus")
api/observability.py:317:    redis_latency = read_latency("metric:redis_latency_ms")
api/observability.py:335:# TYPE stc_redis_latency_ms gauge
api/observability.py:336:stc_redis_latency_ms {redis_latency}
api/observability.py:341:    for key in _r.scan_iter("ztr:tenant:*:meta"):
api/observability.py:346:            usage = _r.hgetall(usage_key) or {}
api/router_endpoint.py:7:@router.get("/v1/runtime/route")
api/tokens.py:8:from api.redis_keys import (
api/tokens.py:24:import redis
api/tokens.py:37:r = redis.from_url(
api/tokens.py:98:        r.incr("metric:token_expired")
api/tokens.py:99:        r.incr("metric:introspect_inactive")
api/tokens.py:106:        r.incr("metric:token_invalid")
api/tokens.py:107:        r.incr("metric:introspection_failure")
api/tokens.py:115:        r.incr("metric:introspect_inactive")
api/tokens.py:123:        r.incr("metric:introspection_failure")
api/tokens.py:130:    session_data = r.hgetall(session_key)
api/tokens.py:135:        r.incr("metric:introspect_inactive")
api/tokens.py:147:    r.incr("metric:introspect_success")
api/tokens.py:188:def increment_tenant_usage(tenant_id: str, field: str, amount: int = 1):
api/tokens.py:192:    pipe.hincrby(usage_key, field, amount)
api/tokens.py:226:    key = f"ztr:{tenant_id}:policy_override:{principal}"
api/tokens.py:228:    raw = r.get(key)
api/tokens.py:256:    pattern = f"ztr:{tenant_id}:audit:entry:*"
api/tokens.py:260:            raw = r.get(key)
api/tokens.py:288:    key = f"ztr:{tenant_id}:policy_override:{principal}"
api/tokens.py:289:    return bool(r.get(key))
api/tokens.py:325:            redis_client=r,
api/tokens.py:382:            r.incr("metric:policy_denied")
api/tokens.py:383:            increment_tenant_usage(tenant_id, "policy_denied")
api/tokens.py:408:            r.incr("metric:policy_denied")
api/tokens.py:409:            increment_tenant_usage(tenant_id, "policy_denied")
api/tokens.py:534:        r.incr("metric:tokens_issued")
api/tokens.py:535:        r.incr("metric:policy_allowed")
api/tokens.py:536:        increment_tenant_usage(tenant_id, "tokens_issued")
api/policy_registry.py:5:import redis
api/policy_registry.py:15:r = redis.from_url(
api/policy_registry.py:22:    return f"ztr:policy:global:{digest}"
api/policy_registry.py:26:    return f"ztr:policy:version:{version}"
api/policy_registry.py:51:    r.hset(key, mapping={
api/policy_registry.py:57:    r.set(policy_version_index(version), digest)
api/policy_registry.py:66:@router.get("/policy/global")
api/policy_registry.py:69:    pattern = "ztr:policy:global:*"
api/policy_registry.py:75:        data = r.hgetall(key)
api/explainer.py:18:    decision = ddr.get("final_decision")
api/explainer.py:38:    principal = _str(ddr.get("principal"), "unknown")
api/explainer.py:39:    intent = _str(ddr.get("intent"), "unknown")
api/explainer.py:40:    obligations = _list(ddr.get("obligations"))
api/explainer.py:41:    risk_score = _num(ddr.get("risk_score"))
api/explainer.py:42:    policy_revision = _str(ddr.get("policy_revision"), "unknown")
api/explainer.py:81:    principal = _str(ddr.get("principal"), "unknown")
api/explainer.py:82:    intent = _str(ddr.get("intent"), "unknown")
api/explainer.py:83:    obligations = _list(ddr.get("obligations"))
api/explainer.py:84:    risk_score = _num(ddr.get("risk_score"))
api/explainer.py:85:    policy_revision = _str(ddr.get("policy_revision"), "unknown")
api/explainer.py:129:            "score": _num(ddr.get("risk_score")),
api/explainer.py:133:            "obligations": _list(ddr.get("obligations")),
api/explainer.py:134:            "policy_revision": _str(ddr.get("policy_revision"), "unknown")
api/explainer.py:146:        "tenant_id": _str(ddr.get("tenant_id"), "unknown"),
api/explainer.py:147:        "session_id": _str(ddr.get("session_id"), "unknown"),
api/explainer.py:148:        "principal": _str(ddr.get("principal"), "unknown"),
api/explainer.py:149:        "intent": _str(ddr.get("intent"), "unknown"),
api/explainer.py:150:        "policy_revision": _str(ddr.get("policy_revision"), "unknown"),
api/explainer.py:151:        "timestamp": ddr.get("timestamp")
api/auth.py:2:import redis
api/auth.py:6:r = redis.from_url(
api/auth.py:18:    tenant_id = r.get(f"ztr:apikey:{hashed}")
api/auth.py:22:    tenant_status = r.get(f"ztr:tenant:{tenant_id}:status")
api/runtime_router.py:2:import redis
api/runtime_router.py:5:r = redis.from_url(os.environ["REDIS_URL"], decode_responses=True)
api/runtime_router.py:9:    nodes = list(r.smembers("runtime:nodes"))
api/intelligence.py:3:import redis
api/intelligence.py:6:r = redis.from_url(
api/intelligence.py:19:@intelligence_router.get("/risk")
api/intelligence.py:32:            data = r.hgetall(key)
api/intelligence.py:148:        for key in r.scan_iter("ztr:tenant:*:policy"):
api/intelligence.py:150:            policy = r.hgetall(key)
api/policy.py:6:@router.get("/v1/policy/bundle")
api/topology.py:2:import redis
api/topology.py:7:r = redis.from_url(os.environ["REDIS_URL"], decode_responses=True)
api/topology.py:9:@router.get("/v1/runtime/topology")
api/topology.py:12:    nodes = r.smembers("runtime:nodes")
api/control_plane_registry.py:5:import redis
api/control_plane_registry.py:14:r = redis.from_url(
api/control_plane_registry.py:21:    return f"ztr:control:tenant:{tenant_id}"
api/control_plane_registry.py:48:    r.hset(key, mapping=record)
api/control_plane_registry.py:56:@router.get("/registry/list")
api/control_plane_registry.py:59:    pattern = "ztr:control:tenant:*"
api/control_plane_registry.py:65:        data = r.hgetall(key)
api/control_plane_registry.py:76:@router.get("/registry/get")
api/control_plane_registry.py:81:    data = r.hgetall(key)
api/server.py:11:import redis
api/server.py:97:r = redis.from_url(os.environ["REDIS_URL"], decode_responses=True)
api/server.py:100:r.sadd("runtime:nodes", NODE_ID)
api/server.py:120:    for key in r.scan_iter("ztr:tenant:*:meta"):
api/server.py:121:        raw = r.get(key)
api/server.py:148:            raise Exception("Redis unhealthy")
api/server.py:151:        tenant_id = r.get("control_plane:tenant") or "tenant-launch"
api/server.py:156:        r.set("metric:audit_latency_ms", audit_latency)
api/server.py:161:        session_count = int(r.get("ztr:sessions:active") or 0)
api/server.py:166:            "redis": "healthy",
api/streaming.py:3:import redis
api/streaming.py:17:r = redis.from_url(
api/streaming.py:55:        key = f"ztr:{tenant_id}:decisions"
api/streaming.py:77:        r.hset(
api/streaming.py:103:            timeline_key = f"ztr:aegis:timeline:{tenant_id}:{principal}"
api/streaming.py:127:            current_key = f"ztr:aegis:{tenant_id}:{principal}"
api/streaming.py:129:            r.set(
api/streaming.py:147:@router.get("/decisions/recent")
api/streaming.py:154:    events = r.lrange(f"ztr:{tenant_id}:decisions", 0, limit - 1)
api/streaming.py:207:@router.get("/decisions/stream")
api/audit.py:33:@router.get("/audit/events")
api/audit.py:68:@router.get("/audit/verify")
api/audit.py:89:@router.get("/audit/latest")
api/audit.py:113:@router.get("/audit/metrics")
api/redis_keys.py:2:# redis_keys.py — Canonical Redis Key Builder
api/redis_keys.py:6:#   Enforce deterministic tenant-scoped Redis key structure.
api/redis_keys.py:9:#   ztr:tenant:{tenant_id}:{resource}
api/redis_keys.py:10:#   ztr:tenant:{tenant_id}:{resource}:{suffix}
api/redis_keys.py:14:    return f"ztr:tenant:{tenant_id}"
api/redis_keys.py:23:    return f"ztr:apikey:{key_hash}"
core/aegis_identity/service.py:46:    redis_client: Any,
aegis_engine.py:23:    # DRIFT UP (monotonic increase)
aegis_engine.py:38:# ⚙️ STEP 1 — Persist Aegis Signals to Redis (Time-Series)
aegis_engine.py:40:    key = f"ztr:aegis:timeline:{tenant_id}:{principal}"
aegis_engine.py:240:        import redis
aegis_engine.py:242:        r = redis.from_url(os.environ["REDIS_URL"], decode_responses=True)
aegis_engine.py:247:        key = f"ztr:aegis:{tenant_id}:{principal}"
aegis_engine.py:256:        r.set(key, json.dumps({
audit_chain.py:29:import redis
audit_chain.py:30:from redis.exceptions import WatchError
audit_chain.py:37:_audit_redis = redis.from_url(REDIS_URL, decode_responses=True)
audit_chain.py:45:        "head":         f"ztr:{tenant_id}:audit:head",
audit_chain.py:46:        "index_all":    f"ztr:{tenant_id}:audit:index:all",
audit_chain.py:47:        "index_prefix": f"ztr:{tenant_id}:audit:index:",
audit_chain.py:48:        "entry_prefix": f"ztr:{tenant_id}:audit:entry:",
audit_chain.py:101:            with _audit_redis.pipeline() as pipe:
audit_chain.py:131:    raw = _audit_redis.get(k["entry_prefix"] + event_hash)
audit_chain.py:148:    total = _audit_redis.llen(key)
audit_chain.py:154:    hashes = _audit_redis.lrange(key, start, -1)
audit_chain.py:162:    total = _audit_redis.llen(k["index_all"])
audit_chain.py:168:    hashes = _audit_redis.lrange(k["index_all"], start, -1)
audit_chain.py:238:    pattern = f"ztr:{tenant_id}:audit:entry:*"
audit_chain.py:243:    for key in _audit_redis.scan_iter(pattern):
audit_chain.py:244:        raw = _audit_redis.get(key)
