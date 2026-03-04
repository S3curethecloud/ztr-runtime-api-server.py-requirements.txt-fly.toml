# =============================================================
# SecureTheCloud — Phase 5 Implementation Checklist
# Ground truth: actual uploaded files read and verified
# Phases 1–4: FROZEN — do not touch
# =============================================================
# 11 items total. Delivered in execution order.
# Each item: FILE · LOCATION · DELTA · ACCEPT · RISK
# =============================================================


# =============================================================
# PHASE 5A — TENANT ISOLATION BASELINE  (7 items)
# =============================================================

# ── 5A-01 ── audit_chain.py — tenant-scope all Redis keys ────
FILE:     audit_chain.py
LOCATION: Lines 27–30 (constants) + emit_event, get_entry,
          list_index, verify_chain signatures

CURRENT:
  AUDIT_HEAD_KEY     = "ztr:audit:head"
  AUDIT_INDEX_ALL    = "ztr:audit:index:all"
  AUDIT_INDEX_PREFIX = "ztr:audit:index:"
  AUDIT_ENTRY_PREFIX = "ztr:audit:entry:"

DELTA:
  DELETE the four constant lines.
  ADD key-builder helper after imports:

    def _keys(tenant_id: str) -> dict:
        return {
            "head":         f"ztr:{tenant_id}:audit:head",
            "index_all":    f"ztr:{tenant_id}:audit:index:all",
            "index_prefix": f"ztr:{tenant_id}:audit:index:",
            "entry_prefix": f"ztr:{tenant_id}:audit:entry:",
        }

  emit_event() — ADD param: tenant_id: str
    k = _keys(tenant_id)
    pipe.watch(k["head"])
    prev_hash = pipe.get(k["head"]) or GENESIS_HASH
    pipe.set(k["head"], event_hash)
    pipe.rpush(k["index_all"], event_hash)
    pipe.rpush(k["index_prefix"] + event_type, event_hash)
    pipe.set(k["entry_prefix"] + event_hash, _canonical(envelope))

  get_entry() — ADD param: tenant_id: str
    k = _keys(tenant_id)
    raw = _audit_redis.get(k["entry_prefix"] + event_hash)

  list_index() — ADD param: tenant_id: str
    k = _keys(tenant_id)
    key = k["index_all"] if event_type == "all" else k["index_prefix"] + event_type

  verify_chain() — ADD param: tenant_id: str
    k = _keys(tenant_id)
    use k["index_all"] for hashes
    call get_entry(h, tenant_id=tenant_id) in loop

FROZEN: _canonical(), _sha256(), WatchError retry loop — do not touch.

ACCEPT:
  emit_event(tenant_id="acme") → writes to ztr:acme:audit:*
  emit_event(tenant_id="beta") → writes to ztr:beta:audit:*
  verify_chain("acme") → cannot see ztr:beta:audit:* entries
RISK: Cross-tenant audit visibility. SOC 2 hard blocker.


# ── 5A-02 ── server.py — pass tenant_id to every emit_event() ─
FILE:     api/server.py (ztr-runtime)
LOCATION: Four emit_event() call sites

DELTA — add tenant_id=tenant_id to each:

  issue_token() → runtime.token_issued:
    emit_event(..., tenant_id=tenant_id)

  introspect() → runtime.token_introspected (revoked path ~line 157):
    emit_event(..., tenant_id=tenant_id)

  introspect() → runtime.token_introspected (active path ~line 170):
    emit_event(..., tenant_id=tenant_id)

  tenant_revoke() → runtime.session_revoked (~line 249):
    emit_event(..., tenant_id=tenant_id)

  NOTE: propagate_revocation() handled separately in 5A-03.

ACCEPT: GET /v1/audit/verify (acme key) returns only acme events.
RISK:   All audit events land in dead global namespace. Chain unverifiable.


# ── 5A-03 ── server.py — fix propagate_revocation() ──────────
FILE:     api/server.py (ztr-runtime)
LOCATION: propagate_revocation() — lines ~195–225

CURRENT (SOT VIOLATION):
  def propagate_revocation(req: RevocationRequest):
      tenant_id = req.decision.get("tenant_id")   # reads from body

DELTA:
  @app.post("/v1/revocations/propagate")
  def propagate_revocation(
      req: RevocationRequest,
      tenant_id: str = Depends(require_tenant_api_key)   # ADD
  ):
      # DELETE: tenant_id = req.decision.get("tenant_id")
      # DELETE: if not tenant_id: raise HTTPException(...)
      # tenant_id comes exclusively from validated API key

      redis_key = f"ztr:{tenant_id}:session:{req.session_id}"
      deleted = r.delete(redis_key)
      audit = emit_event(
          event_type="runtime.session_revoked",
          service="ztr-runtime",
          correlation_id=req.session_id,
          tenant_id=tenant_id,
          payload={...same as current minus tenant_id derivation...},
      )
      return {"status": "ok", "deleted": bool(deleted), "audit": audit}

  ALSO: intelligence-core revocation_propagation.py must send
        X-STC-API-Key header when calling this endpoint.

ACCEPT:
  POST with no key → 401
  POST with acme key → only deletes ztr:acme:session:*
  POST with beta key → cannot touch ztr:acme:session:*
RISK: Any caller revokes any tenant's sessions by spoofing tenant_id in body.


# ── 5A-04 ── server.py — lock all three audit read endpoints ──
FILE:     api/server.py (ztr-runtime)
LOCATION: Lines ~65–83 — three @app.get("/v1/audit/...") functions

CURRENT: No auth, no tenant scoping on any of the three.

DELTA — add Depends(require_tenant_api_key) + route to tenant chain:

  @app.get("/v1/audit/verify")
  def audit_verify(
      limit: int = 5000,
      tenant_id: str = Depends(require_tenant_api_key)
  ):
      return verify_chain(tenant_id=tenant_id, limit=limit)

  @app.get("/v1/audit/index/{event_type}")
  def audit_index(
      event_type: str, limit: int = 50,
      tenant_id: str = Depends(require_tenant_api_key)
  ):
      return {
          "event_type": event_type, "limit": limit,
          "hashes": list_index(tenant_id=tenant_id, event_type=event_type, limit=limit),
      }

  @app.get("/v1/audit/entry/{event_hash}")
  def audit_entry(
      event_hash: str,
      tenant_id: str = Depends(require_tenant_api_key)
  ):
      entry = get_entry(event_hash=event_hash, tenant_id=tenant_id)
      if not entry:
          raise HTTPException(status_code=404, detail="audit_entry_not_found")
      return entry

ACCEPT:
  GET /v1/audit/verify no key → 401
  GET /v1/audit/verify acme key → only acme events returned
RISK: Tenant A reads Tenant B complete audit chain.


# ── 5A-05 ── admin.py — NEW FILE (+ 2 lines in server.py) ────
FILE:     admin.py (NEW)  +  api/server.py (2 line addition)

NEW FILE: admin.py
  Endpoints:
    POST   /v1/admin/tenants                       → create tenant
    POST   /v1/admin/tenants/{tenant_id}/keys      → issue key (shown once)
    DELETE /v1/admin/tenants/{tenant_id}/keys/{kh} → revoke key

  Auth: X-STC-Admin-Secret header checked against ADMIN_SECRET env var.
        Separate from tenant API keys — never overlap.

ADD to server.py (after app = FastAPI(...)):
  from admin import admin_router
  app.include_router(admin_router)

ADD to fly.toml [env] or secrets:
  ADMIN_SECRET = <openssl rand -hex 32>

ACCEPT:
  POST /v1/admin/tenants → 201 + tenant record in Redis
  POST /v1/admin/tenants/acme/keys → returns api_key (shown once only)
  Issued key works on /v1/tokens:issue immediately
  DELETE key hash → that key returns 401 on next use
RISK: No tenant onboarding path. Multi-tenant SaaS cannot launch.


# ── 5A-06 ── server.py — fix CORS ────────────────────────────
FILE:     api/server.py (ztr-runtime)
LOCATION: Lines 18–24

CURRENT:
  allow_origins=["http://localhost:8080"],

DELTA:
  allow_origins=[
      "https://securethecloud.dev",
      "https://stc-intelligence-core.pages.dev",
      "https://shield.securethecloud.dev",
      "https://console.securethecloud.dev",
  ],

ACCEPT: OPTIONS from securethecloud.dev → 200 with correct headers
RISK: Every production frontend call blocked by CORS.


# ── 5A-07 ── server.py — enrich /health ──────────────────────
FILE:     api/server.py (ztr-runtime)
LOCATION: health() — line ~60

CURRENT:
  def health():
      return {"status": "ok"}

DELTA:
  def health():
      try:
          session_count = sum(1 for _ in r.scan_iter("ztr:*:session:*"))
      except Exception:
          session_count = None
      return {
          "status": "ok",
          "active_sessions": session_count,
          "policy_rev": POLICY_REVISION,
      }

ACCEPT: GET /health → { status: "ok", active_sessions: N, policy_rev: "..." }
RISK: Homepage enforcement graph health bar shows "—" for all live fields.


# =============================================================
# PHASE 5B — POLICY-AWARE INTROSPECTION  (4 items)
# =============================================================

# ── 5B-01 ── opa_bridge.py — NEW FILE ────────────────────────
FILE:     opa_bridge.py (NEW — ztr-runtime root)

WHAT: Single function called at Layer 5 of introspection.
      Fail-closed on every error path — never fail-open.

  evaluate_introspect_policy(
      principal, scopes, intent,
      tenant_id, policy_revision, context
  ) → { allow: bool, reason: str, policy_revision: str }

  Fail-closed table:
    OPA returns allow=true  → { allow: True,  reason: "opa_allow" }
    OPA returns allow=false → { allow: False, reason: "opa_deny" }
    Connection timeout      → { allow: False, reason: "opa_unavailable" }
    Any exception           → { allow: False, reason: "opa_error" }

ADD to fly.toml secrets:
  OPA_URL         = http://localhost:8181
  OPA_POLICY_PATH = /v1/data/ztr/introspect/allow

ACCEPT:
  OPA allow   → introspect returns active
  OPA deny    → 401, runtime.policy_denied audit event written
  OPA down    → 401 (fail-closed — never pass through)
RISK: OPA outage with fail-open = permanently ungated enforcement.


# ── 5B-02 ── server.py — wire OPA into introspect() ──────────
FILE:     api/server.py (ztr-runtime)
LOCATION: introspect() — insert between Redis check and final return

CURRENT layers:
  1. JWT decode
  2. Version check
  3. Tenant match
  4. Redis existence
  [return active]

DELTA — insert Layer 5 after Redis check passes:

  ADD to imports:
    from opa_bridge import evaluate_introspect_policy

  ADD after `if not r.exists(session_key):` block resolves (session exists):

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
                "sid": sid,
                "principal": decoded.get("sub"),
                "reason": opa_result["reason"],
                "policy_revision": opa_result["policy_revision"],
                "tenant_id": tenant_id,
            },
        )
        raise HTTPException(status_code=401, detail="policy_denied")

  Final layer order:
    1. JWT decode         (frozen)
    2. Version check      (frozen)
    3. Tenant match       (frozen)
    4. Redis existence    (frozen)
    5. OPA re-evaluation ← NEW 5B
    6. Emit + return active

ACCEPT:
  Phase 3 regression test: valid token + OPA allow → still returns active
  OPA deny  → 401 + runtime.policy_denied in audit chain
  OPA down  → 401 (not 500, not pass-through)
RISK: Without layer 5, introspection is not Zero Trust.


# ── 5B-03 ── server.py — add policy_revision to introspect audit
FILE:     api/server.py (ztr-runtime)
LOCATION: introspect() active path — final emit_event() payload

CURRENT payload:
  "sid", "principal", "result", "jwt_ver", "redis_present", "tenant_id"

DELTA — add two fields:
  "policy_revision": POLICY_REVISION,
  "opa_result":      opa_result.get("reason"),

ACCEPT: Audit entry for runtime.token_introspected contains policy_revision.
RISK: Cannot replay-validate which policy version governed each introspect.


# ── 5B-04 ── policies/ztr_introspect.rego — NEW FILE ─────────
FILE:     policies/ztr_introspect.rego (NEW — ztr-runtime/policies/)

WHAT: Rego policy stub loaded into OPA sidecar.
      Controls the allow/deny decision at Layer 5.

ACCEPT:
  OPA with valid principal + scopes + policy_revision → allow=true
  OPA with empty scopes → allow=false
  OPA with wrong policy_revision → allow=false
RISK: OPA bridge deployed but no policy → every introspect → 401.


# =============================================================
# EXECUTION ORDER
# =============================================================
#  1. audit_chain.py      5A-01
#  2. server.py           5A-02
#  3. server.py           5A-03
#  4. server.py           5A-04
#  5. admin.py (NEW)      5A-05
#  6. server.py           5A-06
#  7. server.py           5A-07
#  8. opa_bridge.py (NEW) 5B-01
#  9. server.py           5B-02
# 10. server.py           5B-03
# 11. rego (NEW)          5B-04

# =============================================================
# NEW SECRETS REQUIRED (fly.toml before deploy)
# =============================================================
#  ADMIN_SECRET      openssl rand -hex 32
#  OPA_URL           http://localhost:8181
#  OPA_POLICY_PATH   /v1/data/ztr/introspect/allow

# =============================================================
# PHASE 5 COMPLETE WHEN ALL 12 GATES CHECKED
# =============================================================
#  [ ] Tenant A cannot read Tenant B audit chain
#  [ ] Tenant A cannot introspect Tenant B tokens
#  [ ] Tenant A cannot revoke Tenant B sessions
#  [ ] /v1/revocations/propagate derives tenant from API key not body
#  [ ] Admin can create tenant, issue key, revoke key
#  [ ] All audit events in ztr:{tenant_id}:audit:* namespace
#  [ ] CORS: localhost:8080 blocked, production origins pass
#  [ ] GET /health returns active_sessions + policy_rev
#  [ ] Valid token + OPA allow → active (no Phase 3 regression)
#  [ ] Valid token + OPA deny  → 401 + policy_denied in audit
#  [ ] OPA unreachable         → 401 (fail-closed)
#  [ ] policy_revision in every introspect audit payload
