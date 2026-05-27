# Aegis Runtime Dependency Map

Status: Phase 1 / Initial Dependency Map In Progress

## Purpose

This document maps Aegis Runtime dependencies and coupling points discovered in `ztr-runtime`.

## Dependency summary

| Dependency class | Files / patterns | Direction | Notes |
|---|---|---|---|
| Internal Aegis dependencies | `aegis_engine.py`, `aegis_stream.py`, `api/aegis_ack.py`, `api/aegis_temporal.py`, `core/aegis_identity/` | Aegis -> Runtime context / Redis / audit | Aegis produces signals, timelines, acknowledgements, and bounded identity integrity context. |
| RiskDNA dependencies | `api/blast_simulator.py`, `api/risk_engine.py`, `api/alerts.py`, `api/tokens.py` | RiskDNA -> Runtime token/session/intelligence surfaces | RiskDNA computes risk context and stale/latest-decision alert state. |
| Session/token dependencies | `api/tokens.py`, `api/sessions.py`, `tests/test_token_revocation.py`, `tests/test_sessions.py` | Runtime -> RiskDNA / Aegis Identity / OPA / Redis | Token issuance path invokes RiskDNA, enriches with Aegis Identity, then passes to OPA. |
| Policy / OPA dependencies | `opa_bridge.py`, `opa-config.yaml`, `opa-sidecar.yaml`, `policies/*.rego`, `policy-bundle/` | Runtime context -> OPA | OPA remains decision authority; Aegis/RiskDNA are context inputs. |
| Audit-chain dependencies | `api/audit.py`, `audit_chain.py`, Aegis/RiskDNA event references | Runtime surfaces -> audit evidence | Aegis ack, temporal access, RiskDNA stale/open/resolved events emit evidence. |
| Redis dependencies | `redis.yaml`, `api/redis_keys.py`, `api/sessions.py`, `api/aegis_ack.py`, `api/aegis_temporal.py`, `api/alerts.py`, `api/observability.py` | Runtime APIs -> Redis | Redis stores sessions, Aegis ack/timeline, RiskDNA alert state, metrics, tenant/control-plane state. |
| Copilot dependencies | `api/copilot_aegis.py`, `api/copilot_bridge.py`, `api/explainer.py` | Copilot -> runtime risk/session/policy context | Copilot surfaces explanation/simulation, not enforcement. |
| Tenant inventory dependencies | `api/control_plane.py`, `api/control_plane_registry.py`, `api/intelligence.py`, `api/observability.py` | Runtime -> tenant registry / Redis | Tenant inventory feeds control-plane, intelligence, and observability surfaces. |
| Observability dependencies | `api/observability.py`, `api/metrics.py`, `prometheus/alerts.yml` | Runtime metrics -> API / Prometheus | Tracks active sessions, revoked sessions, runtime counters, tenant usage. |
| Test dependencies | `tests/test_aegis_identity.py`, `tests/test_decision_pipeline.py`, `tests/test_intelligence.py`, `tests/test_sessions.py`, `tests/test_token_revocation.py` | Tests -> runtime contracts | Tests prove current coupled behavior. |

## Key runtime flow

```text
Token request
→ api/tokens.py
→ simulate_blast_radius(...)
→ compute_riskdna(...)
→ evaluate_identity_integrity(...)
→ context["aegis_identity"]
→ context["risk_score"]
→ OPA policy evaluation
→ audit/session/runtime evidence
Aegis signal flow
core/aegis_identity/
→ Aegis Identity signal
→ RiskDNA enriched score / runtime context
→ Decision Intelligence / sessions / audit
→ OPA receives context
Redis key patterns observed
ztr:aegis:{tenant_id}:{principal}
ztr:aegis:ack:{tenant_id}:{principal}
ztr:aegis:timeline:{tenant_id}:{principal}
ztr:alerts:riskdna:{tenant_id}:status
ztr:alerts:riskdna:{tenant_id}:opened_at
ztr:alerts:riskdna:{tenant_id}:last_seen
ztr:{tenant}:sessions
ztr:sessions:active
metric:sessions_revoked
metrics:sessions_revoked
Exported / copied baseline dependencies

Current evidence shows runtime files and patterns that are likely baseline candidates for ASZ, Blackbox, Kubernetes, or SENTINEL inheritance, but exact copied destinations are not yet proven.

Candidate baseline patterns requiring confirmation
api/sessions.py
api/tokens.py
api/blast_simulator.py
api/intelligence.py
api/observability.py
api/audit.py
audit_chain.py
core/aegis_identity/
policies/issue.rego
policy-bundle/
opa_bridge.py
redis.yaml
prometheus/alerts.yml
fixtures/aegis/
docs/lab-mappings/
Required follow-up

Run an explicit inheritance search across ASZ, Blackbox, Kubernetes/SENTINEL repositories before marking copied baseline mappings complete.

Suggested search terms:

aegis_identity
compute_riskdna
simulate_blast_radius
ztr:aegis
ztr:alerts:riskdna
aegis_temporal
aegis_ack
Decision Intelligence
tenant heatmap
Boundary rule

Aegis dependencies are runtime-context dependencies, not enforcement authority. OPA remains decision authority. Runtime owns session/token side effects. Aegis owns bounded signals only.

