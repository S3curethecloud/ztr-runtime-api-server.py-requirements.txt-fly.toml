# Aegis Runtime Inventory

Status: Phase 1 / Initial Inventory In Progress

## Purpose

This document records the current Aegis Runtime surfaces, routes, backend files, dependencies, and evidence surfaces visible in the `ztr-runtime` repository.

This is a truth-anchor document for the Aegis Runtime Ecosystem Alignment Gate.

## Current repository root

```text
ztr-runtime/
Known Aegis / RiskDNA runtime files
aegis_engine.py
aegis_stream.py
api/aegis_ack.py
api/aegis_temporal.py
api/alerts.py
api/audit.py
api/blast_simulator.py
api/copilot_aegis.py
api/copilot_bridge.py
api/explainer.py
api/intelligence.py
api/metrics.py
api/observability.py
api/risk_engine.py
api/runtime_router.py
api/sessions.py
api/tokens.py
api/topology.py
audit_chain.py
core/aegis_identity/
policies/issue.rego
policies/issue_identity_test.rego
policy-bundle/policies/issue.rego
tests/test_aegis_identity.py
tests/test_decision_pipeline.py
tests/test_intelligence.py
tests/test_sessions.py
tests/test_token_revocation.py
Runtime surfaces discovered
Surface	Route / file evidence	Current classification	Notes
Aegis acknowledgement	api/aegis_ack.py; /aegis/ack; /aegis/ack/{principal}	Aegis-owned runtime signal surface	Stores/reads Aegis acknowledgement state.
Aegis temporal view	api/aegis_temporal.py; /aegis/temporal; /aegis/temporal/{principal}	Aegis-owned evidence/timeline surface	Reads Aegis timeline keys.
Session lifecycle	api/sessions.py; /v1/sessions/active; /v1/sessions/admin/active; /v1/sessions/revoke; /v1/sessions/admin/revoke	Shared runtime substrate	Renders session lifecycle and embeds Aegis signal context.
RiskDNA alerting	api/alerts.py; /v1/alerts/riskdna; /v1/alerts/riskdna/latest-decision	RiskDNA-owned but runtime-rendered	Tracks RiskDNA stale/healthy/latest-decision state.
Blast Radius	api/blast_simulator.py; simulate_blast_radius; summarize_blast	RiskDNA-integrated analysis surface	Computes topology/blast-radius context.
RiskDNA scoring	api/blast_simulator.py; compute_riskdna	RiskDNA-owned logic	Computes runtime risk context.
Token issuance path	api/tokens.py; issue_token; imports compute_riskdna and evaluate_identity_integrity	Shared runtime substrate	Runs RiskDNA, Aegis Identity, then OPA evaluation.
Aegis Identity Integrity	core/aegis_identity/	Aegis-owned bounded intelligence extension	Produces signals and risk modifiers only.
Decision Intelligence	api/intelligence.py; Aegis docs mention Decision Intelligence consumers	Cross-suite integrated surface	Consumes runtime truth, RiskDNA, and Aegis signal context.
Runtime Observability	api/observability.py; session counters and metrics	Shared runtime substrate	Exposes runtime health and session metrics.
Tenant inventory	api/control_plane.py; api/control_plane_registry.py	Shared runtime/control-plane substrate	Provides tenant inventory and control-plane views.
Copilot Aegis simulation	api/copilot_aegis.py; /copilot/aegis/simulate	Copilot-facing rendered explanation surface	Simulates/explains Aegis signal from risk context.
Policy / OPA	policies/issue.rego; policy-bundle/policies/issue.rego; opa_bridge.py	Policy dependency	Aegis/RiskDNA provide context; OPA remains decision authority.
Audit chain	api/audit.py; audit_chain.py	Shared evidence substrate	Runtime evidence/audit dependency.
Minimum page checklist from gate
Required surface	Current evidence status
Overview / Platform Command Center	Pending frontend/source confirmation
Runtime Integrity	Partially evidenced by tests/test_integrity.py, runtime_identity.py, Aegis Identity docs
Runtime Observability	Evidenced by api/observability.py
Shield	Pending route/component confirmation
Sessions	Evidenced by api/sessions.py
Tenants	Evidenced by api/control_plane.py, api/control_plane_registry.py
Provision	Pending route/component confirmation
Billing	Pending route/component confirmation
RiskDNA Analysis	Evidenced by api/blast_simulator.py, api/risk_engine.py, api/alerts.py
Decision Intelligence	Evidenced by api/intelligence.py and Aegis SoT references
Heatmap	Partially evidenced by Decision Intelligence / tenant risk aggregation references
Blast Radius	Evidenced by api/blast_simulator.py
Operator	Pending route/component confirmation
Copilot-facing decision explanation	Evidenced by api/copilot_aegis.py, api/copilot_bridge.py, api/explainer.py
Session explain / revoke	Revoke evidenced by api/sessions.py; explain pending confirmation
Integrity / audit / audit-viewer	Audit evidenced by api/audit.py, audit_chain.py; audit-viewer pending confirmation
Current truth

Aegis Runtime is not a standalone clean module today. It is a runtime substrate with Aegis-owned bounded intelligence extensions, RiskDNA-integrated scoring and blast-radius logic, shared session/token/control-plane substrates, Redis-backed state, OPA policy dependencies, and audit/evidence dependencies.

Pending evidence

This inventory still requires a direct endpoint/router pass over:

api/server.py
api/runtime_router.py
api/router_endpoint.py
admin_router.py
control_plane.py
api/control_plane.py
api/tokens.py
api/sessions.py
api/intelligence.py
api/observability.py

