# Aegis Runtime Ownership Split

Status: Phase 1 / Agent 1 Evidence Recorded

## Purpose

This document classifies Aegis Runtime pages, routes, components, and backend surfaces by ownership.

Required labels:

```text
Aegis-owned
RiskDNA-owned but Aegis-rendered
Shared runtime substrate
Cross-suite integrated surface
Legacy coupled implementation
Ownership matrix
Item	Classification	Primary owner	Supporting owner	System of record	Renderer	Control owner	Recommended future state
core/aegis_identity/	Aegis-owned	Aegis Runtime	Runtime	Runtime context / Aegis Identity module	Runtime / downstream UI	OPA for decisions; Aegis for signal generation	Preserve as bounded signal module.
aegis_engine.py	Aegis-owned	Aegis Runtime	Runtime	Runtime	Runtime	OPA for decisions	Confirm exact callable behavior.
aegis_stream.py	Aegis-owned	Aegis Runtime	Runtime streaming	Runtime stream / Redis	Runtime	Runtime evidence owner	Confirm stream consumers.
api/aegis_ack.py	Aegis-owned	Aegis Runtime	Redis / audit	Redis Aegis ack keys	API / frontend	Aegis signal owner	Keep Aegis-specific acknowledgement behind explicit contract.
api/aegis_temporal.py	Aegis-owned	Aegis Runtime	Redis / audit	Redis Aegis timeline keys	API / frontend	Aegis evidence owner	Keep as evidence/timeline surface.
api/blast_simulator.py	RiskDNA-owned but Aegis-rendered	RiskDNA	Runtime / Aegis	Runtime topology/risk context	Runtime / Aegis UI	OPA for decisions	Split RiskDNA scoring contract from Aegis rendering.
api/risk_engine.py	RiskDNA-owned but Aegis-rendered	RiskDNA	Runtime	Runtime risk context	Runtime / Aegis UI	OPA for decisions	Confirm boundary with compute_riskdna.
api/alerts.py RiskDNA stale/latest decision endpoints	RiskDNA-owned but Aegis-rendered	RiskDNA	Observability / audit	Redis alert keys	Runtime / Aegis UI	Runtime alert owner	Preserve as RiskDNA status surface.
api/tokens.py	Shared runtime substrate	Runtime	RiskDNA / Aegis Identity / OPA	Runtime token issuance path	API	OPA / runtime token owner	Keep coupled until token issuance contract is documented.
api/sessions.py	Shared runtime substrate	Runtime	Aegis / audit / usage	Redis session keys	API / frontend	Runtime session owner	Keep as shared substrate; do not classify as Aegis-owned.
api/observability.py	Shared runtime substrate	Runtime Observability	Sessions / Redis / metrics	Redis counters / runtime metrics	API / frontend / Prometheus	Runtime observability owner	Keep shared.
api/intelligence.py	Cross-suite integrated surface	Runtime Intelligence	RiskDNA / Aegis / tenant context	Runtime evidence/risk aggregation	API / frontend	Runtime intelligence owner	Split Decision Intelligence contract later.
api/copilot_aegis.py	Cross-suite integrated surface	Copilot explanation surface	Aegis / RiskDNA	Input risk context	Copilot-facing API	No enforcement owner; explanation only	Keep explanation-only.
api/copilot_bridge.py	Cross-suite integrated surface	Copilot	Runtime / sessions / policy	Runtime metrics/evidence	Copilot-facing API	No enforcement owner	Keep explanation bridge separate from enforcement.
api/audit.py and audit_chain.py	Shared runtime substrate	Runtime evidence	Aegis / RiskDNA / sessions	Audit chain	API / audit viewer	Runtime evidence owner	Map tamper-evidence in SOC 2 phase.
policies/issue.rego	Shared policy dependency	OPA / policy	Aegis / RiskDNA context providers	Policy bundle	OPA	OPA decision owner	Aegis/RiskDNA must remain context only.
policy-bundle/policies/issue.rego	Shared policy dependency	OPA / policy bundle	Runtime	Policy bundle	OPA	OPA decision owner	Keep in policy contract.
api/control_plane.py	Shared runtime/control-plane substrate	Control Plane	Runtime sessions / tenants	Redis/control-plane registry	API / frontend	Control-plane owner	Do not classify as Aegis-owned.
api/control_plane_registry.py	Shared runtime/control-plane substrate	Control Plane	Runtime	Registry keys	API / frontend	Control-plane owner	Keep as tenant inventory dependency.
lab mappings under docs/lab-mappings/	Cross-suite integrated surface	Aegis evidence mapping	RiskDNA / Decision Intelligence	Docs / fixtures	Docs / UI	Evidence owner pending	Treat as mapping evidence, not enforcement.
fixtures/aegis/	Aegis-owned test/evidence fixtures	Aegis Runtime	Tests	Fixtures	Tests / docs	Aegis test owner	Preserve as deterministic evidence fixtures.
Current rule

Aegis owns bounded intelligence signals and Aegis-specific evidence surfaces.

RiskDNA owns risk computation and blast-radius scoring.

Runtime owns sessions, token issuance, tenant inventory, audit chain, observability, Redis state, and route orchestration.

OPA owns policy decision authority.

Explicit non-ownership

Aegis must not be treated as owner of:

token issuance
session creation
session revocation
OPA policy decisions
Redis runtime state generally
tenant registry
control-plane governance
SENTINEL integration
Vault reference resolution
production enforcement


## Agent 1 Evidence Record

Status: Agent 1 Evidence Recorded

Evidence commits:

```text
0a07fa6 — Add Aegis runtime phase 1 truth anchor docs
f06cab9 — Add Aegis runtime Agent 1 alignment docs
6b76a29 — Add Aegis runtime Agent 1 verification evidence

Evidence files:

docs/aegis/evidence/AEGIS_RUNTIME_ROUTE_EVIDENCE.md
docs/aegis/evidence/AEGIS_RUNTIME_REDIS_STATE_EVIDENCE.md
docs/aegis/evidence/AEGIS_RUNTIME_RISKDNA_AEGIS_OPA_FLOW_EVIDENCE.md

Agent 1 exit position:

Aegis Runtime inventory, ownership split, dependency map, suite alignment,
rendered-vs-owned classification, baseline export candidate map, and initial
SOC 2 alignment are now recorded with repository evidence.

Remaining unresolved items are intentionally reserved for downstream agents:
SOC 2 control ownership, RiskDNA/Aegis boundary hardening, cross-platform
inheritance confirmation, SENTINEL re-baseline, Composition Layer readiness,
Helm/package scope, and doctrine updates.

