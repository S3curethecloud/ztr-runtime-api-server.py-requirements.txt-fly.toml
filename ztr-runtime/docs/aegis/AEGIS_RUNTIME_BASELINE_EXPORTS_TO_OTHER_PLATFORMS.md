
Aegis Runtime Baseline Exports to Other Platforms

Status: Phase 1 / Agent 1 Evidence Recorded

Purpose

This document records which Aegis Runtime files and patterns appear likely to have been exported, copied, or used as baselines for ASZ, Blackbox, Kubernetes/SENTINEL, or other SecureTheCloud platforms.

This file does not claim inheritance is proven unless a destination repository/file is identified.

Current evidence position

The ztr-runtime repository contains runtime baseline patterns that are likely candidates for downstream inheritance:

- session lifecycle APIs
- token issuance path
- RiskDNA scoring and blast-radius functions
- Aegis Identity signal module
- Aegis Redis key conventions
- OPA policy bundle patterns
- audit/event emission patterns
- observability/Prometheus patterns
- tenant/control-plane registry patterns
- Copilot explanation bridges

Exact copied destinations must be confirmed by repository-to-repository search.

Candidate baseline exports
Source pattern	Possible downstream consumer	Current proof level	Assumptions that may have traveled
api/sessions.py	ASZ, Blackbox, Kubernetes/SENTINEL	Candidate only	Session lifecycle shape, revoke semantics, Redis key patterns.
api/tokens.py	ASZ, Blackbox, Kubernetes/SENTINEL	Candidate only	RiskDNA-before-OPA sequencing, Aegis Identity enrichment, audit/session persistence.
api/blast_simulator.py	RiskDNA, Blackbox, Aegis UI, ASZ	Candidate only	Blast-radius scoring model, topology risk assumptions.
api/risk_engine.py	RiskDNA, Blackbox, Aegis UI	Candidate only	Runtime risk computation assumptions.
core/aegis_identity/	Aegis, ASZ, RiskDNA, Blackbox evidence	Candidate only	Aegis signal-only model, identity drift semantics, risk modifier usage.
api/intelligence.py	Decision Intelligence, Blackbox, Copilot	Candidate only	Tenant risk aggregation, heatmap assumptions, runtime truth consumption.
api/observability.py	SENTINEL/Kubernetes, Blackbox, platform UI	Candidate only	Metrics names, session counters, Prometheus output style.
api/audit.py and audit_chain.py	Blackbox, SOC 2 evidence, audit viewer	Candidate only	Audit event shape, evidence chain assumptions.
policies/issue.rego	SENTINEL/Kubernetes, OPA bundles	Candidate only	Aegis/RiskDNA context fields, deny conditions, allow semantics.
policy-bundle/	SENTINEL/Kubernetes, packaged runtime	Candidate only	Bundle structure and policy distribution assumptions.
opa_bridge.py, opa-config.yaml, opa-sidecar.yaml	Kubernetes/SENTINEL	Candidate only	OPA sidecar invocation/config assumptions.
redis.yaml, api/redis_keys.py	Runtime deployments, ASZ, Blackbox	Candidate only	Redis state naming conventions.
prometheus/alerts.yml	Kubernetes/SENTINEL, Observability	Candidate only	Alert definitions and metric thresholds.
fixtures/aegis/	Tests, docs, ASZ assertions, Blackbox demos	Candidate only	Deterministic Aegis scenario fixtures.
docs/lab-mappings/*aegis-runtime.md	Customer demos, ASZ, Blackbox evidence packages	Candidate only	Lab-to-runtime evidence mapping assumptions.
Known inherited assumptions requiring normalization

The following assumptions should become explicit contracts before downstream systems rely on them:

- Aegis produces signals, not authorization decisions.
- RiskDNA computes risk context, not enforcement outcomes.
- OPA remains the decision authority where policy evaluation is required.
- Runtime owns token/session side effects.
- Redis key conventions are shared infrastructure, not Aegis ownership.
- Audit chain/event emission is shared runtime evidence, not Aegis-only evidence.
- Copilot explains context but does not enforce.
- Blackbox records/replays evidence but must not become runtime authority.
- SENTINEL/Kubernetes must not duplicate Aegis runtime command-center behavior.
Required inheritance searches

Before this file can be marked complete, run cross-repository searches for:

aegis_identity
evaluate_identity_integrity
compute_riskdna
simulate_blast_radius
ztr:aegis
ztr:aegis:ack
ztr:aegis:timeline
ztr:alerts:riskdna
riskdna_stale
aegis_temporal
aegis_ack
Decision Intelligence
tenant heatmap
deny_aegis
IDENTITY_DRIFT_DETECTED
Destination map placeholder
Destination platform	Inherited files confirmed	Inherited patterns confirmed	Status
ASZ	Pending	Pending	Not yet mapped
Blackbox	Pending	Pending	Not yet mapped
Kubernetes/SENTINEL	Pending	Pending	Not yet mapped
Composition Layer	Pending	Pending	Not yet mapped
Helm/packaging	Pending	Pending	Not yet mapped
Gate rule

Do not mark copied baseline inheritance complete until destination repository evidence is recorded.

This document is a candidate baseline map until cross-platform file matches are confirmed.


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

