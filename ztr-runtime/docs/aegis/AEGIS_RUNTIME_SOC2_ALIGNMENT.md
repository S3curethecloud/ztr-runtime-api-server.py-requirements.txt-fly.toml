
Aegis Runtime SOC 2 Alignment

Status: Phase 1 / Agent 1 Evidence Recorded

Purpose

This document provides the initial Aegis-layer SOC 2 alignment map required by the Aegis Runtime Alignment Agent.

It does not claim SOC 2 certification, production operating effectiveness, independent audit completion, or final compliance readiness.

Detailed control ownership belongs to the later SOC 2 / Control Alignment Agent.

Alignment principle

Aegis Runtime may support SOC 2-aligned evidence where it provides:

- bounded runtime signals
- deterministic evidence fixtures
- audit-safe runtime events
- traceable session/risk context
- explainable decision context
- policy-input context for OPA

Aegis Runtime does not by itself prove:

- SOC 2 certification
- production operating effectiveness
- complete change-management control
- complete access-control design
- complete incident-response control
- complete evidence immutability
SOC 2-relevant surfaces
Surface	SOC 2 relevance	Evidence source	Aegis role	Gap
core/aegis_identity/	Risk/context signal supporting security monitoring and policy input	Aegis Identity assessment output, tests, fixtures	Produces bounded signal	Needs control owner and review cadence.
api/aegis_ack.py	Operational acknowledgement/evidence state	Redis ack keys, audit event payloads	Produces/records Aegis-specific evidence	Tamper-evidence and retention must be mapped.
api/aegis_temporal.py	Timeline/history support for runtime evidence review	Redis timeline keys, temporal access events	Displays Aegis timeline evidence	Storage/retention/integrity gaps pending.
api/blast_simulator.py	Risk analysis supporting security monitoring	RiskDNA score, blast-radius output	Consumes/renders RiskDNA context	RiskDNA owner and validation cadence needed.
api/alerts.py	Runtime alerting and monitoring	RiskDNA stale/open/resolved events	Renders/uses status context	Alert review and escalation path needed.
api/tokens.py	Access/token decision context	Runtime decision event, OPA result, audit/session payload	Supplies Aegis signal into context	Runtime/OPA own decision authority.
api/sessions.py	Session lifecycle visibility and revocation evidence	Redis session records, audit revocation events	Displays embedded Aegis signal	Session control owner is runtime, not Aegis.
api/observability.py	Runtime monitoring metrics	Runtime counters and Prometheus output	Dependency/consumer only	Metric integrity and review cadence needed.
api/intelligence.py	Decision Intelligence / tenant risk aggregation	Runtime aggregation and risk evidence	Integrated context contributor	Ownership boundary pending.
api/audit.py / audit_chain.py	Evidence traceability	Runtime audit events / audit chain	Emits/depends on evidence	Tamper-evidence design must be confirmed.
policies/issue.rego	Deterministic policy behavior	OPA policy bundle and tests	Provides context fields only	OPA remains decision authority.
fixtures/aegis/	Repeatable evidence scenarios	Fixture JSON files	Provides deterministic scenario evidence	Fixture review/approval path needed.
tests/test_aegis_identity.py	Control design validation support	Unit tests	Validates bounded Aegis behavior	CI status and required test gate pending.
Initial SOC 2 mapping
SOC 2-aligned objective	Aegis Runtime support	Current confidence	Notes
Least privilege	Aegis is signal-only and does not own token/session side effects.	Medium	Must be enforced through OPA/runtime boundaries.
Separation of duties	RiskDNA computes risk, Aegis produces signals, OPA decides, runtime owns sessions/tokens.	Medium	Needs formal ownership matrix from Agent 2.
Auditability	Aegis ack, temporal, token, session, alert, and audit-chain events exist.	Medium	Retention/tamper-evidence not fully mapped.
Deterministic policy behavior	OPA receives Aegis/RiskDNA context and owns decisions.	Medium	Requires policy tests and bundle validation.
Change traceability	Repository docs/tests/fixtures provide traceable source changes.	Low/Medium	Change approval path not documented yet.
Monitoring	Observability and RiskDNA alerting surfaces exist.	Medium	Alert response and review cadence pending.
Evidence integrity	Audit chain exists.	Low/Medium	Tamper-evidence mechanism requires verification.
Explicit SOC 2 non-claims

This document must not be used to claim:

- Aegis Runtime is SOC 2 certified.
- Aegis Runtime has passed an independent SOC 2 audit.
- Aegis Runtime evidence proves production operating effectiveness.
- Aegis Runtime alone owns access-control enforcement.
- Aegis Runtime alone owns control evidence completeness.
Required Agent 2 follow-up

The SOC 2 / Control Alignment Agent must create or update:

docs/aegis/AEGIS_RUNTIME_CONTROL_SCOPE.md
docs/aegis/AEGIS_RUNTIME_CONTROL_OWNERSHIP_MATRIX.md
docs/aegis/AEGIS_RUNTIME_EVIDENCE_MAP.md
docs/aegis/AEGIS_RUNTIME_CHANGE_MANAGEMENT.md
docs/aegis/AEGIS_RUNTIME_SYSTEM_BOUNDARY.md
Current conclusion

Aegis Runtime has SOC 2-aligned evidence potential at the runtime signal, audit, decision-context, session-visibility, and monitoring layers.

The current state is alignment-supporting, not certification-grade, and not yet complete for control ownership or operating effectiveness.


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

