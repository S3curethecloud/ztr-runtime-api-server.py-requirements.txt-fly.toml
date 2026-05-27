
Aegis Runtime Rendered vs Owned Surfaces

Status: Phase 1 / Agent 1 Evidence Recorded

Purpose

This document separates what Aegis owns from what Aegis only renders or participates in.

This distinction is critical because Aegis currently appears in runtime, RiskDNA, session, OPA, audit, Copilot, and Decision Intelligence flows.

Classification rules
Label	Meaning
Owned	Aegis owns the business logic and change approval should include Aegis ownership.
Rendered	Aegis or the runtime experience displays/uses the surface, but another system owns the business logic.
Shared	Aegis participates in a coupled runtime flow; no clean owner split exists yet.
Dependency	Aegis relies on the surface but does not own or render it as primary owner.
Rendered vs owned matrix
Surface / file	Does Aegis own business logic?	Does Aegis render it?	System of record	Evidence source	Change approval owner	Current classification
core/aegis_identity/	Yes	Yes	Runtime context / Aegis Identity module	Aegis Identity assessment output and tests	Aegis Runtime + Runtime owner	Owned
aegis_engine.py	Likely yes	Yes	Runtime	Runtime/Aegis events	Aegis Runtime	Owned pending code review
aegis_stream.py	Partially	Yes	Runtime stream / Redis	Streamed Aegis runtime events	Runtime + Aegis	Shared
api/aegis_ack.py	Yes	Yes	Redis Aegis ack keys	Ack event/audit payloads	Aegis Runtime	Owned
api/aegis_temporal.py	Yes	Yes	Redis Aegis timeline keys	Temporal access events and timeline keys	Aegis Runtime	Owned
api/blast_simulator.py	No	Yes / consumed by Aegis experience	Runtime topology/RiskDNA	RiskDNA score and blast-radius result	RiskDNA	Rendered
api/risk_engine.py	No	Yes / consumed by Aegis experience	Runtime risk context	Risk engine outputs	RiskDNA	Rendered
api/alerts.py RiskDNA endpoints	No	Yes / status-rendered	Redis RiskDNA alert keys	RiskDNA stale/open/resolved events	RiskDNA + Observability	Rendered
api/tokens.py	No	No direct UI render	Runtime token issuance path	Token decision/audit/session payloads	Runtime + OPA policy owner	Shared dependency
api/sessions.py	No	Aegis signal embedded in session response	Redis session keys	Session hashes, Aegis signal lookup, audit events	Runtime session owner	Rendered/shared
api/intelligence.py	No clean split	Yes / integrated intelligence surface	Runtime risk/tenant aggregation	Redis/runtime aggregation	Runtime Intelligence owner pending	Shared
api/copilot_aegis.py	No, explanation only	Yes, simulated Aegis signal	Request risk context	Simulation response	Copilot + Aegis review	Rendered/explanation
api/copilot_bridge.py	No	Runtime/Copilot bridge	Runtime metrics/evidence	Metrics/session/policy counters	Copilot + Runtime	Rendered/explanation
api/observability.py	No	Aegis may consume status	Runtime metrics/Redis	Metrics counters and Prometheus output	Runtime Observability	Dependency
api/audit.py	No	Aegis evidence may be shown	Runtime audit store/chain	Audit events	Runtime evidence owner	Dependency
audit_chain.py	No	No direct render	Audit chain	Audit chain records	Runtime evidence owner	Dependency
policies/issue.rego	No	No	OPA policy bundle	Policy evaluation result	OPA/policy owner	Dependency
policy-bundle/policies/issue.rego	No	No	Policy bundle	Policy bundle	OPA/policy owner	Dependency
fixtures/aegis/	Yes	Test/docs only	Repository fixtures	Fixture JSON and tests	Aegis Runtime	Owned test/evidence fixture
docs/lab-mappings/*aegis-runtime.md	Partially	Docs only	Repository docs	Mapping docs	Aegis + RiskDNA docs owner	Shared evidence mapping
Business logic Aegis owns

Aegis owns:

- Aegis Identity signal generation
- Aegis-specific acknowledgement state
- Aegis-specific temporal/timeline views
- Aegis-specific fixtures
- Aegis-specific runtime evidence mappings
Business logic Aegis does not own

Aegis does not own:

- token issuance
- session creation
- session revocation
- OPA policy decisions
- RiskDNA scoring as a standalone logic domain
- blast-radius computation as RiskDNA logic
- tenant registry
- control-plane registry
- Redis runtime state generally
- audit chain as a whole
- Copilot explanation authority
- production enforcement
Current ambiguity

The following surfaces are not yet clean enough for final doctrine updates:

api/intelligence.py
api/copilot_bridge.py
api/copilot_aegis.py
api/tokens.py
api/sessions.py
aegis_stream.py

These should remain marked as coupled/shared until follow-up source review or decomposition contracts prove otherwise.

Gate rule

Aegis may inform, enrich, explain, and render bounded context.

Aegis must not be treated as the system of record for enforcement, token issuance, session lifecycle, OPA decisions, tenant registry, or production control-plane authority.


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

