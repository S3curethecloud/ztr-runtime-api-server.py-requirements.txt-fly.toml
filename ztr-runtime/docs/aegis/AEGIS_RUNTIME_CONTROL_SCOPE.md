# Aegis Runtime Control Scope

Status: Agent 2 / SOC 2 Control Alignment In Progress

## Purpose

This document defines which controls Aegis Runtime directly supports, which controls it only visualizes, which controls it depends on from other systems, and which controls are outside Aegis authority.

This document is SOC 2-aligned readiness evidence only. It does not claim SOC 2 certification, independent audit completion, production operating effectiveness, or final compliance readiness.

## Scope rule

Aegis Runtime is a bounded runtime signal, evidence, and visibility layer.

Aegis may:

```text
produce bounded runtime signals
enrich risk context
render evidence and timelines
support Decision Intelligence context
support audit and monitoring visibility
provide deterministic fixtures and tests

Aegis must not:

authorize execution
issue tokens as owner
create sessions as owner
revoke sessions as owner
replace OPA
replace RiskDNA
replace Runtime session ownership
replace audit-chain ownership
resolve Vault references
perform production enforcement
Controls Aegis enforces directly
Control area	Direct Aegis control?	Current basis	Notes
Aegis Identity signal generation	Yes	core/aegis_identity/	Aegis controls signal calculation and bounded output shape.
Aegis acknowledgement state	Yes	api/aegis_ack.py	Aegis owns acknowledgement semantics, subject to Redis/audit dependencies.
Aegis temporal/timeline rendering	Yes	api/aegis_temporal.py	Aegis owns timeline access semantics, not underlying Redis globally.
Aegis fixtures and deterministic examples	Yes	fixtures/aegis/, tests/test_aegis_identity.py	Aegis owns deterministic test evidence for signal behavior.
Controls Aegis only visualizes or informs
Control area	Aegis role	System of record	Control owner
Token issuance visibility	Context contributor	api/tokens.py runtime path	Runtime / OPA
Session lifecycle visibility	Embedded signal / rendered context	api/sessions.py, Redis session keys	Runtime session owner
Session revoke controls	Visual/context only	api/sessions.py	Runtime session owner
RiskDNA decision views	Rendered/consumed context	api/blast_simulator.py, api/risk_engine.py, api/alerts.py	RiskDNA
Blast-radius views	Rendered/consumed context	api/blast_simulator.py	RiskDNA
Decision Intelligence	Context contributor	api/intelligence.py	Runtime Intelligence owner pending
Audit chain rendering	Evidence contributor/consumer	api/audit.py, audit_chain.py	Runtime evidence owner
Tenant inventory	Context consumer	api/control_plane.py, api/control_plane_registry.py	Control Plane / Runtime
Runtime observability	Context consumer	api/observability.py, api/metrics.py	Runtime Observability
Policy revision visibility	Context only	policies/, policy-bundle/, OPA config	OPA / policy owner
Controls Aegis depends on
Dependency	Why Aegis depends on it	Owner
OPA policy evaluation	Aegis/RiskDNA signals become policy context; OPA decides.	OPA / policy owner
Runtime token path	Token issuance orchestrates RiskDNA, Aegis Identity, OPA, audit, sessions.	Runtime
Runtime session store	Aegis signals may be displayed alongside session data.	Runtime
Redis state	Aegis ack, timeline, alerts, sessions, and metrics use Redis key patterns.	Runtime infrastructure
Audit chain	Aegis events require audit-safe evidence handling.	Runtime evidence owner
RiskDNA	RiskDNA computes runtime risk context consumed by Aegis/Decision Intelligence.	RiskDNA
Observability	Aegis relies on runtime health and metrics surfaces.	Runtime Observability
Control Plane tenant registry	Aegis/Decision Intelligence may use tenant context.	Control Plane / Runtime
Out of scope for Aegis itself
SOC 2 certification
production operating effectiveness proof
OPA decision ownership
Kubernetes admission enforcement
Vault reference resolution
SENTINEL adapter control
ASZ authorization
Blackbox evidence package ownership
Composition Layer module decomposition
Helm/package toggle authority
production domain cutover
traffic cutover
token/session authority transfer
Current conclusion

Aegis Runtime supports SOC 2-aligned control evidence as a signal, context, and visibility layer.

Aegis does not own the full runtime control environment. Final SOC 2 control ownership requires explicit mapping across Runtime, OPA, RiskDNA, Audit, Observability, Control Plane, and downstream agents.
