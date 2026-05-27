# Aegis Runtime System Boundary

Status: Agent 2 / Evidence Recorded

## Purpose

This document defines the system boundary for Aegis Runtime in the current repository state.

## In boundary

Aegis Runtime boundary includes:

```text
core/aegis_identity/
aegis_engine.py
aegis_stream.py
api/aegis_ack.py
api/aegis_temporal.py
fixtures/aegis/
docs/lab-mappings/*aegis-runtime.md
Aegis-related tests
Aegis fields contributed into runtime context
Aegis fields displayed through session/intelligence/Copilot surfaces
Adjacent but not Aegis-owned
api/tokens.py
api/sessions.py
api/blast_simulator.py
api/risk_engine.py
api/alerts.py
api/intelligence.py
api/copilot_aegis.py
api/copilot_bridge.py
api/observability.py
api/metrics.py
api/audit.py
audit_chain.py
api/control_plane.py
api/control_plane_registry.py
policies/
policy-bundle/
opa_bridge.py
redis.yaml
prometheus/alerts.yml
Out of boundary
SENTINEL runtime adapter authority
Kubernetes admission enforcement
Vault reference resolution
ASZ authorization
Blackbox evidence package ownership
Composition Layer module decomposition authority
Helm packaging claims
production traffic cutover
production enforcement
SOC 2 certification
independent audit operation
System-of-record boundaries
Domain	System of record	Aegis role
Aegis signal generation	Aegis Runtime / core/aegis_identity/	Owner
RiskDNA scoring	RiskDNA runtime logic	Consumer/renderer
Token issuance	Runtime token path	Context contributor
Session lifecycle	Runtime session store	Context contributor/display
Policy decisions	OPA / policy bundle	Context input only
Audit chain	Runtime evidence/audit chain	Evidence contributor/consumer
Observability	Runtime metrics/observability	Consumer
Tenant inventory	Control Plane / Runtime registry	Consumer
Copilot explanation	Copilot / explanation surfaces	Context provider
Baseline inheritance	Destination platform repos	Candidate source only until confirmed
Boundary conclusion

Aegis Runtime is a bounded signal, evidence, and rendering participant inside a coupled runtime.

It is not the whole runtime, not the enforcement authority, not the policy decision authority, and not the production control plane.


## Agent 2 Evidence Record

Status: Agent 2 Evidence Recorded

Evidence commits:

```text
0a07fa6 — Add Aegis runtime phase 1 truth anchor docs
f06cab9 — Add Aegis runtime Agent 1 alignment docs
6b76a29 — Add Aegis runtime Agent 1 verification evidence
ae62832 — Record Aegis runtime Agent 1 evidence status
ac6758e — Add Aegis runtime SOC 2 control alignment docs

Evidence inputs:

docs/aegis/AEGIS_RUNTIME_INVENTORY.md
docs/aegis/AEGIS_RUNTIME_OWNERSHIP_SPLIT.md
docs/aegis/AEGIS_RUNTIME_DEPENDENCY_MAP.md
docs/aegis/AEGIS_RUNTIME_SUITE_ALIGNMENT.md
docs/aegis/AEGIS_RUNTIME_SOC2_ALIGNMENT.md
docs/aegis/AEGIS_RUNTIME_RENDERED_VS_OWNED_SURFACES.md
docs/aegis/AEGIS_RUNTIME_BASELINE_EXPORTS_TO_OTHER_PLATFORMS.md
docs/aegis/evidence/AEGIS_RUNTIME_ROUTE_EVIDENCE.md
docs/aegis/evidence/AEGIS_RUNTIME_REDIS_STATE_EVIDENCE.md
docs/aegis/evidence/AEGIS_RUNTIME_RISKDNA_AEGIS_OPA_FLOW_EVIDENCE.md

Agent 2 exit position:

Aegis Runtime control scope, control ownership, evidence mapping, change
management, and system boundary are recorded as SOC 2-aligned readiness
evidence.

This record does not claim SOC 2 certification, independent audit completion,
production operating effectiveness, or final compliance readiness.

Remaining downstream work is reserved for RiskDNA boundary alignment,
cross-platform inheritance normalization, SENTINEL re-baselining, Composition
Layer readiness, Helm/package scope, and doctrine updates.

