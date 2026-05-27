# Aegis Runtime System Boundary

Status: Agent 2 / SOC 2 Control Alignment In Progress

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
