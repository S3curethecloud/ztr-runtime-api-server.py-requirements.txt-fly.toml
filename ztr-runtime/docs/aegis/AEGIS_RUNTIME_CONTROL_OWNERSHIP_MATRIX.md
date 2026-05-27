# Aegis Runtime Control Ownership Matrix

Status: Agent 2 / Evidence Recorded

## Purpose

This matrix maps runtime capabilities to control objectives, primary control owner, supporting owner, evidence source, system of record, review cadence, and change approval path.

## Control ownership matrix

| Runtime capability | Control objective | Primary control owner | Supporting owner | Evidence source | System of record | Review cadence | Change approval path |
|---|---|---|---|---|---|---|---|
| Token issuance visibility | Ensure token decisions use governed risk and policy context | Runtime / OPA | RiskDNA, Aegis Identity, Audit | `api/tokens.py`, OPA result, audit/session payloads | Runtime token path | Per release and policy change | Runtime + OPA + Aegis/RiskDNA if context fields change |
| Session lifecycle visibility | Ensure active sessions are visible and traceable | Runtime session owner | Aegis signal context, Audit | `api/sessions.py`, Redis session keys | Runtime session store | Per release | Runtime session owner |
| Revoke controls | Ensure revocation is controlled and auditable | Runtime session owner | Audit, Observability | `api/sessions.py`, revocation events, counters | Runtime session store | Per release and incident review | Runtime session owner + Audit |
| Runtime integrity checks | Ensure runtime identity/integrity posture is visible | Runtime | Aegis Identity | `runtime_identity.py`, `tests/test_integrity.py`, Aegis docs | Runtime | Per release | Runtime owner |
| Runtime observability metrics | Ensure runtime health and counters are visible | Runtime Observability | Sessions, Redis, Prometheus | `api/observability.py`, `api/metrics.py`, `prometheus/alerts.yml` | Runtime metrics / Redis | Operational review cadence pending | Observability owner |
| RiskDNA decision views | Ensure risk context is computed and explainable | RiskDNA | Runtime, Aegis-rendered views | `api/blast_simulator.py`, `api/risk_engine.py`, `api/alerts.py` | Runtime risk context | Per release and model/rule update | RiskDNA owner |
| Decision explainability | Ensure decisions can be explained without authority escalation | Runtime Intelligence / Copilot | Aegis, RiskDNA, Audit | `api/intelligence.py`, `api/copilot_aegis.py`, `api/copilot_bridge.py`, `api/explainer.py` | Runtime evidence/risk aggregation | Per release | Runtime Intelligence + Copilot |
| Audit chain rendering | Ensure events are traceable and audit-safe | Runtime evidence owner | Aegis, RiskDNA, Sessions | `api/audit.py`, `audit_chain.py` | Runtime audit chain | Per release and audit review | Runtime evidence owner |
| Tenant inventory | Ensure tenant context is available for runtime governance views | Control Plane / Runtime | Observability, Intelligence | `api/control_plane.py`, `api/control_plane_registry.py` | Control-plane registry / Redis | Per release | Control Plane owner |
| Runtime health / Redis health | Ensure runtime state backend health is visible | Runtime Observability | Runtime infrastructure | `redis.yaml`, `api/observability.py`, Redis key usage evidence | Redis / runtime metrics | Operational review cadence pending | Runtime infrastructure + Observability |
| Policy revision visibility | Ensure policy behavior is deterministic and reviewable | OPA / policy owner | Runtime, Aegis/RiskDNA context providers | `policies/`, `policy-bundle/`, `opa_bridge.py`, tests | OPA policy bundle | Per policy change | OPA / policy owner |
| Aegis Identity signal generation | Ensure Aegis produces bounded non-authoritative signals | Aegis Runtime | RiskDNA, Runtime | `core/aegis_identity/`, fixtures, tests | Aegis Identity module | Per release and signal-rule change | Aegis Runtime owner |
| Aegis acknowledgement | Ensure Aegis acknowledgement state is traceable | Aegis Runtime | Redis, Audit | `api/aegis_ack.py` | Redis Aegis ack keys | Per release | Aegis Runtime + Audit if event shape changes |
| Aegis temporal/timeline | Ensure Aegis timeline view is traceable | Aegis Runtime | Redis, Audit | `api/aegis_temporal.py` | Redis Aegis timeline keys | Per release | Aegis Runtime + Audit if event shape changes |

## Separation of duties

```text
Aegis produces bounded signals.
RiskDNA computes risk context.
OPA decides where policy evaluation is required.
Runtime owns token/session side effects.
Audit owns shared evidence chain.
Observability owns runtime health visibility.
Control Plane owns tenant/control-plane inventory.
Copilot explains but does not enforce.
Known gaps
formal review cadence is not yet assigned for every capability
audit retention and tamper-evidence guarantees require deeper evidence mapping
Decision Intelligence owner is not yet doctrine-final
cross-platform inherited controls are not yet mapped
production operating effectiveness is not proven


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

