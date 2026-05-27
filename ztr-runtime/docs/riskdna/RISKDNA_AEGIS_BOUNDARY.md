# RiskDNA / Aegis Boundary

Status: Agent 3 / Evidence Recorded

## Purpose

This document separates RiskDNA-owned logic from Aegis-owned signal/rendering responsibilities without pretending the codebase is already fully decomposed.

## Boundary summary

RiskDNA owns runtime risk context and scoring.

Aegis owns bounded runtime signals and Aegis-specific evidence/rendering.

Runtime owns token/session side effects and orchestration.

OPA owns policy decisions.

## Current repository evidence

RiskDNA-relevant source surfaces:

```text
api/blast_simulator.py
api/risk_engine.py
api/alerts.py
api/tokens.py
api/intelligence.py
tests/test_intelligence.py
tests/test_decision_pipeline.py

Aegis-relevant source surfaces:

aegis_engine.py
aegis_stream.py
api/aegis_ack.py
api/aegis_temporal.py
api/copilot_aegis.py
core/aegis_identity/
fixtures/aegis/
tests/test_aegis_identity.py
docs/lab-mappings/*aegis-runtime.md

Shared runtime surfaces:

api/tokens.py
api/sessions.py
api/observability.py
api/audit.py
audit_chain.py
policies/
policy-bundle/
opa_bridge.py
redis.yaml
Boundary matrix
Capability	RiskDNA-owned logic	Aegis-owned logic	Shared runtime artifact	Current classification
RiskDNA Authorization Path	Yes, risk context contribution	No	Yes, token path and OPA input	RiskDNA-owned context, runtime-enforced
RiskDNA Universe	Yes	No	Yes, topology/runtime context	RiskDNA-owned concept, runtime-coupled
RiskDNA Analysis page/API	Yes	No, may render	Yes	RiskDNA-owned but runtime/Aegis-rendered
Decision Intelligence	Partial	Partial signal contributor	Yes	Cross-suite integrated surface
Blast radius cards	Yes	No, may render	Yes	RiskDNA-owned but runtime-rendered
Topology risk	Yes	No	Yes	RiskDNA-owned
Recent-window risk	Yes	No	Yes	RiskDNA-owned, alert/observability-coupled
DDR explanation inputs	Partial	Partial context contributor	Yes	Explanation input, not enforcement
Aegis Identity Integrity	No	Yes	Yes, token context	Aegis-owned bounded signal
Token issuance	No	No	Yes	Runtime/OPA-owned
Session revoke	No	No	Yes	Runtime-owned
Non-negotiable authority boundary
RiskDNA informs.
Aegis signals and renders bounded context.
Runtime orchestrates side effects.
OPA decides where policy evaluation is required.
Explicit non-claims

This document does not claim:

RiskDNA is fully separated in code.
Aegis is only a renderer.
RiskDNA owns token issuance.
Aegis owns RiskDNA scoring.
Decision Intelligence has a final standalone module boundary.
Current conclusion

RiskDNA can be described as its own logical module, but not yet as fully separated code.

Aegis rendering responsibilities and Aegis-owned signal responsibilities must remain explicit to prevent RiskDNA from being confused with Aegis Runtime Core.


## Agent 3 Evidence Record

Status: Agent 3 Evidence Recorded

Evidence commits:

```text
0a07fa6 — Add Aegis runtime phase 1 truth anchor docs
f06cab9 — Add Aegis runtime Agent 1 alignment docs
6b76a29 — Add Aegis runtime Agent 1 verification evidence
ae62832 — Record Aegis runtime Agent 1 evidence status
ac6758e — Add Aegis runtime SOC 2 control alignment docs
2e1195b — Record Aegis runtime Agent 2 evidence status
a35869e — Add RiskDNA Aegis boundary alignment docs

Evidence inputs:

docs/aegis/AEGIS_RUNTIME_INVENTORY.md
docs/aegis/AEGIS_RUNTIME_OWNERSHIP_SPLIT.md
docs/aegis/AEGIS_RUNTIME_DEPENDENCY_MAP.md
docs/aegis/AEGIS_RUNTIME_RENDERED_VS_OWNED_SURFACES.md
docs/aegis/AEGIS_RUNTIME_CONTROL_SCOPE.md
docs/aegis/AEGIS_RUNTIME_CONTROL_OWNERSHIP_MATRIX.md
docs/aegis/AEGIS_RUNTIME_SYSTEM_BOUNDARY.md
docs/aegis/evidence/AEGIS_RUNTIME_ROUTE_EVIDENCE.md
docs/aegis/evidence/AEGIS_RUNTIME_REDIS_STATE_EVIDENCE.md
docs/aegis/evidence/AEGIS_RUNTIME_RISKDNA_AEGIS_OPA_FLOW_EVIDENCE.md

Agent 3 exit position:

RiskDNA is now documented as a separable logical module without claiming it is
fully separated in code.

RiskDNA-owned scoring, blast-radius, topology-risk, recent-window-risk, and
runtime dependency responsibilities are separated from Aegis-owned bounded
signals and Aegis-rendered surfaces.

Runtime and OPA ownership boundaries remain preserved.

