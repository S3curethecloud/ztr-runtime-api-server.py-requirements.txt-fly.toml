
RiskDNA System of Record Map

Status: Agent 3 / Evidence Recorded

Purpose

This document identifies the current system of record for RiskDNA-related logic, outputs, and downstream renderers.

System-of-record matrix
Domain	System of record	Files / evidence	Renderers / consumers	Notes
RiskDNA risk computation	RiskDNA runtime logic	api/blast_simulator.py, api/risk_engine.py	Token path, Decision Intelligence, Aegis-rendered views	Primary RiskDNA logic.
Blast radius	Runtime topology / RiskDNA logic	api/blast_simulator.py	Runtime/Aegis/Decision Intelligence	Topology-based risk context.
Recent-window risk	RiskDNA alerting / runtime telemetry	api/alerts.py	Runtime observability / UI	Alert status stored in Redis.
Token risk context	Runtime token path	api/tokens.py	OPA, audit, session storage	RiskDNA is a contributor, not owner of token issuance.
Aegis enriched risk	Runtime token context	api/tokens.py, core/aegis_identity/	OPA, audit, session storage	Aegis modifies context but does not decide.
Decision Intelligence aggregation	Runtime Intelligence	api/intelligence.py	UI / Copilot / evidence views	Ownership pending final doctrine.
Copilot risk explanation	Copilot explanation bridge	api/copilot_bridge.py, api/copilot_aegis.py	Copilot-facing surfaces	Explanation only.
RiskDNA alert state	Redis/runtime alert state	api/alerts.py	Runtime observability	Redis key ownership belongs to runtime infra.
OPA decision outcome	OPA / policy bundle	policies/, policy-bundle/, opa_bridge.py	Runtime token path	OPA is decision authority.
Non-system-of-record surfaces

The following may render or explain RiskDNA but are not the RiskDNA system of record:

Aegis Identity
Aegis temporal views
Aegis acknowledgement views
Copilot explanations
Decision Intelligence dashboards
session listing surfaces
audit viewers
Current conclusion

RiskDNA’s system of record is its runtime risk computation and risk telemetry path, not the Aegis rendering layer.

Runtime remains system of record for token/session side effects, and OPA remains system of record for policy decisions.


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

