
RiskDNA System of Record Map

Status: Agent 3 / RiskDNA Alignment In Progress

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
