# Aegis Runtime Composition Baseline

Status: Agent 5 / Composition Layer Baseline In Progress

## Purpose

This document records how Aegis Runtime should be treated by the Composition Layer after the Aegis, SOC 2/control, RiskDNA, inheritance, and SENTINEL re-baseline agents completed their evidence records.

This document does not implement Composition Layer routing, package selection, Helm toggles, or suite decomposition.

## Evidence inputs

```text
docs/aegis/AEGIS_RUNTIME_INVENTORY.md
docs/aegis/AEGIS_RUNTIME_OWNERSHIP_SPLIT.md
docs/aegis/AEGIS_RUNTIME_DEPENDENCY_MAP.md
docs/aegis/AEGIS_RUNTIME_SUITE_ALIGNMENT.md
docs/aegis/AEGIS_RUNTIME_RENDERED_VS_OWNED_SURFACES.md
docs/aegis/AEGIS_RUNTIME_SYSTEM_BOUNDARY.md
docs/aegis/AEGIS_RUNTIME_CONTROL_SCOPE.md
docs/riskdna/RISKDNA_AEGIS_BOUNDARY.md
docs/riskdna/RISKDNA_SYSTEM_OF_RECORD_MAP.md
docs/riskdna/RISKDNA_RUNTIME_DEPENDENCY_CONTRACT.md
docs/cross-platform/AEGIS_BASELINE_INHERITANCE_NORMALIZATION.md
sentinel/AEGIS_INTEGRATION_REBASELINE.md
Composition baseline

Aegis Runtime must be treated as a coupled runtime participant, not as a clean isolated package.

Current composition classification:

Aegis Runtime = bounded runtime signal + evidence/rendering participant
RiskDNA = runtime risk context and scoring participant
Runtime = token/session/audit/observability/control-plane substrate
OPA = policy decision authority
SENTINEL = Kubernetes runtime adapter boundary, future consumer only
What Composition Layer may do

The Composition Layer may:

reference Aegis as a bounded runtime signal participant
reference RiskDNA as a runtime risk-context participant
show Aegis/RiskDNA as integrated with runtime token/session/audit context
display documented boundaries between Aegis, RiskDNA, Runtime, OPA, and SENTINEL
use these docs as readiness inputs for future decomposition planning
What Composition Layer must not do

The Composition Layer must not:

treat Aegis as a fully independent package
treat RiskDNA as fully separated in code
treat Aegis as token/session authority
treat Aegis as OPA replacement
treat RiskDNA as authorization authority
treat SENTINEL as Aegis Runtime Core
treat Blackbox evidence as runtime authorization
treat ASZ verification as runtime authorization
claim Helm/package decomposition is complete
infer suite membership from copied files alone
release production composition changes from this document
Composition ownership map
Surface	Composition classification	Owner preserved
core/aegis_identity/	Aegis-owned bounded signal component	Aegis Runtime
api/aegis_ack.py	Aegis-owned evidence/state surface	Aegis Runtime
api/aegis_temporal.py	Aegis-owned evidence/timeline surface	Aegis Runtime
api/blast_simulator.py	RiskDNA-owned analysis logic, runtime-coupled	RiskDNA
api/risk_engine.py	RiskDNA-owned risk logic, runtime-coupled	RiskDNA
api/tokens.py	Shared runtime substrate	Runtime / OPA
api/sessions.py	Shared runtime substrate	Runtime
api/intelligence.py	Cross-suite integrated surface	Runtime Intelligence pending final doctrine
api/copilot_aegis.py	Explanation/simulation surface	Copilot + Aegis context
api/copilot_bridge.py	Explanation bridge	Copilot + Runtime
api/audit.py, audit_chain.py	Shared evidence substrate	Runtime evidence owner
policies/, policy-bundle/	Policy decision dependency	OPA / policy owner
sentinel/AEGIS_INTEGRATION_REBASELINE.md	Handoff baseline	Aegis-side documentation only
Composition readiness status
Area	Status	Reason
Aegis as bounded signal participant	Ready for doctrine review	Agent 1/2 evidence recorded.
RiskDNA as logical module	Ready for doctrine review	Agent 3 evidence recorded.
Aegis/RiskDNA split	Partially ready	Code remains coupled; docs clarify boundary.
Token/session ownership	Ready for boundary preservation	Runtime ownership explicitly documented.
OPA decision authority	Ready for boundary preservation	OPA preserved as decision owner.
SENTINEL integration	Ready as Aegis-side handoff only	SENTINEL repo not updated in this phase.
Helm/package toggle	Not ready	Package decomposition not implemented or proven.
Final suite catalog update	Not ready	Doctrine update must happen later.
Current conclusion

The Composition Layer may consume this baseline as planning evidence.

It must not convert Aegis Runtime into a clean package, suite, Helm toggle, or enforcement authority until future implementation and doctrine phases explicitly prove that decomposition.
