
Kubernetes / SENTINEL From Aegis Baseline Map

Status: Agent 7 / Evidence Recorded

Purpose

This document records Aegis Runtime baseline patterns that may have influenced Kubernetes/SENTINEL and identifies assumptions that must become explicit contracts.

This file does not claim a copied file is confirmed unless destination evidence is recorded.

Candidate inherited patterns
Aegis baseline source	Possible Kubernetes/SENTINEL inheritance	Current proof level	Required normalization
policies/issue.rego	OPA policy structure / context fields	Candidate	OPA remains local decision authority.
policy-bundle/	Policy bundle layout	Candidate	Bundle ownership must be explicit.
opa_bridge.py	OPA invocation assumptions	Candidate	SENTINEL may call OPA but must not override OPA.
opa-config.yaml, opa-sidecar.yaml	OPA sidecar deployment assumptions	Candidate	Kubernetes deployment config must not imply Aegis ownership.
api/tokens.py context shape	Admission/runtime policy input assumptions	Candidate	SENTINEL must not duplicate token issuance.
api/blast_simulator.py / RiskDNA context	Risk context input	Candidate	RiskDNA informs only.
core/aegis_identity/	Aegis context fields	Candidate	Aegis signals only; no enforcement authority.
api/observability.py, prometheus/alerts.yml	Runtime metrics / alerting patterns	Candidate	SENTINEL metrics must be adapter-owned, not Aegis-owned.
Assumptions to convert into explicit contracts
SENTINEL is the Kubernetes runtime adapter control point.
OPA remains deterministic local decision authority.
Aegis informs but does not enforce.
RiskDNA informs but does not authorize.
SENTINEL must not become a second Aegis command center.
SENTINEL must not duplicate Aegis runtime shell logic.
SENTINEL must not import token/session authority from Aegis.
Required destination evidence search

Search Kubernetes/SENTINEL repositories for:

aegis_identity
compute_riskdna
simulate_blast_radius
deny_aegis
IDENTITY_DRIFT_DETECTED
policy-bundle
opa_bridge
ztr:aegis
riskdna
Current conclusion

Kubernetes/SENTINEL inheritance from Aegis is not yet proven at the file-copy level.

The main normalization requirement is to ensure SENTINEL consumes documented Aegis truth without duplicating Aegis runtime shell behavior or inheriting hidden token/session assumptions.


## Agent 7 Evidence Record

Status: Agent 7 Evidence Recorded

Evidence commits:

```text
0a07fa6 — Add Aegis runtime phase 1 truth anchor docs
f06cab9 — Add Aegis runtime Agent 1 alignment docs
6b76a29 — Add Aegis runtime Agent 1 verification evidence
ae62832 — Record Aegis runtime Agent 1 evidence status
ac6758e — Add Aegis runtime SOC 2 control alignment docs
2e1195b — Record Aegis runtime Agent 2 evidence status
a35869e — Add RiskDNA Aegis boundary alignment docs
36239bf — Record RiskDNA Aegis alignment evidence status
0215863 — Add Aegis baseline inheritance normalization docs

Evidence inputs:

docs/aegis/AEGIS_RUNTIME_INVENTORY.md
docs/aegis/AEGIS_RUNTIME_OWNERSHIP_SPLIT.md
docs/aegis/AEGIS_RUNTIME_DEPENDENCY_MAP.md
docs/aegis/AEGIS_RUNTIME_BASELINE_EXPORTS_TO_OTHER_PLATFORMS.md
docs/aegis/AEGIS_RUNTIME_RENDERED_VS_OWNED_SURFACES.md
docs/riskdna/RISKDNA_AEGIS_BOUNDARY.md
docs/riskdna/RISKDNA_RUNTIME_DEPENDENCY_CONTRACT.md
docs/aegis/evidence/AEGIS_RUNTIME_ROUTE_EVIDENCE.md
docs/aegis/evidence/AEGIS_RUNTIME_REDIS_STATE_EVIDENCE.md
docs/aegis/evidence/AEGIS_RUNTIME_RISKDNA_AEGIS_OPA_FLOW_EVIDENCE.md

Agent 7 exit position:

ASZ, Blackbox, and Kubernetes/SENTINEL candidate inheritance from Aegis Runtime
is now visible and normalized into explicit contract requirements.

Copied-file inheritance is not claimed as final proof unless destination
repository evidence is later recorded. Hidden inheritance assumptions are now
blocked from becoming implicit authority transfers.

