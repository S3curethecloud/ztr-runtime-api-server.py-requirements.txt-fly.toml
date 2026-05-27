
Kubernetes / SENTINEL From Aegis Baseline Map

Status: Agent 7 / Baseline Inheritance Mapping In Progress

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
