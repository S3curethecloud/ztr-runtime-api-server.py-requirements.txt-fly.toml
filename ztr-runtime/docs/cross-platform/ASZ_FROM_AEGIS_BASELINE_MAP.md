# ASZ From Aegis Baseline Map

Status: Agent 7 / Baseline Inheritance Mapping In Progress

## Purpose

This document records Aegis Runtime baseline patterns that may have influenced ASZ and identifies which assumptions must become explicit contracts.

This file does not claim a copied file is confirmed unless destination evidence is recorded.

## Current evidence position

Aegis Runtime source contains reusable baseline patterns around:

```text
Aegis Identity signal context
RiskDNA risk context
runtime token/session orchestration
OPA policy-input structure
Redis state conventions
audit/event evidence
tenant/control-plane context
Decision Intelligence and explanation surfaces
Candidate inherited patterns
Aegis baseline source	Possible ASZ inheritance	Current proof level	Required normalization
core/aegis_identity/	ASZ assertion context for identity integrity	Candidate	ASZ may verify context but must not authorize.
api/tokens.py risk context flow	Token/risk handoff assumptions	Candidate	Runtime/OPA remains token decision owner.
api/blast_simulator.py / RiskDNA	Risk evidence context	Candidate	RiskDNA computes risk; ASZ verifies cross-domain evidence only.
api/audit.py / audit_chain.py	Audit evidence shape	Candidate	ASZ evidence must not become runtime source of truth.
policies/issue.rego context fields	Policy-input assumptions	Candidate	ASZ must not override OPA decisions.
docs/lab-mappings/*aegis-runtime.md	Cross-domain attack scenario mapping	Candidate	Lab mappings must become explicit assertion contracts.
fixtures/aegis/	Deterministic scenario inputs	Candidate	Fixtures may support ASZ assertions but are not authorization.
Assumptions to convert into explicit contracts
ASZ verifies cross-domain evidence only.
ASZ does not authorize runtime execution.
ASZ does not issue tokens.
ASZ does not create or revoke sessions.
ASZ does not replace RiskDNA.
ASZ does not replace OPA.
ASZ may consume Aegis/RiskDNA evidence as assertion input only.
Required destination evidence search

Search ASZ repositories for:

aegis_identity
evaluate_identity_integrity
compute_riskdna
simulate_blast_radius
ztr:aegis
riskdna
Decision Intelligence
IDENTITY_DRIFT_DETECTED
Current conclusion

ASZ inheritance from Aegis is not yet proven at the file-copy level.

The main normalization requirement is to ensure ASZ remains a verification/assertion layer, not a runtime authorization or enforcement layer.
