# SENTINEL Aegis Integration Re-baseline

Status: Agent 4 / SENTINEL Re-baseline In Progress

## Purpose

This document records the Aegis-side SENTINEL integration re-baseline after the Aegis Runtime, SOC 2/control, RiskDNA, and baseline-inheritance agents completed their evidence records.

This file does not claim SENTINEL repository implementation has changed.

## Evidence inputs

```text
docs/aegis/AEGIS_RUNTIME_INVENTORY.md
docs/aegis/AEGIS_RUNTIME_OWNERSHIP_SPLIT.md
docs/aegis/AEGIS_RUNTIME_DEPENDENCY_MAP.md
docs/aegis/AEGIS_RUNTIME_RENDERED_VS_OWNED_SURFACES.md
docs/aegis/AEGIS_RUNTIME_SYSTEM_BOUNDARY.md
docs/riskdna/RISKDNA_AEGIS_BOUNDARY.md
docs/riskdna/RISKDNA_RUNTIME_DEPENDENCY_CONTRACT.md
docs/cross-platform/KUBERNETES_FROM_AEGIS_BASELINE_MAP.md
docs/cross-platform/AEGIS_BASELINE_INHERITANCE_NORMALIZATION.md
SENTINEL boundary restatement

SENTINEL must treat Aegis as:

bounded runtime signal source
risk/context contributor
evidence context contributor
possible UI/evidence source
not an enforcement authority
not a token/session authority
not an OPA replacement
not a Vault reference resolver
not a Kubernetes admission controller
not a duplicate command center
Integration interpretation
Aegis / RiskDNA surface	SENTINEL interpretation	Boundary
Aegis Identity signal	Optional policy-input context if explicitly contracted	Signal only; no authority transfer
RiskDNA score	Optional risk context if explicitly contracted	Risk informs; does not authorize
Blast-radius context	Optional evidence/context input	Not enforcement by itself
Aegis temporal/ack surfaces	Evidence/visibility only	Not runtime control
Token/session context	Runtime-owned evidence only	SENTINEL must not infer token/session ownership
OPA context fields	Policy input only	OPA remains decision authority
Audit chain evidence	Evidence source only	SENTINEL must not own Aegis audit chain
Redis key conventions	Implementation detail	Do not infer ownership from key names
Decision Intelligence	Explanation/context surface	Not enforcement
What SENTINEL may consume

SENTINEL may consume Aegis/RiskDNA information only when a governed contract defines:

source field
meaning
freshness
system of record
owner
allowed use
forbidden use
evidence handling
failure mode
Required fail-closed rules
If Aegis context is missing, SENTINEL must not invent it.
If RiskDNA context is stale, SENTINEL must not treat it as current.
If Aegis/RiskDNA ownership is ambiguous, SENTINEL must classify it as pending contract.
If OPA context fields are malformed, OPA/policy handling must fail closed according to SENTINEL policy.
If a caller attempts to use Aegis as enforcement authority, deny the authority transfer.
Explicit forbidden integrations
SENTINEL must not duplicate the Aegis command center.
SENTINEL must not become Aegis Runtime Core.
SENTINEL must not copy token issuance behavior from Aegis Runtime.
SENTINEL must not copy session lifecycle behavior from Aegis Runtime.
SENTINEL must not use Aegis to bypass OPA.
SENTINEL must not use RiskDNA to bypass OPA.
SENTINEL must not resolve Vault references through Aegis.
SENTINEL must not treat Blackbox evidence as runtime authorization.
SENTINEL must not treat ASZ verification as runtime authorization.
Current re-baseline conclusion

The Aegis-side integration baseline for SENTINEL is now:

Aegis informs.
RiskDNA informs.
SENTINEL controls Kubernetes runtime adapter boundaries.
OPA decides where policy evaluation is required.
Runtime owns token/session side effects.
Evidence systems record; they do not authorize.
Pending SENTINEL repository action

A future SENTINEL-repo phase may update SENTINEL-owned documentation to consume this Aegis-side re-baseline.

Until that happens, this file is an Aegis-runtime-side handoff baseline only.
