# Aegis Runtime Change Management

Status: Agent 2 / Evidence Recorded

## Purpose

This document defines risk levels and review requirements for changes to Aegis Runtime surfaces.

## Change risk levels

### Low risk

Low-risk changes are documentation, comments, formatting, or test fixture clarifications that do not alter runtime behavior.

Examples:

```text
docs/aegis/* wording updates
docs/lab-mappings/* clarification
test fixture naming cleanup
non-functional comments

Required review:

Aegis Runtime owner
Medium risk

Medium-risk changes alter Aegis signal interpretation, evidence shape, rendered views, metrics, or non-authoritative context.

Examples:

core/aegis_identity feature extraction changes
Aegis acknowledgement payload shape changes
Aegis temporal timeline output changes
RiskDNA rendered view changes
Decision Intelligence aggregation display changes
observability metric naming changes
audit event metadata changes

Required review:

Aegis Runtime owner
Runtime owner
Audit/evidence owner if event shape changes
RiskDNA owner if risk context changes
High risk

High-risk changes alter token/session behavior, OPA policy inputs, deny/allow behavior, runtime side effects, control ownership, or cross-suite authority boundaries.

Examples:

api/tokens.py behavior changes
api/sessions.py revoke behavior changes
policies/*.rego decision changes
policy-bundle changes
OPA bridge behavior changes
Redis key schema changes
audit chain integrity behavior changes
RiskDNA scoring semantics
Aegis signal risk modifier semantics
tenant/control-plane registry semantics

Required review:

Runtime owner
OPA / policy owner
Aegis Runtime owner when Aegis context changes
RiskDNA owner when risk scoring changes
Audit/evidence owner when evidence changes
Control Plane owner when tenant registry changes
SOC 2/control alignment owner when control evidence changes
Changes requiring cross-agent review
Aegis/RiskDNA boundary changes
Aegis signal authority changes
RiskDNA scoring ownership changes
Decision Intelligence ownership changes
OPA policy input schema changes
session/token side-effect changes
audit chain or evidence retention changes
SENTINEL integration assumptions
Composition Layer decomposition claims
Helm/package toggle claims
ASZ/Blackbox/Kubernetes baseline inheritance claims
portfolio doctrine changes
SOC 2 marketing or compliance claims
Changes affecting controls

Any change to the following requires SOC 2/control alignment review:

token issuance visibility
session lifecycle visibility
revoke controls
runtime integrity checks
runtime observability metrics
RiskDNA decision views
decision explainability
audit chain rendering
tenant inventory
runtime health / Redis health
policy revision visibility
Aegis Identity signal generation
Forbidden during this gate without later approval
new suite reassignment involving Aegis
new Helm decomposition claims for Aegis
new SENTINEL integration assumptions about Aegis
new SOC 2 marketing claims tied to Aegis
claiming Aegis is just another module
claiming Aegis owns enforcement
claiming Aegis owns token/session lifecycle
claiming RiskDNA is fully separated before code supports it
Change approval rule

If a change alters authority, system of record, evidence source, control owner, policy behavior, token/session behavior, or cross-platform inheritance, it must be reviewed under the highest applicable risk level.


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

