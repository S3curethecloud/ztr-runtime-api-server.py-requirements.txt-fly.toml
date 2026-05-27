
RiskDNA Runtime Dependency Contract

Status: Agent 3 / Evidence Recorded

Purpose

This document defines the current dependency contract between RiskDNA, Aegis Runtime, Runtime token/session orchestration, OPA, audit, observability, and Copilot-facing explanation surfaces.

Contract rules
RiskDNA computes runtime risk context.
Aegis may consume and render RiskDNA context.
Aegis may enrich context with bounded signals.
Runtime owns token/session side effects.
OPA owns policy decisions.
Audit records evidence.
Copilot explains but does not enforce.
Required RiskDNA outputs

RiskDNA outputs may include:

risk_score
final_score
blast_radius
topology_risk
recent_window_risk
decision context
stale/healthy alert state
Required consumers
Consumer	Allowed use	Forbidden use
Runtime token path	Include RiskDNA in policy context	Treat RiskDNA as authorization authority
Aegis Identity	Use RiskDNA context as input	Bypass RiskDNA or override OPA
OPA	Evaluate policy using RiskDNA context	Accept RiskDNA as external allow/deny authority
Sessions	Store/display risk context	Let RiskDNA own session lifecycle
Audit	Record risk context evidence	Store unbounded sensitive material
Decision Intelligence	Aggregate and explain risk	Claim independent enforcement
Copilot	Explain posture	Enforce, authorize, or mutate runtime state
Runtime flow contract
runtime request
→ runtime context
→ blast radius / topology evaluation
→ RiskDNA score
→ optional Aegis Identity enrichment
→ OPA policy evaluation
→ audit/session/runtime evidence
Change control

RiskDNA changes require review when they affect:

risk scoring semantics
RiskDNA output schema
blast-radius behavior
topology risk behavior
recent-window risk behavior
token path context shape
OPA policy input shape
audit evidence payloads
Decision Intelligence aggregation
Aegis Identity input assumptions
Forbidden assumptions
RiskDNA is not token authority.
RiskDNA is not session authority.
RiskDNA is not OPA.
RiskDNA is not Aegis Core.
RiskDNA is not Copilot.
RiskDNA is not the audit chain.
RiskDNA is not production enforcement.
Current conclusion

RiskDNA is a separable logical module, but current code remains coupled through runtime token issuance, Aegis Identity enrichment, Decision Intelligence, observability, audit, Redis, and OPA input flows.

Future decomposition must preserve this contract before moving RiskDNA behind independent module boundaries.


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

