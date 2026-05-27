
RiskDNA Runtime Dependency Contract

Status: Agent 3 / RiskDNA Alignment In Progress

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
