
RiskDNA Rendering Surfaces

Status: Agent 3 / Evidence Recorded

Purpose

This document identifies where RiskDNA logic is rendered, consumed, or explained through runtime, Aegis, Copilot, or Decision Intelligence surfaces.

Rendering surface matrix
Surface	File / pattern	RiskDNA role	Renderer / consumer	Notes
RiskDNA scoring	api/blast_simulator.py, compute_riskdna	Producer	Runtime token path, Decision Intelligence	Core risk context computation.
Blast radius	api/blast_simulator.py, simulate_blast_radius, summarize_blast	Producer	Runtime/Aegis/Decision Intelligence	Topology and blast-radius evidence.
RiskDNA alerts	api/alerts.py, /v1/alerts/riskdna	Producer/status	Runtime observability / UI	Stale/healthy stream status.
Latest RiskDNA decision	api/alerts.py, /v1/alerts/riskdna/latest-decision	Producer/status	Runtime observability / UI	Latest decision status rendering.
Token issuance context	api/tokens.py	Context provider	Runtime / OPA / audit / sessions	RiskDNA computed before Aegis Identity and OPA.
Decision Intelligence	api/intelligence.py	Context provider	Runtime Intelligence / UI	Aggregates risk/tenant context.
Copilot bridge	api/copilot_bridge.py	Context provider	Copilot explanation	Explains runtime/risk posture.
Copilot Aegis simulate	api/copilot_aegis.py	Input signal context	Copilot/Aegis simulation	Uses risk input to simulate Aegis signal.
Aegis Identity docs	docs/AEGIS_IDENTITY_INTEGRITY_RUNTIME_EXTENSION_SOT.md	Upstream risk context	Aegis Identity	RiskDNA feeds Aegis Identity context.
Lab mappings	docs/lab-mappings/*aegis-runtime.md	Risk context	Aegis evidence docs	Maps AWS scenarios into RiskDNA/Aegis evidence.
Rendered vs owned rule

RiskDNA-owned logic may be rendered by Aegis, runtime UI, Copilot, or Decision Intelligence.

Rendering does not transfer ownership.

Current ambiguous rendering surfaces
api/intelligence.py
api/copilot_bridge.py
api/copilot_aegis.py
docs/lab-mappings/*aegis-runtime.md

These surfaces should remain integrated/coupled until later module contracts define final ownership.

Conclusion

RiskDNA analysis is already consumed across the runtime experience, but rendering and ownership are not identical. Downstream agents must not classify every RiskDNA-rendered surface as Aegis-owned.


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

