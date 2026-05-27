
RiskDNA Rendering Surfaces

Status: Agent 3 / RiskDNA Alignment In Progress

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
