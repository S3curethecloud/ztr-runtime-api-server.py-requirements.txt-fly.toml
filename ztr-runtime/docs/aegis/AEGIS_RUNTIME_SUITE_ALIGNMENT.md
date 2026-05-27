# Aegis Runtime Suite Alignment

Status: Phase 1 / Agent 1 Evidence Recorded

## Purpose

This document maps current Aegis Runtime surfaces into SecureTheCloud suite-alignment buckets without pretending the runtime is cleaner or more modular than the repository currently proves.

## Alignment buckets

Every Aegis-related surface is classified into one of:

```text
Runtime Governance & Enforcement
RiskDNA-integrated analysis surface
Platform shell / experience shell
Shared runtime substrate
Not yet suite-clean
Suite alignment matrix
Surface / file	Alignment bucket	Current rationale	Notes
core/aegis_identity/	Runtime Governance & Enforcement	Bounded Aegis identity signal generation runs inside runtime token flow and feeds OPA context.	Signal-only; not decision authority.
aegis_engine.py	Runtime Governance & Enforcement	Aegis runtime engine behavior belongs to runtime signal/evidence context.	Requires deeper code review before stable contract.
aegis_stream.py	Shared runtime substrate	Runtime streaming appears coupled to Aegis signal publication/consumption.	Coupled until stream contract is separated.
api/aegis_ack.py	Runtime Governance & Enforcement	Aegis acknowledgement surface records Aegis-specific operational state.	Aegis-owned surface with Redis/audit dependency.
api/aegis_temporal.py	Runtime Governance & Enforcement	Aegis temporal timeline surface renders Aegis signal history.	Aegis-owned evidence/timeline surface.
api/blast_simulator.py	RiskDNA-integrated analysis surface	Contains blast radius simulation and RiskDNA scoring.	RiskDNA logic may be rendered inside Aegis experience.
api/risk_engine.py	RiskDNA-integrated analysis surface	Risk engine behavior belongs to RiskDNA analysis.	Must be separated from Aegis ownership claims.
api/alerts.py	RiskDNA-integrated analysis surface	RiskDNA stale/latest-decision alert endpoints.	RiskDNA status surface, runtime-rendered.
api/intelligence.py	Not yet suite-clean	Decision Intelligence aggregates runtime/risk/tenant context.	Cross-suite integrated surface; ownership needs formal contract.
api/copilot_aegis.py	Not yet suite-clean	Copilot-facing Aegis simulation/explanation surface.	Explanation only; no enforcement authority.
api/copilot_bridge.py	Not yet suite-clean	Bridges runtime/session/policy metrics into Copilot-style explanation.	Cross-suite integration.
api/tokens.py	Shared runtime substrate	Token path orchestrates RiskDNA, Aegis Identity, OPA, sessions, audit.	Too coupled to split today.
api/sessions.py	Shared runtime substrate	Session listing/revoke embeds Aegis signal context but is not Aegis-owned.	Runtime owns lifecycle side effects.
api/observability.py	Shared runtime substrate	Runtime metrics, sessions, revocation counters, tenant-level observability.	Shared runtime observability.
api/metrics.py	Shared runtime substrate	Runtime metric aggregation.	Shared substrate.
api/audit.py	Shared runtime substrate	Audit/event surface supporting multiple runtime capabilities.	Evidence substrate, not Aegis-only.
audit_chain.py	Shared runtime substrate	Audit-chain implementation used by runtime evidence.	SOC 2 mapping required later.
api/control_plane.py	Shared runtime substrate	Tenant/session/control-plane runtime operations.	Not Aegis-owned.
api/control_plane_registry.py	Shared runtime substrate	Tenant registry/inventory behavior.	Shared runtime/control-plane substrate.
policies/issue.rego	Runtime Governance & Enforcement	OPA policy receives Aegis/RiskDNA context and decides.	OPA remains decision authority.
policy-bundle/	Runtime Governance & Enforcement	Bundled policy artifacts.	Policy packaging, not Aegis ownership.
fixtures/aegis/	Runtime Governance & Enforcement	Deterministic Aegis fixtures for identity/risk scenarios.	Evidence/test input surface.
docs/lab-mappings/*aegis-runtime.md	RiskDNA-integrated analysis surface	Maps AWS attack scenarios into Aegis/RiskDNA/Decision Intelligence evidence.	Documentation/evidence mapping, not enforcement.
Current suite truth

Aegis Runtime is currently a coupled runtime substrate that includes:

- Aegis-owned bounded intelligence signal generation
- RiskDNA scoring and blast-radius analysis
- shared token/session/audit/observability runtime infrastructure
- OPA policy decision dependencies
- Copilot-facing explanation/simulation surfaces
- tenant/control-plane runtime inventory dependencies
Explicit non-claims

This document does not claim:

- Aegis is fully modularized
- RiskDNA is fully separated in code
- Decision Intelligence has a clean independent module boundary
- Helm/package decomposition is complete
- Aegis owns token issuance or session lifecycle
- Aegis owns policy decision authority
- Aegis is SOC 2 certified
Required follow-up

The doctrine/control-plane agent must later update portfolio doctrine only after this alignment is reconciled with:

docs/aegis/AEGIS_RUNTIME_INVENTORY.md
docs/aegis/AEGIS_RUNTIME_OWNERSHIP_SPLIT.md
docs/aegis/AEGIS_RUNTIME_DEPENDENCY_MAP.md
docs/aegis/AEGIS_RUNTIME_RENDERED_VS_OWNED_SURFACES.md


## Agent 1 Evidence Record

Status: Agent 1 Evidence Recorded

Evidence commits:

```text
0a07fa6 — Add Aegis runtime phase 1 truth anchor docs
f06cab9 — Add Aegis runtime Agent 1 alignment docs
6b76a29 — Add Aegis runtime Agent 1 verification evidence

Evidence files:

docs/aegis/evidence/AEGIS_RUNTIME_ROUTE_EVIDENCE.md
docs/aegis/evidence/AEGIS_RUNTIME_REDIS_STATE_EVIDENCE.md
docs/aegis/evidence/AEGIS_RUNTIME_RISKDNA_AEGIS_OPA_FLOW_EVIDENCE.md

Agent 1 exit position:

Aegis Runtime inventory, ownership split, dependency map, suite alignment,
rendered-vs-owned classification, baseline export candidate map, and initial
SOC 2 alignment are now recorded with repository evidence.

Remaining unresolved items are intentionally reserved for downstream agents:
SOC 2 control ownership, RiskDNA/Aegis boundary hardening, cross-platform
inheritance confirmation, SENTINEL re-baseline, Composition Layer readiness,
Helm/package scope, and doctrine updates.

