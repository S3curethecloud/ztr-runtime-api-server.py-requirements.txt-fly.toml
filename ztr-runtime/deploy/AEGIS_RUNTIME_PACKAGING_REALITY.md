# Aegis Runtime Packaging Reality

Status: Agent 6 / Evidence Recorded

## Purpose

This document records the packaging reality for Aegis Runtime after the Aegis, SOC 2/control, RiskDNA, inheritance, SENTINEL, and Composition Layer agents completed their evidence records.

This document does not implement Helm charts, package toggles, deployment routing, suite metadata, or doctrine updates.

## Evidence inputs

```text
docs/aegis/AEGIS_RUNTIME_INVENTORY.md
docs/aegis/AEGIS_RUNTIME_OWNERSHIP_SPLIT.md
docs/aegis/AEGIS_RUNTIME_DEPENDENCY_MAP.md
docs/aegis/AEGIS_RUNTIME_SUITE_ALIGNMENT.md
docs/aegis/AEGIS_RUNTIME_RENDERED_VS_OWNED_SURFACES.md
docs/aegis/AEGIS_RUNTIME_SYSTEM_BOUNDARY.md
docs/aegis/AEGIS_RUNTIME_CONTROL_SCOPE.md
docs/riskdna/RISKDNA_AEGIS_BOUNDARY.md
docs/riskdna/RISKDNA_RUNTIME_DEPENDENCY_CONTRACT.md
docs/cross-platform/AEGIS_BASELINE_INHERITANCE_NORMALIZATION.md
composition/AEGIS_RUNTIME_COMPOSITION_BASELINE.md
sentinel/AEGIS_INTEGRATION_REBASELINE.md
Current packaging truth

Aegis Runtime is not currently proven to be a clean standalone deployable package.

Current repository evidence shows Aegis Runtime is coupled to:

runtime token issuance
runtime session lifecycle
RiskDNA scoring
OPA policy input and bundles
Redis-backed state
audit chain / evidence emission
observability and metrics
tenant/control-plane context
Copilot and explanation surfaces
Decision Intelligence aggregation
Packaging classification
Area	Current packaging status	Reason
Aegis Identity	Package candidate	Bounded under core/aegis_identity/, but runtime token path dependency remains.
Aegis ack / temporal APIs	Runtime-coupled	Depend on Redis, audit, and runtime routing.
RiskDNA scoring	Logical package candidate	Code exists but is coupled to token path and Decision Intelligence.
Token/session flows	Not Aegis package	Runtime-owned side-effect substrate.
OPA policy bundle	Not Aegis package	Policy/OPA-owned dependency.
Audit chain	Not Aegis package	Shared runtime evidence substrate.
Observability	Not Aegis package	Shared runtime metrics substrate.
Copilot Aegis simulation	Not Aegis package	Explanation bridge, cross-suite.
Decision Intelligence	Not yet package-clean	Cross-suite integrated surface.
SENTINEL integration	Not packaged here	Aegis-side baseline only.
Helm readiness
Claim	Status
Aegis Helm toggle exists	Not proven
RiskDNA Helm toggle exists	Not proven
Aegis can be deployed independently	Not proven
RiskDNA can be deployed independently	Not proven
Aegis can be disabled without affecting runtime token/session paths	Not proven
RiskDNA can be disabled without affecting token/session/OPA context paths	Not proven
OPA remains available independently	Existing config present, but packaging contract not complete
Redis dependencies are externalized cleanly	Not proven
Audit/observability dependencies are externalized cleanly	Not proven
Suite readiness
Suite/package claim	Status	Required before claim
Aegis Runtime Core as independent suite module	Not ready	Clean interface, dependency contract, deploy boundary, tests.
RiskDNA as independent suite module	Not ready	Clean scoring interface, storage contract, renderer split, tests.
Decision Intelligence as independent suite module	Not ready	Ownership and source-of-record contract.
Aegis/RiskDNA as shared runtime feature set	Planning-ready	Current docs support planning only.
Aegis as evidence/rendering participant	Ready for doctrine review	Boundary docs recorded.
Packaging blockers
runtime token path still couples RiskDNA and Aegis Identity
session APIs display Aegis context but are runtime-owned
Redis key ownership is not externalized into a package contract
audit-chain ownership remains shared runtime substrate
Decision Intelligence is cross-suite and not package-clean
Copilot bridge crosses explanation/runtime boundaries
OPA policy input fields are shared and not Aegis-owned
destination-platform inheritance is candidate-only, not copied-file proof
Permitted packaging statement

The only currently safe packaging statement is:

Aegis Runtime and RiskDNA have documented logical boundaries and planning-ready
contracts, but are not yet proven to be independently deployable packages or
Helm toggles.
Forbidden packaging statements
Aegis is independently deployable.
RiskDNA is independently deployable.
Aegis has a Helm toggle.
RiskDNA has a Helm toggle.
Aegis can be disabled without runtime impact.
RiskDNA can be disabled without runtime impact.
Aegis owns token/session runtime behavior.
RiskDNA owns authorization.
Composition Layer can safely split Aegis today.
Suite catalog can mark Aegis package decomposition complete.
Required future work

Before independent packaging can be claimed, a future phase must provide:

explicit module interface contracts
dependency injection boundaries
Redis key ownership contracts
audit/event schema contracts
RiskDNA scoring service contract
Aegis Identity service contract
OPA input schema contract
runtime token/session fallback behavior
disable/enable behavior tests
Helm chart or deployment overlay evidence
CI evidence proving package-level test gates
Current conclusion

Aegis Runtime packaging is documented as planning-ready but not implementation-ready.

No Helm, suite, package, deployment, or production routing claim should be made until future evidence proves clean deploy boundaries.


## Agent 6 Evidence Record

Status: Agent 6 Evidence Recorded

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
edc4276 — Record Aegis baseline inheritance evidence status
801a0ed — Add SENTINEL Aegis integration rebaseline
2918bf0 — Record SENTINEL Aegis rebaseline evidence status
700215b — Add Aegis runtime composition baseline
d6f2842 — Record Aegis runtime composition evidence status
6a02bc8 — Add Aegis runtime packaging reality

Evidence inputs:

docs/aegis/AEGIS_RUNTIME_INVENTORY.md
docs/aegis/AEGIS_RUNTIME_OWNERSHIP_SPLIT.md
docs/aegis/AEGIS_RUNTIME_DEPENDENCY_MAP.md
docs/aegis/AEGIS_RUNTIME_SUITE_ALIGNMENT.md
docs/aegis/AEGIS_RUNTIME_RENDERED_VS_OWNED_SURFACES.md
docs/aegis/AEGIS_RUNTIME_SYSTEM_BOUNDARY.md
docs/riskdna/RISKDNA_AEGIS_BOUNDARY.md
docs/riskdna/RISKDNA_RUNTIME_DEPENDENCY_CONTRACT.md
docs/cross-platform/AEGIS_BASELINE_INHERITANCE_NORMALIZATION.md
composition/AEGIS_RUNTIME_COMPOSITION_BASELINE.md
sentinel/AEGIS_INTEGRATION_REBASELINE.md

Agent 6 exit position:

Aegis Runtime packaging reality is recorded.

Aegis Runtime and RiskDNA have documented logical boundaries and planning-ready
contracts, but they are not yet proven to be independently deployable packages,
suite modules, Helm toggles, or production routing units.

Future package or Helm claims require explicit interface contracts, deployment
evidence, CI evidence, disable/enable behavior tests, and doctrine approval.

