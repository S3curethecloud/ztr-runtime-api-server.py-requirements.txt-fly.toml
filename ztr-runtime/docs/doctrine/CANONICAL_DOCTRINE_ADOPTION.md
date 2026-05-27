# Canonical Doctrine Adoption

Status: Phase 8 / Downstream Repository Adoption In Progress

## Purpose

This document records that the Aegis/RiskDNA runtime repository consumes the canonical SecureTheCloud doctrine-control-plane instead of maintaining local substitute doctrine.

This file is an adoption pointer and evidence record only.

It does not create runtime behavior, Helm packaging, production routing, authorization behavior, token issuance, session creation, OPA replacement, SENTINEL bypass, or production enforcement.

## Canonical doctrine source

Canonical repository:

```text
S3curethecloud/securethecloud-doctrine-control-plane

Canonical Phase 7 commit:

5fbfb08 — Complete Phase 7 Aegis Runtime RiskDNA doctrine delta

Supporting Phase 7 commit:

226f5d1 — Add Phase 7 Aegis Runtime RiskDNA doctrine delta
Required first-read files

Before building or changing this repository, agents must read the doctrine-control-plane first:

AGENTS.md
doctrine.lock.md
docs/portfolio/AGENT_CONSUMPTION_GUIDE.md
docs/portfolio/SUITE_CATALOG.md
docs/portfolio/MODULE_AUTHORITY_MATRIX.md
docs/portfolio/STATUS_TAXONOMY.md
docs/portfolio/COMPOSITION_LAYER_DOCTRINE.md
docs/portfolio/SENTINEL_CONTROL_POINT_RULE.md
docs/portfolio/PRODUCT_PACKAGING_BOUNDARIES.md
docs/soc2/SOC2_ALIGNMENT_OVERVIEW.md
docs/soc2/SOC2_CONTROL_TRACEABILITY.md
docs/soc2/SOC2_EVIDENCE_REGISTER.md
docs/soc2/SOC2_CHANGE_MANAGEMENT.md
contracts/portfolio/suite_catalog.json
contracts/portfolio/module_registry.json
contracts/portfolio/authority_matrix.json
contracts/portfolio/composition_rules.json
contracts/portfolio/status_taxonomy.json
Adopted Phase 7 doctrine truth

The runtime repository adopts the following canonical truths:

Aegis Runtime is a bounded runtime signal, evidence, and rendering participant.
RiskDNA is a logical runtime risk-context and scoring participant.
Aegis informs.
RiskDNA informs.
OPA decides where policy evaluation is required.
SENTINEL remains canonical for runtime-impacting control decisions.
Runtime owns token/session side effects.
Composition does not create authority.
Packaging does not create authority.
Evidence does not create enforcement authority.
Explanation does not create authorization authority.
Local non-authority rule

This repository must not use local documentation to override canonical doctrine.

If local documentation conflicts with doctrine-control-plane, doctrine-control-plane controls unless updated through a governed doctrine phase.

Forbidden local substitute doctrine

This repository must not locally redefine:

suite names
suite membership
module authority
callable interfaces
forbidden actions
product packaging boundaries
status taxonomy values
SENTINEL bypasses
SOC 2 claims
runtime authority
Helm packaging claims
production enforcement claims
Explicit non-claims

This adoption record does not claim:

SOC 2 certification
production operating effectiveness
independent Aegis Runtime Helm toggle
independent RiskDNA Helm toggle
production routing
deployment decomposition
SENTINEL repository implementation update
ASZ / Blackbox / Kubernetes copied-file inheritance proof
runtime authority grant
token issuance grant
authorization behavior grant
runtime session creation grant
provider mutation grant
Kubernetes mutation grant
production enforcement grant
Current conclusion

The Aegis/RiskDNA runtime repository now consumes canonical Phase 7 doctrine as the source of truth for Aegis Runtime and RiskDNA authority boundaries.

This adoption is documentation-only and does not change runtime behavior.
