# Agent Instructions

## SecureTheCloud Doctrine Control Plane Adoption

This repository consumes canonical SecureTheCloud doctrine from:

```text
S3curethecloud/securethecloud-doctrine-control-plane

Before building or changing Aegis Runtime, RiskDNA, runtime evidence, authority boundaries, product packaging, SENTINEL assumptions, ASZ/Blackbox/Kubernetes inheritance, SOC 2 claims, Helm claims, or customer-facing claims, agents must read the doctrine-control-plane first.

Required first-read files:

AGENTS.md
doctrine.lock.md
docs/portfolio/AGENT_CONSUMPTION_GUIDE.md
docs/portfolio/SUITE_CATALOG.md
docs/portfolio/MODULE_AUTHORITY_MATRIX.md
docs/portfolio/STATUS_TAXONOMY.md
docs/portfolio/COMPOSITION_LAYER_DOCTRINE.md
docs/portfolio/SENTINEL_CONTROL_POINT_RULE.md
docs/portfolio/PRODUCT_PACKAGING_BOUNDARIES.md
contracts/portfolio/*.json

Canonical Phase 7 commit adopted by this repository:

5fbfb08 — Complete Phase 7 Aegis Runtime RiskDNA doctrine delta

Local documentation must not override canonical doctrine-control-plane.

If local documentation conflicts with canonical doctrine, canonical doctrine controls unless updated through a governed doctrine phase.

This repository must not invent suite membership, module authority, callable interfaces, forbidden actions, packaging boundaries, status taxonomy values, SENTINEL bypasses, SOC 2 claims, Helm claims, or runtime authority.
