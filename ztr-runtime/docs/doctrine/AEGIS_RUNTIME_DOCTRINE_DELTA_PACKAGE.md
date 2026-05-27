
Aegis Runtime Doctrine Delta Package

Status: Doctrine Update Agent / Delta Package Draft

Purpose

This document records recommended doctrine deltas for a future doctrine-control-plane update.

This is not the canonical doctrine update.

Recommended portfolio doctrine delta

Aegis Runtime should be described as:

A bounded runtime signal, evidence, and rendering participant that contributes
context to runtime decision flows without owning enforcement, token issuance,
session lifecycle, OPA policy decisions, SENTINEL adapter authority, ASZ
authorization, Blackbox evidence package authority, or production enforcement.
Recommended RiskDNA doctrine delta

RiskDNA should be described as:

A logical runtime risk-context and scoring participant that computes risk,
blast-radius, topology-risk, and recent-window-risk context. RiskDNA informs
runtime decision context but does not authorize, issue tokens, create sessions,
replace OPA, or own enforcement.
Recommended Composition Layer doctrine delta

Composition Layer should preserve this rule:

Aegis Runtime and RiskDNA may be represented as planning-ready logical
boundaries, but not as independently deployable packages, Helm toggles, or
production routing units until future implementation evidence proves clean
package boundaries.
Recommended SENTINEL doctrine delta

SENTINEL should preserve this rule:

SENTINEL may consume Aegis/RiskDNA context only through governed contracts.
Aegis informs. RiskDNA informs. OPA decides where policy evaluation is required.
SENTINEL controls Kubernetes runtime adapter boundaries. Runtime owns
token/session side effects.
Recommended ASZ doctrine delta

ASZ should preserve this rule:

ASZ verifies cross-domain evidence only. It may consume Aegis/RiskDNA evidence
as assertion input but must not authorize runtime execution, issue tokens,
create sessions, replace RiskDNA, replace OPA, or mutate runtime authority.
Recommended Blackbox doctrine delta

Blackbox should preserve this rule:

Blackbox records and reviews evidence. It may package Aegis/RiskDNA runtime
evidence but must not become runtime authority, token authority, session
authority, OPA authority, Vault reference resolver, RiskDNA system of record, or
Aegis Runtime Core.
Recommended packaging doctrine delta

Packaging doctrine should state:

Aegis Runtime and RiskDNA are not yet proven independent deployment units.
No Helm toggle, suite module, package decomposition, disable/enable behavior,
or production routing claim is authorized until future evidence proves clean
interfaces, dependency boundaries, deployment overlays, tests, and doctrine
approval.
Recommended SOC 2 doctrine delta

SOC 2 doctrine should state:

Aegis Runtime evidence supports SOC 2-aligned readiness at the signal,
decision-context, evidence, observability, and auditability layers. It does not
claim SOC 2 certification, independent audit completion, production operating
effectiveness, or complete control ownership.
Required future doctrine validation

Before applying these deltas, doctrine-control-plane must validate:

suite membership
module ownership
authority type
callable interfaces
status taxonomy values
product packaging boundaries
SOC 2 traceability
machine-readable contract updates
doctrine.lock.md update requirements
phase tracker requirements
Current conclusion

The recommended doctrine update is a boundary-preserving readiness update.

It must not be converted into a packaging, production, SOC 2 certification, or enforcement claim.
