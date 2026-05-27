# Aegis Runtime Evidence Map

Status: Agent 2 / SOC 2 Control Alignment In Progress

## Purpose

This document maps each Aegis Runtime surface to evidence source, storage location, producer/display role, tamper-evidence status, SOC 2 support suitability, and remaining gaps.

## Evidence map

| Surface | Evidence relied on | Where evidence is stored | Produces or displays? | Tamper-evident? | SOC 2 support suitability | Gaps |
|---|---|---|---|---|---|---|
| Aegis Identity | Signal output, feature vector, score, tests, fixtures | Runtime context, fixtures, tests | Produces | Not fully proven | Supports control design evidence | Retention and approval path pending |
| Aegis acknowledgement | Ack records and audit events | Redis ack keys; audit payloads | Produces/displays | Not fully proven | Supports operational evidence | Redis retention/tamper controls pending |
| Aegis temporal | Timeline keys and temporal access events | Redis timeline keys; audit payloads | Displays | Not fully proven | Supports reviewability | Timeline retention/integrity pending |
| RiskDNA scoring | Risk score, final score, blast radius, topology context | Runtime context / API response / session/audit payloads | Produces outside Aegis; displayed by runtime | Not fully proven | Supports security monitoring context | RiskDNA validation cadence pending |
| Token issuance path | OPA result, RiskDNA context, Aegis Identity signal, audit/session writes | Runtime audit/session storage | Produces runtime evidence | Not fully proven | Strong SOC 2 relevance | Runtime/OPA owner proof pending |
| Session lifecycle | Active session hashes, revoke events, counters | Redis session keys, audit events, metrics | Produces/displays | Not fully proven | Strong SOC 2 relevance | Session retention/review cadence pending |
| Observability | Active session counts, revoked counts, runtime metrics | Redis counters, Prometheus output | Displays | Not fully proven | Supports monitoring evidence | Metric integrity and alert review pending |
| Audit chain | Runtime audit events | Audit chain implementation/storage | Produces/displays | Partially indicated, not proven | Strong SOC 2 relevance | Tamper-evidence design must be verified |
| Decision Intelligence | Tenant risk aggregation, runtime evidence, RiskDNA/Aegis context | Runtime aggregation / Redis | Displays/aggregates | Not fully proven | Supports explainability | Owner and source contracts pending |
| Copilot Aegis simulation | Simulated Aegis signal from risk input | API response, possible audit if recorded | Displays/explains | Not applicable unless persisted | Limited support | Must remain explanation-only |
| Policy / OPA | Policy bundle, Rego tests, OPA result | Policy files, policy bundle, runtime evaluation result | Produces decisions | Policy files are version-controlled | Strong control design evidence | Runtime evaluation evidence retention pending |
| Tenant inventory | Tenant registry and control-plane records | Redis/control-plane registry | Displays | Not fully proven | Supports scoping and access review | Registry ownership and review cadence pending |

## Evidence files recorded during Agent 1

```text
docs/aegis/evidence/AEGIS_RUNTIME_ROUTE_EVIDENCE.md
docs/aegis/evidence/AEGIS_RUNTIME_REDIS_STATE_EVIDENCE.md
docs/aegis/evidence/AEGIS_RUNTIME_RISKDNA_AEGIS_OPA_FLOW_EVIDENCE.md
Suitability levels
Level	Meaning
Strong	Directly supports SOC 2 control design or evidence traceability, subject to owner/review validation.
Moderate	Supports context, monitoring, or explanation but needs control owner validation.
Limited	Useful for explanation/demo only, not sufficient as control evidence alone.
Current conclusion

Aegis Runtime evidence is useful for SOC 2-aligned control design and review support, especially for runtime signal traceability, token/session context, policy-input context, and auditability.

It is not yet sufficient for certification-grade evidence because retention, tamper-evidence, review cadence, owner approval, and production operating effectiveness are not fully documented.
