# LAB Runtime Mapping — AWS Role Chaining Escalation

## Status

Active / Controlled LAB Runtime Mapping

## Lab Identity

Lab ID:

```text
aws-role-chaining-escalation

Linked Shield finding:

shield-rolechain-001

Runtime anchor:

Aegis Identity Integrity / Decision Intelligence
Purpose

This mapping connects the Principal LAB aws-role-chaining-escalation to the SecureTheCloud Runtime signal model.

The LAB teaches how chained sts:AssumeRole paths can create deterministic privilege expansion when an initial principal can reach an intermediate role that can then assume a more privileged downstream role.

Runtime Doctrine
Runtime = source of truth
RiskDNA = runtime risk context
Aegis Identity Integrity = bounded signal
OPA = sole decision authority
Frontend = rendering only
Aegis Signal Model

Expected signal:

IDENTITY_DRIFT_DETECTED

Expected risk modifier threshold:

>= 20

Decision authority:

OPA
Scenario

A principal can assume an intermediate role, and that intermediate role can assume a downstream privileged role.

This creates a deterministic transitive role chain:

Low-Privilege Principal
    ->
sts:AssumeRole into IntermediateRole
    ->
sts:AssumeRole into PrivilegedRole
    ->
Expanded Permissions / Administrative Blast Radius
Runtime Evidence Inputs

The Aegis Identity assessment should use bounded local evidence such as:

principal identity
requested intent
action scopes
RiskDNA score
recent denial count
policy drift state
lab identifier
linked Shield finding identifier
Example Aegis Assessment Context
{
  "tenant_id": "tenant-beta",
  "principal": "rolechain-lab-principal",
  "intent": "sts:AssumeRole",
  "scopes": ["sts:AssumeRole"],
  "context": {
    "risk_score": 80,
    "device_trust": true,
    "session_binding": "rolechain-lab-session",
    "lab_id": "aws-role-chaining-escalation",
    "linked_shield_finding": "shield-rolechain-001"
  },
  "recent_denials": 3,
  "policy_drift": false
}
Boundary

This mapping does not:

authorize access
deny access by itself
issue tokens
create sessions
mutate runtime truth
override OPA
bypass RiskDNA
bypass audit
assume a real AWS role
remediate IAM policy

OPA remains final.
