# LAB Runtime Mapping — AWS Cross-Account Role Escalation

## Status

Active / Controlled LAB Runtime Mapping

## Lab Identity

Lab ID:

```text
aws-cross-account-role-escalation

Linked Shield finding:

shield-xacct-001

Runtime anchor:

Aegis Identity Integrity / Decision Intelligence
Purpose

This mapping connects the Principal LAB aws-cross-account-role-escalation to the SecureTheCloud Runtime signal model.

The LAB teaches how a permissive cross-account trust policy can create a deterministic identity reachability path through sts:AssumeRole.

The runtime mapping explains how that condition should be represented as bounded Aegis identity evidence.

Runtime Doctrine

This mapping preserves the SecureTheCloud doctrine:

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

An external account principal can assume a privileged role in a target AWS account because the target role trust policy allows broad cross-account access.

This creates a deterministic cross-account reachability path:

External Account Principal
    ->
sts:AssumeRole
    ->
Privileged Account Role
    ->
AdministratorAccess / Expanded Blast Radius
Runtime Evidence Inputs

The Aegis Identity assessment should use bounded local evidence such as:

principal identity
intent
scopes
RiskDNA score
recent denial count
policy drift state
negative runtime signal evidence
Example Aegis Assessment Context
{
  "tenant_id": "tenant-beta",
  "principal": "cross-account-lab-principal",
  "intent": "sts:AssumeRole",
  "scopes": ["sts:AssumeRole"],
  "context": {
    "risk_score": 80,
    "device_trust": true,
    "session_binding": "cross-account-lab-session",
    "lab_id": "aws-cross-account-role-escalation",
    "linked_shield_finding": "shield-xacct-001"
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
