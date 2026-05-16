# LAB Runtime Mapping — AWS Privilege Escalation via iam:PassRole

## Status

Active / Controlled LAB Runtime Mapping

## Lab Identity

Lab ID:

```text
aws-privilege-escalation-passrole

Linked Shield finding:

shield-passrole-001

Runtime anchor:

Aegis Identity Integrity / Decision Intelligence
Purpose

This mapping connects the Principal LAB aws-privilege-escalation-passrole to the SecureTheCloud Runtime signal model.

The LAB teaches how iam:PassRole combined with compute service creation or update capability can create a deterministic privilege escalation path.

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

A low-privilege principal has:

iam:PassRole
permission to pass a privileged execution role
compute service creation or update capability
access to bind the privileged role to the compute service

This creates a deterministic privilege escalation path:

Low-Privilege Principal
    ↓
iam:PassRole
    ↓
Lambda Create/Update Capability
    ↓
AdminExecutionRole
    ↓
Elevated Runtime Risk
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
  "principal": "passrole-lab-principal",
  "intent": "iam:PassRole",
  "scopes": ["iam:PassRole"],
  "context": {
    "risk_score": 80,
    "device_trust": true,
    "session_binding": "passrole-lab-session",
    "lab_id": "aws-privilege-escalation-passrole",
    "linked_shield_finding": "shield-passrole-001"
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
deploy infrastructure
remediate IAM policy

OPA remains final.

Completion Criteria

This mapping is complete when:

the mapping document exists
the PassRole Aegis fixture exists
the Aegis unit test validates the expected signal
the test confirms no allow, deny, or authorized field is emitted by Aegis
the runtime working tree is clean after commit
