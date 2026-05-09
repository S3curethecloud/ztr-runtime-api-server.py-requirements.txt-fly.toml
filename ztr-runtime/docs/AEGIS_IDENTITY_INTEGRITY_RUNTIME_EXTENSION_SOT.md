# SecureTheCloud — Aegis Identity Integrity / Adversarial Robustness Runtime Extension SoT

## 1. Document Control

**Type:** Runtime Extension Source of Truth  
**Status:** Active / Controlled  
**Scope:** SecureTheCloud Runtime / Aegis Core  
**Feature Name:** Aegis Identity Integrity v0.1  
**Strategic Theme:** Identity Integrity + Adversarial Robustness as bounded runtime intelligence  
**Owner:** Platform Custodian  
**Approver:** Execution Owner  
**Recommended Path:** `docs/AEGIS_IDENTITY_INTEGRITY_RUNTIME_EXTENSION_SOT.md`

---

## 2. Decision

Embed **Identity Integrity / Adversarial Robustness** into **SecureTheCloud Runtime** as a bounded Aegis extension.

This is not a new standalone platform at this stage.

The extension lives inside the Runtime because the SecureTheCloud baseline defines Runtime as the source of truth, OPA as the sole decision authority, Control Plane as governance, Frontend as rendering, and Aegis Core as bounded intelligence only. :contentReference[oaicite:0]{index=0}

---

## 3. Purpose

The purpose of this extension is to add an identity-aware, adversarially robust signal layer into the Runtime authorization path.

The extension evaluates whether a principal, workload, agent, or runtime identity still behaves consistently with expected identity posture.

It produces bounded intelligence signals such as:

```text
IDENTITY_STABLE
IDENTITY_DRIFT_DETECTED
INSUFFICIENT_DATA

These signals are used as risk context for RiskDNA and OPA.

They do not directly authorize or deny execution.

4. Strategic Goal

The strategic goal is to evolve SecureTheCloud from basic runtime authorization into:

Continuous Identity Integrity Governance

This means the Runtime no longer evaluates only static request fields such as principal, scope, and tenant. It also evaluates behavioral integrity, identity drift, recent deny pressure, policy drift, and adversarial risk posture.

This creates the foundation for a future active-defense model:

Identity Integrity
→ Behavioral Drift Detection
→ Adversarial Robustness
→ Challenge / Response
→ Cross-Zone Trust Context
→ Kubernetes / Sentinel Runtime Policy
5. Why This Is Embedded, Not a New Platform

The extension is embedded into SecureTheCloud Runtime because:

Runtime is already the authoritative execution and telemetry layer.
OPA already governs allow/deny decisions.
RiskDNA already computes runtime risk context.
Aegis Core already owns bounded intelligence signals.
Audit, usage, billing, blast radius, and Decision Intelligence already consume runtime truth.

A standalone repo would introduce unnecessary fragmentation at this stage.

The correct architecture is:

Request
→ Runtime Context
→ RiskDNA
→ Aegis Identity Integrity
→ OPA
→ Runtime Decision
→ Audit / Sessions / Usage / Decision Intelligence
6. Core Doctrine

This extension must preserve the SecureTheCloud doctrine:

Runtime = source of truth
OPA = sole decision authority
Aegis Core = bounded intelligence only
Frontend = rendering only

Aegis Identity Integrity may produce signals and risk modifiers.

It must not:

authorize requests
deny requests by itself
issue tokens
create sessions
mutate runtime truth outside the approved token issue path
override OPA
override tenant policy
bypass control-plane governance
bypass audit
bypass RiskDNA

OPA remains final.

7. What Was Built

A bounded Aegis Identity Integrity module was added under:

core/aegis_identity/

The module evaluates local identity evidence, derives deterministic feature vectors, scores identity risk, and returns a signal object suitable for OPA policy input.

The Runtime token issue path was then modified so that Identity Integrity runs after RiskDNA computation and before OPA evaluation. The patched api/tokens.py imports evaluate_identity_integrity, writes the result under context["aegis_identity"], enriches context["risk_score"], passes the enriched context into OPA, and records the enriched risk score in decision events, audit payloads, and session risk storage.

The OPA issue policy was then patched to deny only when Identity Integrity reports both:

signal == "IDENTITY_DRIFT_DETECTED"
risk_modifier >= 20

The Rego policy keeps OPA as the enforcement authority by adding not deny_identity_integrity to the allow rule.

8. Files Created
8.1 core/aegis_identity/__init__.py
Purpose

Defines the package export surface for the Aegis Identity module.

Responsibilities

Exports:

AEGIS_IDENTITY_SIGNAL_VERSION
AegisIdentityAssessmentRequest
AegisIdentityAssessmentResponse
AegisIdentityFeatureVector
AegisIdentityScore
AegisIdentityService
AegisIdentitySignal
assess_identity
build_identity_features
evaluate_identity_integrity
score_identity_features
Boundary

No runtime wiring.
No route registration.
No token issuance.
No session creation.

8.2 core/aegis_identity/schemas.py
Purpose

Defines the schema contract for Aegis Identity signal evaluation.

Key Models
AegisIdentitySignal
AegisIdentityAssessmentRequest
AegisIdentityFeatureVector
AegisIdentityScore
AegisIdentityAssessmentResponse
Important Fields

AegisIdentityAssessmentRequest includes:

tenant_id
principal
intent
scopes
context
signals
recent_denials
policy_drift
source

AegisIdentityScore includes:

score
tier
signal
confidence
risk_modifier
reasons
evidence
Boundary Fields

The response locks these fields to false:

runtime_authorization_granted: false
token_issued: false
session_created: false

This preserves the rule that Aegis Identity is evidence only.

8.3 core/aegis_identity/features.py
Purpose

Builds a deterministic feature vector from the assessment request.

Responsibilities

Extracts:

signal_count
weighted_signal_total
positive_signal_count
negative_signal_count
max_signal_weight
confidence_average
risk_score
recent_denials
policy_drift
context_keys
Risk Input Handling

The feature extractor supports direct runtime risk input:

context["risk_score"]

and RiskDNA-style nested input:

context["riskdna"]["risk_score"]
context["riskdna"]["final_score"]
Boundary

Feature extraction does not authorize, deny, mutate Redis, issue tokens, create sessions, or call OPA.

8.4 core/aegis_identity/scoring.py
Purpose

Scores the identity feature vector deterministically.

Responsibilities

Computes:

score
tier
signal
confidence
risk_modifier
reasons
evidence
Risk Modifier Logic

The module maps identity risk into bounded risk modifiers:

score >= 85 → risk_modifier 35
score >= 65 → risk_modifier 25
score >= 35 → risk_modifier 15
else       → risk_modifier 0
Signal Logic
INSUFFICIENT_DATA
IDENTITY_STABLE
IDENTITY_DRIFT_DETECTED
Boundary

The score is advisory evidence. It does not grant authorization and does not directly deny requests.

8.5 core/aegis_identity/service.py
Purpose

Provides the local service facade used by Runtime.

Public Functions
AegisIdentityService.assess(...)
assess_identity(...)
evaluate_identity_integrity(...)
Runtime Contract

evaluate_identity_integrity(...) returns a dict shaped for runtime policy input:

{
  "signal": "IDENTITY_STABLE | IDENTITY_DRIFT_DETECTED | INSUFFICIENT_DATA",
  "confidence": 0.95,
  "risk_modifier": 0,
  "reasons": [],
  "decision_authority": "OPA",
  "model": "aegis-identity-v0.1"
}
Boundary

The service does not:

authorize
deny
issue tokens
create sessions
mutate trust registries
register routes
override OPA
8.6 tests/test_aegis_identity.py
Purpose

Validates Aegis Identity module behavior at the Python unit-test level.

Coverage

The test file validates:

normal identity
negative signals
policy drift
recent denials
high modifier
critical tier
identity drift detection
OPA-compatible deny signal shape
stable identity signal does not match deny shape
Important Governance Note

This test file does not replace OPA.

It validates that the signal shape produced by Aegis Identity is compatible with the OPA policy. Actual OPA enforcement is tested separately in Rego.

8.7 policies/issue_identity_test.rego
Purpose

Validates actual OPA behavior for the Identity Integrity policy logic.

Coverage

The Rego test validates:

stable identity signal allows valid issue request
identity drift with high modifier denies issue request
identity drift with low modifier does not trigger identity deny
high modifier without drift does not trigger identity deny
missing aegis_identity preserves existing allow path
existing aegis anomaly still denies
deny_identity_integrity is true for drift + high modifier
deny_identity_integrity is false for stable identity
Boundary

This is the real OPA policy test.

It confirms there is no OPA bypass.

9. Files Modified
9.1 api/tokens.py
Purpose

Runtime token issuance path.

Modification Summary

Added import:

from core.aegis_identity.service import evaluate_identity_integrity

Integrated Identity Integrity inside issue_token() after RiskDNA computation and before OPA evaluation.

New Flow
simulate_blast_radius
→ compute_riskdna
→ evaluate_identity_integrity
→ context["aegis_identity"]
→ context["risk_score"] = RiskDNA final score + identity risk modifier
→ evaluate_issue_policy
→ audit / stream / session
Important Runtime Behavior

The enriched context["risk_score"] is now used for:

policy input
deny decision events
obligation deny decision events
allow decision events
runtime.token_denied audit payloads
runtime.token_issued audit payloads
session risk JSON
Boundary Preserved

api/tokens.py still:

depends on tenant API key
calls OPA through evaluate_issue_policy
enforces obligations after OPA
writes sessions only after allow
emits audit events
publishes decision events
increments usage counters
issues JWT only after policy allow

No unauthorized bypass was introduced.

9.2 policies/issue.rego
Purpose

OPA token issue policy.

Modification Summary

Added Aegis Identity Integrity handling:

aegis_identity_present
identity_drift_detected
identity_high_modifier
deny_identity_integrity

Updated allow condition:

allow if {
    not deny_aegis
    not deny_identity_integrity
    ...
}
Enforcement Rule

OPA denies identity drift only when:

input.context.aegis_identity.signal == "IDENTITY_DRIFT_DETECTED"
input.context.aegis_identity.risk_modifier >= 20
Boundary Preserved

Existing policy logic remains intact:

valid principal
valid tenant
valid intent
valid scopes
intent matches scope
trusted device
valid policy revision
token binding present
risk threshold handling
Aegis anomaly handling
obligations
TTL control
decision output

OPA remains final.

9.3 requirements.txt
Purpose

Runtime dependency specification.

Dependency Notes

The Runtime test environment required:

requests
PyJWT

The app imports requests in the server path and imports jwt through PyJWT in the token path.

DevOps should ensure requirements.txt contains compatible pins.

Observed local environment:

requests==2.33.1
PyJWT==2.12.1

Observed requirements file during validation:

requests==2.33.0
PyJWT==2.12.0

Either version set may be acceptable if CI and deployment resolve cleanly, but DevOps should pin intentionally and consistently.

10. Validation Evidence
10.1 Aegis Identity Unit Tests

Command:

pytest tests/test_aegis_identity.py -q

Result:

9 passed
10.2 Full Runtime Python Suite

Command:

pytest -q

Result:

33 passed
10.3 OPA Policy Tests

Command:

opa fmt -w policies/issue.rego policies/issue_identity_test.rego
opa test policies/

Result:

PASS: 8/8
10.4 Live Runtime Validation

Live UI and curl validation showed:

Normal path:

Risk: 48
Decision: allow
Aegis Signal: NORMAL
Policy Drift: STABLE
Audit Integrity: VALID
Active Session: created

Elevated path:

Risk: 123
Decision: deny
Tier: CRITICAL
Aegis Signal: ANOMALY DETECTED
Audit Integrity: VALID

This confirms the extension is operating as:

Aegis Identity Integrity
→ RiskDNA enriched score
→ OPA issue policy
→ Runtime session/audit/decision surfaces
11. Security and Governance Boundaries
11.1 Aegis Identity Is Signal-Only

Aegis Identity may output:

signal
confidence
risk_modifier
reasons
model
decision_authority

It must not output:

allow: true
deny: true
authorized: true
execution_approved: true
token_issued: true
session_created: true
11.2 OPA Is Final

Aegis Identity never replaces OPA.

The only enforcement decision is made through policies/issue.rego.

11.3 Runtime Remains Source of Truth

Runtime still owns:

session creation
token issuance
audit event emission
usage counters
decision events
JWT signing
tenant runtime context
11.4 Frontend Remains Rendering Only

Frontend may display:

RiskDNA
Aegis signal
Decision Intelligence
Audit integrity
Session posture
Blast radius
Tenant heatmap

Frontend must not invent:

risk score
authorization result
usage truth
billing truth
session truth
policy authority
12. DevOps Deployment Notes
12.1 Files to Deploy

Deploy these files together:

core/aegis_identity/__init__.py
core/aegis_identity/schemas.py
core/aegis_identity/features.py
core/aegis_identity/scoring.py
core/aegis_identity/service.py
api/tokens.py
policies/issue.rego
policies/issue_identity_test.rego
tests/test_aegis_identity.py
requirements.txt
12.2 Required Pre-Deploy Checks

Run:

python -m compileall core/aegis_identity api/tokens.py
pytest tests/test_aegis_identity.py -q
opa fmt -w policies/issue.rego policies/issue_identity_test.rego
opa test policies/
pytest -q

Expected:

Aegis Identity tests pass
OPA policy tests pass
Full runtime tests pass
12.3 Required Environment Variables

Existing runtime requirements remain:

REDIS_URL
POLICY_REVISION
ZTR_JWT_SECRET
ADMIN_SECRET

For local tests:

export REDIS_URL="redis://localhost:6379/0"
export POLICY_REVISION="v1.0.0"
export ZTR_JWT_SECRET="test-secret-value-at-least-32-bytes-long"
export ADMIN_SECRET="test-admin-secret"
12.4 Post-Deploy Live Checks

Normal allow-path request:

curl -X POST https://ztr-runtime.fly.dev/v1/tokens/issue \
  -H "Content-Type: application/json" \
  -H "X-Stc-Api-Key: <ROTATED_TEST_KEY>" \
  -d '{
    "principal": "agent-demo",
    "intent": "refund:create",
    "scopes": ["refund:create"],
    "ttl_seconds": 300,
    "context": {
      "device_trust": true,
      "session_binding": "device-aegis-test",
      "risk_score": 10,
      "after_hours": false
    }
  }'

Expected:

status: issued
decision: allow
risk: medium / normal path
audit integrity remains valid
session appears in active sessions

Elevated risk path should be tested with controlled conditions that produce:

IDENTITY_DRIFT_DETECTED
risk_modifier >= 20

Expected:

HTTP 403
detail: policy_denied
runtime.token_denied audit event
decision event records deny
audit chain remains valid
13. Rollback Plan

If deployment causes runtime instability:

13.1 Revert Runtime Import and Wiring

In api/tokens.py, remove:

from core.aegis_identity.service import evaluate_identity_integrity

and restore:

context = req.context or {}
context["risk_score"] = riskdna["final_score"]

Also restore decision/audit/session risk references to the previous RiskDNA-only final score behavior.

13.2 Revert OPA Policy

In policies/issue.rego, remove:

aegis_identity_present
identity_drift_detected
identity_high_modifier
deny_identity_integrity

and remove:

not deny_identity_integrity

from the allow rule.

13.3 Remove Test-Only Files if Needed

The following files can remain safely because they are not runtime-loaded unless imported, but may be removed for full rollback:

core/aegis_identity/
tests/test_aegis_identity.py
policies/issue_identity_test.rego
13.4 Redeploy Previous Known-Good Runtime

Redeploy the prior runtime image or previous Git commit.

14. Known Limitations

Aegis Identity Integrity v0.1 is deterministic and rule-based.

It does not yet implement:

machine learning model training
real-time media liveness
deepfake detection
adversarial watermarking
challenge-response verification
voice/video biometric verification
ASZ-to-Sentinel adapter integration
Kubernetes workload identity drift scoring

Those are future extensions.

This first milestone intentionally focuses on runtime-safe identity drift signal handling.

15. Future Roadmap
15.1 Near-Term
ASZ → Sentinel Adapter
SentinelPolicyInput contract
Aegis Identity context for ASZ assertions
Kubernetes workload identity signals
OPA policy tests for Sentinel ASZ context
15.2 Mid-Term
Cross-zone identity integrity
Agent behavior baselines
Workload identity drift
Tenant-scoped identity posture
SIEM export of identity integrity signals
15.3 Longer-Term Adversarial Robustness
challenge-response identity verification
semantic integrity scoring
latency-based synthetic media risk
media/object adversarial robustness checks
pre-publication asset immunization
deepfake-resistant runtime access flows
16. Success Criteria

This extension is successful when:

Aegis Identity produces bounded signals
RiskDNA receives enriched risk context
OPA remains final authority
Runtime emits correct audit and decision events
normal identity path still issues tokens
drift/high-modifier path denies through OPA
full tests remain green
Decision Intelligence reflects posture accurately
no frontend invents authority
no new bypass path exists

Current validation status:

Aegis Identity unit tests: passed
OPA policy tests: passed
Runtime full test suite: passed
Live normal path: validated
Live deny path: validated
17. Final Statement

Aegis Identity Integrity v0.1 is a bounded Aegis Runtime extension.

It embeds Identity Integrity and the first foundation of Adversarial Robustness into SecureTheCloud Runtime without creating a new platform, without bypassing OPA, and without destabilizing the baseline control-plane/runtime governance model.

It strengthens SecureTheCloud by moving from static authorization context toward continuous identity-aware runtime governance.

The extension informs.

OPA decides.

Runtime enforces.

Audit proves.
