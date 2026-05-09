package ztr.issue

default allow := false

# --------------------------------------------------
# PHASE 8.3 + 8.4 — AEGIS POLICY INTEGRATION + ENFORCEMENT
# --------------------------------------------------

# --------------------------------------------------
# SAFE AEGIS HANDLING (REGO v1 COMPLIANT)
# --------------------------------------------------

aegis_present if {
	input.context.aegis
}

aegis_anomaly if {
	aegis_present
	input.context.aegis.anomaly == true
}

high_velocity if {
	aegis_present
	input.context.aegis.velocity > 5
}

aegis_flagged if {
	aegis_anomaly
}

aegis_flagged if {
	high_velocity
}

aegis_risk_adjusted := adjusted if {
	aegis_present
	adjusted := input.context.risk_score + input.context.aegis.risk_delta
} else := input.context.risk_score

# 🔒 HARD BLOCK
deny_aegis if {
	aegis_anomaly
}

# --------------------------------------------------
# AEGIS IDENTITY INTEGRITY HANDLING
# --------------------------------------------------

aegis_identity_present if {
	input.context.aegis_identity
}

identity_drift_detected if {
	aegis_identity_present
	input.context.aegis_identity.signal == "IDENTITY_DRIFT_DETECTED"
}

identity_high_modifier if {
	aegis_identity_present
	input.context.aegis_identity.risk_modifier >= 20
}

deny_identity_integrity if {
	identity_drift_detected
	identity_high_modifier
}

# --------------------------------------------------
# CORE VALIDATIONS
# --------------------------------------------------

valid_principal if {
	input.principal != ""
}

valid_tenant if {
	input.tenant_id != ""
}

valid_intent if {
	input.intent != ""
}

valid_scopes if {
	count(input.scopes) > 0
}

intent_matches_scope if {
	input.intent == input.scopes[_]
}

trusted_device if {
	input.context.device_trust == true
}

valid_policy_revision if {
	input.policy_revision != ""
}

token_binding_present if {
	input.context.session_binding != ""
}

acceptable_risk if {
	not high_risk
}

high_risk if {
	input.context.risk_score >= 80
}

high_risk if {
	input.context.after_hours == true
	input.context.risk_score >= 60
}

# --------------------------------------------------
# 🔧 STEP 4 ADDITION (NON-DESTRUCTIVE)
# --------------------------------------------------

medium_risk if {
	input.context.risk_score >= 30
	input.context.risk_score < 60
}

high_risk if {
	input.context.risk_score >= 60
}

# --------------------------------------------------
# 🔒 ALLOW CONDITION (UPDATED)
# --------------------------------------------------

allow if {
	not deny_aegis
	not deny_identity_integrity
	valid_principal
	valid_tenant
	valid_intent
	valid_scopes
	intent_matches_scope
	trusted_device
	valid_policy_revision
	token_binding_present
	acceptable_risk
}

# --------------------------------------------------
# OBLIGATIONS
# --------------------------------------------------

obligations := [
	"ROLE_MATCHED",
	"AMOUNT_OK",
	"RISK_OK",
] if {
	allow
}

obligations := ["REVIEW_REQUIRED"] if {
	not allow
}

# --------------------------------------------------
# TTL CONTROL
# --------------------------------------------------

ttl := 300 if {
	not high_risk
}

ttl := 120 if {
	high_risk
}

# --------------------------------------------------
# DECISION OUTPUT
# --------------------------------------------------

decision := {
	"allow": allow,
	"obligations": obligations,
	"ttl_seconds": ttl,
	"policy_revision": input.policy_revision,
}
