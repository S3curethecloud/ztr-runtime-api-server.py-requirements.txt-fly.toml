package ztr.issue

default allow = false

# --------------------------------------------------
# PHASE 8.3 + 8.4 — AEGIS POLICY INTEGRATION + ENFORCEMENT
# --------------------------------------------------

aegis_anomaly if {
    input.context.aegis.anomaly == true
}

high_velocity if {
    input.context.aegis.velocity > 5
}

aegis_risk_adjusted := input.context.risk_score + input.context.aegis.risk_delta

aegis_flagged if {
    aegis_anomaly
} else if {
    high_velocity
}

# 🔒 HARD BLOCK
deny_aegis if {
    aegis_anomaly
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
# 🔒 ALLOW CONDITION (UPDATED)
# --------------------------------------------------

allow if {
    not deny_aegis
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

obligations = [
    "ROLE_MATCHED",
    "AMOUNT_OK",
    "RISK_OK"
] if {
    allow
}

obligations = [
    "REVIEW_REQUIRED"
] if {
    not allow
}

# --------------------------------------------------
# TTL CONTROL
# --------------------------------------------------

ttl = 300 if {
    not high_risk
}

ttl = 120 if {
    high_risk
}

# --------------------------------------------------
# DECISION OUTPUT
# --------------------------------------------------

decision = {
    "allow": allow,
    "obligations": obligations,
    "ttl_seconds": ttl,
    "policy_revision": input.policy_revision
} if {
    true
}
