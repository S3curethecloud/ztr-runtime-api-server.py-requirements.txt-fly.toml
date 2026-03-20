package ztr.issue

default allow = false

allow if {
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

ttl = 300 if {
    not high_risk
}

ttl = 120 if {
    high_risk
}

decision = {
    "allow": allow,
    "obligations": obligations,
    "ttl_seconds": ttl,
    "policy_revision": input.policy_revision
} if {
    true
}
