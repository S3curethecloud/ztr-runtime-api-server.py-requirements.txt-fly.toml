# SecureTheCloud — Token Issuance Policy
# Phase 5B-02
#
# Evaluated by:
#   POST /v1/data/ztr/issue/allow
#
# Input schema expected from runtime:
#
# {
#   "principal": "user_id",
#   "intent": "refund:create",
#   "scopes": ["refund:create"],
#   "tenant_id": "tenant_123",
#   "context": {
#       "risk_score": 42,
#       "device_trust": true,
#       "after_hours": false
#   }
# }
#
# Fail-closed model:
#   If allow rule does not evaluate true → deny
#

default allow = false


#
# Base allow rule
#
allow {
    valid_principal
    valid_intent
    valid_scopes
    valid_tenant
    acceptable_risk
}


#
# Principal validation
#
valid_principal {
    input.principal != ""
}


#
# Intent validation
#
valid_intent {
    input.intent != ""
}


#
# Scope validation
#
valid_scopes {
    count(input.scopes) > 0
}


#
# Tenant validation
#
valid_tenant {
    input.tenant_id != ""
}


#
# Risk evaluation
#
acceptable_risk {
    not high_risk
}


#
# High risk condition
#
high_risk {
    input.context.risk_score >= 80
}
