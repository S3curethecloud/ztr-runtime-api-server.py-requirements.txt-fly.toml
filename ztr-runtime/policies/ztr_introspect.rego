package ztr.introspect

default allow = false

allow if {
    count(input.principal) > 0
    count(input.scopes) > 0
    count(input.tenant_id) > 0
    input.policy_revision == current_policy_revision
}

current_policy_revision := "dev-1"
