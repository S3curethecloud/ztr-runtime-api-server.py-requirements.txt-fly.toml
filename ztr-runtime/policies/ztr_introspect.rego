package ztr.introspect

default allow = false

allow if {
    input.principal != ""
    count(input.scopes) > 0
    input.tenant_id != ""
    input.policy_revision == current_policy_revision
}

current_policy_revision := "dev-1"
