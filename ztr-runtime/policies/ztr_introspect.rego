package ztr.introspect

default allow := false

allow if {
    input.principal != ""
    input.tenant_id != ""
    count(input.scopes) > 0
    input.policy_revision == current_policy_revision
}


current_policy_revision := "dev-1"
