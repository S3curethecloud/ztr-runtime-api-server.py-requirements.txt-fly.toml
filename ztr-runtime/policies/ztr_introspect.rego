package ztr.introspect

default allow = false

allow if {
    valid_principal
    valid_tenant
    valid_scopes
    valid_policy_revision
}

valid_principal if {
    input.principal != ""
}

valid_tenant if {
    input.tenant_id != ""
}

valid_scopes if {
    is_array(input.scopes)
    count(input.scopes) > 0
}

valid_policy_revision if {
    input.policy_revision == current_policy_revision
}

current_policy_revision := "dev-1"
