package ztr.introspect

default active := false

active if {
    input.token_valid == true
}
