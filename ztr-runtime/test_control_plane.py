from control_plane import register_tenant, set_policy

print(register_tenant("tenant-launch"))

policy = "dummy-policy-v1"
print(set_policy("tenant-launch", policy))
