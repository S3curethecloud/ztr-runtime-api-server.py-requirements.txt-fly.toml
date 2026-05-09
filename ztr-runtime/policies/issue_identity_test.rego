package ztr.issue

# --------------------------------------------------
# AEGIS IDENTITY INTEGRITY — OPA POLICY TESTS
# --------------------------------------------------
#
# These tests validate real OPA policy behavior for issue.rego.
# They do not replace OPA and do not bypass OPA.
#
# Aegis Identity remains signal-only.
# OPA remains final decision authority.
# --------------------------------------------------

test_stable_identity_signal_allows_valid_issue_request if {
	result := decision with input as {
		"tenant_id": "tenant-beta",
		"principal": "agent-demo",
		"intent": "refund:create",
		"scopes": ["refund:create"],
		"ttl_seconds": 300,
		"policy_revision": "test-policy",
		"context": {
			"device_trust": true,
			"session_binding": "device-aegis-test",
			"risk_score": 10,
			"after_hours": false,
			"aegis_identity": {
				"signal": "IDENTITY_STABLE",
				"confidence": 0.95,
				"risk_modifier": 0,
				"reasons": ["no_risk_evidence"],
				"decision_authority": "OPA",
				"model": "aegis-identity-v0.1",
			},
		},
	}

	result.allow == true
	result.ttl_seconds == 300
	result.policy_revision == "test-policy"
}

test_identity_drift_with_high_modifier_denies_issue_request if {
	result := decision with input as {
		"tenant_id": "tenant-beta",
		"principal": "agent-demo",
		"intent": "refund:create",
		"scopes": ["refund:create"],
		"ttl_seconds": 300,
		"policy_revision": "test-policy",
		"context": {
			"device_trust": true,
			"session_binding": "device-aegis-test",
			"risk_score": 10,
			"after_hours": false,
			"aegis_identity": {
				"signal": "IDENTITY_DRIFT_DETECTED",
				"confidence": 0.85,
				"risk_modifier": 25,
				"reasons": ["recent_denials:3"],
				"decision_authority": "OPA",
				"model": "aegis-identity-v0.1",
			},
		},
	}

	result.allow == false
	result.obligations == ["REVIEW_REQUIRED"]
}

test_identity_drift_with_low_modifier_does_not_trigger_identity_deny if {
	result := decision with input as {
		"tenant_id": "tenant-beta",
		"principal": "agent-demo",
		"intent": "refund:create",
		"scopes": ["refund:create"],
		"ttl_seconds": 300,
		"policy_revision": "test-policy",
		"context": {
			"device_trust": true,
			"session_binding": "device-aegis-test",
			"risk_score": 10,
			"after_hours": false,
			"aegis_identity": {
				"signal": "IDENTITY_DRIFT_DETECTED",
				"confidence": 0.85,
				"risk_modifier": 15,
				"reasons": ["bounded_low_modifier"],
				"decision_authority": "OPA",
				"model": "aegis-identity-v0.1",
			},
		},
	}

	result.allow == true
}

test_identity_high_modifier_without_drift_signal_does_not_trigger_identity_deny if {
	result := decision with input as {
		"tenant_id": "tenant-beta",
		"principal": "agent-demo",
		"intent": "refund:create",
		"scopes": ["refund:create"],
		"ttl_seconds": 300,
		"policy_revision": "test-policy",
		"context": {
			"device_trust": true,
			"session_binding": "device-aegis-test",
			"risk_score": 10,
			"after_hours": false,
			"aegis_identity": {
				"signal": "IDENTITY_STABLE",
				"confidence": 0.85,
				"risk_modifier": 25,
				"reasons": ["modifier_without_drift"],
				"decision_authority": "OPA",
				"model": "aegis-identity-v0.1",
			},
		},
	}

	result.allow == true
}

test_missing_aegis_identity_context_preserves_existing_allow_path if {
	result := decision with input as {
		"tenant_id": "tenant-beta",
		"principal": "agent-demo",
		"intent": "refund:create",
		"scopes": ["refund:create"],
		"ttl_seconds": 300,
		"policy_revision": "test-policy",
		"context": {
			"device_trust": true,
			"session_binding": "device-aegis-test",
			"risk_score": 10,
			"after_hours": false,
		},
	}

	result.allow == true
}

test_existing_aegis_anomaly_still_denies_issue_request if {
	result := decision with input as {
		"tenant_id": "tenant-beta",
		"principal": "agent-demo",
		"intent": "refund:create",
		"scopes": ["refund:create"],
		"ttl_seconds": 300,
		"policy_revision": "test-policy",
		"context": {
			"device_trust": true,
			"session_binding": "device-aegis-test",
			"risk_score": 10,
			"after_hours": false,
			"aegis": {
				"anomaly": true,
				"velocity": 1,
				"risk_delta": 0,
			},
			"aegis_identity": {
				"signal": "IDENTITY_STABLE",
				"confidence": 0.95,
				"risk_modifier": 0,
				"reasons": ["no_risk_evidence"],
				"decision_authority": "OPA",
				"model": "aegis-identity-v0.1",
			},
		},
	}

	result.allow == false
	result.obligations == ["REVIEW_REQUIRED"]
}

test_identity_integrity_deny_rule_is_true_for_drift_and_high_modifier if {
	deny_identity_integrity with input as {
		"tenant_id": "tenant-beta",
		"principal": "agent-demo",
		"intent": "refund:create",
		"scopes": ["refund:create"],
		"ttl_seconds": 300,
		"policy_revision": "test-policy",
		"context": {
			"device_trust": true,
			"session_binding": "device-aegis-test",
			"risk_score": 10,
			"after_hours": false,
			"aegis_identity": {
				"signal": "IDENTITY_DRIFT_DETECTED",
				"confidence": 0.85,
				"risk_modifier": 25,
				"reasons": ["recent_denials:3"],
				"decision_authority": "OPA",
				"model": "aegis-identity-v0.1",
			},
		},
	}
}

test_identity_integrity_deny_rule_is_false_for_stable_identity if {
	not deny_identity_integrity with input as {
		"tenant_id": "tenant-beta",
		"principal": "agent-demo",
		"intent": "refund:create",
		"scopes": ["refund:create"],
		"ttl_seconds": 300,
		"policy_revision": "test-policy",
		"context": {
			"device_trust": true,
			"session_binding": "device-aegis-test",
			"risk_score": 10,
			"after_hours": false,
			"aegis_identity": {
				"signal": "IDENTITY_STABLE",
				"confidence": 0.95,
				"risk_modifier": 0,
				"reasons": ["no_risk_evidence"],
				"decision_authority": "OPA",
				"model": "aegis-identity-v0.1",
			},
		},
	}
}
