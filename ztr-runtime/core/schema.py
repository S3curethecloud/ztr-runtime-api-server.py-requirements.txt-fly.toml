# =========================================================
# 🔒 SecureTheCloud — Core Schema Validator
# MGF GOVERNANCE COMPLIANT (NO API COUPLING)
# =========================================================

import hashlib
import json


# =========================================================
# 🔒 CUSTOM EXCEPTION (NO FASTAPI DEPENDENCY)
# =========================================================
class SchemaValidationError(Exception):
    pass


# =========================================================
# 🔒 REQUIRED DECISION EVENT FIELDS (SOC2)
# =========================================================
REQUIRED_DECISION_FIELDS = [
    "timestamp",
    "tenant_id",
    "decision"
]


# =========================================================
# 🔒 VALIDATE DECISION EVENT
# =========================================================
def validate_decision_event(event: dict) -> None:
    for field in REQUIRED_DECISION_FIELDS:
        if field not in event or event[field] in [None, ""]:
            raise SchemaValidationError(
                f"invalid_decision_event_missing_{field}"
            )


# =========================================================
# 🔒 SIGN EVENT (CISA / ZERO TRUST)
# =========================================================
def sign_event(event: dict) -> dict:
    payload = json.dumps(event, sort_keys=True)
    signature = hashlib.sha256(payload.encode()).hexdigest()

    event["event_id"] = signature
    return event


# =========================================================
# 🔒 PREPARE EVENT (VALIDATE + SIGN)
# SINGLE ENTRY POINT — NO DRIFT
# =========================================================
def prepare_decision_event(event: dict) -> dict:
    validate_decision_event(event)
    return sign_event(event)
