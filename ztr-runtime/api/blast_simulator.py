"""
SecureTheCloud — Blast Radius Simulator
Predictive Authorization Engine

This module performs:
1) Blast radius traversal across a dependency graph
2) RiskDNA scoring based on reachable nodes

Used by: api/tokens.py before OPA policy evaluation
"""

from typing import Dict, List, Set


# ---------------------------------------------------------
# Blast Radius Traversal
# ---------------------------------------------------------

def simulate_blast_radius(principal: str, intent: str, graph: Dict[str, List[str]]) -> Set[str]:
    """
    Traverse dependency graph starting from intent.

    Returns all reachable nodes representing potential
    downstream systems affected by the action.
    """

    visited: Set[str] = set()
    stack: List[str] = [intent]

    MAX_NODES = 100

    while stack:

        if len(visited) >= MAX_NODES:
            break

        node = stack.pop()

        if node in visited:
            continue

        visited.add(node)

        neighbors = graph.get(node, [])

        for n in neighbors:
            if n not in visited:
                stack.append(n)

    return visited


# ---------------------------------------------------------
# RiskDNA Scoring
# ---------------------------------------------------------

def compute_riskdna(
    principal: str,
    intent: str,
    nodes: set,
    context: dict,
    recent_denials: int,
    policy_drift: bool
) -> dict:

    sensitive_nodes = {
        "payment_db",
        "audit_ledger",
        "tenant_config",
        "billing_core",
        "identity_store"
    }

    context = context or {}

    # -----------------------------------------------------
    # TOPOLOGY RISK (blast radius)
    # -----------------------------------------------------
    topology_risk = len(nodes) * 2

    for node in nodes:
        if node in sensitive_nodes:
            topology_risk += 10

    # -----------------------------------------------------
    # IDENTITY RISK
    # -----------------------------------------------------
    identity_risk = 10 if principal else 0

    # -----------------------------------------------------
    # BEHAVIOR RISK
    # -----------------------------------------------------
    behavior_risk = min(recent_denials * 5, 20)

    # -----------------------------------------------------
    # POLICY RISK
    # -----------------------------------------------------
    policy_risk = 15 if policy_drift else 0

    # -----------------------------------------------------
    # INPUT / ENVIRONMENT RISK
    # -----------------------------------------------------
    submitted_risk_score = context.get("risk_score", 0)

    try:
        submitted_risk_score = int(float(submitted_risk_score))
    except Exception:
        submitted_risk_score = 0

    if submitted_risk_score < 0:
        submitted_risk_score = 0

    input_risk = min(submitted_risk_score, 30)

    environment_risk = input_risk

    if context.get("after_hours"):
        environment_risk += 20

    if context.get("anomaly"):
        environment_risk += 30

    velocity = context.get("velocity", 0)
    try:
        velocity = float(velocity)
    except Exception:
        velocity = 0

    if velocity > 5:
        environment_risk += 15

    if context.get("device_trust") is False:
        environment_risk += 10

    session_binding = context.get("session_binding")
    if session_binding is False or session_binding in ("", None):
        environment_risk += 10

    # -----------------------------------------------------
    # FINAL SCORE
    # -----------------------------------------------------
    final_score = (
        topology_risk +
        identity_risk +
        behavior_risk +
        policy_risk +
        environment_risk
    )

    # -----------------------------------------------------
    # TIER CLASSIFICATION
    # -----------------------------------------------------
    if final_score <= 30:
        tier = "LOW"
    elif final_score <= 60:
        tier = "MEDIUM"
    elif final_score <= 90:
        tier = "HIGH"
    else:
        tier = "CRITICAL"

    return {
        "identity_risk": identity_risk,
        "behavior_risk": behavior_risk,
        "topology_risk": topology_risk,
        "policy_risk": policy_risk,
        "environment_risk": environment_risk,
        "input_risk": input_risk,
        "submitted_risk_score": submitted_risk_score,
        "final_score": final_score,
        "risk_tier": tier
    }

# ---------------------------------------------------------
# Optional helper for debugging / logging
# ---------------------------------------------------------

def summarize_blast(nodes: Set[str]) -> dict:
    """
    Produce a summary object useful for telemetry
    or debugging logs.
    """

    return {
        "nodes": list(nodes),
        "node_count": len(nodes)
    }
