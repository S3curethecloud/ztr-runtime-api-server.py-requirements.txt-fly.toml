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
    nodes: Set[str],
    context: dict,
    recent_denials: int,
    policy_drift: bool
) -> dict:
    """
    Compute risk score from reachable nodes.

    Risk factors:
    - number of impacted systems
    - presence of sensitive resources
    """

    sensitive_nodes = {
        "payment_db",
        "audit_ledger",
        "tenant_config",
        "billing_core",
        "identity_store"
    }

    score = 0

    # base score = blast radius size
    score += len(nodes) * 2

    # sensitive systems increase risk
    for node in nodes:
        if node in sensitive_nodes:
            score += 10

    # -----------------------------------------------------
    # MINIMAL SAFE IMPLEMENTATION (REQUIRED)
    # -----------------------------------------------------

    identity_risk = 10 if principal else 0
    intent_risk = 5 if intent else 0

    score += identity_risk
    score += intent_risk

    return {
        "identity_risk": identity_risk,
        "intent_risk": intent_risk,
        "topology_risk": len(nodes),
        "behavior_risk": 0,
        "policy_risk": 0,
        "final_score": score
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
