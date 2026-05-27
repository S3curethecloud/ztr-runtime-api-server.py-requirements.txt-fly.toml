
Aegis Baseline Inheritance Normalization

Status: Agent 7 / Baseline Inheritance Mapping In Progress

Purpose

This document normalizes hidden Aegis baseline inheritance into explicit cross-platform contracts.

Normalization principle

Copied files and copied patterns must not silently transfer authority.

A copied Aegis runtime pattern must be classified as one of:

shared evidence pattern
shared context pattern
shared policy-input pattern
shared UI/rendering pattern
runtime substrate pattern
forbidden authority transfer
Shared assumptions that must become explicit
Assumption	Normalized contract
Aegis produces useful runtime context	Aegis produces bounded signals only.
RiskDNA provides risk context	RiskDNA informs and scores risk, but does not authorize.
OPA evaluates policy	OPA remains decision authority where policy evaluation is required.
Runtime owns sessions	Runtime owns session lifecycle and revocation side effects.
Runtime owns token issuance	Runtime owns token side effects; Aegis/RiskDNA provide context only.
Audit evidence can be reused	Evidence reuse must preserve source, integrity, retention, and ownership.
Redis key patterns can be copied	Redis schema ownership must be explicit before reuse.
Copilot can explain Aegis/RiskDNA	Copilot explains but does not enforce.
Blackbox can record evidence	Blackbox records evidence but does not become runtime authority.
ASZ can verify evidence	ASZ verifies cross-domain evidence but does not authorize runtime execution.
SENTINEL can consume runtime context	SENTINEL must not duplicate Aegis command-center logic or token/session authority.
Forbidden hidden inheritance
Aegis ownership transferred to ASZ
Aegis ownership transferred to Blackbox
Aegis ownership transferred to SENTINEL
RiskDNA authority transferred to Aegis renderers
OPA authority transferred to RiskDNA or Aegis
Runtime token/session authority transferred to any downstream renderer
Redis state ownership inferred from copied key names
SOC 2 claims inferred from evidence docs
Helm/package modularity inferred from copied files
Required confirmation before final closure

Each platform-specific inheritance map must eventually record:

destination repository
destination file path
source file or source pattern
whether copied exactly or conceptually inherited
assumption inherited
normalized contract replacing the hidden assumption
remaining drift risk
Current conclusion

Aegis baseline inheritance is now visible as a set of candidate patterns and required contracts.

It is not yet final copied-file proof. Final confirmation requires destination repository search across ASZ, Blackbox, and Kubernetes/SENTINEL.
