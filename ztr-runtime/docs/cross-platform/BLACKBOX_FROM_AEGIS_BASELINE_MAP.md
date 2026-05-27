
Blackbox From Aegis Baseline Map

Status: Agent 7 / Baseline Inheritance Mapping In Progress

Purpose

This document records Aegis Runtime baseline patterns that may have influenced Blackbox and identifies assumptions that must become explicit contracts.

This file does not claim a copied file is confirmed unless destination evidence is recorded.

Candidate inherited patterns
Aegis baseline source	Possible Blackbox inheritance	Current proof level	Required normalization
api/audit.py / audit_chain.py	Evidence package / audit trail assumptions	Candidate	Blackbox records evidence but does not own runtime audit chain.
api/tokens.py decision context	Decision evidence shape	Candidate	Blackbox must not issue or authorize tokens.
api/sessions.py session context	Session evidence display	Candidate	Blackbox must not create/revoke runtime sessions.
api/blast_simulator.py / RiskDNA	Risk and blast-radius evidence	Candidate	RiskDNA owns scoring; Blackbox records evidence.
core/aegis_identity/	Aegis signal evidence	Candidate	Blackbox may record signal evidence only.
api/intelligence.py	Decision Intelligence summary	Candidate	Blackbox may package/read evidence, not become intelligence owner.
docs/lab-mappings/*aegis-runtime.md	Evidence scenario mapping	Candidate	Scenario mapping must be labeled as evidence support, not runtime truth.
fixtures/aegis/	Demo/evidence fixtures	Candidate	Fixtures must remain deterministic and non-production.
Assumptions to convert into explicit contracts
Blackbox records evidence.
Blackbox does not resolve Vault references.
Blackbox does not issue tokens.
Blackbox does not create sessions.
Blackbox does not revoke sessions.
Blackbox does not replace OPA.
Blackbox does not become Aegis Runtime Core.
Blackbox does not become RiskDNA system of record.
Required destination evidence search

Search Blackbox repositories for:

aegis_identity
compute_riskdna
simulate_blast_radius
audit_chain
ztr:aegis
riskdna
Decision Intelligence
blast radius
session evidence
Current conclusion

Blackbox inheritance from Aegis is not yet proven at the file-copy level.

The main normalization requirement is to ensure Blackbox remains evidence-recording/evidence-reviewing only, not runtime enforcement or source-of-truth authority.
