# Product requirements

This document is the stable requirement registry for Variaxiom. Architecture documents explain
how the system is shaped; specifications define individual increments; this registry states the
behaviour that must remain true. Requirement identifiers are permanent and are never reused.

## Core lifecycle

| ID | Requirement | Acceptance evidence |
|---|---|---|
| REQ-CORE-001 | A generated change remains a candidate until an explicit promotion decision accepts its exact artifact digest. | A passing functional candidate cannot alter the active lineage before promotion. |
| REQ-CORE-002 | Candidate generation, evaluation, selection, and deployment are distinct roles and interfaces. | Tests demonstrate that proposer output alone cannot create a promotion or deployment event. |
| REQ-CORE-003 | Every public protocol object has a versioned schema and canonical representation. | Python and Rust consume shared fixtures and produce identical canonical bytes and SHA-256 digests. |

## Authority and trust

| ID | Requirement | Acceptance evidence |
|---|---|---|
| REQ-AUTH-001 | Capability improvement never implies additional authority. | A functionally valid candidate requesting an ungranted capability is rejected. |
| REQ-AUTH-002 | Authority grants are explicit, external, narrow, revocable, and independently addressable. | Grant fixtures show exact-scope acceptance and adjacent-scope rejection. |
| REQ-AUTH-003 | Authority is non-transitive across spawned workers. | A child receives only the capabilities named in its own lease. |
| REQ-TRUST-001 | A proposer cannot be its sole verifier. | Self-verification and same-principal aliases fail the applicable gate. |
| REQ-TRUST-002 | Candidate code cannot read or change hidden evaluators, the constitution, grants, or trusted history. | Isolation and adversarial tests deny each protected surface. |
| REQ-ID-001 | Cryptographic keys acquire principal identity and roles only through an explicit trusted binding; key possession alone grants no authority. | Wrong-principal, unbound-key, revoked-key, wrong-role, and same-principal-alias fixtures fail in Python and Rust. |
| REQ-SIG-001 | Authenticated protocol objects use domain-separated signatures bound to their exact canonical envelope digest and signed kind. | Mutation, wrong-domain, wrong-kind, wrong-key, malformed-signature, and cross-language fixtures fail closed. |

## Evidence and promotion

| ID | Requirement | Acceptance evidence |
|---|---|---|
| REQ-EVID-001 | Evidence is bound to the exact candidate and artifact digest it evaluated. | Evidence for another candidate or artifact cannot satisfy a mandatory check. |
| REQ-EVID-002 | Mandatory checks, verifier identity, independence, environment, cost, and raw result hashes are recorded. | The promotion envelope validates against its schema and can be replayed. |
| REQ-EVID-003 | Deterministic and externally observed evidence outrank uncalibrated model self-report. | Evaluation policy and fixtures reject confidence-only evidence. |
| REQ-PROM-001 | Promotion is a deterministic pure decision over an explicit constitution and supplied facts. | Repeated runs and supported implementations return identical decisions. |
| REQ-PROM-002 | Rejection remains inspectable evidence rather than being silently discarded. | Rejected candidates and reasons remain addressable in lineage history. |

## Lineage, integrity, and recovery

| ID | Requirement | Acceptance evidence |
|---|---|---|
| REQ-LINE-001 | Artifacts are content-addressed with a documented digest algorithm. | Mutation changes the digest and invalidates bound evidence. |
| REQ-LINE-002 | Promotion history is append-only, ordered, tamper-evident, and replayable. | Deletion, insertion, reordering, and mutation are detected. |
| REQ-ROLL-001 | Every accepted promotion retains an existing verified rollback target. | Missing or corrupt rollback targets prevent promotion. |
| REQ-ROLL-002 | Rollback creates auditable history and never erases the failed lineage. | A rollback drill reconstructs both prior and resulting state. |

## Resource and operator control

| ID | Requirement | Acceptance evidence |
|---|---|---|
| REQ-OPS-001 | Work is bounded by explicit time, compute, monetary, spawn, and capability limits. | Limit violations terminate or reject work and emit evidence. |
| REQ-OPS-002 | A human steward can pause execution and revoke authority independently of candidate code. | Recovery tests work when the active phenotype is unavailable or hostile. |
| REQ-OPS-003 | The system does not acquire credentials, persistence, replication, financial authority, or broader access without explicit operator action. | Threat-model tests cover denied escalation paths. |

## Observability and reproducibility

| ID | Requirement | Acceptance evidence |
|---|---|---|
| REQ-OBS-001 | Decisions, costs, traces, environments, and lineage identifiers expose vendor-neutral telemetry hooks. | A local run exports correlated structured events without requiring a hosted backend. |
| REQ-REP-001 | A clean checkout can reproduce every release-defining demonstration. | Documented bootstrap plus verification succeeds from a fresh clone. |
| REQ-REP-002 | Nondeterministic inputs are explicit and captured at trust boundaries. | Replay either reproduces the result or identifies the recorded source of variance. |

## Project-context quality

| ID | Requirement | Acceptance evidence |
|---|---|---|
| REQ-CTX-001 | Repository state, current increment, requirements, decisions, and evidence paths have one discoverable source of truth. | A new contributor reaches the active specification from `AGENTS.md` in two links or fewer. |
| REQ-CTX-002 | Every implementation increment links requirements, acceptance criteria, code, tests, and status. | The traceability table contains no implemented item without evidence. |
| REQ-CTX-003 | Generated indexes never replace normative source documents. | Generated context can be deleted and reconstructed without information loss. |

## Change policy

New requirements need a stable identifier, acceptance evidence, and traceability entry. Changes to
authority, promotion, lineage, rollback, evaluator isolation, or operator control also require an
ADR or RFC and explicit security review.
