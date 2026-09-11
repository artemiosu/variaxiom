# Project status

**Version:** 0.1.0-alpha seed (unreleased; no Git tag yet)
**Maturity:** pre-alpha research implementation
**Primary public proof:** The Authority Test
**Last status review:** 2026-09-11

The concise source of truth for active development is
[`docs/project/current.md`](docs/project/current.md); machine-readable status is in
[`project.yaml`](project.yaml). This file records release-level capability only.

The Python spelling `0.1.0a0` and Rust spelling `0.1.0-alpha.0` are ecosystem-specific forms of
the same pre-release intent; they do not indicate separately published releases.

M1.1 is published; the required remote operating-system matrix, independent public clean-clone
reproduction, and automated audit pass. The M2.1 specification for explicit identity, authority
grants, and detached signatures passed its three-role automated specification council. The 237-case
schema/fixture freeze plus 19 curated Wycheproof vectors also passed three isolated automated
reviews with no remaining P0/P1. This authorizes a disabled implementation, not a production
security claim or a substitute for human review.

Stage-eleven implementation review later exposed an unsafe positive authority flag and an
unfrozen two-phase result API. Issue #16 corrects the contract with an accepted 252-case,
always-non-authorizing freeze. Three isolated automated reviewers reported no P0/P1 on revision
`7642611c014ff683a6aadc614f709ca959f8583b`; this remains defense in depth, not a human audit.

## Implemented

- deterministic candidate/evidence/promotion domain model;
- content-addressed JSON artifact store;
- append-only hash-chained lineage ledger with tamper detection;
- bootstrap constitution with authority, rollback, verifier-independence, evidence, and budget checks;
- accepted/rejected promotion records;
- deterministic, dependency-free Authority Test;
- self-contained HTML evidence report;
- repository verifier and unit tests;
- Rust kernel/protocol/CLI scaffold;
- WIT boundary for future generated tools;
- JSON schemas for public protocol objects;
- architecture, research, governance, launch, and security documentation;
- pinned GitHub Actions CI, dependency review, and OpenSSF Scorecard workflows.
- cross-language canonical promotion envelopes and shared Python/Rust fixtures;
- frozen M2.1 schemas and a 252-case adversarial corpus with a non-authorizing fixture oracle;
- CodeQL, project context routing, requirement traceability, and spec-driven increment gates.

## Not implemented yet

- production WASM component runner;
- production M2.1 signature verifier, signing API, or transparency-log anchoring;
- remote/object-store artifact backend;
- protected hidden-evaluation service;
- provider-neutral adapters for external harnesses;
- population archive and Pareto selector;
- typed memory claims with contradiction and revalidation jobs;
- distributed execution;
- model training or weight-level self-improvement;
- production deployment or autonomous operation.

## Explicit non-goals for the first releases

- unrestricted shell/network defaults;
- autonomous wallets or independent infrastructure purchasing;
- stealth, persistence against operator intent, or uncontrolled replication;
- a general-purpose replacement for Claude Code, Codex, Hermes, OpenClaw, or DeepSeek Harness;
- a promise of guaranteed AGI or technological singularity;
- Kubernetes, Kafka, a plugin marketplace, or a vector database before measured need.

## Meaning of “working”

The current repository proves only a narrow but important claim:

> A candidate can pass functional tests and still be rejected from the inheritable lineage because it requests authority not granted by the external constitution.

This seed is intentionally small. Every future capability must arrive as a falsifiable milestone with evidence rather than as a roadmap claim.
