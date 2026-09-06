# Project status

**Version:** 0.1.0-alpha seed  
**Maturity:** pre-alpha research implementation  
**Primary public proof:** The Authority Test  
**Last status review:** 2026-09-06

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

## Not implemented yet

- production WASM component runner;
- cryptographic signatures or transparency-log anchoring;
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
