# Agent contribution contract

This repository studies proof-gated evolution. Automated contributors must preserve the
boundary between proposing a change and authorizing it.

## Non-negotiable invariants

- Treat working agents as **soma**: they may propose candidates, never write directly to the
  inheritable **germline**.
- Capability is not authority. Never infer a permission grant from benchmark performance,
  model confidence, or task success.
- A proposer cannot be its sole verifier. Promotion needs independent evidence bound to the
  exact content digest under review.
- Keep promotion history append-only, hash-linked, deterministic, and auditable.
- Every promotion retains a verified rollback target.
- Never add covert persistence, uncontrolled replication, credential acquisition, permission
  bypass, autonomous financial authority, or mechanisms that resist operator shutdown.

## Engineering defaults

- Keep the MVP a modular monolith: Python for research/evaluation and a small Rust trusted
  kernel for deterministic policy. Add WASM/WIT only at a real capability boundary.
- Prefer SQLite locally and postpone PostgreSQL until concurrent operation requires it.
- Do not introduce Kubernetes, Kafka, or a vector database without an accepted ADR and measured
  need.
- Keep the Rust kernel free of ambient network/model access and `unsafe` code.
- Store artifacts by content digest and make nondeterminism explicit at system boundaries.

## Before submitting

Run `bash scripts/verify.sh`. If Rust is installed, also run:

```bash
cargo fmt --all -- --check
cargo test --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

Sign commits according to `DCO.md`. Security-sensitive changes to `constitution/`, `schemas/`,
the evaluator boundary, or `crates/kernel/` need focused review and evidence for rollback.
