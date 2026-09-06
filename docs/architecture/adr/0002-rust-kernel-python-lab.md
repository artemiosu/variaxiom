# ADR-0002: Rust kernel and Python research plane

- Status: Accepted
- Date: 2026-09-06

## Context

Security-sensitive policy benefits from a small typed implementation, while agent/evaluation research depends on a rapidly changing Python ecosystem.

## Decision

Implement the target constitutional kernel, capability broker, ledger verifier, and sandbox host in Rust 2024. Implement experiments, model adapters, data analysis, and reference evaluators in Python 3.13/3.14. Maintain language-neutral schemas at the boundary.

## Consequences

Positive: smaller trusted computing base, fast research iteration, clean separation.

Negative: two toolchains, duplicated domain types during bootstrap, FFI/protocol versioning work.
