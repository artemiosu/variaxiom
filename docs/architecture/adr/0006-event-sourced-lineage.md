# ADR-0006: Append-only lineage events plus immutable artifacts

- Status: Accepted
- Date: 2026-09-06

## Context

Self-modifying systems require reconstructable history. Mutable database rows alone obscure why a state exists and make rejected experiments disappear.

## Decision

Store large immutable artifacts by content hash. Record lifecycle transitions in an append-only typed event stream with integrity chaining and, later, signatures/attestations. Treat current views as rebuildable projections.

## Consequences

Positive: traceability, rollback, reproducible experiments, audit exports.

Negative: schema evolution and compaction complexity; hash chains alone do not prevent an attacker with full storage control from rewriting the complete history.
