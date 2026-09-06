# ADR-0005: Modular monolith before distributed services

- Status: Accepted
- Date: 2026-09-06

## Context

Candidate, evidence, lease, promotion, lineage, and rollback semantics are not yet stable. Premature distribution would make invariants harder to understand and test.

## Decision

Build a modular monolith with explicit ports, typed events, and isolated worker processes. Extract services only for a measured scaling requirement or a stronger trust/failure boundary.

## Consequences

Positive: transactional clarity, easier local development, lower operations burden.

Negative: less independent scaling initially; process boundaries must be designed carefully to avoid accidental in-process trust.
