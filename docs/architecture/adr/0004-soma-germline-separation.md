# ADR-0004: Separate working state from inherited state

- Status: Accepted
- Date: 2026-09-06

## Context

Automatic conversion of session reflections into persistent memory or skills can preserve hallucinations, transient outages, prompt injections, and environment-specific failures.

## Decision

Working agents write only episodic observations and candidate packages. The protected germline is updated exclusively by the promotion protocol after clean-room and held-out evaluation.

## Consequences

Positive: evidence-based learning, reversible inheritance, reduced memory poisoning.

Negative: slower learning, extra evaluation cost, need for claim schemas and TTL/revalidation machinery.
