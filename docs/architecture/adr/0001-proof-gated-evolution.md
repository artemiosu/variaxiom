# ADR-0001: Proof-gated evolution instead of in-place self-editing

- Status: Accepted
- Date: 2026-09-06

## Context

LLMs can generate modifications to prompts, skills, tools, workflows, and harness code. The existence of a modification does not establish that it is beneficial, safe, general, or inheritable.

## Decision

Treat every modification as an immutable candidate. A candidate enters the inheritable lineage only through independent evaluation and deterministic constitutional promotion. Rejected candidates and evidence remain in history.

## Consequences

Positive: causal comparison, rollback, auditability, population archives, separation of roles.

Negative: slower than directly editing production; requires evaluator engineering and storage; cannot guarantee evaluator completeness.
