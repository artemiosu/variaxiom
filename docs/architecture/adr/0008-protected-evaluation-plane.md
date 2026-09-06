# ADR-0008: Evaluation is a protected independent plane

- Status: Accepted
- Date: 2026-09-06

## Context

An optimizer will exploit any accessible weakness in its success signal. Allowing candidates to inspect or mutate the deciding evaluator invalidates promotion evidence.

## Decision

Run evaluators in identities and environments distinct from proposers and candidate workers. Keep selected cases hidden, record evaluator versions, require verifier diversity, and govern evaluator changes through a separate RFC/promotion path.

## Consequences

Positive: reduces self-verification and direct reward hacking.

Negative: evaluator secrecy complicates open reproducibility; hidden tests can become stale or biased. The project therefore combines hidden checks with public contracts, external outcomes, and periodic evaluator audits.
