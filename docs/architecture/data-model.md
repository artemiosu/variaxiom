# Data Model

## Canonical objects

Canonical objects are immutable and content-addressed where practical.

### Genome

A manifest points to exact versions/hashes of skills, tools, workflows, memory policies, model routing, evaluator contracts, and parent lineage.

### Candidate

A candidate references a parent and one proposed artifact. It records claims, changed surfaces, requested capabilities, cost envelope, environment, and rollback target.

### Evidence

Evidence references the candidate and artifact hash, evaluator identity/version, check type, status, raw result artifact, environment, cost, timestamps, reproducibility metadata, and independence declaration.

### Promotion decision

A decision records constitution and gate versions, the relevant evidence IDs, accepted/rejected
status, stable reasons, and the digest of the complete promotion input. That input digest commits
to the selected capability grant, candidate, full evidence, trusted context, and exact policy.
The canonical decision-envelope digest is its identity. Selector identity, time, and signatures
belong to the later signed lineage event rather than the deterministic gate result.

### Event

Events are append-only facts with sequence, previous hash, kind, actor, payload, and canonical hash. Events do not replace object storage; they link state transitions.

### Capability lease

A lease records subject, operation/resource constraints, budgets, expiry, parent grant, and revocation.

## Canonicalization

The v1 protocol profile is defined normatively in the active
[cross-language conformance specification](../specs/m1.1-cross-language-conformance.md). It uses
UTF-8 deterministic JSON, sorted object keys and set-like arrays, integers restricted to the
interoperable safe range, explicit envelope versions, and SHA-256. Floats are excluded from the
signed surface. Unicode is preserved without normalization, so distinct code-point sequences
remain distinct inputs.

Artifact hashes cover exact artifact bytes. Protocol digests cover canonical JSON without a
trailing newline. Event hashes cover the canonical event body without its `hash` field; JSONL
record separators are not part of event identity.

## Event sourcing boundary

The event log is the historical source for lifecycle transitions. Current projections—active genome, open candidates, remaining budgets—are derived and can be rebuilt.

Large traces and binaries live in the artifact store; events contain hashes and summaries.

## Transactions

Production promotion should atomically:

1. verify evidence and lease state;
2. write the decision;
3. advance the active lineage pointer;
4. reserve rollback state;
5. emit an outbox event.

External deployment is a later saga with canary and compensating rollback; it cannot always be made atomically reversible.
