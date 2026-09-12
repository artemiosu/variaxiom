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

M2.2 defines the normative local transaction in
[`../specs/m2.2-transactional-sqlite-lineage.md`](../specs/m2.2-transactional-sqlite-lineage.md).
A promotion commit atomically:

1. re-verifies raw M2.1 proposal bytes against the separately supplied live anchor;
2. stores immutable protocol objects and the independently recomputed decision;
3. appends one canonical hash-linked event;
4. exact-head compares and advances the global event head and, only for an accepted decision, the
   selected lineage head;
5. reserves rollback state, updates rebuildable projections, stores an immutable retry receipt,
   and enqueues an outbox row.

A separate operator permission and event advance M2.1 trust anchors; evaluation cannot smuggle an
anchor change. Before SQLite commit, an external root custodian durably records the exact pending
operation. It finalizes the resulting root before acknowledgement or outbox handoff, so recovery
accepts only a previously approved one-event extension. Required and retainable raw artifacts are
streamed under a retention lease and permanently pinned by the transaction; a policy-rejected,
never-pinned artifact that cannot be retained remains represented by immutable bounded observation
evidence rather than being treated as available. The durable pending operation lists the referenced
artifact digests so process-death recovery closes the interval between an in-process lease and a
committed pin.

Rejected decisions append inspectable evidence but do not change selected lineage. External
deployment is a later saga with canary and compensating rollback; it cannot always be made
atomically reversible and is not part of M2.2.
