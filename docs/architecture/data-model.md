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

A decision records constitution version, exact evidence set, capability grant, accepted/rejected status, reasons, selector identity, timestamp, and decision hash.

### Event

Events are append-only facts with sequence, previous hash, kind, actor, payload, and canonical hash. Events do not replace object storage; they link state transitions.

### Capability lease

A lease records subject, operation/resource constraints, budgets, expiry, parent grant, and revocation.

## Canonicalization

The bootstrap uses deterministic JSON serialization and SHA-256. Production design must define Unicode normalization, number representation, schema versioning, large binary handling, and signature envelopes explicitly.

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
