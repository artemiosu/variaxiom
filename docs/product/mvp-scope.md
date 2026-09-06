# MVP scope

## Product stages

The **seed proof** is the current deterministic Authority Test. It demonstrates rejection of
implicit authority expansion but is not the MVP.

The **kernel foundation** covers M1 and M2: canonical protocol, identity/grants, signatures,
transactional SQLite lineage, rollback, and an evidence-backed report. It does not execute
generated code and is not called a product MVP.

The **Integration MVP** adds the bounded WASM reference trial and one external harness
adapter. It accepts untrusted candidate packages from an external producer, evaluates them in a
bounded environment, and records a signed, deterministic, reversible promotion decision.

The MVP does **not** claim open-ended self-improvement. It proves that proposed agent changes can
be inherited under independently inspectable rules without silently inheriting authority.

## Integration MVP vertical slice

The MVP is complete only when one clean-machine scenario demonstrates all of the following:

1. ingest a content-addressed candidate and its declared capability delta;
2. build or load it without granting undeclared host access;
3. collect deterministic and independent evaluation evidence;
4. bind evidence to candidate, artifact, evaluator, environment, cost, and constitution versions;
5. apply the Rust trusted-kernel decision transactionally;
6. sign and append the decision to durable SQLite lineage;
7. reject an otherwise functional candidate with ungranted authority;
8. accept an equivalent bounded candidate;
9. render a human-inspectable evidence and lineage report;
10. perform and verify a rollback without deleting history;
11. accept a candidate from at least one external harness adapter;
12. reproduce the complete trial from a clean checkout.

## Kernel foundation capabilities

- canonical, versioned candidate/evidence/decision envelopes;
- Python research and evaluation plane;
- small deterministic Rust promotion kernel;
- explicit identities and authority grants;
- Ed25519 envelope signatures;
- content-addressed artifacts;
- transactional SQLite event and projection store;
- append-only lineage, rollback, and static reports;
- local OpenTelemetry-compatible hooks;
- adversarial, replay, tamper, and clean-room tests.

The Integration MVP additionally requires bounded WASM/WIT tool execution, a provider-neutral
adapter contract, and one real reference adapter.

## Explicitly outside the MVP

- autonomous production deployment or purchasing;
- unrestricted browser, shell, network, secret, or filesystem access;
- multi-tenant hosted control plane;
- population-scale evolutionary scheduling;
- distributed queues, Kubernetes, Kafka, or a vector database;
- model weight training or claims of recursive general intelligence;
- a plugin marketplace;
- persistence or replication against operator intent.

## Kernel foundation completion gate

The release candidate needs:

- every included requirement mapped to executable evidence in `docs/project/traceability.md`;
- zero unresolved critical/high threat-model findings;
- deterministic protocol conformance on Python and Rust;
- successful Linux, macOS, and Windows CI where applicable;
- at least two clean reproductions, one by an independent reviewer;
- an exercised rollback procedure;
- documented limits, failure cases, and total trial cost.
