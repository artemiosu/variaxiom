# Deployment Evolution

## Mode 0 — local research

- one machine;
- Python reference CLI;
- local content-addressed artifacts;
- hash-chained JSONL ledger;
- no untrusted code execution;
- no production credentials.

## Mode 1 — isolated single node

- Rust supervisor/kernel;
- PostgreSQL + local/S3-compatible artifacts;
- Wasmtime workers;
- rootless OCI for rich workloads;
- local OpenTelemetry collector;
- brokered network and secrets;
- human promotion approval.

## Mode 2 — remote worker pools

- separate candidate and evaluator worker pools;
- mutually isolated networks and identities;
- PostgreSQL outbox/queue;
- immutable build cache;
- signed artifacts and attestations;
- canary deployment controller.

## Mode 3 — federated research

- organizations contribute signed candidate/evidence packages;
- local governance decides trust and promotion;
- no globally automatic authority inheritance;
- replication of public artifacts and lineage proofs;
- diversity across model providers and evaluators.

## Operational requirements before Mode 2

- tested disaster recovery;
- secret rotation and revocation;
- budget enforcement under partitions;
- idempotent event processing;
- reproducible builds;
- audit retention policy;
- data classification and deletion process;
- abuse response and incident playbook;
- independent sandbox review.
