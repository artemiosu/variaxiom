# Technology Stack — September 2026 Baseline

## Decision summary

| Layer | Choice | Why |
|---|---|---|
| Trusted kernel | Rust 2024, toolchain pinned to 1.98.1 | Memory safety, explicit types, reproducible builds, strong library ecosystem |
| Research/evolution plane | Python 3.13 and 3.14 | Best AI/evaluation ecosystem and rapid experimentation; 3.14 is current stable family in Sep 2026 |
| Python project manager | `uv` | Fast reproducible environments, cross-platform lockfile, workspace support |
| Generated component ABI | WIT + WebAssembly Component Model | Typed language-neutral contracts and deny-by-default host imports |
| WASM runtime | Wasmtime | Mature Rust embedding, component support, fuel/epoch/resource controls |
| Rich workload isolation | OCI containers; evaluate gVisor/Firecracker | Browsers and arbitrary build tools need stronger OS-like isolation |
| Local metadata | SQLite | Zero-ops, transactional local mode |
| Server metadata | PostgreSQL | Transactions, constraints, leases, advisory locking, mature operations |
| Artifact storage | Content-addressed filesystem locally; S3-compatible object store later | Immutable reproducible artifacts and cheap scale |
| Events | Append-only typed event log; PostgreSQL outbox when distributed | Reconstructability without premature Kafka |
| Telemetry | OpenTelemetry | Vendor-neutral traces, metrics, logs, cost attribution |
| Schemas | JSON Schema 2020-12 now; Protobuf only for hot/internal RPC if needed | Human-readable contracts and language independence |
| Policy | Small deterministic policy core; evaluate Cedar for policy authoring later | Avoid embedding a large policy engine before requirements stabilize |
| Supply chain | SBOM, Sigstore/SLSA/in-toto roadmap | Provenance and signed promotion packages |
| CI action runtime | Node 24 generation (Checkout v7, CodeQL v4) | Avoid the retired Node 20 Actions runtime |
| CLI | Rust target; Python bootstrap | Fast iteration now, trusted operator surface later |
| UI | Static lineage/evidence reports first; web UI later | A visible proof artifact matters before a dashboard framework |

## Why Rust for the kernel

The kernel must remain understandable and difficult for generated components to influence accidentally. Rust provides memory safety without a garbage-collected runtime and supports Wasmtime embedding. The kernel should still be small: Rust does not make a large trusted codebase safe by itself.

The kernel must not depend on model SDKs, agent frameworks, web retrieval, or arbitrary plugin loading. It receives typed facts and returns policy decisions.

## Why Python for the laboratory

Model providers, benchmark tooling, data science, and research code converge on Python. The evolution plane benefits more from fast replacement and inspectability than from making every experiment part of the trusted computing base.

Python is not used as the sole sandbox boundary. Generated Python runs only inside a separately enforced environment.

The repository supports Python 3.13 and 3.14. Python 3.15 remains prerelease as of the project seed date and is a future CI target, not the production baseline.

## Why `uv`

`uv` provides a cross-platform lockfile and workspace model. The project will commit `uv.lock` when dependency resolution is performed in a networked development environment. The initial offline-built seed intentionally has no runtime dependencies and can be verified with `PYTHONPATH=src`.

## Why WIT and WASM components

A generated tool should not inherit a whole shell merely because it needs to normalize text or call one API. WIT makes imports explicit. The host can expose narrowly scoped functions such as:

```text
read-artifact(hash)
write-artifact(bytes)
http-request(lease-id, request)
log(level, message)
```

No import means no capability.

Caveats:

- the Component Model still has evolving parts;
- host imports can be overbroad;
- browser automation and native toolchains may not fit WASM;
- sandboxing does not solve prompt injection or data authorization.

Therefore WASM is one isolation tier, not the entire security story.

## Why a modular monolith first

The core workflow requires transactional reasoning about:

- candidate identity;
- evidence completeness;
- lease state;
- promotion decision;
- lineage update;
- rollback target.

Splitting this across microservices before semantics are stable creates distributed races and makes audits harder. Internal ports and typed events preserve future separability without operational complexity.

Extract a service only when there is a measured reason such as independent scaling, a distinct trust boundary, or a different failure domain.

## Explicitly deferred technologies

### Kubernetes

Deferred until the project has multiple isolation pools and operational demand. Local process/OCI orchestration is sufficient for early experiments.

### Kafka/Pulsar/NATS JetStream

Deferred until a PostgreSQL outbox or local event log becomes a measured bottleneck. Event semantics matter first.

### Vector database

Deferred. Provenance-aware structured memory and filesystem/artifact search come first. Embeddings are a derived retrieval index, not memory truth.

### LangChain/LangGraph/CrewAI as the core

They may be supported through adapters or used in experiments, but no external agent framework defines Variaxiom's domain model, lineage, promotion, or security boundary. This prevents framework churn from becoming architectural churn.

### Blockchain/DAO governance

Not required for auditability or open governance. Content hashes, signatures, transparent releases, and ordinary legal accountability are simpler. A distributed ledger would not solve evaluator quality or authority design.

### Autonomous wallet and cloud procurement

Explicitly outside scope. Budget accounting is required; autonomous financial sovereignty is not.

## Dependency acceptance rule

A new dependency must answer:

1. Which measurable requirement does it satisfy?
2. Does it enter the trusted computing base?
3. What permissions and transitive dependencies does it add?
4. Can it be replaced behind a port?
5. How is it pinned, scanned, and updated?
6. What is the rollback path?

## Upgrade policy

- Pin reproducible environments.
- Test new Python/Rust/compiler/runtime versions in an experimental matrix before changing the baseline.
- Treat model version changes as experimental interventions, not routine package upgrades.
- Record provider/model identifiers and system fingerprints where available.
- Never attribute a performance gain to a harness mutation without a same-model control.
