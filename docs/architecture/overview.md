# Architecture Overview

## 1. Architectural thesis

Variaxiom is not designed as one long-lived agent that may rewrite itself in place. It is a system for producing, evaluating, selecting, and inheriting **versioned agent phenotypes**.

The central invariant is:

```text
working behavior may be adaptive;
trusted inheritance must be proof-gated.
```

This leads to a two-speed architecture:

- a small, deterministic **constitutional kernel** changes slowly;
- the **evolution laboratory and phenotypes** change rapidly inside explicit boundaries.

The architecture optimizes for five properties in this order:

1. externally observable correctness;
2. authority containment;
3. lineage integrity and reversibility;
4. experimental velocity;
5. scale.

Scale is deliberately last. A distributed system that cannot distinguish improvement from evaluator exploitation only scales error.

## 2. Core ontology

| Term | Meaning |
|---|---|
| **Constitution** | Human-governed machine-readable invariants and amendment procedure |
| **Kernel** | Minimal deterministic code that enforces promotion, authority, budgets, lineage, pause, and rollback |
| **Genome** | Versioned graph of inheritable skills, tools, workflows, memory policies, model-routing policies, and architectural components |
| **Phenotype** | A runnable agent system assembled from one genome, a model set, an environment, and scoped capability leases |
| **Soma** | Temporary working agents, task context, scratch code, and episodic state |
| **Germline** | The protected path through which verified changes enter future phenotypes |
| **Candidate** | A proposed mutation with a parent, artifact hash, claims, requested capabilities, cost envelope, and rollback target |
| **Evidence** | Reproducible observation produced by a named evaluator in a separate trust role |
| **Promotion** | Deterministic decision to accept or reject a candidate for inheritance |
| **Lineage** | Content-addressed ancestry and evidence graph of genomes and candidates |
| **Capability lease** | Narrow, revocable, time- and budget-bounded authority to affect an external resource |
| **Evolutionary productivity** | Verified increase in future improvement capability per unit of total cost and risk |

## 3. Context diagram

```text
                 ┌─────────────────────────────┐
                 │ Human steward / governance  │
                 │ goals · grants · amendments │
                 └──────────────┬──────────────┘
                                │ signed intent
                     ┌──────────▼───────────┐
                     │ Constitutional kernel│
                     │                     │
                     │ identity            │
                     │ capability broker   │
                     │ budgets             │
                     │ promotion gate      │
                     │ lineage / rollback  │
                     │ pause / revoke      │
                     └───────┬───────┬─────┘
                             │       │
                     leases  │       │ promotion decisions
                             │       │
                 ┌───────────▼──┐ ┌──▼───────────────────┐
                 │ Phenotype    │ │ Evolution laboratory │
                 │ factory      │ │                      │
                 │ clean builds │ │ weakness mining      │
                 └──────┬───────┘ │ mutation / archive   │
                        │         │ independent evals    │
                        │         │ adversarial review   │
                 ┌──────▼───────┐ └──────────┬───────────┘
                 │ Working      │            │ evidence
                 │ phenotype    ├────────────┘
                 │ models       │
                 │ skills/tools │
                 │ temporary    │
                 │ cells        │
                 └──────┬───────┘
                        │ effects/outcomes
                 ┌──────▼───────────────────────┐
                 │ External world               │
                 │ repos · APIs · users · data  │
                 └──────────────────────────────┘
```

## 4. Planes and trust domains

### 4.1 Constitutional control plane

Responsibilities:

- verify artifact identities and parent lineage;
- issue and revoke capability leases;
- enforce budgets and spawn quotas;
- apply promotion policy to externally supplied facts;
- record append-only decisions;
- maintain rollback targets;
- expose human pause and recovery controls.

Non-responsibilities:

- planning tasks;
- choosing prompts;
- calling models;
- generating tools;
- judging semantic quality;
- retrieving arbitrary web content.

Keeping these functions out of the kernel reduces the amount of code that must be trusted against a compromised model or plugin.

### 4.2 Evolution plane

Responsibilities:

- collect execution traces and verifier-level failures;
- produce narrow causal hypotheses;
- generate diverse candidate mutations;
- schedule experiments;
- maintain an archive and Pareto frontier;
- commission independent evaluators;
- propose, but never self-authorize, promotion.

The evolution plane is replaceable and itself evolvable. Its proposals remain untrusted until evaluated.

### 4.3 Phenotype/data plane

Responsibilities:

- execute user-approved tasks;
- invoke models and tools;
- create temporary code and artifacts;
- use task-local memory;
- publish observable outcomes and candidate proposals.

A phenotype is disposable. A failed or compromised phenotype must not corrupt constitution, hidden evaluators, authority grants, or prior lineage.

### 4.4 Evaluation plane

Responsibilities:

- deterministic checks;
- held-in and held-out task evaluation;
- metamorphic and differential testing;
- adversarial evaluation;
- cost and latency accounting;
- real-world outcome measurement;
- evaluator integrity monitoring.

Evaluation runs in a separate trust domain. A candidate receives the public contract but not necessarily hidden cases or evaluator secrets.

### 4.5 Observatory

Responsibilities:

- OpenTelemetry traces, metrics, and structured events;
- lineage exploration;
- anomaly detection;
- causal experiment comparison;
- human-readable promotion reports;
- audit export.

Observability is not only operations tooling. It is part of the scientific method: an evolution engine cannot improve a component it cannot attribute failures to.

## 5. The promotion protocol

A candidate is a pure proposal, not an installed change.

```text
Candidate {
  id
  parent_lineage
  content_addressed_artifact
  claimed_effect
  editable_surface
  requested_capability_set
  budget_envelope
  environment_contract
  rollback_target
  proposer_identity
}
```

The candidate moves through states:

```text
proposed
  → built
  → statically_checked
  → sandbox_evaluated
  → adversarially_evaluated
  → shadowed
  → promotion_decided
  → canaried
  → active | rejected | quarantined | rolled_back
```

A promotion decision is accepted only when:

- the artifact and parent are integrity-verified;
- all mandatory checks contain independent passing evidence;
- no critical evidence fails;
- verifier diversity meets policy;
- the candidate does not silently expand authority;
- resource limits are satisfied;
- an addressable rollback target exists;
- evaluator versions and environments are recorded;
- the constitution version authorizing the decision is known.

The bootstrap Python reference implements a minimal version of this protocol. Production implementations must add signatures, stronger identity, isolation, and transactional promotion.

## 6. Soma–germline separation

The most important boundary is not “model versus tool.” It is **working experience versus inheritable structure**.

A working agent may write:

- scratch files;
- episodic observations;
- candidate skills;
- candidate tool adapters;
- candidate memory facts;
- candidate changes to the evolution engine.

It may not directly write:

- the active genome;
- constitutional rules;
- hidden evaluators;
- authority grants;
- trusted lineage history;
- production deployment state.

This prevents a single hallucination, prompt injection, transient outage, or reward-hacking discovery from becoming a permanent “lesson.”

## 7. Generated tool organogenesis

Generated tools are treated as packages crossing a hostile boundary.

Preferred path:

```text
capability gap
 → specification and provenance
 → generated implementation
 → declared WIT interface
 → capability manifest
 → dependency/SBOM capture
 → static analysis
 → reproducible build
 → disposable WASM sandbox
 → contract tests
 → adversarial tests
 → shadow execution
 → signed promotion
```

A tool manifest declares:

- input/output types;
- filesystem paths it may read/write;
- network origins and methods;
- secrets it may request from a broker;
- subprocess and clock/randomness requirements;
- CPU, memory, wall-time, and monetary budgets;
- reversibility and compensation behavior;
- data classification and retention;
- known failure modes.

WASM is preferred for portable, capability-oriented extensions. It is not a complete security solution: prompt injection, bad host imports, browser session exposure, and overly broad leases remain host responsibilities.

## 8. Multi-agent organization

Variaxiom does not use an unbounded “swarm.” Every worker is a typed, finite cell:

```text
CellContract {
  purpose
  parent
  inputs by artifact hash
  output schema
  budget
  deadline / TTL
  capability lease
  dependencies
  completion condition
  termination condition
}
```

A spawn requires a reproduction token from the population controller. Authority is non-transitive: a child receives only explicitly delegated capabilities. Outputs are exchanged through content-addressed artifacts and typed events rather than copied conversation histories.

This design makes parallelism inspectable and supports apoptosis: completed, redundant, expired, or anomalous workers terminate and release resources.

## 9. Memory architecture

Variaxiom separates:

- **working memory:** ephemeral context;
- **episodic memory:** what occurred;
- **semantic memory:** claims about the world;
- **procedural memory:** validated ways of acting;
- **self-model:** calibrated capabilities and limitations;
- **lineage memory:** immutable ancestry and evidence;
- **constitutional memory:** human-governed invariants.

Every persistent claim has provenance, scope, confidence, timestamp, evidence, contradictors, expiry/revalidation conditions, and environment dependencies. Negative claims such as “tool X does not work” receive short TTLs by default because outages and configurations change.

## 10. Storage and data model

Bootstrap:

- local content-addressed filesystem for artifacts;
- append-only hash-chained JSONL event ledger;
- JSON Schema contracts;
- deterministic canonical JSON.

Target single-node deployment:

- PostgreSQL for transactional metadata and leases;
- S3-compatible object storage for immutable artifacts;
- append-only signed event records;
- SQLite for local/offline mode;
- OpenTelemetry collector for traces/metrics/logs.

Search indexes and embeddings are derived views, never the source of truth. A vector database is introduced only after a measured retrieval requirement.

## 11. Technology split

- **Rust 2024:** kernel, policy evaluator, capability broker, ledger verification, sandbox host.
- **Python 3.13/3.14:** experiments, evaluation adapters, model routing, data analysis, research plugins.
- **WIT/WASM Component Model:** generated-tool ABI and portable component packages.
- **OCI + stronger isolation:** rich tool workloads that need OS processes or browsers.
- **Protocol-first integration:** JSON Schema/Protobuf where appropriate; no dependence on a single agent framework.

See [stack.md](stack.md) and the ADRs for rationale.

## 12. Deployment topology

The project starts as a modular monolith with explicit internal ports. The first production-capable topology is:

```text
operator CLI/API
    │
variaxiom supervisor
    ├── kernel process (no model/network ambient access)
    ├── artifact/ledger store
    ├── evolution scheduler
    ├── evaluator workers in isolated pools
    └── phenotype workers in isolated pools
```

Only after measured bottlenecks should queues, remote workers, or separate services be introduced. A future federation may distribute archives and evaluations, but constitutional authority remains explicit and does not emerge from network presence.

## 13. Deliberate non-goals for the first releases

- an all-purpose personal assistant;
- autonomous operation on arbitrary user accounts;
- autonomous wallets or cloud purchasing;
- self-preservation or persistence against operator intent;
- uncontrolled agent reproduction;
- replacing all existing harnesses;
- training foundation models from scratch;
- a universal scalar “intelligence” score;
- a plugin marketplace before package trust and signing exist;
- Kubernetes, Kafka, or microservices before single-node semantics are correct.

## 14. Architectural success criteria

The architecture is working when the project can show, with public artifacts:

1. the same genome rebuilds an equivalent phenotype in a clean environment;
2. a candidate can pass functional tests and still be rejected for authority or lineage violations;
3. a useful candidate can be promoted without the proposer controlling its evaluation;
4. tampering with an artifact or event invalidates verification;
5. a promoted change can be rolled back without losing evidence;
6. a later generation improves held-out performance without critical regressions;
7. the measured improvement cannot be explained solely by a stronger external model;
8. the system improves evolutionary productivity across multiple generations.
