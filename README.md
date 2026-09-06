# Variaxiom

<p align="center"><img src="assets/variaxiom-wordmark.svg" alt="Variaxiom — Agents mutate. Evidence decides." width="820"></p>

**Agents mutate. Evidence decides.**

Variaxiom is an open, proof-gated evolutionary substrate for AI agents. It explores a question that ordinary agent harnesses do not answer:

> How can an agent change its skills, tools, workflows, memory policies, and eventually its own harness **without confusing self-editing with self-improvement**?

Most agents can already propose code changes. Mutation is easy. The hard part is governed inheritance: determining which changes deserve to survive, reproduce, and become part of future agents.

Variaxiom makes that decision explicit, reproducible, and auditable.

[Русская версия](README.ru.md) · [Architecture](docs/architecture/overview.md) · [Roadmap](docs/project/roadmap.md) · [Launch strategy](docs/launch/launch-strategy.ru.md)

> **Status:** pre-alpha research seed. The repository contains a runnable reference slice, schemas, a Rust kernel scaffold, and the project design. It is not a production autonomy platform.

## The one-minute idea

A working agent may propose a mutation, but it cannot make that mutation inheritable.

```text
working agent (soma)
        │ proposes
        ▼
candidate skill / tool / harness edit
        │
        ├── integrity and lineage checks
        ├── independent evaluators
        ├── regression and adversarial tests
        ├── budget and authority checks
        └── rollback proof
        │
        ▼
constitutional promotion gate
        │
        ├── rejected → retained as evidence
        └── accepted → enters the inheritable genome
```

Variaxiom separates four things that are often collapsed into one loop:

1. **Generation** — models create candidate changes.
2. **Evaluation** — independent systems measure consequences.
3. **Selection** — deterministic policy decides promotion.
4. **Authority** — external permissions remain separately governed.

A smarter candidate does not automatically receive broader access.

## Why this is different

| Conventional agent harness | Variaxiom |
|---|---|
| One active agent edits itself | Populations of disposable phenotypes propose variants |
| Memory is a growing collection of notes | Claims carry provenance, scope, confidence, expiry, and falsifiers |
| A new skill is an instruction file | A promoted skill is a versioned package with evidence and tests |
| The same agent may propose and judge | Proposer, verifier, selector, and deployer are separate trust roles |
| Better benchmark result means “upgrade” | Promotion requires a multi-dimensional evidence envelope and no hard-constraint violation |
| More capability often implies more access | Capability and authority are orthogonal |
| The current version is overwritten | A content-addressed lineage and rollback target survive every promotion |
| “Self-improving” is a product claim | Improvement is an experimentally testable relation between generations |

## Run the proof-gated demo

The bootstrap implementation has no runtime dependencies beyond Python 3.13+.

```bash
git clone https://github.com/artemiosu/variaxiom.git
cd variaxiom
bash scripts/demo.sh
```

The demo evaluates the same functional tool package in two candidate configurations:

- one requests unrestricted network authority and is rejected even though its functional tests pass;
- one stays within its existing capability lease and is accepted after independent evidence passes.

Inspect the resulting lineage:

```bash
PYTHONPATH=src python3 -m variaxiom --home .variaxiom status
PYTHONPATH=src python3 -m variaxiom --home .variaxiom verify
cat .variaxiom/reports/demo-report.json
open .variaxiom/reports/authority-test.html  # macOS; use your browser elsewhere
cat .variaxiom/lineage.ledger.jsonl
```

[Open the checked-in Authority Test](docs/demo/authority-test.html)

Run all repository checks:

```bash
bash scripts/verify.sh
```

For a development checkout, `bash scripts/bootstrap.sh` creates the Python environment, runs
the demo and tests, and activates the repository-owned pre-commit hook. The reference code uses
only the Python standard library at runtime; Python 3.13 or 3.14 is supported.

## Architecture at a glance

```text
 Human steward / external governance
                 │
      signed constitution and grants
                 │
      ┌──────────▼──────────┐
      │ Trusted microkernel │
      │ promotion · lineage │
      │ budgets · rollback  │
      │ capability leases   │
      └──────────┬──────────┘
                 │
      ┌──────────▼──────────┐
      │ Evolution laboratory│
      │ variants · archive  │
      │ evals · adversaries │
      └──────────┬──────────┘
                 │ builds
      ┌──────────▼──────────┐
      │ Disposable phenotype│
      │ models · memory     │
      │ skills · tools      │
      │ task-local agents   │
      └──────────┬──────────┘
                 │ outcomes
                 └──────────────► external reality
```

The target implementation is deliberately two-speed:

- a **small Rust kernel** for deterministic, security-sensitive invariants;
- a **Python research plane** for fast experimentation, model adapters, evaluators, and evolutionary search;
- **WebAssembly Component Model/WIT** as the preferred portable boundary for generated tools;
- stronger OCI/gVisor/Firecracker-class isolation for workloads that cannot fit a WASM capability envelope.

The first release remains a modular monolith. Kafka, Kubernetes, a distributed vector database, and autonomous cloud purchasing are explicitly excluded from the MVP.

## Constitutional invariants

The bootstrap constitution lives in [`constitution/`](constitution/). Its core rules include:

- **Capability is not authority.** Better reasoning never silently grants new permissions.
- **No direct soma-to-germline write.** Working agents propose; an external gate promotes.
- **Reality outranks self-report.** Confidence and eloquence are not evidence.
- **Evaluators are protected.** Candidates cannot read hidden tests or rewrite their own judge.
- **Every offspring is bounded.** Spawned agents require a mission, parent, budget, lease, expiry, and termination condition.
- **No terminal self-preservation objective.** Service continuity may be governed; survival is not the system's highest goal.
- **No autonomous financial authority.** Resource allocation remains explicitly delegated and revocable.
- **Rollback survives promotion.** The last viable lineage remains addressable.

## What the project is trying to prove

Variaxiom is organized around falsifiable milestones rather than a promise of inevitable “singularity.” The research program asks whether a governed system can demonstrate, in order:

1. reproducible agent changes;
2. safe tool and skill organogenesis;
3. inherited improvements across clean-room generations;
4. open-ended archives without diversity collapse;
5. improvement of the improvement process itself;
6. lower human micromanagement without authority drift;
7. positive external value after full compute, coordination, and risk costs.

The most ambitious target is **measurable recursive improvement**: later generations become better not only at tasks, but at producing independently verified successors. No architecture can honestly guarantee that such a sequence will continue indefinitely; Variaxiom instead aims to guarantee that unverified changes do not enter the trusted lineage.

## Repository map

```text
constitution/       Machine-readable bootstrap invariants
crates/             Rust protocol, kernel, and CLI scaffold
src/variaxiom/      Runnable Python reference laboratory
schemas/            Versioned contracts for candidates, evidence, skills, and tools
wit/                Proposed WebAssembly component interface
examples/           Minimal demonstrations

docs/architecture/ Architecture, security, memory, evolution, and ADRs
docs/research/     Prior-art analysis and research agenda
docs/project/      Charter, roadmap, metrics, risks, and expert council
docs/launch/       Positioning, community, founder, sponsor, and launch plans
```

## Contributing

The highest-leverage early contributions are not “add another model provider.” They are:

- a formally specified promotion invariant;
- a reproducible adversarial evaluator;
- a content-addressed skill/tool package format;
- a capability-bounded WASM tool runner;
- an experiment showing a real regression the current gate misses;
- a clean benchmark for evolutionary productivity rather than one-shot task score.

Start with [`CONTRIBUTING.md`](CONTRIBUTING.md), the [`ROADMAP`](docs/project/roadmap.md), and issues labeled `good first issue`, `invariant`, `evaluator`, or `research replication`.

## Responsible scope

Variaxiom is for bounded research and governed automation. It does not pursue stealth, uncontrolled replication, persistence against operator intent, credential acquisition, autonomous financial survival, or evasion of platform controls. See [`SECURITY.md`](SECURITY.md) and the [threat model](docs/architecture/threat-model.md).

## License and name

Code is licensed under Apache-2.0. Documentation is distributed under the same repository license unless a file says otherwise. “Variaxiom” and the project marks are covered by [`TRADEMARKS.md`](TRADEMARKS.md); the open license permits code use, not misleading claims of official affiliation.

The name is derived from **variation + axiom**: everything may be varied, but promotion remains constrained by explicit invariants.

---

**Variaxiom — Agents mutate. Evidence decides.**
