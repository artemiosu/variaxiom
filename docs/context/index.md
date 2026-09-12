# Context index

This is the routing page for humans and coding agents. Read the core pack, then only the pack for
the surface being changed. Normative source files outrank summaries and generated graphs.

When sources conflict, stop the affected work and resolve the conflict explicitly. Precedence is:
constitution and machine-enforced invariants; accepted requirements; accepted ADRs; the active
accepted specification; schemas and implementation; current status; roadmap and strategy. A
lower-precedence source cannot silently weaken a higher-precedence source. Status never turns a
planned claim into a normative requirement, and generated context never resolves a conflict.

## Core pack for every change

1. [`../../AGENTS.md`](../../AGENTS.md)
2. [`../project/current.md`](../project/current.md)
3. [`../product/requirements.md`](../product/requirements.md)
4. the active file under [`../specs/`](../specs/)
5. [`../project/traceability.md`](../project/traceability.md)

## Trusted kernel and promotion

- [`../architecture/overview.md`](../architecture/overview.md)
- [`../architecture/capability-security.md`](../architecture/capability-security.md)
- [`../architecture/threat-model.md`](../architecture/threat-model.md)
- [`../../constitution/constitution.toml`](../../constitution/constitution.toml)
- `crates/protocol/`, `crates/kernel/`, `src/variaxiom/promotion.py`
- [`../project/agent-review-council.md`](../project/agent-review-council.md)

## Schemas and protocol compatibility

- [`../specs/m1.1-cross-language-conformance.md`](../specs/m1.1-cross-language-conformance.md)
- [`../specs/m2.1-identity-grants-signatures.md`](../specs/m2.1-identity-grants-signatures.md)
- [`../architecture/data-model.md`](../architecture/data-model.md)
- `schemas/`, `fixtures/conformance/`, `src/variaxiom/canonical.py`, `crates/protocol/`

## Identity, grants, and signatures

- [`../specs/m2.1-identity-grants-signatures.md`](../specs/m2.1-identity-grants-signatures.md)
- [`../project/m2.1-runtime-implementation.md`](../project/m2.1-runtime-implementation.md)
- [`../architecture/adr/0010-ed25519-detached-signatures.md`](../architecture/adr/0010-ed25519-detached-signatures.md)
- [`../architecture/capability-security.md`](../architecture/capability-security.md)
- [`../architecture/threat-model.md`](../architecture/threat-model.md)
- [`../project/risk-register.md`](../project/risk-register.md)

## Transactional lineage and recovery

- [`../specs/m2.2-transactional-sqlite-lineage.md`](../specs/m2.2-transactional-sqlite-lineage.md)
- [`../architecture/adr/0011-transactional-sqlite-lineage.md`](../architecture/adr/0011-transactional-sqlite-lineage.md)
- [`../architecture/data-model.md`](../architecture/data-model.md)
- [`../architecture/threat-model.md`](../architecture/threat-model.md)
- [`../project/risk-register.md`](../project/risk-register.md)
- `crates/kernel/` and the future frozen `schemas/v3/` and transaction fixtures

## Evaluation and research

- [`../research/evaluation-framework.md`](../research/evaluation-framework.md)
- [`../research/research-agenda.md`](../research/research-agenda.md)
- [`../architecture/evolution-loop.md`](../architecture/evolution-loop.md)

## WASM and generated tools

- [`../architecture/adr/0003-wasm-component-boundary.md`](../architecture/adr/0003-wasm-component-boundary.md)
- [`../architecture/capability-security.md`](../architecture/capability-security.md)
- [`../../wit/variaxiom-tool.wit`](../../wit/variaxiom-tool.wit)
- [`../../schemas/tool-manifest.schema.json`](../../schemas/tool-manifest.schema.json)

## Memory

- [`../architecture/memory.md`](../architecture/memory.md)
- [`../architecture/adr/0004-soma-germline-separation.md`](../architecture/adr/0004-soma-germline-separation.md)

## Operations and releases

- [`../architecture/deployment.md`](../architecture/deployment.md)
- [`../../SECURITY.md`](../../SECURITY.md)
- [`../../REPRODUCIBILITY.md`](../../REPRODUCIBILITY.md)
- [`../reports/m1.1-independent-reproduction-2026-09-06.md`](../reports/m1.1-independent-reproduction-2026-09-06.md)
- [`../reports/m2.1-schema-fixture-council-2026-09-07.md`](../reports/m2.1-schema-fixture-council-2026-09-07.md)
- [`../reports/m2.1-result-contract-council-2026-09-11.md`](../reports/m2.1-result-contract-council-2026-09-11.md)
- [`../reports/m2.1-implementation-council-2026-09-11.md`](../reports/m2.1-implementation-council-2026-09-11.md)
- [`../project/github-setup.md`](../project/github-setup.md)

## Product and community

- [`../product/mvp-scope.md`](../product/mvp-scope.md)
- [`../project/roadmap.md`](../project/roadmap.md)
- [`../project/metrics.md`](../project/metrics.md)
- [`../launch/launch-strategy.ru.md`](../launch/launch-strategy.ru.md)

## Derived tooling policy

Knowledge graphs, generated summaries, and assistant indexes may accelerate navigation, but they
are disposable views. They must record their source revision and must never become the only place
where a requirement, decision, or security invariant exists.
