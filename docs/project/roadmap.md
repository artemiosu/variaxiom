# Roadmap

Dates are targets, not promises. Every phase has an exit gate; features do not substitute for evidence.

## Phase 0 — Seed (September 2026)

**Goal:** establish the category and make one invariant visible.

Delivered in the seed:

- name, constitution, schemas, architecture, governance, and launch plan;
- standard-library Python promotion demo;
- immutable artifact store and hash-chained ledger;
- Rust kernel/protocol scaffold;
- WIT component interface;
- repository verification tests.

**Exit gate:** a third party can clone, run, and understand why a functionally passing candidate is rejected for authority expansion.

## Phase 1 — Credible kernel (weeks 1–6)

- compile and test Rust workspace in CI;
- canonical envelope and schema conformance tests across Rust/Python;
- Ed25519 signing of candidate/evidence/decision envelopes;
- SQLite transactional store and projections;
- explicit identity and authority-grant objects;
- tamper/replay/fault-injection suite;
- static HTML lineage report.

**Exit gate:** promotion is transactional, signed, reproducible, and rollback-tested.

## Phase 2 — Isolated organogenesis (weeks 5–12)

- Wasmtime host with fuel, epoch, memory, and import limits;
- generated tool package builder;
- lease-backed WIT host functions;
- SBOM/provenance capture;
- contract, property, and adversarial tool tests;
- first browser/OCI worker design, not enabled by default.

**Exit gate:** an agent-generated tool gains a new bounded capability without host or secret access beyond its manifest.

## Phase 3 — External harness adapters (months 3–5)

- generic trace/candidate adapter SDK;
- reference integrations for two distinct agent systems;
- same-model control experiments;
- standardized task/evidence bundle;
- public comparison report.

Candidate integrations: Codex/Claude Code via observable task runners where permitted, plus one fully open harness such as DeepSeek Harness or Hermes.

**Exit gate:** two unrelated harnesses can submit candidates into the same promotion/evidence protocol.

## Phase 4 — Evidence-gated memory (months 4–7)

- structured claim store with provenance, scope, confidence, TTL, and contradictions;
- episode → hypothesis → candidate skill pipeline;
- clean-room skill replay;
- negative-knowledge revalidation;
- memory poisoning benchmark.

**Exit gate:** the system learns a reusable procedure while rejecting a plausible but false session-derived rule.

## Phase 5 — Population and archive (months 6–10)

- multiple lineages and parent selection;
- Pareto archive and behavioral novelty metrics;
- experiment budget scheduler;
- duplicate-work detection;
- bounded multi-agent cell contracts and apoptosis;
- diversity-collapse diagnostics.

**Exit gate:** an archive-based run produces a better held-out descendant than single-lineage overwrite under matched cost.

## Phase 6 — Self-harness experiment (months 9–14)

- verifier-grounded weakness mining;
- explicit editable-surface map;
- narrow harness proposal operators;
- held-in/held-out regression gates;
- evaluator-hacking challenge set;
- independent reproduction report.

**Exit gate:** a fixed-model agent improves its own harness on held-out tasks, and the gain survives clean reconstruction and adversarial evaluation.

## Phase 7 — Evolutionary productivity (months 12–20)

- metaproductivity benchmark;
- mutation-operator candidates;
- optimizer/parent-selection candidates;
- multi-generation statistical protocol;
- full cost/human-intervention accounting.

**Exit gate:** a candidate improver produces better verified descendants per unit total cost across repeated trials.

## Phase 8 — Model adaptation research (18+ months)

- synthetic-data provenance and filtering;
- small/open-model LoRA or distillation experiments;
- joint harness/weight controls;
- model-collapse and evaluator-gaming defenses;
- reproducible training lineage.

**Exit gate:** joint adaptation beats harness-only and weight-only controls without critical regression or data leakage.

## Phase 9 — Federated research ecosystem (after protocol stability)

- signed external evidence/candidate packages;
- reproducible remote experiments;
- local trust policies;
- grant-funded benchmark and red-team programs;
- hosted observatory as an optional sustainability path.

**Exit gate:** independent organizations contribute and verify lineages without surrendering governance or secrets.

## Things deliberately postponed

- plugin marketplace;
- autonomous production actions;
- multi-tenant cloud service;
- autonomous financial resource acquisition;
- unrestricted browser/computer-use workers;
- Kubernetes-scale deployment;
- claims of general recursive self-improvement.
