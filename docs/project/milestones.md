# Initial Milestones and Issue Map

## M0 — Public seed

- [ ] Create public GitHub repository and push seed commit.
- [ ] Enable Discussions, private vulnerability reporting, branch protection, and required reviews.
- [ ] Add repository description, topics, social preview, and website placeholder.
- [ ] Record a two-minute demo GIF/video.
- [ ] Open five curated `good first issue` tasks.

## M1 — Cross-language conformance

- [ ] Compile Rust workspace on Linux/macOS/Windows.
- [ ] Add shared JSON fixtures for Python/Rust decisions.
- [ ] Specify canonical JSON and signature envelope.
- [ ] Add property tests for capability deltas and event chaining.

## M2 — Signed lineage

- [ ] Define identity/grant schema.
- [ ] Implement signing and verification.
- [ ] Add transactional SQLite store.
- [ ] Create static lineage report.
- [ ] Add rollback drill.

## M3 — WASM tool boundary

- [ ] Host minimal WIT component.
- [ ] Enforce fuel, memory, epoch, and output limits.
- [ ] Implement artifact read/write imports.
- [ ] Implement brokered domain-scoped HTTP import.
- [ ] Publish adversarial examples.

## M4 — First external integration

- [ ] Define adapter SDK.
- [ ] Capture trace from one open harness.
- [ ] Convert a proposed skill/tool change into a Variaxiom candidate.
- [ ] Evaluate and publish accepted/rejected evidence bundle.

## Suggested first contributor issues

1. **Good first issue:** render `demo-report.json` as a standalone HTML lineage card.
2. **Invariant:** add tests that an evidence item from another artifact can never satisfy a mandatory check.
3. **Schema:** add `$defs` for common identity/hash/timestamp types.
4. **Research replication:** reproduce the bootstrap demo on Python 3.14 across three operating systems.
5. **Security:** write a property-based adversarial corpus for malformed ledger events.
6. **WASM:** implement a no-network deterministic text tool component.
7. **Docs:** translate the architecture overview and contribution guide into Russian/Chinese.
8. **Evaluator:** create a metamorphic test pack for slug normalization.
