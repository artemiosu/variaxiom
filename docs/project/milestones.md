# Initial Milestones and Issue Map

## M0 — Public seed

- [x] Create public GitHub repository and push seed commit.
- [x] Enable Discussions and founder-compatible branch protection.
- [ ] Confirm private vulnerability reporting after GitHub authentication is restored.
- [ ] Upload the checked-in social preview through GitHub repository settings.
- [x] Add repository description, topics, and Pages website.
- [ ] Record a two-minute demo GIF/video.
- [ ] Open five curated `good first issue` tasks.

## M1 — Cross-language conformance

- [ ] Compile and test the Rust workspace on Linux/macOS/Windows CI.
- [x] Add shared JSON fixtures for Python/Rust decisions.
- [x] Specify canonical JSON and a signature-ready decision envelope.
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
