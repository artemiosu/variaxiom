# Increment specifications

Specifications are the executable bridge between the roadmap and implementation. One active
specification should normally exist at a time.

## Definition of Ready

An increment is ready when it has:

- a bounded problem and explicit non-goals;
- linked `REQ-*` identifiers;
- trust-boundary and authority impact;
- normative inputs, outputs, errors, and versioning rules;
- acceptance criteria with named evidence;
- rollback or removal plan;
- unresolved questions called out rather than silently assumed.

## Definition of Done

An increment is done when:

- every acceptance criterion has reproducible evidence;
- positive, negative, regression, and relevant adversarial tests pass;
- schemas, public documentation, threat model, and traceability are updated;
- Python and Rust agree where the protocol crosses both implementations;
- format, lint, test, repository verification, and clean-clone bootstrap pass;
- promotion-sensitive changes receive independent review;
- `docs/project/current.md` and `project.yaml` reflect the new state.

Use lowercase milestone identifiers in filenames, for example
`m1.1-cross-language-conformance.md`. A specification is normative only after review; roadmap
prose remains directional.

## Increment registry

- [`m1.1-cross-language-conformance.md`](m1.1-cross-language-conformance.md) — implemented and
  independently reproduced; external security review remains separate.
- [`m2.1-identity-grants-signatures.md`](m2.1-identity-grants-signatures.md) — accepted after a
  unanimous three-role automated security-council review; schemas and shared fixtures precede the
  disabled verifier implementation.
