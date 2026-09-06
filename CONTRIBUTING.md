# Contributing to Variaxiom

Thank you for helping build a system where agent improvement is a claim that must earn evidence.

## Before opening code

1. Read the [current context](docs/project/current.md) and follow the task-specific pack in the [context index](docs/context/index.md).
2. For behavior, protocol, or trust-boundary changes, open an RFC issue before a large pull request.
3. Keep the trusted kernel small. Features belong outside the kernel unless they enforce an invariant that cannot be delegated safely.
4. Never solve a failed check by weakening the check without an explicit evaluator-change RFC.

## Contribution tracks

- **Invariant:** specify and test a property that must survive all evolution.
- **Evaluator:** build deterministic, hidden, adversarial, or external-outcome evaluations.
- **Runtime:** capability broker, sandbox, artifact store, or lineage infrastructure.
- **Evolution:** population, archive, diversity, parent selection, and mutation operators.
- **Memory:** provenance, confidence, TTL, contradiction, revalidation, and forgetting.
- **Research replication:** reproduce published results and document deviations.
- **Developer experience:** one-command demos, diagnostics, docs, and examples.

## Development setup

Python reference plane:

```bash
python3 --version  # 3.13 or 3.14
bash scripts/verify.sh
```

Optional editable install:

```bash
python3 -m pip install -e .
variaxiom demo --reset
```

Rust kernel scaffold:

```bash
cargo fmt --all --check
cargo test --workspace
```

The project intentionally keeps the bootstrap Python path standard-library-only. Proposed dependencies need an ADR or a clear explanation of why the standard library is insufficient.

## Pull-request evidence

A PR that changes behavior should include:

- the failure mode or hypothesis it addresses;
- the editable surface and trust domain affected;
- tests that fail before and pass after the change;
- regression checks for preserved behavior;
- authority and data-flow impact;
- cost/latency impact where relevant;
- rollback procedure;
- limitations and known counterexamples.

A new skill or tool package should additionally include a manifest, provenance, required capabilities, deterministic checks, adversarial cases, environment scope, and expiry/revalidation policy.

## Commit and review rules

- Use focused commits and clear conventional-style subjects where practical.
- Sign off commits under the [Developer Certificate of Origin](DCO.md): `git commit -s`.
- Two independent reviews are the target for changes to `constitution/`, `crates/kernel/`, schemas, promotion logic, security policy, or evaluator acceptance criteria. During bootstrap, while only one maintainer exists, the founder may merge after all required evidence passes, but must record the exception in the PR. This exception ends when a second trusted maintainer is appointed.
- The proposer must not be the only reviewer of a promotion-rule change.
- Generated code must be identified and reviewed to the same standard as human-written code.

## Tests

Run:

```bash
bash scripts/verify.sh
```

Do not submit a benchmark-only improvement without held-out or adversarial evaluation. Do not delete a failing test merely because it blocks a desired candidate.

## Responsible research

Do not contribute features whose primary purpose is persistence against operator intent, unbounded propagation, credential acquisition, stealth, uncontrolled resource purchasing, bypassing platform restrictions, or hiding actions from audit. Research on these risks is welcome in isolated test fixtures and threat models, not as deployable capabilities.

## Communication

Use Issues for actionable work, Discussions for research questions and design exploration, and RFCs for decisions that change architecture or governance. Critique ideas and evidence, not people.
