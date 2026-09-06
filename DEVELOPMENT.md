# Development Guide

## Bootstrap philosophy

The first vertical slice deliberately uses the Python standard library so reviewers can understand the promotion semantics without first auditing a large dependency graph. The target architecture adds Rust and Wasmtime only where their boundaries create measurable value.

## Commands

```bash
make demo
make test
make verify
make clean
```

Direct CLI use:

```bash
PYTHONPATH=src python3 -m variaxiom --home .variaxiom demo --reset
PYTHONPATH=src python3 -m variaxiom --home .variaxiom verify
PYTHONPATH=src python3 -m variaxiom --home .variaxiom status
```

## Code boundaries

- `src/variaxiom/`: executable research reference, not the final security boundary.
- `crates/protocol/`: stable wire/domain types.
- `crates/kernel/`: deterministic rules only; no model, network, shell, or arbitrary plugin execution.
- `crates/cli/`: operator-facing tooling.
- `schemas/`: language-neutral contracts.
- `wit/`: future generated-tool ABI.

## Adding a feature

First determine the trust domain. If a feature generates hypotheses, calls models, retrieves memory, or runs experiments, it belongs in the research/evolution plane. If it must deny an unsafe promotion even when every model is compromised, it may belong in the kernel—but requires an ADR and constitutional review.

## Reproducibility

Record inputs, environment, model/provider/version when available, random seeds, budgets, artifact hashes, evaluator versions, and raw outcomes. Avoid storing chain-of-thought; store observable actions, concise rationales, and evidence required to reproduce decisions.
