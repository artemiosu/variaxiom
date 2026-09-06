# Reproducibility

Variaxiom treats reproducibility as a product feature, not an appendix.

## Reference environment

- Python 3.13 or 3.14;
- no third-party Python runtime dependencies for the current demo;
- Linux, macOS, or another environment with POSIX-compatible shell scripts;
- Rust 1.98.1 as pinned by `rust-toolchain.toml` for the kernel.
- development-only Python validation dependencies installed by `scripts/bootstrap.sh`.

## Reproduce the Authority Test

```bash
bash scripts/demo.sh
```

Then verify the lineage:

```bash
PYTHONPATH=src python3 -m variaxiom --home .variaxiom verify
```

The deterministic fixture uses fixed timestamps and canonical JSON. Clean runs should produce this lineage head:

```text
9cbe298edea1d7b03cf3bc175dd8a2ec525ec545e9be4625d5a6d565238e3a13
```

## Run the complete local verification

```bash
bash scripts/verify.sh
```

This performs:

1. repository structure and local-link checks;
2. Draft 2020-12 metaschema and instance validation plus YAML/TOML parsing;
3. frozen shared Python/Rust canonical-envelope fixtures;
4. Python unit and conformance tests;
5. regeneration-drift detection for checked-in demo artifacts;
6. a clean demo run and hash-chain verification.

Run the Rust side of the same vectors with:

```bash
cargo fmt --all -- --check
cargo test --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

## Inspect the evidence

```text
.variaxiom/evidence/
.variaxiom/promotions/
.variaxiom/lineage.ledger.jsonl
.variaxiom/reports/demo-report.json
.variaxiom/reports/authority-test.html
```

## Compare two clean runs

```bash
rm -rf /tmp/vx-a /tmp/vx-b
PYTHONPATH=src python3 -m variaxiom --home /tmp/vx-a demo --reset >/dev/null
PYTHONPATH=src python3 -m variaxiom --home /tmp/vx-b demo --reset >/dev/null
sha256sum /tmp/vx-a/lineage.ledger.jsonl /tmp/vx-b/lineage.ledger.jsonl
```

The two hashes should match.

## Recorded clean-clone evidence

Revision `b0624843a0c21566395828ac50ca9e7382473807` was cloned from GitHub into an empty
temporary directory on 2026-09-06. Bootstrap, repository validation, 23 Python tests, the
14-event ledger check, 17 Rust tests, Rust formatting, and Clippy all passed. The same revision's
[Linux/macOS/Windows CI matrix](https://github.com/artemiosu/variaxiom/actions/runs/34060093302)
also passed. This records automated reproducibility; an external human reproduction remains a
separate release gate.

## Reproducibility boundaries

The current proof is deterministic because it uses a fixed evaluator fixture. Future model-backed experiments will not be assumed deterministic. They must record at least:

- model/provider/version identifier;
- prompt and harness version;
- sampling parameters;
- tool/environment image digest;
- input artifact hashes;
- evaluator version and hidden-pool identifier;
- seed when supported;
- wall time, compute, token, and monetary cost;
- repetitions and uncertainty interval.

A single successful run is evidence of possibility, not evidence of a stable inherited capability.
