# Reproducibility

Variaxiom treats reproducibility as a product feature, not an appendix.

## Reference environment

- Python 3.13 or 3.14;
- no third-party Python runtime dependencies for the current demo;
- Linux, macOS, or another environment with POSIX-compatible shell scripts;
- Rust stable compatible with `rust-toolchain.toml` for the kernel scaffold.

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
ba30063e36b5f184af58273c08f886635053e3e15b427e7354defdfdc2e64fdc
```

## Run the complete local verification

```bash
bash scripts/verify.sh
```

This performs:

1. repository structure and local-link checks;
2. JSON Schema syntax checks;
3. Python unit tests;
4. a clean demo run;
5. hash-chain verification.

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
