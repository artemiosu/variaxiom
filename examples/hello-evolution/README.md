# Hello Evolution

This example is intentionally smaller than a real agent harness. It proves one
architectural claim:

> A candidate can pass functional tests and still be rejected when it asks for
> authority it does not need.

Run from the repository root:

```bash
PYTHONPATH=src python3 -m variaxiom.cli demo --reset
```

The demo creates two descendants of the same seed:

1. `candidate:slug-tool-unbounded` asks for unrestricted network access. Its
   functional checks pass, but the constitutional gate rejects it.
2. `candidate:slug-tool-bounded` asks for no new authority. Independent checks
   pass and it is promoted.

Inspect `.variaxiom/lineage.ledger.jsonl` and
`.variaxiom/reports/demo-report.json` after the run.

This bootstrap does **not** execute arbitrary model-generated code. That boundary
will be implemented behind a WebAssembly/container isolation port rather than
inside the Python process.
