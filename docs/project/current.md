# Current development context

- **Reviewed:** 2026-09-06
- **Release:** 0.1.0-alpha seed (unreleased; no Git tag yet)
- **Current product increment:** M1.1 — cross-language canonical decision envelope
- **Active specification:** [`../specs/m1.1-cross-language-conformance.md`](../specs/m1.1-cross-language-conformance.md)

## Current verified baseline

- baseline revision: `1f4eb7968d6c24425b58f0cebe6c4b7e6571bbba`;
- the public repository, Discussions, and Pages were observed live on 2026-09-06, but authenticated
  settings still require a fresh external-state check;
- Python Authority Test is deterministic and its 14-event ledger verifies;
- Python unit suite and Rust kernel tests pass;
- CI, CodeQL, dependency review, Dependabot, and OpenSSF workflows are configured;
- Rust 1.98.1 and Python 3.13/3.14 are the supported development baseline;
- the trusted implementation remains a local modular monolith.

The display release, Python package version (`0.1.0a0`), and Rust workspace version
(`0.1.0-alpha.0`) express the same pre-release intent in different ecosystem syntaxes. They do
not claim that a release tag exists; `project.yaml` records the authoritative release state.

## Now

M1.1 is implemented in the working tree: Python and Rust share a versioned decision envelope,
canonical bytes, digest rules, reason codes, and conformance fixtures. Its status remains pending
remote Linux/macOS/Windows matrix verification and an independent review. Do not begin signatures
or persistence until that evidence is recorded.

## Next

1. M2.1 — identity, authority grants, and signature envelopes.
2. M2.2 — transactional SQLite lineage and projections.
3. M2.3 — tamper/replay/fault-injection suite and rollback drill.
4. M2.4 — static lineage report backed by the transactional store.

## Open decisions

- select the Ed25519 library and key representation only after the signed bytes are stable;
- decide whether a future envelope version adopts full RFC 8785/JCS;
- appoint a second trusted maintainer before requiring one external approval on `main`;
- choose the first external harness adapter no earlier than the adapter contract specification.

## Parallel launch work

- upload the checked-in social preview in GitHub's repository UI;
- record the two-minute Authority Test demo;
- publish a small curated issue set rather than copying the whole roadmap;
- obtain the first independent clean-machine reproduction.

## External blockers

- recheck GitHub authentication, repository rules, and security settings from an authenticated
  session before treating them as current;
- recheck `ssh -T git@github.com`; the recorded baseline used HTTPS because SSH authentication
  was unavailable;
- upload the checked-in social preview through the GitHub repository UI.

## Context rule

For any task, start at [`../context/index.md`](../context/index.md), read only the named context
pack, then inspect the implementation. Update this file when the active increment or verified
baseline changes.
