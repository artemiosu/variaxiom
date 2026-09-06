# Current development context

- **Reviewed:** 2026-09-06
- **Release:** 0.1.0-alpha seed (unreleased; no Git tag yet)
- **Current product increment:** M1.1 — cross-language canonical decision envelope
- **Active specification:** [`../specs/m1.1-cross-language-conformance.md`](../specs/m1.1-cross-language-conformance.md)

## Current verified baseline

- baseline revision: `b0624843a0c21566395828ac50ca9e7382473807`;
- the public repository, Discussions, Pages, branch protection, security settings, and private
  vulnerability reporting were authenticated and checked on 2026-09-06;
- Python Authority Test is deterministic and its 14-event ledger verifies;
- Python unit suite and Rust kernel tests pass locally and in the Linux/macOS/Windows matrix;
- CI, CodeQL, dependency review, Dependabot, and OpenSSF workflows are configured;
- Rust 1.98.1 and Python 3.13/3.14 are the supported development baseline;
- the trusted implementation remains a local modular monolith.

The display release, Python package version (`0.1.0a0`), and Rust workspace version
(`0.1.0-alpha.0`) express the same pre-release intent in different ecosystem syntaxes. They do
not claim that a release tag exists; `project.yaml` records the authoritative release state.

## Now

M1.1 is published and its automated evidence passes: Python and Rust share a versioned decision
envelope, canonical bytes, digest rules, reason codes, and conformance fixtures; the required
GitHub matrix is green and a fresh clone reproduced the complete bootstrap and verification at
`b062484`. An independent automated conformance audit found no remaining P0/P1 blocker. External
human review remains open, so do not begin signatures or persistence until that review is recorded.

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

- SSH authentication is unavailable (`Permission denied (publickey)`); HTTPS is the verified Git
  transport and should remain configured unless an operator installs and tests an SSH key;
- obtain an external human review of the promotion-sensitive M1.1 contract;
- upload the checked-in social preview through the GitHub repository UI.

## Context rule

For any task, start at [`../context/index.md`](../context/index.md), read only the named context
pack, then inspect the implementation. Update this file when the active increment or verified
baseline changes.
