# Current development context

- **Reviewed:** 2026-09-07
- **Release:** 0.1.0-alpha seed (unreleased; no Git tag yet)
- **Current product increment:** M1.1 — independently reproduced; human security review pending
- **Active specification:** [`../specs/m1.1-cross-language-conformance.md`](../specs/m1.1-cross-language-conformance.md)

## Current verified baseline

- independently reproduced revision: `e2a6a0f29bff9bd720433fefaebd4c4a26bbff2c`;
- M1.1 implementation revision: `b0624843a0c21566395828ac50ca9e7382473807`;
- the public repository, Discussions, Pages, branch protection, security settings, and private
  vulnerability reporting were authenticated and checked on 2026-09-06;
- Python Authority Test is deterministic and its 14-event ledger verifies;
- Python unit suite and Rust kernel tests pass locally and in the Linux/macOS/Windows matrix;
- CI, CodeQL, dependency review, Dependabot, and OpenSSF workflows are configured;
- the GitHub social preview is uploaded and the English-only Pages landing is published;
- Rust 1.98.1 and Python 3.13/3.14 are the supported development baseline;
- the trusted implementation remains a local modular monolith.

The display release, Python package version (`0.1.0a0`), and Rust workspace version
(`0.1.0-alpha.0`) express the same pre-release intent in different ecosystem syntaxes. They do
not claim that a release tag exists; `project.yaml` records the authoritative release state.

## Now

M1.1 is published and independently reproduced from the public repository. The clean-clone report
records the exact environment, commands, 23 Python tests, 17 Rust tests, eight shared fixtures,
14-event ledger, and clean final worktree. The evidence is published in closed issue #3. External
human security review remains open, so do not begin signatures or persistence until that review is
recorded.

## Next

1. Complete [independent security review issue #5](https://github.com/artemiosu/variaxiom/issues/5)
   for the proposed M2.1 contract in
   [PR #4](https://github.com/artemiosu/variaxiom/pull/4).
2. Accept the M2.1 specification before implementing identity, grants, or signatures.
3. M2.2 — transactional SQLite lineage and projections.
4. M2.3 — tamper/replay/fault-injection suite and rollback drill.

## Open decisions

- select the Ed25519 library and key representation only after the signed bytes are stable;
- decide whether a future envelope version adopts full RFC 8785/JCS;
- appoint a second trusted maintainer before requiring one external approval on `main`;
- choose the first external harness adapter no earlier than the adapter contract specification.

## Parallel launch work

- record the two-minute Authority Test demo;
- publish a small curated issue set rather than copying the whole roadmap;
- obtain the first independent human security review.

## External blockers

- SSH authentication is unavailable (`Permission denied (publickey)`); HTTPS is the verified Git
  transport and should remain configured unless an operator installs and tests an SSH key;
- complete external human security review
  [issue #5](https://github.com/artemiosu/variaxiom/issues/5) for the promotion-sensitive M1.1 and
  proposed M2.1 contracts.

## Context rule

For any task, start at [`../context/index.md`](../context/index.md), read only the named context
pack, then inspect the implementation. Update this file when the active increment or verified
baseline changes.
