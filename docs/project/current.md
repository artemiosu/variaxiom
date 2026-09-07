# Current development context

- **Reviewed:** 2026-09-07
- **Release:** 0.1.0-alpha seed (unreleased; no Git tag yet)
- **Current product increment:** M2.1 — identity, authority grants, and detached signatures
- **Active specification:** [`../specs/m2.1-identity-grants-signatures.md`](../specs/m2.1-identity-grants-signatures.md) (accepted for disabled experimental implementation)

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
14-event ledger, and clean final worktree. The report is published in closed issue #3.

M2.1 is now the active **accepted specification**. It defines principals, trusted key bindings,
exact-candidate authority grants, explicit time/revocation snapshots, and detached Ed25519
signatures. Three isolated automated reviewers reached unanimous PASS with no remaining P0/P1.
This authorizes only schemas and shared adversarial fixtures first; the verifier remains disabled
and cannot append durable lineage.

## Next

1. Review the M2.1 schema and shared-fixture freeze in its dedicated PR; no gate behavior changes.
2. Complete every normative adversarial/boundary fixture group, then add matching disabled
   Python/Rust verification.
3. M2.2 — transactional SQLite lineage and projections.
4. M2.3 — tamper/replay/fault-injection suite and rollback drill.

## Open decisions

- production key custody and rotation remain unresolved beyond the M2.1 verifier contract;
- decide whether a future envelope version adopts full RFC 8785/JCS;
- appoint a second trusted maintainer before requiring one external approval on `main`;
- choose the first external harness adapter no earlier than the adapter contract specification.

## Parallel launch work

- record the two-minute Authority Test demo;
- publish a small curated issue set rather than copying the whole roadmap;
- publish implementation evidence after the schemas/fixture freeze and differential verification.

## External blockers

- SSH authentication is unavailable (`Permission denied (publickey)`); HTTPS is the verified Git
  transport and should remain configured unless an operator installs and tests an SSH key;
- no external blocker prevents the schemas/shared-fixtures phase.

## Context rule

For any task, start at [`../context/index.md`](../context/index.md), read only the named context
pack, then inspect the implementation. Update this file when the active increment or verified
baseline changes.
