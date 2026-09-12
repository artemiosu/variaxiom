# Current development context

- **Reviewed:** 2026-09-11
- **Release:** 0.1.0-alpha seed (unreleased; no Git tag yet)
- **Current product increment:** M2.1 — identity, authority grants, and detached signatures
- **Active specification:** [`../specs/m2.1-identity-grants-signatures.md`](../specs/m2.1-identity-grants-signatures.md) (issue #16 correction accepted for disabled experimental implementation)

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

The initial M2.1 schema/shared-fixture baseline contained 237 cases plus 19 curated Wycheproof
vectors. Three isolated automated reviewers reached unanimous PASS on revision
`84467c08d3867a807b3328cb1410ba91b2852654`. Stage-eleven review then superseded that result
contract through issue #16; the current accepted corpus is the 252-case correction described
below. Neither review is a human security audit, and no M2.1 runtime may yet authorize or append
durable lineage.

Automated stage-eleven review of draft implementation PR
[#12](https://github.com/artemiosu/variaxiom/pull/12) found a contract defect: 27 live fixture
results set `authorizing: true`, including two rejected policy decisions, and the distinct
two-phase public result schemas were not frozen. Correction issue
[#16](https://github.com/artemiosu/variaxiom/issues/16) now has four exact non-authorizing result
schemas, an `evaluate-new` entry point, direct selector adversarial and point/scalar boundary cases,
replay-to-anchor digest binding, and a 252-case inventory. Three isolated automated reviewers
reported unanimous PASS with no P0/P1 on revision
`7642611c014ff683a6aadc614f709ca959f8583b`; GitHub CI and an independent clean-clone bootstrap also
passed. The public report is
[`../reports/m2.1-result-contract-council-2026-09-11.md`](../reports/m2.1-result-contract-council-2026-09-11.md).
This is not a human security audit and does not enable an authorizing runtime.

Disabled runtime implementation is tracked in [issue #11](https://github.com/artemiosu/variaxiom/issues/11)
and follows the bounded [implementation plan](m2.1-runtime-implementation.md). The frozen corpus is
an input to that work and cannot be silently changed by the implementation PR. Its first draft
now implements all eleven internal frozen stages in both Python and Rust: canonical wire,
structural validation, trusted-context binding, target/key digest recomputation, and anchored
identity/role/revocation checks followed by the strict Ed25519 profile, exact evidence and grant
binding, constitution/artifact binding, deterministic M1.1 policy, exact decision comparison, and
promotion-selector verification. Both implementations match all 252 accepted cases at their
assigned boundary, including 51 policy decisions and 49 stage-eleven results. The distinct public
`evaluate_new`, `verify_attested_proposal`, `replay_historical`, `initialize_anchor`, and
`advance_anchor` operations return the accepted result shapes; replay binds the exact separately
supplied anchor snapshot actually used by verification. Every result fixes `authorizing` to
`false`, returned anchor data is immutable, and callers cannot directly construct a successful
result. Only the five normative operations are supported by the Python facade and Rust kernel
crate. Rust keeps its cross-crate protocol bridge hidden from generated documentation, and the
history carrier exists only under the explicit non-default `conformance` feature. The
implementation remains disabled and cannot sign, append, or activate durable lineage.

The issue #16 contract correction removed the earlier positive-authority fixture defect and is
now consumed by the completed disabled implementation. Exact revision
`ec38563d93bab1854592caebbad31a67d7e714a2` passed a fresh public-clone bootstrap and full verify,
the Linux/macOS/Windows GitHub matrix, CodeQL, dependency review, and three isolated automated
review roles with no P0/P1/P2. The public evidence is recorded in
[`../reports/m2.1-implementation-council-2026-09-11.md`](../reports/m2.1-implementation-council-2026-09-11.md).
This is still not a human security audit, production cryptography certification, or authority
capability.

## Next

1. Merge reviewed PR #12 and close issue #11 without enabling the verifier or lineage append.
2. M2.2 — specify transactional SQLite lineage, exact-head compare-and-swap, idempotency, crash
   recovery, and deterministic projections before implementation.
3. M2.3 — tamper/replay/fault-injection suite and rollback drill.

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
