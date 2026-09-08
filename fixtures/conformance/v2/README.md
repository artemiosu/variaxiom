# M2.1 conformance fixtures

This directory contains the implementation-independent M2.1 wire-contract candidate.

- `base-attested-proposal.json` is a complete schema-valid proposal with four distinct test
  principals and deterministic signatures.
- `golden-signature.json` freezes the selector target digest, exact signing-message bytes, public
  key, and detached signature.
- `manifest.json` points to self-contained positive, negative, boundary, replay, and transition
  cases under `cases/`.
- every case carries exact canonical input bytes, their digest, its trusted anchor or ordered
  anchor history, expected reached stage/code, exact resulting anchor where applicable, and the
  relevant complete signature vectors.
- `schemas/v2/anchor-initialization.schema.json` defines the exact genesis input used by the
  `initialize-anchor` entry point.
- `schemas/v2/anchor-history.schema.json` defines the bounded, closed transition-history carrier
  used only by conformance tests.

The only signing seeds in the generator are the four published RFC 8032 section 7.1 test vectors,
explicitly labelled non-secret interoperability material. No project-generated private key or
production credential is stored here. `scripts/regenerate_m2_fixtures.py` deterministically
rebuilds every object, digest, message, and test signature.

`scripts/verify_m2_fixtures.py` executes the normative stage order and checks every declared result.
It pins the complete ordered inventory at 232 cases with SHA-256
`879edaf3a061749e38c51de606cd35c9291316a80d69d6cbdfc9b3da619ffb58`; adding, removing,
renaming, moving, or reclassifying a case requires an explicit reviewed update to that pin. The
hashed UTF-8 preimage is one LF-terminated line per manifest entry in manifest order:
`<stage>:<case_id>:<fixture>`.
The Rust test independently verifies the same positive and invalid Ed25519 vectors with
`curve25519-dalek` and `ed25519-dalek::verify_strict`. JSON files are formatted for review, but
runners never treat those pretty-printed bytes as wire input; `input_base64url` is authoritative.
`wycheproof-ed25519-subset.json` adds a provenance-pinned Apache-2.0 subset of C2SP Project
Wycheproof; Python and Rust both execute every selected valid and invalid vector.

Schema resolution is offline and deterministic: consumers preload every `$id` from the repository
`schemas/` tree into a local Draft 2020-12 registry. HTTPS schema identifiers are stable names, not
network fetch instructions; the repository verifier exercises the published manifest wrapper with
that registry.

These fixtures do not enable the M2.1 runtime verifier and cannot append lineage. Freeze status is
granted only after the independent automated council reviews the exact commit and reports no P0/P1.
