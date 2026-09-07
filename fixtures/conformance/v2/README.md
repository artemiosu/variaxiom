# M2.1 conformance fixtures

This directory contains the implementation-independent M2.1 wire-contract candidate.

- `base-attested-proposal.json` is a complete schema-valid proposal with four distinct test
  principals and deterministic signatures.
- `golden-signature.json` freezes the selector target digest, exact signing-message bytes, public
  key, and detached signature.
- `manifest.json` points to self-contained positive, negative, boundary, replay, and transition
  cases under `cases/`.
- every case carries exact canonical input bytes, their digest, its trusted anchor or ordered
  anchor history, expected stage/code, and the relevant complete signature vectors.

The only signing seeds in the generator are the four published RFC 8032 section 7.1 test vectors,
explicitly labelled non-secret interoperability material. No project-generated private key or
production credential is stored here. `scripts/regenerate_m2_fixtures.py` deterministically
rebuilds every object, digest, message, and test signature.

`scripts/verify_m2_fixtures.py` executes the normative stage order and checks every declared result.
The Rust test independently verifies the same positive and invalid Ed25519 vectors with
`curve25519-dalek` and `ed25519-dalek::verify_strict`. JSON files are formatted for review, but
runners never treat those pretty-printed bytes as wire input; `input_base64url` is authoritative.
`wycheproof-ed25519-subset.json` adds a provenance-pinned Apache-2.0 subset of C2SP Project
Wycheproof; Python and Rust both execute every selected valid and invalid vector.

These fixtures do not enable the M2.1 runtime verifier and cannot append lineage. Freeze status is
granted only after the independent automated council reviews the exact commit and reports no P0/P1.
