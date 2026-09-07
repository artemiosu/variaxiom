# M2.1 conformance fixtures

This directory freezes the first implementation-independent M2.1 wire contract.

- `base-attested-proposal.json` is a complete schema-valid proposal with four distinct test
  principals and deterministic signatures.
- `golden-signature.json` freezes the selector target digest, exact signing-message bytes, public
  key, and detached signature.
- `manifest.json` names the trusted anchor and shared positive/negative cases.

The signing keys were deterministic test material used once to create public signatures. No private
key or production credential is stored here. `scripts/regenerate_m2_fixtures.py` reconstructs the
objects and checks their canonical digests without generating keys or signatures.

These fixtures do not enable the M2.1 verifier. Later implementation commits must consume the same
files in Python and Rust and must extend the manifest with every boundary and adversarial class
required by the accepted specification before the disabled verifier can be considered complete.
