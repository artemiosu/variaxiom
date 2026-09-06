# ADR 0010: Ed25519 detached signatures and explicit trust roots

- **Status:** proposed; security review required before acceptance
- **Date:** 2026-09-06
- **Decision owner:** bootstrap maintainer under the founder review exception for proposal only
- **Specification:** [`../../specs/m2.1-identity-grants-signatures.md`](../../specs/m2.1-identity-grants-signatures.md)

## Context

M1.1 stabilizes canonical protocol bytes, but identity labels and grant maps are not authenticated.
The next increment needs signatures without making three dangerous equivalences: key equals
principal, signature equals authority, or current mutable trust state equals historical truth.

The implementation must remain small, cross-platform, and interoperable between Python and Rust.
It must not implement elliptic-curve arithmetic itself or place private keys inside the trusted
verification kernel.

## Decision

Use RFC 8032 Ed25519 with application-level domain separation over the SHA-256 identity of an exact
canonical envelope. Signatures are detached so candidate, evidence, grant, and decision identities
remain stable when attestations are added.

Represent public keys as raw 32-byte Ed25519 values and signatures as raw 64-byte values, both in
canonical unpadded base64url. Derive `key_id` from SHA-256 of the raw public key. Bind keys to
principals and roles only through an explicit trusted snapshot committed by `promotion-input/v2`.

Use the maintained [`cryptography`](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/)
Ed25519 API in Python and [`ed25519-dalek`](https://docs.rs/ed25519-dalek/latest/ed25519_dalek/)
in Rust. Use each library only for key decoding, signing in test/CLI boundaries, and verification;
canonicalization, domain construction, trust policy, and grant policy remain project code with
shared fixtures. Exact dependency versions are committed in the lock files during implementation.

The verifier accepts no caller-provided prebuilt signing message. It validates the target, computes
its digest, constructs the normative domain-separated bytes, and then verifies.

## Consequences

- widely reviewed cryptographic implementations replace bespoke crypto;
- raw keys avoid PEM/DER parser variability on the protocol wire;
- detached signatures permit multiple attestations without changing target identity;
- trusted snapshots make role, revocation, and historical replay explicit;
- application-level domain separation works in both chosen libraries without depending on
  Ed25519ctx or Ed25519ph support;
- Python gains a compiled dependency, increasing bootstrap and supply-chain surface;
- key custody, rotation, threshold authorization, and hardware-backed signing remain separate
  operational problems.

## Alternatives considered

- **HMAC:** rejected because every verifier would also gain signing power.
- **RSA-PSS or ECDSA:** rejected for larger wire objects or greater encoding/nonce complexity without
  a demonstrated project benefit.
- **Ed25519ctx/Ed25519ph:** deferred because the selected Python API exposes standard Ed25519 and an
  explicit project message provides portable domain separation.
- **PEM, DER, or JWK on the protocol wire:** rejected for v1 because one raw Ed25519 key needs no
  algorithm-negotiation container. Import/export adapters may support them later.
- **DID or network key resolution:** rejected because mutable resolution adds network and governance
  ambiguity to a local deterministic gate.
- **Embed signatures in target objects:** rejected because it creates circular identity problems
  and changes content identity for each signer.
- **Treat `key_id` as authority:** rejected because compromised or self-generated keys must not
  acquire a principal or role without a trusted governance binding.

## Security review notes

Review must cover canonical base64url enforcement, small-order/non-canonical signature behavior,
wrong-domain vectors, key/role aliasing, expiry boundaries, replay, revocation snapshots, error
oracles, dependency features, and secret-free logs. Shared fixtures define the accepted behavior if
library defaults differ.

## Rollback

Do not remove or reinterpret M1.1. Until M2.1 is released, the signature-aware v2 entry point can be
removed while retaining fixtures and experimental events. After release, changes use a new signed
protocol version.

