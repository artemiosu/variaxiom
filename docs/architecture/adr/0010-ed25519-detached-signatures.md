# ADR 0010: Ed25519 detached signatures and explicit trust roots

- **Status:** proposed revision 4; final automated security-council re-review required before acceptance
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

An embedded snapshot is not a trust root. Live verification additionally requires an operator-
controlled anchor containing exact identity- and authorization-context digests, trust domain,
sequence, trusted time, a persistent key-ownership registry, and monotonic key/grant revocation
sets. The authorization context commits the constitution identity, lineage and parent authority,
and verified artifacts; the pinned constitution is the sole source of budget and verifier policy.
Historical replay is a separate non-authorizing API.
One key is bound to exactly one principal per trust domain and cannot be reassigned in v1; an
explicit anchor-transition function enforces that history.

Use PyNaCl's maintained libsodium-backed Ed25519 verification API in Python and
[`ed25519-dalek`](https://docs.rs/ed25519-dalek/latest/ed25519_dalek/)
in Rust. Use each library only for key decoding, signing in test/CLI boundaries, and verification;
canonicalization, domain construction, trust policy, and grant policy remain project code with
shared fixtures. Exact dependency versions are committed in the lock files during implementation.

Both runtimes first require canonical, decodable, non-identity prime-order-subgroup public keys and
`R` points. Python uses PyNaCl's libsodium point validator (libsodium 1.0.21+) and `VerifyKey.verify`;
Rust uses `curve25519-dalek` decompression/recompression plus `is_torsion_free`, followed by
`VerifyingKey::verify_strict`. Both reject `S >= L`. Batch, hazmat, prehash/digest, context,
PKCS#8/PEM, and serde features are disabled. The locked shared torsion, mixed-order, scalar, and
Wycheproof corpus prevents permissive library defaults from widening protocol acceptance.

The verifier accepts no caller-provided prebuilt signing message. It validates the target, computes
its digest, and constructs bytes containing domain version, algorithm, trust domain, principal,
key ID, signed kind, and digest, with an explicit `0x0A` delimiter after every field.

Signed evidence uses `evidence/v2.subject_candidate_digest`. Grants additionally bind the trust
domain, capability vocabulary, constitution digest, and lineage ID. M2.1 produces signed proposals
through a two-phase evaluate-then-selector-attest API only; exact-head durable authorization and
transactional compare-and-swap are deferred to M2.2.

## Consequences

- widely reviewed cryptographic implementations replace bespoke crypto;
- raw keys avoid PEM/DER parser variability on the protocol wire;
- detached signatures permit multiple attestations without changing target identity;
- trusted snapshots make role, revocation, and historical replay explicit;
- separately pinned anchors prevent self-minted or stale snapshots from authorizing new work;
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
oracles, dependency features, resource bounds, and secret-free logs. Shared fixtures define the
accepted behavior if library defaults differ.

Future algorithms require new key-ID and signature versions plus a new domain prefix. There is no
algorithm negotiation, downgrade, fallback, or reinterpretation of `Ed25519` in v1.

## Rollback

Do not remove or reinterpret M1.1. Until M2.1 is released, the signature-aware v2 verifier can be
removed while retaining fixtures and experimental events. It has no durable append capability.
After release, changes use a new signed protocol version; durable authorization remains unavailable
until M2.2 supplies exact-head transactional semantics.
