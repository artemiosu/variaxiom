# ADR 0009: Canonical promotion envelope v1

- **Status:** accepted for bootstrap implementation
- **Date:** 2026-09-06
- **Decision owner:** bootstrap maintainer under the documented founder review exception
- **Specification:** [`../../specs/m1.1-cross-language-conformance.md`](../../specs/m1.1-cross-language-conformance.md)

## Context

The seed Python and Rust gates represented the same concepts with different names, money types,
decision shapes, reason ordering, and error text. The seed decision fingerprint also committed to
evidence IDs but not the full evidence, context, grant selection, or policy. Signing those bytes
would preserve ambiguity and allow same-ID evidence replacement.

## Decision

Adopt a versioned canonical JSON profile shared by Python and Rust. Use integer micro-US dollars,
stable machine reason codes, sorted set-like collections, lowercase SHA-256, and fail-closed wire
parsing. Every decision includes `input_digest`, computed over a domain-separated promotion-input
envelope containing the exact candidate, complete evidence, trusted context, selected grant, and
constitution fields.

The protocol crate uses `serde`, `serde_json`, and `sha2`. These dependencies enlarge the trusted
surface but are preferable to a bespoke JSON parser or cryptographic implementation. Their exact
versions remain locked and reviewed by dependency automation.

## Consequences

- Python and Rust can compare exact canonical bytes and digests through one fixture corpus.
- Replacing any bound input changes `input_digest` even when identifiers are reused.
- Floats and out-of-safe-range integers cannot enter the v1 canonical surface.
- The pre-public seed field `estimated_cost_usd` changes incompatibly to
  `estimated_cost_micro_usd`.
- Signatures remain out of scope until these bytes have independent review.

## Alternatives considered

- **Keep implementation-specific JSON:** rejected because signatures and replay would disagree.
- **Use floating-point JCS immediately:** rejected to keep v1 cross-runtime semantics small.
- **Write dependency-free Rust JSON and SHA-256:** rejected because bespoke security primitives
  create a larger review burden than the locked, widely used libraries.
- **Hash only decision IDs and reason text:** rejected because it does not bind the decision to
  the facts that justified it.

## Follow-up

M2.1 must define signature domain separation, key identities, grant expiry/revocation, and exact
constitution artifact binding. A future RFC may adopt full RFC 8785, but it must use a new
envelope version rather than reinterpreting v1.
