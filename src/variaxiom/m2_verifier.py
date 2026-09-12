"""Public non-authorizing M2.1 verification API.

The staged inspectors and conformance-history carrier are deliberately kept in
the private implementation module. Public callers receive only the five
normative operations and their sealed result types.
"""

from ._m2_verifier import (
    AnchorTransitionResult,
    EvaluatedProposal,
    ReplayResult,
    VerificationResult,
    VerifiedProposal,
    advance_anchor,
    evaluate_new,
    initialize_anchor,
    replay_historical,
    verify_attested_proposal,
)

__all__ = [
    "AnchorTransitionResult",
    "EvaluatedProposal",
    "ReplayResult",
    "VerificationResult",
    "VerifiedProposal",
    "advance_anchor",
    "evaluate_new",
    "initialize_anchor",
    "replay_historical",
    "verify_attested_proposal",
]
