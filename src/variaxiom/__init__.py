"""Variaxiom reference laboratory.

The Python package is an executable specification of proof-gated agent
adaptation. It is intentionally small and dependency-light. Production-grade
untrusted-code isolation belongs outside the Python process.
"""

from .domain import Candidate, Evidence, PromotionDecision
from .ledger import HashChainLedger, LedgerVerification
from .m2_verifier import (
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
from .promotion import PromotionContext, PromotionGate

__all__ = [
    "AnchorTransitionResult",
    "Candidate",
    "EvaluatedProposal",
    "Evidence",
    "HashChainLedger",
    "LedgerVerification",
    "PromotionContext",
    "PromotionDecision",
    "PromotionGate",
    "ReplayResult",
    "VerificationResult",
    "VerifiedProposal",
    "advance_anchor",
    "evaluate_new",
    "initialize_anchor",
    "replay_historical",
    "verify_attested_proposal",
]

__version__ = "0.1.0a0"
