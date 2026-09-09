"""Variaxiom reference laboratory.

The Python package is an executable specification of proof-gated agent
adaptation. It is intentionally small and dependency-light. Production-grade
untrusted-code isolation belongs outside the Python process.
"""

from .domain import Candidate, Evidence, PromotionDecision
from .ledger import HashChainLedger, LedgerVerification
from .m2_verifier import (
    CanonicalM2Wire,
    ContextBoundM2Input,
    DigestBoundM2Input,
    IdentityBoundM2Input,
    M2WireRejection,
    SignatureVerifiedM2Input,
    StructurallyValidM2Input,
    inspect_m2_stage_five,
    inspect_m2_stage_four,
    inspect_m2_stage_six,
    inspect_m2_stage_three,
    inspect_m2_stage_two,
    inspect_m2_wire,
)
from .promotion import PromotionContext, PromotionGate

__all__ = [
    "Candidate",
    "CanonicalM2Wire",
    "ContextBoundM2Input",
    "DigestBoundM2Input",
    "Evidence",
    "HashChainLedger",
    "IdentityBoundM2Input",
    "LedgerVerification",
    "M2WireRejection",
    "PromotionContext",
    "PromotionDecision",
    "PromotionGate",
    "SignatureVerifiedM2Input",
    "StructurallyValidM2Input",
    "inspect_m2_stage_five",
    "inspect_m2_stage_four",
    "inspect_m2_stage_six",
    "inspect_m2_stage_three",
    "inspect_m2_stage_two",
    "inspect_m2_wire",
]

__version__ = "0.1.0a0"
