"""Variaxiom reference laboratory.

The Python package is an executable specification of proof-gated agent
adaptation. It is intentionally small and dependency-light. Production-grade
untrusted-code isolation belongs outside the Python process.
"""

from .domain import Candidate, Evidence, PromotionDecision
from .ledger import HashChainLedger, LedgerVerification
from .promotion import PromotionContext, PromotionGate

__all__ = [
    "Candidate",
    "Evidence",
    "HashChainLedger",
    "LedgerVerification",
    "PromotionContext",
    "PromotionDecision",
    "PromotionGate",
]

__version__ = "0.1.0a0"
