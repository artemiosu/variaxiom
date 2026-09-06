"""Core immutable domain objects for candidates, evidence, and promotion."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

from .canonical import JSONValue, content_hash, to_json_value

EvidenceStatus = Literal["pass", "fail", "error"]
DecisionStatus = Literal["accepted", "rejected"]


@dataclass(frozen=True, slots=True)
class Candidate:
    """A proposed inheritable change.

    A candidate is not a skill or tool merely because a model wrote it. It is a
    content-addressed proposal plus lineage, budget, rollback, and authority
    metadata. Only an accepted promotion decision can make it inheritable.
    """

    candidate_id: str
    parent_id: str
    artifact_hash: str
    proposer: str
    rollback_target: str
    baseline_capabilities: frozenset[str] = field(default_factory=frozenset)
    requested_capabilities: frozenset[str] = field(default_factory=frozenset)
    estimated_cost_usd: float = 0.0
    metadata: dict[str, JSONValue] = field(default_factory=dict)

    @property
    def authority_delta(self) -> frozenset[str]:
        return self.requested_capabilities - self.baseline_capabilities

    def as_dict(self) -> dict[str, JSONValue]:
        raw = asdict(self)
        return to_json_value(raw)  # type: ignore[return-value]

    @property
    def fingerprint(self) -> str:
        return content_hash(self.as_dict())


@dataclass(frozen=True, slots=True)
class Evidence:
    """A verifier's observation about one candidate artifact."""

    evidence_id: str
    subject_id: str
    artifact_hash: str
    check: str
    status: EvidenceStatus
    verifier: str
    independent: bool
    details: dict[str, JSONValue] = field(default_factory=dict)

    def as_dict(self) -> dict[str, JSONValue]:
        return to_json_value(asdict(self))  # type: ignore[return-value]

    @property
    def fingerprint(self) -> str:
        return content_hash(self.as_dict())


@dataclass(frozen=True, slots=True)
class PromotionDecision:
    """Deterministic result of applying the constitution to evidence."""

    candidate_id: str
    status: DecisionStatus
    reasons: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    gate_version: str = "proof-gate/v1"

    @property
    def accepted(self) -> bool:
        return self.status == "accepted"

    def as_dict(self) -> dict[str, JSONValue]:
        return to_json_value(asdict(self))  # type: ignore[return-value]

    @property
    def fingerprint(self) -> str:
        return content_hash(self.as_dict())
