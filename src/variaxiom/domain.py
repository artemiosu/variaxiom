"""Core immutable domain objects for candidates, evidence, and promotion."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Literal

from .canonical import JSONValue, content_hash, to_json_value

EvidenceStatus = Literal["pass", "fail", "error"]
DecisionStatus = Literal["accepted", "rejected"]


def _empty_capabilities() -> frozenset[str]:
    return frozenset()


def _empty_json_object() -> dict[str, JSONValue]:
    return {}


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
    baseline_capabilities: frozenset[str] = field(default_factory=_empty_capabilities)
    requested_capabilities: frozenset[str] = field(default_factory=_empty_capabilities)
    estimated_cost_micro_usd: int = 0
    metadata: dict[str, JSONValue] = field(default_factory=_empty_json_object)

    def as_dict(self) -> dict[str, JSONValue]:
        return to_json_value(
            {
                "candidate_id": self.candidate_id,
                "parent_id": self.parent_id,
                "artifact_hash": self.artifact_hash,
                "proposer": self.proposer,
                "rollback_target": self.rollback_target,
                "baseline_capabilities": sorted(self.baseline_capabilities),
                "requested_capabilities": sorted(self.requested_capabilities),
                "estimated_cost_micro_usd": self.estimated_cost_micro_usd,
                "metadata": self.metadata,
            }
        )  # type: ignore[return-value]

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
    details: dict[str, JSONValue] = field(default_factory=_empty_json_object)

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
    input_digest: str
    constitution_version: str = "constitution/v1"
    gate_version: str = "proof-gate/v1"

    @property
    def accepted(self) -> bool:
        return self.status == "accepted"

    def as_dict(self) -> dict[str, JSONValue]:
        return to_json_value(asdict(self))  # type: ignore[return-value]

    @property
    def fingerprint(self) -> str:
        # Local import avoids a module cycle while ensuring invalid decisions
        # cannot acquire a durable identity.
        from .protocol import decision_from_dict

        validated = decision_from_dict(self.as_dict())
        return content_hash(validated.envelope())

    def envelope(self) -> dict[str, JSONValue]:
        return {
            "envelope_version": "variaxiom-envelope/v1",
            "kind": "promotion-decision",
            "payload": self.as_dict(),
        }

    @property
    def envelope_fingerprint(self) -> str:
        return self.fingerprint
