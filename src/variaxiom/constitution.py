"""Machine-readable constitutional constraints."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class Constitution:
    version: str
    mandatory_checks: tuple[str, ...]
    minimum_independent_verifiers: int
    max_candidate_cost_usd: float
    require_known_parent: bool = True
    require_rollback_target: bool = True
    forbid_self_verification: bool = True
    forbid_implicit_authority_escalation: bool = True
    reject_any_failed_evidence: bool = True

    @classmethod
    def default(cls) -> "Constitution":
        return cls(
            version="constitution/v1",
            mandatory_checks=("unit", "regression", "security", "budget"),
            minimum_independent_verifiers=2,
            max_candidate_cost_usd=5.0,
        )

    @classmethod
    def from_toml(cls, path: Path) -> "Constitution":
        data = tomllib.loads(path.read_text("utf-8"))
        promotion = data["promotion"]
        invariants = data["invariants"]
        return cls(
            version=str(data["constitution"]["version"]),
            mandatory_checks=tuple(str(item) for item in promotion["mandatory_checks"]),
            minimum_independent_verifiers=int(
                promotion["minimum_independent_verifiers"]
            ),
            max_candidate_cost_usd=float(promotion["max_candidate_cost_usd"]),
            require_known_parent=bool(invariants["require_known_parent"]),
            require_rollback_target=bool(invariants["require_rollback_target"]),
            forbid_self_verification=bool(invariants["forbid_self_verification"]),
            forbid_implicit_authority_escalation=bool(
                invariants["forbid_implicit_authority_escalation"]
            ),
            reject_any_failed_evidence=bool(invariants["reject_any_failed_evidence"]),
        )
