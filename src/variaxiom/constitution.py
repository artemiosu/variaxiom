"""Machine-readable constitutional constraints."""

from __future__ import annotations

import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path

from .canonical import JSONValue, to_json_value


@dataclass(frozen=True, slots=True)
class Constitution:
    version: str
    mandatory_checks: tuple[str, ...]
    minimum_independent_verifiers: int
    max_candidate_cost_micro_usd: int
    require_known_parent: bool = True
    require_rollback_target: bool = True
    forbid_self_verification: bool = True
    forbid_implicit_authority_escalation: bool = True
    reject_any_failed_evidence: bool = True

    @classmethod
    def default(cls) -> Constitution:
        return cls(
            version="constitution/v1",
            mandatory_checks=("unit", "regression", "security", "budget"),
            minimum_independent_verifiers=2,
            max_candidate_cost_micro_usd=5_000_000,
        )

    @classmethod
    def from_toml(cls, path: Path) -> Constitution:
        data = tomllib.loads(path.read_text("utf-8"))
        promotion = data["promotion"]
        invariants = data["invariants"]
        return cls(
            version=str(data["constitution"]["version"]),
            mandatory_checks=tuple(str(item) for item in promotion["mandatory_checks"]),
            minimum_independent_verifiers=int(promotion["minimum_independent_verifiers"]),
            max_candidate_cost_micro_usd=int(promotion["max_candidate_cost_micro_usd"]),
            require_known_parent=bool(invariants["require_known_parent"]),
            require_rollback_target=bool(invariants["require_rollback_target"]),
            forbid_self_verification=bool(invariants["forbid_self_verification"]),
            forbid_implicit_authority_escalation=bool(
                invariants["forbid_implicit_authority_escalation"]
            ),
            reject_any_failed_evidence=bool(invariants["reject_any_failed_evidence"]),
        )

    def as_dict(self) -> dict[str, JSONValue]:
        raw = asdict(self)
        # Mandatory checks are a protocol set. Normalize their order just as the
        # Rust BTreeSet does so constructors and TOML source order cannot affect
        # a promotion-input digest.
        raw["mandatory_checks"] = sorted(self.mandatory_checks)
        return to_json_value(raw)  # type: ignore[return-value]
