"""Deterministic proof gate for inheritable agent changes."""

from __future__ import annotations

from dataclasses import dataclass, field

from .constitution import Constitution
from .domain import Candidate, Evidence, PromotionDecision


@dataclass(frozen=True, slots=True)
class PromotionContext:
    """Facts supplied by trusted storage and governance, not by the candidate."""

    known_lineage_ids: frozenset[str]
    known_artifact_hashes: frozenset[str]
    authority_grants: dict[str, frozenset[str]] = field(default_factory=dict)


class PromotionGate:
    """Apply constitutional invariants to a candidate and its evidence."""

    def __init__(self, constitution: Constitution | None = None) -> None:
        self.constitution = constitution or Constitution.default()

    def decide(
        self,
        candidate: Candidate,
        evidence: list[Evidence],
        context: PromotionContext,
        *,
        authority_grant_id: str | None = None,
    ) -> PromotionDecision:
        reasons: list[str] = []
        constitution = self.constitution

        if candidate.artifact_hash not in context.known_artifact_hashes:
            reasons.append("candidate artifact is absent or not integrity-verified")

        if constitution.require_known_parent and candidate.parent_id not in context.known_lineage_ids:
            reasons.append("candidate parent is not present in the trusted lineage")

        if (
            constitution.require_rollback_target
            and candidate.rollback_target not in context.known_lineage_ids
        ):
            reasons.append("rollback target is not present in the trusted lineage")

        if candidate.estimated_cost_usd < 0:
            reasons.append("candidate cost cannot be negative")
        elif candidate.estimated_cost_usd > constitution.max_candidate_cost_usd:
            reasons.append(
                "candidate exceeds the constitutional experiment cost ceiling "
                f"({candidate.estimated_cost_usd:.2f} > "
                f"{constitution.max_candidate_cost_usd:.2f} USD)"
            )

        if constitution.forbid_implicit_authority_escalation and candidate.authority_delta:
            granted = (
                context.authority_grants.get(authority_grant_id, frozenset())
                if authority_grant_id
                else frozenset()
            )
            missing = candidate.authority_delta - granted
            if missing:
                reasons.append(
                    "candidate requests authority not covered by an explicit external grant: "
                    + ", ".join(sorted(missing))
                )

        relevant: list[Evidence] = []
        for item in evidence:
            if item.subject_id != candidate.candidate_id:
                continue
            relevant.append(item)
            if item.artifact_hash != candidate.artifact_hash:
                reasons.append(f"evidence {item.evidence_id} addresses a different artifact")
            if constitution.forbid_self_verification and item.verifier == candidate.proposer:
                reasons.append(f"evidence {item.evidence_id} is self-verification")
            if constitution.reject_any_failed_evidence and item.status != "pass":
                reasons.append(
                    f"evidence {item.evidence_id} reports {item.status} for {item.check}"
                )

        by_check: dict[str, list[Evidence]] = {}
        for item in relevant:
            by_check.setdefault(item.check, []).append(item)

        for check in constitution.mandatory_checks:
            passing = [
                item
                for item in by_check.get(check, [])
                if item.status == "pass"
                and item.independent
                and item.artifact_hash == candidate.artifact_hash
                and item.verifier != candidate.proposer
            ]
            if not passing:
                reasons.append(f"missing independent passing evidence for mandatory check: {check}")

        independent_verifiers = {
            item.verifier
            for item in relevant
            if item.independent
            and item.status == "pass"
            and item.artifact_hash == candidate.artifact_hash
            and item.verifier != candidate.proposer
        }
        if len(independent_verifiers) < constitution.minimum_independent_verifiers:
            reasons.append(
                "insufficient independent verifier diversity "
                f"({len(independent_verifiers)} < "
                f"{constitution.minimum_independent_verifiers})"
            )

        unique_reasons = tuple(dict.fromkeys(reasons))
        return PromotionDecision(
            candidate_id=candidate.candidate_id,
            status="rejected" if unique_reasons else "accepted",
            reasons=unique_reasons or ("all constitutional promotion gates passed",),
            evidence_ids=tuple(sorted(item.evidence_id for item in relevant)),
        )
