"""Deterministic proof gate for inheritable agent changes."""

from __future__ import annotations

from dataclasses import dataclass, field

from .canonical import JSONValue, to_json_value
from .constitution import Constitution
from .domain import Candidate, Evidence, PromotionDecision


def _empty_authority_grants() -> dict[str, frozenset[str]]:
    return {}


@dataclass(frozen=True, slots=True)
class PromotionContext:
    """Facts supplied by trusted storage and governance, not by the candidate."""

    known_lineage_ids: frozenset[str]
    known_artifact_hashes: frozenset[str]
    authority_grants: dict[str, frozenset[str]] = field(default_factory=_empty_authority_grants)
    lineage_capabilities: dict[str, frozenset[str]] = field(default_factory=_empty_authority_grants)

    def as_dict(self) -> dict[str, JSONValue]:
        return to_json_value(
            {
                "authority_grants": {
                    grant_id: sorted(capabilities)
                    for grant_id, capabilities in self.authority_grants.items()
                },
                "lineage_capabilities": {
                    lineage_id: sorted(capabilities)
                    for lineage_id, capabilities in self.lineage_capabilities.items()
                },
                "known_artifact_hashes": sorted(self.known_artifact_hashes),
                "known_lineage_ids": sorted(self.known_lineage_ids),
            }
        )  # type: ignore[return-value]


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

        # Local imports avoid a module cycle. Take one validated, owned snapshot and
        # use it for both hashing and policy so mutable caller-owned lists/dicts
        # cannot change the facts between commitment and evaluation.
        from .protocol import (
            candidate_from_dict,
            constitution_from_dict,
            context_from_dict,
            evidence_from_dict,
            promotion_input_digest,
        )

        candidate = candidate_from_dict(candidate.as_dict())
        evidence = [evidence_from_dict(item.as_dict()) for item in evidence]
        context = context_from_dict(context.as_dict())
        constitution = constitution_from_dict(self.constitution.as_dict())

        input_digest = promotion_input_digest(
            candidate, evidence, context, constitution, authority_grant_id
        )

        if candidate.artifact_hash not in context.known_artifact_hashes:
            reasons.append("artifact.not_verified")

        if (
            constitution.require_known_parent
            and candidate.parent_id not in context.known_lineage_ids
        ):
            reasons.append("lineage.parent_unknown")

        if (
            constitution.require_rollback_target
            and candidate.rollback_target not in context.known_lineage_ids
        ):
            reasons.append("rollback.target_unknown")

        if candidate.estimated_cost_micro_usd > constitution.max_candidate_cost_micro_usd:
            reasons.append("candidate.cost_limit_exceeded")

        if constitution.forbid_implicit_authority_escalation:
            trusted_baseline = context.lineage_capabilities.get(candidate.parent_id)
            if trusted_baseline is None:
                reasons.append("authority.baseline_unknown")
                trusted_baseline = frozenset[str]()
            elif candidate.baseline_capabilities != trusted_baseline:
                reasons.append("authority.baseline_mismatch")
            authority_delta = candidate.requested_capabilities - trusted_baseline
            if authority_delta:
                granted = (
                    context.authority_grants.get(authority_grant_id, frozenset())
                    if authority_grant_id
                    else frozenset[str]()
                )
                missing = authority_delta - granted
                if missing:
                    reasons.append("authority.not_granted:" + ",".join(sorted(missing)))

        relevant: list[Evidence] = []
        for item in evidence:
            if item.subject_id != candidate.candidate_id:
                continue
            relevant.append(item)
            if item.artifact_hash != candidate.artifact_hash:
                reasons.append(f"evidence.artifact_mismatch:{item.evidence_id}")
            if constitution.forbid_self_verification and item.verifier == candidate.proposer:
                reasons.append(f"evidence.self_verification:{item.evidence_id}")
            if constitution.reject_any_failed_evidence and item.status != "pass":
                reasons.append(f"evidence.failed:{item.evidence_id}:{item.status}")

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
                reasons.append(f"evidence.missing_check:{check}")

        independent_verifiers = {
            item.verifier
            for item in relevant
            if item.independent
            and item.status == "pass"
            and item.artifact_hash == candidate.artifact_hash
            and item.verifier != candidate.proposer
        }
        if len(independent_verifiers) < constitution.minimum_independent_verifiers:
            reasons.append("evidence.verifier_diversity")

        unique_reasons = tuple(sorted(set(reasons)))
        return PromotionDecision(
            candidate_id=candidate.candidate_id,
            status="rejected" if unique_reasons else "accepted",
            reasons=unique_reasons or ("promotion.accepted",),
            evidence_ids=tuple(sorted(item.evidence_id for item in relevant)),
            input_digest=input_digest,
            constitution_version=constitution.version,
        )
