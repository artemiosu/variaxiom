from __future__ import annotations

import unittest

from variaxiom.constitution import Constitution
from variaxiom.domain import Candidate, Evidence
from variaxiom.promotion import PromotionContext, PromotionGate


class PromotionGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.artifact = "a" * 64
        self.parent = "genome:0"
        self.context = PromotionContext(
            known_lineage_ids=frozenset({self.parent}),
            known_artifact_hashes=frozenset({self.artifact}),
        )
        self.gate = PromotionGate(Constitution.default())

    def candidate(self, **overrides: object) -> Candidate:
        values: dict[str, object] = {
            "candidate_id": "candidate:1",
            "parent_id": self.parent,
            "artifact_hash": self.artifact,
            "proposer": "agent:builder",
            "rollback_target": self.parent,
            "baseline_capabilities": frozenset({"artifact.read"}),
            "requested_capabilities": frozenset({"artifact.read"}),
            "estimated_cost_usd": 0.10,
        }
        values.update(overrides)
        return Candidate(**values)  # type: ignore[arg-type]

    def evidence(self, candidate: Candidate) -> list[Evidence]:
        result: list[Evidence] = []
        for index, check in enumerate(("unit", "regression", "security", "budget")):
            result.append(
                Evidence(
                    evidence_id=f"e:{check}",
                    subject_id=candidate.candidate_id,
                    artifact_hash=candidate.artifact_hash,
                    check=check,
                    status="pass",
                    verifier="verifier:a" if index % 2 == 0 else "verifier:b",
                    independent=True,
                )
            )
        return result

    def test_accepts_bounded_candidate_with_independent_evidence(self) -> None:
        candidate = self.candidate()
        decision = self.gate.decide(candidate, self.evidence(candidate), self.context)
        self.assertTrue(decision.accepted)

    def test_rejects_authority_escalation_without_grant(self) -> None:
        candidate = self.candidate(
            requested_capabilities=frozenset({"artifact.read", "network.unrestricted"})
        )
        decision = self.gate.decide(candidate, self.evidence(candidate), self.context)
        self.assertFalse(decision.accepted)
        self.assertIn("authority", " ".join(decision.reasons))

    def test_accepts_explicitly_granted_authority(self) -> None:
        candidate = self.candidate(
            requested_capabilities=frozenset({"artifact.read", "network.example.com"})
        )
        context = PromotionContext(
            known_lineage_ids=self.context.known_lineage_ids,
            known_artifact_hashes=self.context.known_artifact_hashes,
            authority_grants={"grant:owner-1": frozenset({"network.example.com"})},
        )
        decision = self.gate.decide(
            candidate,
            self.evidence(candidate),
            context,
            authority_grant_id="grant:owner-1",
        )
        self.assertTrue(decision.accepted)

    def test_rejects_self_verification(self) -> None:
        candidate = self.candidate()
        evidence = self.evidence(candidate)
        evidence[0] = Evidence(
            evidence_id="e:unit:self",
            subject_id=candidate.candidate_id,
            artifact_hash=candidate.artifact_hash,
            check="unit",
            status="pass",
            verifier=candidate.proposer,
            independent=True,
        )
        decision = self.gate.decide(candidate, evidence, self.context)
        self.assertFalse(decision.accepted)
        self.assertIn("self-verification", " ".join(decision.reasons))

    def test_rejects_missing_rollback_target(self) -> None:
        candidate = self.candidate(rollback_target="missing")
        decision = self.gate.decide(candidate, self.evidence(candidate), self.context)
        self.assertFalse(decision.accepted)
        self.assertIn("rollback", " ".join(decision.reasons))


if __name__ == "__main__":
    unittest.main()
