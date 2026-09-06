from __future__ import annotations

import unittest
from copy import deepcopy
from dataclasses import replace
from pathlib import Path

from variaxiom.canonical import (
    MAX_CANONICAL_DEPTH,
    MAX_SAFE_INTEGER,
    canonical_json,
    content_hash,
    strict_json_loads,
)
from variaxiom.constitution import Constitution
from variaxiom.domain import Evidence
from variaxiom.promotion import PromotionGate
from variaxiom.protocol import (
    ConformanceCase,
    ProtocolError,
    decision_envelope_from_dict,
    decision_envelope_json,
    decision_from_dict,
    promotion_input_envelope,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "conformance" / "v1" / "promotion"


class CrossLanguageConformanceTests(unittest.TestCase):
    def raw_cases(self) -> list[dict[str, object]]:
        return [strict_json_loads(path.read_bytes()) for path in sorted(FIXTURES.glob("*.json"))]

    def test_shared_promotion_vectors_match_exactly(self) -> None:
        raw_cases = self.raw_cases()
        self.assertTrue(raw_cases)
        for raw in raw_cases:
            with self.subTest(case=raw["case_id"]):
                case = ConformanceCase.from_dict(raw)
                decision = PromotionGate(case.constitution).decide(
                    case.candidate,
                    list(case.evidence),
                    case.context,
                    authority_grant_id=case.authority_grant_id,
                )
                expected = case.expected
                input_envelope = promotion_input_envelope(
                    case.candidate,
                    case.evidence,
                    case.context,
                    case.constitution,
                    case.authority_grant_id,
                )
                self.assertEqual(decision.as_dict(), expected["decision"])
                self.assertEqual(
                    canonical_json(input_envelope).decode("utf-8"),
                    expected["input_envelope_json"],
                )
                self.assertEqual(decision.input_digest, expected["input_digest"])
                self.assertEqual(
                    decision_envelope_json(decision), expected["decision_envelope_json"]
                )
                parsed_decision = decision_envelope_from_dict(
                    strict_json_loads(expected["decision_envelope_json"])
                )
                self.assertEqual(parsed_decision, decision)
                self.assertEqual(content_hash(decision.envelope()), expected["decision_digest"])

    def test_bound_input_mutation_changes_digest(self) -> None:
        raw = self.raw_cases()[0]
        case = ConformanceCase.from_dict(raw)
        original = PromotionGate(case.constitution).decide(
            case.candidate, list(case.evidence), case.context
        )
        changed_candidate = replace(
            case.candidate,
            metadata={**case.candidate.metadata, "reproducible": False},
        )
        mutated = PromotionGate(case.constitution).decide(
            changed_candidate, list(case.evidence), case.context
        )
        self.assertNotEqual(original.input_digest, mutated.input_digest)

    def test_canonical_profile_rejects_float_and_large_integer(self) -> None:
        with self.assertRaises(TypeError):
            canonical_json({"value": 1.5})
        with self.assertRaises(ValueError):
            canonical_json({"value": MAX_SAFE_INTEGER + 1})
        with self.assertRaises(TypeError):
            canonical_json({"value": {1, "1"}})
        with self.assertRaises(ValueError):
            strict_json_loads('{"value":1,"value":2}')
        with self.assertRaises(ValueError):
            strict_json_loads(b'\xef\xbb\xbf{"value":1}')
        with self.assertRaises(ValueError):
            strict_json_loads(b'\xff\xfe{\x00"\x00v\x00"\x00:\x001\x00}\x00')
        with self.assertRaises(ValueError):
            strict_json_loads('{"value":"\\ud800"}')
        with self.assertRaises(ValueError):
            strict_json_loads('{"\\ud800":1}')

        nested: object = 0
        for _ in range(MAX_CANONICAL_DEPTH):
            nested = {"value": nested}
        canonical_json(nested)
        with self.assertRaises(ValueError):
            canonical_json({"value": nested})

    def test_unknown_fields_and_duplicate_evidence_ids_fail_closed(self) -> None:
        raw = self.raw_cases()[0]
        unknown = deepcopy(raw)
        unknown["candidate"]["surprise"] = True  # type: ignore[index]
        with self.assertRaises(ProtocolError):
            ConformanceCase.from_dict(unknown)

        duplicate = deepcopy(raw)
        duplicate["evidence"][1]["evidence_id"] = duplicate["evidence"][0][  # type: ignore[index]
            "evidence_id"
        ]
        with self.assertRaises(ProtocolError):
            ConformanceCase.from_dict(duplicate)

        malformed = deepcopy(raw)
        malformed["candidate"]["artifact_hash"] = "not-a-digest"  # type: ignore[index]
        with self.assertRaises(ProtocolError):
            ConformanceCase.from_dict(malformed)

    def test_duplicate_members_in_protocol_sets_fail_closed(self) -> None:
        raw = self.raw_cases()[0]
        duplicate_capability = deepcopy(raw)
        duplicate_capability["candidate"]["baseline_capabilities"] = [  # type: ignore[index]
            "artifact.read",
            "artifact.read",
        ]
        duplicate_lineage = deepcopy(raw)
        duplicate_lineage["context"]["known_lineage_ids"] = [  # type: ignore[index]
            "genome:0",
            "genome:0",
        ]
        duplicate_check = deepcopy(raw)
        duplicate_check["constitution"]["mandatory_checks"] = ["unit", "unit"]  # type: ignore[index]
        duplicate_grant_capability = deepcopy(raw)
        duplicate_grant_capability["context"]["authority_grants"] = {  # type: ignore[index]
            "grant:test": ["artifact.write", "artifact.write"]
        }
        unsorted_capabilities = deepcopy(raw)
        unsorted_capabilities["candidate"]["requested_capabilities"] = [  # type: ignore[index]
            "network.unrestricted",
            "artifact.read",
        ]
        incomplete_lineage_authority = deepcopy(raw)
        incomplete_lineage_authority["context"]["lineage_capabilities"] = {}  # type: ignore[index]
        for malformed in (
            duplicate_capability,
            duplicate_lineage,
            duplicate_check,
            duplicate_grant_capability,
            unsorted_capabilities,
            incomplete_lineage_authority,
        ):
            with self.assertRaises(ProtocolError):
                ConformanceCase.from_dict(malformed)

    def test_in_process_gate_uses_wire_validation(self) -> None:
        case = ConformanceCase.from_dict(self.raw_cases()[0])
        malformed_evidence = list(case.evidence)
        malformed_evidence[0] = Evidence(
            evidence_id=malformed_evidence[0].evidence_id,
            subject_id=malformed_evidence[0].subject_id,
            artifact_hash=malformed_evidence[0].artifact_hash,
            check=malformed_evidence[0].check,
            status="unknown",  # type: ignore[arg-type]
            verifier=malformed_evidence[0].verifier,
            independent=True,
        )
        with self.assertRaises(ProtocolError):
            PromotionGate(case.constitution).decide(
                case.candidate, malformed_evidence, case.context
            )

        invalid_constitution = Constitution(
            version="constitution/v1",
            mandatory_checks=("unit",),
            minimum_independent_verifiers=0,
            max_candidate_cost_micro_usd=5_000_000,
        )
        with self.assertRaises(ProtocolError):
            PromotionGate(invalid_constitution).decide(
                case.candidate, list(case.evidence), case.context
            )

        empty_checks = Constitution(
            version="constitution/v1",
            mandatory_checks=(),
            minimum_independent_verifiers=1,
            max_candidate_cost_micro_usd=5_000_000,
        )
        with self.assertRaises(ProtocolError):
            PromotionGate(empty_checks).decide(case.candidate, list(case.evidence), case.context)

        malformed_context = type(case.context)(
            known_lineage_ids=case.context.known_lineage_ids,
            known_artifact_hashes=case.context.known_artifact_hashes | {"not-a-digest"},
            authority_grants=case.context.authority_grants,
            lineage_capabilities=case.context.lineage_capabilities,
        )
        with self.assertRaises(ProtocolError):
            PromotionGate(case.constitution).decide(
                case.candidate, list(case.evidence), malformed_context
            )

        with self.assertRaises(ProtocolError):
            PromotionGate(case.constitution).decide(
                replace(case.candidate, estimated_cost_micro_usd=-1),
                list(case.evidence),
                case.context,
            )

        with self.assertRaises(ProtocolError):
            PromotionGate(replace(case.constitution, forbid_self_verification=False)).decide(
                case.candidate, list(case.evidence), case.context
            )

        with self.assertRaises(ProtocolError):
            PromotionGate(case.constitution).decide(
                case.candidate,
                list(case.evidence),
                case.context,
                authority_grant_id="grant:missing",
            )

        with self.assertRaises(TypeError):
            PromotionGate(case.constitution).decide(
                replace(case.candidate, metadata={"ambiguous": {1, "1"}}),  # type: ignore[dict-item]
                list(case.evidence),
                case.context,
            )

    def test_default_and_toml_constitutions_have_one_canonical_form(self) -> None:
        root = FIXTURES.parents[3]
        from_toml = Constitution.from_toml(root / "constitution" / "constitution.toml")
        self.assertEqual(Constitution.default().as_dict(), from_toml.as_dict())

    def test_invalid_decision_envelopes_fail_closed(self) -> None:
        raw = next(item for item in self.raw_cases() if item["case_id"] == "bounded-accepted")
        envelope = strict_json_loads(raw["expected"]["decision_envelope_json"])  # type: ignore[index]
        envelope["payload"]["reasons"] = ["artifact.not_verified"]
        with self.assertRaises(ProtocolError):
            decision_envelope_from_dict(envelope)

        wrong_version = strict_json_loads(
            raw["expected"]["decision_envelope_json"]  # type: ignore[index]
        )
        wrong_version["envelope_version"] = "variaxiom-envelope/v2"
        with self.assertRaises(ProtocolError):
            decision_envelope_from_dict(wrong_version)

    def test_invalid_decision_cannot_receive_a_durable_identity(self) -> None:
        case = ConformanceCase.from_dict(self.raw_cases()[0])
        invalid = replace(
            decision_from_dict(case.expected["decision"]),
            status="accepted",
            reasons=("artifact.not_verified",),
        )
        with self.assertRaises(ProtocolError):
            _ = invalid.fingerprint
        with self.assertRaises(ProtocolError):
            decision_envelope_json(invalid)


if __name__ == "__main__":
    unittest.main()
