from __future__ import annotations

import base64
import unittest
from pathlib import Path
from typing import Any, cast

from variaxiom.canonical import canonical_json, strict_json_loads
from variaxiom.m2_verifier import (
    CanonicalM2Wire,
    ContextBoundM2Input,
    DigestBoundM2Input,
    EvidenceBoundM2Input,
    GrantBoundM2Input,
    IdentityBoundM2Input,
    M2WireRejection,
    PolicyContextBoundM2Input,
    PolicyEvaluatedM2Input,
    SignatureVerifiedM2Input,
    StructurallyValidM2Input,
    inspect_m2_stage_eight,
    inspect_m2_stage_five,
    inspect_m2_stage_four,
    inspect_m2_stage_nine,
    inspect_m2_stage_seven,
    inspect_m2_stage_six,
    inspect_m2_stage_ten,
    inspect_m2_stage_three,
    inspect_m2_stage_two,
    inspect_m2_wire,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures" / "conformance" / "v2"


def decode_input(case: dict[str, Any]) -> bytes:
    encoded = cast(str, case["input_base64url"])
    return base64.urlsafe_b64decode(encoded + "=" * ((4 - len(encoded) % 4) % 4))


class M2WireInspectionTests(unittest.TestCase):
    def cases(self) -> list[dict[str, Any]]:
        manifest = cast(
            dict[str, Any], strict_json_loads((FIXTURES / "manifest.json").read_bytes())
        )
        return [
            cast(
                dict[str, Any],
                strict_json_loads((FIXTURES / cast(str, entry["fixture"])).read_bytes()),
            )
            for entry in cast(list[dict[str, Any]], manifest["cases"])
        ]

    def test_all_frozen_stage_one_rejections_match(self) -> None:
        cases = [case for case in self.cases() if case["stage"] == 1]
        self.assertEqual(len(cases), 8)
        for case in cases:
            with self.subTest(case=case["case_id"]):
                result = inspect_m2_wire(decode_input(case))
                self.assertIsInstance(result, M2WireRejection)
                rejection = cast(M2WireRejection, result)
                expected = cast(dict[str, Any], case["expected"])
                self.assertEqual(rejection.stage, expected["reached_stage"])
                self.assertEqual(rejection.code, expected["code"])
                self.assertFalse(rejection.authorizing)

    def test_canonical_fixture_is_immutable_and_round_trips(self) -> None:
        raw = canonical_json(
            strict_json_loads((FIXTURES / "base-attested-proposal.json").read_bytes())
        )
        result = inspect_m2_wire(raw)
        self.assertIsInstance(result, CanonicalM2Wire)
        wire = cast(CanonicalM2Wire, result)
        first = cast(dict[str, Any], wire.decode())
        first["kind"] = "mutated"
        second = cast(dict[str, Any], wire.decode())
        self.assertEqual(second["kind"], "attested-proposal")
        self.assertNotEqual(first, second)

    def test_exact_wire_limit_fixture_is_accepted_by_stage_one(self) -> None:
        case = next(case for case in self.cases() if case["case_id"] == "wire-size-exact-limit")
        raw = decode_input(case)
        self.assertEqual(len(raw), 1_048_576)
        result = inspect_m2_wire(memoryview(raw))
        self.assertIsInstance(result, CanonicalM2Wire)
        wire = cast(CanonicalM2Wire, result)
        self.assertEqual(wire.sha256, case["input_sha256"])

    def test_all_frozen_stage_two_rejections_match(self) -> None:
        cases = [case for case in self.cases() if case["expected"]["reached_stage"] == 2]
        self.assertEqual(len(cases), 78)
        for case in cases:
            with self.subTest(case=case["case_id"]):
                result = inspect_m2_stage_two(
                    decode_input(case),
                    case["entrypoint"],
                    trusted_anchor=cast(Any, case.get("trusted_anchor")),
                )
                self.assertIsInstance(result, M2WireRejection)
                rejection = cast(M2WireRejection, result)
                expected = cast(dict[str, Any], case["expected"])
                self.assertEqual(rejection.stage, expected["reached_stage"])
                self.assertEqual(rejection.code, expected["code"])
                self.assertFalse(rejection.authorizing)

    def test_every_later_stage_case_passes_the_structural_boundary(self) -> None:
        cases = [case for case in self.cases() if case["expected"]["reached_stage"] > 2]
        self.assertEqual(len(cases), 151)
        for case in cases:
            with self.subTest(case=case["case_id"]):
                result = inspect_m2_stage_two(
                    decode_input(case),
                    case["entrypoint"],
                    trusted_anchor=cast(Any, case.get("trusted_anchor")),
                )
                self.assertIsInstance(result, StructurallyValidM2Input)
                accepted = cast(StructurallyValidM2Input, result)
                self.assertFalse(accepted.authorizing)
                self.assertEqual(accepted.entrypoint, case["entrypoint"])

    def test_external_anchor_is_snapshotted(self) -> None:
        case = next(case for case in self.cases() if case["case_id"] == "bounded-signed-proposal")
        anchor = cast(dict[str, Any], case["trusted_anchor"])
        result = inspect_m2_stage_two(
            decode_input(case), "verify-attested-proposal", trusted_anchor=anchor
        )
        self.assertIsInstance(result, StructurallyValidM2Input)
        accepted = cast(StructurallyValidM2Input, result)
        anchor["trust_domain_id"] = "trust-domain:mutated"
        snapshot = cast(dict[str, Any], accepted.decode_trusted_anchor())
        self.assertEqual(snapshot["trust_domain_id"], "trust-domain:example")

    def test_malformed_nested_shape_fails_closed_without_an_exception(self) -> None:
        case = next(case for case in self.cases() if case["case_id"] == "bounded-signed-proposal")
        value = cast(dict[str, Any], strict_json_loads(decode_input(case)))
        value["payload"]["promotion_input"]["payload"]["candidate"]["envelope"]["payload"] = []
        result = inspect_m2_stage_two(
            canonical_json(value),
            "verify-attested-proposal",
            trusted_anchor=case["trusted_anchor"],
        )
        self.assertEqual(result, M2WireRejection(stage=2, code="input.schema_invalid"))

    def test_all_frozen_stage_three_rejections_match(self) -> None:
        cases = [case for case in self.cases() if case["expected"]["reached_stage"] == 3]
        self.assertEqual(len(cases), 23)
        for case in cases:
            with self.subTest(case=case["case_id"]):
                result = inspect_m2_stage_three(
                    decode_input(case),
                    case["entrypoint"],
                    trusted_anchor=cast(Any, case.get("trusted_anchor")),
                )
                self.assertIsInstance(result, M2WireRejection)
                rejection = cast(M2WireRejection, result)
                expected = cast(dict[str, Any], case["expected"])
                self.assertEqual(rejection.stage, expected["reached_stage"])
                self.assertEqual(rejection.code, expected["code"])
                self.assertFalse(rejection.authorizing)

    def test_every_later_stage_case_passes_the_context_boundary(self) -> None:
        cases = [case for case in self.cases() if case["expected"]["reached_stage"] > 3]
        self.assertEqual(len(cases), 128)
        for case in cases:
            with self.subTest(case=case["case_id"]):
                result = inspect_m2_stage_three(
                    decode_input(case),
                    case["entrypoint"],
                    trusted_anchor=cast(Any, case.get("trusted_anchor")),
                )
                self.assertIsInstance(result, ContextBoundM2Input)
                accepted = cast(ContextBoundM2Input, result)
                self.assertFalse(accepted.authorizing)
                self.assertEqual(accepted.entrypoint, case["entrypoint"])

    def test_all_frozen_stage_four_rejections_match(self) -> None:
        cases = [case for case in self.cases() if case["expected"]["reached_stage"] == 4]
        self.assertEqual(len(cases), 11)
        for case in cases:
            with self.subTest(case=case["case_id"]):
                result = inspect_m2_stage_four(
                    decode_input(case),
                    case["entrypoint"],
                    trusted_anchor=cast(Any, case.get("trusted_anchor")),
                )
                self.assertIsInstance(result, M2WireRejection)
                rejection = cast(M2WireRejection, result)
                self.assertEqual(rejection.stage, 4)
                self.assertEqual(rejection.code, case["expected"]["code"])
                self.assertFalse(rejection.authorizing)

    def test_every_later_stage_case_passes_the_digest_boundary(self) -> None:
        cases = [case for case in self.cases() if case["expected"]["reached_stage"] > 4]
        self.assertEqual(len(cases), 117)
        for case in cases:
            with self.subTest(case=case["case_id"]):
                result = inspect_m2_stage_four(
                    decode_input(case),
                    case["entrypoint"],
                    trusted_anchor=cast(Any, case.get("trusted_anchor")),
                )
                self.assertIsInstance(result, DigestBoundM2Input)
                self.assertFalse(cast(DigestBoundM2Input, result).authorizing)

    def test_all_frozen_stage_five_rejections_match(self) -> None:
        cases = [case for case in self.cases() if case["expected"]["reached_stage"] == 5]
        self.assertEqual(len(cases), 23)
        for case in cases:
            with self.subTest(case=case["case_id"]):
                result = inspect_m2_stage_five(
                    decode_input(case),
                    case["entrypoint"],
                    trusted_anchor=cast(Any, case.get("trusted_anchor")),
                )
                self.assertIsInstance(result, M2WireRejection)
                rejection = cast(M2WireRejection, result)
                self.assertEqual(rejection.stage, 5)
                self.assertEqual(rejection.code, case["expected"]["code"])
                self.assertFalse(rejection.authorizing)

    def test_every_later_stage_case_passes_the_identity_boundary(self) -> None:
        cases = [case for case in self.cases() if case["expected"]["reached_stage"] > 5]
        self.assertEqual(len(cases), 94)
        for case in cases:
            with self.subTest(case=case["case_id"]):
                result = inspect_m2_stage_five(
                    decode_input(case),
                    case["entrypoint"],
                    trusted_anchor=cast(Any, case.get("trusted_anchor")),
                )
                self.assertIsInstance(result, IdentityBoundM2Input)
                self.assertFalse(cast(IdentityBoundM2Input, result).authorizing)

    def test_all_frozen_stage_six_rejections_match(self) -> None:
        cases = [
            case
            for case in self.cases()
            if case["expected"]["reached_stage"] == 6 and case["expected"]["code"] is not None
        ]
        self.assertEqual(len(cases), 25)
        for case in cases:
            with self.subTest(case=case["case_id"]):
                result = inspect_m2_stage_six(
                    decode_input(case),
                    case["entrypoint"],
                    trusted_anchor=cast(Any, case.get("trusted_anchor")),
                )
                self.assertIsInstance(result, M2WireRejection)
                rejection = cast(M2WireRejection, result)
                self.assertEqual(rejection.stage, 6)
                self.assertEqual(rejection.code, case["expected"]["code"])
                self.assertFalse(rejection.authorizing)

    def test_successful_anchor_operations_return_the_exact_frozen_anchor(self) -> None:
        cases = [
            case
            for case in self.cases()
            if case["expected"]["reached_stage"] == 6 and case["expected"]["code"] is None
        ]
        self.assertEqual(len(cases), 7)
        for case in cases:
            with self.subTest(case=case["case_id"]):
                result = inspect_m2_stage_six(
                    decode_input(case),
                    case["entrypoint"],
                    trusted_anchor=cast(Any, case.get("trusted_anchor")),
                )
                self.assertIsInstance(result, SignatureVerifiedM2Input)
                accepted = cast(SignatureVerifiedM2Input, result)
                self.assertFalse(accepted.authorizing)
                self.assertEqual(
                    accepted.decode_resulting_anchor(), case["expected"]["expected_anchor"]
                )

    def test_every_later_stage_case_passes_the_signature_boundary(self) -> None:
        cases = [case for case in self.cases() if case["expected"]["reached_stage"] > 6]
        self.assertEqual(len(cases), 62)
        for case in cases:
            with self.subTest(case=case["case_id"]):
                result = inspect_m2_stage_six(
                    decode_input(case),
                    case["entrypoint"],
                    trusted_anchor=cast(Any, case.get("trusted_anchor")),
                )
                self.assertIsInstance(result, SignatureVerifiedM2Input)
                self.assertFalse(cast(SignatureVerifiedM2Input, result).authorizing)

    def test_frozen_stage_seven_rejection_matches(self) -> None:
        cases = [case for case in self.cases() if case["expected"]["reached_stage"] == 7]
        self.assertEqual(len(cases), 1)
        for case in cases:
            result = inspect_m2_stage_seven(
                decode_input(case),
                case["entrypoint"],
                trusted_anchor=cast(Any, case.get("trusted_anchor")),
            )
            self.assertEqual(
                result,
                M2WireRejection(stage=7, code=case["expected"]["code"]),
                case["case_id"],
            )

    def test_every_later_case_passes_the_evidence_boundary(self) -> None:
        cases = [case for case in self.cases() if case["expected"]["reached_stage"] > 7]
        self.assertEqual(len(cases), 61)
        for case in cases:
            with self.subTest(case=case["case_id"]):
                result = inspect_m2_stage_seven(
                    decode_input(case),
                    case["entrypoint"],
                    trusted_anchor=cast(Any, case.get("trusted_anchor")),
                )
                self.assertIsInstance(result, EvidenceBoundM2Input)
                self.assertFalse(cast(EvidenceBoundM2Input, result).authorizing)

    def test_frozen_stage_eight_rejections_match(self) -> None:
        cases = [case for case in self.cases() if case["expected"]["reached_stage"] == 8]
        self.assertEqual(len(cases), 21)
        for case in cases:
            with self.subTest(case=case["case_id"]):
                result = inspect_m2_stage_eight(
                    decode_input(case),
                    case["entrypoint"],
                    trusted_anchor=cast(Any, case.get("trusted_anchor")),
                )
                self.assertEqual(
                    result,
                    M2WireRejection(stage=8, code=case["expected"]["code"]),
                )

    def test_every_later_case_passes_the_grant_boundary(self) -> None:
        cases = [case for case in self.cases() if case["expected"]["reached_stage"] > 8]
        self.assertEqual(len(cases), 40)
        for case in cases:
            with self.subTest(case=case["case_id"]):
                result = inspect_m2_stage_eight(
                    decode_input(case),
                    case["entrypoint"],
                    trusted_anchor=cast(Any, case.get("trusted_anchor")),
                )
                self.assertIsInstance(result, GrantBoundM2Input)
                self.assertFalse(cast(GrantBoundM2Input, result).authorizing)

    def test_frozen_stage_nine_rejections_match(self) -> None:
        cases = [case for case in self.cases() if case["expected"]["reached_stage"] == 9]
        self.assertEqual(len(cases), 3)
        for case in cases:
            with self.subTest(case=case["case_id"]):
                result = inspect_m2_stage_nine(
                    decode_input(case),
                    case["entrypoint"],
                    trusted_anchor=cast(Any, case.get("trusted_anchor")),
                )
                self.assertEqual(
                    result,
                    M2WireRejection(stage=9, code=case["expected"]["code"]),
                )

    def test_every_later_case_passes_the_policy_context_boundary(self) -> None:
        cases = [case for case in self.cases() if case["expected"]["reached_stage"] > 9]
        self.assertEqual(len(cases), 37)
        for case in cases:
            with self.subTest(case=case["case_id"]):
                result = inspect_m2_stage_nine(
                    decode_input(case),
                    case["entrypoint"],
                    trusted_anchor=cast(Any, case.get("trusted_anchor")),
                )
                self.assertIsInstance(result, PolicyContextBoundM2Input)
                self.assertFalse(cast(PolicyContextBoundM2Input, result).authorizing)

    def test_stage_ten_computes_every_frozen_policy_decision(self) -> None:
        cases = [case for case in self.cases() if case["expected"]["reached_stage"] > 9]
        self.assertEqual(len(cases), 37)
        mismatched_supplied_decisions = 0
        policy_rejections = 0
        for case in cases:
            with self.subTest(case=case["case_id"]):
                result = inspect_m2_stage_ten(
                    decode_input(case),
                    case["entrypoint"],
                    trusted_anchor=cast(Any, case.get("trusted_anchor")),
                )
                self.assertIsInstance(result, PolicyEvaluatedM2Input)
                evaluated = cast(PolicyEvaluatedM2Input, result)
                self.assertFalse(evaluated.authorizing)
                self.assertEqual(
                    evaluated.decode_resulting_anchor(), case["expected"]["expected_anchor"]
                )
                decision = cast(dict[str, Any], evaluated.decode_decision())
                wire_value = cast(dict[str, Any], strict_json_loads(decode_input(case)))
                proposal = (
                    wire_value["probe_attested_proposal"]
                    if case["entrypoint"] == "advance-anchor-history"
                    else wire_value
                )
                supplied = proposal["payload"]["decision"]
                if case["expected"]["code"] == "decision.content_mismatch":
                    mismatched_supplied_decisions += 1
                    self.assertNotEqual(decision, supplied)
                else:
                    self.assertEqual(decision, supplied)
                if case["stage"] == 10:
                    policy_rejections += 1
                    self.assertEqual(decision["payload"]["status"], "rejected")
                if case["case_id"] == "bounded-signed-proposal":
                    decision["payload"]["status"] = "mutated"
                    fresh = cast(dict[str, Any], evaluated.decode_decision())
                    self.assertEqual(fresh["payload"]["status"], "accepted")
        self.assertEqual(mismatched_supplied_decisions, 2)
        self.assertEqual(policy_rejections, 2)


if __name__ == "__main__":
    unittest.main()
