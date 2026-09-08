from __future__ import annotations

import base64
import unittest
from pathlib import Path
from typing import Any, cast

from variaxiom.canonical import canonical_json, strict_json_loads
from variaxiom.m2_verifier import (
    CanonicalM2Wire,
    ContextBoundM2Input,
    M2WireRejection,
    StructurallyValidM2Input,
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


if __name__ == "__main__":
    unittest.main()
