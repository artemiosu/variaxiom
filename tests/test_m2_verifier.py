from __future__ import annotations

import base64
import unittest
from pathlib import Path
from typing import Any, cast

from variaxiom.canonical import canonical_json, strict_json_loads
from variaxiom.m2_verifier import CanonicalM2Wire, M2WireRejection, inspect_m2_wire

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


if __name__ == "__main__":
    unittest.main()
