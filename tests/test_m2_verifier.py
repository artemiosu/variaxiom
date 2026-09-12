from __future__ import annotations

import base64
import unittest
from pathlib import Path
from typing import Any, cast
from unittest.mock import patch

import variaxiom._m2_verifier as m2_verifier_module
import variaxiom.m2_verifier as public_m2_api
from variaxiom._m2_verifier import (
    AnchorTransitionResult,
    CanonicalM2Wire,
    ContextBoundM2Input,
    DigestBoundM2Input,
    EvaluatedProposal,
    EvidenceBoundM2Input,
    GrantBoundM2Input,
    IdentityBoundM2Input,
    M2WireRejection,
    PolicyContextBoundM2Input,
    PolicyEvaluatedM2Input,
    ReplayResult,
    SignatureVerifiedM2Input,
    StructurallyValidM2Input,
    VerificationResult,
    VerifiedM2Proposal,
    VerifiedProposal,
    advance_anchor,
    evaluate_new,
    initialize_anchor,
    inspect_m2_stage_eight,
    inspect_m2_stage_eleven,
    inspect_m2_stage_five,
    inspect_m2_stage_four,
    inspect_m2_stage_nine,
    inspect_m2_stage_seven,
    inspect_m2_stage_six,
    inspect_m2_stage_ten,
    inspect_m2_stage_three,
    inspect_m2_stage_two,
    inspect_m2_wire,
    replay_historical,
    verify_attested_proposal,
)
from variaxiom.canonical import canonical_json, sha256_bytes, strict_json_loads

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
        self.assertEqual(len(cases), 166)
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
        self.assertEqual(len(cases), 24)
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
        self.assertEqual(len(cases), 142)
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
        self.assertEqual(len(cases), 131)
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
        self.assertEqual(len(cases), 108)
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
        self.assertEqual(len(cases), 76)
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
        self.assertEqual(len(cases), 75)
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
        self.assertEqual(len(cases), 54)
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
        self.assertEqual(len(cases), 51)
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
        self.assertEqual(len(cases), 51)
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
                if case["entrypoint"] != "evaluate-new":
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
                if decision["payload"]["status"] == "rejected":
                    policy_rejections += 1
                if case["case_id"] == "bounded-signed-proposal":
                    decision["payload"]["status"] = "mutated"
                    fresh = cast(dict[str, Any], evaluated.decode_decision())
                    self.assertEqual(fresh["payload"]["status"], "accepted")
        self.assertEqual(mismatched_supplied_decisions, 2)
        self.assertEqual(policy_rejections, 3)

    def test_stage_eleven_matches_every_frozen_terminal_result(self) -> None:
        cases = [case for case in self.cases() if case["expected"]["reached_stage"] == 11]
        self.assertEqual(len(cases), 49)
        verified = 0
        rejected = 0
        fixture_authorizing = 0
        for case in cases:
            with self.subTest(case=case["case_id"]):
                result = inspect_m2_stage_eleven(
                    decode_input(case),
                    case["entrypoint"],
                    trusted_anchor=cast(Any, case.get("trusted_anchor")),
                )
                expected = cast(dict[str, Any], case["expected"])
                if expected["status"] == "rejected":
                    rejected += 1
                    self.assertIsInstance(result, M2WireRejection)
                    rejection = cast(M2WireRejection, result)
                    self.assertEqual(rejection.stage, expected["reached_stage"])
                    self.assertEqual(rejection.code, expected["code"])
                    self.assertFalse(rejection.authorizing)
                    continue

                verified += 1
                self.assertIsInstance(result, VerifiedM2Proposal)
                proposal = cast(VerifiedM2Proposal, result)
                fixture_authorizing += int(expected["authorizing"])
                self.assertFalse(proposal.authorizing)
                self.assertEqual(proposal.decode_resulting_anchor(), expected["expected_anchor"])
                decision = cast(dict[str, Any], proposal.decode_decision())
                self.assertEqual(decision["payload"]["status"], expected["decision_status"])
                if case["case_id"] == "bounded-signed-proposal":
                    with self.assertRaises(TypeError):
                        VerifiedM2Proposal(proposal.policy_evaluated)  # type: ignore[call-arg]
                    decoded = cast(dict[str, Any], proposal.decode())
                    decoded["payload"]["decision"]["payload"]["status"] = "mutated"
                    fresh = cast(dict[str, Any], proposal.decode())
                    self.assertEqual(fresh["payload"]["decision"]["payload"]["status"], "accepted")

        self.assertEqual(verified, 30)
        self.assertEqual(rejected, 19)
        self.assertEqual(fixture_authorizing, 0)

    def test_public_result_apis_match_the_frozen_contract(self) -> None:
        cases = {case["case_id"]: case for case in self.cases()}

        evaluated_case = cases["evaluate-new-accepted"]
        evaluated = evaluate_new(decode_input(evaluated_case), evaluated_case["trusted_anchor"])
        self.assertIsInstance(evaluated, EvaluatedProposal)
        self.assertEqual(
            cast(EvaluatedProposal, evaluated).as_dict(),
            strict_json_loads((FIXTURES / "base-evaluated-proposal.json").read_bytes()),
        )

        verified_case = cases["bounded-signed-proposal"]
        verified = verify_attested_proposal(
            decode_input(verified_case), verified_case["trusted_anchor"]
        )
        self.assertIsInstance(verified, VerifiedProposal)
        self.assertEqual(
            cast(VerifiedProposal, verified).as_dict(),
            strict_json_loads((FIXTURES / "base-verified-proposal.json").read_bytes()),
        )

        replay_case = cases["historical-replay-nonauthorizing"]
        replay = replay_historical(decode_input(replay_case), replay_case["trusted_anchor"])
        self.assertIsInstance(replay, ReplayResult)
        self.assertEqual(
            cast(ReplayResult, replay).as_dict(),
            strict_json_loads((FIXTURES / "base-replay-result.json").read_bytes()),
        )

        initialize_case = cases["initialize-anchor-genesis"]
        initialize_input = cast(dict[str, Any], strict_json_loads(decode_input(initialize_case)))
        initialized = initialize_anchor(
            cast(Any, initialize_input["initial_identity_context"]),
            cast(Any, initialize_input["initial_authorization_context"]),
            cast(int, initialize_input["trusted_now_unix_s"]),
        )
        self.assertIsInstance(initialized, AnchorTransitionResult)
        self.assertEqual(
            cast(AnchorTransitionResult, initialized).as_dict()["resulting_anchor"],
            initialize_case["expected"]["expected_anchor"],
        )

        advance_case = cases["anchor-new-key-add"]
        advance_input = cast(dict[str, Any], strict_json_loads(decode_input(advance_case)))
        step = cast(list[dict[str, Any]], advance_input["steps"])[0]
        advanced = advance_anchor(
            cast(Any, advance_input["initial_anchor"]),
            cast(Any, advance_input["initial_identity_context"]),
            cast(Any, step["next_identity_context"]),
            cast(Any, step["next_authorization_context"]),
            cast(int, step["trusted_now_unix_s"]),
        )
        self.assertIsInstance(advanced, AnchorTransitionResult)
        self.assertEqual(
            cast(AnchorTransitionResult, advanced).as_dict()["resulting_anchor"],
            advance_case["expected"]["expected_anchor"],
        )

        retained_case = cases["anchor-new-key-add-omit"]
        retained_input = cast(dict[str, Any], strict_json_loads(decode_input(retained_case)))
        retained_anchor = cast(Any, retained_input["initial_anchor"])
        retained_identity = cast(Any, retained_input["initial_identity_context"])
        for retained_step in cast(list[dict[str, Any]], retained_input["steps"]):
            transition = advance_anchor(
                retained_anchor,
                retained_identity,
                cast(Any, retained_step["next_identity_context"]),
                cast(Any, retained_step["next_authorization_context"]),
                cast(int, retained_step["trusted_now_unix_s"]),
            )
            self.assertIsInstance(transition, AnchorTransitionResult)
            retained_anchor = cast(AnchorTransitionResult, transition).as_dict()["resulting_anchor"]
            retained_identity = retained_step["next_identity_context"]
        self.assertEqual(retained_anchor, retained_case["expected"]["expected_anchor"])

        rebind_case = cases["anchor-new-key-rebind-rejected"]
        rebind_input = cast(dict[str, Any], strict_json_loads(decode_input(rebind_case)))
        rebind_anchor = cast(Any, rebind_input["initial_anchor"])
        rebind_identity = cast(Any, rebind_input["initial_identity_context"])
        rebind_result: AnchorTransitionResult | VerificationResult | None = None
        for rebind_step in cast(list[dict[str, Any]], rebind_input["steps"]):
            rebind_result = advance_anchor(
                rebind_anchor,
                rebind_identity,
                cast(Any, rebind_step["next_identity_context"]),
                cast(Any, rebind_step["next_authorization_context"]),
                cast(int, rebind_step["trusted_now_unix_s"]),
            )
            if isinstance(rebind_result, VerificationResult):
                break
            rebind_anchor = rebind_result.as_dict()["resulting_anchor"]
            rebind_identity = rebind_step["next_identity_context"]
        self.assertIsInstance(rebind_result, VerificationResult)
        rebind_rejection = cast(VerificationResult, rebind_result)
        self.assertEqual(rebind_rejection.status, "rejected")
        self.assertEqual(rebind_rejection.code, "identity.key_ambiguous")

        rejected_case = cases["evaluate-new-anchor-mismatch"]
        rejected = evaluate_new(decode_input(rejected_case), rejected_case["trusted_anchor"])
        self.assertIsInstance(rejected, VerificationResult)
        rejected_result = cast(VerificationResult, rejected)
        self.assertEqual(rejected_result.status, "rejected")
        self.assertEqual(rejected_result.code, "identity.context_untrusted")

    def test_public_result_constructors_are_not_caller_accessible(self) -> None:
        attempts = (
            (VerificationResult, ()),
            (VerificationResult, ("verified", None)),
            (EvaluatedProposal, (b"{}", b"{}")),
            (VerifiedProposal, (b"{}",)),
            (ReplayResult, ("a" * 64, "b" * 64, "c" * 64)),
            (AnchorTransitionResult, (b"{}",)),
        )
        for result_type, args in attempts:
            with self.subTest(result_type=result_type.__name__), self.assertRaises(TypeError):
                result_type(*args)  # type: ignore[call-arg]
            with self.subTest(result_type=result_type.__name__), self.assertRaises(TypeError):
                type(f"Forged{result_type.__name__}", (result_type,), {})

    def test_public_module_exposes_only_normative_operations_and_results(self) -> None:
        expected = {
            "AnchorTransitionResult",
            "EvaluatedProposal",
            "ReplayResult",
            "VerificationResult",
            "VerifiedProposal",
            "advance_anchor",
            "evaluate_new",
            "initialize_anchor",
            "replay_historical",
            "verify_attested_proposal",
        }
        self.assertEqual(set(public_m2_api.__all__), expected)
        self.assertFalse(hasattr(public_m2_api, "M2Entrypoint"))
        self.assertFalse(hasattr(public_m2_api, "inspect_m2_stage_eleven"))

    def test_replay_result_binds_the_anchor_snapshot_actually_verified(self) -> None:
        case = next(
            case for case in self.cases() if case["case_id"] == "historical-replay-nonauthorizing"
        )
        anchor = cast(dict[str, Any], strict_json_loads(canonical_json(case["trusted_anchor"])))
        verified_anchor_data = canonical_json(anchor)
        real_verify_key = m2_verifier_module.VerifyKey
        mutated = False

        class MutatingVerifyKey:
            def __init__(self, key: bytes) -> None:
                self._delegate = real_verify_key(key)

            def verify(self, message: bytes, signature: bytes) -> bytes:
                nonlocal mutated
                if not mutated:
                    mutated = True
                    anchor["trusted_now_unix_s"] = cast(int, anchor["trusted_now_unix_s"]) + 1
                return self._delegate.verify(message, signature)

        with patch.object(m2_verifier_module, "VerifyKey", MutatingVerifyKey):
            replay = replay_historical(decode_input(case), anchor)

        self.assertTrue(mutated)
        self.assertIsInstance(replay, ReplayResult)
        replay_result = cast(ReplayResult, replay)
        self.assertEqual(
            replay_result.recorded_trusted_anchor_digest,
            sha256_bytes(verified_anchor_data),
        )
        self.assertNotEqual(
            replay_result.recorded_trusted_anchor_digest,
            sha256_bytes(canonical_json(anchor)),
        )


if __name__ == "__main__":
    unittest.main()
