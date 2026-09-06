#!/usr/bin/env python3
"""Regenerate the reviewed cross-language promotion vectors."""

from __future__ import annotations

import argparse
import json
from copy import deepcopy
from pathlib import Path
from typing import Any

from variaxiom.canonical import canonical_json, content_hash
from variaxiom.promotion import PromotionGate
from variaxiom.protocol import (
    candidate_from_dict,
    constitution_from_dict,
    context_from_dict,
    decision_envelope_json,
    evidence_from_dict,
    promotion_input_envelope,
)

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "fixtures" / "conformance" / "v1" / "promotion"
ARTIFACT = "a" * 64
OTHER_ARTIFACT = "b" * 64


def constitution() -> dict[str, Any]:
    return {
        "version": "constitution/v1",
        "mandatory_checks": ["budget", "regression", "security", "unit"],
        "minimum_independent_verifiers": 2,
        "max_candidate_cost_micro_usd": 5_000_000,
        "require_known_parent": True,
        "require_rollback_target": True,
        "forbid_self_verification": True,
        "forbid_implicit_authority_escalation": True,
        "reject_any_failed_evidence": True,
    }


def candidate() -> dict[str, Any]:
    return {
        "candidate_id": "candidate:fixture",
        "parent_id": "genome:0",
        "artifact_hash": ARTIFACT,
        "proposer": "agent:builder",
        "rollback_target": "genome:0",
        "baseline_capabilities": ["artifact.read"],
        "requested_capabilities": ["artifact.read"],
        "estimated_cost_micro_usd": 100_000,
        "metadata": {"label": "ограниченный вариант", "reproducible": True},
    }


def evidence() -> list[dict[str, Any]]:
    return [
        {
            "evidence_id": f"e:{check}",
            "subject_id": "candidate:fixture",
            "artifact_hash": ARTIFACT,
            "check": check,
            "status": "pass",
            "verifier": "verifier:a" if index % 2 == 0 else "verifier:b",
            "independent": True,
            "details": {"attempts": 1},
        }
        for index, check in enumerate(("budget", "regression", "security", "unit"))
    ]


def context() -> dict[str, Any]:
    return {
        "known_lineage_ids": ["genome:0"],
        "known_artifact_hashes": [ARTIFACT],
        "authority_grants": {},
        "lineage_capabilities": {"genome:0": ["artifact.read"]},
    }


def base_case(case_id: str) -> dict[str, Any]:
    return {
        "case_id": case_id,
        "protocol_version": "promotion-input/v1",
        "constitution": constitution(),
        "candidate": candidate(),
        "evidence": evidence(),
        "context": context(),
        "authority_grant_id": None,
        "expected": {},
    }


def cases() -> list[dict[str, Any]]:
    accepted = base_case("bounded-accepted")

    authority = base_case("authority-drift-rejected")
    authority["candidate"]["requested_capabilities"] = [
        "artifact.read",
        "network.unrestricted",
    ]

    granted = base_case("exact-authority-grant-accepted")
    granted["candidate"]["requested_capabilities"] = [
        "artifact.read",
        "network.example.com",
    ]
    granted["context"]["authority_grants"] = {"grant:owner": ["network.example.com"]}
    granted["authority_grant_id"] = "grant:owner"

    partial_grant = base_case("partial-authority-grant-rejected")
    partial_grant["candidate"]["requested_capabilities"] = [
        "artifact.read",
        "network.example.com",
        "secret.production",
    ]
    partial_grant["context"]["authority_grants"] = {"grant:owner": ["network.example.com"]}
    partial_grant["authority_grant_id"] = "grant:owner"

    over_budget = base_case("cost-limit-rejected")
    over_budget["candidate"]["estimated_cost_micro_usd"] = 5_000_001

    wrong_artifact = base_case("foreign-artifact-evidence-rejected")
    wrong_artifact["evidence"][3]["artifact_hash"] = OTHER_ARTIFACT

    self_failed = base_case("self-verification-and-failure-rejected")
    self_failed["evidence"][3]["verifier"] = "agent:builder"
    self_failed["evidence"][3]["status"] = "fail"

    spoofed_baseline = base_case("spoofed-baseline-rejected")
    spoofed_baseline["candidate"]["baseline_capabilities"] = [
        "artifact.read",
        "network.unrestricted",
    ]
    spoofed_baseline["candidate"]["requested_capabilities"] = [
        "artifact.read",
        "network.unrestricted",
    ]

    return [
        accepted,
        authority,
        granted,
        partial_grant,
        over_budget,
        wrong_artifact,
        self_failed,
        spoofed_baseline,
    ]


def materialize(raw: dict[str, Any]) -> str:
    prepared = deepcopy(raw)
    candidate_value = candidate_from_dict(prepared["candidate"])
    constitution_value = constitution_from_dict(prepared["constitution"])
    context_value = context_from_dict(prepared["context"])
    evidence_values = [evidence_from_dict(item) for item in prepared["evidence"]]
    authority_grant_id = prepared["authority_grant_id"]
    decision = PromotionGate(constitution_value).decide(
        candidate_value,
        evidence_values,
        context_value,
        authority_grant_id=authority_grant_id,
    )
    input_envelope = promotion_input_envelope(
        candidate_value,
        evidence_values,
        context_value,
        constitution_value,
        authority_grant_id,
    )
    decision_json = decision_envelope_json(decision)
    prepared["expected"] = {
        "decision": decision.as_dict(),
        "input_envelope_json": canonical_json(input_envelope).decode("utf-8"),
        "input_digest": decision.input_digest,
        "decision_envelope_json": decision_json,
        "decision_digest": content_hash(decision.envelope()),
    }
    return json.dumps(prepared, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    failures: list[str] = []
    if not args.check:
        OUTPUT.mkdir(parents=True, exist_ok=True)
    for case in cases():
        path = OUTPUT / f"{case['case_id']}.json"
        rendered = materialize(case)
        if args.check:
            if not path.is_file() or path.read_text("utf-8") != rendered:
                failures.append(str(path.relative_to(ROOT)))
        else:
            path.write_bytes(rendered.encode("utf-8"))
            print(f"wrote {path.relative_to(ROOT)}")
    if failures:
        print("stale conformance fixtures: " + ", ".join(failures))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
