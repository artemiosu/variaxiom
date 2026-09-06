"""Bootstrap deterministic evaluators.

The bootstrap evaluator executes a tiny trusted demonstration implementation.
It intentionally does not claim to sandbox arbitrary model-generated code.
Production candidates will be evaluated through isolated WebAssembly or
container backends described in the architecture documents.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

from .canonical import JSONValue
from .domain import Candidate, Evidence


@dataclass(frozen=True, slots=True)
class CheckResult:
    check: str
    passed: bool
    details: dict[str, JSONValue]


def normalize_slug(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value)
    ascii_value = normalized.encode("ascii", "ignore").decode("ascii")
    lowered = ascii_value.lower()
    collapsed = re.sub(r"[^a-z0-9]+", "-", lowered).strip("-")
    return re.sub(r"-{2,}", "-", collapsed)


def evaluate_slug_tool(candidate: Candidate) -> list[Evidence]:
    cases = {
        "Hello, World!": "hello-world",
        "  proof---gated  agents ": "proof-gated-agents",
        "Café déjà vu": "cafe-deja-vu",
        "": "",
    }
    mismatches = {
        source: {"expected": expected, "actual": normalize_slug(source)}
        for source, expected in cases.items()
        if normalize_slug(source) != expected
    }

    security_cases = ["../../etc/passwd", "$(rm -rf /)", "<script>alert(1)</script>"]
    unsafe_outputs = [
        output
        for source in security_cases
        if "/" in (output := normalize_slug(source))
        or "<" in output
        or ">" in output
        or "$" in output
    ]

    raw_results = [
        CheckResult("unit", not mismatches, {"cases": len(cases), "mismatches": len(mismatches)}),
        CheckResult(
            "regression",
            normalize_slug("Agents Mutate Evidence Decides") == "agents-mutate-evidence-decides",
            {"fixture": "tagline"},
        ),
        CheckResult(
            "security",
            not unsafe_outputs,
            {"adversarial_cases": len(security_cases), "unsafe_outputs": len(unsafe_outputs)},
        ),
        CheckResult(
            "budget",
            candidate.estimated_cost_micro_usd <= 5_000_000,
            {"estimated_cost_micro_usd": candidate.estimated_cost_micro_usd},
        ),
    ]

    evidence: list[Evidence] = []
    for index, result in enumerate(raw_results, 1):
        verifier = "verifier:deterministic-tests" if index % 2 else "verifier:policy-audit"
        evidence.append(
            Evidence(
                evidence_id=f"{candidate.candidate_id}:{result.check}",
                subject_id=candidate.candidate_id,
                artifact_hash=candidate.artifact_hash,
                check=result.check,
                status="pass" if result.passed else "fail",
                verifier=verifier,
                independent=True,
                details=result.details,
            )
        )
    return evidence
