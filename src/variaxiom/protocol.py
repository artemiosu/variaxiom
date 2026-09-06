"""Strict parsing helpers for the versioned cross-language protocol."""

from __future__ import annotations

from collections.abc import Sequence, Set
from dataclasses import dataclass
from typing import Any, cast

from .canonical import (
    MAX_SAFE_INTEGER,
    MIN_SAFE_INTEGER,
    JSONValue,
    canonical_json,
    content_hash,
    strict_json_loads,
    to_json_value,
)
from .constitution import Constitution
from .domain import Candidate, Evidence, PromotionDecision
from .promotion import PromotionContext


class ProtocolError(ValueError):
    """A wire object is structurally invalid or ambiguous."""


def _object(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProtocolError(f"{path} must be an object with string keys")
    raw = cast(dict[object, object], value)
    if not all(isinstance(key, str) for key in raw):
        raise ProtocolError(f"{path} must be an object with string keys")
    return cast(dict[str, Any], raw)


def _json_object(value: Any, path: str) -> dict[str, JSONValue]:
    raw = _object(value, path)
    converted = to_json_value(raw)
    if not isinstance(converted, dict):  # pragma: no cover - guaranteed by _object
        raise ProtocolError(f"{path} must be a JSON object")
    return converted


def _fields(
    value: Any,
    path: str,
    required: set[str],
    optional: Set[str] = frozenset(),
) -> dict[str, Any]:
    data = _object(value, path)
    missing = required - data.keys()
    unknown = data.keys() - required - optional
    if missing:
        raise ProtocolError(f"{path} missing fields: {', '.join(sorted(missing))}")
    if unknown:
        raise ProtocolError(f"{path} has unknown fields: {', '.join(sorted(unknown))}")
    return data


def _string(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value:
        raise ProtocolError(f"{path} must be a non-empty string")
    if any(
        ord(character) < 32 or ord(character) == 127 or 0xD800 <= ord(character) <= 0xDFFF
        for character in value
    ):
        raise ProtocolError(f"{path} contains a forbidden control or surrogate character")
    return value


def _nonempty_scalar_string(value: Any, path: str) -> str:
    """Validate a general JSON string without applying protocol-token rules."""

    if not isinstance(value, str) or not value:
        raise ProtocolError(f"{path} must be a non-empty string")
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise ProtocolError(f"{path} contains a lone Unicode surrogate")
    return value


def _integer(value: Any, path: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ProtocolError(f"{path} must be an integer")
    if not MIN_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
        raise ProtocolError(f"{path} must be in the canonical v1 integer range")
    return value


def _sha256(value: Any, path: str) -> str:
    digest = _string(value, path)
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise ProtocolError(f"{path} must be a lowercase SHA-256 digest")
    return digest


def _boolean(value: Any, path: str) -> bool:
    if not isinstance(value, bool):
        raise ProtocolError(f"{path} must be a boolean")
    return value


def _unique_strings(value: Any, path: str) -> frozenset[str]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ProtocolError(f"{path} must be an array")
    sequence = cast(Sequence[object], value)
    items = [_string(item, f"{path}[]") for item in sequence]
    if len(items) != len(set(items)):
        raise ProtocolError(f"{path} contains duplicates")
    if items != sorted(items):
        raise ProtocolError(f"{path} must be sorted")
    return frozenset(items)


def _capabilities(value: Any, path: str) -> frozenset[str]:
    capabilities = _unique_strings(value, path)
    if any("," in capability for capability in capabilities):
        raise ProtocolError(f"{path} capability names cannot contain commas")
    return capabilities


def _ordered_unique_strings(value: Any, path: str) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ProtocolError(f"{path} must be an array")
    sequence = cast(Sequence[object], value)
    items = tuple(_string(item, f"{path}[]") for item in sequence)
    if len(items) != len(set(items)):
        raise ProtocolError(f"{path} contains duplicates")
    if items != tuple(sorted(items)):
        raise ProtocolError(f"{path} must be sorted")
    return items


def _valid_reason(reason: str) -> bool:
    exact = {
        "artifact.not_verified",
        "authority.baseline_mismatch",
        "authority.baseline_unknown",
        "candidate.cost_limit_exceeded",
        "evidence.verifier_diversity",
        "lineage.parent_unknown",
        "promotion.accepted",
        "rollback.target_unknown",
    }
    if reason in exact:
        return True
    authority = reason.removeprefix("authority.not_granted:")
    if authority != reason:
        capabilities = authority.split(",")
        return all(capabilities) and capabilities == sorted(set(capabilities))
    for prefix in (
        "evidence.artifact_mismatch:",
        "evidence.self_verification:",
        "evidence.missing_check:",
    ):
        suffix = reason.removeprefix(prefix)
        if suffix != reason:
            return bool(suffix)
    failed = reason.removeprefix("evidence.failed:")
    if failed != reason and ":" in failed:
        evidence_id, status = failed.rsplit(":", 1)
        return bool(evidence_id) and status in {"fail", "error"}
    return False


def candidate_from_dict(value: Any) -> Candidate:
    data = _fields(
        value,
        "candidate",
        {
            "candidate_id",
            "parent_id",
            "artifact_hash",
            "proposer",
            "rollback_target",
            "baseline_capabilities",
            "requested_capabilities",
            "estimated_cost_micro_usd",
        },
        {"metadata"},
    )
    estimated_cost = _integer(
        data["estimated_cost_micro_usd"], "candidate.estimated_cost_micro_usd"
    )
    if estimated_cost < 0:
        raise ProtocolError("candidate.estimated_cost_micro_usd must be non-negative")
    return Candidate(
        candidate_id=_string(data["candidate_id"], "candidate.candidate_id"),
        parent_id=_string(data["parent_id"], "candidate.parent_id"),
        artifact_hash=_sha256(data["artifact_hash"], "candidate.artifact_hash"),
        proposer=_string(data["proposer"], "candidate.proposer"),
        rollback_target=_string(data["rollback_target"], "candidate.rollback_target"),
        baseline_capabilities=_capabilities(
            data["baseline_capabilities"], "candidate.baseline_capabilities"
        ),
        requested_capabilities=_capabilities(
            data["requested_capabilities"], "candidate.requested_capabilities"
        ),
        estimated_cost_micro_usd=estimated_cost,
        metadata=_json_object(data.get("metadata", {}), "candidate.metadata"),
    )


def evidence_from_dict(value: Any) -> Evidence:
    data = _fields(
        value,
        "evidence",
        {
            "evidence_id",
            "subject_id",
            "artifact_hash",
            "check",
            "status",
            "verifier",
            "independent",
        },
        {"details"},
    )
    status = _string(data["status"], "evidence.status")
    if status not in {"pass", "fail", "error"}:
        raise ProtocolError("evidence.status must be pass, fail, or error")
    return Evidence(
        evidence_id=_string(data["evidence_id"], "evidence.evidence_id"),
        subject_id=_string(data["subject_id"], "evidence.subject_id"),
        artifact_hash=_sha256(data["artifact_hash"], "evidence.artifact_hash"),
        check=_string(data["check"], "evidence.check"),
        status=status,  # type: ignore[arg-type]
        verifier=_string(data["verifier"], "evidence.verifier"),
        independent=_boolean(data["independent"], "evidence.independent"),
        details=_json_object(data.get("details", {}), "evidence.details"),
    )


def context_from_dict(value: Any) -> PromotionContext:
    data = _fields(
        value,
        "context",
        {
            "known_lineage_ids",
            "known_artifact_hashes",
            "authority_grants",
            "lineage_capabilities",
        },
    )
    grants = _object(data["authority_grants"], "context.authority_grants")
    lineage_capabilities = _object(data["lineage_capabilities"], "context.lineage_capabilities")
    artifact_hashes = _unique_strings(
        data["known_artifact_hashes"], "context.known_artifact_hashes"
    )
    for artifact_hash in artifact_hashes:
        _sha256(artifact_hash, "context.known_artifact_hashes[]")
    known_lineage_ids = _unique_strings(data["known_lineage_ids"], "context.known_lineage_ids")
    if set(lineage_capabilities) != set(known_lineage_ids):
        raise ProtocolError("context.lineage_capabilities must cover known_lineage_ids exactly")
    return PromotionContext(
        known_lineage_ids=known_lineage_ids,
        known_artifact_hashes=artifact_hashes,
        authority_grants={
            _string(grant_id, "context.authority_grants key"): _capabilities(
                capabilities, f"context.authority_grants.{grant_id}"
            )
            for grant_id, capabilities in grants.items()
        },
        lineage_capabilities={
            _string(lineage_id, "context.lineage_capabilities key"): _capabilities(
                capabilities, f"context.lineage_capabilities.{lineage_id}"
            )
            for lineage_id, capabilities in lineage_capabilities.items()
        },
    )


def constitution_from_dict(value: Any) -> Constitution:
    data = _fields(
        value,
        "constitution",
        {
            "version",
            "mandatory_checks",
            "minimum_independent_verifiers",
            "max_candidate_cost_micro_usd",
            "require_known_parent",
            "require_rollback_target",
            "forbid_self_verification",
            "forbid_implicit_authority_escalation",
            "reject_any_failed_evidence",
        },
    )
    version = _string(data["version"], "constitution.version")
    if version != "constitution/v1":
        raise ProtocolError("unsupported constitution.version")
    mandatory_checks = _unique_strings(data["mandatory_checks"], "constitution.mandatory_checks")
    if not mandatory_checks:
        raise ProtocolError("constitution.mandatory_checks cannot be empty")
    minimum_verifiers = _integer(
        data["minimum_independent_verifiers"],
        "constitution.minimum_independent_verifiers",
    )
    if minimum_verifiers < 1:
        raise ProtocolError("constitution.minimum_independent_verifiers must be positive")
    maximum_cost = _integer(
        data["max_candidate_cost_micro_usd"],
        "constitution.max_candidate_cost_micro_usd",
    )
    if maximum_cost < 0:
        raise ProtocolError("constitution.max_candidate_cost_micro_usd must be non-negative")
    constitution = Constitution(
        version=version,
        mandatory_checks=tuple(sorted(mandatory_checks)),
        minimum_independent_verifiers=minimum_verifiers,
        max_candidate_cost_micro_usd=maximum_cost,
        require_known_parent=_boolean(
            data["require_known_parent"], "constitution.require_known_parent"
        ),
        require_rollback_target=_boolean(
            data["require_rollback_target"], "constitution.require_rollback_target"
        ),
        forbid_self_verification=_boolean(
            data["forbid_self_verification"], "constitution.forbid_self_verification"
        ),
        forbid_implicit_authority_escalation=_boolean(
            data["forbid_implicit_authority_escalation"],
            "constitution.forbid_implicit_authority_escalation",
        ),
        reject_any_failed_evidence=_boolean(
            data["reject_any_failed_evidence"], "constitution.reject_any_failed_evidence"
        ),
    )
    if not all(
        (
            constitution.require_known_parent,
            constitution.require_rollback_target,
            constitution.forbid_self_verification,
            constitution.forbid_implicit_authority_escalation,
            constitution.reject_any_failed_evidence,
        )
    ):
        raise ProtocolError("constitution/v1 security invariants cannot be disabled")
    return constitution


def decision_from_dict(value: Any) -> PromotionDecision:
    """Parse and validate a canonical promotion-decision payload."""

    data = _fields(
        value,
        "decision",
        {
            "candidate_id",
            "status",
            "reasons",
            "evidence_ids",
            "input_digest",
            "constitution_version",
            "gate_version",
        },
    )
    status = _string(data["status"], "decision.status")
    if status not in {"accepted", "rejected"}:
        raise ProtocolError("decision.status must be accepted or rejected")
    reasons = _ordered_unique_strings(data["reasons"], "decision.reasons")
    if not reasons or any(not _valid_reason(reason) for reason in reasons):
        raise ProtocolError("decision.reasons contains an invalid reason code")
    if status == "accepted" and reasons != ("promotion.accepted",):
        raise ProtocolError("accepted decision must contain only promotion.accepted")
    if status == "rejected" and "promotion.accepted" in reasons:
        raise ProtocolError("rejected decision cannot contain promotion.accepted")
    constitution_version = _string(data["constitution_version"], "decision.constitution_version")
    gate_version = _string(data["gate_version"], "decision.gate_version")
    if constitution_version != "constitution/v1" or gate_version != "proof-gate/v1":
        raise ProtocolError("unsupported decision version")
    return PromotionDecision(
        candidate_id=_string(data["candidate_id"], "decision.candidate_id"),
        status=status,  # type: ignore[arg-type]
        reasons=reasons,
        evidence_ids=_ordered_unique_strings(data["evidence_ids"], "decision.evidence_ids"),
        input_digest=_sha256(data["input_digest"], "decision.input_digest"),
        constitution_version=constitution_version,
        gate_version=gate_version,
    )


def decision_envelope_from_dict(value: Any) -> PromotionDecision:
    """Parse a domain-separated promotion-decision envelope."""

    data = _fields(value, "decision envelope", {"envelope_version", "kind", "payload"})
    if data["envelope_version"] != "variaxiom-envelope/v1":
        raise ProtocolError("unsupported decision envelope version")
    if data["kind"] != "promotion-decision":
        raise ProtocolError("unexpected decision envelope kind")
    return decision_from_dict(data["payload"])


@dataclass(frozen=True, slots=True)
class ConformanceCase:
    """One shared promotion fixture consumed by Python and Rust."""

    case_id: str
    constitution: Constitution
    candidate: Candidate
    evidence: tuple[Evidence, ...]
    context: PromotionContext
    authority_grant_id: str | None
    expected: dict[str, Any]

    @classmethod
    def from_dict(cls, value: Any) -> ConformanceCase:
        data = _fields(
            value,
            "fixture",
            {
                "case_id",
                "protocol_version",
                "constitution",
                "candidate",
                "evidence",
                "context",
                "authority_grant_id",
                "expected",
            },
        )
        if data["protocol_version"] != "promotion-input/v1":
            raise ProtocolError("unsupported fixture protocol_version")
        evidence_raw = data["evidence"]
        if isinstance(evidence_raw, (str, bytes)) or not isinstance(evidence_raw, list):
            raise ProtocolError("fixture.evidence must be an array")
        evidence_values = cast(list[object], evidence_raw)
        evidence = tuple(evidence_from_dict(item) for item in evidence_values)
        evidence_ids = [item.evidence_id for item in evidence]
        if len(evidence_ids) != len(set(evidence_ids)):
            raise ProtocolError("fixture.evidence contains duplicate evidence_id")
        grant_id = data["authority_grant_id"]
        if grant_id is not None:
            grant_id = _string(grant_id, "fixture.authority_grant_id")
        case = cls(
            case_id=_string(data["case_id"], "fixture.case_id"),
            constitution=constitution_from_dict(data["constitution"]),
            candidate=candidate_from_dict(data["candidate"]),
            evidence=evidence,
            context=context_from_dict(data["context"]),
            authority_grant_id=grant_id,
            expected=_fields(
                data["expected"],
                "fixture.expected",
                {
                    "decision",
                    "input_envelope_json",
                    "input_digest",
                    "decision_envelope_json",
                    "decision_digest",
                },
            ),
        )
        expected_decision = decision_from_dict(case.expected["decision"])
        input_json = _nonempty_scalar_string(
            case.expected["input_envelope_json"], "fixture.expected.input_envelope_json"
        )
        decision_json = _nonempty_scalar_string(
            case.expected["decision_envelope_json"],
            "fixture.expected.decision_envelope_json",
        )
        input_digest = _sha256(case.expected["input_digest"], "fixture.expected.input_digest")
        decision_digest = _sha256(
            case.expected["decision_digest"], "fixture.expected.decision_digest"
        )
        input_envelope = promotion_input_envelope(
            case.candidate,
            case.evidence,
            case.context,
            case.constitution,
            case.authority_grant_id,
        )
        parsed_input_envelope = _fields(
            strict_json_loads(input_json),
            "fixture.expected input envelope",
            {"envelope_version", "kind", "payload"},
        )
        if parsed_input_envelope != input_envelope:
            raise ProtocolError("fixture expected input envelope does not match fixture input")
        if input_json != canonical_json(input_envelope).decode("utf-8"):
            raise ProtocolError("fixture expected input envelope is not canonical JSON")
        parsed_decision = decision_envelope_from_dict(strict_json_loads(decision_json))
        if parsed_decision != expected_decision:
            raise ProtocolError("fixture expected decision envelope does not match decision")
        if decision_json != canonical_json(parsed_decision.envelope()).decode("utf-8"):
            raise ProtocolError("fixture expected decision envelope is not canonical JSON")
        if content_hash(input_envelope) != input_digest:
            raise ProtocolError("fixture expected input digest does not match its envelope")
        if content_hash(parsed_decision.envelope()) != decision_digest:
            raise ProtocolError("fixture expected decision digest does not match its envelope")
        if expected_decision.input_digest != input_digest:
            raise ProtocolError("fixture decision does not bind its expected input digest")
        return case


def promotion_input_envelope(
    candidate: Candidate,
    evidence: Sequence[Evidence],
    context: PromotionContext,
    constitution: Constitution,
    authority_grant_id: str | None,
) -> dict[str, JSONValue]:
    """Build the exact normalized input that a decision commits to."""

    # Dataclass annotations are not runtime guards. Re-parse their public forms so
    # callers of the in-process gate receive the same fail-closed behavior as wire
    # consumers before policy rules run.
    candidate_snapshot = candidate_from_dict(candidate.as_dict())
    evidence_snapshot = tuple(evidence_from_dict(item.as_dict()) for item in evidence)
    context_snapshot = context_from_dict(context.as_dict())
    constitution_snapshot = constitution_from_dict(constitution.as_dict())
    if authority_grant_id is not None:
        _string(authority_grant_id, "authority_grant_id")
        if authority_grant_id not in context_snapshot.authority_grants:
            raise ProtocolError("authority_grant_id does not exist in trusted context")

    evidence_ids = [item.evidence_id for item in evidence_snapshot]
    if len(evidence_ids) != len(set(evidence_ids)):
        raise ProtocolError("promotion input contains duplicate evidence_id")
    return {
        "envelope_version": "variaxiom-envelope/v1",
        "kind": "promotion-input",
        "payload": {
            "authority_grant_id": authority_grant_id,
            "candidate": candidate_snapshot.as_dict(),
            "constitution": constitution_snapshot.as_dict(),
            "context": context_snapshot.as_dict(),
            "evidence": [
                item.as_dict()
                for item in sorted(evidence_snapshot, key=lambda item: item.evidence_id)
            ],
            "protocol_version": "promotion-input/v1",
        },
    }


def promotion_input_digest(
    candidate: Candidate,
    evidence: Sequence[Evidence],
    context: PromotionContext,
    constitution: Constitution,
    authority_grant_id: str | None,
) -> str:
    return content_hash(
        promotion_input_envelope(candidate, evidence, context, constitution, authority_grant_id)
    )


def decision_envelope_json(decision: PromotionDecision) -> str:
    # Route emitters through the same fail-closed validation used by parsers.
    validated = decision_from_dict(decision.as_dict())
    return canonical_json(validated.envelope()).decode("utf-8")
