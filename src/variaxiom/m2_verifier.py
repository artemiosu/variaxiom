"""Disabled M2.1 verification primitives.

This module only inspects bounded canonical wire bytes and computes pure policy
results. It has no signing, ambient trust, activation, or lineage-append
capability.
"""

from __future__ import annotations

import base64
import hashlib
import re
from collections.abc import Callable
from dataclasses import dataclass
from importlib import import_module
from typing import Any, Final, Literal, NoReturn, Protocol, cast

from .canonical import JSONValue, canonical_json, sha256_bytes, strict_json_loads


class _SodiumBindings(Protocol):
    def crypto_core_ed25519_is_valid_point(self, point: bytes) -> bool: ...


class _VerifyKey(Protocol):
    def __init__(self, key: bytes) -> None: ...

    def verify(self, message: bytes, signature: bytes) -> bytes: ...


# PyNaCl does not publish typing metadata. Keep the untyped boundary here and
# expose only the two maintained verification operations used by this module.
bindings = cast(_SodiumBindings, import_module("nacl.bindings"))
VerifyKey = cast(type[_VerifyKey], import_module("nacl.signing").VerifyKey)

MAX_M2_WIRE_BYTES: Final = 1_048_576


@dataclass(frozen=True, slots=True)
class M2WireRejection:
    """Stable fail-closed result for an invalid M2.1 wire representation."""

    stage: int
    code: str
    authorizing: bool = False


@dataclass(frozen=True, slots=True)
class CanonicalM2Wire:
    """Immutable canonical bytes accepted at the M2.1 stage-one boundary."""

    data: bytes
    sha256: str

    def decode(self) -> JSONValue:
        """Return a fresh decoded value so callers cannot mutate validated state."""

        value: JSONValue = strict_json_loads(self.data)
        return value


M2WireInspection = CanonicalM2Wire | M2WireRejection

M2Entrypoint = Literal[
    "verify-attested-proposal",
    "replay-historical",
    "initialize-anchor",
    "advance-anchor-history",
]


@dataclass(frozen=True, slots=True)
class StructurallyValidM2Input:
    """Owned input that passed stages one and two, but grants no authority."""

    entrypoint: M2Entrypoint
    wire: CanonicalM2Wire
    trusted_anchor_data: bytes | None = None
    authorizing: bool = False

    def decode(self) -> JSONValue:
        """Return a fresh copy of the structurally validated input."""

        return self.wire.decode()

    def decode_trusted_anchor(self) -> JSONValue | None:
        """Return a fresh copy of the optional external anchor snapshot."""

        if self.trusted_anchor_data is None:
            return None
        return strict_json_loads(self.trusted_anchor_data)


M2StageTwoInspection = StructurallyValidM2Input | M2WireRejection


@dataclass(frozen=True, slots=True)
class ContextBoundM2Input:
    """Owned input that passed stages one through three, but grants no authority."""

    structural: StructurallyValidM2Input
    authorizing: bool = False

    @property
    def entrypoint(self) -> M2Entrypoint:
        """Return the operation whose contexts were checked."""

        return self.structural.entrypoint

    def decode(self) -> JSONValue:
        """Return a fresh copy of the context-bound input."""

        return self.structural.decode()

    def decode_trusted_anchor(self) -> JSONValue | None:
        """Return a fresh copy of the external anchor used for the check."""

        return self.structural.decode_trusted_anchor()


M2StageThreeInspection = ContextBoundM2Input | M2WireRejection


@dataclass(frozen=True, slots=True)
class DigestBoundM2Input:
    """Owned input that passed stages one through four, but grants no authority."""

    context: ContextBoundM2Input
    authorizing: bool = False

    @property
    def entrypoint(self) -> M2Entrypoint:
        return self.context.entrypoint

    def decode(self) -> JSONValue:
        return self.context.decode()

    def decode_trusted_anchor(self) -> JSONValue | None:
        return self.context.decode_trusted_anchor()


M2StageFourInspection = DigestBoundM2Input | M2WireRejection


@dataclass(frozen=True, slots=True)
class IdentityBoundM2Input:
    """Owned input that passed stages one through five, but grants no authority."""

    digest_bound: DigestBoundM2Input
    authorizing: bool = False

    @property
    def entrypoint(self) -> M2Entrypoint:
        return self.digest_bound.entrypoint

    def decode(self) -> JSONValue:
        return self.digest_bound.decode()

    def decode_trusted_anchor(self) -> JSONValue | None:
        return self.digest_bound.decode_trusted_anchor()


M2StageFiveInspection = IdentityBoundM2Input | M2WireRejection


@dataclass(frozen=True, slots=True)
class SignatureVerifiedM2Input:
    """Owned input that passed stages one through six without authorizing effects."""

    identity_bound: IdentityBoundM2Input
    resulting_anchor_data: bytes | None = None
    authorizing: bool = False

    @property
    def entrypoint(self) -> M2Entrypoint:
        return self.identity_bound.entrypoint

    def decode(self) -> JSONValue:
        return self.identity_bound.decode()

    def decode_trusted_anchor(self) -> JSONValue | None:
        return self.identity_bound.decode_trusted_anchor()

    def decode_resulting_anchor(self) -> JSONValue | None:
        if self.resulting_anchor_data is None:
            return None
        return strict_json_loads(self.resulting_anchor_data)


M2StageSixInspection = SignatureVerifiedM2Input | M2WireRejection


@dataclass(frozen=True, slots=True)
class EvidenceBoundM2Input:
    """Owned input whose evidence names the exact signed candidate digest."""

    signature_verified: SignatureVerifiedM2Input
    authorizing: bool = False

    @property
    def entrypoint(self) -> M2Entrypoint:
        return self.signature_verified.entrypoint

    def decode(self) -> JSONValue:
        return self.signature_verified.decode()

    def decode_trusted_anchor(self) -> JSONValue | None:
        return self.signature_verified.decode_trusted_anchor()

    def decode_resulting_anchor(self) -> JSONValue | None:
        return self.signature_verified.decode_resulting_anchor()


M2StageSevenInspection = EvidenceBoundM2Input | M2WireRejection


@dataclass(frozen=True, slots=True)
class GrantBoundM2Input:
    """Owned input whose optional grant exactly matches the authority delta."""

    evidence_bound: EvidenceBoundM2Input
    authorizing: bool = False

    @property
    def entrypoint(self) -> M2Entrypoint:
        return self.evidence_bound.entrypoint

    def decode(self) -> JSONValue:
        return self.evidence_bound.decode()

    def decode_trusted_anchor(self) -> JSONValue | None:
        return self.evidence_bound.decode_trusted_anchor()

    def decode_resulting_anchor(self) -> JSONValue | None:
        return self.evidence_bound.decode_resulting_anchor()


M2StageEightInspection = GrantBoundM2Input | M2WireRejection


@dataclass(frozen=True, slots=True)
class PolicyContextBoundM2Input:
    """Owned input bound to the exact constitution and artifact at stage nine."""

    grant_bound: GrantBoundM2Input
    authorizing: bool = False

    @property
    def entrypoint(self) -> M2Entrypoint:
        return self.grant_bound.entrypoint

    def decode(self) -> JSONValue:
        return self.grant_bound.decode()

    def decode_trusted_anchor(self) -> JSONValue | None:
        return self.grant_bound.decode_trusted_anchor()

    def decode_resulting_anchor(self) -> JSONValue | None:
        return self.grant_bound.decode_resulting_anchor()


M2StageNineInspection = PolicyContextBoundM2Input | M2WireRejection


@dataclass(frozen=True, slots=True)
class PolicyEvaluatedM2Input:
    """Pure M1.1 policy result over a fully bound M2.1 input."""

    policy_context: PolicyContextBoundM2Input
    decision_data: bytes
    authorizing: bool = False

    @property
    def entrypoint(self) -> M2Entrypoint:
        return self.policy_context.entrypoint

    def decode(self) -> JSONValue:
        return self.policy_context.decode()

    def decode_trusted_anchor(self) -> JSONValue | None:
        return self.policy_context.decode_trusted_anchor()

    def decode_resulting_anchor(self) -> JSONValue | None:
        return self.policy_context.decode_resulting_anchor()

    def decode_decision(self) -> JSONValue:
        return strict_json_loads(self.decision_data)


M2StageTenInspection = PolicyEvaluatedM2Input | M2WireRejection

_SHA256 = re.compile(r"[a-f0-9]{64}\Z")
_PRINCIPAL_ID = re.compile(r"principal:[a-z0-9._:/-]+\Z")
_TRUST_DOMAIN_ID = re.compile(r"trust-domain:[a-z0-9._:/-]+\Z")
_KEY_ID = re.compile(r"key:sha256:[a-f0-9]{64}\Z")
_GRANT_ID = re.compile(r"grant:sha256:[a-f0-9]{64}\Z")
_CAPABILITY = re.compile(r"[a-z0-9._:/-]+\Z")
_MAX_SAFE = 9_007_199_254_740_991


class _StageTwoError(Exception):
    def __init__(self, code: str) -> None:
        self.code = code


def _reject(code: str = "input.schema_invalid") -> NoReturn:
    raise _StageTwoError(code)


class _StageThreeError(Exception):
    def __init__(self, code: str) -> None:
        self.code = code


def _reject_stage_three(code: str) -> NoReturn:
    raise _StageThreeError(code)


class _LaterStageError(Exception):
    def __init__(self, stage: int, code: str) -> None:
        self.stage = stage
        self.code = code


def _reject_later(stage: int, code: str) -> NoReturn:
    raise _LaterStageError(stage, code)


def _object(value: Any, fields: set[str], required: set[str] | None = None) -> dict[str, Any]:
    if not isinstance(value, dict):
        _reject()
    raw = cast(dict[object, object], value)
    if not all(isinstance(key, str) for key in raw):
        _reject()
    result = cast(dict[str, Any], raw)
    if set(result) - fields or not (required or fields).issubset(result):
        _reject()
    return result


def _array(value: Any, *, minimum: int = 0) -> list[Any]:
    if not isinstance(value, list):
        _reject()
    result = cast(list[Any], value)
    if len(result) < minimum:
        _reject()
    return result


def _maybe_object(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    return cast(dict[str, Any], value)


def _maybe_array(value: Any) -> list[Any] | None:
    if not isinstance(value, list):
        return None
    return cast(list[Any], value)


def _string(value: Any, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value:
        _reject()
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        _reject()
    if pattern is not None and pattern.fullmatch(value) is None:
        _reject()
    return value


def _token(value: Any) -> str:
    token = _string(value)
    if "," in token:
        _reject()
    return token


def _safe_uint(value: Any, *, positive: bool = False) -> int:
    minimum = 1 if positive else 0
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= _MAX_SAFE:
        _reject()
    return value


def _boolean(value: Any) -> bool:
    if not isinstance(value, bool):
        _reject()
    return value


def _sorted_strings(
    value: Any,
    validator: Callable[[Any], str],
    *,
    minimum: int = 0,
    maximum: int | None = None,
) -> list[str]:
    items = _array(value, minimum=minimum)
    if maximum is not None and len(items) > maximum:
        _reject("input.limit_exceeded")
    strings = [validator(item) for item in items]
    if strings != sorted(set(strings)):
        _reject()
    return strings


def _exact_envelope(value: Any, kind: str) -> tuple[dict[str, Any], dict[str, Any]]:
    envelope = _object(value, {"envelope_version", "kind", "payload"})
    if envelope["envelope_version"] != "variaxiom-envelope/v1" or envelope["kind"] != kind:
        _reject()
    payload = envelope["payload"]
    if not isinstance(payload, dict):
        _reject()
    return envelope, cast(dict[str, Any], payload)


def _validate_signature(value: Any) -> None:
    _, payload = _exact_envelope(value, "detached-signature")
    fields = {
        "signature_version",
        "algorithm",
        "trust_domain_id",
        "principal_id",
        "key_id",
        "signed_kind",
        "signed_digest",
        "signature_base64url",
    }
    payload = _object(payload, fields)
    if payload["signature_version"] != "detached-signature/v1":
        _reject()
    _token(payload["algorithm"])
    _string(payload["trust_domain_id"], _TRUST_DOMAIN_ID)
    _string(payload["principal_id"], _PRINCIPAL_ID)
    _string(payload["key_id"], _KEY_ID)
    if payload["signed_kind"] not in {
        "candidate",
        "evidence",
        "authority-grant",
        "promotion-decision",
    }:
        _reject()
    _string(payload["signed_digest"], _SHA256)
    _string(payload["signature_base64url"])


def _validate_candidate(value: Any) -> dict[str, Any]:
    _, payload = _exact_envelope(value, "candidate")
    fields = {
        "candidate_version",
        "candidate_id",
        "parent_id",
        "artifact_hash",
        "proposer",
        "rollback_target",
        "baseline_capabilities",
        "requested_capabilities",
        "estimated_cost_micro_usd",
        "metadata",
    }
    payload = _object(payload, fields)
    if payload["candidate_version"] != "candidate/v2":
        _reject()
    _token(payload["candidate_id"])
    _token(payload["parent_id"])
    _string(payload["artifact_hash"], _SHA256)
    _string(payload["proposer"], _PRINCIPAL_ID)
    _token(payload["rollback_target"])
    _sorted_strings(
        payload["baseline_capabilities"], lambda item: _string(item, _CAPABILITY), maximum=128
    )
    _sorted_strings(
        payload["requested_capabilities"], lambda item: _string(item, _CAPABILITY), maximum=128
    )
    _safe_uint(payload["estimated_cost_micro_usd"])
    metadata = _object(payload["metadata"], set(cast(dict[str, Any], payload["metadata"])), set())
    if len(canonical_json(cast(JSONValue, metadata))) > 65_536:
        _reject("input.limit_exceeded")
    return payload


def _validate_evidence(value: Any) -> str:
    _, payload = _exact_envelope(value, "evidence")
    fields = {
        "evidence_version",
        "evidence_id",
        "subject_candidate_digest",
        "artifact_hash",
        "check",
        "status",
        "verifier",
        "independent",
        "details",
    }
    payload = _object(payload, fields)
    if payload["evidence_version"] != "evidence/v2":
        _reject()
    evidence_id = _token(payload["evidence_id"])
    _string(payload["subject_candidate_digest"], _SHA256)
    _string(payload["artifact_hash"], _SHA256)
    _token(payload["check"])
    if payload["status"] not in {"pass", "fail", "error"}:
        _reject()
    _string(payload["verifier"], _PRINCIPAL_ID)
    _boolean(payload["independent"])
    details = _object(payload["details"], set(cast(dict[str, Any], payload["details"])), set())
    if len(canonical_json(cast(JSONValue, details))) > 65_536:
        _reject("input.limit_exceeded")
    return evidence_id


def _validate_constitution(value: Any) -> None:
    _, payload = _exact_envelope(value, "constitution")
    fields = {
        "version",
        "mandatory_checks",
        "minimum_independent_verifiers",
        "max_candidate_cost_micro_usd",
        "require_known_parent",
        "require_rollback_target",
        "forbid_self_verification",
        "forbid_implicit_authority_escalation",
        "reject_any_failed_evidence",
    }
    payload = _object(payload, fields)
    if payload["version"] != "constitution/v1":
        _reject()
    _sorted_strings(payload["mandatory_checks"], _string, minimum=1)
    _safe_uint(payload["minimum_independent_verifiers"], positive=True)
    _safe_uint(payload["max_candidate_cost_micro_usd"])
    for field in fields - {
        "version",
        "mandatory_checks",
        "minimum_independent_verifiers",
        "max_candidate_cost_micro_usd",
    }:
        if _boolean(payload[field]) is not True:
            _reject()


def _validate_principal(value: Any) -> tuple[str, list[str]]:
    payload = _object(value, {"principal_version", "principal_id", "roles", "keys"})
    if payload["principal_version"] != "principal/v1":
        _reject()
    principal_id = _string(payload["principal_id"], _PRINCIPAL_ID)
    _sorted_strings(payload["roles"], _token, minimum=1, maximum=8)
    keys = _array(payload["keys"], minimum=1)
    if len(keys) > 8:
        _reject("input.limit_exceeded")
    key_ids: list[str] = []
    for value in keys:
        binding = _object(
            value, {"key_binding_version", "algorithm", "key_id", "public_key_base64url"}
        )
        if binding["key_binding_version"] != "key-binding/v1":
            _reject()
        _token(binding["algorithm"])
        key_ids.append(_string(binding["key_id"], _KEY_ID))
        _string(binding["public_key_base64url"])
    if key_ids != sorted(set(key_ids)):
        _reject()
    return principal_id, key_ids


def _validate_identity_context(value: Any) -> dict[str, Any]:
    _, payload = _exact_envelope(value, "identity-context")
    fields = {
        "identity_context_version",
        "trust_domain_id",
        "snapshot_sequence",
        "previous_snapshot_digest",
        "evaluation_time_unix_s",
        "principals",
        "revoked_key_ids",
        "revoked_grant_ids",
    }
    payload = _object(payload, fields)
    if payload["identity_context_version"] != "identity-context/v1":
        _reject()
    _string(payload["trust_domain_id"], _TRUST_DOMAIN_ID)
    sequence = _safe_uint(payload["snapshot_sequence"])
    previous = payload["previous_snapshot_digest"]
    if (sequence == 0 and previous is not None) or (sequence != 0 and previous is None):
        _reject()
    if previous is not None:
        _string(previous, _SHA256)
    _safe_uint(payload["evaluation_time_unix_s"])
    principals = _array(payload["principals"], minimum=1)
    if len(principals) > 64:
        _reject("input.limit_exceeded")
    principal_ids = [_validate_principal(item)[0] for item in principals]
    if principal_ids != sorted(principal_ids):
        _reject()
    _sorted_strings(payload["revoked_key_ids"], lambda item: _string(item, _KEY_ID), maximum=4096)
    _sorted_strings(
        payload["revoked_grant_ids"], lambda item: _string(item, _GRANT_ID), maximum=4096
    )
    return payload


def _validate_authorization_context(value: Any) -> dict[str, Any]:
    _, payload = _exact_envelope(value, "authorization-context")
    fields = {
        "authorization_context_version",
        "trust_domain_id",
        "capability_namespace",
        "lineage_id",
        "constitution_envelope_digest",
        "constitution_artifact_hash",
        "known_lineage_ids",
        "lineage_capabilities",
        "verified_artifact_hashes",
    }
    payload = _object(payload, fields)
    if payload["authorization_context_version"] != "authorization-context/v1":
        _reject()
    _string(payload["trust_domain_id"], _TRUST_DOMAIN_ID)
    _token(payload["capability_namespace"])
    _token(payload["lineage_id"])
    _string(payload["constitution_envelope_digest"], _SHA256)
    _string(payload["constitution_artifact_hash"], _SHA256)
    known = _sorted_strings(payload["known_lineage_ids"], _token, maximum=4096)
    lineage = _object(
        payload["lineage_capabilities"],
        set(cast(dict[str, Any], payload["lineage_capabilities"])),
        set(),
    )
    if len(lineage) > 4096:
        _reject("input.limit_exceeded")
    for key, capabilities in lineage.items():
        _token(key)
        _sorted_strings(capabilities, lambda item: _string(item, _CAPABILITY), maximum=128)
    if known != sorted(lineage):
        _reject()
    _sorted_strings(
        payload["verified_artifact_hashes"], lambda item: _string(item, _SHA256), maximum=4096
    )
    return payload


def _validate_grant(value: Any) -> None:
    _, payload = _exact_envelope(value, "authority-grant")
    fields = {
        "grant_version",
        "audience",
        "trust_domain_id",
        "capability_namespace",
        "constitution_digest",
        "lineage_id",
        "issuer_principal_id",
        "subject_candidate_digest",
        "capabilities",
        "not_before_unix_s",
        "expires_at_unix_s",
        "delegable",
    }
    payload = _object(payload, fields)
    if payload["grant_version"] != "authority-grant/v1":
        _reject()
    _token(payload["audience"])
    _string(payload["trust_domain_id"], _TRUST_DOMAIN_ID)
    _token(payload["capability_namespace"])
    _string(payload["constitution_digest"], _SHA256)
    _token(payload["lineage_id"])
    _string(payload["issuer_principal_id"], _PRINCIPAL_ID)
    _string(payload["subject_candidate_digest"], _SHA256)
    _sorted_strings(
        payload["capabilities"], lambda item: _string(item, _CAPABILITY), minimum=1, maximum=128
    )
    _safe_uint(payload["not_before_unix_s"])
    _safe_uint(payload["expires_at_unix_s"], positive=True)
    _boolean(payload["delegable"])


def _validate_decision(value: Any) -> None:
    _, payload = _exact_envelope(value, "promotion-decision")
    fields = {
        "candidate_id",
        "status",
        "reasons",
        "evidence_ids",
        "input_digest",
        "constitution_version",
        "gate_version",
    }
    payload = _object(payload, fields)
    _string(payload["candidate_id"])
    if payload["status"] not in {"accepted", "rejected"}:
        _reject()
    reasons = _sorted_strings(payload["reasons"], _string, minimum=1)
    if payload["status"] == "accepted" and reasons != ["promotion.accepted"]:
        _reject()
    if payload["status"] == "rejected" and "promotion.accepted" in reasons:
        _reject()
    _sorted_strings(payload["evidence_ids"], _string)
    _string(payload["input_digest"], _SHA256)
    if (
        payload["constitution_version"] != "constitution/v1"
        or payload["gate_version"] != "proof-gate/v1"
    ):
        _reject()


def _validate_attested(value: Any) -> None:
    _, payload = _exact_envelope(value, "attested-proposal")
    payload = _object(
        payload, {"proposal_version", "promotion_input", "decision", "selector_signature"}
    )
    if payload["proposal_version"] != "attested-proposal/v1":
        _reject()
    _, body = _exact_envelope(payload["promotion_input"], "promotion-input")
    body = _object(
        body,
        {
            "protocol_version",
            "candidate",
            "evidence",
            "constitution",
            "identity_context",
            "authorization_context",
            "authority_grant",
        },
        {
            "protocol_version",
            "candidate",
            "evidence",
            "constitution",
            "identity_context",
            "authorization_context",
        },
    )
    if body["protocol_version"] != "promotion-input/v2":
        _reject()
    candidate_pair = _object(body["candidate"], {"envelope", "signature"})
    _validate_candidate(candidate_pair["envelope"])
    _validate_signature(candidate_pair["signature"])
    evidence = _array(body["evidence"], minimum=1)
    if len(evidence) > 256:
        _reject("input.limit_exceeded")
    evidence_ids: list[str] = []
    for item in evidence:
        pair = _object(item, {"envelope", "signature"})
        evidence_ids.append(_validate_evidence(pair["envelope"]))
        _validate_signature(pair["signature"])
    if evidence_ids != sorted(evidence_ids):
        _reject()
    constitution = _object(body["constitution"], {"envelope", "artifact_hash"})
    _validate_constitution(constitution["envelope"])
    _string(constitution["artifact_hash"], _SHA256)
    _validate_identity_context(body["identity_context"])
    _validate_authorization_context(body["authorization_context"])
    if "authority_grant" in body:
        grant = _object(body["authority_grant"], {"envelope", "signature"})
        _validate_grant(grant["envelope"])
        _validate_signature(grant["signature"])
    _validate_decision(payload["decision"])
    _validate_signature(payload["selector_signature"])


def _validate_anchor(value: Any) -> dict[str, Any]:
    fields = {
        "trust_domain_id",
        "current_identity_context_digest",
        "current_authorization_context_digest",
        "current_snapshot_sequence",
        "trusted_now_unix_s",
        "key_ownership_registry",
        "revoked_key_ids",
        "revoked_grant_ids",
    }
    anchor = _object(value, fields)
    _string(anchor["trust_domain_id"], _TRUST_DOMAIN_ID)
    _string(anchor["current_identity_context_digest"], _SHA256)
    _string(anchor["current_authorization_context_digest"], _SHA256)
    _safe_uint(anchor["current_snapshot_sequence"])
    _safe_uint(anchor["trusted_now_unix_s"])
    registry = _object(
        anchor["key_ownership_registry"],
        set(cast(dict[str, Any], anchor["key_ownership_registry"])),
        set(),
    )
    if len(registry) > 4096:
        _reject("input.limit_exceeded")
    for key, principal in registry.items():
        _string(key, _KEY_ID)
        _string(principal, _PRINCIPAL_ID)
    _sorted_strings(anchor["revoked_key_ids"], lambda item: _string(item, _KEY_ID), maximum=4096)
    _sorted_strings(
        anchor["revoked_grant_ids"], lambda item: _string(item, _GRANT_ID), maximum=4096
    )
    return anchor


def _preflight_context(identity: Any, authorization: Any, *, versions_only: bool = False) -> None:
    pairs = [
        (identity, "identity-context", "identity_context_version", "identity-context/v1"),
        (
            authorization,
            "authorization-context",
            "authorization_context_version",
            "authorization-context/v1",
        ),
    ]
    for value, _, field, expected in pairs:
        item = _maybe_object(value)
        if item is not None:
            if "envelope_version" in item and item["envelope_version"] != "variaxiom-envelope/v1":
                _reject("input.version_unsupported")
            payload = _maybe_object(item.get("payload"))
            if payload is not None and field in payload and payload[field] != expected:
                _reject("input.version_unsupported")
    identity_object = _maybe_object(identity)
    identity_payload = _maybe_object(identity_object.get("payload")) if identity_object else None
    if identity_payload is not None:
        for raw_principal in _maybe_array(identity_payload.get("principals")) or []:
            principal = _maybe_object(raw_principal)
            if principal is not None and principal.get("principal_version") not in {
                None,
                "principal/v1",
            }:
                _reject("input.version_unsupported")
            if principal is not None:
                for raw_key in _maybe_array(principal.get("keys")) or []:
                    key = _maybe_object(raw_key)
                    if key is not None and key.get("key_binding_version") not in {
                        None,
                        "key-binding/v1",
                    }:
                        _reject("input.version_unsupported")
    if versions_only:
        return
    for value, kind, _, _ in pairs:
        item = _maybe_object(value)
        if item is not None and "kind" in item and item["kind"] != kind:
            _reject("input.kind_mismatch")


def _preflight_attested(value: Any) -> None:
    root = _maybe_object(value)
    if root is None:
        return
    paths: list[tuple[Any, str]] = [(root, "attested-proposal")]
    payload = _maybe_object(root.get("payload"))
    promotion = _maybe_object(payload.get("promotion_input")) if payload else None
    body = _maybe_object(promotion.get("payload")) if promotion else None
    if promotion is not None:
        paths.append((promotion, "promotion-input"))
    if body is not None:
        for name, kind in (
            ("identity_context", "identity-context"),
            ("authorization_context", "authorization-context"),
        ):
            paths.append((body.get(name), kind))
        for pair_name, kind in (("candidate", "candidate"), ("authority_grant", "authority-grant")):
            pair = _maybe_object(body.get(pair_name))
            if pair is not None:
                paths.extend(
                    ((pair.get("envelope"), kind), (pair.get("signature"), "detached-signature"))
                )
        constitution = _maybe_object(body.get("constitution"))
        if constitution is not None:
            paths.append((constitution.get("envelope"), "constitution"))
        evidence = _maybe_array(body.get("evidence"))
        if evidence is not None:
            for raw_pair in evidence:
                pair = _maybe_object(raw_pair)
                if pair is not None:
                    paths.extend(
                        (
                            (pair.get("envelope"), "evidence"),
                            (pair.get("signature"), "detached-signature"),
                        )
                    )
    if payload is not None:
        paths.extend(
            (
                (payload.get("decision"), "promotion-decision"),
                (payload.get("selector_signature"), "detached-signature"),
            )
        )
    for node, _ in paths:
        item = _maybe_object(node)
        if (
            item is not None
            and "envelope_version" in item
            and item["envelope_version"] != "variaxiom-envelope/v1"
        ):
            _reject("input.version_unsupported")
    version_names = {
        "attested-proposal": ("proposal_version", "attested-proposal/v1"),
        "promotion-input": ("protocol_version", "promotion-input/v2"),
        "candidate": ("candidate_version", "candidate/v2"),
        "evidence": ("evidence_version", "evidence/v2"),
        "constitution": ("version", "constitution/v1"),
        "identity-context": ("identity_context_version", "identity-context/v1"),
        "authorization-context": ("authorization_context_version", "authorization-context/v1"),
        "authority-grant": ("grant_version", "authority-grant/v1"),
        "detached-signature": ("signature_version", "detached-signature/v1"),
    }
    for node, kind in paths:
        item = _maybe_object(node)
        if item is None:
            continue
        target = _maybe_object(item.get("payload"))
        pair = version_names.get(kind)
        if pair and target is not None and pair[0] in target and target[pair[0]] != pair[1]:
            _reject("input.version_unsupported")
    if body is not None:
        _preflight_context(
            body.get("identity_context"), body.get("authorization_context"), versions_only=True
        )
    for node, kind in paths:
        item = _maybe_object(node)
        if item is not None and "kind" in item and item["kind"] != kind:
            _reject("input.kind_mismatch")


def _enforce_string_limits(value: Any, *, excluded: bool = False) -> None:
    if isinstance(value, str):
        if not excluded and len(value.encode("utf-8")) > 256:
            _reject("input.limit_exceeded")
    elif isinstance(value, list):
        for item in cast(list[Any], value):
            _enforce_string_limits(item, excluded=excluded)
    elif isinstance(value, dict):
        for key, item in cast(dict[str, Any], value).items():
            _enforce_string_limits(key, excluded=excluded)
            _enforce_string_limits(item, excluded=excluded or key in {"metadata", "details"})


def _stage_two(value: JSONValue, entrypoint: M2Entrypoint, anchor: JSONValue | None) -> None:
    if entrypoint not in {
        "verify-attested-proposal",
        "replay-historical",
        "initialize-anchor",
        "advance-anchor-history",
    }:
        _reject()
    if entrypoint in {"verify-attested-proposal", "replay-historical"}:
        _preflight_attested(value)
        _enforce_string_limits(value)
        _validate_attested(value)
        if anchor is None:
            _reject()
        _enforce_string_limits(anchor)
        _validate_anchor(anchor)
        return
    history = _maybe_object(value)
    if history is None:
        _reject()
    if entrypoint == "initialize-anchor":
        identity = history.get("initial_identity_context")
        authorization = history.get("initial_authorization_context")
        _preflight_context(identity, authorization)
        _enforce_string_limits(history)
        init = _object(
            history,
            {"initial_identity_context", "initial_authorization_context", "trusted_now_unix_s"},
        )
        _validate_identity_context(init["initial_identity_context"])
        _validate_authorization_context(init["initial_authorization_context"])
        _safe_uint(init["trusted_now_unix_s"])
        return
    initial_identity = history.get("initial_identity_context")
    initial_authorization = history.get("initial_authorization_context")
    steps = history.get("steps")
    contexts: list[tuple[Any, Any]] = [(initial_identity, initial_authorization)]
    step_values = _maybe_array(steps)
    if step_values is not None:
        for raw_step in step_values:
            step = _maybe_object(raw_step)
            if step is not None:
                contexts.append(
                    (step.get("next_identity_context"), step.get("next_authorization_context"))
                )
    for identity, authorization in contexts:
        _preflight_context(identity, authorization, versions_only=True)
    for identity, authorization in contexts:
        _preflight_context(identity, authorization)
    _enforce_string_limits(history)
    history = _object(
        history,
        {
            "initial_anchor",
            "initial_identity_context",
            "initial_authorization_context",
            "steps",
            "probe_attested_proposal",
        },
        {"initial_anchor", "initial_identity_context", "initial_authorization_context", "steps"},
    )
    current_anchor = _validate_anchor(history["initial_anchor"])
    _validate_identity_context(history["initial_identity_context"])
    _validate_authorization_context(history["initial_authorization_context"])
    steps_list = _array(history["steps"], minimum=1)
    if len(steps_list) > 16:
        _reject("input.limit_exceeded")
    projected_ownership = set(cast(dict[str, Any], current_anchor["key_ownership_registry"]))
    projected_revoked_keys = set(cast(list[str], current_anchor["revoked_key_ids"]))
    projected_revoked_grants = set(cast(list[str], current_anchor["revoked_grant_ids"]))
    for step_value in steps_list:
        step = _object(
            step_value,
            {"next_identity_context", "next_authorization_context", "trusted_now_unix_s"},
        )
        identity = _validate_identity_context(step["next_identity_context"])
        _validate_authorization_context(step["next_authorization_context"])
        _safe_uint(step["trusted_now_unix_s"])
        new_keys = {
            cast(str, key["key_id"])
            for principal in cast(list[dict[str, Any]], identity["principals"])
            for key in cast(list[dict[str, Any]], principal["keys"])
        }
        projected_ownership.update(new_keys)
        projected_revoked_keys.update(cast(list[str], identity["revoked_key_ids"]))
        projected_revoked_grants.update(cast(list[str], identity["revoked_grant_ids"]))
        if any(
            len(collection) > 4096
            for collection in (
                projected_ownership,
                projected_revoked_keys,
                projected_revoked_grants,
            )
        ):
            _reject("input.limit_exceeded")


def inspect_m2_stage_two(
    source: bytes | bytearray | memoryview,
    entrypoint: M2Entrypoint,
    *,
    trusted_anchor: JSONValue | None = None,
) -> M2StageTwoInspection:
    """Apply M2.1 stages one and two without authentication or authority."""

    wire = inspect_m2_wire(source)
    if isinstance(wire, M2WireRejection):
        return wire
    anchor_snapshot: JSONValue | None = None
    anchor_data: bytes | None = None
    if trusted_anchor is not None:
        try:
            anchor_data = canonical_json(trusted_anchor)
            anchor_snapshot = strict_json_loads(anchor_data)
        except (TypeError, ValueError):
            return M2WireRejection(stage=2, code="input.schema_invalid")
    try:
        _stage_two(wire.decode(), entrypoint, anchor_snapshot)
    except (AttributeError, IndexError, KeyError, TypeError, ValueError, _StageTwoError) as error:
        code = error.code if isinstance(error, _StageTwoError) else "input.schema_invalid"
        return M2WireRejection(stage=2, code=code)
    return StructurallyValidM2Input(
        entrypoint=entrypoint, wire=wire, trusted_anchor_data=anchor_data
    )


def _canonical_digest(value: JSONValue) -> str:
    return sha256_bytes(canonical_json(value))


def _attested_contexts(value: JSONValue) -> tuple[dict[str, Any], dict[str, Any]]:
    root = cast(dict[str, Any], value)
    body = cast(dict[str, Any], root["payload"])["promotion_input"]["payload"]
    return cast(dict[str, Any], body["identity_context"]), cast(
        dict[str, Any], body["authorization_context"]
    )


def _attested_signatures(value: JSONValue) -> list[dict[str, Any]]:
    root = cast(dict[str, Any], value)
    payload = cast(dict[str, Any], root["payload"])
    body = cast(dict[str, Any], payload["promotion_input"])["payload"]
    signatures = [cast(dict[str, Any], body["candidate"])["signature"]]
    signatures.extend(item["signature"] for item in cast(list[dict[str, Any]], body["evidence"]))
    grant = body.get("authority_grant")
    if grant is not None:
        signatures.append(cast(dict[str, Any], grant)["signature"])
    return signatures


def _stage_three_attested(value: JSONValue, anchor: dict[str, Any]) -> None:
    identity, authorization = _attested_contexts(value)
    identity_payload = cast(dict[str, Any], identity["payload"])
    sequence = cast(int, identity_payload["snapshot_sequence"])
    anchor_sequence = cast(int, anchor["current_snapshot_sequence"])
    if sequence < anchor_sequence:
        _reject_stage_three("identity.context_stale")
    if (
        identity_payload["trust_domain_id"] != anchor["trust_domain_id"]
        or _canonical_digest(cast(JSONValue, identity)) != anchor["current_identity_context_digest"]
        or sequence != anchor_sequence
        or identity_payload["evaluation_time_unix_s"] != anchor["trusted_now_unix_s"]
    ):
        _reject_stage_three("identity.context_untrusted")
    authorization_payload = cast(dict[str, Any], authorization["payload"])
    if (
        authorization_payload["trust_domain_id"] != anchor["trust_domain_id"]
        or _canonical_digest(cast(JSONValue, authorization))
        != anchor["current_authorization_context_digest"]
    ):
        _reject_stage_three("authorization.context_untrusted")
    if any(
        cast(dict[str, Any], signature["payload"])["trust_domain_id"] != anchor["trust_domain_id"]
        for signature in _attested_signatures(value)
    ):
        _reject_stage_three("signature.domain_mismatch")


def _stage_three_initialize(value: JSONValue) -> None:
    request = cast(dict[str, Any], value)
    identity = cast(dict[str, Any], request["initial_identity_context"])
    authorization = cast(dict[str, Any], request["initial_authorization_context"])
    identity_payload = cast(dict[str, Any], identity["payload"])
    authorization_payload = cast(dict[str, Any], authorization["payload"])
    if (
        identity_payload["snapshot_sequence"] != 0
        or identity_payload["previous_snapshot_digest"] is not None
        or identity_payload["evaluation_time_unix_s"] != request["trusted_now_unix_s"]
        or authorization_payload["trust_domain_id"] != identity_payload["trust_domain_id"]
    ):
        _reject_stage_three("identity.context_untrusted")


def _identity_key_owners(identity: dict[str, Any]) -> dict[str, str]:
    payload = cast(dict[str, Any], identity["payload"])
    return {
        cast(str, key["key_id"]): cast(str, principal["principal_id"])
        for principal in cast(list[dict[str, Any]], payload["principals"])
        for key in cast(list[dict[str, Any]], principal["keys"])
    }


def _stage_three_history(value: JSONValue) -> None:
    history = cast(dict[str, Any], value)
    anchor = cast(dict[str, Any], history["initial_anchor"])
    previous_identity = cast(dict[str, Any], history["initial_identity_context"])
    authorization = cast(dict[str, Any], history["initial_authorization_context"])
    previous_payload = cast(dict[str, Any], previous_identity["payload"])
    authorization_payload = cast(dict[str, Any], authorization["payload"])
    if (
        _canonical_digest(cast(JSONValue, previous_identity))
        != anchor["current_identity_context_digest"]
        or _canonical_digest(cast(JSONValue, authorization))
        != anchor["current_authorization_context_digest"]
        or previous_payload["trust_domain_id"] != anchor["trust_domain_id"]
        or authorization_payload["trust_domain_id"] != anchor["trust_domain_id"]
        or previous_payload["snapshot_sequence"] != anchor["current_snapshot_sequence"]
        or previous_payload["evaluation_time_unix_s"] != anchor["trusted_now_unix_s"]
        or not set(cast(list[str], previous_payload["revoked_key_ids"])).issubset(
            cast(list[str], anchor["revoked_key_ids"])
        )
        or not set(cast(list[str], previous_payload["revoked_grant_ids"])).issubset(
            cast(list[str], anchor["revoked_grant_ids"])
        )
        or any(
            cast(dict[str, Any], anchor["key_ownership_registry"]).get(key_id) != principal_id
            for key_id, principal_id in _identity_key_owners(previous_identity).items()
        )
    ):
        _reject_stage_three("identity.context_untrusted")

    current_anchor = strict_json_loads(canonical_json(cast(JSONValue, anchor)))
    current = cast(dict[str, Any], current_anchor)
    for raw_step in cast(list[dict[str, Any]], history["steps"]):
        identity = cast(dict[str, Any], raw_step["next_identity_context"])
        next_authorization = cast(dict[str, Any], raw_step["next_authorization_context"])
        payload = cast(dict[str, Any], identity["payload"])
        next_authorization_payload = cast(dict[str, Any], next_authorization["payload"])
        now = cast(int, raw_step["trusted_now_unix_s"])
        if now < cast(int, current["trusted_now_unix_s"]) or cast(
            int, payload["evaluation_time_unix_s"]
        ) < cast(int, current["trusted_now_unix_s"]):
            _reject_stage_three("identity.context_stale")
        if (
            payload["trust_domain_id"] != current["trust_domain_id"]
            or cast(int, payload["snapshot_sequence"])
            != cast(int, current["current_snapshot_sequence"]) + 1
            or payload["previous_snapshot_digest"]
            != _canonical_digest(cast(JSONValue, previous_identity))
            or payload["evaluation_time_unix_s"] != now
            or next_authorization_payload["trust_domain_id"] != current["trust_domain_id"]
            or not set(cast(list[str], current["revoked_key_ids"])).issubset(
                cast(list[str], payload["revoked_key_ids"])
            )
            or not set(cast(list[str], current["revoked_grant_ids"])).issubset(
                cast(list[str], payload["revoked_grant_ids"])
            )
        ):
            _reject_stage_three("identity.context_untrusted")
        registry = cast(dict[str, str], current["key_ownership_registry"])
        for key_id, principal_id in _identity_key_owners(identity).items():
            registry.setdefault(key_id, principal_id)
        current = {
            "trust_domain_id": current["trust_domain_id"],
            "current_identity_context_digest": _canonical_digest(cast(JSONValue, identity)),
            "current_authorization_context_digest": _canonical_digest(
                cast(JSONValue, next_authorization)
            ),
            "current_snapshot_sequence": payload["snapshot_sequence"],
            "trusted_now_unix_s": now,
            "key_ownership_registry": dict(sorted(registry.items())),
            "revoked_key_ids": sorted(
                set(cast(list[str], current["revoked_key_ids"]))
                | set(cast(list[str], payload["revoked_key_ids"]))
            ),
            "revoked_grant_ids": sorted(
                set(cast(list[str], current["revoked_grant_ids"]))
                | set(cast(list[str], payload["revoked_grant_ids"]))
            ),
        }
        previous_identity = identity

    probe = history.get("probe_attested_proposal")
    if probe is not None:
        _stage_three_attested(cast(JSONValue, probe), current)


def inspect_m2_stage_three(
    source: bytes | bytearray | memoryview,
    entrypoint: M2Entrypoint,
    *,
    trusted_anchor: JSONValue | None = None,
) -> M2StageThreeInspection:
    """Apply M2.1 stages one through three without granting authority."""

    structural = inspect_m2_stage_two(source, entrypoint, trusted_anchor=trusted_anchor)
    if isinstance(structural, M2WireRejection):
        return structural
    try:
        value = structural.decode()
        if entrypoint in {"verify-attested-proposal", "replay-historical"}:
            anchor = structural.decode_trusted_anchor()
            if not isinstance(anchor, dict):
                return M2WireRejection(stage=2, code="input.schema_invalid")
            _stage_three_attested(value, cast(dict[str, Any], anchor))
        elif entrypoint == "initialize-anchor":
            _stage_three_initialize(value)
        else:
            _stage_three_history(value)
    except (AttributeError, IndexError, KeyError, TypeError, ValueError, _StageThreeError) as error:
        code = error.code if isinstance(error, _StageThreeError) else "identity.context_untrusted"
        return M2WireRejection(stage=3, code=code)
    return ContextBoundM2Input(structural=structural)


_SignaturePair = tuple[dict[str, Any], str, str]
_ROLE_FOR_KIND: Final = {
    "candidate": "candidate-proposer",
    "evidence": "evidence-verifier",
    "authority-grant": "authority-issuer",
    "promotion-decision": "promotion-selector",
}


def _signature_pairs(value: JSONValue, *, include_selector: bool = False) -> list[_SignaturePair]:
    root = cast(dict[str, Any], value)
    proposal = cast(dict[str, Any], root["payload"])
    body = cast(dict[str, Any], proposal["promotion_input"])["payload"]
    candidate = cast(dict[str, Any], body["candidate"])
    pairs: list[_SignaturePair] = [
        (candidate, "candidate", candidate["envelope"]["payload"]["proposer"])
    ]
    pairs.extend(
        (item, "evidence", item["envelope"]["payload"]["verifier"])
        for item in cast(list[dict[str, Any]], body["evidence"])
    )
    grant = body.get("authority_grant")
    if grant is not None:
        grant_pair = cast(dict[str, Any], grant)
        pairs.append(
            (
                grant_pair,
                "authority-grant",
                grant_pair["envelope"]["payload"]["issuer_principal_id"],
            )
        )
    if include_selector:
        selector = cast(dict[str, Any], proposal["selector_signature"])
        pairs.append(
            (
                {"envelope": proposal["decision"], "signature": selector},
                "promotion-decision",
                selector["payload"]["principal_id"],
            )
        )
    return pairs


def _identity_maps(
    identity: dict[str, Any],
) -> tuple[dict[str, dict[str, Any]], dict[str, tuple[str, dict[str, Any]]], bool]:
    payload = cast(dict[str, Any], identity["payload"])
    principals: dict[str, dict[str, Any]] = {}
    keys: dict[str, tuple[str, dict[str, Any]]] = {}
    public_keys: set[str] = set()
    ambiguous = False
    for principal in cast(list[dict[str, Any]], payload["principals"]):
        principal_id = cast(str, principal["principal_id"])
        ambiguous |= principal_id in principals
        principals[principal_id] = principal
        for key in cast(list[dict[str, Any]], principal["keys"]):
            key_id = cast(str, key["key_id"])
            public = cast(str, key["public_key_base64url"])
            ambiguous |= key_id in keys or public in public_keys
            keys[key_id] = (principal_id, key)
            public_keys.add(public)
    return principals, keys, ambiguous


def _public_bytes(value: str) -> bytes | None:
    try:
        raw = base64.b64decode(
            value + "=" * ((4 - len(value) % 4) % 4), altchars=b"-_", validate=True
        )
    except (ValueError, TypeError):
        return None
    if len(raw) != 32 or base64.urlsafe_b64encode(raw).decode().rstrip("=") != value:
        return None
    return raw


def _computed_key_id(binding: dict[str, Any]) -> str | None:
    public = _public_bytes(cast(str, binding["public_key_base64url"]))
    if public is None:
        return None
    return "key:sha256:" + hashlib.sha256(b"variaxiom-key/v1\0Ed25519\0" + public).hexdigest()


def _stage_four_pairs(
    pairs: list[_SignaturePair], keys: dict[str, tuple[str, dict[str, Any]]]
) -> None:
    for pair, _, _ in pairs:
        signature = cast(dict[str, Any], pair["signature"])["payload"]
        if signature["signed_digest"] != _canonical_digest(cast(JSONValue, pair["envelope"])):
            _reject_later(4, "signature.digest_mismatch")
    for pair, _, _ in pairs:
        signature = cast(dict[str, Any], pair["signature"])["payload"]
        binding = keys.get(cast(str, signature["key_id"]))
        if binding is not None:
            expected = _computed_key_id(binding[1])
            if expected is not None and binding[1]["key_id"] != expected:
                _reject_later(4, "signature.key_id_mismatch")
    for pair, kind, _ in pairs:
        signature = cast(dict[str, Any], pair["signature"])["payload"]
        if signature["signed_kind"] != kind:
            _reject_later(4, "signature.kind_mismatch")


def _stage_four_all_bindings(identity: dict[str, Any]) -> None:
    payload = cast(dict[str, Any], identity["payload"])
    for principal in cast(list[dict[str, Any]], payload["principals"]):
        for binding in cast(list[dict[str, Any]], principal["keys"]):
            expected = _computed_key_id(binding)
            if expected is not None and binding["key_id"] != expected:
                _reject_later(4, "signature.key_id_mismatch")


def _stage_four_attested(value: JSONValue) -> None:
    identity, _ = _attested_contexts(value)
    _, keys, _ = _identity_maps(identity)
    _stage_four_pairs(_signature_pairs(value), keys)


def _stage_four(value: JSONValue, entrypoint: M2Entrypoint) -> None:
    if entrypoint in {"verify-attested-proposal", "replay-historical"}:
        _stage_four_attested(value)
        return
    request = cast(dict[str, Any], value)
    if entrypoint == "initialize-anchor":
        _stage_four_all_bindings(cast(dict[str, Any], request["initial_identity_context"]))
        return
    identities = [cast(dict[str, Any], request["initial_identity_context"])]
    identities.extend(
        cast(dict[str, Any], step["next_identity_context"])
        for step in cast(list[dict[str, Any]], request["steps"])
    )
    for identity in identities:
        _stage_four_all_bindings(identity)
    probe = request.get("probe_attested_proposal")
    if probe is not None:
        _stage_four_attested(cast(JSONValue, probe))


def _stage_five_attested(value: JSONValue, anchor: dict[str, Any]) -> None:
    identity, _ = _attested_contexts(value)
    principals, keys, ambiguous = _identity_maps(identity)
    pairs = _signature_pairs(value)
    for pair, _, actor in pairs:
        signature = cast(dict[str, Any], pair["signature"])["payload"]
        if signature["principal_id"] != actor:
            _reject_later(5, "signature.principal_mismatch")
    if ambiguous:
        _reject_later(5, "identity.key_ambiguous")
    for pair, _, _ in pairs:
        signature = cast(dict[str, Any], pair["signature"])["payload"]
        if signature["principal_id"] not in principals:
            _reject_later(5, "identity.principal_unknown")
    for pair, _, _ in pairs:
        signature = cast(dict[str, Any], pair["signature"])["payload"]
        binding = keys.get(cast(str, signature["key_id"]))
        if binding is None or binding[0] != signature["principal_id"]:
            _reject_later(5, "identity.key_unbound")
    revoked_keys = set(cast(list[str], anchor["revoked_key_ids"]))
    for pair, _, _ in pairs:
        signature = cast(dict[str, Any], pair["signature"])["payload"]
        if signature["key_id"] in revoked_keys:
            _reject_later(5, "signature.key_revoked")
    body = cast(dict[str, Any], cast(dict[str, Any], value)["payload"])["promotion_input"][
        "payload"
    ]
    grant = body.get("authority_grant")
    if grant is not None:
        grant_pair = cast(dict[str, Any], grant)
        grant_id = "grant:sha256:" + _canonical_digest(cast(JSONValue, grant_pair["envelope"]))
        if grant_id in cast(list[str], anchor["revoked_grant_ids"]):
            _reject_later(5, "grant.revoked")
    for pair, kind, _ in pairs:
        signature = cast(dict[str, Any], pair["signature"])["payload"]
        roles = cast(list[str], principals[cast(str, signature["principal_id"])]["roles"])
        if _ROLE_FOR_KIND[kind] not in roles:
            _reject_later(5, "identity.role_missing")
    evidence_actors = [actor for _, kind, actor in pairs if kind == "evidence"]
    other_actors = [actor for _, kind, actor in pairs if kind != "evidence"]
    if len(other_actors) != len(set(other_actors)) or set(evidence_actors) & set(other_actors):
        _reject_later(5, "identity.role_conflict")
    constitution = cast(dict[str, Any], body["constitution"])["envelope"]["payload"]
    evidence_principals = set(evidence_actors)
    if (
        evidence_principals
        and len(evidence_principals) < constitution["minimum_independent_verifiers"]
    ):
        _reject_later(5, "identity.not_independent")


def _advance_anchor_snapshot(
    anchor: dict[str, Any], identity: dict[str, Any], authorization: dict[str, Any], now: int
) -> dict[str, Any]:
    payload = cast(dict[str, Any], identity["payload"])
    registry = dict(cast(dict[str, str], anchor["key_ownership_registry"]))
    for key_id, principal_id in _identity_key_owners(identity).items():
        registry.setdefault(key_id, principal_id)
    return {
        "trust_domain_id": anchor["trust_domain_id"],
        "current_identity_context_digest": _canonical_digest(cast(JSONValue, identity)),
        "current_authorization_context_digest": _canonical_digest(cast(JSONValue, authorization)),
        "current_snapshot_sequence": payload["snapshot_sequence"],
        "trusted_now_unix_s": now,
        "key_ownership_registry": dict(sorted(registry.items())),
        "revoked_key_ids": sorted(
            set(cast(list[str], anchor["revoked_key_ids"]))
            | set(cast(list[str], payload["revoked_key_ids"]))
        ),
        "revoked_grant_ids": sorted(
            set(cast(list[str], anchor["revoked_grant_ids"]))
            | set(cast(list[str], payload["revoked_grant_ids"]))
        ),
    }


def _stage_five_context(identity: dict[str, Any]) -> dict[str, tuple[str, dict[str, Any]]]:
    _, keys, ambiguous = _identity_maps(identity)
    if ambiguous:
        _reject_later(5, "identity.key_ambiguous")
    return keys


def _stage_five(value: JSONValue, entrypoint: M2Entrypoint, anchor: JSONValue | None) -> None:
    if entrypoint in {"verify-attested-proposal", "replay-historical"}:
        _stage_five_attested(value, cast(dict[str, Any], anchor))
        return
    request = cast(dict[str, Any], value)
    if entrypoint == "initialize-anchor":
        _stage_five_context(cast(dict[str, Any], request["initial_identity_context"]))
        return
    current = cast(dict[str, Any], request["initial_anchor"])
    _stage_five_context(cast(dict[str, Any], request["initial_identity_context"]))
    for step in cast(list[dict[str, Any]], request["steps"]):
        identity = cast(dict[str, Any], step["next_identity_context"])
        authorization = cast(dict[str, Any], step["next_authorization_context"])
        keys = _stage_five_context(identity)
        registry = cast(dict[str, str], current["key_ownership_registry"])
        for key_id, (principal_id, _) in keys.items():
            prior_owner = registry.get(key_id)
            if prior_owner is not None and prior_owner != principal_id:
                _reject_later(5, "identity.key_ambiguous")
            if key_id in cast(list[str], current["revoked_key_ids"]):
                _reject_later(5, "signature.key_revoked")
        current = _advance_anchor_snapshot(
            current, identity, authorization, cast(int, step["trusted_now_unix_s"])
        )
    probe = request.get("probe_attested_proposal")
    if probe is not None:
        _stage_five_attested(cast(JSONValue, probe), current)


def inspect_m2_stage_four(
    source: bytes | bytearray | memoryview,
    entrypoint: M2Entrypoint,
    *,
    trusted_anchor: JSONValue | None = None,
) -> M2StageFourInspection:
    """Apply M2.1 stages one through four without granting authority."""

    context = inspect_m2_stage_three(source, entrypoint, trusted_anchor=trusted_anchor)
    if isinstance(context, M2WireRejection):
        return context
    try:
        _stage_four(context.decode(), entrypoint)
    except (AttributeError, IndexError, KeyError, TypeError, ValueError, _LaterStageError) as error:
        code = error.code if isinstance(error, _LaterStageError) else "signature.digest_mismatch"
        return M2WireRejection(stage=4, code=code)
    return DigestBoundM2Input(context=context)


def inspect_m2_stage_five(
    source: bytes | bytearray | memoryview,
    entrypoint: M2Entrypoint,
    *,
    trusted_anchor: JSONValue | None = None,
) -> M2StageFiveInspection:
    """Apply M2.1 stages one through five without cryptography or authority."""

    digest_bound = inspect_m2_stage_four(source, entrypoint, trusted_anchor=trusted_anchor)
    if isinstance(digest_bound, M2WireRejection):
        return digest_bound
    try:
        _stage_five(digest_bound.decode(), entrypoint, digest_bound.decode_trusted_anchor())
    except (AttributeError, IndexError, KeyError, TypeError, ValueError, _LaterStageError) as error:
        code = error.code if isinstance(error, _LaterStageError) else "identity.context_untrusted"
        stage = error.stage if isinstance(error, _LaterStageError) else 5
        return M2WireRejection(stage=stage, code=code)
    return IdentityBoundM2Input(digest_bound=digest_bound)


_ED25519_L: Final = 2**252 + 27742317777372353535851937790883648493


def _decode_unpadded(value: str, length: int) -> bytes:
    try:
        raw = base64.b64decode(
            value + "=" * ((4 - len(value) % 4) % 4), altchars=b"-_", validate=True
        )
    except (TypeError, ValueError) as error:
        raise _LaterStageError(6, "signature.encoding_invalid") from error
    if len(raw) != length or base64.urlsafe_b64encode(raw).decode().rstrip("=") != value:
        _reject_later(6, "signature.encoding_invalid")
    return raw


def _signing_message(signature: dict[str, Any]) -> bytes:
    fields = (
        "variaxiom-signature/v1",
        signature["algorithm"],
        signature["trust_domain_id"],
        signature["principal_id"],
        signature["key_id"],
        signature["signed_kind"],
        signature["signed_digest"],
    )
    try:
        return ("\n".join(cast(tuple[str, ...], fields)) + "\n").encode("ascii")
    except UnicodeEncodeError as error:
        raise _LaterStageError(6, "signature.encoding_invalid") from error


def _stage_six_pairs(
    pairs: list[_SignaturePair], keys: dict[str, tuple[str, dict[str, Any]]]
) -> None:
    for pair, _, _ in pairs:
        signature = cast(dict[str, Any], pair["signature"])["payload"]
        binding = keys[cast(str, signature["key_id"])][1]
        if signature["algorithm"] != "Ed25519" or binding["algorithm"] != "Ed25519":
            _reject_later(6, "signature.algorithm_unsupported")

    prepared: list[tuple[bytes, bytes, bytes]] = []
    for pair, _, _ in pairs:
        signature = cast(dict[str, Any], pair["signature"])["payload"]
        binding = keys[cast(str, signature["key_id"])][1]
        public = _decode_unpadded(cast(str, binding["public_key_base64url"]), 32)
        raw_signature = _decode_unpadded(cast(str, signature["signature_base64url"]), 64)
        r_value = raw_signature[:32]
        s_value = raw_signature[32:]
        if (
            not bindings.crypto_core_ed25519_is_valid_point(public)
            or not bindings.crypto_core_ed25519_is_valid_point(r_value)
            or int.from_bytes(s_value, "little") >= _ED25519_L
        ):
            _reject_later(6, "signature.encoding_invalid")
        prepared.append((public, _signing_message(signature), raw_signature))

    for public, message, raw_signature in prepared:
        try:
            VerifyKey(public).verify(message, raw_signature)
        except Exception as error:
            raise _LaterStageError(6, "signature.invalid") from error


def _identity_bindings(identity: dict[str, Any]) -> list[dict[str, Any]]:
    payload = cast(dict[str, Any], identity["payload"])
    return [
        key
        for principal in cast(list[dict[str, Any]], payload["principals"])
        for key in cast(list[dict[str, Any]], principal["keys"])
    ]


def _stage_six_contexts(identities: list[dict[str, Any]]) -> None:
    bindings_to_check = [
        binding for identity in identities for binding in _identity_bindings(identity)
    ]
    for binding in bindings_to_check:
        if binding["algorithm"] != "Ed25519":
            _reject_later(6, "signature.algorithm_unsupported")
    for binding in bindings_to_check:
        public = _decode_unpadded(cast(str, binding["public_key_base64url"]), 32)
        if not bindings.crypto_core_ed25519_is_valid_point(public):
            _reject_later(6, "signature.encoding_invalid")


def _stage_six_attested(value: JSONValue) -> None:
    identity, _ = _attested_contexts(value)
    _, keys, _ = _identity_maps(identity)
    _stage_six_pairs(_signature_pairs(value), keys)


def _initial_anchor_snapshot(request: dict[str, Any]) -> dict[str, Any]:
    identity = cast(dict[str, Any], request["initial_identity_context"])
    authorization = cast(dict[str, Any], request["initial_authorization_context"])
    payload = cast(dict[str, Any], identity["payload"])
    return {
        "trust_domain_id": payload["trust_domain_id"],
        "current_identity_context_digest": _canonical_digest(cast(JSONValue, identity)),
        "current_authorization_context_digest": _canonical_digest(cast(JSONValue, authorization)),
        "current_snapshot_sequence": payload["snapshot_sequence"],
        "trusted_now_unix_s": request["trusted_now_unix_s"],
        "key_ownership_registry": dict(sorted(_identity_key_owners(identity).items())),
        "revoked_key_ids": list(cast(list[str], payload["revoked_key_ids"])),
        "revoked_grant_ids": list(cast(list[str], payload["revoked_grant_ids"])),
    }


def _stage_six(value: JSONValue, entrypoint: M2Entrypoint) -> dict[str, Any] | None:
    if entrypoint in {"verify-attested-proposal", "replay-historical"}:
        _stage_six_attested(value)
        return None
    request = cast(dict[str, Any], value)
    if entrypoint == "initialize-anchor":
        identity = cast(dict[str, Any], request["initial_identity_context"])
        _stage_six_contexts([identity])
        return _initial_anchor_snapshot(request)

    identities = [cast(dict[str, Any], request["initial_identity_context"])]
    identities.extend(
        cast(dict[str, Any], step["next_identity_context"])
        for step in cast(list[dict[str, Any]], request["steps"])
    )
    _stage_six_contexts(identities)
    current = cast(dict[str, Any], request["initial_anchor"])
    for step in cast(list[dict[str, Any]], request["steps"]):
        current = _advance_anchor_snapshot(
            current,
            cast(dict[str, Any], step["next_identity_context"]),
            cast(dict[str, Any], step["next_authorization_context"]),
            cast(int, step["trusted_now_unix_s"]),
        )
    probe = request.get("probe_attested_proposal")
    if probe is not None:
        _stage_six_attested(cast(JSONValue, probe))
    return current


def inspect_m2_stage_six(
    source: bytes | bytearray | memoryview,
    entrypoint: M2Entrypoint,
    *,
    trusted_anchor: JSONValue | None = None,
) -> M2StageSixInspection:
    """Apply M2.1 stages one through six without signing or authority."""

    identity_bound = inspect_m2_stage_five(source, entrypoint, trusted_anchor=trusted_anchor)
    if isinstance(identity_bound, M2WireRejection):
        return identity_bound
    try:
        resulting_anchor = _stage_six(identity_bound.decode(), entrypoint)
        anchor_data = (
            canonical_json(cast(JSONValue, resulting_anchor))
            if resulting_anchor is not None
            else None
        )
    except (AttributeError, IndexError, KeyError, TypeError, ValueError, _LaterStageError) as error:
        code = error.code if isinstance(error, _LaterStageError) else "signature.encoding_invalid"
        return M2WireRejection(stage=6, code=code)
    return SignatureVerifiedM2Input(
        identity_bound=identity_bound, resulting_anchor_data=anchor_data
    )


def _promotion_body(value: JSONValue) -> dict[str, Any]:
    root = cast(dict[str, Any], value)
    proposal = cast(dict[str, Any], root["payload"])
    promotion_input = cast(dict[str, Any], proposal["promotion_input"])
    return cast(dict[str, Any], promotion_input["payload"])


def _proposal_value(value: JSONValue, entrypoint: M2Entrypoint) -> JSONValue:
    if entrypoint in {"verify-attested-proposal", "replay-historical"}:
        return value
    if entrypoint == "advance-anchor-history":
        probe = cast(dict[str, Any], value).get("probe_attested_proposal")
        if isinstance(probe, dict):
            return cast(JSONValue, probe)
    _reject_later(2, "input.kind_mismatch")


def _stage_seven(value: JSONValue) -> None:
    body = _promotion_body(value)
    candidate_pair = cast(dict[str, Any], body["candidate"])
    candidate_digest = _canonical_digest(cast(JSONValue, candidate_pair["envelope"]))
    for evidence_pair in cast(list[dict[str, Any]], body["evidence"]):
        evidence = cast(dict[str, Any], evidence_pair["envelope"])["payload"]
        if cast(dict[str, Any], evidence)["subject_candidate_digest"] != candidate_digest:
            _reject_later(7, "evidence.subject_digest_mismatch")


def inspect_m2_stage_seven(
    source: bytes | bytearray | memoryview,
    entrypoint: M2Entrypoint,
    *,
    trusted_anchor: JSONValue | None = None,
) -> M2StageSevenInspection:
    """Bind every signed evidence envelope to the exact candidate digest."""

    signature_verified = inspect_m2_stage_six(source, entrypoint, trusted_anchor=trusted_anchor)
    if isinstance(signature_verified, M2WireRejection):
        return signature_verified
    try:
        _stage_seven(_proposal_value(signature_verified.decode(), entrypoint))
    except (AttributeError, IndexError, KeyError, TypeError, ValueError, _LaterStageError) as error:
        code = (
            error.code
            if isinstance(error, _LaterStageError)
            else "evidence.subject_digest_mismatch"
        )
        stage = error.stage if isinstance(error, _LaterStageError) else 7
        return M2WireRejection(stage=stage, code=code)
    return EvidenceBoundM2Input(signature_verified=signature_verified)


def _stage_eight(value: JSONValue) -> None:
    body = _promotion_body(value)
    candidate_pair = cast(dict[str, Any], body["candidate"])
    candidate_envelope = cast(dict[str, Any], candidate_pair["envelope"])
    candidate = cast(dict[str, Any], candidate_envelope["payload"])
    candidate_digest = _canonical_digest(cast(JSONValue, candidate_envelope))
    authorization = cast(dict[str, Any], body["authorization_context"])
    authorization_payload = cast(dict[str, Any], authorization["payload"])
    constitution_pair = cast(dict[str, Any], body["constitution"])
    constitution_envelope = cast(dict[str, Any], constitution_pair["envelope"])
    lineage_capabilities = cast(dict[str, list[str]], authorization_payload["lineage_capabilities"])
    parent_capabilities = set(lineage_capabilities.get(cast(str, candidate["parent_id"]), []))
    delta = sorted(set(cast(list[str], candidate["requested_capabilities"])) - parent_capabilities)
    grant_pair = body.get("authority_grant")
    if grant_pair is None:
        if delta:
            _reject_later(8, "grant.capability_mismatch")
        return

    grant_envelope = cast(dict[str, Any], cast(dict[str, Any], grant_pair)["envelope"])
    grant = cast(dict[str, Any], grant_envelope["payload"])
    if grant["audience"] != "variaxiom-promotion/v2":
        _reject_later(8, "grant.audience_mismatch")
    if (
        grant["trust_domain_id"] != authorization_payload["trust_domain_id"]
        or grant["capability_namespace"] != authorization_payload["capability_namespace"]
        or grant["constitution_digest"] != _canonical_digest(cast(JSONValue, constitution_envelope))
        or grant["lineage_id"] != authorization_payload["lineage_id"]
    ):
        _reject_later(8, "grant.context_mismatch")
    if grant["subject_candidate_digest"] != candidate_digest:
        _reject_later(8, "grant.subject_mismatch")
    if grant["capabilities"] != delta:
        _reject_later(8, "grant.capability_mismatch")
    not_before = cast(int, grant["not_before_unix_s"])
    expires_at = cast(int, grant["expires_at_unix_s"])
    if not_before >= expires_at:
        _reject_later(8, "grant.interval_invalid")
    identity = cast(dict[str, Any], body["identity_context"])
    now = cast(int, cast(dict[str, Any], identity["payload"])["evaluation_time_unix_s"])
    if now < not_before:
        _reject_later(8, "grant.not_yet_valid")
    if now >= expires_at:
        _reject_later(8, "grant.expired")
    if grant["delegable"] is not False:
        _reject_later(8, "grant.delegation_forbidden")


def inspect_m2_stage_eight(
    source: bytes | bytearray | memoryview,
    entrypoint: M2Entrypoint,
    *,
    trusted_anchor: JSONValue | None = None,
) -> M2StageEightInspection:
    """Validate an exact-delta, bounded, non-delegable authority grant."""

    evidence_bound = inspect_m2_stage_seven(source, entrypoint, trusted_anchor=trusted_anchor)
    if isinstance(evidence_bound, M2WireRejection):
        return evidence_bound
    try:
        _stage_eight(_proposal_value(evidence_bound.decode(), entrypoint))
    except (AttributeError, IndexError, KeyError, TypeError, ValueError, _LaterStageError) as error:
        code = error.code if isinstance(error, _LaterStageError) else "grant.context_mismatch"
        stage = error.stage if isinstance(error, _LaterStageError) else 8
        return M2WireRejection(stage=stage, code=code)
    return GrantBoundM2Input(evidence_bound=evidence_bound)


def _stage_nine(value: JSONValue) -> None:
    body = _promotion_body(value)
    authorization = cast(dict[str, Any], body["authorization_context"])
    authorization_payload = cast(dict[str, Any], authorization["payload"])
    constitution_pair = cast(dict[str, Any], body["constitution"])
    constitution_envelope = cast(dict[str, Any], constitution_pair["envelope"])
    if authorization_payload["constitution_envelope_digest"] != _canonical_digest(
        cast(JSONValue, constitution_envelope)
    ):
        _reject_later(9, "constitution.context_mismatch")
    artifact_hash = constitution_pair["artifact_hash"]
    if (
        artifact_hash != _canonical_digest(cast(JSONValue, constitution_envelope["payload"]))
        or authorization_payload["constitution_artifact_hash"] != artifact_hash
    ):
        _reject_later(9, "constitution.artifact_mismatch")


def inspect_m2_stage_nine(
    source: bytes | bytearray | memoryview,
    entrypoint: M2Entrypoint,
    *,
    trusted_anchor: JSONValue | None = None,
) -> M2StageNineInspection:
    """Bind policy to the anchored constitution envelope and artifact bytes."""

    grant_bound = inspect_m2_stage_eight(source, entrypoint, trusted_anchor=trusted_anchor)
    if isinstance(grant_bound, M2WireRejection):
        return grant_bound
    try:
        _stage_nine(_proposal_value(grant_bound.decode(), entrypoint))
    except (AttributeError, IndexError, KeyError, TypeError, ValueError, _LaterStageError) as error:
        code = (
            error.code if isinstance(error, _LaterStageError) else "constitution.context_mismatch"
        )
        stage = error.stage if isinstance(error, _LaterStageError) else 9
        return M2WireRejection(stage=stage, code=code)
    return PolicyContextBoundM2Input(grant_bound=grant_bound)


def _policy_decision(value: JSONValue) -> dict[str, JSONValue]:
    from .constitution import Constitution
    from .domain import Candidate, Evidence, EvidenceStatus, PromotionDecision
    from .promotion import PromotionContext, PromotionGate

    root = cast(dict[str, Any], value)
    proposal = cast(dict[str, Any], root["payload"])
    promotion_input = cast(dict[str, Any], proposal["promotion_input"])
    body = cast(dict[str, Any], promotion_input["payload"])
    candidate_payload = cast(
        dict[str, Any], cast(dict[str, Any], body["candidate"])["envelope"]["payload"]
    )
    candidate = Candidate(
        candidate_id=cast(str, candidate_payload["candidate_id"]),
        parent_id=cast(str, candidate_payload["parent_id"]),
        artifact_hash=cast(str, candidate_payload["artifact_hash"]),
        proposer=cast(str, candidate_payload["proposer"]),
        rollback_target=cast(str, candidate_payload["rollback_target"]),
        baseline_capabilities=frozenset(
            cast(list[str], candidate_payload["baseline_capabilities"])
        ),
        requested_capabilities=frozenset(
            cast(list[str], candidate_payload["requested_capabilities"])
        ),
        estimated_cost_micro_usd=cast(int, candidate_payload["estimated_cost_micro_usd"]),
        metadata=cast(dict[str, JSONValue], candidate_payload["metadata"]),
    )
    evidence: list[Evidence] = []
    for evidence_pair in cast(list[dict[str, Any]], body["evidence"]):
        item = cast(dict[str, Any], evidence_pair["envelope"])["payload"]
        payload = cast(dict[str, Any], item)
        evidence.append(
            Evidence(
                evidence_id=cast(str, payload["evidence_id"]),
                subject_id=candidate.candidate_id,
                artifact_hash=cast(str, payload["artifact_hash"]),
                check=cast(str, payload["check"]),
                status=cast(EvidenceStatus, payload["status"]),
                verifier=cast(str, payload["verifier"]),
                independent=cast(bool, payload["independent"]),
                details=cast(dict[str, JSONValue], payload["details"]),
            )
        )
    constitution_payload = cast(
        dict[str, Any], cast(dict[str, Any], body["constitution"])["envelope"]["payload"]
    )
    constitution = Constitution(
        version=cast(str, constitution_payload["version"]),
        mandatory_checks=tuple(cast(list[str], constitution_payload["mandatory_checks"])),
        minimum_independent_verifiers=cast(
            int, constitution_payload["minimum_independent_verifiers"]
        ),
        max_candidate_cost_micro_usd=cast(
            int, constitution_payload["max_candidate_cost_micro_usd"]
        ),
        require_known_parent=cast(bool, constitution_payload["require_known_parent"]),
        require_rollback_target=cast(bool, constitution_payload["require_rollback_target"]),
        forbid_self_verification=cast(bool, constitution_payload["forbid_self_verification"]),
        forbid_implicit_authority_escalation=cast(
            bool, constitution_payload["forbid_implicit_authority_escalation"]
        ),
        reject_any_failed_evidence=cast(bool, constitution_payload["reject_any_failed_evidence"]),
    )
    authorization = cast(dict[str, Any], body["authorization_context"])
    authorization_payload = cast(dict[str, Any], authorization["payload"])
    grant_pair = body.get("authority_grant")
    authority_grants: dict[str, frozenset[str]] = {}
    grant_id: str | None = None
    if grant_pair is not None:
        grant_envelope = cast(dict[str, Any], cast(dict[str, Any], grant_pair)["envelope"])
        grant_id = "grant:sha256:" + _canonical_digest(cast(JSONValue, grant_envelope))
        authority_grants[grant_id] = frozenset(
            cast(list[str], cast(dict[str, Any], grant_envelope["payload"])["capabilities"])
        )
    context = PromotionContext(
        known_lineage_ids=frozenset(cast(list[str], authorization_payload["known_lineage_ids"])),
        known_artifact_hashes=frozenset(
            cast(list[str], authorization_payload["verified_artifact_hashes"])
        ),
        authority_grants=authority_grants,
        lineage_capabilities={
            lineage_id: frozenset(capabilities)
            for lineage_id, capabilities in cast(
                dict[str, list[str]], authorization_payload["lineage_capabilities"]
            ).items()
        },
    )
    raw = PromotionGate(constitution).decide(
        candidate, evidence, context, authority_grant_id=grant_id
    )
    decision = PromotionDecision(
        candidate_id=raw.candidate_id,
        status=raw.status,
        reasons=raw.reasons,
        evidence_ids=raw.evidence_ids,
        input_digest=_canonical_digest(cast(JSONValue, promotion_input)),
        constitution_version=raw.constitution_version,
        gate_version=raw.gate_version,
    )
    return decision.envelope()


def inspect_m2_stage_ten(
    source: bytes | bytearray | memoryview,
    entrypoint: M2Entrypoint,
    *,
    trusted_anchor: JSONValue | None = None,
) -> M2StageTenInspection:
    """Return the pure deterministic M1.1 policy decision for a bound M2 input."""

    policy_context = inspect_m2_stage_nine(source, entrypoint, trusted_anchor=trusted_anchor)
    if isinstance(policy_context, M2WireRejection):
        return policy_context
    try:
        decision_data = canonical_json(
            _policy_decision(_proposal_value(policy_context.decode(), entrypoint))
        )
    except (AttributeError, IndexError, KeyError, TypeError, ValueError):
        return M2WireRejection(stage=2, code="input.schema_invalid")
    return PolicyEvaluatedM2Input(
        policy_context=policy_context,
        decision_data=decision_data,
    )


def inspect_m2_wire(source: bytes | bytearray | memoryview) -> M2WireInspection:
    """Apply only the normative M2.1 stage-one wire checks.

    Success does not authenticate the payload and grants no authority. Later
    verifier stages must consume ``CanonicalM2Wire.data`` rather than a mutable
    object supplied by the caller.
    """

    source_size = source.nbytes if isinstance(source, memoryview) else len(source)
    if source_size > MAX_M2_WIRE_BYTES:
        return M2WireRejection(stage=1, code="input.limit_exceeded")
    data = bytes(source)

    try:
        value: JSONValue = strict_json_loads(data)
    except (TypeError, ValueError) as error:
        message = str(error)
        if "duplicate JSON object key" in message:
            code = "input.duplicate_member"
        elif "nesting exceeds" in message:
            code = "input.limit_exceeded"
        else:
            code = "input.encoding_invalid"
        return M2WireRejection(stage=1, code=code)

    if canonical_json(value) != data:
        return M2WireRejection(stage=1, code="input.encoding_invalid")

    return CanonicalM2Wire(data=data, sha256=sha256_bytes(data))
