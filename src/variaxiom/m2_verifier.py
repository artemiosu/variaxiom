"""Disabled M2.1 verification primitives.

This module only inspects bounded canonical wire bytes. It has no signing,
ambient trust, policy, activation, or lineage-append capability.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Final, Literal, NoReturn, cast

from .canonical import JSONValue, canonical_json, sha256_bytes, strict_json_loads

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
