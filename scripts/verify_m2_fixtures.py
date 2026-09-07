#!/usr/bin/env python3
"""Execute every frozen M2.1 case through the normative stage order.

This is a fixture oracle, not a production verifier. It deliberately has no signing API,
no lineage append capability, and no ambient source of trust or time.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from nacl import bindings
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey
from referencing import Registry, Resource
from regenerate_m2_fixtures import canonical_bytes, digest, key_id_from_public, policy_decision

from variaxiom.canonical import canonical_json, strict_json_loads

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures/conformance/v2"
MAX_SAFE = 9_007_199_254_740_991
L = 2**252 + 27742317777372353535851937790883648493
ROLE_FOR_KIND = {
    "candidate": "candidate-proposer",
    "evidence": "evidence-verifier",
    "authority-grant": "authority-issuer",
    "promotion-decision": "promotion-selector",
}

REQUIRED_CASE_IDS = {
    "authorization-domain-reanchored-confused-deputy",
    "initialize-anchor-genesis",
    "initialize-anchor-domain-mismatch",
    "insufficient-independent-verifiers",
    "nested-candidate-envelope-version-unsupported",
    "nested-candidate-kind-mismatch",
    "precedence-digest-before-key-id",
    "precedence-key-id-before-kind",
    "precedence-evidence-digest-before-candidate-kind",
    "precedence-stage-four-before-five",
    "precedence-principal-before-ambiguous",
    "precedence-ambiguous-before-unknown",
    "precedence-unknown-before-unbound",
    "precedence-unbound-before-revoked-key",
    "precedence-revoked-key-before-grant",
    "precedence-revoked-grant-before-role",
    "precedence-role-before-conflict",
    "precedence-conflict-before-independence",
    "precedence-encoding-before-equation",
    "precedence-context-before-subject",
    "precedence-subject-before-capability",
    "precedence-capability-before-interval",
    "precedence-interval-before-early",
    "precedence-early-before-delegation",
    "precedence-expired-before-delegation",
    "public-key-wrong-length",
    "revoked-grant-removal",
    "revoked-key-removal",
    "selector-issuer-role-conflict",
    "selector-proposer-role-conflict",
    "selector-verifier-role-conflict",
    "signature-wrong-length",
    "signing-message-extra-final-lf",
    "signing-message-missing-final-lf",
    "standard-base64-signature-rejected",
    "unsupported-key-binding-algorithm",
}

Result = tuple[str, int | None, str | None, str, bool]


class Rejected(Exception):
    def __init__(self, stage: int, code: str) -> None:
        super().__init__(code)
        self.stage = stage
        self.code = code


def reject(stage: int, code: str) -> None:
    raise Rejected(stage, code)


def decode_unpadded(value: str, length: int) -> bytes:
    if not isinstance(value, str) or len(value) not in {43, 86} or "=" in value:
        reject(6, "signature.encoding_invalid")
    try:
        raw = base64.b64decode(
            value + "=" * ((4 - len(value) % 4) % 4), altchars=b"-_", validate=True
        )
    except (ValueError, TypeError):
        reject(6, "signature.encoding_invalid")
    canonical = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    if len(raw) != length or canonical != value:
        reject(6, "signature.encoding_invalid")
    return raw


def signing_message(payload: dict[str, Any]) -> bytes:
    try:
        return "\n".join(
            [
                "variaxiom-signature/v1",
                payload["algorithm"],
                payload["trust_domain_id"],
                payload["principal_id"],
                payload["key_id"],
                payload["signed_kind"],
                payload["signed_digest"],
                "",
            ]
        ).encode("ascii")
    except (KeyError, UnicodeEncodeError):
        reject(2, "input.schema_invalid")


def load_schemas() -> tuple[dict[str, dict[str, Any]], Registry[Any]]:
    schemas: dict[str, dict[str, Any]] = {}
    resources: list[tuple[str, Resource[Any]]] = []
    for path in sorted((ROOT / "schemas").rglob("*.json")):
        value = json.loads(path.read_text("utf-8"))
        schemas[str(path.relative_to(ROOT / "schemas"))] = value
        if "$id" in value:
            resources.append((value["$id"], Resource.from_contents(value)))
    return schemas, Registry().with_resources(resources)


SCHEMAS, REGISTRY = load_schemas()


def schema_errors(value: object, schema_name: str) -> list[Any]:
    validator = Draft202012Validator(SCHEMAS[schema_name], registry=REGISTRY)
    return list(validator.iter_errors(value))


def at_path(value: object, path: tuple[str | int, ...]) -> object | None:
    current = value
    for part in path:
        if isinstance(part, str) and isinstance(current, dict):
            current = current.get(part)
        elif isinstance(part, int) and isinstance(current, list) and part < len(current):
            current = current[part]
        else:
            return None
    return current


def version_kind_preflight(value: dict[str, Any]) -> None:
    """Check every known nested version and envelope kind before JSON Schema."""
    envelope_paths: list[tuple[tuple[str | int, ...], str]] = [
        ((), "attested-proposal"),
        (("payload", "promotion_input"), "promotion-input"),
        (("payload", "promotion_input", "payload", "candidate", "envelope"), "candidate"),
        (("payload", "promotion_input", "payload", "candidate", "signature"), "detached-signature"),
        (("payload", "promotion_input", "payload", "constitution", "envelope"), "constitution"),
        (("payload", "promotion_input", "payload", "identity_context"), "identity-context"),
        (
            ("payload", "promotion_input", "payload", "authorization_context"),
            "authorization-context",
        ),
        (("payload", "decision"), "promotion-decision"),
        (("payload", "selector_signature"), "detached-signature"),
    ]
    body = at_path(value, ("payload", "promotion_input", "payload"))
    if isinstance(body, dict):
        for index, _ in enumerate(body.get("evidence", [])):
            envelope_paths.extend(
                [
                    (
                        ("payload", "promotion_input", "payload", "evidence", index, "envelope"),
                        "evidence",
                    ),
                    (
                        ("payload", "promotion_input", "payload", "evidence", index, "signature"),
                        "detached-signature",
                    ),
                ]
            )
        if "authority_grant" in body:
            envelope_paths.extend(
                [
                    (
                        ("payload", "promotion_input", "payload", "authority_grant", "envelope"),
                        "authority-grant",
                    ),
                    (
                        ("payload", "promotion_input", "payload", "authority_grant", "signature"),
                        "detached-signature",
                    ),
                ]
            )
    version_fields: list[tuple[tuple[str | int, ...], str, str]] = []
    for path, _ in envelope_paths:
        version_fields.append((path, "envelope_version", "variaxiom-envelope/v1"))
    for path, expected_kind in envelope_paths:
        if expected_kind == "detached-signature":
            version_fields.append(
                ((*path, "payload"), "signature_version", "detached-signature/v1")
            )
    version_fields.extend(
        [
            (("payload",), "proposal_version", "attested-proposal/v1"),
            (("payload", "promotion_input", "payload"), "protocol_version", "promotion-input/v2"),
            (
                ("payload", "promotion_input", "payload", "candidate", "envelope", "payload"),
                "candidate_version",
                "candidate/v2",
            ),
            (
                ("payload", "promotion_input", "payload", "constitution", "envelope", "payload"),
                "version",
                "constitution/v1",
            ),
            (
                ("payload", "promotion_input", "payload", "identity_context", "payload"),
                "identity_context_version",
                "identity-context/v1",
            ),
            (
                ("payload", "promotion_input", "payload", "authorization_context", "payload"),
                "authorization_context_version",
                "authorization-context/v1",
            ),
        ]
    )
    if isinstance(body, dict):
        for index, _ in enumerate(body.get("evidence", [])):
            version_fields.append(
                (
                    (
                        "payload",
                        "promotion_input",
                        "payload",
                        "evidence",
                        index,
                        "envelope",
                        "payload",
                    ),
                    "evidence_version",
                    "evidence/v2",
                )
            )
        if "authority_grant" in body:
            version_fields.append(
                (
                    (
                        "payload",
                        "promotion_input",
                        "payload",
                        "authority_grant",
                        "envelope",
                        "payload",
                    ),
                    "grant_version",
                    "authority-grant/v1",
                )
            )
        identity = body.get("identity_context", {}).get("payload", {})
        if isinstance(identity, dict):
            for p_index, principal in enumerate(identity.get("principals", [])):
                version_fields.append(
                    (
                        (
                            "payload",
                            "promotion_input",
                            "payload",
                            "identity_context",
                            "payload",
                            "principals",
                            p_index,
                        ),
                        "principal_version",
                        "principal/v1",
                    )
                )
                if isinstance(principal, dict):
                    for k_index, _ in enumerate(principal.get("keys", [])):
                        version_fields.append(
                            (
                                (
                                    "payload",
                                    "promotion_input",
                                    "payload",
                                    "identity_context",
                                    "payload",
                                    "principals",
                                    p_index,
                                    "keys",
                                    k_index,
                                ),
                                "key_binding_version",
                                "key-binding/v1",
                            )
                        )
    for path, _ in sorted(envelope_paths, key=lambda item: str(item[0])):
        node = at_path(value, path)
        if (
            isinstance(node, dict)
            and "envelope_version" in node
            and node["envelope_version"] != "variaxiom-envelope/v1"
        ):
            reject(2, "input.version_unsupported")
    for path, field, expected in sorted(version_fields, key=lambda item: (str(item[0]), item[1])):
        node = at_path(value, path)
        if isinstance(node, dict) and field in node and node[field] != expected:
            reject(2, "input.version_unsupported")
    for path, expected_kind in sorted(envelope_paths, key=lambda item: str(item[0])):
        node = at_path(value, path)
        if isinstance(node, dict) and "kind" in node and node["kind"] != expected_kind:
            reject(2, "input.kind_mismatch")


def walk(value: object) -> list[object]:
    values = [value]
    if isinstance(value, dict):
        for key, item in value.items():
            values.extend(walk(key))
            values.extend(walk(item))
    elif isinstance(value, list):
        for item in value:
            values.extend(walk(item))
    return values


def semantic_stage_two(value: dict[str, Any]) -> None:
    def protocol_strings(item: object, excluded: bool = False) -> list[str]:
        if isinstance(item, str):
            return [] if excluded else [item]
        if isinstance(item, list):
            return [value for child in item for value in protocol_strings(child, excluded)]
        if isinstance(item, dict):
            return [
                value
                for key, child in item.items()
                for value in protocol_strings(child, excluded or key in {"metadata", "details"})
            ]
        return []

    for item in protocol_strings(value):
        if len(item.encode("utf-8")) > 256:
            reject(2, "input.limit_exceeded")
        if any(ord(char) < 32 or ord(char) == 127 for char in item):
            reject(2, "input.schema_invalid")
    try:
        body = value["payload"]["promotion_input"]["payload"]
        candidate = body["candidate"]["envelope"]["payload"]
        identity = body["identity_context"]["payload"]
        authorization = body["authorization_context"]["payload"]
    except (KeyError, TypeError):
        reject(2, "input.schema_invalid")
    token_paths = [
        candidate["candidate_id"],
        candidate["parent_id"],
        candidate["proposer"],
        candidate["rollback_target"],
        identity["trust_domain_id"],
        authorization["capability_namespace"],
        authorization["lineage_id"],
    ]
    for token in token_paths:
        if "," in token:
            reject(2, "input.schema_invalid")
    if (
        len(identity["principals"]) > 64
        or any(len(item["keys"]) > 8 or len(item["roles"]) > 8 for item in identity["principals"])
        or len(identity["revoked_key_ids"]) > 4096
        or len(identity["revoked_grant_ids"]) > 4096
        or len(authorization["known_lineage_ids"]) > 4096
        or len(authorization["lineage_capabilities"]) > 4096
        or len(authorization["verified_artifact_hashes"]) > 4096
        or len(body["evidence"]) > 256
    ):
        reject(2, "input.limit_exceeded")
    capability_groups = [
        candidate["baseline_capabilities"],
        candidate["requested_capabilities"],
        *authorization["lineage_capabilities"].values(),
    ]
    if isinstance(body.get("authority_grant"), dict):
        capability_groups.append(body["authority_grant"]["envelope"]["payload"]["capabilities"])
    if any(len(group) > 128 for group in capability_groups):
        reject(2, "input.limit_exceeded")
    signature_count = 1 + len(body["evidence"]) + (1 if "authority_grant" in body else 0)
    if signature_count > 258:
        reject(2, "input.limit_exceeded")
    sorted_collections: list[list[str]] = [
        candidate["baseline_capabilities"],
        candidate["requested_capabilities"],
        identity["revoked_key_ids"],
        identity["revoked_grant_ids"],
        authorization["known_lineage_ids"],
        authorization["verified_artifact_hashes"],
    ]
    sorted_collections.extend(item["roles"] for item in identity["principals"])
    sorted_collections.extend(
        [key["key_id"] for key in item["keys"]] for item in identity["principals"]
    )
    sorted_collections.extend(authorization["lineage_capabilities"].values())
    sorted_collections.extend(
        item["envelope"]["payload"]["capabilities"]
        for item in [body.get("authority_grant")]
        if isinstance(item, dict)
    )
    for collection in sorted_collections:
        if collection != sorted(set(collection)):
            reject(2, "input.schema_invalid")
    if [item["principal_id"] for item in identity["principals"]] != sorted(
        item["principal_id"] for item in identity["principals"]
    ):
        reject(2, "input.schema_invalid")
    evidence_ids = [item["envelope"]["payload"]["evidence_id"] for item in body["evidence"]]
    if evidence_ids != sorted(evidence_ids):
        reject(2, "input.schema_invalid")
    if authorization["known_lineage_ids"] != sorted(authorization["lineage_capabilities"]):
        reject(2, "input.schema_invalid")
    if len(canonical_bytes(candidate["metadata"])) > 65_536:
        reject(2, "input.limit_exceeded")
    for item in body["evidence"]:
        if len(canonical_bytes(item["envelope"]["payload"]["details"])) > 65_536:
            reject(2, "input.limit_exceeded")


def all_pairs(
    attested: dict[str, Any], include_selector: bool = False
) -> list[tuple[dict[str, Any], str, str]]:
    body = attested["payload"]["promotion_input"]["payload"]
    candidate = body["candidate"]
    pairs = [(candidate, "candidate", candidate["envelope"]["payload"]["proposer"])]
    pairs.extend(
        (item, "evidence", item["envelope"]["payload"]["verifier"]) for item in body["evidence"]
    )
    grant = body.get("authority_grant")
    if isinstance(grant, dict):
        pairs.append(
            (grant, "authority-grant", grant["envelope"]["payload"]["issuer_principal_id"])
        )
    if include_selector:
        pairs.append(
            (
                {
                    "envelope": attested["payload"]["decision"],
                    "signature": attested["payload"]["selector_signature"],
                },
                "promotion-decision",
                attested["payload"]["selector_signature"]["payload"]["principal_id"],
            )
        )
    return pairs


def identity_maps(
    attested: dict[str, Any],
) -> tuple[dict[str, dict[str, Any]], dict[str, tuple[str, dict[str, Any]]], bool]:
    identity = attested["payload"]["promotion_input"]["payload"]["identity_context"]["payload"]
    principals: dict[str, dict[str, Any]] = {}
    keys: dict[str, tuple[str, dict[str, Any]]] = {}
    public_keys: set[str] = set()
    ambiguous = False
    for principal in identity["principals"]:
        principal_id = principal["principal_id"]
        if principal_id in principals:
            ambiguous = True
        principals[principal_id] = principal
        for key in principal["keys"]:
            if key["key_id"] in keys or key["public_key_base64url"] in public_keys:
                ambiguous = True
            keys[key["key_id"]] = (principal_id, key)
            public_keys.add(key["public_key_base64url"])
    return principals, keys, ambiguous


def stage_four(
    pairs: list[tuple[dict[str, Any], str, str]], keys: dict[str, tuple[str, dict[str, Any]]]
) -> None:
    for pair, _, _ in pairs:
        signature = pair["signature"]["payload"]
        if signature["signed_digest"] != digest(pair["envelope"]):
            reject(4, "signature.digest_mismatch")
    for pair, _kind, _ in pairs:
        signature = pair["signature"]["payload"]
        binding = keys.get(signature["key_id"])
        if binding is not None:
            try:
                computed = key_id_from_public(binding[1]["public_key_base64url"])
            except Exception:
                reject(6, "signature.encoding_invalid")
            if computed != binding[1]["key_id"]:
                reject(4, "signature.key_id_mismatch")
    for pair, kind, _ in pairs:
        signature = pair["signature"]["payload"]
        if signature["signed_kind"] != kind:
            reject(4, "signature.kind_mismatch")


def stage_five(
    attested: dict[str, Any],
    anchor: dict[str, Any],
    pairs: list[tuple[dict[str, Any], str, str]],
    principals: dict[str, dict[str, Any]],
    keys: dict[str, tuple[str, dict[str, Any]]],
    ambiguous: bool,
    *,
    role_pairs: list[tuple[dict[str, Any], str, str]] | None = None,
) -> None:
    for pair, _, actor in pairs:
        sig = pair["signature"]["payload"]
        if sig["principal_id"] != actor:
            reject(5, "signature.principal_mismatch")
    if ambiguous:
        reject(5, "identity.key_ambiguous")
    for pair, _, _ in pairs:
        sig = pair["signature"]["payload"]
        if sig["principal_id"] not in principals:
            reject(5, "identity.principal_unknown")
    for pair, _, _ in pairs:
        sig = pair["signature"]["payload"]
        binding = keys.get(sig["key_id"])
        if binding is None or binding[0] != sig["principal_id"]:
            reject(5, "identity.key_unbound")
    for pair, _, _ in pairs:
        sig = pair["signature"]["payload"]
        if sig["key_id"] in anchor["revoked_key_ids"]:
            reject(5, "signature.key_revoked")
    body = attested["payload"]["promotion_input"]["payload"]
    grant = body.get("authority_grant")
    if isinstance(grant, dict):
        grant_id = "grant:sha256:" + digest(grant["envelope"])
        if grant_id in anchor["revoked_grant_ids"]:
            reject(5, "grant.revoked")
    for pair, kind, _ in pairs:
        sig = pair["signature"]["payload"]
        if ROLE_FOR_KIND[kind] not in principals[sig["principal_id"]]["roles"]:
            reject(5, "identity.role_missing")
    actors_to_compare = role_pairs or pairs
    evidence_actors = [actor for (_, kind, actor) in actors_to_compare if kind == "evidence"]
    other_actors = [actor for (_, kind, actor) in actors_to_compare if kind != "evidence"]
    if len(other_actors) != len(set(other_actors)) or set(evidence_actors) & set(other_actors):
        reject(5, "identity.role_conflict")
    constitution = body["constitution"]["envelope"]["payload"]
    evidence_principals = {item[2] for item in actors_to_compare if item[1] == "evidence"}
    if (
        evidence_principals
        and len(evidence_principals) < constitution["minimum_independent_verifiers"]
    ):
        reject(5, "identity.not_independent")


def stage_six(
    pairs: list[tuple[dict[str, Any], str, str]],
    keys: dict[str, tuple[str, dict[str, Any]]],
) -> None:
    prepared: list[tuple[bytes, bytes, bytes]] = []
    for pair, _, _ in pairs:
        sig = pair["signature"]["payload"]
        binding = keys[sig["key_id"]][1]
        if sig["algorithm"] != "Ed25519" or binding["algorithm"] != "Ed25519":
            reject(6, "signature.algorithm_unsupported")
    for pair, _, _ in pairs:
        sig = pair["signature"]["payload"]
        binding = keys[sig["key_id"]][1]
        public = decode_unpadded(binding["public_key_base64url"], 32)
        raw_signature = decode_unpadded(sig["signature_base64url"], 64)
        if not bindings.crypto_core_ed25519_is_valid_point(public):
            reject(6, "signature.encoding_invalid")
        r_value, s_value = raw_signature[:32], raw_signature[32:]
        if (
            not bindings.crypto_core_ed25519_is_valid_point(r_value)
            or int.from_bytes(s_value, "little") >= L
        ):
            reject(6, "signature.encoding_invalid")
        prepared.append((public, signing_message(sig), raw_signature))
    for public, message, raw_signature in prepared:
        try:
            VerifyKey(public).verify(message, raw_signature)
        except BadSignatureError:
            reject(6, "signature.invalid")


def classify_signature_vector(vector: dict[str, Any]) -> str | None:
    """Independently derive every field in a published signature vector."""
    try:
        if vector["target_digest"] != digest(vector["target_envelope"]):
            reject(4, "signature.digest_mismatch")
        if vector["signed_digest"] != vector["target_digest"]:
            reject(4, "signature.digest_mismatch")
        try:
            public = decode_unpadded(vector["public_key_base64url"], 32)
            computed_key_id = (
                "key:sha256:" + hashlib.sha256(b"variaxiom-key/v1\0Ed25519\0" + public).hexdigest()
            )
        except Rejected:
            reject(6, "signature.encoding_invalid")
        if vector["key_id"] != computed_key_id:
            reject(4, "signature.key_id_mismatch")
        if vector["signed_kind"] != vector["target_envelope"]["kind"]:
            reject(4, "signature.kind_mismatch")
        if vector["algorithm"] != "Ed25519":
            reject(6, "signature.algorithm_unsupported")
        raw_signature = decode_unpadded(vector["signature_base64url"], 64)
        r_value, s_value = raw_signature[:32], raw_signature[32:]
        if (
            not bindings.crypto_core_ed25519_is_valid_point(public)
            or not bindings.crypto_core_ed25519_is_valid_point(r_value)
            or int.from_bytes(s_value, "little") >= L
        ):
            reject(6, "signature.encoding_invalid")
        payload = {
            "algorithm": vector["algorithm"],
            "trust_domain_id": vector["trust_domain_id"],
            "principal_id": vector["principal_id"],
            "key_id": vector["key_id"],
            "signed_kind": vector["signed_kind"],
            "signed_digest": vector["signed_digest"],
        }
        try:
            supplied_message = bytes.fromhex(vector["message_hex"])
        except ValueError:
            reject(6, "signature.encoding_invalid")
        if supplied_message != signing_message(payload):
            reject(6, "signature.invalid")
        try:
            VerifyKey(public).verify(supplied_message, raw_signature)
        except BadSignatureError:
            reject(6, "signature.invalid")
        return None
    except (KeyError, TypeError):
        return "input.schema_invalid"
    except Rejected as error:
        return error.code


def evaluate_anchor_history(case: dict[str, Any], history: dict[str, Any]) -> Result:
    try:
        anchor = history["initial_anchor"]
        previous_identity = history["initial_identity_context"]
        authorization = history["initial_authorization_context"]
        if (
            digest(previous_identity) != anchor["current_identity_context_digest"]
            or digest(authorization) != anchor["current_authorization_context_digest"]
        ):
            reject(3, "identity.context_untrusted")
        for step in history["steps"]:
            identity = step["next_identity_context"]
            next_authorization = step["next_authorization_context"]
            now = step["trusted_now_unix_s"]
            payload = identity["payload"]
            if (
                now < anchor["trusted_now_unix_s"]
                or payload["evaluation_time_unix_s"] < anchor["trusted_now_unix_s"]
            ):
                reject(3, "identity.context_stale")
            if (
                payload["trust_domain_id"] != anchor["trust_domain_id"]
                or payload["snapshot_sequence"] != anchor["current_snapshot_sequence"] + 1
                or payload["previous_snapshot_digest"] != digest(previous_identity)
                or payload["evaluation_time_unix_s"] != now
                or next_authorization["payload"]["trust_domain_id"] != anchor["trust_domain_id"]
                or not set(anchor["revoked_key_ids"]).issubset(payload["revoked_key_ids"])
                or not set(anchor["revoked_grant_ids"]).issubset(payload["revoked_grant_ids"])
            ):
                reject(3, "identity.context_untrusted")
            seen_ids: set[str] = set()
            seen_public: set[str] = set()
            for descriptor in payload["principals"]:
                for binding in descriptor["keys"]:
                    key_id = binding["key_id"]
                    public = binding["public_key_base64url"]
                    if key_id in seen_ids or public in seen_public:
                        reject(5, "identity.key_ambiguous")
                    seen_ids.add(key_id)
                    seen_public.add(public)
                    prior_owner = anchor["key_ownership_registry"].get(key_id)
                    if prior_owner is not None and prior_owner != descriptor["principal_id"]:
                        reject(5, "identity.key_ambiguous")
                    if key_id in anchor["revoked_key_ids"]:
                        reject(5, "signature.key_revoked")
            anchor = {
                "trust_domain_id": anchor["trust_domain_id"],
                "current_identity_context_digest": digest(identity),
                "current_authorization_context_digest": digest(next_authorization),
                "current_snapshot_sequence": payload["snapshot_sequence"],
                "trusted_now_unix_s": now,
                "key_ownership_registry": dict(anchor["key_ownership_registry"]),
                "revoked_key_ids": sorted(
                    set(anchor["revoked_key_ids"]) | set(payload["revoked_key_ids"])
                ),
                "revoked_grant_ids": sorted(
                    set(anchor["revoked_grant_ids"]) | set(payload["revoked_grant_ids"])
                ),
            }
            for descriptor in payload["principals"]:
                for binding in descriptor["keys"]:
                    anchor["key_ownership_registry"].setdefault(
                        binding["key_id"], descriptor["principal_id"]
                    )
            anchor["key_ownership_registry"] = dict(
                sorted(anchor["key_ownership_registry"].items())
            )
            previous_identity = identity
            authorization = next_authorization
        probe = history.get("probe_attested_proposal")
        if probe is not None:
            probe_wire = canonical_bytes(probe)
            probe_case = {
                "entrypoint": "verify-attested-proposal",
                "input_base64url": base64.urlsafe_b64encode(probe_wire).decode().rstrip("="),
                "input_sha256": hashlib.sha256(probe_wire).hexdigest(),
                "trusted_anchor": anchor,
            }
            return evaluate_case(probe_case)
        return "verified", None, None, "not-reached", False
    except (KeyError, TypeError):
        return "rejected", 2, "input.schema_invalid", "not-reached", False
    except Rejected as error:
        return "rejected", error.stage, error.code, "not-reached", False


def evaluate_initialize_anchor(value: dict[str, Any]) -> Result:
    try:
        identity = value["initial_identity_context"]
        authorization = value["initial_authorization_context"]
        identity_payload = identity["payload"]
        authorization_payload = authorization["payload"]
        for item, _expected_kind, version_field, expected_version in (
            (identity, "identity-context", "identity_context_version", "identity-context/v1"),
            (
                authorization,
                "authorization-context",
                "authorization_context_version",
                "authorization-context/v1",
            ),
        ):
            if (
                item.get("envelope_version") != "variaxiom-envelope/v1"
                or item["payload"].get(version_field) != expected_version
            ):
                reject(2, "input.version_unsupported")
        for item, expected_kind in (
            (identity, "identity-context"),
            (authorization, "authorization-context"),
        ):
            if item.get("kind") != expected_kind:
                reject(2, "input.kind_mismatch")
        if schema_errors(value, "v2/anchor-initialization.schema.json"):
            reject(2, "input.schema_invalid")
        if (
            identity_payload["snapshot_sequence"] != 0
            or identity_payload["previous_snapshot_digest"] is not None
            or identity_payload["evaluation_time_unix_s"] != value["trusted_now_unix_s"]
            or authorization_payload["trust_domain_id"] != identity_payload["trust_domain_id"]
        ):
            reject(3, "identity.context_untrusted")
        if len(identity_payload["principals"]) > 64:
            reject(2, "input.limit_exceeded")
        seen_principals: set[str] = set()
        seen_keys: set[str] = set()
        seen_public: set[str] = set()
        for principal in identity_payload["principals"]:
            if principal["principal_id"] in seen_principals:
                reject(5, "identity.key_ambiguous")
            seen_principals.add(principal["principal_id"])
            if len(principal["keys"]) > 8 or len(principal["roles"]) > 8:
                reject(2, "input.limit_exceeded")
            for binding in principal["keys"]:
                if binding["key_id"] in seen_keys or binding["public_key_base64url"] in seen_public:
                    reject(5, "identity.key_ambiguous")
                seen_keys.add(binding["key_id"])
                seen_public.add(binding["public_key_base64url"])
        return "verified", None, None, "not-reached", False
    except (KeyError, TypeError):
        return "rejected", 2, "input.schema_invalid", "not-reached", False
    except Rejected as error:
        return "rejected", error.stage, error.code, "not-reached", False


def evaluate_case(case: dict[str, Any]) -> Result:
    raw = base64.urlsafe_b64decode(
        case["input_base64url"] + "=" * ((4 - len(case["input_base64url"]) % 4) % 4)
    )
    if hashlib.sha256(raw).hexdigest() != case["input_sha256"]:
        return "rejected", 1, "input.encoding_invalid", "not-reached", False
    if len(raw) > 1_048_576:
        return "rejected", 1, "input.limit_exceeded", "not-reached", False
    try:
        value = strict_json_loads(raw)
    except ValueError as error:
        message = str(error)
        code = (
            "input.duplicate_member"
            if "duplicate JSON object key" in message
            else "input.encoding_invalid"
        )
        if "nesting exceeds" in message:
            code = "input.limit_exceeded"
        return "rejected", 1, code, "not-reached", False
    if canonical_json(value) != raw:
        return "rejected", 1, "input.encoding_invalid", "not-reached", False
    if not isinstance(value, dict):
        return "rejected", 2, "input.schema_invalid", "not-reached", False
    if case["entrypoint"] == "advance-anchor-history":
        return evaluate_anchor_history(case, value)
    if case["entrypoint"] == "initialize-anchor":
        return evaluate_initialize_anchor(value)
    try:
        version_kind_preflight(value)
        if schema_errors(value, "v2/envelope.schema.json"):
            reject(2, "input.schema_invalid")
        semantic_stage_two(value)
        anchor = case["trusted_anchor"]
        if (
            len(anchor["key_ownership_registry"]) > 4096
            or len(anchor["revoked_key_ids"]) > 4096
            or len(anchor["revoked_grant_ids"]) > 4096
        ):
            reject(2, "input.limit_exceeded")
        body = value["payload"]["promotion_input"]["payload"]
        identity = body["identity_context"]
        authorization = body["authorization_context"]
        identity_payload = identity["payload"]
        if identity_payload["snapshot_sequence"] < anchor["current_snapshot_sequence"]:
            reject(3, "identity.context_stale")
        if (
            identity_payload["trust_domain_id"] != anchor["trust_domain_id"]
            or digest(identity) != anchor["current_identity_context_digest"]
            or identity_payload["snapshot_sequence"] != anchor["current_snapshot_sequence"]
            or identity_payload["evaluation_time_unix_s"] != anchor["trusted_now_unix_s"]
        ):
            reject(3, "identity.context_untrusted")
        if (
            authorization["payload"]["trust_domain_id"] != anchor["trust_domain_id"]
            or digest(authorization) != anchor["current_authorization_context_digest"]
        ):
            reject(3, "authorization.context_untrusted")
        for pair, _, _ in all_pairs(value):
            if pair["signature"]["payload"]["trust_domain_id"] != anchor["trust_domain_id"]:
                reject(3, "signature.domain_mismatch")
        principals, keys, ambiguous = identity_maps(value)
        pairs = all_pairs(value)
        stage_four(pairs, keys)
        stage_five(value, anchor, pairs, principals, keys, ambiguous)
        stage_six(pairs, keys)
        candidate_digest = digest(body["candidate"]["envelope"])
        for item in body["evidence"]:
            if item["envelope"]["payload"]["subject_candidate_digest"] != candidate_digest:
                reject(7, "evidence.subject_digest_mismatch")
        grant_pair = body.get("authority_grant")
        candidate = body["candidate"]["envelope"]["payload"]
        auth = authorization["payload"]
        constitution = body["constitution"]["envelope"]
        parent_caps = auth["lineage_capabilities"].get(candidate["parent_id"], [])
        delta = sorted(set(candidate["requested_capabilities"]) - set(parent_caps))
        if grant_pair is None:
            if delta:
                reject(8, "grant.capability_mismatch")
        else:
            grant = grant_pair["envelope"]["payload"]
            if grant["audience"] != "variaxiom-promotion/v2":
                reject(8, "grant.audience_mismatch")
            if (
                grant["trust_domain_id"] != auth["trust_domain_id"]
                or grant["capability_namespace"] != auth["capability_namespace"]
                or grant["constitution_digest"] != digest(constitution)
                or grant["lineage_id"] != auth["lineage_id"]
            ):
                reject(8, "grant.context_mismatch")
            if grant["subject_candidate_digest"] != candidate_digest:
                reject(8, "grant.subject_mismatch")
            if grant["capabilities"] != delta:
                reject(8, "grant.capability_mismatch")
            if grant["not_before_unix_s"] >= grant["expires_at_unix_s"]:
                reject(8, "grant.interval_invalid")
            now = identity_payload["evaluation_time_unix_s"]
            if now < grant["not_before_unix_s"]:
                reject(8, "grant.not_yet_valid")
            if now >= grant["expires_at_unix_s"]:
                reject(8, "grant.expired")
            if grant["delegable"]:
                reject(8, "grant.delegation_forbidden")
        constitution_pair = body["constitution"]
        if auth["constitution_envelope_digest"] != digest(constitution_pair["envelope"]):
            reject(9, "constitution.context_mismatch")
        if (
            constitution_pair["artifact_hash"] != digest(constitution_pair["envelope"]["payload"])
            or auth["constitution_artifact_hash"] != constitution_pair["artifact_hash"]
        ):
            reject(9, "constitution.artifact_mismatch")
        expected_decision = policy_decision(value["payload"]["promotion_input"])
        if canonical_bytes(expected_decision) != canonical_bytes(value["payload"]["decision"]):
            reject(11, "decision.content_mismatch")
        selector_pair = all_pairs(value, include_selector=True)[-1]
        try:
            if (
                selector_pair[0]["signature"]["payload"]["trust_domain_id"]
                != anchor["trust_domain_id"]
            ):
                raise Rejected(11, "signature.domain_mismatch")
            stage_four([selector_pair], keys)
            stage_five(
                value,
                anchor,
                [selector_pair],
                principals,
                keys,
                ambiguous,
                role_pairs=all_pairs(value, include_selector=True),
            )
            stage_six([selector_pair], keys)
        except Rejected as selector_error:
            raise Rejected(11, selector_error.code) from selector_error
        return (
            "verified",
            None,
            None,
            expected_decision["payload"]["status"],
            case["entrypoint"] == "verify-attested-proposal",
        )
    except Rejected as error:
        return "rejected", error.stage, error.code, "not-reached", False


def main() -> int:
    manifest = json.loads((FIXTURES / "manifest.json").read_text("utf-8"))
    failures: list[str] = []
    counts: dict[int, int] = {}
    case_ids = {item["case_id"] for item in manifest["cases"]}
    missing_required = sorted(REQUIRED_CASE_IDS - case_ids)
    if missing_required:
        failures.append(f"manifest missing required adversarial cases: {missing_required}")
    for item in manifest["cases"]:
        case = json.loads((FIXTURES / item["fixture"]).read_text("utf-8"))
        observed_status, observed_stage, observed_code, decision_status, authorizing = (
            evaluate_case(case)
        )
        expected = case["expected"]
        if observed_stage is not None:
            counts[observed_stage] = counts.get(observed_stage, 0) + 1
        if (
            observed_status != expected["status"]
            or observed_code != expected["code"]
            or (observed_stage or case["stage"]) != case["stage"]
            or decision_status != expected["decision_status"]
            or authorizing != expected["authorizing"]
        ):
            failures.append(
                f"{case['case_id']}: observed={(observed_status, observed_stage, observed_code, decision_status, authorizing)} "
                f"expected={(expected['status'], case['stage'], expected['code'], expected['decision_status'], expected['authorizing'])}"
            )
        for vector in case["signature_vectors"]:
            observed_vector_code = classify_signature_vector(vector)
            expected_vector_code = vector["expected_code"]
            if observed_vector_code != expected_vector_code:
                failures.append(
                    f"{case['case_id']}/{vector['vector_id']}: signature-vector code "
                    f"{observed_vector_code!r} != {expected_vector_code!r}"
                )
    wycheproof = json.loads((FIXTURES / "wycheproof-ed25519-subset.json").read_text("utf-8"))
    for item in wycheproof["vectors"]:
        accepted = False
        try:
            public = bytes.fromhex(item["public_key_hex"])
            signature = bytes.fromhex(item["signature_hex"])
            message = bytes.fromhex(item["message_hex"])
            if len(public) == 32 and len(signature) == 64:
                r_value, s_value = signature[:32], signature[32:]
                if (
                    bindings.crypto_core_ed25519_is_valid_point(public)
                    and bindings.crypto_core_ed25519_is_valid_point(r_value)
                    and int.from_bytes(s_value, "little") < L
                ):
                    VerifyKey(public).verify(message, signature)
                    accepted = True
        except (BadSignatureError, ValueError):
            accepted = False
        if accepted != (item["expected"] == "valid"):
            failures.append(
                f"Wycheproof tcId {item['tc_id']} ({item['flag']}): accepted={accepted}, "
                f"expected={item['expected']}"
            )
    if failures:
        print("M2.1 fixture execution failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    stages = ", ".join(f"{stage}:{count}" for stage, count in sorted(counts.items()))
    print(
        f"M2.1 fixture execution passed ({len(manifest['cases'])} cases; "
        f"{len(wycheproof['vectors'])} Wycheproof vectors; rejected stages {stages})."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
