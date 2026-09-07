#!/usr/bin/env python3
# ruff: noqa: RUF005
"""Generate the self-contained M2.1 conformance corpus.

The four signing seeds below are published RFC 8032 section 7.1 test vectors. They are
non-secret interoperability material, never production credentials. Keeping their provenance
explicit makes every fixture reproducible without placing project-generated private keys in Git.
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

from nacl import bindings
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

from variaxiom.constitution import Constitution
from variaxiom.domain import Candidate, Evidence
from variaxiom.promotion import PromotionContext, PromotionGate

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "fixtures/conformance/v2"
CASES = OUT / "cases"
SPEC = ROOT / "docs/specs/m2.1-identity-grants-signatures.md"
ENVELOPE_VERSION = "variaxiom-envelope/v1"
DOMAIN = "trust-domain:example"
EVALUATION_TIME = 1_788_739_200
L = 2**252 + 27742317777372353535851937790883648493

# RFC 8032 section 7.1 TEST 1, TEST 2, TEST 3, and TEST 1024.
RFC8032_SEEDS = {
    "builder": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    "issuer": "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
    "selector": "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
    "verifier": "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5",
}

ROLE = {
    "builder": "candidate-proposer",
    "issuer": "authority-issuer",
    "selector": "promotion-selector",
    "verifier": "evidence-verifier",
}


def canonical_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def digest(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def raw_base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def decode_base64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))


def envelope(kind: str, payload: dict[str, Any]) -> dict[str, Any]:
    return {"envelope_version": ENVELOPE_VERSION, "kind": kind, "payload": payload}


def signing_key(name: str) -> SigningKey:
    return SigningKey(bytes.fromhex(RFC8032_SEEDS[name]))


def public_key(name: str) -> str:
    return raw_base64url(bytes(signing_key(name).verify_key))


def key_id_from_public(encoded: str) -> str:
    raw = decode_base64url(encoded)
    value = hashlib.sha256(b"variaxiom-key/v1\0Ed25519\0" + raw).hexdigest()
    return f"key:sha256:{value}"


def key_id(name: str) -> str:
    return key_id_from_public(public_key(name))


def signing_message(payload: dict[str, Any]) -> bytes:
    fields = [
        "variaxiom-signature/v1",
        payload["algorithm"],
        payload["trust_domain_id"],
        payload["principal_id"],
        payload["key_id"],
        payload["signed_kind"],
        payload["signed_digest"],
        "",
    ]
    return "\n".join(fields).encode("ascii")


def signature(
    target: object,
    signed_kind: str,
    signer: str,
    *,
    principal_id: str | None = None,
    trust_domain_id: str = DOMAIN,
    algorithm: str = "Ed25519",
) -> dict[str, Any]:
    payload = {
        "signature_version": "detached-signature/v1",
        "algorithm": algorithm,
        "trust_domain_id": trust_domain_id,
        "principal_id": principal_id or f"principal:{signer}",
        "key_id": key_id(signer),
        "signed_kind": signed_kind,
        "signed_digest": digest(target),
        "signature_base64url": "pending",
    }
    payload["signature_base64url"] = raw_base64url(
        signing_key(signer).sign(signing_message(payload)).signature
    )
    return envelope("detached-signature", payload)


def principal(name: str, *, roles: list[str] | None = None) -> dict[str, Any]:
    return {
        "principal_version": "principal/v1",
        "principal_id": f"principal:{name}",
        "roles": sorted(roles or [ROLE[name]]),
        "keys": [
            {
                "key_binding_version": "key-binding/v1",
                "algorithm": "Ed25519",
                "key_id": key_id(name),
                "public_key_base64url": public_key(name),
            }
        ],
    }


def policy_decision(promotion_input: dict[str, Any]) -> dict[str, Any]:
    promotion = promotion_input["payload"]
    candidate_payload = promotion["candidate"]["envelope"]["payload"]
    evidence_payloads = [item["envelope"]["payload"] for item in promotion["evidence"]]
    constitution_payload = promotion["constitution"]["envelope"]["payload"]
    authorization = promotion["authorization_context"]["payload"]
    grant_pair = promotion.get("authority_grant")
    authority_grants: dict[str, frozenset[str]] = {}
    grant_id_value: str | None = None
    if isinstance(grant_pair, dict):
        grant_id_value = "grant:sha256:" + digest(grant_pair["envelope"])
        authority_grants[grant_id_value] = frozenset(
            grant_pair["envelope"]["payload"]["capabilities"]
        )
    candidate = Candidate(
        candidate_id=candidate_payload["candidate_id"],
        parent_id=candidate_payload["parent_id"],
        artifact_hash=candidate_payload["artifact_hash"],
        proposer=candidate_payload["proposer"],
        rollback_target=candidate_payload["rollback_target"],
        baseline_capabilities=frozenset(candidate_payload["baseline_capabilities"]),
        requested_capabilities=frozenset(candidate_payload["requested_capabilities"]),
        estimated_cost_micro_usd=candidate_payload["estimated_cost_micro_usd"],
        metadata=candidate_payload["metadata"],
    )
    evidence = [
        Evidence(
            evidence_id=item["evidence_id"],
            subject_id=candidate_payload["candidate_id"],
            artifact_hash=item["artifact_hash"],
            check=item["check"],
            status=item["status"],
            verifier=item["verifier"],
            independent=item["independent"],
            details=item["details"],
        )
        for item in evidence_payloads
    ]
    constitution = Constitution(
        version=constitution_payload["version"],
        mandatory_checks=tuple(constitution_payload["mandatory_checks"]),
        minimum_independent_verifiers=constitution_payload["minimum_independent_verifiers"],
        max_candidate_cost_micro_usd=constitution_payload["max_candidate_cost_micro_usd"],
        require_known_parent=constitution_payload["require_known_parent"],
        require_rollback_target=constitution_payload["require_rollback_target"],
        forbid_self_verification=constitution_payload["forbid_self_verification"],
        forbid_implicit_authority_escalation=constitution_payload[
            "forbid_implicit_authority_escalation"
        ],
        reject_any_failed_evidence=constitution_payload["reject_any_failed_evidence"],
    )
    context = PromotionContext(
        known_lineage_ids=frozenset(authorization["known_lineage_ids"]),
        known_artifact_hashes=frozenset(authorization["verified_artifact_hashes"]),
        authority_grants=authority_grants,
        lineage_capabilities={
            item: frozenset(capabilities)
            for item, capabilities in authorization["lineage_capabilities"].items()
        },
    )
    raw = PromotionGate(constitution).decide(
        candidate, evidence, context, authority_grant_id=grant_id_value
    )
    return envelope(
        "promotion-decision",
        {
            "candidate_id": raw.candidate_id,
            "status": raw.status,
            "reasons": list(raw.reasons),
            "evidence_ids": list(raw.evidence_ids),
            "input_digest": digest(promotion_input),
            "constitution_version": raw.constitution_version,
            "gate_version": raw.gate_version,
        },
    )


def build() -> tuple[dict[str, Any], dict[str, Any]]:
    candidate = envelope(
        "candidate",
        {
            "candidate_version": "candidate/v2",
            "candidate_id": "candidate:bounded-network",
            "parent_id": "genome:parent",
            "artifact_hash": "b" * 64,
            "proposer": "principal:builder",
            "rollback_target": "genome:parent",
            "baseline_capabilities": [],
            "requested_capabilities": ["network.example.com"],
            "estimated_cost_micro_usd": 10,
            "metadata": {},
        },
    )
    evidence = envelope(
        "evidence",
        {
            "evidence_version": "evidence/v2",
            "evidence_id": "evidence:unit",
            "subject_candidate_digest": digest(candidate),
            "artifact_hash": "b" * 64,
            "check": "unit",
            "status": "pass",
            "verifier": "principal:verifier",
            "independent": True,
            "details": {},
        },
    )
    constitution = envelope(
        "constitution",
        {
            "version": "constitution/v1",
            "mandatory_checks": ["unit"],
            "minimum_independent_verifiers": 1,
            "max_candidate_cost_micro_usd": 100,
            "require_known_parent": True,
            "require_rollback_target": True,
            "forbid_self_verification": True,
            "forbid_implicit_authority_escalation": True,
            "reject_any_failed_evidence": True,
        },
    )
    identity = envelope(
        "identity-context",
        {
            "identity_context_version": "identity-context/v1",
            "trust_domain_id": DOMAIN,
            "snapshot_sequence": 0,
            "previous_snapshot_digest": None,
            "evaluation_time_unix_s": EVALUATION_TIME,
            "principals": [principal(name) for name in sorted(RFC8032_SEEDS)],
            "revoked_key_ids": [],
            "revoked_grant_ids": [],
        },
    )
    constitution_artifact = digest(constitution["payload"])
    authorization = envelope(
        "authorization-context",
        {
            "authorization_context_version": "authorization-context/v1",
            "trust_domain_id": DOMAIN,
            "capability_namespace": "variaxiom-capability/v1",
            "lineage_id": "lineage:example",
            "constitution_envelope_digest": digest(constitution),
            "constitution_artifact_hash": constitution_artifact,
            "known_lineage_ids": ["genome:parent"],
            "lineage_capabilities": {"genome:parent": []},
            "verified_artifact_hashes": ["b" * 64],
        },
    )
    grant = envelope(
        "authority-grant",
        {
            "grant_version": "authority-grant/v1",
            "audience": "variaxiom-promotion/v2",
            "trust_domain_id": DOMAIN,
            "capability_namespace": "variaxiom-capability/v1",
            "constitution_digest": digest(constitution),
            "lineage_id": "lineage:example",
            "issuer_principal_id": "principal:issuer",
            "subject_candidate_digest": digest(candidate),
            "capabilities": ["network.example.com"],
            "not_before_unix_s": EVALUATION_TIME,
            "expires_at_unix_s": EVALUATION_TIME + 3600,
            "delegable": False,
        },
    )
    promotion_input = envelope(
        "promotion-input",
        {
            "protocol_version": "promotion-input/v2",
            "candidate": {
                "envelope": candidate,
                "signature": signature(candidate, "candidate", "builder"),
            },
            "evidence": [
                {"envelope": evidence, "signature": signature(evidence, "evidence", "verifier")}
            ],
            "constitution": {"envelope": constitution, "artifact_hash": constitution_artifact},
            "identity_context": identity,
            "authorization_context": authorization,
            "authority_grant": {
                "envelope": grant,
                "signature": signature(grant, "authority-grant", "issuer"),
            },
        },
    )
    decision = policy_decision(promotion_input)
    attested = envelope(
        "attested-proposal",
        {
            "proposal_version": "attested-proposal/v1",
            "promotion_input": promotion_input,
            "decision": decision,
            "selector_signature": signature(decision, "promotion-decision", "selector"),
        },
    )
    return attested, anchor_for(attested)


def anchor_for(attested: dict[str, Any]) -> dict[str, Any]:
    promotion = attested["payload"]["promotion_input"]["payload"]
    identity = promotion["identity_context"]
    authorization = promotion["authorization_context"]
    principals = identity["payload"]["principals"]
    registry = {key["key_id"]: item["principal_id"] for item in principals for key in item["keys"]}
    return {
        "trust_domain_id": identity["payload"]["trust_domain_id"],
        "current_identity_context_digest": digest(identity),
        "current_authorization_context_digest": digest(authorization),
        "current_snapshot_sequence": identity["payload"]["snapshot_sequence"],
        "trusted_now_unix_s": identity["payload"]["evaluation_time_unix_s"],
        "key_ownership_registry": dict(sorted(registry.items())),
        "revoked_key_ids": identity["payload"]["revoked_key_ids"],
        "revoked_grant_ids": identity["payload"]["revoked_grant_ids"],
    }


def promotion(attested: dict[str, Any]) -> dict[str, Any]:
    return attested["payload"]["promotion_input"]["payload"]


def resign_all(attested: dict[str, Any], signer_overrides: dict[str, str] | None = None) -> None:
    signers = signer_overrides or {}
    body = promotion(attested)
    candidate_pair = body["candidate"]
    candidate_pair["signature"] = signature(
        candidate_pair["envelope"], "candidate", signers.get("candidate", "builder")
    )
    for item in body["evidence"]:
        name = signers.get(item["envelope"]["payload"]["evidence_id"], "verifier")
        item["signature"] = signature(item["envelope"], "evidence", name)
    grant = body.get("authority_grant")
    if isinstance(grant, dict):
        grant["signature"] = signature(
            grant["envelope"], "authority-grant", signers.get("authority-grant", "issuer")
        )
    decision = policy_decision(attested["payload"]["promotion_input"])
    attested["payload"]["decision"] = decision
    attested["payload"]["selector_signature"] = signature(
        decision, "promotion-decision", signers.get("promotion-decision", "selector")
    )


def find_public_key(attested: dict[str, Any], wanted_key_id: str) -> str:
    principals = promotion(attested)["identity_context"]["payload"]["principals"]
    for item in principals:
        for key in item["keys"]:
            if key["key_id"] == wanted_key_id:
                return key["public_key_base64url"]
    return public_key("builder")


def vector(
    vector_id: str,
    target: dict[str, Any],
    signature_envelope: dict[str, Any],
    attested: dict[str, Any],
) -> dict[str, Any]:
    sig = signature_envelope["payload"]
    actual_digest = digest(target)
    expected = "verified"
    code: str | None = None
    encoded_public = find_public_key(attested, sig["key_id"])
    if sig["algorithm"] != "Ed25519":
        expected, code = "rejected", "signature.algorithm_unsupported"
    elif sig["signed_digest"] != actual_digest:
        expected, code = "rejected", "signature.digest_mismatch"
    elif key_id_from_public(encoded_public) != sig["key_id"]:
        expected, code = "rejected", "signature.key_id_mismatch"
    elif sig["signed_kind"] != target["kind"]:
        expected, code = "rejected", "signature.kind_mismatch"
    else:
        try:
            public = decode_base64url(encoded_public)
            raw_signature = decode_base64url(sig["signature_base64url"])
            canonical_public = raw_base64url(public)
            canonical_signature = raw_base64url(raw_signature)
            if (
                len(public) != 32
                or len(raw_signature) != 64
                or canonical_public != encoded_public
                or canonical_signature != sig["signature_base64url"]
                or not bindings.crypto_core_ed25519_is_valid_point(public)
                or not bindings.crypto_core_ed25519_is_valid_point(raw_signature[:32])
                or int.from_bytes(raw_signature[32:], "little") >= L
            ):
                expected, code = "rejected", "signature.encoding_invalid"
            else:
                VerifyKey(public).verify(signing_message(sig), raw_signature)
        except (BadSignatureError, ValueError):
            expected, code = "rejected", "signature.invalid"
    result = {
        "vector_version": "m2.1-signature-vector/v1",
        "vector_id": vector_id,
        "target_envelope": target,
        "target_digest": actual_digest,
        "trust_domain_id": sig["trust_domain_id"],
        "principal_id": sig["principal_id"],
        "key_id": sig["key_id"],
        "public_key_base64url": encoded_public,
        "signed_kind": sig["signed_kind"],
        "message_hex": signing_message(sig).hex(),
        "signature_base64url": sig["signature_base64url"],
        "expected": expected,
        "expected_code": code,
    }
    return result


def vectors(attested: dict[str, Any]) -> list[dict[str, Any]]:
    body = promotion(attested)
    result = [
        vector("candidate", body["candidate"]["envelope"], body["candidate"]["signature"], attested)
    ]
    result.extend(
        vector(
            item["envelope"]["payload"]["evidence_id"],
            item["envelope"],
            item["signature"],
            attested,
        )
        for item in body["evidence"]
    )
    grant = body.get("authority_grant")
    if isinstance(grant, dict):
        result.append(vector("authority-grant", grant["envelope"], grant["signature"], attested))
    if "selector_signature" in attested["payload"]:
        result.append(
            vector(
                "promotion-decision",
                attested["payload"]["decision"],
                attested["payload"]["selector_signature"],
                attested,
            )
        )
    return result


def make_case(
    case_id: str,
    stage: int,
    source: bytes | dict[str, Any],
    anchor: dict[str, Any],
    code: str | None,
    *,
    decision_status: str = "not-reached",
    entrypoint: str = "verify-attested-proposal",
    authorizing: bool = True,
    notes: str = "Frozen shared conformance vector.",
) -> dict[str, Any]:
    wire = source if isinstance(source, bytes) else canonical_bytes(source)
    case = {
        "case_version": "m2.1-conformance-case/v1",
        "case_id": case_id,
        "entrypoint": entrypoint,
        "stage": stage,
        "input_base64url": raw_base64url(wire),
        "input_sha256": hashlib.sha256(wire).hexdigest(),
        "trusted_anchor": anchor,
        "expected": {
            "status": "verified" if code is None else "rejected",
            "code": code,
            "decision_status": decision_status,
            "authorizing": authorizing if code is None else False,
        },
        "signature_vectors": (
            vectors(source)
            if isinstance(source, dict)
            and stage >= 3
            and entrypoint in {"verify-attested-proposal", "replay-historical"}
            else []
        ),
        "notes": notes,
    }
    return case


def next_identity(
    previous: dict[str, Any],
    sequence: int,
    *,
    principals: list[dict[str, Any]] | None = None,
    revoked_key_ids: list[str] | None = None,
    revoked_grant_ids: list[str] | None = None,
    previous_digest: str | None = None,
    evaluation_time: int | None = None,
) -> dict[str, Any]:
    result = copy.deepcopy(previous)
    payload = result["payload"]
    payload["snapshot_sequence"] = sequence
    payload["previous_snapshot_digest"] = previous_digest or digest(previous)
    payload["evaluation_time_unix_s"] = evaluation_time or EVALUATION_TIME + sequence
    if principals is not None:
        payload["principals"] = principals
    if revoked_key_ids is not None:
        payload["revoked_key_ids"] = sorted(revoked_key_ids)
    if revoked_grant_ids is not None:
        payload["revoked_grant_ids"] = sorted(revoked_grant_ids)
    return result


def advance_expected_anchor(
    previous: dict[str, Any], identity: dict[str, Any], authorization: dict[str, Any], now: int
) -> dict[str, Any]:
    result = copy.deepcopy(previous)
    result["current_identity_context_digest"] = digest(identity)
    result["current_authorization_context_digest"] = digest(authorization)
    result["current_snapshot_sequence"] = identity["payload"]["snapshot_sequence"]
    result["trusted_now_unix_s"] = now
    for descriptor in identity["payload"]["principals"]:
        for binding in descriptor["keys"]:
            result["key_ownership_registry"].setdefault(
                binding["key_id"], descriptor["principal_id"]
            )
    result["key_ownership_registry"] = dict(sorted(result["key_ownership_registry"].items()))
    result["revoked_key_ids"] = sorted(
        set(result["revoked_key_ids"]) | set(identity["payload"]["revoked_key_ids"])
    )
    result["revoked_grant_ids"] = sorted(
        set(result["revoked_grant_ids"]) | set(identity["payload"]["revoked_grant_ids"])
    )
    return result


def history_case(
    case_id: str,
    base: dict[str, Any],
    initial_anchor: dict[str, Any],
    steps: list[dict[str, Any]],
    code: str | None,
    stage: int,
    *,
    probe: dict[str, Any] | None = None,
) -> dict[str, Any]:
    body = promotion(base)
    history: dict[str, Any] = {
        "initial_anchor": initial_anchor,
        "initial_identity_context": body["identity_context"],
        "initial_authorization_context": body["authorization_context"],
        "steps": steps,
    }
    if probe is not None:
        history["probe_attested_proposal"] = probe
    wire = canonical_bytes(history)
    return {
        "case_version": "m2.1-conformance-case/v1",
        "case_id": case_id,
        "entrypoint": "advance-anchor-history",
        "stage": stage,
        "input_base64url": raw_base64url(wire),
        "input_sha256": hashlib.sha256(wire).hexdigest(),
        "expected": {
            "status": "verified" if code is None else "rejected",
            "code": code,
            "decision_status": "not-reached",
            "authorizing": code is None,
        },
        "signature_vectors": vectors(probe) if probe is not None else [],
        "anchor_history": history,
        "notes": "Self-contained ordered anchor transition history.",
    }


def set_path(value: dict[str, Any], path: tuple[str | int, ...], replacement: Any) -> None:
    current: Any = value
    for part in path[:-1]:
        current = current[part]
    current[path[-1]] = replacement


def proposal_case(
    base: dict[str, Any],
    base_anchor: dict[str, Any],
    case_id: str,
    stage: int,
    code: str | None,
    mutate: Any,
    *,
    refresh: bool = False,
    reanchor: bool = False,
    decision_status: str = "not-reached",
    notes: str = "Frozen shared conformance vector.",
) -> dict[str, Any]:
    value = copy.deepcopy(base)
    mutate(value)
    if refresh:
        resign_all(value)
    anchor = anchor_for(value) if reanchor else copy.deepcopy(base_anchor)
    return make_case(
        case_id,
        stage,
        value,
        anchor,
        code,
        decision_status=decision_status,
        notes=notes,
    )


def build_cases(base: dict[str, Any], base_anchor: dict[str, Any]) -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = [
        make_case(
            "bounded-signed-proposal",
            11,
            base,
            base_anchor,
            None,
            decision_status="accepted",
            notes="Complete accepted path with four distinct principals and four verified signatures.",
        ),
        make_case("utf8-bom-rejected", 1, b"\xef\xbb\xbf{}", base_anchor, "input.encoding_invalid"),
        make_case(
            "utf16-rejected", 1, b"\xff\xfe{\x00}\x00", base_anchor, "input.encoding_invalid"
        ),
        make_case(
            "lone-surrogate-rejected", 1, b'{"x":"\\ud800"}', base_anchor, "input.encoding_invalid"
        ),
        make_case(
            "depth-limit-rejected",
            1,
            b"[" * 65 + b"0" + b"]" * 65,
            base_anchor,
            "input.limit_exceeded",
        ),
        make_case(
            "duplicate-member-rejected", 1, b'{"x":1,"x":2}', base_anchor, "input.duplicate_member"
        ),
        make_case(
            "noncanonical-wire-rejected", 1, b'{"x": 1}', base_anchor, "input.encoding_invalid"
        ),
        make_case(
            "unsafe-integer-rejected",
            1,
            b'{"x":9007199254740992}',
            base_anchor,
            "input.encoding_invalid",
        ),
        make_case(
            "wire-size-plus-one-rejected", 1, b" " * 1_048_577, base_anchor, "input.limit_exceeded"
        ),
    ]

    def mutate(path: tuple[str | int, ...], replacement: Any) -> Any:
        return lambda value: set_path(value, path, replacement)

    candidate_payload = (
        "payload",
        "promotion_input",
        "payload",
        "candidate",
        "envelope",
        "payload",
    )
    candidate_sig = ("payload", "promotion_input", "payload", "candidate", "signature", "payload")
    evidence_payload = (
        "payload",
        "promotion_input",
        "payload",
        "evidence",
        0,
        "envelope",
        "payload",
    )
    evidence_sig = ("payload", "promotion_input", "payload", "evidence", 0, "signature", "payload")
    authorization_payload = (
        "payload",
        "promotion_input",
        "payload",
        "authorization_context",
        "payload",
    )
    grant_payload = (
        "payload",
        "promotion_input",
        "payload",
        "authority_grant",
        "envelope",
        "payload",
    )
    grant_sig = ("payload", "promotion_input", "payload", "authority_grant", "signature", "payload")

    for case_id, path, replacement, code in [
        (
            "wrong-envelope-version",
            ("envelope_version",),
            "variaxiom-envelope/v9",
            "input.version_unsupported",
        ),
        ("wrong-envelope-kind", ("kind",), "unknown-kind", "input.kind_mismatch"),
        (
            "nonascii-principal-rejected",
            candidate_payload + ("proposer",),
            "principal:строитель",
            "input.schema_invalid",
        ),
        (
            "comma-token-rejected",
            candidate_payload + ("candidate_id",),
            "candidate:bad,token",
            "input.schema_invalid",
        ),
        (
            "unsorted-capabilities-rejected",
            candidate_payload + ("requested_capabilities",),
            ["z.example", "a.example"],
            "input.schema_invalid",
        ),
        (
            "duplicate-capabilities-rejected",
            candidate_payload + ("requested_capabilities",),
            ["network.example.com", "network.example.com"],
            "input.schema_invalid",
        ),
    ]:
        cases.append(proposal_case(base, base_anchor, case_id, 2, code, mutate(path, replacement)))

    def add_unknown(value: dict[str, Any]) -> None:
        value["surprise"] = True

    cases.append(
        proposal_case(
            base, base_anchor, "unknown-field-rejected", 2, "input.schema_invalid", add_unknown
        )
    )

    def remove_selector(value: dict[str, Any]) -> None:
        del value["payload"]["selector_signature"]

    cases.append(
        proposal_case(
            base, base_anchor, "missing-selector", 2, "input.schema_invalid", remove_selector
        )
    )

    def refresh_candidate_bindings(value: dict[str, Any]) -> None:
        body = promotion(value)
        candidate_digest = digest(body["candidate"]["envelope"])
        for item in body["evidence"]:
            item["envelope"]["payload"]["subject_candidate_digest"] = candidate_digest
        if "authority_grant" in body:
            body["authority_grant"]["envelope"]["payload"]["subject_candidate_digest"] = (
                candidate_digest
            )
        resign_all(value)

    def candidate_with_id(value: dict[str, Any], candidate_id: str) -> None:
        promotion(value)["candidate"]["envelope"]["payload"]["candidate_id"] = candidate_id
        refresh_candidate_bindings(value)

    cases.append(
        proposal_case(
            base,
            base_anchor,
            "token-utf8-256-bytes",
            11,
            None,
            lambda value: candidate_with_id(value, "é" * 128),
            decision_status="accepted",
        )
    )
    cases.append(
        proposal_case(
            base,
            base_anchor,
            "token-utf8-257-bytes-rejected",
            2,
            "input.limit_exceeded",
            lambda value: set_path(value, candidate_payload + ("candidate_id",), "é" * 129),
        )
    )

    exact_metadata = {"x": "a" * 65_528}
    over_metadata = {"x": "a" * 65_529}

    def candidate_metadata(value: dict[str, Any], metadata: dict[str, Any]) -> None:
        promotion(value)["candidate"]["envelope"]["payload"]["metadata"] = metadata
        refresh_candidate_bindings(value)

    cases.append(
        proposal_case(
            base,
            base_anchor,
            "metadata-exact-limit",
            11,
            None,
            lambda value: candidate_metadata(value, exact_metadata),
            decision_status="accepted",
        )
    )
    cases.append(
        proposal_case(
            base,
            base_anchor,
            "metadata-limit-plus-one",
            2,
            "input.limit_exceeded",
            lambda value: set_path(value, candidate_payload + ("metadata",), over_metadata),
        )
    )

    capabilities_128 = [f"cap.{index:03d}" for index in range(128)]

    def exact_capabilities(value: dict[str, Any]) -> None:
        body = promotion(value)
        body["candidate"]["envelope"]["payload"]["requested_capabilities"] = capabilities_128
        body["authority_grant"]["envelope"]["payload"]["capabilities"] = capabilities_128
        refresh_candidate_bindings(value)

    cases.append(
        proposal_case(
            base,
            base_anchor,
            "capabilities-exact-limit",
            11,
            None,
            exact_capabilities,
            decision_status="accepted",
        )
    )
    cases.append(
        proposal_case(
            base,
            base_anchor,
            "capabilities-limit-plus-one",
            2,
            "input.limit_exceeded",
            lambda value: set_path(
                value,
                candidate_payload + ("requested_capabilities",),
                [*capabilities_128, "cap.128"],
            ),
        )
    )

    def synthetic_binding(index: int) -> dict[str, Any]:
        scalar = index.to_bytes(32, "little")
        encoded = raw_base64url(bindings.crypto_scalarmult_ed25519_base_noclamp(scalar))
        return {
            "key_binding_version": "key-binding/v1",
            "algorithm": "Ed25519",
            "key_id": key_id_from_public(encoded),
            "public_key_base64url": encoded,
        }

    def principal_limit(value: dict[str, Any], count: int, refresh: bool) -> None:
        principals = promotion(value)["identity_context"]["payload"]["principals"]
        for index in range(count - len(principals)):
            principals.append(
                {
                    "principal_version": "principal/v1",
                    "principal_id": f"principal:extra-{index:03d}",
                    "roles": ["evidence-verifier"],
                    "keys": [synthetic_binding(1000 + index)],
                }
            )
        principals.sort(key=lambda item: item["principal_id"])
        if refresh:
            resign_all(value)

    cases.append(
        proposal_case(
            base,
            base_anchor,
            "principals-exact-limit",
            11,
            None,
            lambda value: principal_limit(value, 64, True),
            reanchor=True,
            decision_status="accepted",
        )
    )
    cases.append(
        proposal_case(
            base,
            base_anchor,
            "principals-limit-plus-one",
            2,
            "input.limit_exceeded",
            lambda value: principal_limit(value, 65, False),
        )
    )

    def builder_key_limit(value: dict[str, Any], count: int, refresh: bool) -> None:
        builder = next(
            item
            for item in promotion(value)["identity_context"]["payload"]["principals"]
            if item["principal_id"] == "principal:builder"
        )
        builder["keys"].extend(synthetic_binding(2000 + index) for index in range(count - 1))
        builder["keys"].sort(key=lambda item: item["key_id"])
        if refresh:
            resign_all(value)

    cases.append(
        proposal_case(
            base,
            base_anchor,
            "keys-per-principal-exact-limit",
            11,
            None,
            lambda value: builder_key_limit(value, 8, True),
            reanchor=True,
            decision_status="accepted",
        )
    )
    cases.append(
        proposal_case(
            base,
            base_anchor,
            "keys-per-principal-limit-plus-one",
            2,
            "input.limit_exceeded",
            lambda value: builder_key_limit(value, 9, False),
        )
    )

    def evidence_limit(value: dict[str, Any], count: int, refresh: bool) -> None:
        body = promotion(value)
        template = body["evidence"][0]
        body["evidence"] = []
        for index in range(count):
            item = copy.deepcopy(template)
            item["envelope"]["payload"]["evidence_id"] = f"evidence:{index:03d}"
            body["evidence"].append(item)
        if refresh:
            resign_all(value)

    cases.append(
        proposal_case(
            base,
            base_anchor,
            "evidence-and-crypto-ops-exact-limit",
            11,
            None,
            lambda value: evidence_limit(value, 256, True),
            decision_status="accepted",
        )
    )
    cases.append(
        proposal_case(
            base,
            base_anchor,
            "evidence-limit-plus-one",
            2,
            "input.limit_exceeded",
            lambda value: evidence_limit(value, 257, False),
        )
    )

    exact_wire = copy.deepcopy(base)
    evidence_limit(exact_wire, 16, False)
    for item in promotion(exact_wire)["evidence"][:-1]:
        item["envelope"]["payload"]["details"] = exact_metadata
    resign_all(exact_wire)
    remaining = 1_048_576 - len(canonical_bytes(exact_wire))
    if remaining < 6 or remaining > 65_534:
        raise RuntimeError(f"cannot construct exact wire-size fixture; remaining={remaining}")
    promotion(exact_wire)["evidence"][-1]["envelope"]["payload"]["details"] = {
        "x": "a" * (remaining - 6)
    }
    resign_all(exact_wire)
    if len(canonical_bytes(exact_wire)) != 1_048_576:
        raise RuntimeError("exact wire-size fixture is not exactly 1,048,576 bytes")
    cases.append(
        make_case(
            "wire-size-exact-limit",
            11,
            exact_wire,
            base_anchor,
            None,
            decision_status="accepted",
        )
    )

    def role_limit(value: dict[str, Any], count: int, refresh: bool) -> None:
        builder = next(
            item
            for item in promotion(value)["identity_context"]["payload"]["principals"]
            if item["principal_id"] == "principal:builder"
        )
        builder["roles"] = sorted(
            ["candidate-proposer", *[f"reserved-role-{index}" for index in range(count - 1)]]
        )
        if refresh:
            resign_all(value)

    cases.append(
        proposal_case(
            base,
            base_anchor,
            "roles-per-principal-exact-limit",
            11,
            None,
            lambda value: role_limit(value, 8, True),
            reanchor=True,
            decision_status="accepted",
        )
    )
    cases.append(
        proposal_case(
            base,
            base_anchor,
            "roles-per-principal-limit-plus-one",
            2,
            "input.limit_exceeded",
            lambda value: role_limit(value, 9, False),
        )
    )

    def revocation_limit(value: dict[str, Any], field: str, count: int, refresh: bool) -> None:
        prefix = "key:sha256:" if field == "revoked_key_ids" else "grant:sha256:"
        promotion(value)["identity_context"]["payload"][field] = [
            prefix + f"{index + 10_000:064x}" for index in range(count)
        ]
        if refresh:
            resign_all(value)

    for field, label in (
        ("revoked_key_ids", "revoked-keys"),
        ("revoked_grant_ids", "revoked-grants"),
    ):
        cases.append(
            proposal_case(
                base,
                base_anchor,
                f"{label}-exact-limit",
                11,
                None,
                lambda value, field=field: revocation_limit(value, field, 4096, True),
                reanchor=True,
                decision_status="accepted",
            )
        )
        cases.append(
            proposal_case(
                base,
                base_anchor,
                f"{label}-limit-plus-one",
                2,
                "input.limit_exceeded",
                lambda value, field=field: revocation_limit(value, field, 4097, False),
            )
        )

    def lineage_limit(value: dict[str, Any], count: int, refresh: bool) -> None:
        authorization = promotion(value)["authorization_context"]["payload"]
        identifiers = ["genome:parent", *[f"genome:{index:04d}" for index in range(count - 1)]]
        identifiers = sorted(set(identifiers))
        authorization["known_lineage_ids"] = identifiers
        authorization["lineage_capabilities"] = {identifier: [] for identifier in identifiers}
        if refresh:
            resign_all(value)

    cases.append(
        proposal_case(
            base,
            base_anchor,
            "lineage-records-exact-limit",
            11,
            None,
            lambda value: lineage_limit(value, 4096, True),
            reanchor=True,
            decision_status="accepted",
        )
    )
    cases.append(
        proposal_case(
            base,
            base_anchor,
            "lineage-records-limit-plus-one",
            2,
            "input.limit_exceeded",
            lambda value: lineage_limit(value, 4097, False),
        )
    )

    def artifact_limit(value: dict[str, Any], count: int, refresh: bool) -> None:
        values = ["b" * 64, *[f"{index + 1:064x}" for index in range(count - 1)]]
        promotion(value)["authorization_context"]["payload"]["verified_artifact_hashes"] = sorted(
            set(values)
        )
        if refresh:
            resign_all(value)

    cases.append(
        proposal_case(
            base,
            base_anchor,
            "verified-artifacts-exact-limit",
            11,
            None,
            lambda value: artifact_limit(value, 4096, True),
            reanchor=True,
            decision_status="accepted",
        )
    )
    cases.append(
        proposal_case(
            base,
            base_anchor,
            "verified-artifacts-limit-plus-one",
            2,
            "input.limit_exceeded",
            lambda value: artifact_limit(value, 4097, False),
        )
    )

    def evidence_details(value: dict[str, Any], size: int, refresh: bool) -> None:
        promotion(value)["evidence"][0]["envelope"]["payload"]["details"] = {"x": "a" * (size - 8)}
        if refresh:
            resign_all(value)

    cases.append(
        proposal_case(
            base,
            base_anchor,
            "evidence-details-exact-limit",
            11,
            None,
            lambda value: evidence_details(value, 65_536, True),
            decision_status="accepted",
        )
    )
    cases.append(
        proposal_case(
            base,
            base_anchor,
            "evidence-details-limit-plus-one",
            2,
            "input.limit_exceeded",
            lambda value: evidence_details(value, 65_537, False),
        )
    )

    exact_registry = copy.deepcopy(base_anchor)
    for index in range(4096 - len(exact_registry["key_ownership_registry"])):
        exact_registry["key_ownership_registry"]["key:sha256:" + f"{index + 50_000:064x}"] = (
            "principal:builder"
        )
    exact_registry["key_ownership_registry"] = dict(
        sorted(exact_registry["key_ownership_registry"].items())
    )
    cases.append(
        make_case(
            "anchor-key-registry-exact-limit",
            11,
            base,
            exact_registry,
            None,
            decision_status="accepted",
        )
    )
    over_registry = copy.deepcopy(exact_registry)
    over_registry["key_ownership_registry"]["key:sha256:" + "f" * 64] = "principal:builder"
    over_registry["key_ownership_registry"] = dict(
        sorted(over_registry["key_ownership_registry"].items())
    )
    cases.append(
        make_case(
            "anchor-key-registry-limit-plus-one",
            2,
            base,
            over_registry,
            "input.limit_exceeded",
        )
    )

    # Stage 3: trusted context and signature-domain equality.
    def wrong_candidate_domain(value: dict[str, Any]) -> None:
        pair = promotion(value)["candidate"]
        pair["signature"] = signature(
            pair["envelope"], "candidate", "builder", trust_domain_id="trust-domain:other"
        )
        value["payload"]["decision"] = policy_decision(value["payload"]["promotion_input"])
        value["payload"]["selector_signature"] = signature(
            value["payload"]["decision"], "promotion-decision", "selector"
        )

    cases.append(
        proposal_case(
            base,
            base_anchor,
            "candidate-domain-mismatch",
            3,
            "signature.domain_mismatch",
            wrong_candidate_domain,
        )
    )

    def wrong_object_domain(value: dict[str, Any], object_kind: str) -> None:
        body = promotion(value)
        if object_kind == "evidence":
            pair = body["evidence"][0]
            signer = "verifier"
        else:
            pair = body["authority_grant"]
            signer = "issuer"
        pair["signature"] = signature(
            pair["envelope"], object_kind, signer, trust_domain_id="trust-domain:other"
        )
        value["payload"]["decision"] = policy_decision(value["payload"]["promotion_input"])
        value["payload"]["selector_signature"] = signature(
            value["payload"]["decision"], "promotion-decision", "selector"
        )

    for object_kind in ("evidence", "authority-grant"):
        cases.append(
            proposal_case(
                base,
                base_anchor,
                f"{object_kind}-signature-domain-mismatch",
                3,
                "signature.domain_mismatch",
                lambda value, kind=object_kind: wrong_object_domain(value, kind),
            )
        )
    for name, path, replacement, code in [
        ("identity-sequence-stale", ("current_snapshot_sequence",), 1, "identity.context_stale"),
        (
            "identity-digest-untrusted",
            ("current_identity_context_digest",),
            "a" * 64,
            "identity.context_untrusted",
        ),
        (
            "authorization-digest-untrusted",
            ("current_authorization_context_digest",),
            "a" * 64,
            "authorization.context_untrusted",
        ),
        (
            "trusted-time-untrusted",
            ("trusted_now_unix_s",),
            EVALUATION_TIME + 1,
            "identity.context_untrusted",
        ),
        (
            "anchor-domain-untrusted",
            ("trust_domain_id",),
            "trust-domain:other",
            "identity.context_untrusted",
        ),
    ]:
        changed_anchor = copy.deepcopy(base_anchor)
        set_path(changed_anchor, path, replacement)
        cases.append(make_case(name, 3, base, changed_anchor, code))

    for field, replacement in [
        ("capability_namespace", "variaxiom-capability/v9"),
        ("constitution_envelope_digest", "a" * 64),
        ("constitution_artifact_hash", "a" * 64),
        ("lineage_capabilities", {"genome:parent": ["filesystem.read"]}),
        ("verified_artifact_hashes", ["a" * 64]),
        ("lineage_id", "lineage:other"),
        ("trust_domain_id", "trust-domain:other"),
    ]:
        cases.append(
            proposal_case(
                base,
                base_anchor,
                f"authorization-{field.replace('_', '-')}-untrusted",
                3,
                "authorization.context_untrusted",
                mutate(authorization_payload + (field,), replacement),
            )
        )

    def replace_lineage_set(value: dict[str, Any]) -> None:
        authorization = promotion(value)["authorization_context"]["payload"]
        authorization["known_lineage_ids"] = ["genome:other"]
        authorization["lineage_capabilities"] = {"genome:other": []}

    cases.append(
        proposal_case(
            base,
            base_anchor,
            "authorization-lineage-set-untrusted",
            3,
            "authorization.context_untrusted",
            replace_lineage_set,
        )
    )

    # Stage 4: binding before identity lookup or cryptography.
    for case_id, path, replacement, code in [
        (
            "candidate-digest-mismatch",
            candidate_sig + ("signed_digest",),
            "a" * 64,
            "signature.digest_mismatch",
        ),
        (
            "candidate-kind-mismatch",
            candidate_sig + ("signed_kind",),
            "evidence",
            "signature.kind_mismatch",
        ),
        (
            "evidence-digest-mismatch",
            evidence_sig + ("signed_digest",),
            "a" * 64,
            "signature.digest_mismatch",
        ),
        (
            "grant-digest-mismatch",
            grant_sig + ("signed_digest",),
            "a" * 64,
            "signature.digest_mismatch",
        ),
    ]:
        cases.append(proposal_case(base, base_anchor, case_id, 4, code, mutate(path, replacement)))

    def key_id_mismatch(value: dict[str, Any]) -> None:
        body = promotion(value)
        binding = next(
            item
            for item in body["identity_context"]["payload"]["principals"]
            if item["principal_id"] == "principal:builder"
        )["keys"][0]
        binding["key_id"] = "key:sha256:" + "a" * 64
        body["candidate"]["signature"]["payload"]["key_id"] = binding["key_id"]

    cases.append(
        proposal_case(
            base,
            base_anchor,
            "candidate-key-id-mismatch",
            4,
            "signature.key_id_mismatch",
            key_id_mismatch,
            reanchor=True,
        )
    )

    # Stage 5: principal bindings, roles, separation, and revocation.
    def principal_mismatch(value: dict[str, Any]) -> None:
        pair = promotion(value)["candidate"]
        pair["signature"] = signature(
            pair["envelope"], "candidate", "builder", principal_id="principal:verifier"
        )
        value["payload"]["decision"] = policy_decision(value["payload"]["promotion_input"])
        value["payload"]["selector_signature"] = signature(
            value["payload"]["decision"], "promotion-decision", "selector"
        )

    cases.append(
        proposal_case(
            base,
            base_anchor,
            "candidate-principal-mismatch",
            5,
            "signature.principal_mismatch",
            principal_mismatch,
        )
    )

    def object_principal_mismatch(value: dict[str, Any], object_kind: str) -> None:
        body = promotion(value)
        if object_kind == "evidence":
            pair = body["evidence"][0]
            signer = "verifier"
            claim = "principal:builder"
        else:
            pair = body["authority_grant"]
            signer = "issuer"
            claim = "principal:builder"
        pair["signature"] = signature(pair["envelope"], object_kind, signer, principal_id=claim)
        value["payload"]["decision"] = policy_decision(value["payload"]["promotion_input"])
        value["payload"]["selector_signature"] = signature(
            value["payload"]["decision"], "promotion-decision", "selector"
        )

    for object_kind in ("evidence", "authority-grant"):
        cases.append(
            proposal_case(
                base,
                base_anchor,
                f"{object_kind}-principal-mismatch",
                5,
                "signature.principal_mismatch",
                lambda value, kind=object_kind: object_principal_mismatch(value, kind),
            )
        )

    def unknown_candidate(value: dict[str, Any]) -> None:
        pair = promotion(value)["candidate"]
        pair["envelope"]["payload"]["proposer"] = "principal:unknown"
        pair["signature"] = signature(
            pair["envelope"], "candidate", "builder", principal_id="principal:unknown"
        )
        value["payload"]["decision"] = policy_decision(value["payload"]["promotion_input"])
        value["payload"]["selector_signature"] = signature(
            value["payload"]["decision"], "promotion-decision", "selector"
        )

    cases.append(
        proposal_case(
            base,
            base_anchor,
            "candidate-principal-unknown",
            5,
            "identity.principal_unknown",
            unknown_candidate,
        )
    )

    def unbound_candidate(value: dict[str, Any]) -> None:
        pair = promotion(value)["candidate"]
        pair["signature"] = signature(
            pair["envelope"], "candidate", "verifier", principal_id="principal:builder"
        )
        value["payload"]["decision"] = policy_decision(value["payload"]["promotion_input"])
        value["payload"]["selector_signature"] = signature(
            value["payload"]["decision"], "promotion-decision", "selector"
        )

    cases.append(
        proposal_case(
            base,
            base_anchor,
            "candidate-key-unbound",
            5,
            "identity.key_unbound",
            unbound_candidate,
        )
    )

    def role_conflict(value: dict[str, Any]) -> None:
        body = promotion(value)
        body["evidence"][0]["envelope"]["payload"]["verifier"] = "principal:builder"
        for item in body["identity_context"]["payload"]["principals"]:
            if item["principal_id"] == "principal:builder":
                item["roles"] = ["candidate-proposer", "evidence-verifier"]
        resign_all(value, {"evidence:unit": "builder"})

    cases.append(
        proposal_case(
            base,
            base_anchor,
            "proposer-verifier-role-conflict",
            5,
            "identity.role_conflict",
            role_conflict,
            reanchor=True,
        )
    )

    def duplicate_key(value: dict[str, Any]) -> None:
        principals = promotion(value)["identity_context"]["payload"]["principals"]
        principals[1]["keys"] = copy.deepcopy(principals[0]["keys"])
        resign_all(value)

    cases.append(
        proposal_case(
            base,
            base_anchor,
            "cross-principal-key-alias",
            5,
            "identity.key_ambiguous",
            duplicate_key,
            reanchor=True,
        )
    )

    def wrong_role(value: dict[str, Any]) -> None:
        body = promotion(value)
        body["candidate"]["envelope"]["payload"]["proposer"] = "principal:verifier"
        resign_all(value, {"candidate": "verifier"})

    cases.append(
        proposal_case(
            base, base_anchor, "candidate-role-missing", 5, "identity.role_missing", wrong_role
        )
    )

    revoked_anchor = copy.deepcopy(base_anchor)
    revoked_anchor["revoked_key_ids"] = [key_id("builder")]
    cases.append(
        make_case("revoked-proposer-key", 5, base, revoked_anchor, "signature.key_revoked")
    )

    # Stage 6: strict encoding and Ed25519 equation.
    cases.append(
        proposal_case(
            base,
            base_anchor,
            "unsupported-signature-algorithm",
            6,
            "signature.algorithm_unsupported",
            mutate(candidate_sig + ("algorithm",), "Ed448"),
        )
    )
    cases.append(
        proposal_case(
            base,
            base_anchor,
            "padded-signature-rejected",
            6,
            "signature.encoding_invalid",
            mutate(
                candidate_sig + ("signature_base64url",),
                promotion(base)["candidate"]["signature"]["payload"]["signature_base64url"] + "=",
            ),
        )
    )
    canonical_signature = promotion(base)["candidate"]["signature"]["payload"][
        "signature_base64url"
    ]
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    last_index = alphabet.index(canonical_signature[-1])
    alternate = canonical_signature[:-1] + alphabet[last_index + 1]
    cases.append(
        proposal_case(
            base,
            base_anchor,
            "noncanonical-pad-bits-rejected",
            6,
            "signature.encoding_invalid",
            mutate(candidate_sig + ("signature_base64url",), alternate),
        )
    )
    cases.append(
        proposal_case(
            base,
            base_anchor,
            "low-order-r-rejected",
            6,
            "signature.encoding_invalid",
            mutate(
                candidate_sig + ("signature_base64url",),
                raw_base64url(b"\x01" + b"\x00" * 31 + b"\x00" * 32),
            ),
        )
    )
    l_value = 2**252 + 27742317777372353535851937790883648493
    base_signature = decode_base64url(
        promotion(base)["candidate"]["signature"]["payload"]["signature_base64url"]
    )
    for suffix, scalar, expected in [
        ("l-minus-one", l_value - 1, "signature.invalid"),
        ("l", l_value, "signature.encoding_invalid"),
        ("l-plus-one", l_value + 1, "signature.encoding_invalid"),
    ]:
        encoded = raw_base64url(base_signature[:32] + scalar.to_bytes(32, "little"))
        cases.append(
            proposal_case(
                base,
                base_anchor,
                f"signature-s-{suffix}",
                6,
                expected,
                mutate(candidate_sig + ("signature_base64url",), encoded),
            )
        )
    invalid_equation = promotion(base)["evidence"][0]["signature"]["payload"]["signature_base64url"]
    cases.append(
        proposal_case(
            base,
            base_anchor,
            "invalid-signature-equation",
            6,
            "signature.invalid",
            mutate(candidate_sig + ("signature_base64url",), invalid_equation),
        )
    )

    torsion_points = [
        "0100000000000000000000000000000000000000000000000000000000000000",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "0000000000000000000000000000000000000000000000000000000000000080",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    ]
    for index, point in enumerate(torsion_points):
        raw_signature = bytes.fromhex(point) + base_signature[32:]
        cases.append(
            proposal_case(
                base,
                base_anchor,
                f"torsion-r-{index}-rejected",
                6,
                "signature.encoding_invalid",
                mutate(candidate_sig + ("signature_base64url",), raw_base64url(raw_signature)),
            )
        )

    mixed_order = bytes.fromhex("95" + "99" * 31)
    mixed_signature = mixed_order + base_signature[32:]
    cases.append(
        proposal_case(
            base,
            base_anchor,
            "mixed-order-r-rejected",
            6,
            "signature.encoding_invalid",
            mutate(candidate_sig + ("signature_base64url",), raw_base64url(mixed_signature)),
        )
    )

    noncanonical_y = bytes.fromhex("ed" + "ff" * 30 + "7f")
    cases.append(
        proposal_case(
            base,
            base_anchor,
            "noncanonical-r-rejected",
            6,
            "signature.encoding_invalid",
            mutate(
                candidate_sig + ("signature_base64url",),
                raw_base64url(noncanonical_y + base_signature[32:]),
            ),
        )
    )

    def replace_builder_public(value: dict[str, Any], encoded: str) -> None:
        body = promotion(value)
        descriptor = next(
            item
            for item in body["identity_context"]["payload"]["principals"]
            if item["principal_id"] == "principal:builder"
        )
        binding = descriptor["keys"][0]
        binding["public_key_base64url"] = encoded
        binding["key_id"] = key_id_from_public(encoded)
        body["candidate"]["signature"]["payload"]["key_id"] = binding["key_id"]

    for case_id, encoded in [
        ("mixed-order-public-key-rejected", raw_base64url(mixed_order)),
        ("noncanonical-public-key-rejected", raw_base64url(noncanonical_y)),
    ]:
        cases.append(
            proposal_case(
                base,
                base_anchor,
                case_id,
                6,
                "signature.encoding_invalid",
                lambda value, encoded=encoded: replace_builder_public(value, encoded),
                reanchor=True,
            )
        )

    canonical_public = public_key("builder")
    public_last = alphabet.index(canonical_public[-1])
    alternate_public = canonical_public[:-1] + alphabet[public_last + 1]
    cases.append(
        proposal_case(
            base,
            base_anchor,
            "noncanonical-public-key-pad-bits",
            6,
            "signature.encoding_invalid",
            lambda value: replace_builder_public(value, alternate_public),
            reanchor=True,
        )
    )

    # Stage 7: exact evidence binding with a fresh valid signature.
    cases.append(
        proposal_case(
            base,
            base_anchor,
            "evidence-adjacent-candidate",
            7,
            "evidence.subject_digest_mismatch",
            mutate(evidence_payload + ("subject_candidate_digest",), "a" * 64),
            refresh=True,
        )
    )

    # Stage 8: grant scope, time, revocation, and delegation with fresh signatures.
    grant_cases = [
        ("grant-wrong-audience", "audience", "other-audience", "grant.audience_mismatch"),
        ("grant-wrong-domain", "trust_domain_id", "trust-domain:other", "grant.context_mismatch"),
        (
            "grant-wrong-namespace",
            "capability_namespace",
            "variaxiom-capability/v9",
            "grant.context_mismatch",
        ),
        ("grant-wrong-constitution", "constitution_digest", "a" * 64, "grant.context_mismatch"),
        ("grant-wrong-lineage", "lineage_id", "lineage:other", "grant.context_mismatch"),
        ("grant-wrong-subject", "subject_candidate_digest", "a" * 64, "grant.subject_mismatch"),
        (
            "grant-capability-superset",
            "capabilities",
            ["filesystem.write", "network.example.com"],
            "grant.capability_mismatch",
        ),
        (
            "grant-capability-partial",
            "capabilities",
            ["filesystem.write"],
            "grant.capability_mismatch",
        ),
        (
            "grant-interval-invalid",
            "not_before_unix_s",
            EVALUATION_TIME + 3600,
            "grant.interval_invalid",
        ),
        ("grant-not-yet-valid", "not_before_unix_s", EVALUATION_TIME + 1, "grant.not_yet_valid"),
        ("grant-delegation-forbidden", "delegable", True, "grant.delegation_forbidden"),
    ]
    for case_id, field, replacement, code in grant_cases:
        cases.append(
            proposal_case(
                base,
                base_anchor,
                case_id,
                8,
                code,
                mutate(grant_payload + (field,), replacement),
                refresh=True,
            )
        )

    def expired_grant(value: dict[str, Any]) -> None:
        grant = promotion(value)["authority_grant"]["envelope"]["payload"]
        grant["not_before_unix_s"] = EVALUATION_TIME - 10
        grant["expires_at_unix_s"] = EVALUATION_TIME

    cases.append(
        proposal_case(
            base, base_anchor, "grant-expired", 8, "grant.expired", expired_grant, refresh=True
        )
    )

    def omit_grant(value: dict[str, Any]) -> None:
        del promotion(value)["authority_grant"]
        resign_all(value)

    cases.append(
        proposal_case(
            base,
            base_anchor,
            "grant-required-for-delta",
            8,
            "grant.capability_mismatch",
            omit_grant,
        )
    )

    def zero_delta_without_grant(value: dict[str, Any]) -> None:
        body = promotion(value)
        body["candidate"]["envelope"]["payload"]["requested_capabilities"] = []
        del body["authority_grant"]
        refresh_candidate_bindings(value)

    cases.append(
        proposal_case(
            base,
            base_anchor,
            "zero-delta-without-grant",
            11,
            None,
            zero_delta_without_grant,
            decision_status="accepted",
        )
    )

    def redundant_zero_delta_grant(value: dict[str, Any]) -> None:
        promotion(value)["candidate"]["envelope"]["payload"]["requested_capabilities"] = []
        refresh_candidate_bindings(value)

    cases.append(
        proposal_case(
            base,
            base_anchor,
            "zero-delta-redundant-grant",
            8,
            "grant.capability_mismatch",
            redundant_zero_delta_grant,
        )
    )

    revoked_grant_anchor = copy.deepcopy(base_anchor)
    revoked_grant_anchor["revoked_grant_ids"] = [
        "grant:sha256:" + digest(promotion(base)["authority_grant"]["envelope"])
    ]
    cases.append(
        make_case("revoked-authority-grant", 5, base, revoked_grant_anchor, "grant.revoked")
    )

    # Stage 9: exact constitution envelope and content artifact.
    def constitution_context_mismatch(value: dict[str, Any]) -> None:
        body = promotion(value)
        body["constitution"]["envelope"]["payload"]["max_candidate_cost_micro_usd"] = 101
        body["authority_grant"]["envelope"]["payload"]["constitution_digest"] = digest(
            body["constitution"]["envelope"]
        )
        resign_all(value)

    cases.append(
        proposal_case(
            base,
            base_anchor,
            "constitution-context-mismatch",
            9,
            "constitution.context_mismatch",
            constitution_context_mismatch,
        )
    )
    cases.append(
        proposal_case(
            base,
            base_anchor,
            "constitution-artifact-mismatch",
            9,
            "constitution.artifact_mismatch",
            mutate(
                ("payload", "promotion_input", "payload", "constitution", "artifact_hash"), "a" * 64
            ),
            refresh=True,
        )
    )

    # Stage 10 policy rejection is a verified proposal with a rejected decision.
    def policy_cost(value: dict[str, Any]) -> None:
        set_path(value, candidate_payload + ("estimated_cost_micro_usd",), 101)
        refresh_candidate_bindings(value)

    def policy_baseline(value: dict[str, Any]) -> None:
        set_path(value, candidate_payload + ("baseline_capabilities",), ["network.example.com"])
        refresh_candidate_bindings(value)

    cases.append(
        proposal_case(
            base,
            base_anchor,
            "policy-cost-rejected",
            10,
            None,
            policy_cost,
            decision_status="rejected",
            notes="Policy rejection is a verified, signed result rather than a verifier error.",
        )
    )
    cases.append(
        proposal_case(
            base,
            base_anchor,
            "policy-baseline-mismatch",
            10,
            None,
            policy_baseline,
            decision_status="rejected",
        )
    )

    # Stage 11 decision content and selector verification.
    def wrong_decision(value: dict[str, Any]) -> None:
        value["payload"]["decision"]["payload"]["status"] = "rejected"
        value["payload"]["decision"]["payload"]["reasons"] = ["artifact.not_verified"]
        value["payload"]["selector_signature"] = signature(
            value["payload"]["decision"], "promotion-decision", "selector"
        )

    cases.append(
        proposal_case(
            base,
            base_anchor,
            "decision-content-mismatch",
            11,
            "decision.content_mismatch",
            wrong_decision,
        )
    )
    cases.append(
        proposal_case(
            base,
            base_anchor,
            "selector-signature-invalid",
            11,
            "signature.invalid",
            mutate(
                ("payload", "selector_signature", "payload", "signature_base64url"),
                invalid_equation,
            ),
        )
    )

    # Multi-fault vectors freeze precedence rather than relying on implementation traversal.
    def multi_stage_four(value: dict[str, Any]) -> None:
        signature_payload = promotion(value)["candidate"]["signature"]["payload"]
        signature_payload["signed_digest"] = "a" * 64
        signature_payload["signed_kind"] = "evidence"

    cases.append(
        proposal_case(
            base,
            base_anchor,
            "precedence-digest-before-kind",
            4,
            "signature.digest_mismatch",
            multi_stage_four,
        )
    )

    def multi_stage_six(value: dict[str, Any]) -> None:
        signature_payload = promotion(value)["candidate"]["signature"]["payload"]
        signature_payload["algorithm"] = "Ed448"
        signature_payload["signature_base64url"] = "invalid="

    cases.append(
        proposal_case(
            base,
            base_anchor,
            "precedence-algorithm-before-encoding",
            6,
            "signature.algorithm_unsupported",
            multi_stage_six,
        )
    )

    def multi_stage_eight(value: dict[str, Any]) -> None:
        grant = promotion(value)["authority_grant"]["envelope"]["payload"]
        grant["audience"] = "other-audience"
        grant["trust_domain_id"] = "trust-domain:other"
        resign_all(value)

    cases.append(
        proposal_case(
            base,
            base_anchor,
            "precedence-audience-before-context",
            8,
            "grant.audience_mismatch",
            multi_stage_eight,
        )
    )

    def multi_stage_nine(value: dict[str, Any]) -> None:
        body = promotion(value)
        body["constitution"]["envelope"]["payload"]["max_candidate_cost_micro_usd"] = 101
        body["constitution"]["artifact_hash"] = "a" * 64
        body["authority_grant"]["envelope"]["payload"]["constitution_digest"] = digest(
            body["constitution"]["envelope"]
        )
        resign_all(value)

    cases.append(
        proposal_case(
            base,
            base_anchor,
            "precedence-constitution-context-before-artifact",
            9,
            "constitution.context_mismatch",
            multi_stage_nine,
        )
    )

    def multi_stage_eleven(value: dict[str, Any]) -> None:
        wrong_decision(value)
        value["payload"]["selector_signature"]["payload"]["signature_base64url"] = invalid_equation

    cases.append(
        proposal_case(
            base,
            base_anchor,
            "precedence-decision-before-selector-signature",
            11,
            "decision.content_mismatch",
            multi_stage_eleven,
        )
    )

    def selector_domain(value: dict[str, Any]) -> None:
        value["payload"]["selector_signature"] = signature(
            value["payload"]["decision"],
            "promotion-decision",
            "selector",
            trust_domain_id="trust-domain:other",
        )

    cases.append(
        proposal_case(
            base,
            base_anchor,
            "selector-domain-mismatch",
            11,
            "signature.domain_mismatch",
            selector_domain,
        )
    )

    def selector_wrong_role(value: dict[str, Any]) -> None:
        value["payload"]["selector_signature"] = signature(
            value["payload"]["decision"], "promotion-decision", "verifier"
        )

    cases.append(
        proposal_case(
            base,
            base_anchor,
            "selector-role-missing",
            11,
            "identity.role_missing",
            selector_wrong_role,
        )
    )

    # Historical replay is reproducible but never authorizing.
    cases.append(
        make_case(
            "historical-replay-nonauthorizing",
            11,
            base,
            base_anchor,
            None,
            decision_status="accepted",
            entrypoint="replay-historical",
            authorizing=False,
        )
    )

    base_body = promotion(base)
    identity0 = base_body["identity_context"]
    authorization0 = base_body["authorization_context"]

    identity1 = next_identity(identity0, 1)
    identity2 = next_identity(identity1, 2)
    identity3 = next_identity(identity2, 3)
    positive_steps = [
        {
            "next_identity_context": identity1,
            "next_authorization_context": authorization0,
            "trusted_now_unix_s": EVALUATION_TIME + 1,
        },
        {
            "next_identity_context": identity2,
            "next_authorization_context": authorization0,
            "trusted_now_unix_s": EVALUATION_TIME + 2,
        },
        {
            "next_identity_context": identity3,
            "next_authorization_context": authorization0,
            "trusted_now_unix_s": EVALUATION_TIME + 3,
        },
    ]
    cases.append(
        history_case("anchor-three-step-advance", base, base_anchor, positive_steps, None, 5)
    )

    skipped = next_identity(identity0, 2)
    cases.append(
        history_case(
            "anchor-sequence-skip",
            base,
            base_anchor,
            [
                {
                    "next_identity_context": skipped,
                    "next_authorization_context": authorization0,
                    "trusted_now_unix_s": EVALUATION_TIME + 2,
                }
            ],
            "identity.context_untrusted",
            3,
        )
    )
    wrong_previous = next_identity(identity0, 1, previous_digest="a" * 64)
    cases.append(
        history_case(
            "anchor-wrong-predecessor",
            base,
            base_anchor,
            [
                {
                    "next_identity_context": wrong_previous,
                    "next_authorization_context": authorization0,
                    "trusted_now_unix_s": EVALUATION_TIME + 1,
                }
            ],
            "identity.context_untrusted",
            3,
        )
    )
    decreasing_time = next_identity(identity0, 1, evaluation_time=EVALUATION_TIME - 1)
    cases.append(
        history_case(
            "anchor-time-rollback",
            base,
            base_anchor,
            [
                {
                    "next_identity_context": decreasing_time,
                    "next_authorization_context": authorization0,
                    "trusted_now_unix_s": EVALUATION_TIME - 1,
                }
            ],
            "identity.context_stale",
            3,
        )
    )

    revoke_key_1 = next_identity(identity0, 1, revoked_key_ids=[key_id("builder")])
    principals_without_builder = [
        item
        for item in revoke_key_1["payload"]["principals"]
        if item["principal_id"] != "principal:builder"
    ]
    revoke_key_2 = next_identity(
        revoke_key_1, 2, principals=principals_without_builder, revoked_key_ids=[]
    )
    revoke_key_3 = next_identity(
        revoke_key_2,
        3,
        principals=identity0["payload"]["principals"],
        revoked_key_ids=[],
    )
    cases.append(
        history_case(
            "revoked-key-washout-reintroduction",
            base,
            base_anchor,
            [
                {
                    "next_identity_context": revoke_key_1,
                    "next_authorization_context": authorization0,
                    "trusted_now_unix_s": EVALUATION_TIME + 1,
                },
                {
                    "next_identity_context": revoke_key_2,
                    "next_authorization_context": authorization0,
                    "trusted_now_unix_s": EVALUATION_TIME + 2,
                },
                {
                    "next_identity_context": revoke_key_3,
                    "next_authorization_context": authorization0,
                    "trusted_now_unix_s": EVALUATION_TIME + 3,
                },
            ],
            "signature.key_revoked",
            5,
        )
    )

    old_grant_id = "grant:sha256:" + digest(base_body["authority_grant"]["envelope"])
    revoke_grant_1 = next_identity(identity0, 1, revoked_grant_ids=[old_grant_id])
    revoke_grant_2 = next_identity(revoke_grant_1, 2, revoked_grant_ids=[])
    revoke_grant_3 = next_identity(revoke_grant_2, 3, revoked_grant_ids=[])
    revoked_probe = copy.deepcopy(base)
    promotion(revoked_probe)["identity_context"] = revoke_grant_3
    resign_all(revoked_probe)
    cases.append(
        history_case(
            "revoked-grant-washout-replay",
            base,
            base_anchor,
            [
                {
                    "next_identity_context": revoke_grant_1,
                    "next_authorization_context": authorization0,
                    "trusted_now_unix_s": EVALUATION_TIME + 1,
                },
                {
                    "next_identity_context": revoke_grant_2,
                    "next_authorization_context": authorization0,
                    "trusted_now_unix_s": EVALUATION_TIME + 2,
                },
                {
                    "next_identity_context": revoke_grant_3,
                    "next_authorization_context": authorization0,
                    "trusted_now_unix_s": EVALUATION_TIME + 3,
                },
            ],
            "grant.revoked",
            5,
            probe=revoked_probe,
        )
    )

    reassigned_principals = copy.deepcopy(identity0["payload"]["principals"])
    builder_descriptor = next(
        item for item in reassigned_principals if item["principal_id"] == "principal:builder"
    )
    verifier_descriptor = next(
        item for item in reassigned_principals if item["principal_id"] == "principal:verifier"
    )
    old_builder_binding = builder_descriptor["keys"][0]
    builder_descriptor["keys"] = [synthetic_binding(3000)]
    verifier_descriptor["keys"].append(old_builder_binding)
    verifier_descriptor["keys"].sort(key=lambda item: item["key_id"])
    reassigned_identity = next_identity(identity0, 1, principals=reassigned_principals)
    cases.append(
        history_case(
            "historical-key-reassignment",
            base,
            base_anchor,
            [
                {
                    "next_identity_context": reassigned_identity,
                    "next_authorization_context": authorization0,
                    "trusted_now_unix_s": EVALUATION_TIME + 1,
                }
            ],
            "identity.key_ambiguous",
            5,
        )
    )
    return sorted(cases, key=lambda item: (item["stage"], item["case_id"]))


def render(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    base, anchor = build()
    cases = build_cases(base, anchor)
    manifest = {
        "manifest_version": "m2.1-conformance-manifest/v2",
        "spec_revision": hashlib.sha256(SPEC.read_bytes()).hexdigest(),
        "base_fixture": "base-attested-proposal.json",
        "cases": [
            {
                "case_id": item["case_id"],
                "fixture": f"cases/{item['case_id']}.json",
                "stage": item["stage"],
            }
            for item in cases
        ],
    }
    golden = vectors(base)[-1]
    outputs = {
        OUT / "base-attested-proposal.json": render(base),
        OUT / "golden-signature.json": render(golden),
        OUT / "manifest.json": render(manifest),
        **{CASES / f"{item['case_id']}.json": render(item) for item in cases},
    }
    existing_cases = set(CASES.glob("*.json")) if CASES.exists() else set()
    stale_extra = existing_cases - set(outputs)
    stale = [
        path for path, data in outputs.items() if not path.exists() or path.read_bytes() != data
    ]
    if args.check:
        for path in [*stale, *sorted(stale_extra)]:
            print(f"stale: {path.relative_to(ROOT)}")
        if stale or stale_extra:
            return 1
        print(f"M2.1 conformance corpus is current ({len(cases)} cases).")
        return 0
    CASES.mkdir(parents=True, exist_ok=True)
    for path in stale_extra:
        path.unlink()
    for path, data in outputs.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        print(path.relative_to(ROOT))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
