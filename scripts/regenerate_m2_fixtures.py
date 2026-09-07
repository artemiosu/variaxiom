#!/usr/bin/env python3
"""Generate the frozen M2.1 schema/conformance seed without private key material."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "fixtures/conformance/v2"
SPEC = ROOT / "docs/specs/m2.1-identity-grants-signatures.md"
ENVELOPE_VERSION = "variaxiom-envelope/v1"
DOMAIN = "trust-domain:example"

KEYS = {
    "builder": (
        "key:sha256:123a695f5133c0017e23ec2445f26a338fd42fdef1e7d4e4e2648e6f9ceb9e4a",
        "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik",
    ),
    "issuer": (
        "key:sha256:42192effec83331231d11e7460b0b5e1d700c4ec62db434028b0f834e5849142",
        "gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q",
    ),
    "selector": (
        "key:sha256:834e7202571554f42301cbafee31f38d7bdfd7232540dfc811902047b660d2d0",
        "7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E",
    ),
    "verifier": (
        "key:sha256:2d91a8fdb51ae7a99a5da1bf88770e5d5830dfcba7d6e8c060d6ad56fbcc17de",
        "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w",
    ),
}

SIGNATURES = {
    "builder": "tZeLwNZXvNFJNkqeJsv-jvn_Qk85EVYYD3KhDVTUCGatKMhhwsc64t5MP8VtHErICaFNdJhzwjSWKNFEIEHzDA",
    "verifier": "BvY1G9QHGdvmhs3wB7-065r-BmWjUqvwptawJQ9MqmRK5EBlBpwIg7kkbGRf__IrKZ1WLWAHLqHc5jUANX-fAg",
    "issuer": "EdvnhWaiYhPvJpXHzC0OAzfwSa9sznEVSIqbhf1kEejcDn31Q4_O9ecJg8sCgzr0OY8j6GmQ67fOYu-uqph8CQ",
    "selector": "zJvkFvYT9kNSDeZcLFrcQF6_UebCLxRgiDmL9JtxEZwNDJoeAPeTdymi4bKRInw-CQbWqk6BcQiSTtFvcsWtDQ",
}


def canonical_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def digest(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def envelope(kind: str, payload: dict[str, Any]) -> dict[str, Any]:
    return {"envelope_version": ENVELOPE_VERSION, "kind": kind, "payload": payload}


def signature(target: object, signed_kind: str, principal: str) -> dict[str, Any]:
    return envelope(
        "detached-signature",
        {
            "signature_version": "detached-signature/v1",
            "algorithm": "Ed25519",
            "trust_domain_id": DOMAIN,
            "principal_id": f"principal:{principal}",
            "key_id": KEYS[principal][0],
            "signed_kind": signed_kind,
            "signed_digest": digest(target),
            "signature_base64url": SIGNATURES[principal],
        },
    )


def build() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
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
    constitution_artifact = hashlib.sha256(canonical_bytes(constitution["payload"])).hexdigest()
    roles = {
        "builder": "candidate-proposer",
        "issuer": "authority-issuer",
        "selector": "promotion-selector",
        "verifier": "evidence-verifier",
    }
    principals = [
        {
            "principal_version": "principal/v1",
            "principal_id": f"principal:{name}",
            "roles": [roles[name]],
            "keys": [
                {
                    "key_binding_version": "key-binding/v1",
                    "algorithm": "Ed25519",
                    "key_id": KEYS[name][0],
                    "public_key_base64url": KEYS[name][1],
                }
            ],
        }
        for name in sorted(KEYS)
    ]
    identity = envelope(
        "identity-context",
        {
            "identity_context_version": "identity-context/v1",
            "trust_domain_id": DOMAIN,
            "snapshot_sequence": 0,
            "previous_snapshot_digest": None,
            "evaluation_time_unix_s": 1788739200,
            "principals": principals,
            "revoked_key_ids": [],
            "revoked_grant_ids": [],
        },
    )
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
            "not_before_unix_s": 1788739200,
            "expires_at_unix_s": 1788742800,
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
    decision = envelope(
        "promotion-decision",
        {
            "candidate_id": "candidate:bounded-network",
            "status": "accepted",
            "reasons": ["promotion.accepted"],
            "evidence_ids": ["evidence:unit"],
            "input_digest": digest(promotion_input),
            "constitution_version": "constitution/v1",
            "gate_version": "proof-gate/v1",
        },
    )
    selector_signature = signature(decision, "promotion-decision", "selector")
    attested = envelope(
        "attested-proposal",
        {
            "proposal_version": "attested-proposal/v1",
            "promotion_input": promotion_input,
            "decision": decision,
            "selector_signature": selector_signature,
        },
    )
    anchor = {
        "trust_domain_id": DOMAIN,
        "current_identity_context_digest": digest(identity),
        "current_authorization_context_digest": digest(authorization),
        "current_snapshot_sequence": 0,
        "trusted_now_unix_s": 1788739200,
        "key_ownership_registry": {KEYS[name][0]: f"principal:{name}" for name in sorted(KEYS)},
        "revoked_key_ids": [],
        "revoked_grant_ids": [],
    }
    selector_payload = selector_signature["payload"]
    message = "\n".join(
        [
            "variaxiom-signature/v1",
            "Ed25519",
            DOMAIN,
            "principal:selector",
            KEYS["selector"][0],
            "promotion-decision",
            digest(decision),
            "",
        ]
    ).encode("ascii")
    golden = {
        "vector_version": "m2.1-signature-vector/v1",
        "target_envelope": decision,
        "target_digest": digest(decision),
        "trust_domain_id": DOMAIN,
        "principal_id": "principal:selector",
        "key_id": KEYS["selector"][0],
        "public_key_base64url": KEYS["selector"][1],
        "signed_kind": "promotion-decision",
        "message_hex": message.hex(),
        "signature_base64url": selector_payload["signature_base64url"],
        "expected": "verified",
    }
    return attested, anchor, golden


def raw_base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def manifest(anchor: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "manifest_version": "m2.1-conformance-manifest/v1",
        "spec_revision": hashlib.sha256(SPEC.read_bytes()).hexdigest(),
        "base_fixture": "base-attested-proposal.json",
        "trusted_anchor": anchor,
        "cases": [
            {
                "case_id": "bounded-signed-proposal",
                "stage": 11,
                "operation": "base",
                "expected_status": "verified",
                "expected_code": None,
            },
            {
                "case_id": "utf8-bom-rejected",
                "stage": 1,
                "operation": "raw-base64url",
                "raw_base64url": raw_base64url(b"\xef\xbb\xbf{}"),
                "expected_status": "rejected",
                "expected_code": "input.encoding_invalid",
            },
            {
                "case_id": "utf16-rejected",
                "stage": 1,
                "operation": "raw-base64url",
                "raw_base64url": raw_base64url(b"\xff\xfe{\x00}\x00"),
                "expected_status": "rejected",
                "expected_code": "input.encoding_invalid",
            },
            {
                "case_id": "lone-surrogate-rejected",
                "stage": 1,
                "operation": "raw-base64url",
                "raw_base64url": raw_base64url(b'{"x":"\\ud800"}'),
                "expected_status": "rejected",
                "expected_code": "input.encoding_invalid",
            },
            {
                "case_id": "depth-limit-rejected",
                "stage": 1,
                "operation": "raw-base64url",
                "raw_base64url": raw_base64url(b"[" * 65 + b"0" + b"]" * 65),
                "expected_status": "rejected",
                "expected_code": "input.limit_exceeded",
            },
            {
                "case_id": "duplicate-member-rejected",
                "stage": 1,
                "operation": "raw-base64url",
                "raw_base64url": raw_base64url(b'{"x":1,"x":2}'),
                "expected_status": "rejected",
                "expected_code": "input.duplicate_member",
            },
            {
                "case_id": "noncanonical-wire-rejected",
                "stage": 1,
                "operation": "raw-base64url",
                "raw_base64url": raw_base64url(b'{"x": 1}'),
                "expected_status": "rejected",
                "expected_code": "input.encoding_invalid",
            },
            {
                "case_id": "wrong-envelope-version",
                "stage": 2,
                "operation": "replace",
                "json_pointer": "/envelope_version",
                "value": "variaxiom-envelope/v9",
                "expected_status": "rejected",
                "expected_code": "input.version_unsupported",
            },
            {
                "case_id": "wrong-envelope-kind",
                "stage": 2,
                "operation": "replace",
                "json_pointer": "/kind",
                "value": "unknown-kind",
                "expected_status": "rejected",
                "expected_code": "input.kind_mismatch",
            },
            {
                "case_id": "unknown-field-rejected",
                "stage": 2,
                "operation": "add",
                "json_pointer": "/surprise",
                "value": True,
                "expected_status": "rejected",
                "expected_code": "input.schema_invalid",
            },
            {
                "case_id": "unsafe-integer-rejected",
                "stage": 1,
                "operation": "raw-base64url",
                "raw_base64url": raw_base64url(b'{"x":9007199254740992}'),
                "expected_status": "rejected",
                "expected_code": "input.encoding_invalid",
            },
            {
                "case_id": "unsorted-capabilities-rejected",
                "stage": 2,
                "operation": "replace",
                "json_pointer": "/payload/promotion_input/payload/candidate/envelope/payload/requested_capabilities",
                "value": ["z.example", "a.example"],
                "expected_status": "rejected",
                "expected_code": "input.schema_invalid",
            },
            {
                "case_id": "nonascii-principal-rejected",
                "stage": 2,
                "operation": "replace",
                "json_pointer": "/payload/promotion_input/payload/candidate/envelope/payload/proposer",
                "value": "principal:строитель",
                "expected_status": "rejected",
                "expected_code": "input.schema_invalid",
            },
            {
                "case_id": "padded-base64-rejected",
                "stage": 2,
                "operation": "replace",
                "json_pointer": "/payload/promotion_input/payload/identity_context/payload/principals/0/keys/0/public_key_base64url",
                "value": "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=",
                "expected_status": "rejected",
                "expected_code": "input.schema_invalid",
            },
            {
                "case_id": "missing-selector",
                "stage": 2,
                "operation": "remove",
                "json_pointer": "/payload/selector_signature",
                "expected_status": "rejected",
                "expected_code": "input.schema_invalid",
            },
            {
                "case_id": "wrong-signature-domain",
                "stage": 3,
                "operation": "replace",
                "json_pointer": "/payload/promotion_input/payload/candidate/signature/payload/trust_domain_id",
                "value": "trust-domain:other",
                "expected_status": "rejected",
                "expected_code": "signature.domain_mismatch",
            },
            {
                "case_id": "swapped-authorization-context",
                "stage": 3,
                "operation": "replace",
                "json_pointer": "/payload/promotion_input/payload/authorization_context/payload/lineage_id",
                "value": "lineage:attacker",
                "expected_status": "rejected",
                "expected_code": "authorization.context_untrusted",
            },
            {
                "case_id": "stale-identity-context",
                "stage": 3,
                "operation": "anchor-replace",
                "json_pointer": "/current_snapshot_sequence",
                "value": 1,
                "expected_status": "rejected",
                "expected_code": "identity.context_stale",
            },
            {
                "case_id": "actor-signature-mismatch",
                "stage": 5,
                "operation": "replace",
                "json_pointer": "/payload/promotion_input/payload/candidate/signature/payload/principal_id",
                "value": "principal:verifier",
                "expected_status": "rejected",
                "expected_code": "signature.principal_mismatch",
            },
            {
                "case_id": "revoked-proposer-key",
                "stage": 5,
                "operation": "anchor-replace",
                "json_pointer": "/revoked_key_ids",
                "value": [KEYS["builder"][0]],
                "expected_status": "rejected",
                "expected_code": "signature.key_revoked",
            },
            {
                "case_id": "low-order-signature-point",
                "stage": 6,
                "operation": "replace",
                "json_pointer": "/payload/promotion_input/payload/candidate/signature/payload/signature_base64url",
                "value": "A" * 86,
                "expected_status": "rejected",
                "expected_code": "signature.encoding_invalid",
            },
        ],
    }
    result["cases"] = sorted(result["cases"], key=lambda item: (item["stage"], item["case_id"]))
    return result


def render(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    attested, anchor, golden = build()
    outputs = {
        OUT / "base-attested-proposal.json": render(attested),
        OUT / "golden-signature.json": render(golden),
        OUT / "manifest.json": render(manifest(anchor)),
    }
    stale = [
        path for path, data in outputs.items() if not path.exists() or path.read_bytes() != data
    ]
    if args.check:
        if stale:
            for path in stale:
                print(f"stale: {path.relative_to(ROOT)}")
            return 1
        print("M2.1 schema/fixture seed is current.")
        return 0
    OUT.mkdir(parents=True, exist_ok=True)
    for path, data in outputs.items():
        path.write_bytes(data)
        print(path.relative_to(ROOT))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
