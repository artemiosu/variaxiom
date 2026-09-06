//! Canonical JSON profile tests shared by every protocol object.

use std::collections::{BTreeMap, BTreeSet};

use variaxiom_protocol::{
    Candidate, Constitution, DecisionStatus, MAX_CANONICAL_DEPTH, MAX_SAFE_INTEGER,
    PromotionContext, PromotionDecision, PromotionInput, canonical_digest, canonical_json,
    parse_json_strict,
};

#[test]
fn canonical_profile_sorts_keys_and_preserves_utf8() {
    let value = serde_json::json!({"z": 1, "a": "вариант", "nested": {"b": true, "a": null}});
    let bytes = canonical_json(&value).expect("fixture is inside canonical profile");
    assert_eq!(
        String::from_utf8(bytes).expect("canonical JSON is UTF-8"),
        r#"{"a":"вариант","nested":{"a":null,"b":true},"z":1}"#
    );
}

#[test]
fn canonical_profile_rejects_floats_and_large_integers() {
    assert!(canonical_json(&serde_json::json!({"value": 1.5})).is_err());
    assert!(canonical_json(&serde_json::json!({"value": MAX_SAFE_INTEGER + 1})).is_err());
    assert!(parse_json_strict::<serde_json::Value>(br#"{"value":1.5}"#).is_err());
    assert!(
        parse_json_strict::<serde_json::Value>(
            format!(r#"{{"value":{}}}"#, MAX_SAFE_INTEGER + 1).as_bytes()
        )
        .is_err()
    );
}

#[test]
fn digest_changes_when_a_bound_field_changes() {
    let base = Candidate {
        candidate_id: "candidate:1".into(),
        parent_id: "genome:0".into(),
        artifact_hash: "a".repeat(64),
        proposer: "agent:builder".into(),
        rollback_target: "genome:0".into(),
        baseline_capabilities: BTreeSet::new(),
        requested_capabilities: BTreeSet::new(),
        estimated_cost_micro_usd: 1,
        metadata: BTreeMap::new(),
    };
    let mut changed = base.clone();
    changed.estimated_cost_micro_usd = 2;
    assert_ne!(
        canonical_digest(&base).expect("canonical candidate"),
        canonical_digest(&changed).expect("canonical candidate")
    );
}

#[test]
fn unknown_wire_fields_fail_closed() {
    let raw = format!(
        r#"{{"candidate_id":"candidate:1","parent_id":"genome:0","artifact_hash":"{}","proposer":"agent:builder","rollback_target":"genome:0","baseline_capabilities":[],"requested_capabilities":[],"estimated_cost_micro_usd":1,"surprise":true}}"#,
        "a".repeat(64)
    );
    assert!(serde_json::from_str::<Candidate>(&raw).is_err());
}

#[test]
fn duplicate_protocol_set_members_fail_closed() {
    let candidate = format!(
        r#"{{"candidate_id":"candidate:1","parent_id":"genome:0","artifact_hash":"{}","proposer":"agent:builder","rollback_target":"genome:0","baseline_capabilities":["artifact.read","artifact.read"],"requested_capabilities":[],"estimated_cost_micro_usd":1}}"#,
        "a".repeat(64)
    );
    assert!(serde_json::from_str::<Candidate>(&candidate).is_err());

    let context = format!(
        r#"{{"known_lineage_ids":["genome:0","genome:0"],"known_artifact_hashes":["{}"],"authority_grants":{{}},"lineage_capabilities":{{"genome:0":[]}}}}"#,
        "a".repeat(64)
    );
    assert!(serde_json::from_str::<PromotionContext>(&context).is_err());

    let constitution = r#"{"version":"constitution/v1","mandatory_checks":["unit","unit"],"minimum_independent_verifiers":1,"max_candidate_cost_micro_usd":1,"require_known_parent":true,"require_rollback_target":true,"forbid_self_verification":true,"forbid_implicit_authority_escalation":true,"reject_any_failed_evidence":true}"#;
    assert!(serde_json::from_str::<Constitution>(constitution).is_err());

    let duplicate_grant = r#"{"known_lineage_ids":[],"known_artifact_hashes":[],"authority_grants":{"grant:test":["artifact.write","artifact.write"]},"lineage_capabilities":{}}"#;
    assert!(serde_json::from_str::<PromotionContext>(duplicate_grant).is_err());

    let unsorted = format!(
        r#"{{"candidate_id":"candidate:1","parent_id":"genome:0","artifact_hash":"{}","proposer":"agent:builder","rollback_target":"genome:0","baseline_capabilities":[],"requested_capabilities":["z","a"],"estimated_cost_micro_usd":1}}"#,
        "a".repeat(64)
    );
    assert!(serde_json::from_str::<Candidate>(&unsorted).is_err());
}

#[test]
fn unsorted_wire_evidence_fails_validation() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../fixtures/conformance/v1/promotion/bounded-accepted.json"
    ))
    .expect("fixture JSON");
    let mut input = serde_json::json!({
        "protocol_version": fixture["protocol_version"],
        "candidate": fixture["candidate"],
        "evidence": fixture["evidence"],
        "context": fixture["context"],
        "authority_grant_id": fixture["authority_grant_id"],
        "constitution": fixture["constitution"],
    });
    input["evidence"]
        .as_array_mut()
        .expect("evidence array")
        .reverse();
    let parsed: PromotionInput = serde_json::from_value(input).expect("typed input");
    assert!(parsed.validate().is_err());
}

#[test]
fn strict_parser_rejects_duplicate_keys_and_non_utf8_forms() {
    assert!(parse_json_strict::<serde_json::Value>(br#"{"metadata":{"x":1,"x":2}}"#).is_err());
    assert!(parse_json_strict::<serde_json::Value>(b"\xef\xbb\xbf{}").is_err());
    assert!(parse_json_strict::<serde_json::Value>(b"\xff\xfe{\x00}\x00").is_err());
    assert!(parse_json_strict::<serde_json::Value>(br#"{"value":"\ud800"}"#).is_err());
}

#[test]
fn canonical_profile_has_a_bounded_nesting_depth() {
    let mut value = serde_json::Value::Null;
    for _ in 0..MAX_CANONICAL_DEPTH {
        value = serde_json::json!({"value": value});
    }
    assert!(canonical_json(&value).is_ok());
    let too_deep = serde_json::json!({"value": value});
    assert!(canonical_json(&too_deep).is_err());

    let mut candidate = Candidate {
        candidate_id: "candidate:deep".into(),
        parent_id: "genome:0".into(),
        artifact_hash: "a".repeat(64),
        proposer: "agent:builder".into(),
        rollback_target: "genome:0".into(),
        baseline_capabilities: BTreeSet::new(),
        requested_capabilities: BTreeSet::new(),
        estimated_cost_micro_usd: 1,
        metadata: BTreeMap::new(),
    };
    candidate.metadata.insert("deep".into(), too_deep);
    assert!(canonical_json(&candidate).is_err());
}

#[test]
fn invalid_decision_cannot_receive_a_canonical_identity() {
    let invalid = PromotionDecision {
        candidate_id: "candidate:1".into(),
        status: DecisionStatus::Accepted,
        reasons: vec!["artifact.not_verified".into()],
        evidence_ids: Vec::new(),
        input_digest: "a".repeat(64),
        constitution_version: "constitution/v1".into(),
        gate_version: "proof-gate/v1".into(),
    };
    assert!(canonical_json(&invalid.envelope()).is_err());
}
