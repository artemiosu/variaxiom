//! Golden cross-language promotion vectors.

use std::fs;
use std::path::PathBuf;

use serde::Deserialize;
use variaxiom_kernel::PromotionGate;
use variaxiom_protocol::{
    Candidate, Constitution, Evidence, PROMOTION_INPUT_VERSION, PromotionContext,
    PromotionDecision, PromotionInput, canonical_digest, canonical_json,
    parse_promotion_decision_envelope, parse_promotion_input_envelope,
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    case_id: String,
    protocol_version: String,
    constitution: Constitution,
    candidate: Candidate,
    evidence: Vec<Evidence>,
    context: PromotionContext,
    authority_grant_id: Option<String>,
    expected: Expected,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Expected {
    decision: PromotionDecision,
    input_envelope_json: String,
    input_digest: String,
    decision_envelope_json: String,
    decision_digest: String,
}

fn fixture_paths() -> Vec<PathBuf> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("fixtures/conformance/v1/promotion");
    let mut paths = fs::read_dir(root)
        .expect("shared fixture directory exists")
        .map(|entry| entry.expect("readable fixture entry").path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect::<Vec<_>>();
    paths.sort();
    paths
}

#[test]
fn shared_promotion_vectors_match_exactly() {
    let paths = fixture_paths();
    assert!(
        !paths.is_empty(),
        "at least one conformance fixture is required"
    );
    for path in paths {
        let fixture: Fixture = variaxiom_protocol::parse_json_strict(
            &fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display())),
        )
        .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()));
        assert_eq!(fixture.protocol_version, PROMOTION_INPUT_VERSION);

        let input = PromotionInput::new(
            fixture.candidate.clone(),
            fixture.evidence.clone(),
            fixture.context.clone(),
            fixture.authority_grant_id.clone(),
            fixture.constitution.clone(),
        );
        let input_envelope = input.envelope();
        let input_json = String::from_utf8(
            canonical_json(&input_envelope).expect("typed fixture input is canonical"),
        )
        .expect("canonical JSON is UTF-8");
        assert_eq!(
            input_json, fixture.expected.input_envelope_json,
            "{}",
            fixture.case_id
        );
        assert_eq!(
            canonical_digest(&input_envelope).expect("typed fixture input is canonical"),
            fixture.expected.input_digest,
            "{}",
            fixture.case_id
        );
        let parsed_input =
            parse_promotion_input_envelope(fixture.expected.input_envelope_json.as_bytes())
                .expect("expected input envelope is strict and valid");
        assert_eq!(parsed_input.payload, input, "{}", fixture.case_id);

        let decision = PromotionGate::new(fixture.constitution)
            .decide(
                &fixture.candidate,
                &fixture.evidence,
                &fixture.context,
                fixture.authority_grant_id.as_deref(),
            )
            .expect("typed fixture input is canonical");
        assert_eq!(decision, fixture.expected.decision, "{}", fixture.case_id);
        let decision_envelope = decision.envelope();
        let decision_json = String::from_utf8(
            canonical_json(&decision_envelope).expect("typed decision is canonical"),
        )
        .expect("canonical JSON is UTF-8");
        assert_eq!(
            decision_json, fixture.expected.decision_envelope_json,
            "{}",
            fixture.case_id
        );
        assert_eq!(
            canonical_digest(&decision_envelope).expect("typed decision is canonical"),
            fixture.expected.decision_digest,
            "{}",
            fixture.case_id
        );
        let parsed_decision =
            parse_promotion_decision_envelope(fixture.expected.decision_envelope_json.as_bytes())
                .expect("expected decision envelope is strict and valid");
        assert_eq!(parsed_decision.payload, decision, "{}", fixture.case_id);
    }
}
