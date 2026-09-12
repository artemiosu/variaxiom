//! Frozen M2.1 stage-ten policy tests.

use std::fs;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use variaxiom_kernel::inspect_m2_stage_ten;
use variaxiom_protocol::{DecisionStatus, M2Entrypoint, parse_json_strict};

#[derive(Deserialize)]
struct Manifest {
    cases: Vec<ManifestEntry>,
}

#[derive(Deserialize)]
struct ManifestEntry {
    fixture: String,
}

#[derive(Deserialize)]
struct Case {
    case_id: String,
    entrypoint: String,
    input_base64url: String,
    #[serde(default)]
    trusted_anchor: Option<serde_json::Value>,
    expected: Expected,
}

#[derive(Deserialize)]
struct Expected {
    code: Option<String>,
    reached_stage: u8,
    #[serde(default)]
    expected_anchor: Option<serde_json::Value>,
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("kernel crate has repository parent")
        .to_path_buf()
}

fn load_case(path: &Path) -> Case {
    serde_json::from_slice(&fs::read(path).expect("fixture is readable"))
        .expect("fixture has case shape")
}

fn input(case: &Case) -> Vec<u8> {
    URL_SAFE_NO_PAD
        .decode(&case.input_base64url)
        .expect("fixture input uses base64url")
}

fn entrypoint(case: &Case) -> M2Entrypoint {
    match case.entrypoint.as_str() {
        "evaluate-new" => M2Entrypoint::EvaluateNew,
        "verify-attested-proposal" => M2Entrypoint::VerifyAttestedProposal,
        "replay-historical" => M2Entrypoint::ReplayHistorical,
        "advance-anchor-history" => M2Entrypoint::AdvanceAnchorHistory,
        other => panic!("unexpected stage-ten fixture entrypoint: {other}"),
    }
}

fn proposal<'a>(value: &'a serde_json::Value, case: &Case) -> &'a serde_json::Value {
    if case.entrypoint == "evaluate-new" {
        value
    } else if case.entrypoint == "advance-anchor-history" {
        &value["probe_attested_proposal"]
    } else {
        value
    }
}

#[test]
fn every_frozen_stage_ten_policy_decision_matches() {
    let repository = root();
    let manifest: Manifest = serde_json::from_slice(
        &fs::read(repository.join("fixtures/conformance/v2/manifest.json"))
            .expect("manifest is readable"),
    )
    .expect("manifest has expected shape");
    let cases = manifest
        .cases
        .iter()
        .map(|entry| {
            load_case(
                &repository
                    .join("fixtures/conformance/v2")
                    .join(&entry.fixture),
            )
        })
        .filter(|case| case.expected.reached_stage > 9)
        .collect::<Vec<_>>();
    assert_eq!(cases.len(), 51);

    let mut mismatched_supplied_decisions = 0;
    let mut policy_rejections = 0;
    for case in cases {
        let raw = input(&case);
        let result = inspect_m2_stage_ten(&raw, entrypoint(&case), case.trusted_anchor.as_ref())
            .unwrap_or_else(|error| {
                panic!(
                    "{}: {} at stage {}",
                    case.case_id,
                    error.code(),
                    error.stage()
                )
            });
        assert!(!result.authorizing(), "{}", case.case_id);
        assert_eq!(
            result.resulting_anchor(),
            case.expected.expected_anchor.as_ref(),
            "{}",
            case.case_id
        );
        let computed =
            serde_json::to_value(result.decision().envelope()).expect("typed decision serializes");
        let value: serde_json::Value = parse_json_strict(&raw).expect("fixture parses strictly");
        if case.entrypoint != "evaluate-new" {
            let supplied = &proposal(&value, &case)["payload"]["decision"];
            if case.expected.code.as_deref() == Some("decision.content_mismatch") {
                mismatched_supplied_decisions += 1;
                assert_ne!(&computed, supplied, "{}", case.case_id);
            } else {
                assert_eq!(&computed, supplied, "{}", case.case_id);
            }
        }
        if result.decision().status == DecisionStatus::Rejected {
            policy_rejections += 1;
        }
    }
    assert_eq!(mismatched_supplied_decisions, 2);
    assert_eq!(policy_rejections, 3);
}
