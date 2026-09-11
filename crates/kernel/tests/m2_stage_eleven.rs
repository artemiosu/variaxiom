//! Frozen M2.1 terminal decision and selector tests.

use std::fs;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use variaxiom_kernel::inspect_m2_stage_eleven;
use variaxiom_protocol::{DecisionStatus, M2Entrypoint};

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
    status: String,
    code: Option<String>,
    decision_status: String,
    authorizing: bool,
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
        "verify-attested-proposal" => M2Entrypoint::VerifyAttestedProposal,
        "replay-historical" => M2Entrypoint::ReplayHistorical,
        "advance-anchor-history" => M2Entrypoint::AdvanceAnchorHistory,
        other => panic!("unexpected stage-eleven fixture entrypoint: {other}"),
    }
}

#[test]
fn every_frozen_terminal_result_matches() {
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
        .filter(|case| case.expected.reached_stage == 11)
        .collect::<Vec<_>>();
    assert_eq!(cases.len(), 37);

    let mut verified = 0;
    let mut rejected = 0;
    let mut unsafe_fixture_authorizing = 0;
    for case in cases {
        let result = inspect_m2_stage_eleven(
            &input(&case),
            entrypoint(&case),
            case.trusted_anchor.as_ref(),
        );
        if case.expected.status == "rejected" {
            rejected += 1;
            let error = result.expect_err("frozen case must reject");
            assert_eq!(error.stage, case.expected.reached_stage, "{}", case.case_id);
            assert_eq!(
                Some(error.code),
                case.expected.code.as_deref(),
                "{}",
                case.case_id
            );
            assert!(!error.authorizing, "{}", case.case_id);
            continue;
        }

        verified += 1;
        let proposal = result.unwrap_or_else(|error| {
            panic!("{}: {} at stage {}", case.case_id, error.code, error.stage)
        });
        unsafe_fixture_authorizing += usize::from(case.expected.authorizing);
        assert!(!proposal.authorizing(), "{}", case.case_id);
        assert_eq!(
            proposal.resulting_anchor(),
            case.expected.expected_anchor.as_ref(),
            "{}",
            case.case_id
        );
        let status = match proposal.decision().status {
            DecisionStatus::Accepted => "accepted",
            DecisionStatus::Rejected => "rejected",
        };
        assert_eq!(status, case.expected.decision_status, "{}", case.case_id);
    }
    assert_eq!(verified, 29);
    assert_eq!(rejected, 8);
    assert_eq!(unsafe_fixture_authorizing, 27);
}
