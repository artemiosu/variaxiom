//! Frozen M2.1 terminal decision and selector tests.

use std::fs;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use variaxiom_kernel::{
    advance_anchor, evaluate_new, initialize_anchor, inspect_m2_stage_eleven, replay_historical,
    verify_attested_proposal,
};
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
    assert_eq!(cases.len(), 49);

    let mut verified = 0;
    let mut rejected = 0;
    let mut fixture_authorizing = 0;
    for case in cases {
        let result = inspect_m2_stage_eleven(
            &input(&case),
            entrypoint(&case),
            case.trusted_anchor.as_ref(),
        );
        if case.expected.status == "rejected" {
            rejected += 1;
            let error = result.expect_err("frozen case must reject");
            assert_eq!(
                error.stage(),
                case.expected.reached_stage,
                "{}",
                case.case_id
            );
            assert_eq!(
                Some(error.code()),
                case.expected.code.as_deref(),
                "{}",
                case.case_id
            );
            assert!(!error.authorizing(), "{}", case.case_id);
            continue;
        }

        verified += 1;
        let proposal = result.unwrap_or_else(|error| {
            panic!(
                "{}: {} at stage {}",
                case.case_id,
                error.code(),
                error.stage()
            )
        });
        fixture_authorizing += usize::from(case.expected.authorizing);
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
    assert_eq!(verified, 30);
    assert_eq!(rejected, 19);
    assert_eq!(fixture_authorizing, 0);
}

#[test]
fn public_result_apis_match_the_frozen_contract() {
    let repository = root();
    let fixture_root = repository.join("fixtures/conformance/v2");
    let manifest: Manifest = serde_json::from_slice(
        &fs::read(fixture_root.join("manifest.json")).expect("manifest is readable"),
    )
    .expect("manifest has expected shape");
    let cases = manifest
        .cases
        .iter()
        .map(|entry| load_case(&fixture_root.join(&entry.fixture)))
        .map(|case| (case.case_id.clone(), case))
        .collect::<std::collections::BTreeMap<_, _>>();

    let evaluated_case = &cases["evaluate-new-accepted"];
    let evaluated = evaluate_new(
        &input(evaluated_case),
        evaluated_case
            .trusted_anchor
            .as_ref()
            .expect("live anchor is present"),
    )
    .expect("evaluation succeeds");
    let expected: serde_json::Value = serde_json::from_slice(
        &fs::read(fixture_root.join("base-evaluated-proposal.json"))
            .expect("evaluated result is readable"),
    )
    .expect("evaluated result parses");
    assert_eq!(evaluated.as_value(), expected);
    assert!(!evaluated.authorizing());

    let verified_case = &cases["bounded-signed-proposal"];
    let verified = verify_attested_proposal(
        &input(verified_case),
        verified_case
            .trusted_anchor
            .as_ref()
            .expect("live anchor is present"),
    )
    .expect("proposal verifies");
    let expected: serde_json::Value = serde_json::from_slice(
        &fs::read(fixture_root.join("base-verified-proposal.json"))
            .expect("verified result is readable"),
    )
    .expect("verified result parses");
    assert_eq!(verified.as_value(), expected);
    assert!(!verified.authorizing());

    let replay_case = &cases["historical-replay-nonauthorizing"];
    let replay = replay_historical(
        &input(replay_case),
        replay_case
            .trusted_anchor
            .as_ref()
            .expect("recorded anchor is present"),
    )
    .expect("historical replay verifies");
    let expected: serde_json::Value = serde_json::from_slice(
        &fs::read(fixture_root.join("base-replay-result.json")).expect("replay result is readable"),
    )
    .expect("replay result parses");
    assert_eq!(replay.as_value(), expected);
    assert!(!replay.authorizing());

    let initialize_case = &cases["initialize-anchor-genesis"];
    let initialize_input: serde_json::Value =
        serde_json::from_slice(&input(initialize_case)).expect("genesis input parses");
    let initialized = initialize_anchor(
        &initialize_input["initial_identity_context"],
        &initialize_input["initial_authorization_context"],
        initialize_input["trusted_now_unix_s"]
            .as_u64()
            .expect("trusted time is unsigned"),
    )
    .expect("genesis validates");
    assert_eq!(
        initialized.as_value()["resulting_anchor"],
        initialize_case
            .expected
            .expected_anchor
            .as_ref()
            .expect("expected genesis anchor is present")
            .clone()
    );
    assert!(!initialized.authorizing());

    let advance_case = &cases["anchor-new-key-add"];
    let advance_input: serde_json::Value =
        serde_json::from_slice(&input(advance_case)).expect("anchor input parses");
    let step = &advance_input["steps"][0];
    let advanced = advance_anchor(
        &advance_input["initial_anchor"],
        &advance_input["initial_identity_context"],
        &step["next_identity_context"],
        &step["next_authorization_context"],
        step["trusted_now_unix_s"]
            .as_u64()
            .expect("trusted time is unsigned"),
    )
    .expect("anchor transition validates");
    assert_eq!(
        advanced.as_value()["resulting_anchor"],
        advance_case
            .expected
            .expected_anchor
            .as_ref()
            .expect("expected advanced anchor is present")
            .clone()
    );
    assert!(!advanced.authorizing());

    let retained_case = &cases["anchor-new-key-add-omit"];
    let retained_input: serde_json::Value =
        serde_json::from_slice(&input(retained_case)).expect("retention history parses");
    let mut retained_anchor = retained_input["initial_anchor"].clone();
    let mut retained_identity = retained_input["initial_identity_context"].clone();
    for retained_step in retained_input["steps"]
        .as_array()
        .expect("retention steps are present")
    {
        let transition = advance_anchor(
            &retained_anchor,
            &retained_identity,
            &retained_step["next_identity_context"],
            &retained_step["next_authorization_context"],
            retained_step["trusted_now_unix_s"]
                .as_u64()
                .expect("trusted time is unsigned"),
        )
        .expect("ownership-retention transition validates");
        retained_anchor = transition.as_value()["resulting_anchor"].clone();
        retained_identity = retained_step["next_identity_context"].clone();
    }
    assert_eq!(
        retained_anchor,
        retained_case
            .expected
            .expected_anchor
            .as_ref()
            .expect("retained expected anchor is present")
            .clone()
    );

    let rebind_case = &cases["anchor-new-key-rebind-rejected"];
    let rebind_input: serde_json::Value =
        serde_json::from_slice(&input(rebind_case)).expect("rebind history parses");
    let mut rebind_anchor = rebind_input["initial_anchor"].clone();
    let mut rebind_identity = rebind_input["initial_identity_context"].clone();
    let mut rebind_code = None;
    for rebind_step in rebind_input["steps"]
        .as_array()
        .expect("rebind steps are present")
    {
        match advance_anchor(
            &rebind_anchor,
            &rebind_identity,
            &rebind_step["next_identity_context"],
            &rebind_step["next_authorization_context"],
            rebind_step["trusted_now_unix_s"]
                .as_u64()
                .expect("trusted time is unsigned"),
        ) {
            Ok(transition) => {
                rebind_anchor = transition.as_value()["resulting_anchor"].clone();
                rebind_identity = rebind_step["next_identity_context"].clone();
            }
            Err(rejection) => {
                rebind_code = Some(rejection.code().to_owned());
                break;
            }
        }
    }
    assert_eq!(rebind_code.as_deref(), Some("identity.key_ambiguous"));

    let rejected_case = &cases["evaluate-new-anchor-mismatch"];
    let rejected = evaluate_new(
        &input(rejected_case),
        rejected_case
            .trusted_anchor
            .as_ref()
            .expect("live anchor is present"),
    )
    .expect_err("mismatched anchor rejects");
    assert_eq!(rejected.code(), "identity.context_untrusted");
    assert!(!rejected.authorizing());
}
