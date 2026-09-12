//! M2.1 stage-one wire conformance tests.

use std::fs;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use variaxiom_protocol::{
    M2Entrypoint, MAX_M2_WIRE_BYTES, canonical_json, inspect_m2_stage_eight, inspect_m2_stage_five,
    inspect_m2_stage_four, inspect_m2_stage_nine, inspect_m2_stage_seven, inspect_m2_stage_six,
    inspect_m2_stage_three, inspect_m2_stage_two, inspect_m2_wire, parse_json_strict,
};

#[derive(Deserialize)]
struct Manifest {
    cases: Vec<ManifestEntry>,
}

#[derive(Deserialize)]
struct ManifestEntry {
    case_id: String,
    stage: u8,
    fixture: String,
}

#[derive(Deserialize)]
struct Case {
    case_id: String,
    entrypoint: String,
    input_base64url: String,
    input_sha256: String,
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
        .expect("protocol crate has repository parent")
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
        "initialize-anchor" => M2Entrypoint::InitializeAnchor,
        "advance-anchor-history" => M2Entrypoint::AdvanceAnchorHistory,
        other => panic!("unexpected fixture entrypoint: {other}"),
    }
}

#[test]
fn frozen_stage_one_rejections_match() {
    let repository = root();
    let manifest: Manifest = serde_json::from_slice(
        &fs::read(repository.join("fixtures/conformance/v2/manifest.json"))
            .expect("manifest is readable"),
    )
    .expect("manifest has expected shape");
    let stage_one = manifest
        .cases
        .iter()
        .filter(|entry| entry.stage == 1)
        .collect::<Vec<_>>();
    assert_eq!(stage_one.len(), 8);

    for entry in stage_one {
        let case = load_case(
            &repository
                .join("fixtures/conformance/v2")
                .join(&entry.fixture),
        );
        assert_eq!(case.case_id, entry.case_id);
        let rejection = inspect_m2_wire(&input(&case)).expect_err("case must fail stage one");
        assert_eq!(
            rejection.stage, case.expected.reached_stage,
            "{}",
            case.case_id
        );
        assert_eq!(
            Some(rejection.code),
            case.expected.code.as_deref(),
            "{}",
            case.case_id
        );
        assert!(!rejection.authorizing);
    }
}

#[test]
fn canonical_base_and_exact_limit_are_accepted() {
    let repository = root();
    let base_source =
        fs::read(repository.join("fixtures/conformance/v2/base-attested-proposal.json"))
            .expect("base fixture is readable");
    let base_value: serde_json::Value =
        parse_json_strict(&base_source).expect("base fixture parses strictly");
    let base = canonical_json(&base_value).expect("base fixture canonicalizes");
    let wire = inspect_m2_wire(&base).expect("base fixture is canonical");
    assert_eq!(wire.as_bytes(), base);
    assert_eq!(wire.digest().len(), 64);
    assert_eq!(
        wire.value().get("kind").and_then(serde_json::Value::as_str),
        Some("attested-proposal")
    );

    let exact =
        load_case(&repository.join("fixtures/conformance/v2/cases/wire-size-exact-limit.json"));
    let exact_input = input(&exact);
    assert_eq!(exact_input.len(), MAX_M2_WIRE_BYTES);
    let exact_wire = inspect_m2_wire(&exact_input).expect("exact byte limit must pass stage one");
    assert_eq!(exact_wire.digest(), exact.input_sha256);
}

#[test]
fn frozen_stage_two_rejections_match() {
    let repository = root();
    let manifest: Manifest = serde_json::from_slice(
        &fs::read(repository.join("fixtures/conformance/v2/manifest.json"))
            .expect("manifest is readable"),
    )
    .expect("manifest has expected shape");
    let stage_two = manifest
        .cases
        .iter()
        .filter(|entry| entry.stage == 2)
        .collect::<Vec<_>>();
    assert_eq!(stage_two.len(), 78);

    for entry in stage_two {
        let case = load_case(
            &repository
                .join("fixtures/conformance/v2")
                .join(&entry.fixture),
        );
        let result = inspect_m2_stage_two(
            &input(&case),
            entrypoint(&case),
            case.trusted_anchor.as_ref(),
        );
        let rejection = match result {
            Err(error) => error,
            Ok(_) => panic!("{} unexpectedly passed stage two", case.case_id),
        };
        assert_eq!(
            rejection.stage, case.expected.reached_stage,
            "{}",
            case.case_id
        );
        assert_eq!(
            Some(rejection.code),
            case.expected.code.as_deref(),
            "{}",
            case.case_id
        );
        assert!(!rejection.authorizing);
    }
}

#[test]
fn every_later_stage_case_passes_the_structural_boundary() {
    let repository = root();
    let manifest: Manifest = serde_json::from_slice(
        &fs::read(repository.join("fixtures/conformance/v2/manifest.json"))
            .expect("manifest is readable"),
    )
    .expect("manifest has expected shape");
    let later = manifest
        .cases
        .iter()
        .filter(|entry| entry.stage > 2)
        .collect::<Vec<_>>();
    assert_eq!(later.len(), 166);
    for entry in later {
        let case = load_case(
            &repository
                .join("fixtures/conformance/v2")
                .join(&entry.fixture),
        );
        let result = inspect_m2_stage_two(
            &input(&case),
            entrypoint(&case),
            case.trusted_anchor.as_ref(),
        )
        .unwrap_or_else(|error| {
            panic!("{}: {} at stage {}", case.case_id, error.code, error.stage)
        });
        assert!(!result.authorizing());
        assert_eq!(result.entrypoint(), entrypoint(&case));
    }
}

#[test]
fn malformed_nested_shape_fails_closed_and_anchor_is_owned() {
    let repository = root();
    let case =
        load_case(&repository.join("fixtures/conformance/v2/cases/bounded-signed-proposal.json"));
    let mut value: serde_json::Value = parse_json_strict(&input(&case)).expect("case parses");
    value["payload"]["promotion_input"]["payload"]["candidate"]["envelope"]["payload"] =
        serde_json::json!([]);
    let malformed = canonical_json(&value).expect("mutation canonicalizes");
    let rejection = inspect_m2_stage_two(
        &malformed,
        M2Entrypoint::VerifyAttestedProposal,
        case.trusted_anchor.as_ref(),
    )
    .expect_err("malformed nested payload must fail closed");
    assert_eq!(rejection.code, "input.schema_invalid");

    let mut caller_anchor = case.trusted_anchor.clone().expect("case has anchor");
    let accepted = inspect_m2_stage_two(
        &input(&case),
        M2Entrypoint::VerifyAttestedProposal,
        Some(&caller_anchor),
    )
    .expect("base case passes stage two");
    caller_anchor["trust_domain_id"] = serde_json::json!("trust-domain:mutated");
    assert_eq!(
        accepted
            .trusted_anchor()
            .and_then(|anchor| anchor["trust_domain_id"].as_str()),
        Some("trust-domain:example")
    );
}

#[test]
fn frozen_stage_three_rejections_match() {
    let repository = root();
    let manifest: Manifest = serde_json::from_slice(
        &fs::read(repository.join("fixtures/conformance/v2/manifest.json"))
            .expect("manifest is readable"),
    )
    .expect("manifest has expected shape");
    let stage_three = manifest
        .cases
        .iter()
        .filter(|entry| entry.stage == 3)
        .collect::<Vec<_>>();
    assert_eq!(stage_three.len(), 24);

    for entry in stage_three {
        let case = load_case(
            &repository
                .join("fixtures/conformance/v2")
                .join(&entry.fixture),
        );
        let rejection = inspect_m2_stage_three(
            &input(&case),
            entrypoint(&case),
            case.trusted_anchor.as_ref(),
        )
        .expect_err("case must fail stage three");
        assert_eq!(
            rejection.stage, case.expected.reached_stage,
            "{}",
            case.case_id
        );
        assert_eq!(
            Some(rejection.code),
            case.expected.code.as_deref(),
            "{}",
            case.case_id
        );
        assert!(!rejection.authorizing);
    }
}

#[test]
fn every_later_stage_case_passes_the_context_boundary() {
    let repository = root();
    let manifest: Manifest = serde_json::from_slice(
        &fs::read(repository.join("fixtures/conformance/v2/manifest.json"))
            .expect("manifest is readable"),
    )
    .expect("manifest has expected shape");
    let later = manifest
        .cases
        .iter()
        .filter(|entry| entry.stage > 3)
        .collect::<Vec<_>>();
    assert_eq!(later.len(), 142);
    for entry in later {
        let case = load_case(
            &repository
                .join("fixtures/conformance/v2")
                .join(&entry.fixture),
        );
        let result = inspect_m2_stage_three(
            &input(&case),
            entrypoint(&case),
            case.trusted_anchor.as_ref(),
        )
        .unwrap_or_else(|error| {
            panic!("{}: {} at stage {}", case.case_id, error.code, error.stage)
        });
        assert!(!result.authorizing());
        assert_eq!(result.entrypoint(), entrypoint(&case));
    }
}

#[test]
fn frozen_stage_four_rejections_match() {
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
        .filter(|case| case.expected.reached_stage == 4)
        .collect::<Vec<_>>();
    assert_eq!(cases.len(), 11);
    for case in cases {
        let rejection = inspect_m2_stage_four(
            &input(&case),
            entrypoint(&case),
            case.trusted_anchor.as_ref(),
        )
        .expect_err("case must fail stage four");
        assert_eq!(rejection.stage, 4, "{}", case.case_id);
        assert_eq!(
            Some(rejection.code),
            case.expected.code.as_deref(),
            "{}",
            case.case_id
        );
        assert!(!rejection.authorizing);
    }
}

#[test]
fn every_later_stage_case_passes_the_digest_boundary() {
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
        .filter(|case| case.expected.reached_stage > 4)
        .collect::<Vec<_>>();
    assert_eq!(cases.len(), 131);
    for case in cases {
        let result = inspect_m2_stage_four(
            &input(&case),
            entrypoint(&case),
            case.trusted_anchor.as_ref(),
        )
        .unwrap_or_else(|error| {
            panic!("{}: {} at stage {}", case.case_id, error.code, error.stage)
        });
        assert!(!result.authorizing());
    }
}

#[test]
fn frozen_stage_five_rejections_match() {
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
        .filter(|case| case.expected.reached_stage == 5)
        .collect::<Vec<_>>();
    assert_eq!(cases.len(), 23);
    for case in cases {
        let rejection = inspect_m2_stage_five(
            &input(&case),
            entrypoint(&case),
            case.trusted_anchor.as_ref(),
        )
        .expect_err("case must fail stage five");
        assert_eq!(rejection.stage, 5, "{}", case.case_id);
        assert_eq!(
            Some(rejection.code),
            case.expected.code.as_deref(),
            "{}",
            case.case_id
        );
        assert!(!rejection.authorizing);
    }
}

#[test]
fn every_later_stage_case_passes_the_identity_boundary() {
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
        .filter(|case| case.expected.reached_stage > 5)
        .collect::<Vec<_>>();
    assert_eq!(cases.len(), 108);
    for case in cases {
        let result = inspect_m2_stage_five(
            &input(&case),
            entrypoint(&case),
            case.trusted_anchor.as_ref(),
        )
        .unwrap_or_else(|error| {
            panic!("{}: {} at stage {}", case.case_id, error.code, error.stage)
        });
        assert!(!result.authorizing());
    }
}

#[test]
fn frozen_stage_six_rejections_match() {
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
        .filter(|case| case.expected.reached_stage == 6 && case.expected.code.is_some())
        .collect::<Vec<_>>();
    assert_eq!(cases.len(), 25);
    for case in cases {
        let rejection = inspect_m2_stage_six(
            &input(&case),
            entrypoint(&case),
            case.trusted_anchor.as_ref(),
        )
        .expect_err("case must fail stage six");
        assert_eq!(rejection.stage, 6, "{}", case.case_id);
        assert_eq!(
            Some(rejection.code),
            case.expected.code.as_deref(),
            "{}",
            case.case_id
        );
        assert!(!rejection.authorizing);
    }
}

#[test]
fn successful_anchor_operations_return_the_exact_frozen_anchor() {
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
        .filter(|case| case.expected.reached_stage == 6 && case.expected.code.is_none())
        .collect::<Vec<_>>();
    assert_eq!(cases.len(), 7);
    for case in cases {
        let result = inspect_m2_stage_six(
            &input(&case),
            entrypoint(&case),
            case.trusted_anchor.as_ref(),
        )
        .unwrap_or_else(|error| {
            panic!("{}: {} at stage {}", case.case_id, error.code, error.stage)
        });
        assert!(!result.authorizing());
        assert_eq!(
            result.resulting_anchor(),
            case.expected.expected_anchor.as_ref(),
            "{}",
            case.case_id
        );
    }
}

#[test]
fn every_later_stage_case_passes_the_signature_boundary() {
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
        .filter(|case| case.expected.reached_stage > 6)
        .collect::<Vec<_>>();
    assert_eq!(cases.len(), 76);
    for case in cases {
        let result = inspect_m2_stage_six(
            &input(&case),
            entrypoint(&case),
            case.trusted_anchor.as_ref(),
        )
        .unwrap_or_else(|error| {
            panic!("{}: {} at stage {}", case.case_id, error.code, error.stage)
        });
        assert!(!result.authorizing());
    }
}

#[test]
fn frozen_stage_seven_rejection_matches() {
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
        .filter(|case| case.expected.reached_stage == 7)
        .collect::<Vec<_>>();
    assert_eq!(cases.len(), 1);
    for case in cases {
        let rejection = inspect_m2_stage_seven(
            &input(&case),
            entrypoint(&case),
            case.trusted_anchor.as_ref(),
        )
        .expect_err("case must fail stage seven");
        assert_eq!(rejection.stage, 7, "{}", case.case_id);
        assert_eq!(
            Some(rejection.code),
            case.expected.code.as_deref(),
            "{}",
            case.case_id
        );
        assert!(!rejection.authorizing);
    }
}

#[test]
fn every_later_case_passes_the_evidence_boundary() {
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
        .filter(|case| case.expected.reached_stage > 7)
        .collect::<Vec<_>>();
    assert_eq!(cases.len(), 75);
    for case in cases {
        let result = inspect_m2_stage_seven(
            &input(&case),
            entrypoint(&case),
            case.trusted_anchor.as_ref(),
        )
        .unwrap_or_else(|error| {
            panic!("{}: {} at stage {}", case.case_id, error.code, error.stage)
        });
        assert!(!result.authorizing());
    }
}

#[test]
fn frozen_stage_eight_rejections_match() {
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
        .filter(|case| case.expected.reached_stage == 8)
        .collect::<Vec<_>>();
    assert_eq!(cases.len(), 21);
    for case in cases {
        let rejection = inspect_m2_stage_eight(
            &input(&case),
            entrypoint(&case),
            case.trusted_anchor.as_ref(),
        )
        .expect_err("case must fail stage eight");
        assert_eq!(rejection.stage, 8, "{}", case.case_id);
        assert_eq!(
            Some(rejection.code),
            case.expected.code.as_deref(),
            "{}",
            case.case_id
        );
        assert!(!rejection.authorizing);
    }
}

#[test]
fn every_later_case_passes_the_grant_boundary() {
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
        .filter(|case| case.expected.reached_stage > 8)
        .collect::<Vec<_>>();
    assert_eq!(cases.len(), 54);
    for case in cases {
        let result = inspect_m2_stage_eight(
            &input(&case),
            entrypoint(&case),
            case.trusted_anchor.as_ref(),
        )
        .unwrap_or_else(|error| {
            panic!("{}: {} at stage {}", case.case_id, error.code, error.stage)
        });
        assert!(!result.authorizing());
    }
}

#[test]
fn frozen_stage_nine_rejections_match() {
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
        .filter(|case| case.expected.reached_stage == 9)
        .collect::<Vec<_>>();
    assert_eq!(cases.len(), 3);
    for case in cases {
        let rejection = inspect_m2_stage_nine(
            &input(&case),
            entrypoint(&case),
            case.trusted_anchor.as_ref(),
        )
        .expect_err("case must fail stage nine");
        assert_eq!(rejection.stage, 9, "{}", case.case_id);
        assert_eq!(
            Some(rejection.code),
            case.expected.code.as_deref(),
            "{}",
            case.case_id
        );
        assert!(!rejection.authorizing);
    }
}

#[test]
fn every_later_case_passes_the_policy_context_boundary() {
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
    for case in cases {
        let result = inspect_m2_stage_nine(
            &input(&case),
            entrypoint(&case),
            case.trusted_anchor.as_ref(),
        )
        .unwrap_or_else(|error| {
            panic!("{}: {} at stage {}", case.case_id, error.code, error.stage)
        });
        assert!(!result.authorizing());
    }
}
