//! M2.1 stage-one wire conformance tests.

use std::fs;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use variaxiom_protocol::{MAX_M2_WIRE_BYTES, canonical_json, inspect_m2_wire, parse_json_strict};

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
    input_base64url: String,
    input_sha256: String,
    expected: Expected,
}

#[derive(Deserialize)]
struct Expected {
    code: Option<String>,
    reached_stage: u8,
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
