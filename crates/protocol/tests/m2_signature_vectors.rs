#![forbid(unsafe_code)]
//! Cross-runtime verification of the frozen M2.1 Ed25519 vectors.

use std::fs;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::traits::IsIdentity;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use variaxiom_protocol::canonical_digest;

const L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

#[derive(Deserialize)]
struct Manifest {
    cases: Vec<CaseReference>,
}

#[derive(Deserialize)]
struct CaseReference {
    fixture: String,
}

#[derive(Deserialize)]
struct Case {
    signature_vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    vector_id: String,
    target_envelope: Value,
    target_digest: String,
    algorithm: String,
    trust_domain_id: String,
    principal_id: String,
    key_id: String,
    key_binding_algorithm: String,
    public_key_base64url: String,
    signed_kind: String,
    signed_digest: String,
    message_hex: String,
    signature_base64url: String,
    expected: String,
    expected_code: Option<String>,
}

#[derive(Deserialize)]
struct WycheproofSubset {
    vectors: Vec<WycheproofVector>,
}

#[derive(Deserialize)]
struct WycheproofVector {
    tc_id: u64,
    public_key_hex: String,
    message_hex: String,
    signature_hex: String,
    expected: String,
}

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("fixtures/conformance/v2")
}

fn decode_hex(source: &str) -> Option<Vec<u8>> {
    if source.len() % 2 != 0 {
        return None;
    }
    (0..source.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&source[index..index + 2], 16).ok())
        .collect()
}

fn scalar_is_canonical(scalar: &[u8; 32]) -> bool {
    for index in (0..32).rev() {
        if scalar[index] < L[index] {
            return true;
        }
        if scalar[index] > L[index] {
            return false;
        }
    }
    false
}

fn point_is_accepted(encoded: &[u8; 32]) -> bool {
    let compressed = CompressedEdwardsY(*encoded);
    let Some(point) = compressed.decompress() else {
        return false;
    };
    point.compress().to_bytes() == *encoded && !point.is_identity() && point.is_torsion_free()
}

fn classify(vector: &Vector) -> Result<(), &'static str> {
    let target_digest =
        canonical_digest(&vector.target_envelope).map_err(|_| "signature.digest_mismatch")?;
    if target_digest != vector.target_digest {
        return Err("signature.digest_mismatch");
    }
    if vector.signed_digest != vector.target_digest {
        return Err("signature.digest_mismatch");
    }
    let public = URL_SAFE_NO_PAD
        .decode(&vector.public_key_base64url)
        .map_err(|_| "signature.encoding_invalid")?;
    let computed_key_id = format!(
        "key:sha256:{:x}",
        Sha256::digest([b"variaxiom-key/v1\0Ed25519\0".as_slice(), &public].concat())
    );
    if computed_key_id != vector.key_id {
        return Err("signature.key_id_mismatch");
    }
    if vector.target_envelope.get("kind").and_then(Value::as_str)
        != Some(vector.signed_kind.as_str())
    {
        return Err("signature.kind_mismatch");
    }
    if vector.algorithm != "Ed25519" || vector.key_binding_algorithm != "Ed25519" {
        return Err("signature.algorithm_unsupported");
    }
    let signature = URL_SAFE_NO_PAD
        .decode(&vector.signature_base64url)
        .map_err(|_| "signature.encoding_invalid")?;
    if URL_SAFE_NO_PAD.encode(&public) != vector.public_key_base64url
        || URL_SAFE_NO_PAD.encode(&signature) != vector.signature_base64url
    {
        return Err("signature.encoding_invalid");
    }
    let public: [u8; 32] = public
        .try_into()
        .map_err(|_| "signature.encoding_invalid")?;
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| "signature.encoding_invalid")?;
    let r: [u8; 32] = signature[..32]
        .try_into()
        .map_err(|_| "signature.encoding_invalid")?;
    let s: [u8; 32] = signature[32..]
        .try_into()
        .map_err(|_| "signature.encoding_invalid")?;
    if !point_is_accepted(&public) || !point_is_accepted(&r) || !scalar_is_canonical(&s) {
        return Err("signature.encoding_invalid");
    }
    let verifying_key =
        VerifyingKey::from_bytes(&public).map_err(|_| "signature.encoding_invalid")?;
    let signature = Signature::from_bytes(&signature);
    let message = decode_hex(&vector.message_hex).ok_or("signature.encoding_invalid")?;
    let expected_message = format!(
        "variaxiom-signature/v1\n{}\n{}\n{}\n{}\n{}\n{}\n",
        vector.algorithm,
        vector.trust_domain_id,
        vector.principal_id,
        vector.key_id,
        vector.signed_kind,
        vector.signed_digest
    )
    .into_bytes();
    if message != expected_message {
        return Err("signature.invalid");
    }
    verifying_key
        .verify_strict(&message, &signature)
        .map_err(|_| "signature.invalid")
}

fn verify_raw(public: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let Ok(public) = <[u8; 32]>::try_from(public) else {
        return false;
    };
    let Ok(signature) = <[u8; 64]>::try_from(signature) else {
        return false;
    };
    let r: [u8; 32] = signature[..32].try_into().expect("fixed signature prefix");
    let s: [u8; 32] = signature[32..].try_into().expect("fixed signature suffix");
    if !point_is_accepted(&public) || !point_is_accepted(&r) || !scalar_is_canonical(&s) {
        return false;
    }
    let Ok(key) = VerifyingKey::from_bytes(&public) else {
        return false;
    };
    key.verify_strict(message, &Signature::from_bytes(&signature))
        .is_ok()
}

#[test]
fn shared_m2_signature_vectors_match_strict_rust_profile() {
    let root = fixture_root();
    let manifest: Manifest =
        serde_json::from_slice(&fs::read(root.join("manifest.json")).expect("read M2.1 manifest"))
            .expect("parse M2.1 manifest");
    let mut checked = 0usize;
    for reference in manifest.cases {
        let case: Case = serde_json::from_slice(
            &fs::read(root.join(reference.fixture)).expect("read M2.1 case"),
        )
        .expect("parse M2.1 case");
        for vector in case.signature_vectors {
            let observed = classify(&vector);
            match (vector.expected.as_str(), vector.expected_code.as_deref()) {
                ("verified", None) => assert!(
                    observed.is_ok(),
                    "{} unexpectedly rejected: {observed:?}",
                    vector.vector_id
                ),
                ("rejected", Some(_)) => {
                    assert_eq!(
                        observed.unwrap_err(),
                        vector.expected_code.as_deref().unwrap()
                    )
                }
                _ => continue,
            }
            checked += 1;
        }
    }
    assert!(
        checked >= 4,
        "expected positive and negative shared signature vectors"
    );
}

#[test]
fn curated_wycheproof_subset_matches_strict_rust_profile() {
    let root = fixture_root();
    let subset: WycheproofSubset = serde_json::from_slice(
        &fs::read(root.join("wycheproof-ed25519-subset.json"))
            .expect("read curated Wycheproof subset"),
    )
    .expect("parse curated Wycheproof subset");
    assert!(subset.vectors.len() >= 10);
    for vector in subset.vectors {
        let public = decode_hex(&vector.public_key_hex).expect("valid public-key hex");
        let message = decode_hex(&vector.message_hex).expect("valid message hex");
        let signature = decode_hex(&vector.signature_hex).expect("valid signature hex");
        assert_eq!(
            verify_raw(&public, &message, &signature),
            vector.expected == "valid",
            "Wycheproof tcId {}",
            vector.tc_id
        );
    }
}
