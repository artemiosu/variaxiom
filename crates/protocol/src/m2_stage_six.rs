//! Disabled M2.1 strict Ed25519 verifier (stage six).

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::traits::IsIdentity;
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::{Map, Value};

use crate::{
    CanonicalM2Wire, IdentityBoundM2Input, M2Entrypoint, M2WireRejection, canonical_digest,
    inspect_m2_stage_five,
};

const L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// Owned input that passed the strict stage-six signature profile.
#[derive(Clone, Debug, PartialEq)]
pub struct SignatureVerifiedM2Input {
    identity_bound: IdentityBoundM2Input,
    resulting_anchor: Option<Value>,
}

impl SignatureVerifiedM2Input {
    /// Return the inspected operation.
    #[must_use]
    pub const fn entrypoint(&self) -> M2Entrypoint {
        self.identity_bound.entrypoint()
    }

    /// Return the immutable canonical wire snapshot.
    #[must_use]
    pub const fn wire(&self) -> &CanonicalM2Wire {
        self.identity_bound.wire()
    }

    /// Return the separately owned external anchor snapshot, when present.
    #[must_use]
    pub const fn trusted_anchor(&self) -> Option<&Value> {
        self.identity_bound.trusted_anchor()
    }

    /// Return the exact resulting anchor for initialization/history operations.
    #[must_use]
    pub const fn resulting_anchor(&self) -> Option<&Value> {
        self.resulting_anchor.as_ref()
    }

    /// Signature verification alone never authorizes an effect.
    #[must_use]
    pub const fn authorizing(&self) -> bool {
        false
    }
}

#[derive(Clone, Copy)]
struct Invalid(&'static str);
type Check<T = ()> = Result<T, Invalid>;

fn object(value: &Value) -> Check<&Map<String, Value>> {
    value
        .as_object()
        .ok_or(Invalid("signature.encoding_invalid"))
}

fn text(value: &Value) -> Check<&str> {
    value.as_str().ok_or(Invalid("signature.encoding_invalid"))
}

fn proposal_payload(value: &Value) -> Check<&Map<String, Value>> {
    object(&object(value)?["payload"])
}

fn promotion_body(value: &Value) -> Check<&Map<String, Value>> {
    let root = object(value)?;
    if root.get("kind").and_then(Value::as_str) == Some("promotion-input") {
        object(&root["payload"])
    } else {
        let proposal = proposal_payload(value)?;
        object(&object(&proposal["promotion_input"])?["payload"])
    }
}

#[derive(Clone, Copy)]
struct Pair<'a> {
    signature: &'a Value,
}

fn pairs(value: &Value) -> Check<Vec<Pair<'_>>> {
    let body = promotion_body(value)?;
    let candidate = object(&body["candidate"])?;
    let mut result = vec![Pair {
        signature: &candidate["signature"],
    }];
    for evidence in body["evidence"]
        .as_array()
        .ok_or(Invalid("signature.encoding_invalid"))?
    {
        result.push(Pair {
            signature: &object(evidence)?["signature"],
        });
    }
    if let Some(grant) = body.get("authority_grant") {
        result.push(Pair {
            signature: &object(grant)?["signature"],
        });
    }
    Ok(result)
}

fn selector_pair(value: &Value) -> Check<Pair<'_>> {
    Ok(Pair {
        signature: &proposal_payload(value)?["selector_signature"],
    })
}

type KeyMap<'a> = BTreeMap<String, &'a Map<String, Value>>;

fn identity_keys(identity: &Value) -> Check<KeyMap<'_>> {
    let payload = object(&object(identity)?["payload"])?;
    let mut keys = BTreeMap::new();
    for principal in payload["principals"]
        .as_array()
        .ok_or(Invalid("signature.encoding_invalid"))?
    {
        let principal = object(principal)?;
        for key in principal["keys"]
            .as_array()
            .ok_or(Invalid("signature.encoding_invalid"))?
        {
            let key = object(key)?;
            keys.insert(text(&key["key_id"])?.to_owned(), key);
        }
    }
    Ok(keys)
}

fn attested_identity(value: &Value) -> Check<&Value> {
    Ok(&promotion_body(value)?["identity_context"])
}

fn signature_payload(pair: Pair<'_>) -> Check<&Map<String, Value>> {
    object(&object(pair.signature)?["payload"])
}

fn decode<const SIZE: usize>(value: &Value) -> Check<[u8; SIZE]> {
    let encoded = text(value)?;
    let raw = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| Invalid("signature.encoding_invalid"))?;
    if URL_SAFE_NO_PAD.encode(&raw) != encoded {
        return Err(Invalid("signature.encoding_invalid"));
    }
    raw.try_into()
        .map_err(|_| Invalid("signature.encoding_invalid"))
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

fn signing_message(signature: &Map<String, Value>) -> Check<Vec<u8>> {
    let fields = [
        "variaxiom-signature/v1",
        text(&signature["algorithm"])?,
        text(&signature["trust_domain_id"])?,
        text(&signature["principal_id"])?,
        text(&signature["key_id"])?,
        text(&signature["signed_kind"])?,
        text(&signature["signed_digest"])?,
    ];
    if fields.iter().any(|field| !field.is_ascii()) {
        return Err(Invalid("signature.encoding_invalid"));
    }
    Ok(format!("{}\n", fields.join("\n")).into_bytes())
}

fn stage_six_pairs(pairs: &[Pair<'_>], keys: &KeyMap<'_>) -> Check {
    for pair in pairs {
        let signature = signature_payload(*pair)?;
        let binding = keys
            .get(text(&signature["key_id"])?)
            .ok_or(Invalid("signature.encoding_invalid"))?;
        if signature["algorithm"] != "Ed25519" || binding["algorithm"] != "Ed25519" {
            return Err(Invalid("signature.algorithm_unsupported"));
        }
    }

    let mut prepared = Vec::new();
    for pair in pairs {
        let signature = signature_payload(*pair)?;
        let binding = keys
            .get(text(&signature["key_id"])?)
            .ok_or(Invalid("signature.encoding_invalid"))?;
        let public = decode::<32>(&binding["public_key_base64url"])?;
        let raw_signature = decode::<64>(&signature["signature_base64url"])?;
        let r: [u8; 32] = raw_signature[..32]
            .try_into()
            .map_err(|_| Invalid("signature.encoding_invalid"))?;
        let s: [u8; 32] = raw_signature[32..]
            .try_into()
            .map_err(|_| Invalid("signature.encoding_invalid"))?;
        if !point_is_accepted(&public) || !point_is_accepted(&r) || !scalar_is_canonical(&s) {
            return Err(Invalid("signature.encoding_invalid"));
        }
        let key =
            VerifyingKey::from_bytes(&public).map_err(|_| Invalid("signature.encoding_invalid"))?;
        prepared.push((
            key,
            signing_message(signature)?,
            Signature::from_bytes(&raw_signature),
        ));
    }

    for (key, message, signature) in prepared {
        key.verify_strict(&message, &signature)
            .map_err(|_| Invalid("signature.invalid"))?;
    }
    Ok(())
}

fn stage_six_attested(value: &Value) -> Check {
    let keys = identity_keys(attested_identity(value)?)?;
    stage_six_pairs(&pairs(value)?, &keys)
}

pub(crate) fn verify_selector_stage_six(value: &Value) -> Result<(), M2WireRejection> {
    let keys = identity_keys(attested_identity(value).map_err(|error| M2WireRejection {
        stage: 11,
        code: error.0,
        authorizing: false,
    })?)
    .map_err(|error| M2WireRejection {
        stage: 11,
        code: error.0,
        authorizing: false,
    })?;
    let selector = selector_pair(value).map_err(|error| M2WireRejection {
        stage: 11,
        code: error.0,
        authorizing: false,
    })?;
    stage_six_pairs(&[selector], &keys).map_err(|error| M2WireRejection {
        stage: 11,
        code: error.0,
        authorizing: false,
    })
}

fn identity_bindings(identity: &Value) -> Check<Vec<&Map<String, Value>>> {
    let payload = object(&object(identity)?["payload"])?;
    let mut result = Vec::new();
    for principal in payload["principals"]
        .as_array()
        .ok_or(Invalid("signature.encoding_invalid"))?
    {
        for key in object(principal)?["keys"]
            .as_array()
            .ok_or(Invalid("signature.encoding_invalid"))?
        {
            result.push(object(key)?);
        }
    }
    Ok(result)
}

fn stage_six_contexts(identities: &[&Value]) -> Check {
    let bindings = identities
        .iter()
        .map(|identity| identity_bindings(identity))
        .collect::<Check<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    for binding in &bindings {
        if binding["algorithm"] != "Ed25519" {
            return Err(Invalid("signature.algorithm_unsupported"));
        }
    }
    for binding in bindings {
        let public = decode::<32>(&binding["public_key_base64url"])?;
        if !point_is_accepted(&public) {
            return Err(Invalid("signature.encoding_invalid"));
        }
    }
    Ok(())
}

fn key_owners(identity: &Value) -> Check<BTreeMap<String, String>> {
    let payload = object(&object(identity)?["payload"])?;
    let mut result = BTreeMap::new();
    for principal in payload["principals"]
        .as_array()
        .ok_or(Invalid("signature.encoding_invalid"))?
    {
        let principal = object(principal)?;
        for key in principal["keys"]
            .as_array()
            .ok_or(Invalid("signature.encoding_invalid"))?
        {
            result.insert(
                text(&object(key)?["key_id"])?.to_owned(),
                text(&principal["principal_id"])?.to_owned(),
            );
        }
    }
    Ok(result)
}

fn string_set(value: &Value) -> Check<BTreeSet<String>> {
    value
        .as_array()
        .ok_or(Invalid("signature.encoding_invalid"))?
        .iter()
        .map(|item| text(item).map(str::to_owned))
        .collect()
}

fn initial_anchor(request: &Map<String, Value>) -> Check<Value> {
    let identity = &request["initial_identity_context"];
    let authorization = &request["initial_authorization_context"];
    let payload = object(&object(identity)?["payload"])?;
    let registry = key_owners(identity)?
        .into_iter()
        .map(|(key, principal)| (key, Value::String(principal)))
        .collect();
    Ok(Value::Object(Map::from_iter([
        (
            "trust_domain_id".to_owned(),
            payload["trust_domain_id"].clone(),
        ),
        (
            "current_identity_context_digest".to_owned(),
            Value::String(canonical_digest(identity).map_err(|_| Invalid("signature.invalid"))?),
        ),
        (
            "current_authorization_context_digest".to_owned(),
            Value::String(
                canonical_digest(authorization).map_err(|_| Invalid("signature.invalid"))?,
            ),
        ),
        (
            "current_snapshot_sequence".to_owned(),
            payload["snapshot_sequence"].clone(),
        ),
        (
            "trusted_now_unix_s".to_owned(),
            request["trusted_now_unix_s"].clone(),
        ),
        ("key_ownership_registry".to_owned(), Value::Object(registry)),
        (
            "revoked_key_ids".to_owned(),
            payload["revoked_key_ids"].clone(),
        ),
        (
            "revoked_grant_ids".to_owned(),
            payload["revoked_grant_ids"].clone(),
        ),
    ])))
}

fn advance_anchor(
    anchor: &Map<String, Value>,
    identity: &Value,
    authorization: &Value,
    now: &Value,
) -> Check<Map<String, Value>> {
    let payload = object(&object(identity)?["payload"])?;
    let mut registry = object(&anchor["key_ownership_registry"])?.clone();
    for (key, principal) in key_owners(identity)? {
        registry.entry(key).or_insert(Value::String(principal));
    }
    let mut revoked_keys = string_set(&anchor["revoked_key_ids"])?;
    revoked_keys.extend(string_set(&payload["revoked_key_ids"])?);
    let mut revoked_grants = string_set(&anchor["revoked_grant_ids"])?;
    revoked_grants.extend(string_set(&payload["revoked_grant_ids"])?);
    Ok(Map::from_iter([
        (
            "trust_domain_id".to_owned(),
            anchor["trust_domain_id"].clone(),
        ),
        (
            "current_identity_context_digest".to_owned(),
            Value::String(canonical_digest(identity).map_err(|_| Invalid("signature.invalid"))?),
        ),
        (
            "current_authorization_context_digest".to_owned(),
            Value::String(
                canonical_digest(authorization).map_err(|_| Invalid("signature.invalid"))?,
            ),
        ),
        (
            "current_snapshot_sequence".to_owned(),
            payload["snapshot_sequence"].clone(),
        ),
        ("trusted_now_unix_s".to_owned(), now.clone()),
        ("key_ownership_registry".to_owned(), Value::Object(registry)),
        (
            "revoked_key_ids".to_owned(),
            Value::Array(revoked_keys.into_iter().map(Value::String).collect()),
        ),
        (
            "revoked_grant_ids".to_owned(),
            Value::Array(revoked_grants.into_iter().map(Value::String).collect()),
        ),
    ]))
}

fn stage_six(identity_bound: &IdentityBoundM2Input) -> Check<Option<Value>> {
    let value = identity_bound.wire().value();
    match identity_bound.entrypoint() {
        M2Entrypoint::EvaluateNew
        | M2Entrypoint::VerifyAttestedProposal
        | M2Entrypoint::ReplayHistorical => {
            stage_six_attested(value)?;
            Ok(None)
        }
        M2Entrypoint::InitializeAnchor => {
            let request = object(value)?;
            stage_six_contexts(&[&request["initial_identity_context"]])?;
            Ok(Some(initial_anchor(request)?))
        }
        #[cfg(feature = "conformance")]
        M2Entrypoint::AdvanceAnchorHistory => {
            let history = object(value)?;
            let steps = history["steps"]
                .as_array()
                .ok_or(Invalid("signature.encoding_invalid"))?;
            let mut identities = vec![&history["initial_identity_context"]];
            for step in steps {
                identities.push(&object(step)?["next_identity_context"]);
            }
            stage_six_contexts(&identities)?;
            let mut anchor = object(&history["initial_anchor"])?.clone();
            for step in steps {
                let step = object(step)?;
                anchor = advance_anchor(
                    &anchor,
                    &step["next_identity_context"],
                    &step["next_authorization_context"],
                    &step["trusted_now_unix_s"],
                )?;
            }
            if let Some(probe) = history.get("probe_attested_proposal") {
                stage_six_attested(probe)?;
            }
            Ok(Some(Value::Object(anchor)))
        }
    }
}

pub(crate) fn verify_anchor_transition_keys(
    previous_anchor: &Value,
    previous_identity: &Value,
    next_identity: &Value,
    next_authorization: &Value,
    trusted_now: &Value,
) -> Result<Value, M2WireRejection> {
    stage_six_contexts(&[previous_identity, next_identity]).map_err(|error| M2WireRejection {
        stage: 6,
        code: error.0,
        authorizing: false,
    })?;
    let anchor = object(previous_anchor).map_err(|error| M2WireRejection {
        stage: 6,
        code: error.0,
        authorizing: false,
    })?;
    let resulting = advance_anchor(anchor, next_identity, next_authorization, trusted_now)
        .map_err(|error| M2WireRejection {
            stage: 6,
            code: error.0,
            authorizing: false,
        })?;
    Ok(Value::Object(resulting))
}

/// Apply M2.1 stages one through six without signing or authority.
pub fn inspect_m2_stage_six(
    source: &[u8],
    entrypoint: M2Entrypoint,
    trusted_anchor: Option<&Value>,
) -> Result<SignatureVerifiedM2Input, M2WireRejection> {
    let identity_bound = inspect_m2_stage_five(source, entrypoint, trusted_anchor)?;
    let resulting_anchor = stage_six(&identity_bound).map_err(|error| M2WireRejection {
        stage: 6,
        code: error.0,
        authorizing: false,
    })?;
    Ok(SignatureVerifiedM2Input {
        identity_bound,
        resulting_anchor,
    })
}
