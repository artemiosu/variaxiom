//! Disabled M2.1 trusted-context verifier (stages one through three only).

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use crate::{
    CanonicalM2Wire, M2Entrypoint, M2WireRejection, StructurallyValidM2Input, canonical_digest,
    inspect_m2_stage_two,
};

/// Owned input whose identity and authorization contexts match trusted state.
///
/// Later signature, identity, grant, policy, and selector checks have not run,
/// so this value never authorizes an effect.
#[derive(Clone, Debug, PartialEq)]
pub struct ContextBoundM2Input {
    structural: StructurallyValidM2Input,
}

impl ContextBoundM2Input {
    /// Return the operation whose contexts were checked.
    #[must_use]
    pub const fn entrypoint(&self) -> M2Entrypoint {
        self.structural.entrypoint()
    }

    /// Return the immutable canonical wire snapshot.
    #[must_use]
    pub const fn wire(&self) -> &CanonicalM2Wire {
        self.structural.wire()
    }

    /// Return the separately owned external anchor snapshot, when present.
    #[must_use]
    pub const fn trusted_anchor(&self) -> Option<&Value> {
        self.structural.trusted_anchor()
    }

    /// Context binding alone never authorizes an effect.
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
        .ok_or(Invalid("identity.context_untrusted"))
}

fn uint(value: &Value) -> Check<u64> {
    value.as_u64().ok_or(Invalid("identity.context_untrusted"))
}

fn text(value: &Value) -> Check<&str> {
    value.as_str().ok_or(Invalid("identity.context_untrusted"))
}

fn digest(value: &Value) -> Check<String> {
    canonical_digest(value).map_err(|_| Invalid("identity.context_untrusted"))
}

fn promotion_input(value: &Value) -> Check<&Value> {
    let root = object(value)?;
    if root.get("kind").and_then(Value::as_str) == Some("promotion-input") {
        Ok(value)
    } else {
        let proposal = object(&root["payload"])?;
        Ok(&proposal["promotion_input"])
    }
}

fn contexts(value: &Value) -> Check<(&Value, &Value)> {
    let promotion = object(promotion_input(value)?)?;
    let body = object(&promotion["payload"])?;
    Ok((&body["identity_context"], &body["authorization_context"]))
}

fn signatures(value: &Value) -> Check<Vec<&Value>> {
    let promotion = object(promotion_input(value)?)?;
    let body = object(&promotion["payload"])?;
    let mut result = vec![&object(&body["candidate"])?["signature"]];
    for evidence in body["evidence"]
        .as_array()
        .ok_or(Invalid("identity.context_untrusted"))?
    {
        result.push(&object(evidence)?["signature"]);
    }
    if let Some(grant) = body.get("authority_grant") {
        result.push(&object(grant)?["signature"]);
    }
    Ok(result)
}

fn stage_three_attested(value: &Value, anchor: &Map<String, Value>) -> Check {
    let (identity, authorization) = contexts(value)?;
    let identity_payload = object(&object(identity)?["payload"])?;
    let sequence = uint(&identity_payload["snapshot_sequence"])?;
    let anchor_sequence = uint(&anchor["current_snapshot_sequence"])?;
    if sequence < anchor_sequence {
        return Err(Invalid("identity.context_stale"));
    }
    if identity_payload["trust_domain_id"] != anchor["trust_domain_id"]
        || digest(identity)? != text(&anchor["current_identity_context_digest"])?
        || sequence != anchor_sequence
        || identity_payload["evaluation_time_unix_s"] != anchor["trusted_now_unix_s"]
    {
        return Err(Invalid("identity.context_untrusted"));
    }
    let authorization_payload = object(&object(authorization)?["payload"])?;
    if authorization_payload["trust_domain_id"] != anchor["trust_domain_id"]
        || digest(authorization)? != text(&anchor["current_authorization_context_digest"])?
    {
        return Err(Invalid("authorization.context_untrusted"));
    }
    for signature in signatures(value)? {
        let payload = object(&object(signature)?["payload"])?;
        if payload["trust_domain_id"] != anchor["trust_domain_id"] {
            return Err(Invalid("signature.domain_mismatch"));
        }
    }
    Ok(())
}

fn stage_three_initialize(value: &Value) -> Check {
    let request = object(value)?;
    let identity = object(&request["initial_identity_context"])?;
    let identity_payload = object(&identity["payload"])?;
    let authorization = object(&request["initial_authorization_context"])?;
    let authorization_payload = object(&authorization["payload"])?;
    if uint(&identity_payload["snapshot_sequence"])? != 0
        || !identity_payload["previous_snapshot_digest"].is_null()
        || identity_payload["evaluation_time_unix_s"] != request["trusted_now_unix_s"]
        || authorization_payload["trust_domain_id"] != identity_payload["trust_domain_id"]
    {
        return Err(Invalid("identity.context_untrusted"));
    }
    Ok(())
}

fn key_owners(identity: &Value) -> Check<BTreeMap<String, String>> {
    let payload = object(&object(identity)?["payload"])?;
    let mut result = BTreeMap::new();
    for principal in payload["principals"]
        .as_array()
        .ok_or(Invalid("identity.context_untrusted"))?
    {
        let principal = object(principal)?;
        let principal_id = text(&principal["principal_id"])?;
        for key in principal["keys"]
            .as_array()
            .ok_or(Invalid("identity.context_untrusted"))?
        {
            result.insert(
                text(&object(key)?["key_id"])?.to_owned(),
                principal_id.to_owned(),
            );
        }
    }
    Ok(result)
}

fn string_set(value: &Value) -> Check<BTreeSet<String>> {
    value
        .as_array()
        .ok_or(Invalid("identity.context_untrusted"))?
        .iter()
        .map(|item| text(item).map(str::to_owned))
        .collect()
}

#[cfg(feature = "conformance")]
fn stage_three_history(value: &Value) -> Check {
    let history = object(value)?;
    let mut anchor = object(&history["initial_anchor"])?.clone();
    let mut previous_identity = history["initial_identity_context"].clone();
    let authorization = &history["initial_authorization_context"];
    let previous_payload = object(&object(&previous_identity)?["payload"])?;
    let authorization_payload = object(&object(authorization)?["payload"])?;
    let anchor_revoked_keys = string_set(&anchor["revoked_key_ids"])?;
    let anchor_revoked_grants = string_set(&anchor["revoked_grant_ids"])?;
    let previous_revoked_keys = string_set(&previous_payload["revoked_key_ids"])?;
    let previous_revoked_grants = string_set(&previous_payload["revoked_grant_ids"])?;
    let registry = object(&anchor["key_ownership_registry"])?;
    let owners_match = key_owners(&previous_identity)?
        .iter()
        .all(|(key, principal)| {
            registry.get(key).and_then(Value::as_str) == Some(principal.as_str())
        });
    if digest(&previous_identity)? != text(&anchor["current_identity_context_digest"])?
        || digest(authorization)? != text(&anchor["current_authorization_context_digest"])?
        || previous_payload["trust_domain_id"] != anchor["trust_domain_id"]
        || authorization_payload["trust_domain_id"] != anchor["trust_domain_id"]
        || previous_payload["snapshot_sequence"] != anchor["current_snapshot_sequence"]
        || previous_payload["evaluation_time_unix_s"] != anchor["trusted_now_unix_s"]
        || !previous_revoked_keys.is_subset(&anchor_revoked_keys)
        || !previous_revoked_grants.is_subset(&anchor_revoked_grants)
        || !owners_match
    {
        return Err(Invalid("identity.context_untrusted"));
    }

    for step in history["steps"]
        .as_array()
        .ok_or(Invalid("identity.context_untrusted"))?
    {
        let step = object(step)?;
        let identity = &step["next_identity_context"];
        let next_authorization = &step["next_authorization_context"];
        let payload = object(&object(identity)?["payload"])?;
        let authorization_payload = object(&object(next_authorization)?["payload"])?;
        let now = uint(&step["trusted_now_unix_s"])?;
        let prior_now = uint(&anchor["trusted_now_unix_s"])?;
        if now < prior_now || uint(&payload["evaluation_time_unix_s"])? < prior_now {
            return Err(Invalid("identity.context_stale"));
        }
        let anchor_keys = string_set(&anchor["revoked_key_ids"])?;
        let anchor_grants = string_set(&anchor["revoked_grant_ids"])?;
        let next_keys = string_set(&payload["revoked_key_ids"])?;
        let next_grants = string_set(&payload["revoked_grant_ids"])?;
        if payload["trust_domain_id"] != anchor["trust_domain_id"]
            || uint(&payload["snapshot_sequence"])?
                != uint(&anchor["current_snapshot_sequence"])? + 1
            || text(&payload["previous_snapshot_digest"])? != digest(&previous_identity)?
            || uint(&payload["evaluation_time_unix_s"])? != now
            || authorization_payload["trust_domain_id"] != anchor["trust_domain_id"]
            || !anchor_keys.is_subset(&next_keys)
            || !anchor_grants.is_subset(&next_grants)
        {
            return Err(Invalid("identity.context_untrusted"));
        }

        let mut registry = object(&anchor["key_ownership_registry"])?.clone();
        for (key, principal) in key_owners(identity)? {
            registry.entry(key).or_insert(Value::String(principal));
        }
        anchor.insert(
            "current_identity_context_digest".to_owned(),
            Value::String(digest(identity)?),
        );
        anchor.insert(
            "current_authorization_context_digest".to_owned(),
            Value::String(digest(next_authorization)?),
        );
        anchor.insert(
            "current_snapshot_sequence".to_owned(),
            payload["snapshot_sequence"].clone(),
        );
        anchor.insert("trusted_now_unix_s".to_owned(), Value::from(now));
        anchor.insert("key_ownership_registry".to_owned(), Value::Object(registry));
        anchor.insert(
            "revoked_key_ids".to_owned(),
            Value::Array(next_keys.into_iter().map(Value::String).collect()),
        );
        anchor.insert(
            "revoked_grant_ids".to_owned(),
            Value::Array(next_grants.into_iter().map(Value::String).collect()),
        );
        previous_identity = identity.clone();
    }

    if let Some(probe) = history.get("probe_attested_proposal") {
        stage_three_attested(probe, &anchor)?;
    }
    Ok(())
}

fn validate(structural: &StructurallyValidM2Input) -> Check {
    match structural.entrypoint() {
        M2Entrypoint::EvaluateNew
        | M2Entrypoint::VerifyAttestedProposal
        | M2Entrypoint::ReplayHistorical => {
            let anchor = structural
                .trusted_anchor()
                .ok_or(Invalid("identity.context_untrusted"))?;
            stage_three_attested(structural.wire().value(), object(anchor)?)
        }
        M2Entrypoint::InitializeAnchor => stage_three_initialize(structural.wire().value()),
        #[cfg(feature = "conformance")]
        M2Entrypoint::AdvanceAnchorHistory => stage_three_history(structural.wire().value()),
    }
}

pub(crate) fn validate_anchor_transition_context(
    previous_anchor: &Value,
    previous_identity: &Value,
    next_identity: &Value,
    next_authorization: &Value,
    trusted_now: &Value,
) -> Result<(), M2WireRejection> {
    let result = (|| {
        let anchor = object(previous_anchor)?;
        let previous_payload = object(&object(previous_identity)?["payload"])?;
        let next_payload = object(&object(next_identity)?["payload"])?;
        let authorization_payload = object(&object(next_authorization)?["payload"])?;
        let anchor_keys = string_set(&anchor["revoked_key_ids"])?;
        let anchor_grants = string_set(&anchor["revoked_grant_ids"])?;
        let previous_keys = string_set(&previous_payload["revoked_key_ids"])?;
        let previous_grants = string_set(&previous_payload["revoked_grant_ids"])?;
        let registry = object(&anchor["key_ownership_registry"])?;
        let owners_match = key_owners(previous_identity)?
            .iter()
            .all(|(key, principal)| {
                registry.get(key).and_then(Value::as_str) == Some(principal.as_str())
            });
        if digest(previous_identity)? != text(&anchor["current_identity_context_digest"])?
            || previous_payload["trust_domain_id"] != anchor["trust_domain_id"]
            || previous_payload["snapshot_sequence"] != anchor["current_snapshot_sequence"]
            || previous_payload["evaluation_time_unix_s"] != anchor["trusted_now_unix_s"]
            || !previous_keys.is_subset(&anchor_keys)
            || !previous_grants.is_subset(&anchor_grants)
            || !owners_match
        {
            return Err(Invalid("identity.context_untrusted"));
        }

        let now = uint(trusted_now)?;
        let prior_now = uint(&anchor["trusted_now_unix_s"])?;
        if now < prior_now {
            return Err(Invalid("identity.context_stale"));
        }
        let next_keys = string_set(&next_payload["revoked_key_ids"])?;
        let next_grants = string_set(&next_payload["revoked_grant_ids"])?;
        if next_payload["trust_domain_id"] != anchor["trust_domain_id"]
            || authorization_payload["trust_domain_id"] != anchor["trust_domain_id"]
            || uint(&next_payload["snapshot_sequence"])?
                != uint(&anchor["current_snapshot_sequence"])? + 1
            || text(&next_payload["previous_snapshot_digest"])? != digest(previous_identity)?
            || uint(&next_payload["evaluation_time_unix_s"])? != now
            || !anchor_keys.is_subset(&next_keys)
            || !anchor_grants.is_subset(&next_grants)
        {
            return Err(Invalid("identity.context_untrusted"));
        }
        Ok(())
    })();
    result.map_err(|error: Invalid| M2WireRejection {
        stage: 3,
        code: error.0,
        authorizing: false,
    })
}

/// Apply M2.1 stages one through three without cryptography or authority.
pub fn inspect_m2_stage_three(
    source: &[u8],
    entrypoint: M2Entrypoint,
    trusted_anchor: Option<&Value>,
) -> Result<ContextBoundM2Input, M2WireRejection> {
    let structural = inspect_m2_stage_two(source, entrypoint, trusted_anchor)?;
    validate(&structural).map_err(|error| M2WireRejection {
        stage: 3,
        code: error.0,
        authorizing: false,
    })?;
    Ok(ContextBoundM2Input { structural })
}
