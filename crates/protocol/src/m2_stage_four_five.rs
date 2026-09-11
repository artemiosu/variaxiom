//! Disabled M2.1 digest and identity verifier (stages four and five).

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};

use crate::{
    CanonicalM2Wire, ContextBoundM2Input, M2Entrypoint, M2WireRejection, canonical_digest,
    inspect_m2_stage_three,
};

/// Owned input that passed target-digest and key-ID checks.
#[derive(Clone, Debug, PartialEq)]
pub struct DigestBoundM2Input {
    context: ContextBoundM2Input,
}

impl DigestBoundM2Input {
    /// Return the inspected operation.
    #[must_use]
    pub const fn entrypoint(&self) -> M2Entrypoint {
        self.context.entrypoint()
    }

    /// Return the immutable canonical wire snapshot.
    #[must_use]
    pub const fn wire(&self) -> &CanonicalM2Wire {
        self.context.wire()
    }

    /// Return the separately owned external anchor snapshot, when present.
    #[must_use]
    pub const fn trusted_anchor(&self) -> Option<&Value> {
        self.context.trusted_anchor()
    }

    /// Digest binding alone never authorizes an effect.
    #[must_use]
    pub const fn authorizing(&self) -> bool {
        false
    }
}

/// Owned input that passed identity, role, and revocation checks.
#[derive(Clone, Debug, PartialEq)]
pub struct IdentityBoundM2Input {
    digest_bound: DigestBoundM2Input,
}

impl IdentityBoundM2Input {
    /// Return the inspected operation.
    #[must_use]
    pub const fn entrypoint(&self) -> M2Entrypoint {
        self.digest_bound.entrypoint()
    }

    /// Return the immutable canonical wire snapshot.
    #[must_use]
    pub const fn wire(&self) -> &CanonicalM2Wire {
        self.digest_bound.wire()
    }

    /// Return the separately owned external anchor snapshot, when present.
    #[must_use]
    pub const fn trusted_anchor(&self) -> Option<&Value> {
        self.digest_bound.trusted_anchor()
    }

    /// Identity binding alone never authorizes an effect.
    #[must_use]
    pub const fn authorizing(&self) -> bool {
        false
    }
}

#[derive(Clone, Copy)]
struct Invalid {
    stage: u8,
    code: &'static str,
}

type Check<T = ()> = Result<T, Invalid>;

fn invalid(stage: u8, code: &'static str) -> Invalid {
    Invalid { stage, code }
}

fn object(value: &Value) -> Check<&Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| invalid(5, "identity.context_untrusted"))
}

fn text(value: &Value) -> Check<&str> {
    value
        .as_str()
        .ok_or_else(|| invalid(5, "identity.context_untrusted"))
}

fn proposal_payload(value: &Value) -> Check<&Map<String, Value>> {
    object(&object(value)?["payload"])
}

fn promotion_body(value: &Value) -> Check<&Map<String, Value>> {
    let proposal = proposal_payload(value)?;
    object(&object(&proposal["promotion_input"])?["payload"])
}

#[derive(Clone, Copy)]
struct Pair<'a> {
    envelope: &'a Value,
    signature: &'a Value,
    kind: &'static str,
    actor: &'a str,
}

fn pairs(value: &Value) -> Check<Vec<Pair<'_>>> {
    let body = promotion_body(value)?;
    let candidate = object(&body["candidate"])?;
    let candidate_payload = object(&object(&candidate["envelope"])?["payload"])?;
    let mut result = vec![Pair {
        envelope: &candidate["envelope"],
        signature: &candidate["signature"],
        kind: "candidate",
        actor: text(&candidate_payload["proposer"])?,
    }];
    for evidence in body["evidence"]
        .as_array()
        .ok_or_else(|| invalid(5, "identity.context_untrusted"))?
    {
        let evidence = object(evidence)?;
        let payload = object(&object(&evidence["envelope"])?["payload"])?;
        result.push(Pair {
            envelope: &evidence["envelope"],
            signature: &evidence["signature"],
            kind: "evidence",
            actor: text(&payload["verifier"])?,
        });
    }
    if let Some(grant) = body.get("authority_grant") {
        let grant = object(grant)?;
        let payload = object(&object(&grant["envelope"])?["payload"])?;
        result.push(Pair {
            envelope: &grant["envelope"],
            signature: &grant["signature"],
            kind: "authority-grant",
            actor: text(&payload["issuer_principal_id"])?,
        });
    }
    Ok(result)
}

fn selector_pair(value: &Value) -> Check<Pair<'_>> {
    let proposal = proposal_payload(value)?;
    let signature = &proposal["selector_signature"];
    let actor = text(&object(&object(signature)?["payload"])?["principal_id"])?;
    Ok(Pair {
        envelope: &proposal["decision"],
        signature,
        kind: "promotion-decision",
        actor,
    })
}

fn pairs_with_selector(value: &Value) -> Check<Vec<Pair<'_>>> {
    let mut result = pairs(value)?;
    result.push(selector_pair(value)?);
    Ok(result)
}

type PrincipalMap<'a> = BTreeMap<String, &'a Map<String, Value>>;
type KeyMap<'a> = BTreeMap<String, (String, &'a Map<String, Value>)>;

fn identity_maps(identity: &Value) -> Check<(PrincipalMap<'_>, KeyMap<'_>, bool)> {
    let payload = object(&object(identity)?["payload"])?;
    let mut principals = BTreeMap::new();
    let mut keys = BTreeMap::new();
    let mut public_keys = BTreeSet::new();
    let mut ambiguous = false;
    for principal in payload["principals"]
        .as_array()
        .ok_or_else(|| invalid(5, "identity.context_untrusted"))?
    {
        let principal = object(principal)?;
        let principal_id = text(&principal["principal_id"])?.to_owned();
        ambiguous |= principals.insert(principal_id.clone(), principal).is_some();
        for key in principal["keys"]
            .as_array()
            .ok_or_else(|| invalid(5, "identity.context_untrusted"))?
        {
            let key = object(key)?;
            let key_id = text(&key["key_id"])?.to_owned();
            let public = text(&key["public_key_base64url"])?.to_owned();
            ambiguous |= keys.insert(key_id, (principal_id.clone(), key)).is_some();
            ambiguous |= !public_keys.insert(public);
        }
    }
    Ok((principals, keys, ambiguous))
}

fn computed_key_id(binding: &Map<String, Value>) -> Option<String> {
    let encoded = binding.get("public_key_base64url")?.as_str()?;
    let public = URL_SAFE_NO_PAD.decode(encoded).ok()?;
    if public.len() != 32 || URL_SAFE_NO_PAD.encode(&public) != encoded {
        return None;
    }
    let mut digest = Sha256::new();
    digest.update(b"variaxiom-key/v1\0Ed25519\0");
    digest.update(public);
    let encoded = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Some(format!("key:sha256:{encoded}"))
}

fn signature_payload(pair: Pair<'_>) -> Check<&Map<String, Value>> {
    object(&object(pair.signature)?["payload"])
}

fn stage_four_pairs(pairs: &[Pair<'_>], keys: &KeyMap<'_>) -> Check {
    for pair in pairs {
        let signature = signature_payload(*pair)?;
        let target =
            canonical_digest(pair.envelope).map_err(|_| invalid(4, "signature.digest_mismatch"))?;
        if text(&signature["signed_digest"])? != target {
            return Err(invalid(4, "signature.digest_mismatch"));
        }
    }
    for pair in pairs {
        let signature = signature_payload(*pair)?;
        if let Some((_, binding)) = keys.get(text(&signature["key_id"])?)
            && let Some(expected) = computed_key_id(binding)
            && text(&binding["key_id"])? != expected
        {
            return Err(invalid(4, "signature.key_id_mismatch"));
        }
    }
    for pair in pairs {
        if text(&signature_payload(*pair)?["signed_kind"])? != pair.kind {
            return Err(invalid(4, "signature.kind_mismatch"));
        }
    }
    Ok(())
}

fn stage_four_bindings(identity: &Value) -> Check {
    let payload = object(&object(identity)?["payload"])?;
    for principal in payload["principals"]
        .as_array()
        .ok_or_else(|| invalid(4, "signature.key_id_mismatch"))?
    {
        let principal = object(principal)?;
        for binding in principal["keys"]
            .as_array()
            .ok_or_else(|| invalid(4, "signature.key_id_mismatch"))?
        {
            let binding = object(binding)?;
            if let Some(expected) = computed_key_id(binding)
                && text(&binding["key_id"])? != expected
            {
                return Err(invalid(4, "signature.key_id_mismatch"));
            }
        }
    }
    Ok(())
}

fn attested_identity(value: &Value) -> Check<&Value> {
    Ok(&promotion_body(value)?["identity_context"])
}

fn stage_four_attested(value: &Value) -> Check {
    let (_, keys, _) = identity_maps(attested_identity(value)?)?;
    stage_four_pairs(&pairs(value)?, &keys)
}

fn stage_four(context: &ContextBoundM2Input) -> Check {
    let value = context.wire().value();
    match context.entrypoint() {
        M2Entrypoint::VerifyAttestedProposal | M2Entrypoint::ReplayHistorical => {
            stage_four_attested(value)
        }
        M2Entrypoint::InitializeAnchor => {
            stage_four_bindings(&object(value)?["initial_identity_context"])
        }
        M2Entrypoint::AdvanceAnchorHistory => {
            let history = object(value)?;
            stage_four_bindings(&history["initial_identity_context"])?;
            for step in history["steps"]
                .as_array()
                .ok_or_else(|| invalid(4, "signature.digest_mismatch"))?
            {
                stage_four_bindings(&object(step)?["next_identity_context"])?;
            }
            if let Some(probe) = history.get("probe_attested_proposal") {
                stage_four_attested(probe)?;
            }
            Ok(())
        }
    }
}

fn required_role(kind: &str) -> &'static str {
    match kind {
        "candidate" => "candidate-proposer",
        "evidence" => "evidence-verifier",
        "authority-grant" => "authority-issuer",
        "promotion-decision" => "promotion-selector",
        _ => "",
    }
}

fn has_role(principal: &Map<String, Value>, role: &str) -> bool {
    principal["roles"]
        .as_array()
        .is_some_and(|roles| roles.iter().any(|item| item.as_str() == Some(role)))
}

fn stage_five_attested_pairs(
    value: &Value,
    anchor: &Map<String, Value>,
    pairs: &[Pair<'_>],
    role_pairs: &[Pair<'_>],
) -> Check {
    let (principals, keys, ambiguous) = identity_maps(attested_identity(value)?)?;
    for pair in pairs {
        if text(&signature_payload(*pair)?["principal_id"])? != pair.actor {
            return Err(invalid(5, "signature.principal_mismatch"));
        }
    }
    if ambiguous {
        return Err(invalid(5, "identity.key_ambiguous"));
    }
    for pair in pairs {
        if !principals.contains_key(text(&signature_payload(*pair)?["principal_id"])?) {
            return Err(invalid(5, "identity.principal_unknown"));
        }
    }
    for pair in pairs {
        let signature = signature_payload(*pair)?;
        let principal_id = text(&signature["principal_id"])?;
        if keys
            .get(text(&signature["key_id"])?)
            .is_none_or(|(owner, _)| owner != principal_id)
        {
            return Err(invalid(5, "identity.key_unbound"));
        }
    }
    let revoked_keys = anchor["revoked_key_ids"]
        .as_array()
        .ok_or_else(|| invalid(5, "identity.context_untrusted"))?;
    for pair in pairs {
        let key_id = text(&signature_payload(*pair)?["key_id"])?;
        if revoked_keys
            .iter()
            .any(|item| item.as_str() == Some(key_id))
        {
            return Err(invalid(5, "signature.key_revoked"));
        }
    }
    let body = promotion_body(value)?;
    if let Some(grant) = body.get("authority_grant") {
        let envelope = &object(grant)?["envelope"];
        let grant_id = format!(
            "grant:sha256:{}",
            canonical_digest(envelope).map_err(|_| invalid(5, "grant.revoked"))?
        );
        if anchor["revoked_grant_ids"]
            .as_array()
            .ok_or_else(|| invalid(5, "identity.context_untrusted"))?
            .iter()
            .any(|item| item.as_str() == Some(grant_id.as_str()))
        {
            return Err(invalid(5, "grant.revoked"));
        }
    }
    for pair in pairs {
        let principal_id = text(&signature_payload(*pair)?["principal_id"])?;
        let principal = principals
            .get(principal_id)
            .ok_or_else(|| invalid(5, "identity.principal_unknown"))?;
        if !has_role(principal, required_role(pair.kind)) {
            return Err(invalid(5, "identity.role_missing"));
        }
    }
    let evidence_actors = role_pairs
        .iter()
        .filter(|pair| pair.kind == "evidence")
        .map(|pair| pair.actor)
        .collect::<BTreeSet<_>>();
    let other_actors = role_pairs
        .iter()
        .filter(|pair| pair.kind != "evidence")
        .map(|pair| pair.actor)
        .collect::<Vec<_>>();
    if other_actors.len() != other_actors.iter().copied().collect::<BTreeSet<_>>().len()
        || other_actors
            .iter()
            .any(|actor| evidence_actors.contains(actor))
    {
        return Err(invalid(5, "identity.role_conflict"));
    }
    let constitution = object(&object(&body["constitution"])?["envelope"])?;
    let constitution = object(&constitution["payload"])?;
    let minimum = constitution["minimum_independent_verifiers"]
        .as_u64()
        .ok_or_else(|| invalid(5, "identity.context_untrusted"))?;
    if !evidence_actors.is_empty() && evidence_actors.len() < minimum as usize {
        return Err(invalid(5, "identity.not_independent"));
    }
    Ok(())
}

fn stage_five_attested(value: &Value, anchor: &Map<String, Value>) -> Check {
    let pairs = pairs(value)?;
    stage_five_attested_pairs(value, anchor, &pairs, &pairs)
}

pub(crate) fn verify_selector_stages_four_five(
    value: &Value,
    anchor: &Value,
) -> Result<(), M2WireRejection> {
    let identity = attested_identity(value).map_err(|error| M2WireRejection {
        stage: 11,
        code: error.code,
        authorizing: false,
    })?;
    let (_, keys, _) = identity_maps(identity).map_err(|error| M2WireRejection {
        stage: 11,
        code: error.code,
        authorizing: false,
    })?;
    let selector = selector_pair(value).map_err(|error| M2WireRejection {
        stage: 11,
        code: error.code,
        authorizing: false,
    })?;
    stage_four_pairs(&[selector], &keys).map_err(|error| M2WireRejection {
        stage: 11,
        code: error.code,
        authorizing: false,
    })?;
    let all_pairs = pairs_with_selector(value).map_err(|error| M2WireRejection {
        stage: 11,
        code: error.code,
        authorizing: false,
    })?;
    let anchor = object(anchor).map_err(|error| M2WireRejection {
        stage: 11,
        code: error.code,
        authorizing: false,
    })?;
    stage_five_attested_pairs(value, anchor, &[selector], &all_pairs).map_err(|error| {
        M2WireRejection {
            stage: 11,
            code: error.code,
            authorizing: false,
        }
    })
}

fn stage_five_context(identity: &Value) -> Check<KeyMap<'_>> {
    let (_, keys, ambiguous) = identity_maps(identity)?;
    if ambiguous {
        return Err(invalid(5, "identity.key_ambiguous"));
    }
    Ok(keys)
}

fn advance_anchor(
    anchor: &Map<String, Value>,
    identity: &Value,
    authorization: &Value,
    now: &Value,
) -> Check<Map<String, Value>> {
    let payload = object(&object(identity)?["payload"])?;
    let mut registry = object(&anchor["key_ownership_registry"])?.clone();
    for (key, (principal, _)) in &identity_maps(identity)?.1 {
        registry
            .entry(key.clone())
            .or_insert_with(|| Value::String(principal.clone()));
    }
    let mut revoked_keys = anchor["revoked_key_ids"]
        .as_array()
        .ok_or_else(|| invalid(5, "identity.context_untrusted"))?
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    revoked_keys.extend(
        payload["revoked_key_ids"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned),
    );
    let mut revoked_grants = anchor["revoked_grant_ids"]
        .as_array()
        .ok_or_else(|| invalid(5, "identity.context_untrusted"))?
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    revoked_grants.extend(
        payload["revoked_grant_ids"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned),
    );
    Ok(Map::from_iter([
        (
            "trust_domain_id".to_owned(),
            anchor["trust_domain_id"].clone(),
        ),
        (
            "current_identity_context_digest".to_owned(),
            Value::String(
                canonical_digest(identity).map_err(|_| invalid(5, "identity.context_untrusted"))?,
            ),
        ),
        (
            "current_authorization_context_digest".to_owned(),
            Value::String(
                canonical_digest(authorization)
                    .map_err(|_| invalid(5, "identity.context_untrusted"))?,
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

fn stage_five(digest_bound: &DigestBoundM2Input) -> Check {
    let value = digest_bound.wire().value();
    match digest_bound.entrypoint() {
        M2Entrypoint::VerifyAttestedProposal | M2Entrypoint::ReplayHistorical => {
            let anchor = digest_bound
                .trusted_anchor()
                .ok_or_else(|| invalid(5, "identity.context_untrusted"))?;
            stage_five_attested(value, object(anchor)?)
        }
        M2Entrypoint::InitializeAnchor => {
            stage_five_context(&object(value)?["initial_identity_context"])?;
            Ok(())
        }
        M2Entrypoint::AdvanceAnchorHistory => {
            let history = object(value)?;
            let mut anchor = object(&history["initial_anchor"])?.clone();
            stage_five_context(&history["initial_identity_context"])?;
            for step in history["steps"]
                .as_array()
                .ok_or_else(|| invalid(5, "identity.context_untrusted"))?
            {
                let step = object(step)?;
                let identity = &step["next_identity_context"];
                let keys = stage_five_context(identity)?;
                let registry = object(&anchor["key_ownership_registry"])?;
                let revoked = anchor["revoked_key_ids"]
                    .as_array()
                    .ok_or_else(|| invalid(5, "identity.context_untrusted"))?;
                for (key, (principal, _)) in &keys {
                    if registry
                        .get(key)
                        .and_then(Value::as_str)
                        .is_some_and(|owner| owner != principal)
                    {
                        return Err(invalid(5, "identity.key_ambiguous"));
                    }
                    if revoked.iter().any(|item| item.as_str() == Some(key)) {
                        return Err(invalid(5, "signature.key_revoked"));
                    }
                }
                anchor = advance_anchor(
                    &anchor,
                    identity,
                    &step["next_authorization_context"],
                    &step["trusted_now_unix_s"],
                )?;
            }
            if let Some(probe) = history.get("probe_attested_proposal") {
                stage_five_attested(probe, &anchor)?;
            }
            Ok(())
        }
    }
}

/// Apply M2.1 stages one through four without cryptography or authority.
pub fn inspect_m2_stage_four(
    source: &[u8],
    entrypoint: M2Entrypoint,
    trusted_anchor: Option<&Value>,
) -> Result<DigestBoundM2Input, M2WireRejection> {
    let context = inspect_m2_stage_three(source, entrypoint, trusted_anchor)?;
    stage_four(&context).map_err(|error| M2WireRejection {
        stage: error.stage,
        code: error.code,
        authorizing: false,
    })?;
    Ok(DigestBoundM2Input { context })
}

/// Apply M2.1 stages one through five without cryptography or authority.
pub fn inspect_m2_stage_five(
    source: &[u8],
    entrypoint: M2Entrypoint,
    trusted_anchor: Option<&Value>,
) -> Result<IdentityBoundM2Input, M2WireRejection> {
    let digest_bound = inspect_m2_stage_four(source, entrypoint, trusted_anchor)?;
    stage_five(&digest_bound).map_err(|error| M2WireRejection {
        stage: error.stage,
        code: error.code,
        authorizing: false,
    })?;
    Ok(IdentityBoundM2Input { digest_bound })
}
