//! Disabled M2.1 structural verifier (stages one and two only).

use std::collections::BTreeSet;

use serde_json::{Map, Value};

use crate::{CanonicalM2Wire, M2WireRejection, canonical_json, inspect_m2_wire, parse_json_strict};

/// M2.1 operation whose untrusted input is being inspected.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum M2Entrypoint {
    /// Evaluate an unsigned promotion input and return non-authorizing policy data.
    EvaluateNew,
    /// Inspect a signed proposal plus a separately supplied anchor snapshot.
    VerifyAttestedProposal,
    /// Inspect a historical proposal without authorizing a new transition.
    ReplayHistorical,
    /// Inspect a genesis anchor initialization request.
    InitializeAnchor,
    /// Inspect a bounded sequence of anchor transitions.
    #[cfg(feature = "conformance")]
    AdvanceAnchorHistory,
}

/// Owned input that passed stages one and two but grants no authority.
#[derive(Clone, Debug, PartialEq)]
pub struct StructurallyValidM2Input {
    entrypoint: M2Entrypoint,
    wire: CanonicalM2Wire,
    trusted_anchor: Option<Value>,
}

impl StructurallyValidM2Input {
    /// Return the operation whose input was inspected.
    #[must_use]
    pub const fn entrypoint(&self) -> M2Entrypoint {
        self.entrypoint
    }
    /// Return the immutable canonical wire snapshot.
    #[must_use]
    pub const fn wire(&self) -> &CanonicalM2Wire {
        &self.wire
    }
    /// Return the separately owned external anchor snapshot, when present.
    #[must_use]
    pub const fn trusted_anchor(&self) -> Option<&Value> {
        self.trusted_anchor.as_ref()
    }
    /// Structural inspection never authorizes an effect.
    #[must_use]
    pub const fn authorizing(&self) -> bool {
        false
    }
}

#[derive(Clone, Copy)]
struct Invalid(&'static str);
type Check<T = ()> = Result<T, Invalid>;

fn schema() -> Invalid {
    Invalid("input.schema_invalid")
}
fn limit() -> Invalid {
    Invalid("input.limit_exceeded")
}
fn object(value: &Value) -> Check<&Map<String, Value>> {
    value.as_object().ok_or_else(schema)
}
fn array(value: &Value) -> Check<&Vec<Value>> {
    value.as_array().ok_or_else(schema)
}

fn exact<'a>(
    value: &'a Value,
    required: &[&str],
    optional: &[&str],
) -> Check<&'a Map<String, Value>> {
    let item = object(value)?;
    if required.iter().any(|field| !item.contains_key(*field))
        || item
            .keys()
            .any(|field| !required.contains(&field.as_str()) && !optional.contains(&field.as_str()))
    {
        return Err(schema());
    }
    Ok(item)
}

fn envelope<'a>(value: &'a Value, kind: &str) -> Check<&'a Map<String, Value>> {
    let item = exact(value, &["envelope_version", "kind", "payload"], &[])?;
    if item["envelope_version"] != "variaxiom-envelope/v1" || item["kind"] != kind {
        return Err(schema());
    }
    object(&item["payload"])?;
    Ok(item)
}

fn text(value: &Value) -> Check<&str> {
    let item = value
        .as_str()
        .filter(|item| !item.is_empty())
        .ok_or_else(schema)?;
    if item
        .chars()
        .any(|character| character <= '\u{1f}' || character == '\u{7f}')
    {
        return Err(schema());
    }
    Ok(item)
}

fn token(value: &Value) -> Check<&str> {
    let item = text(value)?;
    if item.contains(',') {
        return Err(schema());
    }
    Ok(item)
}

fn digest(value: &Value) -> Check<&str> {
    let item = text(value)?;
    if item.len() != 64
        || !item
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(schema());
    }
    Ok(item)
}

fn prefixed<'a>(value: &'a Value, prefix: &str) -> Check<&'a str> {
    let item = text(value)?;
    let suffix = item.strip_prefix(prefix).ok_or_else(schema)?;
    if suffix.len() != 64
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(schema());
    }
    Ok(item)
}

fn ascii_id<'a>(value: &'a Value, prefix: &str) -> Check<&'a str> {
    let item = text(value)?;
    let suffix = item.strip_prefix(prefix).ok_or_else(schema)?;
    if suffix.is_empty()
        || !suffix.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._:/-".contains(&byte)
        })
    {
        return Err(schema());
    }
    Ok(item)
}

fn sorted<'a, F>(value: &'a Value, minimum: usize, maximum: usize, check: F) -> Check<Vec<&'a str>>
where
    F: Fn(&'a Value) -> Check<&'a str>,
{
    let items = array(value)?;
    if items.len() < minimum {
        return Err(schema());
    }
    if items.len() > maximum {
        return Err(limit());
    }
    let actual = items.iter().map(check).collect::<Check<Vec<_>>>()?;
    let mut expected = actual.clone();
    expected.sort_unstable();
    expected.dedup();
    if actual != expected {
        return Err(schema());
    }
    Ok(actual)
}

fn uint(value: &Value) -> Check<u64> {
    value
        .as_u64()
        .filter(|number| *number <= 9_007_199_254_740_991)
        .ok_or_else(schema)
}

fn signature(value: &Value) -> Check {
    let body = &envelope(value, "detached-signature")?["payload"];
    let body = exact(
        body,
        &[
            "signature_version",
            "algorithm",
            "trust_domain_id",
            "principal_id",
            "key_id",
            "signed_kind",
            "signed_digest",
            "signature_base64url",
        ],
        &[],
    )?;
    if body["signature_version"] != "detached-signature/v1" {
        return Err(schema());
    }
    for field in ["algorithm", "signature_base64url"] {
        text(&body[field])?;
    }
    ascii_id(&body["trust_domain_id"], "trust-domain:")?;
    ascii_id(&body["principal_id"], "principal:")?;
    prefixed(&body["key_id"], "key:sha256:")?;
    digest(&body["signed_digest"])?;
    if !matches!(
        body["signed_kind"].as_str(),
        Some("candidate" | "evidence" | "authority-grant" | "promotion-decision")
    ) {
        return Err(schema());
    }
    Ok(())
}

fn principal(value: &Value) -> Check<&str> {
    let body = exact(
        value,
        &["principal_version", "principal_id", "roles", "keys"],
        &[],
    )?;
    if body["principal_version"] != "principal/v1" {
        return Err(schema());
    }
    let id = ascii_id(&body["principal_id"], "principal:")?;
    sorted(&body["roles"], 1, 8, token)?;
    let keys = array(&body["keys"])?;
    if keys.is_empty() {
        return Err(schema());
    }
    if keys.len() > 8 {
        return Err(limit());
    }
    let mut ids = Vec::new();
    for key in keys {
        let key = exact(
            key,
            &[
                "key_binding_version",
                "algorithm",
                "key_id",
                "public_key_base64url",
            ],
            &[],
        )?;
        if key["key_binding_version"] != "key-binding/v1" {
            return Err(schema());
        }
        text(&key["algorithm"])?;
        ids.push(prefixed(&key["key_id"], "key:sha256:")?);
        text(&key["public_key_base64url"])?;
    }
    let mut expected = ids.clone();
    expected.sort_unstable();
    expected.dedup();
    if ids != expected {
        return Err(schema());
    }
    Ok(id)
}

fn identity(value: &Value) -> Check<&Map<String, Value>> {
    let body = &envelope(value, "identity-context")?["payload"];
    let body = exact(
        body,
        &[
            "identity_context_version",
            "trust_domain_id",
            "snapshot_sequence",
            "previous_snapshot_digest",
            "evaluation_time_unix_s",
            "principals",
            "revoked_key_ids",
            "revoked_grant_ids",
        ],
        &[],
    )?;
    if body["identity_context_version"] != "identity-context/v1" {
        return Err(schema());
    }
    ascii_id(&body["trust_domain_id"], "trust-domain:")?;
    let sequence = uint(&body["snapshot_sequence"])?;
    if (sequence == 0 && !body["previous_snapshot_digest"].is_null())
        || (sequence != 0 && body["previous_snapshot_digest"].is_null())
    {
        return Err(schema());
    }
    if sequence != 0 {
        text(&body["previous_snapshot_digest"])?;
    }
    uint(&body["evaluation_time_unix_s"])?;
    let principals = array(&body["principals"])?;
    if principals.is_empty() {
        return Err(schema());
    }
    if principals.len() > 64 {
        return Err(limit());
    }
    let ids = principals
        .iter()
        .map(principal)
        .collect::<Check<Vec<_>>>()?;
    let mut expected = ids.clone();
    expected.sort_unstable();
    if ids != expected {
        return Err(schema());
    }
    sorted(&body["revoked_key_ids"], 0, 4096, |item| {
        prefixed(item, "key:sha256:")
    })?;
    sorted(&body["revoked_grant_ids"], 0, 4096, |item| {
        prefixed(item, "grant:sha256:")
    })?;
    Ok(body)
}

fn authorization(value: &Value) -> Check<&Map<String, Value>> {
    let body = &envelope(value, "authorization-context")?["payload"];
    let body = exact(
        body,
        &[
            "authorization_context_version",
            "trust_domain_id",
            "capability_namespace",
            "lineage_id",
            "constitution_envelope_digest",
            "constitution_artifact_hash",
            "known_lineage_ids",
            "lineage_capabilities",
            "verified_artifact_hashes",
        ],
        &[],
    )?;
    if body["authorization_context_version"] != "authorization-context/v1" {
        return Err(schema());
    }
    ascii_id(&body["trust_domain_id"], "trust-domain:")?;
    token(&body["capability_namespace"])?;
    token(&body["lineage_id"])?;
    digest(&body["constitution_envelope_digest"])?;
    digest(&body["constitution_artifact_hash"])?;
    let known = sorted(&body["known_lineage_ids"], 0, 4096, token)?;
    let lineage = object(&body["lineage_capabilities"])?;
    if lineage.len() > 4096 {
        return Err(limit());
    }
    for (key, capabilities) in lineage {
        token(&Value::String(key.clone()))?;
        sorted(capabilities, 0, 128, text)?;
    }
    if known != lineage.keys().map(String::as_str).collect::<Vec<_>>() {
        return Err(schema());
    }
    sorted(&body["verified_artifact_hashes"], 0, 4096, digest)?;
    Ok(body)
}

fn context_preflight(identity: &Value, authorization: &Value, kinds: bool) -> Check {
    for (item, field, expected) in [
        (identity, "identity_context_version", "identity-context/v1"),
        (
            authorization,
            "authorization_context_version",
            "authorization-context/v1",
        ),
    ] {
        if item
            .get("envelope_version")
            .is_some_and(|version| version != "variaxiom-envelope/v1")
        {
            return Err(Invalid("input.version_unsupported"));
        }
        if item
            .pointer(&format!("/payload/{field}"))
            .is_some_and(|version| version != expected)
        {
            return Err(Invalid("input.version_unsupported"));
        }
    }
    if let Some(principals) = identity
        .pointer("/payload/principals")
        .and_then(Value::as_array)
    {
        for principal in principals {
            if principal
                .get("principal_version")
                .is_some_and(|version| version != "principal/v1")
            {
                return Err(Invalid("input.version_unsupported"));
            }
            if let Some(keys) = principal.get("keys").and_then(Value::as_array) {
                for key in keys {
                    if key
                        .get("key_binding_version")
                        .is_some_and(|version| version != "key-binding/v1")
                    {
                        return Err(Invalid("input.version_unsupported"));
                    }
                }
            }
        }
    }
    if kinds {
        for (item, expected) in [
            (identity, "identity-context"),
            (authorization, "authorization-context"),
        ] {
            if item.get("kind").is_some_and(|kind| kind != expected) {
                return Err(Invalid("input.kind_mismatch"));
            }
        }
    }
    Ok(())
}

fn promotion_input_paths(value: &Value) -> Vec<(&Value, &'static str)> {
    let mut paths = vec![(value, "promotion-input")];
    let Some(body) = value.get("payload") else {
        return paths;
    };
    for (field, kind) in [
        ("identity_context", "identity-context"),
        ("authorization_context", "authorization-context"),
    ] {
        if let Some(item) = body.get(field) {
            paths.push((item, kind));
        }
    }
    for (field, kind) in [
        ("candidate", "candidate"),
        ("authority_grant", "authority-grant"),
    ] {
        if let Some(pair) = body.get(field) {
            if let Some(item) = pair.get("envelope") {
                paths.push((item, kind));
            }
            if let Some(item) = pair.get("signature") {
                paths.push((item, "detached-signature"));
            }
        }
    }
    if let Some(item) = body.pointer("/constitution/envelope") {
        paths.push((item, "constitution"));
    }
    if let Some(items) = body.get("evidence").and_then(Value::as_array) {
        for pair in items {
            if let Some(item) = pair.get("envelope") {
                paths.push((item, "evidence"));
            }
            if let Some(item) = pair.get("signature") {
                paths.push((item, "detached-signature"));
            }
        }
    }
    paths
}

fn attested_paths(value: &Value) -> Vec<(&Value, &'static str)> {
    let mut paths = vec![(value, "attested-proposal")];
    let Some(payload) = value.get("payload") else {
        return paths;
    };
    if let Some(input) = payload.get("promotion_input") {
        paths.push((input, "promotion-input"));
        if let Some(body) = input.get("payload") {
            for (field, kind) in [
                ("identity_context", "identity-context"),
                ("authorization_context", "authorization-context"),
            ] {
                if let Some(item) = body.get(field) {
                    paths.push((item, kind));
                }
            }
            for (field, kind) in [
                ("candidate", "candidate"),
                ("authority_grant", "authority-grant"),
            ] {
                if let Some(pair) = body.get(field) {
                    if let Some(item) = pair.get("envelope") {
                        paths.push((item, kind));
                    }
                    if let Some(item) = pair.get("signature") {
                        paths.push((item, "detached-signature"));
                    }
                }
            }
            if let Some(item) = body.pointer("/constitution/envelope") {
                paths.push((item, "constitution"));
            }
            if let Some(items) = body.get("evidence").and_then(Value::as_array) {
                for pair in items {
                    if let Some(item) = pair.get("envelope") {
                        paths.push((item, "evidence"));
                    }
                    if let Some(item) = pair.get("signature") {
                        paths.push((item, "detached-signature"));
                    }
                }
            }
        }
    }
    if let Some(item) = payload.get("decision") {
        paths.push((item, "promotion-decision"));
    }
    if let Some(item) = payload.get("selector_signature") {
        paths.push((item, "detached-signature"));
    }
    paths
}

fn proposal_preflight(value: &Value, attested: bool) -> Check {
    let paths = if attested {
        attested_paths(value)
    } else {
        promotion_input_paths(value)
    };
    for (item, _) in &paths {
        if item
            .get("envelope_version")
            .is_some_and(|version| version != "variaxiom-envelope/v1")
        {
            return Err(Invalid("input.version_unsupported"));
        }
    }
    let versions = [
        (
            "attested-proposal",
            "proposal_version",
            "attested-proposal/v1",
        ),
        ("promotion-input", "protocol_version", "promotion-input/v2"),
        ("candidate", "candidate_version", "candidate/v2"),
        ("evidence", "evidence_version", "evidence/v2"),
        ("constitution", "version", "constitution/v1"),
        (
            "identity-context",
            "identity_context_version",
            "identity-context/v1",
        ),
        (
            "authorization-context",
            "authorization_context_version",
            "authorization-context/v1",
        ),
        ("authority-grant", "grant_version", "authority-grant/v1"),
        (
            "detached-signature",
            "signature_version",
            "detached-signature/v1",
        ),
    ];
    for (item, kind) in &paths {
        if let Some((_, field, expected)) = versions.iter().find(|(name, _, _)| name == kind)
            && item
                .get("payload")
                .and_then(|body| body.get(*field))
                .is_some_and(|version| version != *expected)
        {
            return Err(Invalid("input.version_unsupported"));
        }
    }
    let body = if attested {
        value.pointer("/payload/promotion_input/payload")
    } else {
        value.pointer("/payload")
    };
    if let Some(body) = body {
        context_preflight(
            &body["identity_context"],
            &body["authorization_context"],
            false,
        )?;
    }
    for (item, kind) in paths {
        if item.get("kind").is_some_and(|actual| actual != kind) {
            return Err(Invalid("input.kind_mismatch"));
        }
    }
    Ok(())
}

fn strings(value: &Value, excluded: bool) -> Check {
    match value {
        Value::String(item) if !excluded && item.len() > 256 => Err(limit()),
        Value::Array(items) => {
            for item in items {
                strings(item, excluded)?;
            }
            Ok(())
        }
        Value::Object(items) => {
            for (key, item) in items {
                if !excluded && key.len() > 256 {
                    return Err(limit());
                }
                strings(
                    item,
                    excluded || matches!(key.as_str(), "metadata" | "details"),
                )?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn pair(value: &Value, kind: &str) -> Check {
    let pair = exact(value, &["envelope", "signature"], &[])?;
    match kind {
        "candidate" => candidate(&pair["envelope"]),
        "evidence" => evidence(&pair["envelope"]).map(|_| ()),
        "authority-grant" => {
            let body = &envelope(&pair["envelope"], "authority-grant")?["payload"];
            let body = exact(
                body,
                &[
                    "grant_version",
                    "audience",
                    "trust_domain_id",
                    "capability_namespace",
                    "constitution_digest",
                    "lineage_id",
                    "issuer_principal_id",
                    "subject_candidate_digest",
                    "capabilities",
                    "not_before_unix_s",
                    "expires_at_unix_s",
                    "delegable",
                ],
                &[],
            )?;
            if body["grant_version"] != "authority-grant/v1" {
                return Err(schema());
            }
            token(&body["audience"])?;
            ascii_id(&body["trust_domain_id"], "trust-domain:")?;
            token(&body["capability_namespace"])?;
            digest(&body["constitution_digest"])?;
            token(&body["lineage_id"])?;
            ascii_id(&body["issuer_principal_id"], "principal:")?;
            digest(&body["subject_candidate_digest"])?;
            sorted(&body["capabilities"], 1, 128, |item| ascii_id(item, ""))?;
            uint(&body["not_before_unix_s"])?;
            if uint(&body["expires_at_unix_s"])? == 0 || !body["delegable"].is_boolean() {
                return Err(schema());
            }
            Ok(())
        }
        _ => Err(schema()),
    }?;
    signature(&pair["signature"])
}

fn candidate(value: &Value) -> Check {
    let body = &envelope(value, "candidate")?["payload"];
    let body = exact(
        body,
        &[
            "candidate_version",
            "candidate_id",
            "parent_id",
            "artifact_hash",
            "proposer",
            "rollback_target",
            "baseline_capabilities",
            "requested_capabilities",
            "estimated_cost_micro_usd",
            "metadata",
        ],
        &[],
    )?;
    token(&body["candidate_id"])?;
    token(&body["parent_id"])?;
    token(&body["rollback_target"])?;
    if body["candidate_version"] != "candidate/v2" {
        return Err(schema());
    }
    digest(&body["artifact_hash"])?;
    ascii_id(&body["proposer"], "principal:")?;
    sorted(&body["baseline_capabilities"], 0, 128, |item| {
        ascii_id(item, "")
    })?;
    sorted(&body["requested_capabilities"], 0, 128, |item| {
        ascii_id(item, "")
    })?;
    uint(&body["estimated_cost_micro_usd"])?;
    object(&body["metadata"])?;
    if canonical_json(&body["metadata"])
        .map_err(|_| schema())?
        .len()
        > 65_536
    {
        return Err(limit());
    }
    Ok(())
}

fn evidence(value: &Value) -> Check<&str> {
    let body = &envelope(value, "evidence")?["payload"];
    let body = exact(
        body,
        &[
            "evidence_version",
            "evidence_id",
            "subject_candidate_digest",
            "artifact_hash",
            "check",
            "status",
            "verifier",
            "independent",
            "details",
        ],
        &[],
    )?;
    if body["evidence_version"] != "evidence/v2" {
        return Err(schema());
    }
    let id = token(&body["evidence_id"])?;
    digest(&body["subject_candidate_digest"])?;
    digest(&body["artifact_hash"])?;
    token(&body["check"])?;
    if !matches!(body["status"].as_str(), Some("pass" | "fail" | "error"))
        || !body["independent"].is_boolean()
    {
        return Err(schema());
    }
    ascii_id(&body["verifier"], "principal:")?;
    object(&body["details"])?;
    if canonical_json(&body["details"])
        .map_err(|_| schema())?
        .len()
        > 65_536
    {
        return Err(limit());
    }
    Ok(id)
}

fn constitution(value: &Value) -> Check {
    let body = &envelope(value, "constitution")?["payload"];
    let body = exact(
        body,
        &[
            "version",
            "mandatory_checks",
            "minimum_independent_verifiers",
            "max_candidate_cost_micro_usd",
            "require_known_parent",
            "require_rollback_target",
            "forbid_self_verification",
            "forbid_implicit_authority_escalation",
            "reject_any_failed_evidence",
        ],
        &[],
    )?;
    if body["version"] != "constitution/v1" || uint(&body["minimum_independent_verifiers"])? == 0 {
        return Err(schema());
    }
    sorted(&body["mandatory_checks"], 1, usize::MAX, text)?;
    uint(&body["max_candidate_cost_micro_usd"])?;
    for field in [
        "require_known_parent",
        "require_rollback_target",
        "forbid_self_verification",
        "forbid_implicit_authority_escalation",
        "reject_any_failed_evidence",
    ] {
        if body[field] != true {
            return Err(schema());
        }
    }
    Ok(())
}

fn decision(value: &Value) -> Check {
    let body = &envelope(value, "promotion-decision")?["payload"];
    let body = exact(
        body,
        &[
            "candidate_id",
            "status",
            "reasons",
            "evidence_ids",
            "input_digest",
            "constitution_version",
            "gate_version",
        ],
        &[],
    )?;
    text(&body["candidate_id"])?;
    let status = body["status"].as_str().ok_or_else(schema)?;
    let reasons = sorted(&body["reasons"], 1, usize::MAX, text)?;
    if !matches!(status, "accepted" | "rejected")
        || (status == "accepted" && reasons != ["promotion.accepted"])
        || (status == "rejected" && reasons.contains(&"promotion.accepted"))
    {
        return Err(schema());
    }
    sorted(&body["evidence_ids"], 0, usize::MAX, text)?;
    digest(&body["input_digest"])?;
    if body["constitution_version"] != "constitution/v1" || body["gate_version"] != "proof-gate/v1"
    {
        return Err(schema());
    }
    Ok(())
}

fn promotion_input(value: &Value) -> Check {
    let input = &envelope(value, "promotion-input")?["payload"];
    let input = exact(
        input,
        &[
            "protocol_version",
            "candidate",
            "evidence",
            "constitution",
            "identity_context",
            "authorization_context",
        ],
        &["authority_grant"],
    )?;
    pair(&input["candidate"], "candidate")?;
    let evidence_items = array(&input["evidence"])?;
    if evidence_items.is_empty() {
        return Err(schema());
    }
    if evidence_items.len() > 256 {
        return Err(limit());
    }
    let mut ids = Vec::new();
    for item in evidence_items {
        let pair_body = exact(item, &["envelope", "signature"], &[])?;
        ids.push(evidence(&pair_body["envelope"])?);
        signature(&pair_body["signature"])?;
    }
    let mut expected = ids.clone();
    expected.sort_unstable();
    if ids != expected {
        return Err(schema());
    }
    let constitution_pair = exact(&input["constitution"], &["envelope", "artifact_hash"], &[])?;
    constitution(&constitution_pair["envelope"])?;
    digest(&constitution_pair["artifact_hash"])?;
    identity(&input["identity_context"])?;
    authorization(&input["authorization_context"])?;
    if let Some(grant) = input.get("authority_grant") {
        pair(grant, "authority-grant")?;
    }
    Ok(())
}

fn attested(value: &Value) -> Check {
    let payload = &envelope(value, "attested-proposal")?["payload"];
    let payload = exact(
        payload,
        &[
            "proposal_version",
            "promotion_input",
            "decision",
            "selector_signature",
        ],
        &[],
    )?;
    promotion_input(&payload["promotion_input"])?;
    decision(&payload["decision"])?;
    signature(&payload["selector_signature"])?;
    Ok(())
}

fn anchor(value: &Value) -> Check<&Map<String, Value>> {
    let body = exact(
        value,
        &[
            "trust_domain_id",
            "current_identity_context_digest",
            "current_authorization_context_digest",
            "current_snapshot_sequence",
            "trusted_now_unix_s",
            "key_ownership_registry",
            "revoked_key_ids",
            "revoked_grant_ids",
        ],
        &[],
    )?;
    let registry = object(&body["key_ownership_registry"])?;
    if registry.len() > 4096 {
        return Err(limit());
    }
    ascii_id(&body["trust_domain_id"], "trust-domain:")?;
    digest(&body["current_identity_context_digest"])?;
    digest(&body["current_authorization_context_digest"])?;
    uint(&body["current_snapshot_sequence"])?;
    uint(&body["trusted_now_unix_s"])?;
    for (key, principal) in registry {
        prefixed(&Value::String(key.clone()), "key:sha256:")?;
        ascii_id(principal, "principal:")?;
    }
    sorted(&body["revoked_key_ids"], 0, 4096, |item| {
        prefixed(item, "key:sha256:")
    })?;
    sorted(&body["revoked_grant_ids"], 0, 4096, |item| {
        prefixed(item, "grant:sha256:")
    })?;
    Ok(body)
}

fn validate(value: &Value, entrypoint: M2Entrypoint, trusted_anchor: Option<&Value>) -> Check {
    match entrypoint {
        M2Entrypoint::EvaluateNew => {
            proposal_preflight(value, false)?;
            strings(value, false)?;
            promotion_input(value)?;
            let trusted_anchor = trusted_anchor.ok_or_else(schema)?;
            strings(trusted_anchor, false)?;
            anchor(trusted_anchor)?;
        }
        M2Entrypoint::VerifyAttestedProposal | M2Entrypoint::ReplayHistorical => {
            proposal_preflight(value, true)?;
            strings(value, false)?;
            attested(value)?;
            let trusted_anchor = trusted_anchor.ok_or_else(schema)?;
            strings(trusted_anchor, false)?;
            anchor(trusted_anchor)?;
        }
        M2Entrypoint::InitializeAnchor => {
            let body = object(value)?;
            let identity_value = body.get("initial_identity_context").unwrap_or(&Value::Null);
            let authorization_value = body
                .get("initial_authorization_context")
                .unwrap_or(&Value::Null);
            context_preflight(identity_value, authorization_value, true)?;
            strings(value, false)?;
            let body = exact(
                value,
                &[
                    "initial_identity_context",
                    "initial_authorization_context",
                    "trusted_now_unix_s",
                ],
                &[],
            )?;
            identity(&body["initial_identity_context"])?;
            authorization(&body["initial_authorization_context"])?;
            uint(&body["trusted_now_unix_s"])?;
        }
        #[cfg(feature = "conformance")]
        M2Entrypoint::AdvanceAnchorHistory => {
            let body = object(value)?;
            let initial_identity = body.get("initial_identity_context").unwrap_or(&Value::Null);
            let initial_authorization = body
                .get("initial_authorization_context")
                .unwrap_or(&Value::Null);
            let mut contexts = vec![(initial_identity, initial_authorization)];
            if let Some(steps) = body.get("steps").and_then(Value::as_array) {
                for step in steps {
                    contexts.push((
                        step.get("next_identity_context").unwrap_or(&Value::Null),
                        step.get("next_authorization_context")
                            .unwrap_or(&Value::Null),
                    ));
                }
            }
            for (identity, authorization) in &contexts {
                context_preflight(identity, authorization, false)?;
            }
            for (identity, authorization) in &contexts {
                context_preflight(identity, authorization, true)?;
            }
            strings(value, false)?;
            let body = exact(
                value,
                &[
                    "initial_anchor",
                    "initial_identity_context",
                    "initial_authorization_context",
                    "steps",
                ],
                &["probe_attested_proposal"],
            )?;
            let current = anchor(&body["initial_anchor"])?;
            identity(&body["initial_identity_context"])?;
            authorization(&body["initial_authorization_context"])?;
            let steps = array(&body["steps"])?;
            if steps.is_empty() {
                return Err(schema());
            }
            if steps.len() > 16 {
                return Err(limit());
            }
            let mut ownership = current["key_ownership_registry"]
                .as_object()
                .ok_or_else(schema)?
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>();
            let mut revoked_keys = current["revoked_key_ids"]
                .as_array()
                .ok_or_else(schema)?
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect::<BTreeSet<_>>();
            let mut revoked_grants = current["revoked_grant_ids"]
                .as_array()
                .ok_or_else(schema)?
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect::<BTreeSet<_>>();
            for step in steps {
                let step = exact(
                    step,
                    &[
                        "next_identity_context",
                        "next_authorization_context",
                        "trusted_now_unix_s",
                    ],
                    &[],
                )?;
                let next = identity(&step["next_identity_context"])?;
                authorization(&step["next_authorization_context"])?;
                uint(&step["trusted_now_unix_s"])?;
                ownership.extend(
                    next["principals"]
                        .as_array()
                        .ok_or_else(schema)?
                        .iter()
                        .flat_map(|principal| principal["keys"].as_array().into_iter().flatten())
                        .filter_map(|key| key["key_id"].as_str())
                        .map(str::to_owned),
                );
                revoked_keys.extend(
                    next["revoked_key_ids"]
                        .as_array()
                        .ok_or_else(schema)?
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned),
                );
                revoked_grants.extend(
                    next["revoked_grant_ids"]
                        .as_array()
                        .ok_or_else(schema)?
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned),
                );
                if ownership.len() > 4096
                    || revoked_keys.len() > 4096
                    || revoked_grants.len() > 4096
                {
                    return Err(limit());
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn validate_anchor_transition_structure(
    previous_anchor: &Value,
    previous_identity: &Value,
    next_identity: &Value,
    next_authorization: &Value,
    trusted_now: &Value,
) -> Result<(), M2WireRejection> {
    let result = (|| {
        for identity_value in [previous_identity, next_identity] {
            context_preflight(identity_value, next_authorization, false)?;
        }
        for identity_value in [previous_identity, next_identity] {
            context_preflight(identity_value, next_authorization, true)?;
        }
        for value in [
            previous_anchor,
            previous_identity,
            next_identity,
            next_authorization,
            trusted_now,
        ] {
            strings(value, false)?;
        }
        let anchor = anchor(previous_anchor)?;
        identity(previous_identity)?;
        let identity_payload = identity(next_identity)?;
        authorization(next_authorization)?;
        uint(trusted_now)?;

        let mut ownership = anchor["key_ownership_registry"]
            .as_object()
            .ok_or_else(schema)?
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        for principal in identity_payload["principals"]
            .as_array()
            .ok_or_else(schema)?
        {
            for key in object(principal)?["keys"].as_array().ok_or_else(schema)? {
                ownership.insert(text(&object(key)?["key_id"])?.to_owned());
            }
        }
        let mut revoked_keys = anchor["revoked_key_ids"]
            .as_array()
            .ok_or_else(schema)?
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        revoked_keys.extend(
            identity_payload["revoked_key_ids"]
                .as_array()
                .ok_or_else(schema)?
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned),
        );
        let mut revoked_grants = anchor["revoked_grant_ids"]
            .as_array()
            .ok_or_else(schema)?
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        revoked_grants.extend(
            identity_payload["revoked_grant_ids"]
                .as_array()
                .ok_or_else(schema)?
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned),
        );
        if [ownership.len(), revoked_keys.len(), revoked_grants.len()]
            .into_iter()
            .any(|size| size > 4096)
        {
            return Err(limit());
        }
        Ok(())
    })();
    result.map_err(|error: Invalid| M2WireRejection {
        stage: 2,
        code: error.0,
        authorizing: false,
    })
}

/// Apply M2.1 stages one and two without authentication or authority.
pub fn inspect_m2_stage_two(
    source: &[u8],
    entrypoint: M2Entrypoint,
    trusted_anchor: Option<&Value>,
) -> Result<StructurallyValidM2Input, M2WireRejection> {
    let wire = inspect_m2_wire(source)?;
    let anchor_snapshot = trusted_anchor
        .map(|anchor| {
            canonical_json(anchor)
                .map_err(|_| schema())
                .and_then(|bytes| parse_json_strict(&bytes).map_err(|_| schema()))
        })
        .transpose()
        .map_err(|error| M2WireRejection {
            stage: 2,
            code: error.0,
            authorizing: false,
        })?;
    validate(wire.value(), entrypoint, anchor_snapshot.as_ref()).map_err(|error| {
        M2WireRejection {
            stage: 2,
            code: error.0,
            authorizing: false,
        }
    })?;
    Ok(StructurallyValidM2Input {
        entrypoint,
        wire,
        trusted_anchor: anchor_snapshot,
    })
}
