//! Disabled M2.1 evidence, grant, and constitution bindings (stages 7–9).

use std::collections::BTreeSet;

use serde_json::{Map, Value};

use crate::{
    CanonicalM2Wire, M2Entrypoint, M2WireRejection, SignatureVerifiedM2Input, canonical_digest,
    inspect_m2_stage_six,
};

/// Owned input whose evidence names the exact candidate envelope digest.
#[derive(Clone, Debug, PartialEq)]
pub struct EvidenceBoundM2Input {
    signature_verified: SignatureVerifiedM2Input,
}

impl EvidenceBoundM2Input {
    /// Return the inspected operation.
    #[must_use]
    pub const fn entrypoint(&self) -> M2Entrypoint {
        self.signature_verified.entrypoint()
    }

    /// Return the immutable canonical wire snapshot.
    #[must_use]
    pub const fn wire(&self) -> &CanonicalM2Wire {
        self.signature_verified.wire()
    }

    /// Return the separately owned external anchor snapshot.
    #[must_use]
    pub const fn trusted_anchor(&self) -> Option<&Value> {
        self.signature_verified.trusted_anchor()
    }

    /// Return the exact resulting anchor retained for a history probe.
    #[must_use]
    pub const fn resulting_anchor(&self) -> Option<&Value> {
        self.signature_verified.resulting_anchor()
    }

    /// This intermediate boundary never authorizes an effect.
    #[must_use]
    pub const fn authorizing(&self) -> bool {
        false
    }
}

/// Owned input whose optional grant exactly matches the authority delta.
#[derive(Clone, Debug, PartialEq)]
pub struct GrantBoundM2Input {
    evidence_bound: EvidenceBoundM2Input,
}

impl GrantBoundM2Input {
    /// Return the inspected operation.
    #[must_use]
    pub const fn entrypoint(&self) -> M2Entrypoint {
        self.evidence_bound.entrypoint()
    }

    /// Return the immutable canonical wire snapshot.
    #[must_use]
    pub const fn wire(&self) -> &CanonicalM2Wire {
        self.evidence_bound.wire()
    }

    /// Return the separately owned external anchor snapshot.
    #[must_use]
    pub const fn trusted_anchor(&self) -> Option<&Value> {
        self.evidence_bound.trusted_anchor()
    }

    /// Return the exact resulting anchor retained for a history probe.
    #[must_use]
    pub const fn resulting_anchor(&self) -> Option<&Value> {
        self.evidence_bound.resulting_anchor()
    }

    /// This intermediate boundary never authorizes an effect.
    #[must_use]
    pub const fn authorizing(&self) -> bool {
        false
    }
}

/// Owned input bound to the exact constitution envelope and artifact.
#[derive(Clone, Debug, PartialEq)]
pub struct PolicyContextBoundM2Input {
    grant_bound: GrantBoundM2Input,
}

impl PolicyContextBoundM2Input {
    /// Return the inspected operation.
    #[must_use]
    pub const fn entrypoint(&self) -> M2Entrypoint {
        self.grant_bound.entrypoint()
    }

    /// Return the immutable canonical wire snapshot.
    #[must_use]
    pub const fn wire(&self) -> &CanonicalM2Wire {
        self.grant_bound.wire()
    }

    /// Return the separately owned external anchor snapshot.
    #[must_use]
    pub const fn trusted_anchor(&self) -> Option<&Value> {
        self.grant_bound.trusted_anchor()
    }

    /// Return the exact resulting anchor retained for a history probe.
    #[must_use]
    pub const fn resulting_anchor(&self) -> Option<&Value> {
        self.grant_bound.resulting_anchor()
    }

    /// This intermediate boundary never authorizes an effect.
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

fn invalid<T>(stage: u8, code: &'static str) -> Check<T> {
    Err(Invalid { stage, code })
}

fn object<'a>(value: &'a Value, stage: u8, code: &'static str) -> Check<&'a Map<String, Value>> {
    value.as_object().ok_or(Invalid { stage, code })
}

fn text<'a>(value: &'a Value, stage: u8, code: &'static str) -> Check<&'a str> {
    value.as_str().ok_or(Invalid { stage, code })
}

fn integer(value: &Value, stage: u8, code: &'static str) -> Check<i64> {
    value.as_i64().ok_or(Invalid { stage, code })
}

fn proposal_value(value: &Value, entrypoint: M2Entrypoint) -> Check<&Value> {
    match entrypoint {
        M2Entrypoint::VerifyAttestedProposal | M2Entrypoint::ReplayHistorical => Ok(value),
        M2Entrypoint::AdvanceAnchorHistory => object(value, 2, "input.kind_mismatch")?
            .get("probe_attested_proposal")
            .ok_or(Invalid {
                stage: 2,
                code: "input.kind_mismatch",
            }),
        M2Entrypoint::InitializeAnchor => invalid(2, "input.kind_mismatch"),
    }
}

fn promotion_body<'a>(
    value: &'a Value,
    stage: u8,
    code: &'static str,
) -> Check<&'a Map<String, Value>> {
    let proposal = object(&object(value, stage, code)?["payload"], stage, code)?;
    object(
        &object(&proposal["promotion_input"], stage, code)?["payload"],
        stage,
        code,
    )
}

fn stage_seven(value: &Value) -> Check {
    let body = promotion_body(value, 7, "evidence.subject_digest_mismatch")?;
    let candidate_pair = object(&body["candidate"], 7, "evidence.subject_digest_mismatch")?;
    let candidate_digest = canonical_digest(&candidate_pair["envelope"]).map_err(|_| Invalid {
        stage: 7,
        code: "evidence.subject_digest_mismatch",
    })?;
    for evidence_pair in body["evidence"].as_array().ok_or(Invalid {
        stage: 7,
        code: "evidence.subject_digest_mismatch",
    })? {
        let evidence_pair = object(evidence_pair, 7, "evidence.subject_digest_mismatch")?;
        let evidence = object(
            &object(
                &evidence_pair["envelope"],
                7,
                "evidence.subject_digest_mismatch",
            )?["payload"],
            7,
            "evidence.subject_digest_mismatch",
        )?;
        if evidence["subject_candidate_digest"] != candidate_digest {
            return invalid(7, "evidence.subject_digest_mismatch");
        }
    }
    Ok(())
}

fn strings(value: &Value, stage: u8, code: &'static str) -> Check<BTreeSet<String>> {
    value
        .as_array()
        .ok_or(Invalid { stage, code })?
        .iter()
        .map(|item| text(item, stage, code).map(str::to_owned))
        .collect()
}

fn stage_eight(value: &Value) -> Check {
    let body = promotion_body(value, 8, "grant.context_mismatch")?;
    let candidate_pair = object(&body["candidate"], 8, "grant.context_mismatch")?;
    let candidate_envelope = &candidate_pair["envelope"];
    let candidate = object(
        &object(candidate_envelope, 8, "grant.context_mismatch")?["payload"],
        8,
        "grant.context_mismatch",
    )?;
    let candidate_digest = canonical_digest(candidate_envelope).map_err(|_| Invalid {
        stage: 8,
        code: "grant.context_mismatch",
    })?;
    let authorization = object(
        &object(&body["authorization_context"], 8, "grant.context_mismatch")?["payload"],
        8,
        "grant.context_mismatch",
    )?;
    let parent = text(&candidate["parent_id"], 8, "grant.context_mismatch")?;
    let lineage_capabilities = object(
        &authorization["lineage_capabilities"],
        8,
        "grant.context_mismatch",
    )?;
    let parent_capabilities = lineage_capabilities
        .get(parent)
        .map(|value| strings(value, 8, "grant.context_mismatch"))
        .transpose()?
        .unwrap_or_default();
    let requested = strings(
        &candidate["requested_capabilities"],
        8,
        "grant.context_mismatch",
    )?;
    let delta = requested
        .difference(&parent_capabilities)
        .cloned()
        .collect::<BTreeSet<_>>();

    let Some(grant_pair) = body.get("authority_grant") else {
        return if delta.is_empty() {
            Ok(())
        } else {
            invalid(8, "grant.capability_mismatch")
        };
    };
    let grant_pair = object(grant_pair, 8, "grant.context_mismatch")?;
    let grant_envelope = &grant_pair["envelope"];
    let grant = object(
        &object(grant_envelope, 8, "grant.context_mismatch")?["payload"],
        8,
        "grant.context_mismatch",
    )?;
    if grant["audience"] != "variaxiom-promotion/v2" {
        return invalid(8, "grant.audience_mismatch");
    }
    let constitution_pair = object(&body["constitution"], 8, "grant.context_mismatch")?;
    let constitution_digest =
        canonical_digest(&constitution_pair["envelope"]).map_err(|_| Invalid {
            stage: 8,
            code: "grant.context_mismatch",
        })?;
    if grant["trust_domain_id"] != authorization["trust_domain_id"]
        || grant["capability_namespace"] != authorization["capability_namespace"]
        || grant["constitution_digest"] != constitution_digest
        || grant["lineage_id"] != authorization["lineage_id"]
    {
        return invalid(8, "grant.context_mismatch");
    }
    if grant["subject_candidate_digest"] != candidate_digest {
        return invalid(8, "grant.subject_mismatch");
    }
    if strings(&grant["capabilities"], 8, "grant.capability_mismatch")? != delta {
        return invalid(8, "grant.capability_mismatch");
    }
    let not_before = integer(&grant["not_before_unix_s"], 8, "grant.interval_invalid")?;
    let expires_at = integer(&grant["expires_at_unix_s"], 8, "grant.interval_invalid")?;
    if not_before >= expires_at {
        return invalid(8, "grant.interval_invalid");
    }
    let identity = object(
        &object(&body["identity_context"], 8, "grant.context_mismatch")?["payload"],
        8,
        "grant.context_mismatch",
    )?;
    let now = integer(
        &identity["evaluation_time_unix_s"],
        8,
        "grant.interval_invalid",
    )?;
    if now < not_before {
        return invalid(8, "grant.not_yet_valid");
    }
    if now >= expires_at {
        return invalid(8, "grant.expired");
    }
    if grant["delegable"].as_bool() != Some(false) {
        return invalid(8, "grant.delegation_forbidden");
    }
    Ok(())
}

fn stage_nine(value: &Value) -> Check {
    let body = promotion_body(value, 9, "constitution.context_mismatch")?;
    let authorization = object(
        &object(
            &body["authorization_context"],
            9,
            "constitution.context_mismatch",
        )?["payload"],
        9,
        "constitution.context_mismatch",
    )?;
    let constitution_pair = object(&body["constitution"], 9, "constitution.context_mismatch")?;
    let constitution_envelope = &constitution_pair["envelope"];
    let envelope_digest = canonical_digest(constitution_envelope).map_err(|_| Invalid {
        stage: 9,
        code: "constitution.context_mismatch",
    })?;
    if authorization["constitution_envelope_digest"] != envelope_digest {
        return invalid(9, "constitution.context_mismatch");
    }
    let constitution_payload =
        &object(constitution_envelope, 9, "constitution.artifact_mismatch")?["payload"];
    let artifact_digest = canonical_digest(constitution_payload).map_err(|_| Invalid {
        stage: 9,
        code: "constitution.artifact_mismatch",
    })?;
    if constitution_pair["artifact_hash"] != artifact_digest
        || authorization["constitution_artifact_hash"] != constitution_pair["artifact_hash"]
    {
        return invalid(9, "constitution.artifact_mismatch");
    }
    Ok(())
}

fn rejection(error: Invalid) -> M2WireRejection {
    M2WireRejection {
        stage: error.stage,
        code: error.code,
        authorizing: false,
    }
}

/// Apply M2.1 stages one through seven without granting authority.
pub fn inspect_m2_stage_seven(
    source: &[u8],
    entrypoint: M2Entrypoint,
    trusted_anchor: Option<&Value>,
) -> Result<EvidenceBoundM2Input, M2WireRejection> {
    let signature_verified = inspect_m2_stage_six(source, entrypoint, trusted_anchor)?;
    let proposal =
        proposal_value(signature_verified.wire().value(), entrypoint).map_err(rejection)?;
    stage_seven(proposal).map_err(rejection)?;
    Ok(EvidenceBoundM2Input { signature_verified })
}

/// Apply M2.1 stages one through eight without granting authority.
pub fn inspect_m2_stage_eight(
    source: &[u8],
    entrypoint: M2Entrypoint,
    trusted_anchor: Option<&Value>,
) -> Result<GrantBoundM2Input, M2WireRejection> {
    let evidence_bound = inspect_m2_stage_seven(source, entrypoint, trusted_anchor)?;
    let proposal = proposal_value(evidence_bound.wire().value(), entrypoint).map_err(rejection)?;
    stage_eight(proposal).map_err(rejection)?;
    Ok(GrantBoundM2Input { evidence_bound })
}

/// Apply M2.1 stages one through nine without granting authority.
pub fn inspect_m2_stage_nine(
    source: &[u8],
    entrypoint: M2Entrypoint,
    trusted_anchor: Option<&Value>,
) -> Result<PolicyContextBoundM2Input, M2WireRejection> {
    let grant_bound = inspect_m2_stage_eight(source, entrypoint, trusted_anchor)?;
    let proposal = proposal_value(grant_bound.wire().value(), entrypoint).map_err(rejection)?;
    stage_nine(proposal).map_err(rejection)?;
    Ok(PolicyContextBoundM2Input { grant_bound })
}
