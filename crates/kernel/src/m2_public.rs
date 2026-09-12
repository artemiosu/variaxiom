//! Public non-authorizing M2.1 result APIs.

use serde_json::{Value, json};
use variaxiom_protocol::{
    M2Entrypoint, M2WireRejection, canonical_digest, canonical_json, inspect_m2_stage_six,
    validate_trusted_anchor_transition,
};

use crate::m2_stage_eleven::inspect_m2_stage_eleven;
use crate::m2_stage_ten::inspect_m2_stage_ten;

/// Stable rejected verification result shared by every public M2.1 entry point.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationResult {
    code: String,
}

impl VerificationResult {
    fn from_rejection(rejection: M2WireRejection) -> Self {
        Self {
            code: rejection.code.to_owned(),
        }
    }

    fn schema_invalid() -> Self {
        Self {
            code: "input.schema_invalid".to_owned(),
        }
    }

    /// Return the stable failure code.
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Serialize the exact public verification-result/v1 value.
    #[must_use]
    pub fn as_value(&self) -> Value {
        json!({
            "verification_version": "verification-result/v1",
            "status": "rejected",
            "code": self.code,
        })
    }

    /// Rejections never authorize effects.
    #[must_use]
    pub const fn authorizing(&self) -> bool {
        false
    }
}

fn verified_value() -> Value {
    json!({
        "verification_version": "verification-result/v1",
        "status": "verified",
        "code": null,
    })
}

/// Pure policy evaluation over one exact promotion-input/v2 envelope.
#[derive(Clone, Debug, PartialEq)]
pub struct EvaluatedProposal {
    promotion_input: Value,
    decision: Value,
}

impl EvaluatedProposal {
    /// Return the exact public evaluated-proposal/v1 value.
    #[must_use]
    pub fn as_value(&self) -> Value {
        json!({
            "result_version": "evaluated-proposal/v1",
            "verification": verified_value(),
            "authorizing": false,
            "promotion_input": self.promotion_input,
            "decision": self.decision,
        })
    }

    /// M2.1 evaluation is evidence only.
    #[must_use]
    pub const fn authorizing(&self) -> bool {
        false
    }
}

/// Fully verified attested-proposal/v1 data without activation capability.
#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedProposal {
    attested_proposal: Value,
}

impl VerifiedProposal {
    /// Return the exact public verified-proposal/v1 value.
    #[must_use]
    pub fn as_value(&self) -> Value {
        json!({
            "result_version": "verified-proposal/v1",
            "verification": verified_value(),
            "authorizing": false,
            "attested_proposal": self.attested_proposal,
        })
    }

    /// Verification is evidence only and cannot append lineage.
    #[must_use]
    pub const fn authorizing(&self) -> bool {
        false
    }
}

/// Historical reproduction bound to the exact separately supplied anchor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayResult {
    attested_proposal_digest: String,
    recorded_trusted_anchor_digest: String,
    reproduced_decision_digest: String,
}

impl ReplayResult {
    /// Return the exact public replay-result/v1 value.
    #[must_use]
    pub fn as_value(&self) -> Value {
        json!({
            "result_version": "replay-result/v1",
            "verification": verified_value(),
            "authorizing": false,
            "attested_proposal_digest": self.attested_proposal_digest,
            "recorded_trusted_anchor_digest": self.recorded_trusted_anchor_digest,
            "reproduced_decision_digest": self.reproduced_decision_digest,
        })
    }

    /// Historical replay can never authorize a current effect.
    #[must_use]
    pub const fn authorizing(&self) -> bool {
        false
    }
}

/// Explicit trusted-anchor initialization or transition result.
#[derive(Clone, Debug, PartialEq)]
pub struct AnchorTransitionResult {
    resulting_anchor: Value,
}

impl AnchorTransitionResult {
    /// Return the exact public anchor-transition-result/v1 value.
    #[must_use]
    pub fn as_value(&self) -> Value {
        json!({
            "result_version": "anchor-transition-result/v1",
            "verification": verified_value(),
            "authorizing": false,
            "resulting_anchor": self.resulting_anchor,
        })
    }

    /// Anchor validation does not authorize promotion or lineage append.
    #[must_use]
    pub const fn authorizing(&self) -> bool {
        false
    }
}

/// Evaluate a raw promotion input without selector signing or authority.
pub fn evaluate_new(
    source: &[u8],
    live_trusted_anchor: &Value,
) -> Result<EvaluatedProposal, VerificationResult> {
    let evaluated =
        inspect_m2_stage_ten(source, M2Entrypoint::EvaluateNew, Some(live_trusted_anchor))
            .map_err(VerificationResult::from_rejection)?;
    let decision = serde_json::to_value(evaluated.decision().envelope())
        .map_err(|_| VerificationResult::schema_invalid())?;
    Ok(EvaluatedProposal {
        promotion_input: evaluated.wire().value().clone(),
        decision,
    })
}

/// Verify a selector-attested proposal as non-authorizing evidence.
pub fn verify_attested_proposal(
    source: &[u8],
    live_trusted_anchor: &Value,
) -> Result<VerifiedProposal, VerificationResult> {
    let verified = inspect_m2_stage_eleven(
        source,
        M2Entrypoint::VerifyAttestedProposal,
        Some(live_trusted_anchor),
    )
    .map_err(VerificationResult::from_rejection)?;
    Ok(VerifiedProposal {
        attested_proposal: verified.wire().value().clone(),
    })
}

/// Reproduce a historical decision and bind the exact recorded anchor.
pub fn replay_historical(
    source: &[u8],
    recorded_trusted_anchor: &Value,
) -> Result<ReplayResult, VerificationResult> {
    let verified = inspect_m2_stage_eleven(
        source,
        M2Entrypoint::ReplayHistorical,
        Some(recorded_trusted_anchor),
    )
    .map_err(VerificationResult::from_rejection)?;
    let proposal = verified.wire().value();
    let decision = serde_json::to_value(verified.decision().envelope())
        .map_err(|_| VerificationResult::schema_invalid())?;
    Ok(ReplayResult {
        attested_proposal_digest: canonical_digest(proposal)
            .map_err(|_| VerificationResult::schema_invalid())?,
        recorded_trusted_anchor_digest: canonical_digest(
            verified
                .trusted_anchor()
                .ok_or_else(VerificationResult::schema_invalid)?,
        )
        .map_err(|_| VerificationResult::schema_invalid())?,
        reproduced_decision_digest: canonical_digest(&decision)
            .map_err(|_| VerificationResult::schema_invalid())?,
    })
}

fn anchor_operation(
    source: &[u8],
    entrypoint: M2Entrypoint,
) -> Result<AnchorTransitionResult, VerificationResult> {
    let verified = inspect_m2_stage_six(source, entrypoint, None)
        .map_err(VerificationResult::from_rejection)?;
    let resulting_anchor = verified
        .resulting_anchor()
        .cloned()
        .ok_or_else(VerificationResult::schema_invalid)?;
    Ok(AnchorTransitionResult { resulting_anchor })
}

/// Validate explicit genesis contexts and construct a non-authorizing anchor.
pub fn initialize_anchor(
    genesis_identity_context: &Value,
    genesis_authorization_context: &Value,
    trusted_now_unix_s: u64,
) -> Result<AnchorTransitionResult, VerificationResult> {
    let request = json!({
        "initial_identity_context": genesis_identity_context,
        "initial_authorization_context": genesis_authorization_context,
        "trusted_now_unix_s": trusted_now_unix_s,
    });
    let source = canonical_json(&request).map_err(|_| VerificationResult::schema_invalid())?;
    anchor_operation(&source, M2Entrypoint::InitializeAnchor)
}

/// Validate one explicit trusted-anchor transition without ambient state.
pub fn advance_anchor(
    previous_anchor: &Value,
    previous_identity_context: &Value,
    next_identity_context: &Value,
    next_authorization_context: &Value,
    trusted_now_unix_s: u64,
) -> Result<AnchorTransitionResult, VerificationResult> {
    let transition = validate_trusted_anchor_transition(
        previous_anchor,
        previous_identity_context,
        next_identity_context,
        next_authorization_context,
        trusted_now_unix_s,
    )
    .map_err(VerificationResult::from_rejection)?;
    debug_assert!(!transition.authorizing());
    Ok(AnchorTransitionResult {
        resulting_anchor: transition.resulting_anchor().clone(),
    })
}
