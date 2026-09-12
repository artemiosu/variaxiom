//! Disabled M2.1 exact-decision and selector verification (stage eleven).

use serde_json::Value;
use variaxiom_protocol::{
    CanonicalM2Wire, M2Entrypoint, M2WireRejection, PromotionDecision, canonical_json,
    verify_m2_selector_attestation,
};

use crate::m2_stage_ten::{PolicyEvaluatedM2Input, inspect_m2_stage_ten};

fn rejection(code: &'static str) -> M2WireRejection {
    M2WireRejection {
        stage: 11,
        code,
        authorizing: false,
    }
}

fn proposal_value(value: &Value, entrypoint: M2Entrypoint) -> Result<&Value, M2WireRejection> {
    match entrypoint {
        M2Entrypoint::VerifyAttestedProposal | M2Entrypoint::ReplayHistorical => Ok(value),
        M2Entrypoint::AdvanceAnchorHistory => value
            .as_object()
            .and_then(|history| history.get("probe_attested_proposal"))
            .ok_or_else(|| rejection("input.schema_invalid")),
        M2Entrypoint::EvaluateNew | M2Entrypoint::InitializeAnchor => {
            Err(rejection("input.schema_invalid"))
        }
    }
}

/// A fully verified signed proposal with no durable-lineage capability.
#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedM2Proposal {
    policy_evaluated: PolicyEvaluatedM2Input,
}

impl VerifiedM2Proposal {
    /// Return the inspected operation.
    #[cfg(feature = "internal-api")]
    #[must_use]
    pub const fn entrypoint(&self) -> M2Entrypoint {
        self.policy_evaluated.entrypoint()
    }

    /// Return the immutable canonical wire snapshot.
    #[must_use]
    pub const fn wire(&self) -> &CanonicalM2Wire {
        self.policy_evaluated.wire()
    }

    /// Return the exact recomputed decision.
    #[must_use]
    pub const fn decision(&self) -> &PromotionDecision {
        self.policy_evaluated.decision()
    }

    /// Return the separately owned trusted anchor snapshot.
    #[must_use]
    pub const fn trusted_anchor(&self) -> Option<&Value> {
        self.policy_evaluated.trusted_anchor()
    }

    /// Return the exact resulting anchor retained for a history probe.
    #[cfg(feature = "internal-api")]
    #[must_use]
    pub const fn resulting_anchor(&self) -> Option<&Value> {
        self.policy_evaluated.resulting_anchor()
    }

    /// M2.1 results are always non-authorizing data.
    ///
    /// No value returned by this disabled verifier can activate a candidate
    /// or append durable lineage.
    #[cfg(feature = "internal-api")]
    #[must_use]
    pub const fn authorizing(&self) -> bool {
        false
    }
}

/// Apply all M2.1 verifier stages and verify the selector attestation.
pub fn inspect_m2_stage_eleven(
    source: &[u8],
    entrypoint: M2Entrypoint,
    trusted_anchor: Option<&Value>,
) -> Result<VerifiedM2Proposal, M2WireRejection> {
    let policy_evaluated = inspect_m2_stage_ten(source, entrypoint, trusted_anchor)?;
    let decision = serde_json::to_value(policy_evaluated.decision().envelope())
        .map_err(|_| rejection("input.schema_invalid"))?;
    let proposal = proposal_value(policy_evaluated.wire().value(), entrypoint)?;
    let supplied = proposal
        .as_object()
        .and_then(|envelope| envelope.get("payload"))
        .and_then(Value::as_object)
        .and_then(|payload| payload.get("decision"))
        .ok_or_else(|| rejection("input.schema_invalid"))?;
    let supplied = canonical_json(supplied).map_err(|_| rejection("input.schema_invalid"))?;
    let computed = canonical_json(&decision).map_err(|_| rejection("input.schema_invalid"))?;
    if supplied != computed {
        return Err(rejection("decision.content_mismatch"));
    }
    verify_m2_selector_attestation(policy_evaluated.policy_context())?;
    Ok(VerifiedM2Proposal { policy_evaluated })
}
