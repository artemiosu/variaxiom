//! Disabled M2.1 exact-decision and selector verification (stage eleven).

use serde_json::Value;
use variaxiom_protocol::{
    CanonicalM2Wire, M2Entrypoint, M2WireRejection, PromotionDecision,
    verify_m2_stage_eleven_protocol,
};

use crate::{PolicyEvaluatedM2Input, inspect_m2_stage_ten};

/// A fully verified signed proposal with no durable-lineage capability.
#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedM2Proposal {
    policy_evaluated: PolicyEvaluatedM2Input,
}

impl VerifiedM2Proposal {
    /// Return the inspected operation.
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
    #[must_use]
    pub const fn resulting_anchor(&self) -> Option<&Value> {
        self.policy_evaluated.resulting_anchor()
    }

    /// Live verification authorizes only the proposal as data.
    ///
    /// Replay and anchor-history probes remain non-authorizing. No M2.1
    /// result can activate a candidate or append durable lineage.
    #[must_use]
    pub const fn authorizing(&self) -> bool {
        matches!(self.entrypoint(), M2Entrypoint::VerifyAttestedProposal)
    }
}

/// Apply all M2.1 verifier stages and verify the selector attestation.
pub fn inspect_m2_stage_eleven(
    source: &[u8],
    entrypoint: M2Entrypoint,
    trusted_anchor: Option<&Value>,
) -> Result<VerifiedM2Proposal, M2WireRejection> {
    let policy_evaluated = inspect_m2_stage_ten(source, entrypoint, trusted_anchor)?;
    let decision = serde_json::to_value(policy_evaluated.decision().envelope()).map_err(|_| {
        M2WireRejection {
            stage: 11,
            code: "input.schema_invalid",
            authorizing: false,
        }
    })?;
    verify_m2_stage_eleven_protocol(policy_evaluated.policy_context(), &decision)?;
    Ok(VerifiedM2Proposal { policy_evaluated })
}
