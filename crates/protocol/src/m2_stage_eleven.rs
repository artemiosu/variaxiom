//! Disabled M2.1 decision and selector verification support (stage eleven).

use serde_json::{Map, Value};

use crate::m2_stage_four_five::verify_selector_stages_four_five;
use crate::m2_stage_six::verify_selector_stage_six;
use crate::{M2Entrypoint, M2WireRejection, PolicyContextBoundM2Input};

fn rejection(code: &'static str) -> M2WireRejection {
    M2WireRejection {
        stage: 11,
        code,
        authorizing: false,
    }
}

fn object(value: &Value) -> Result<&Map<String, Value>, M2WireRejection> {
    value
        .as_object()
        .ok_or_else(|| rejection("input.schema_invalid"))
}

fn proposal_value(value: &Value, entrypoint: M2Entrypoint) -> Result<&Value, M2WireRejection> {
    match entrypoint {
        M2Entrypoint::VerifyAttestedProposal | M2Entrypoint::ReplayHistorical => Ok(value),
        #[cfg(feature = "conformance")]
        M2Entrypoint::AdvanceAnchorHistory => object(value)?
            .get("probe_attested_proposal")
            .ok_or_else(|| rejection("input.schema_invalid")),
        M2Entrypoint::EvaluateNew | M2Entrypoint::InitializeAnchor => {
            Err(rejection("input.schema_invalid"))
        }
    }
}

/// Verify only the selector signature over the proposal's embedded decision.
///
/// This is not a complete stage-eleven verifier and does not recompute policy.
/// The trusted kernel must first compare the embedded decision with its own
/// independently recomputed decision. Success remains data only; it does not
/// append or activate lineage.
pub fn verify_m2_selector_attestation(
    policy_context: &PolicyContextBoundM2Input,
) -> Result<(), M2WireRejection> {
    let proposal = proposal_value(policy_context.wire().value(), policy_context.entrypoint())?;
    let payload = object(&object(proposal)?["payload"])?;
    let anchor = policy_context
        .resulting_anchor()
        .or_else(|| policy_context.trusted_anchor())
        .ok_or_else(|| rejection("input.schema_invalid"))?;
    let signature = object(&payload["selector_signature"])?;
    let signature_payload = object(&signature["payload"])?;
    if signature_payload["trust_domain_id"] != object(anchor)?["trust_domain_id"] {
        return Err(rejection("signature.domain_mismatch"));
    }

    verify_selector_stages_four_five(proposal, anchor)?;
    verify_selector_stage_six(proposal)
}
