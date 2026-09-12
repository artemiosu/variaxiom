//! Disabled pure M2.1 policy evaluation (stage ten).

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};
use variaxiom_protocol::{
    Candidate, CanonicalM2Wire, Constitution, DecisionStatus, Evidence, EvidenceStatus,
    M2Entrypoint, M2WireRejection, PolicyContextBoundM2Input, PromotionContext, PromotionDecision,
    canonical_digest, inspect_m2_stage_nine,
};

use crate::PromotionGate;

/// Pure deterministic policy result over a fully bound M2.1 input.
#[derive(Clone, Debug, PartialEq)]
pub struct PolicyEvaluatedM2Input {
    policy_context: PolicyContextBoundM2Input,
    decision: PromotionDecision,
}

impl PolicyEvaluatedM2Input {
    /// Return the exact stage-nine policy context used by the kernel.
    #[must_use]
    pub const fn policy_context(&self) -> &PolicyContextBoundM2Input {
        &self.policy_context
    }

    /// Return the inspected operation.
    #[cfg(feature = "conformance")]
    #[must_use]
    pub const fn entrypoint(&self) -> M2Entrypoint {
        self.policy_context.entrypoint()
    }

    /// Return the immutable canonical wire snapshot.
    #[must_use]
    pub const fn wire(&self) -> &CanonicalM2Wire {
        self.policy_context.wire()
    }

    /// Return the separately owned trusted anchor snapshot.
    #[must_use]
    pub const fn trusted_anchor(&self) -> Option<&Value> {
        self.policy_context.trusted_anchor()
    }

    /// Return the exact resulting anchor retained for a history probe.
    #[cfg(feature = "conformance")]
    #[must_use]
    pub const fn resulting_anchor(&self) -> Option<&Value> {
        self.policy_context.resulting_anchor()
    }

    /// Return the exact deterministic promotion decision.
    #[must_use]
    pub const fn decision(&self) -> &PromotionDecision {
        &self.decision
    }

    /// Policy evaluation alone never authorizes an effect.
    #[cfg(feature = "conformance")]
    #[must_use]
    pub const fn authorizing(&self) -> bool {
        false
    }
}

type Check<T> = Result<T, ()>;

fn object(value: &Value) -> Check<&Map<String, Value>> {
    value.as_object().ok_or(())
}

fn text(value: &Value) -> Check<&str> {
    value.as_str().ok_or(())
}

fn integer(value: &Value) -> Check<i64> {
    value.as_i64().ok_or(())
}

fn boolean(value: &Value) -> Check<bool> {
    value.as_bool().ok_or(())
}

fn strings(value: &Value) -> Check<BTreeSet<String>> {
    value
        .as_array()
        .ok_or(())?
        .iter()
        .map(|item| text(item).map(str::to_owned))
        .collect()
}

fn json_object(value: &Value) -> Check<BTreeMap<String, Value>> {
    Ok(object(value)?
        .iter()
        .map(|(key, item)| (key.clone(), item.clone()))
        .collect())
}

fn proposal_value(value: &Value, entrypoint: M2Entrypoint) -> Check<&Value> {
    match entrypoint {
        M2Entrypoint::EvaluateNew => Ok(value),
        M2Entrypoint::VerifyAttestedProposal | M2Entrypoint::ReplayHistorical => Ok(value),
        #[cfg(feature = "conformance")]
        M2Entrypoint::AdvanceAnchorHistory => {
            object(value)?.get("probe_attested_proposal").ok_or(())
        }
        M2Entrypoint::InitializeAnchor => Err(()),
    }
}

fn promotion_input(value: &Value) -> Check<&Value> {
    let root = object(value)?;
    if root.get("kind").and_then(Value::as_str) == Some("promotion-input") {
        Ok(value)
    } else {
        Ok(&object(&root["payload"])?["promotion_input"])
    }
}

fn promotion_body(value: &Value) -> Check<&Map<String, Value>> {
    object(&object(promotion_input(value)?)?["payload"])
}

fn candidate(body: &Map<String, Value>) -> Check<Candidate> {
    let payload = object(&object(&body["candidate"])?["envelope"])?;
    let payload = object(&payload["payload"])?;
    Ok(Candidate {
        candidate_id: text(&payload["candidate_id"])?.to_owned(),
        parent_id: text(&payload["parent_id"])?.to_owned(),
        artifact_hash: text(&payload["artifact_hash"])?.to_owned(),
        proposer: text(&payload["proposer"])?.to_owned(),
        rollback_target: text(&payload["rollback_target"])?.to_owned(),
        baseline_capabilities: strings(&payload["baseline_capabilities"])?,
        requested_capabilities: strings(&payload["requested_capabilities"])?,
        estimated_cost_micro_usd: integer(&payload["estimated_cost_micro_usd"])?,
        metadata: json_object(&payload["metadata"])?,
    })
}

fn evidence(body: &Map<String, Value>, candidate_id: &str) -> Check<Vec<Evidence>> {
    body["evidence"]
        .as_array()
        .ok_or(())?
        .iter()
        .map(|pair| {
            let payload = object(&object(&object(pair)?["envelope"])?["payload"])?;
            let status = match text(&payload["status"])? {
                "pass" => EvidenceStatus::Pass,
                "fail" => EvidenceStatus::Fail,
                "error" => EvidenceStatus::Error,
                _ => return Err(()),
            };
            Ok(Evidence {
                evidence_id: text(&payload["evidence_id"])?.to_owned(),
                subject_id: candidate_id.to_owned(),
                artifact_hash: text(&payload["artifact_hash"])?.to_owned(),
                check: text(&payload["check"])?.to_owned(),
                status,
                verifier: text(&payload["verifier"])?.to_owned(),
                independent: boolean(&payload["independent"])?,
                details: json_object(&payload["details"])?,
            })
        })
        .collect()
}

fn constitution(body: &Map<String, Value>) -> Check<Constitution> {
    let payload = object(&object(&object(&body["constitution"])?["envelope"])?["payload"])?;
    Ok(Constitution {
        version: text(&payload["version"])?.to_owned(),
        mandatory_checks: strings(&payload["mandatory_checks"])?,
        minimum_independent_verifiers: integer(&payload["minimum_independent_verifiers"])?,
        max_candidate_cost_micro_usd: integer(&payload["max_candidate_cost_micro_usd"])?,
        require_known_parent: boolean(&payload["require_known_parent"])?,
        require_rollback_target: boolean(&payload["require_rollback_target"])?,
        forbid_self_verification: boolean(&payload["forbid_self_verification"])?,
        forbid_implicit_authority_escalation: boolean(
            &payload["forbid_implicit_authority_escalation"],
        )?,
        reject_any_failed_evidence: boolean(&payload["reject_any_failed_evidence"])?,
    })
}

fn context(body: &Map<String, Value>) -> Check<(PromotionContext, Option<String>)> {
    let authorization = object(&object(&body["authorization_context"])?["payload"])?;
    let lineage_capabilities = object(&authorization["lineage_capabilities"])?
        .iter()
        .map(|(lineage_id, capabilities)| Ok((lineage_id.clone(), strings(capabilities)?)))
        .collect::<Check<BTreeMap<_, _>>>()?;
    let mut authority_grants = BTreeMap::new();
    let grant_id = if let Some(pair) = body.get("authority_grant") {
        let envelope = &object(pair)?["envelope"];
        let identifier = format!(
            "grant:sha256:{}",
            canonical_digest(envelope).map_err(|_| ())?
        );
        let payload = object(&object(envelope)?["payload"])?;
        authority_grants.insert(identifier.clone(), strings(&payload["capabilities"])?);
        Some(identifier)
    } else {
        None
    };
    Ok((
        PromotionContext {
            known_lineage_ids: strings(&authorization["known_lineage_ids"])?,
            known_artifact_hashes: strings(&authorization["verified_artifact_hashes"])?,
            authority_grants,
            lineage_capabilities,
        },
        grant_id,
    ))
}

fn evaluate_policy(value: &Value) -> Check<PromotionDecision> {
    let body = promotion_body(value)?;
    let candidate = candidate(body)?;
    let evidence = evidence(body, &candidate.candidate_id)?;
    let constitution = constitution(body)?;
    let (context, grant_id) = context(body)?;
    let mut decision = PromotionGate::new(constitution)
        .decide(&candidate, &evidence, &context, grant_id.as_deref())
        .map_err(|_| ())?;
    decision.input_digest = canonical_digest(promotion_input(value)?).map_err(|_| ())?;
    decision.validate().map_err(|_| ())?;
    Ok(decision)
}

/// Apply M2.1 stages one through ten and return a non-authorizing policy result.
pub fn inspect_m2_stage_ten(
    source: &[u8],
    entrypoint: M2Entrypoint,
    trusted_anchor: Option<&Value>,
) -> Result<PolicyEvaluatedM2Input, M2WireRejection> {
    let policy_context = inspect_m2_stage_nine(source, entrypoint, trusted_anchor)?;
    let proposal = proposal_value(policy_context.wire().value(), entrypoint)
        .map_err(|()| M2WireRejection::new(2, "input.kind_mismatch"))?;
    let decision =
        evaluate_policy(proposal).map_err(|()| M2WireRejection::new(2, "input.schema_invalid"))?;
    debug_assert!(matches!(
        decision.status,
        DecisionStatus::Accepted | DecisionStatus::Rejected
    ));
    Ok(PolicyEvaluatedM2Input {
        policy_context,
        decision,
    })
}
