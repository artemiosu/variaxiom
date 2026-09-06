//! Minimal trusted promotion gate.
//!
//! The kernel does not plan, call models, generate tools, or execute arbitrary
//! code. It only applies small deterministic rules to facts produced by other
//! trust domains.

use std::collections::BTreeSet;

pub use variaxiom_protocol::Constitution;
use variaxiom_protocol::{
    Candidate, CanonicalError, DecisionStatus, Evidence, EvidenceStatus, GATE_VERSION,
    PromotionContext, PromotionDecision, PromotionInput, canonical_digest,
};

/// Pure deterministic gate. It has no ambient network, filesystem, or model access.
#[derive(Clone, Debug, Default)]
pub struct PromotionGate {
    constitution: Constitution,
}

impl PromotionGate {
    /// Construct a gate from an explicit constitution.
    #[must_use]
    pub const fn new(constitution: Constitution) -> Self {
        Self { constitution }
    }

    /// Decide whether a candidate may enter the inheritable lineage.
    pub fn decide(
        &self,
        candidate: &Candidate,
        evidence: &[Evidence],
        context: &PromotionContext,
        authority_grant_id: Option<&str>,
    ) -> Result<PromotionDecision, CanonicalError> {
        let input = PromotionInput::new(
            candidate.clone(),
            evidence.to_vec(),
            context.clone(),
            authority_grant_id.map(String::from),
            self.constitution.clone(),
        );
        input.validate()?;
        let input_digest = canonical_digest(&input.envelope())?;
        let mut reasons = BTreeSet::new();

        if !context
            .known_artifact_hashes
            .contains(&candidate.artifact_hash)
        {
            reasons.insert("artifact.not_verified".into());
        }
        if self.constitution.require_known_parent
            && !context.known_lineage_ids.contains(&candidate.parent_id)
        {
            reasons.insert("lineage.parent_unknown".into());
        }
        if self.constitution.require_rollback_target
            && !context
                .known_lineage_ids
                .contains(&candidate.rollback_target)
        {
            reasons.insert("rollback.target_unknown".into());
        }
        if candidate.estimated_cost_micro_usd > self.constitution.max_candidate_cost_micro_usd {
            reasons.insert("candidate.cost_limit_exceeded".into());
        }

        if self.constitution.forbid_implicit_authority_escalation {
            let trusted_baseline = context.lineage_capabilities.get(&candidate.parent_id);
            let empty_baseline = BTreeSet::new();
            let trusted_baseline = match trusted_baseline {
                Some(capabilities) => {
                    if capabilities != &candidate.baseline_capabilities {
                        reasons.insert("authority.baseline_mismatch".into());
                    }
                    capabilities
                }
                None => {
                    reasons.insert("authority.baseline_unknown".into());
                    &empty_baseline
                }
            };
            let delta = candidate
                .requested_capabilities
                .difference(trusted_baseline)
                .cloned()
                .collect::<BTreeSet<_>>();
            if !delta.is_empty() {
                let granted = authority_grant_id
                    .and_then(|id| context.authority_grants.get(id))
                    .cloned()
                    .unwrap_or_default();
                let missing: Vec<_> = delta.difference(&granted).cloned().collect();
                if !missing.is_empty() {
                    reasons.insert(format!("authority.not_granted:{}", missing.join(",")));
                }
            }
        }

        let relevant: Vec<_> = evidence
            .iter()
            .filter(|item| item.subject_id == candidate.candidate_id)
            .collect();
        let mut verifier_ids = BTreeSet::new();

        for item in &relevant {
            if item.artifact_hash != candidate.artifact_hash {
                reasons.insert(format!("evidence.artifact_mismatch:{}", item.evidence_id));
            }
            if self.constitution.forbid_self_verification && item.verifier == candidate.proposer {
                reasons.insert(format!("evidence.self_verification:{}", item.evidence_id));
            }
            if self.constitution.reject_any_failed_evidence && item.status != EvidenceStatus::Pass {
                let status = match item.status {
                    EvidenceStatus::Pass => "pass",
                    EvidenceStatus::Fail => "fail",
                    EvidenceStatus::Error => "error",
                };
                reasons.insert(format!("evidence.failed:{}:{status}", item.evidence_id));
            }
            if item.independent
                && item.status == EvidenceStatus::Pass
                && item.verifier != candidate.proposer
                && item.artifact_hash == candidate.artifact_hash
            {
                verifier_ids.insert(item.verifier.clone());
            }
        }

        for check in &self.constitution.mandatory_checks {
            let passed = relevant.iter().any(|item| {
                item.check == *check
                    && item.status == EvidenceStatus::Pass
                    && item.independent
                    && item.verifier != candidate.proposer
                    && item.artifact_hash == candidate.artifact_hash
            });
            if !passed {
                reasons.insert(format!("evidence.missing_check:{check}"));
            }
        }

        let verifier_count = i64::try_from(verifier_ids.len()).unwrap_or(i64::MAX);
        if verifier_count < self.constitution.minimum_independent_verifiers {
            reasons.insert("evidence.verifier_diversity".into());
        }

        let accepted = reasons.is_empty();
        if accepted {
            reasons.insert("promotion.accepted".into());
        }
        let evidence_ids = relevant
            .iter()
            .map(|item| item.evidence_id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();

        let decision = PromotionDecision {
            candidate_id: candidate.candidate_id.clone(),
            status: if accepted {
                DecisionStatus::Accepted
            } else {
                DecisionStatus::Rejected
            },
            reasons: reasons.into_iter().collect(),
            evidence_ids,
            input_digest,
            constitution_version: self.constitution.version.clone(),
            gate_version: GATE_VERSION.into(),
        };
        decision.validate()?;
        Ok(decision)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::{Constitution, PromotionGate};
    use variaxiom_protocol::{Candidate, Evidence, EvidenceStatus, PromotionContext};

    fn candidate() -> Candidate {
        Candidate {
            candidate_id: "candidate:1".into(),
            parent_id: "genome:0".into(),
            artifact_hash: "a".repeat(64),
            proposer: "agent:builder".into(),
            rollback_target: "genome:0".into(),
            baseline_capabilities: ["artifact.read"].into_iter().map(String::from).collect(),
            requested_capabilities: ["artifact.read"].into_iter().map(String::from).collect(),
            estimated_cost_micro_usd: 100_000,
            metadata: BTreeMap::new(),
        }
    }

    fn evidence(candidate: &Candidate) -> Vec<Evidence> {
        ["unit", "regression", "security", "budget"]
            .into_iter()
            .enumerate()
            .map(|(index, check)| Evidence {
                evidence_id: format!("e:{check}"),
                subject_id: candidate.candidate_id.clone(),
                artifact_hash: candidate.artifact_hash.clone(),
                check: check.into(),
                status: EvidenceStatus::Pass,
                verifier: if index % 2 == 0 {
                    "verifier:a".into()
                } else {
                    "verifier:b".into()
                },
                independent: true,
                details: BTreeMap::new(),
            })
            .collect()
    }

    fn context(candidate: &Candidate) -> PromotionContext {
        PromotionContext {
            known_lineage_ids: ["genome:0"].into_iter().map(String::from).collect(),
            known_artifact_hashes: [candidate.artifact_hash.clone()].into_iter().collect(),
            authority_grants: BTreeMap::new(),
            lineage_capabilities: [("genome:0".into(), candidate.baseline_capabilities.clone())]
                .into_iter()
                .collect(),
        }
    }

    #[test]
    fn accepts_bounded_candidate() {
        let candidate = candidate();
        let decision = PromotionGate::new(Constitution::default())
            .decide(
                &candidate,
                &evidence(&candidate),
                &context(&candidate),
                None,
            )
            .expect("typed values are canonical");
        assert!(decision.accepted(), "{:?}", decision.reasons);
    }

    #[test]
    fn rejects_implicit_authority_escalation() {
        let mut candidate = candidate();
        candidate
            .requested_capabilities
            .insert("network.unrestricted".into());
        let decision = PromotionGate::new(Constitution::default())
            .decide(
                &candidate,
                &evidence(&candidate),
                &context(&candidate),
                None,
            )
            .expect("typed values are canonical");
        assert!(!decision.accepted());
        assert!(
            decision
                .reasons
                .iter()
                .any(|reason| reason.contains("authority"))
        );
    }

    #[test]
    fn rejects_candidate_that_spoofs_its_authority_baseline() {
        let mut candidate = candidate();
        candidate
            .baseline_capabilities
            .insert("network.unrestricted".into());
        candidate
            .requested_capabilities
            .insert("network.unrestricted".into());
        let mut context = context(&candidate);
        context.lineage_capabilities.insert(
            "genome:0".into(),
            ["artifact.read"].into_iter().map(String::from).collect(),
        );
        let decision = PromotionGate::new(Constitution::default())
            .decide(&candidate, &evidence(&candidate), &context, None)
            .expect("typed values are canonical");
        assert!(!decision.accepted());
        assert!(
            decision
                .reasons
                .contains(&"authority.baseline_mismatch".into())
        );
        assert!(
            decision
                .reasons
                .contains(&"authority.not_granted:network.unrestricted".into())
        );
    }

    #[test]
    fn explicit_grant_is_narrow() {
        let mut candidate = candidate();
        candidate
            .requested_capabilities
            .insert("network.example.com".into());
        let mut context = context(&candidate);
        context.authority_grants = [(
            "grant:owner".into(),
            ["network.example.com"]
                .into_iter()
                .map(String::from)
                .collect::<BTreeSet<_>>(),
        )]
        .into_iter()
        .collect();
        let decision = PromotionGate::new(Constitution::default())
            .decide(
                &candidate,
                &evidence(&candidate),
                &context,
                Some("grant:owner"),
            )
            .expect("typed values are canonical");
        assert!(decision.accepted(), "{:?}", decision.reasons);
    }

    #[test]
    fn duplicate_evidence_identifiers_fail_before_policy() {
        let candidate = candidate();
        let mut evidence = evidence(&candidate);
        evidence[1].evidence_id = evidence[0].evidence_id.clone();
        let result = PromotionGate::new(Constitution::default()).decide(
            &candidate,
            &evidence,
            &context(&candidate),
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn invalid_constitution_fails_before_policy() {
        let candidate = candidate();
        let constitution = Constitution {
            minimum_independent_verifiers: 0,
            ..Constitution::default()
        };
        let result = PromotionGate::new(constitution).decide(
            &candidate,
            &evidence(&candidate),
            &context(&candidate),
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn negative_cost_and_disabled_invariant_fail_before_policy() {
        let mut negative_candidate = candidate();
        negative_candidate.estimated_cost_micro_usd = -1;
        let result = PromotionGate::new(Constitution::default()).decide(
            &negative_candidate,
            &evidence(&negative_candidate),
            &context(&negative_candidate),
            None,
        );
        assert!(result.is_err());

        let candidate = candidate();
        let constitution = Constitution {
            forbid_self_verification: false,
            ..Constitution::default()
        };
        let result = PromotionGate::new(constitution).decide(
            &candidate,
            &evidence(&candidate),
            &context(&candidate),
            None,
        );
        assert!(result.is_err());
    }
}
