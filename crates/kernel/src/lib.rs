//! Minimal trusted promotion gate.
//!
//! The kernel does not plan, call models, generate tools, or execute arbitrary
//! code. It only applies small deterministic rules to facts produced by other
//! trust domains.

use std::collections::BTreeSet;

use variaxiom_protocol::{
    Candidate, Evidence, EvidenceStatus, PromotionContext, PromotionDecision,
};

/// Machine-enforced promotion policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Constitution {
    /// Checks every inheritable candidate must pass.
    pub mandatory_checks: BTreeSet<String>,
    /// Minimum number of independent verifier identities.
    pub minimum_independent_verifiers: usize,
    /// Candidate budget ceiling in integer micro-dollars.
    pub max_candidate_cost_micro_usd: u64,
}

impl Default for Constitution {
    fn default() -> Self {
        Self {
            mandatory_checks: ["unit", "regression", "security", "budget"]
                .into_iter()
                .map(String::from)
                .collect(),
            minimum_independent_verifiers: 2,
            max_candidate_cost_micro_usd: 5_000_000,
        }
    }
}

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
    #[must_use]
    pub fn decide(
        &self,
        candidate: &Candidate,
        evidence: &[Evidence],
        context: &PromotionContext,
        authority_grant_id: Option<&str>,
    ) -> PromotionDecision {
        let mut reasons = Vec::new();

        if !context
            .known_artifact_hashes
            .contains(&candidate.artifact_hash)
        {
            reasons.push("candidate artifact is absent or not integrity-verified".into());
        }
        if !context.known_lineage_ids.contains(&candidate.parent_id) {
            reasons.push("candidate parent is not present in the trusted lineage".into());
        }
        if !context
            .known_lineage_ids
            .contains(&candidate.rollback_target)
        {
            reasons.push("rollback target is not present in the trusted lineage".into());
        }
        if candidate.estimated_cost_micro_usd > self.constitution.max_candidate_cost_micro_usd {
            reasons.push("candidate exceeds the constitutional cost ceiling".into());
        }

        let delta = candidate.authority_delta();
        if !delta.is_empty() {
            let granted = authority_grant_id
                .and_then(|id| context.authority_grants.get(id))
                .cloned()
                .unwrap_or_default();
            let missing: Vec<_> = delta.difference(&granted).cloned().collect();
            if !missing.is_empty() {
                reasons.push(format!(
                    "candidate requests authority without an external grant: {}",
                    missing.join(", ")
                ));
            }
        }

        let relevant: Vec<_> = evidence
            .iter()
            .filter(|item| item.subject_id == candidate.id)
            .collect();
        let mut verifier_ids = BTreeSet::new();

        for item in &relevant {
            if item.artifact_hash != candidate.artifact_hash {
                reasons.push(format!("evidence {} addresses another artifact", item.id));
            }
            if item.verifier == candidate.proposer {
                reasons.push(format!("evidence {} is self-verification", item.id));
            }
            if item.status != EvidenceStatus::Pass {
                reasons.push(format!("evidence {} did not pass", item.id));
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
                reasons.push(format!(
                    "missing independent passing evidence for mandatory check: {check}"
                ));
            }
        }

        if verifier_ids.len() < self.constitution.minimum_independent_verifiers {
            reasons.push("insufficient independent verifier diversity".into());
        }

        reasons.sort();
        reasons.dedup();
        let accepted = reasons.is_empty();
        if accepted {
            reasons.push("all constitutional promotion gates passed".into());
        }

        PromotionDecision {
            candidate_id: candidate.id.clone(),
            accepted,
            reasons,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::{Constitution, PromotionGate};
    use variaxiom_protocol::{Candidate, Evidence, EvidenceStatus, PromotionContext};

    fn candidate() -> Candidate {
        Candidate {
            id: "candidate:1".into(),
            parent_id: "genome:0".into(),
            artifact_hash: "a".repeat(64),
            proposer: "agent:builder".into(),
            rollback_target: "genome:0".into(),
            baseline_capabilities: ["artifact.read"].into_iter().map(String::from).collect(),
            requested_capabilities: ["artifact.read"].into_iter().map(String::from).collect(),
            estimated_cost_micro_usd: 100_000,
        }
    }

    fn evidence(candidate: &Candidate) -> Vec<Evidence> {
        ["unit", "regression", "security", "budget"]
            .into_iter()
            .enumerate()
            .map(|(index, check)| Evidence {
                id: format!("e:{check}"),
                subject_id: candidate.id.clone(),
                artifact_hash: candidate.artifact_hash.clone(),
                check: check.into(),
                status: EvidenceStatus::Pass,
                verifier: if index % 2 == 0 {
                    "verifier:a".into()
                } else {
                    "verifier:b".into()
                },
                independent: true,
            })
            .collect()
    }

    fn context(candidate: &Candidate) -> PromotionContext {
        PromotionContext {
            known_lineage_ids: ["genome:0"].into_iter().map(String::from).collect(),
            known_artifact_hashes: [candidate.artifact_hash.clone()].into_iter().collect(),
            authority_grants: BTreeMap::new(),
        }
    }

    #[test]
    fn accepts_bounded_candidate() {
        let candidate = candidate();
        let decision = PromotionGate::new(Constitution::default()).decide(
            &candidate,
            &evidence(&candidate),
            &context(&candidate),
            None,
        );
        assert!(decision.accepted, "{:?}", decision.reasons);
    }

    #[test]
    fn rejects_implicit_authority_escalation() {
        let mut candidate = candidate();
        candidate
            .requested_capabilities
            .insert("network.unrestricted".into());
        let decision = PromotionGate::new(Constitution::default()).decide(
            &candidate,
            &evidence(&candidate),
            &context(&candidate),
            None,
        );
        assert!(!decision.accepted);
        assert!(
            decision
                .reasons
                .iter()
                .any(|reason| reason.contains("authority"))
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
        let decision = PromotionGate::new(Constitution::default()).decide(
            &candidate,
            &evidence(&candidate),
            &context,
            Some("grant:owner"),
        );
        assert!(decision.accepted, "{:?}", decision.reasons);
    }
}
