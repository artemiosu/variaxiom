//! Demonstrate that functional evidence cannot silently grant authority.

use std::collections::{BTreeMap, BTreeSet};

use variaxiom_kernel::{Constitution, PromotionGate};
use variaxiom_protocol::{Candidate, Evidence, EvidenceStatus, PromotionContext};

fn main() {
    let baseline: BTreeSet<_> = ["artifact.read"].into_iter().map(String::from).collect();
    let mut requested = baseline.clone();
    requested.insert("network.unrestricted".into());

    let candidate = Candidate {
        id: "candidate:demo".into(),
        parent_id: "genome:0".into(),
        artifact_hash: "a".repeat(64),
        proposer: "agent:mutator".into(),
        rollback_target: "genome:0".into(),
        baseline_capabilities: baseline,
        requested_capabilities: requested,
        estimated_cost_micro_usd: 10_000,
    };

    let evidence: Vec<_> = ["unit", "regression", "security", "budget"]
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
        .collect();

    let context = PromotionContext {
        known_lineage_ids: ["genome:0"].into_iter().map(String::from).collect(),
        known_artifact_hashes: [candidate.artifact_hash.clone()].into_iter().collect(),
        authority_grants: BTreeMap::new(),
    };

    let decision =
        PromotionGate::new(Constitution::default()).decide(&candidate, &evidence, &context, None);

    println!("accepted={}", decision.accepted);
    for reason in decision.reasons {
        println!("- {reason}");
    }
}
