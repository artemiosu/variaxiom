//! Dependency-light protocol types shared by the trusted kernel.

use std::collections::{BTreeMap, BTreeSet};

/// A proposed inheritable change.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Candidate {
    /// Stable candidate identifier.
    pub id: String,
    /// Parent lineage node.
    pub parent_id: String,
    /// Content-addressed artifact digest.
    pub artifact_hash: String,
    /// Actor that proposed the candidate.
    pub proposer: String,
    /// Known-good lineage node to restore.
    pub rollback_target: String,
    /// Authority held by the parent phenotype.
    pub baseline_capabilities: BTreeSet<String>,
    /// Authority requested by the candidate.
    pub requested_capabilities: BTreeSet<String>,
    /// Budget estimate represented as integer micro-dollars.
    pub estimated_cost_micro_usd: u64,
}

impl Candidate {
    /// Return capabilities requested beyond the parent's authority.
    #[must_use]
    pub fn authority_delta(&self) -> BTreeSet<String> {
        self.requested_capabilities
            .difference(&self.baseline_capabilities)
            .cloned()
            .collect()
    }
}

/// Outcome reported by an evaluator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceStatus {
    /// The check passed.
    Pass,
    /// The check failed.
    Fail,
    /// The evaluator could not complete the check.
    Error,
}

/// Evidence about exactly one candidate artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Evidence {
    /// Stable evidence identifier.
    pub id: String,
    /// Candidate identifier.
    pub subject_id: String,
    /// Exact evaluated artifact digest.
    pub artifact_hash: String,
    /// Check name.
    pub check: String,
    /// Check outcome.
    pub status: EvidenceStatus,
    /// Evaluator identity.
    pub verifier: String,
    /// Whether governance considers this verifier independent.
    pub independent: bool,
}

/// Trusted facts supplied to the promotion gate.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PromotionContext {
    /// Existing lineage nodes.
    pub known_lineage_ids: BTreeSet<String>,
    /// Artifacts verified by the content store.
    pub known_artifact_hashes: BTreeSet<String>,
    /// Explicit external grants, keyed by grant identifier.
    pub authority_grants: BTreeMap<String, BTreeSet<String>>,
}

/// Deterministic promotion result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PromotionDecision {
    /// Candidate considered by the gate.
    pub candidate_id: String,
    /// Whether the candidate may become inheritable.
    pub accepted: bool,
    /// Human-inspectable deterministic reasons.
    pub reasons: Vec<String>,
}
