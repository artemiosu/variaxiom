//! Versioned protocol types and canonical serialization shared by the trusted kernel.

mod m2_stage_three;
mod m2_stage_two;

pub use m2_stage_three::{ContextBoundM2Input, inspect_m2_stage_three};
pub use m2_stage_two::{M2Entrypoint, StructurallyValidM2Input, inspect_m2_stage_two};

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::de::{self, DeserializeOwned, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Version of the canonical outer envelope.
pub const ENVELOPE_VERSION: &str = "variaxiom-envelope/v1";
/// Version of the promotion-input payload.
pub const PROMOTION_INPUT_VERSION: &str = "promotion-input/v1";
/// Version of the bootstrap promotion gate.
pub const GATE_VERSION: &str = "proof-gate/v1";
/// Largest integer accepted by the v1 cross-runtime profile.
pub const MAX_SAFE_INTEGER: i64 = (1_i64 << 53) - 1;
/// Smallest integer accepted by the v1 cross-runtime profile.
pub const MIN_SAFE_INTEGER: i64 = -MAX_SAFE_INTEGER;
/// Maximum object/array nesting below a canonical root value.
pub const MAX_CANONICAL_DEPTH: usize = 64;
/// Maximum accepted M2.1 wire input size in bytes.
pub const MAX_M2_WIRE_BYTES: usize = 1_048_576;

mod private {
    use super::CanonicalError;

    pub trait Sealed {
        fn validate_source(&self, depth: usize) -> Result<(), CanonicalError>;

        fn envelope_kind(&self) -> Option<&'static str> {
            None
        }
    }
}

/// Sealed marker for decoded JSON and Variaxiom protocol types that are safe
/// inputs to the canonical serializer. Arbitrary serde graphs are excluded.
#[allow(private_bounds)]
pub trait CanonicalSource: private::Sealed + Serialize {}

/// Canonical serialization failed or encountered a value outside the v1 profile.
#[derive(Debug)]
pub enum CanonicalError {
    /// `serde_json` could not represent the supplied value.
    Json(serde_json::Error),
    /// The value contains a float or integer outside the interoperable range.
    UnsupportedNumber(String),
    /// A typed protocol value violates a fail-closed structural invariant.
    InvalidProtocol(String),
}

impl Display for CanonicalError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => write!(formatter, "JSON serialization failed: {error}"),
            Self::UnsupportedNumber(path) => {
                write!(formatter, "number outside canonical v1 profile at {path}")
            }
            Self::InvalidProtocol(message) => {
                write!(formatter, "invalid protocol input: {message}")
            }
        }
    }
}

impl Error for CanonicalError {}

impl From<serde_json::Error> for CanonicalError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

fn validate_value(value: &Value, path: &str) -> Result<(), CanonicalError> {
    validate_value_at_depth(value, path, 0)
}

fn validate_value_at_depth(value: &Value, path: &str, depth: usize) -> Result<(), CanonicalError> {
    if depth > MAX_CANONICAL_DEPTH {
        return Err(CanonicalError::InvalidProtocol(format!(
            "canonical nesting exceeds {MAX_CANONICAL_DEPTH} at {path}"
        )));
    }
    match value {
        Value::Null | Value::Bool(_) | Value::String(_) => Ok(()),
        Value::Number(number) => {
            let valid = number
                .as_i64()
                .is_some_and(|item| (MIN_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&item))
                || number
                    .as_u64()
                    .is_some_and(|item| item <= MAX_SAFE_INTEGER as u64);
            if valid {
                Ok(())
            } else {
                Err(CanonicalError::UnsupportedNumber(path.into()))
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                validate_value_at_depth(item, &format!("{path}[{index}]"), depth + 1)?;
            }
            Ok(())
        }
        Value::Object(items) => {
            for (key, item) in items {
                validate_value_at_depth(item, &format!("{path}.{key}"), depth + 1)?;
            }
            Ok(())
        }
    }
}

fn sort_object_keys(value: Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.into_iter().map(sort_object_keys).collect()),
        Value::Object(items) => {
            let mut entries = items.into_iter().collect::<Vec<_>>();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            let mut sorted = serde_json::Map::new();
            for (key, item) in entries {
                sorted.insert(key, sort_object_keys(item));
            }
            Value::Object(sorted)
        }
        scalar => scalar,
    }
}

/// Serialize a protocol value to deterministic UTF-8 JSON bytes.
pub fn canonical_json<T: CanonicalSource>(value: &T) -> Result<Vec<u8>, CanonicalError> {
    private::Sealed::validate_source(value, 0)?;
    let value = serde_json::to_value(value)?;
    validate_value(&value, "$")?;
    let value = sort_object_keys(value);
    Ok(serde_json::to_vec(&value)?)
}

/// Return a lowercase SHA-256 digest over canonical JSON bytes.
pub fn canonical_digest<T: CanonicalSource>(value: &T) -> Result<String, CanonicalError> {
    let bytes = canonical_json(value)?;
    Ok(sha256_hex(&bytes))
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .map(StrictValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value.into())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_seq<A>(self, mut access: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(StrictValue(value)) = access.next_element()? {
            values.push(value);
        }
        Ok(StrictValue(Value::Array(values)))
    }

    fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut values = serde_json::Map::new();
        while let Some(key) = access.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom(format!(
                    "duplicate JSON object key: {key}"
                )));
            }
            let StrictValue(value) = access.next_value()?;
            values.insert(key, value);
        }
        Ok(StrictValue(Value::Object(values)))
    }
}

/// Parse a JSON byte string while rejecting duplicate member names at every depth.
pub fn parse_json_strict<T: DeserializeOwned>(source: &[u8]) -> Result<T, CanonicalError> {
    let value: StrictValue = serde_json::from_slice(source)?;
    validate_value(&value.0, "$")?;
    Ok(serde_json::from_value(value.0)?)
}

/// Stable stage-one rejection returned for untrusted M2.1 wire bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct M2WireRejection {
    /// Normative validation stage. This type currently represents stage one only.
    pub stage: u8,
    /// Stable M2.1 failure code.
    pub code: &'static str,
    /// Wire inspection never authorizes a side effect.
    pub authorizing: bool,
}

/// Immutable canonical bytes accepted at the M2.1 stage-one boundary.
#[derive(Clone, Debug, PartialEq)]
pub struct CanonicalM2Wire {
    bytes: Vec<u8>,
    digest: String,
    value: Value,
}

impl CanonicalM2Wire {
    /// Return the exact canonical bytes accepted by the boundary.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Return the lowercase SHA-256 digest of the exact wire bytes.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Return the decoded immutable view of the canonical value.
    #[must_use]
    pub const fn value(&self) -> &Value {
        &self.value
    }
}

fn m2_wire_rejection(code: &'static str) -> M2WireRejection {
    M2WireRejection {
        stage: 1,
        code,
        authorizing: false,
    }
}

/// Apply only the normative M2.1 stage-one wire checks.
///
/// Success authenticates nothing and grants no authority. Later stages must
/// consume this owned snapshot rather than a caller-controlled mutable value.
pub fn inspect_m2_wire(source: &[u8]) -> Result<CanonicalM2Wire, M2WireRejection> {
    if source.len() > MAX_M2_WIRE_BYTES {
        return Err(m2_wire_rejection("input.limit_exceeded"));
    }

    let value = match parse_json_strict::<Value>(source) {
        Ok(value) => value,
        Err(error) => {
            let message = error.to_string();
            let code = if message.contains("duplicate JSON object key") {
                "input.duplicate_member"
            } else if message.contains("nesting exceeds")
                || message.contains("recursion limit exceeded")
            {
                "input.limit_exceeded"
            } else {
                "input.encoding_invalid"
            };
            return Err(m2_wire_rejection(code));
        }
    };
    let encoded =
        canonical_json(&value).map_err(|_| m2_wire_rejection("input.encoding_invalid"))?;
    if encoded != source {
        return Err(m2_wire_rejection("input.encoding_invalid"));
    }

    Ok(CanonicalM2Wire {
        bytes: source.to_vec(),
        digest: sha256_hex(source),
        value,
    })
}

fn valid_token(value: &str) -> bool {
    !value.is_empty()
        && !value
            .chars()
            .any(|character| character <= '\u{1f}' || character == '\u{7f}')
}

fn deserialize_unique_set<'de, D>(deserializer: D) -> Result<BTreeSet<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let values = Vec::<String>::deserialize(deserializer)?;
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(de::Error::custom(
            "set members must be unique and lexicographically sorted",
        ));
    }
    let mut unique = BTreeSet::new();
    for value in values {
        if !unique.insert(value.clone()) {
            return Err(de::Error::custom(format!("duplicate set member: {value}")));
        }
    }
    Ok(unique)
}

struct UniqueGrantsVisitor;

impl<'de> Visitor<'de> for UniqueGrantsVisitor {
    type Value = BTreeMap<String, BTreeSet<String>>;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("an object of uniquely named grants with unique capability arrays")
    }

    fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut grants = BTreeMap::new();
        while let Some((grant_id, capabilities)) = access.next_entry::<String, Vec<String>>()? {
            if grants.contains_key(&grant_id) {
                return Err(de::Error::custom(format!(
                    "duplicate authority grant: {grant_id}"
                )));
            }
            let mut unique = BTreeSet::new();
            if capabilities.windows(2).any(|pair| pair[0] >= pair[1]) {
                return Err(de::Error::custom(format!(
                    "capabilities in {grant_id} must be unique and lexicographically sorted"
                )));
            }
            for capability in capabilities {
                if !unique.insert(capability.clone()) {
                    return Err(de::Error::custom(format!(
                        "duplicate capability in grant {grant_id}: {capability}"
                    )));
                }
            }
            grants.insert(grant_id, unique);
        }
        Ok(grants)
    }
}

fn deserialize_unique_grants<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, BTreeSet<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_map(UniqueGrantsVisitor)
}

/// A proposed inheritable change.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Candidate {
    /// Stable candidate identifier.
    pub candidate_id: String,
    /// Parent lineage node.
    pub parent_id: String,
    /// Content-addressed artifact digest.
    pub artifact_hash: String,
    /// Actor that proposed the candidate.
    pub proposer: String,
    /// Known-good lineage node to restore.
    pub rollback_target: String,
    /// Candidate-declared parent authority, verified against trusted context.
    #[serde(deserialize_with = "deserialize_unique_set")]
    pub baseline_capabilities: BTreeSet<String>,
    /// Authority requested by the candidate.
    #[serde(deserialize_with = "deserialize_unique_set")]
    pub requested_capabilities: BTreeSet<String>,
    /// Budget estimate represented as integer micro-dollars.
    pub estimated_cost_micro_usd: i64,
    /// Protocol-safe extension data.
    #[serde(default)]
    pub metadata: BTreeMap<String, Value>,
}

/// Return whether a string is a lowercase SHA-256 digest.
#[must_use]
pub fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Outcome reported by an evaluator.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EvidenceStatus {
    /// The check passed.
    Pass,
    /// The check failed.
    Fail,
    /// The evaluator could not complete the check.
    Error,
}

/// Evidence about exactly one candidate artifact.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    /// Stable evidence identifier.
    pub evidence_id: String,
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
    /// Protocol-safe evaluator details.
    #[serde(default)]
    pub details: BTreeMap<String, Value>,
}

/// Trusted facts supplied to the promotion gate.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionContext {
    /// Existing lineage nodes.
    #[serde(deserialize_with = "deserialize_unique_set")]
    pub known_lineage_ids: BTreeSet<String>,
    /// Artifacts verified by the content store.
    #[serde(deserialize_with = "deserialize_unique_set")]
    pub known_artifact_hashes: BTreeSet<String>,
    /// Explicit external grants, keyed by grant identifier.
    #[serde(deserialize_with = "deserialize_unique_grants")]
    pub authority_grants: BTreeMap<String, BTreeSet<String>>,
    /// Authority recorded for each trusted lineage node, keyed by lineage ID.
    #[serde(deserialize_with = "deserialize_unique_grants")]
    pub lineage_capabilities: BTreeMap<String, BTreeSet<String>>,
}

/// Machine-enforced promotion policy included in the hashed input.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Constitution {
    /// Version of this constitution.
    pub version: String,
    /// Checks every inheritable candidate must pass.
    #[serde(deserialize_with = "deserialize_unique_set")]
    pub mandatory_checks: BTreeSet<String>,
    /// Minimum number of independent verifier identities.
    pub minimum_independent_verifiers: i64,
    /// Candidate budget ceiling in integer micro-dollars.
    pub max_candidate_cost_micro_usd: i64,
    /// Require the parent to exist in trusted lineage.
    pub require_known_parent: bool,
    /// Require an existing rollback target.
    pub require_rollback_target: bool,
    /// Reject proposer-produced verification.
    pub forbid_self_verification: bool,
    /// Reject authority expansion without a matching external grant.
    pub forbid_implicit_authority_escalation: bool,
    /// Reject every non-passing relevant evidence item.
    pub reject_any_failed_evidence: bool,
}

impl Default for Constitution {
    fn default() -> Self {
        Self {
            version: "constitution/v1".into(),
            mandatory_checks: ["unit", "regression", "security", "budget"]
                .into_iter()
                .map(String::from)
                .collect(),
            minimum_independent_verifiers: 2,
            max_candidate_cost_micro_usd: 5_000_000,
            require_known_parent: true,
            require_rollback_target: true,
            forbid_self_verification: true,
            forbid_implicit_authority_escalation: true,
            reject_any_failed_evidence: true,
        }
    }
}

/// Complete replayable input whose digest is bound into a decision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionInput {
    /// Input protocol version.
    pub protocol_version: String,
    /// Candidate under review.
    pub candidate: Candidate,
    /// Evidence ordered by identifier before construction.
    pub evidence: Vec<Evidence>,
    /// Trusted lineage and grant facts.
    pub context: PromotionContext,
    /// Grant selected by the external caller, when any.
    pub authority_grant_id: Option<String>,
    /// Exact policy applied by the gate.
    pub constitution: Constitution,
}

/// Stable promotion status.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DecisionStatus {
    /// Candidate may enter the inheritable lineage.
    Accepted,
    /// Candidate must not enter the inheritable lineage.
    Rejected,
}

/// Deterministic result of applying a constitution to a hashed input.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionDecision {
    /// Candidate considered by the gate.
    pub candidate_id: String,
    /// Promotion status.
    pub status: DecisionStatus,
    /// Stable, sorted reason codes.
    pub reasons: Vec<String>,
    /// Sorted identifiers of relevant evidence.
    pub evidence_ids: Vec<String>,
    /// Digest of the complete canonical promotion-input envelope.
    pub input_digest: String,
    /// Constitution version applied to the decision.
    pub constitution_version: String,
    /// Promotion gate version.
    pub gate_version: String,
}

fn valid_reason(reason: &str) -> bool {
    if matches!(
        reason,
        "artifact.not_verified"
            | "candidate.cost_limit_exceeded"
            | "evidence.verifier_diversity"
            | "lineage.parent_unknown"
            | "authority.baseline_unknown"
            | "authority.baseline_mismatch"
            | "promotion.accepted"
            | "rollback.target_unknown"
    ) {
        return true;
    }
    if let Some(suffix) = reason.strip_prefix("authority.not_granted:") {
        let capabilities = suffix.split(',').collect::<Vec<_>>();
        return !suffix.is_empty()
            && capabilities.iter().all(|item| !item.is_empty())
            && capabilities.windows(2).all(|pair| pair[0] < pair[1]);
    }
    for prefix in [
        "evidence.artifact_mismatch:",
        "evidence.self_verification:",
        "evidence.missing_check:",
    ] {
        if reason
            .strip_prefix(prefix)
            .is_some_and(|suffix| !suffix.is_empty())
        {
            return true;
        }
    }
    reason
        .strip_prefix("evidence.failed:")
        .and_then(|suffix| suffix.rsplit_once(':'))
        .is_some_and(|(evidence_id, status)| {
            !evidence_id.is_empty() && matches!(status, "fail" | "error")
        })
}

impl PromotionDecision {
    /// Whether this decision accepted the candidate.
    #[must_use]
    pub const fn accepted(&self) -> bool {
        matches!(self.status, DecisionStatus::Accepted)
    }

    /// Validate version, ordering, reason semantics, and digest shape.
    pub fn validate(&self) -> Result<(), CanonicalError> {
        if !valid_token(&self.candidate_id) || !is_sha256(&self.input_digest) {
            return Err(CanonicalError::InvalidProtocol(
                "decision candidate_id or input_digest is invalid".into(),
            ));
        }
        if self.constitution_version != "constitution/v1" || self.gate_version != GATE_VERSION {
            return Err(CanonicalError::InvalidProtocol(
                "unsupported decision version".into(),
            ));
        }
        if self.reasons.is_empty()
            || self.reasons.windows(2).any(|pair| pair[0] >= pair[1])
            || self
                .reasons
                .iter()
                .any(|reason| !valid_token(reason) || !valid_reason(reason))
        {
            return Err(CanonicalError::InvalidProtocol(
                "decision reasons must be valid, unique, and sorted".into(),
            ));
        }
        if self
            .evidence_ids
            .iter()
            .any(|evidence_id| !valid_token(evidence_id))
            || self.evidence_ids.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(CanonicalError::InvalidProtocol(
                "decision evidence_ids must be non-empty, unique, and sorted".into(),
            ));
        }
        match self.status {
            DecisionStatus::Accepted if self.reasons != ["promotion.accepted"] => {
                return Err(CanonicalError::InvalidProtocol(
                    "accepted decision must contain only promotion.accepted".into(),
                ));
            }
            DecisionStatus::Rejected
                if self
                    .reasons
                    .iter()
                    .any(|reason| reason == "promotion.accepted") =>
            {
                return Err(CanonicalError::InvalidProtocol(
                    "rejected decision cannot contain promotion.accepted".into(),
                ));
            }
            _ => {}
        }
        Ok(())
    }

    /// Wrap this decision in the v1 canonical envelope.
    #[must_use]
    pub fn envelope(&self) -> Envelope<Self> {
        Envelope {
            envelope_version: ENVELOPE_VERSION.into(),
            kind: "promotion-decision".into(),
            payload: self.clone(),
        }
    }
}

/// Versioned domain-separated canonical envelope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope<T> {
    /// Canonical envelope format.
    pub envelope_version: String,
    /// Domain separator for the payload.
    pub kind: String,
    /// Typed payload.
    pub payload: T,
}

impl PromotionInput {
    /// Normalize evidence ordering and construct a replayable input.
    #[must_use]
    pub fn new(
        candidate: Candidate,
        mut evidence: Vec<Evidence>,
        context: PromotionContext,
        authority_grant_id: Option<String>,
        constitution: Constitution,
    ) -> Self {
        evidence.sort_by(|left, right| left.evidence_id.cmp(&right.evidence_id));
        Self {
            protocol_version: PROMOTION_INPUT_VERSION.into(),
            candidate,
            evidence,
            context,
            authority_grant_id,
            constitution,
        }
    }

    /// Validate invariants that cannot be expressed by the Rust field types alone.
    pub fn validate(&self) -> Result<(), CanonicalError> {
        if self.protocol_version != PROMOTION_INPUT_VERSION {
            return Err(CanonicalError::InvalidProtocol(
                "unsupported promotion input version".into(),
            ));
        }
        if !valid_token(&self.candidate.candidate_id)
            || !valid_token(&self.candidate.parent_id)
            || !valid_token(&self.candidate.proposer)
            || !valid_token(&self.candidate.rollback_target)
        {
            return Err(CanonicalError::InvalidProtocol(
                "candidate identifiers must be non-empty".into(),
            ));
        }
        if !is_sha256(&self.candidate.artifact_hash) {
            return Err(CanonicalError::InvalidProtocol(
                "candidate artifact_hash must be lowercase SHA-256".into(),
            ));
        }
        if self.constitution.version != "constitution/v1"
            || self.constitution.mandatory_checks.is_empty()
            || self
                .constitution
                .mandatory_checks
                .iter()
                .any(|check| !valid_token(check))
        {
            return Err(CanonicalError::InvalidProtocol(
                "constitution version must be supported and mandatory checks non-empty".into(),
            ));
        }
        if !(1..=MAX_SAFE_INTEGER).contains(&self.constitution.minimum_independent_verifiers) {
            return Err(CanonicalError::InvalidProtocol(
                "minimum_independent_verifiers must be a positive safe integer".into(),
            ));
        }
        if !(0..=MAX_SAFE_INTEGER).contains(&self.constitution.max_candidate_cost_micro_usd) {
            return Err(CanonicalError::InvalidProtocol(
                "max_candidate_cost_micro_usd must be a non-negative safe integer".into(),
            ));
        }
        if !self.constitution.require_known_parent
            || !self.constitution.require_rollback_target
            || !self.constitution.forbid_self_verification
            || !self.constitution.forbid_implicit_authority_escalation
            || !self.constitution.reject_any_failed_evidence
        {
            return Err(CanonicalError::InvalidProtocol(
                "constitution/v1 security invariants cannot be disabled".into(),
            ));
        }
        if !(0..=MAX_SAFE_INTEGER).contains(&self.candidate.estimated_cost_micro_usd) {
            return Err(CanonicalError::InvalidProtocol(
                "estimated_cost_micro_usd must be a non-negative safe integer".into(),
            ));
        }
        if self
            .context
            .known_lineage_ids
            .iter()
            .any(|lineage_id| !valid_token(lineage_id))
        {
            return Err(CanonicalError::InvalidProtocol(
                "known lineage identifiers must be non-empty".into(),
            ));
        }
        if self
            .context
            .lineage_capabilities
            .keys()
            .any(|lineage_id| !valid_token(lineage_id))
        {
            return Err(CanonicalError::InvalidProtocol(
                "lineage capability identifiers must be non-empty".into(),
            ));
        }
        if self
            .context
            .lineage_capabilities
            .keys()
            .ne(self.context.known_lineage_ids.iter())
        {
            return Err(CanonicalError::InvalidProtocol(
                "lineage_capabilities must cover known_lineage_ids exactly".into(),
            ));
        }
        if self
            .authority_grant_id
            .as_ref()
            .is_some_and(|grant_id| !self.context.authority_grants.contains_key(grant_id))
        {
            return Err(CanonicalError::InvalidProtocol(
                "authority_grant_id does not exist in trusted context".into(),
            ));
        }
        if self
            .context
            .authority_grants
            .keys()
            .any(|grant_id| !valid_token(grant_id))
            || self
                .authority_grant_id
                .as_ref()
                .is_some_and(|grant_id| !valid_token(grant_id))
        {
            return Err(CanonicalError::InvalidProtocol(
                "authority grant identifiers must be non-empty".into(),
            ));
        }
        if self
            .candidate
            .baseline_capabilities
            .union(&self.candidate.requested_capabilities)
            .any(|capability| !valid_token(capability) || capability.contains(','))
        {
            return Err(CanonicalError::InvalidProtocol(
                "capability names must be non-empty and cannot contain commas".into(),
            ));
        }
        for artifact_hash in &self.context.known_artifact_hashes {
            if !is_sha256(artifact_hash) {
                return Err(CanonicalError::InvalidProtocol(
                    "context artifact hash must be lowercase SHA-256".into(),
                ));
            }
        }
        if self
            .context
            .authority_grants
            .values()
            .chain(self.context.lineage_capabilities.values())
            .any(|capabilities| {
                capabilities
                    .iter()
                    .any(|capability| !valid_token(capability) || capability.contains(','))
            })
        {
            return Err(CanonicalError::InvalidProtocol(
                "trusted capability names must be non-empty and cannot contain commas".into(),
            ));
        }
        if self
            .evidence
            .windows(2)
            .any(|pair| pair[0].evidence_id >= pair[1].evidence_id)
        {
            return Err(CanonicalError::InvalidProtocol(
                "evidence must be strictly sorted by evidence_id".into(),
            ));
        }
        let mut evidence_ids = BTreeSet::new();
        for item in &self.evidence {
            if !valid_token(&item.evidence_id)
                || !valid_token(&item.subject_id)
                || !valid_token(&item.check)
                || !valid_token(&item.verifier)
            {
                return Err(CanonicalError::InvalidProtocol(
                    "evidence identifiers must be non-empty".into(),
                ));
            }
            if !evidence_ids.insert(&item.evidence_id) {
                return Err(CanonicalError::InvalidProtocol(format!(
                    "duplicate evidence_id: {}",
                    item.evidence_id
                )));
            }
            if !is_sha256(&item.artifact_hash) {
                return Err(CanonicalError::InvalidProtocol(format!(
                    "evidence artifact_hash is not lowercase SHA-256: {}",
                    item.evidence_id
                )));
            }
        }
        Ok(())
    }

    /// Wrap this input in the v1 canonical envelope.
    #[must_use]
    pub fn envelope(&self) -> Envelope<Self> {
        Envelope {
            envelope_version: ENVELOPE_VERSION.into(),
            kind: "promotion-input".into(),
            payload: self.clone(),
        }
    }
}

impl private::Sealed for Value {
    fn validate_source(&self, depth: usize) -> Result<(), CanonicalError> {
        validate_value_at_depth(self, "$", depth)
    }
}
impl CanonicalSource for Value {}
impl private::Sealed for Candidate {
    fn validate_source(&self, depth: usize) -> Result<(), CanonicalError> {
        for (key, value) in &self.metadata {
            validate_value_at_depth(value, &format!("$.metadata.{key}"), depth + 2)?;
        }
        Ok(())
    }
}
impl CanonicalSource for Candidate {}
impl private::Sealed for Evidence {
    fn validate_source(&self, depth: usize) -> Result<(), CanonicalError> {
        for (key, value) in &self.details {
            validate_value_at_depth(value, &format!("$.details.{key}"), depth + 2)?;
        }
        Ok(())
    }
}
impl CanonicalSource for Evidence {}
impl private::Sealed for PromotionContext {
    fn validate_source(&self, _depth: usize) -> Result<(), CanonicalError> {
        Ok(())
    }
}
impl CanonicalSource for PromotionContext {}
impl private::Sealed for Constitution {
    fn validate_source(&self, _depth: usize) -> Result<(), CanonicalError> {
        Ok(())
    }
}
impl CanonicalSource for Constitution {}
impl private::Sealed for PromotionInput {
    fn validate_source(&self, depth: usize) -> Result<(), CanonicalError> {
        self.validate()?;
        private::Sealed::validate_source(&self.candidate, depth + 1)?;
        for item in &self.evidence {
            private::Sealed::validate_source(item, depth + 2)?;
        }
        Ok(())
    }

    fn envelope_kind(&self) -> Option<&'static str> {
        Some("promotion-input")
    }
}
impl CanonicalSource for PromotionInput {}
impl private::Sealed for PromotionDecision {
    fn validate_source(&self, _depth: usize) -> Result<(), CanonicalError> {
        self.validate()
    }

    fn envelope_kind(&self) -> Option<&'static str> {
        Some("promotion-decision")
    }
}
impl CanonicalSource for PromotionDecision {}
impl<T: CanonicalSource> private::Sealed for Envelope<T> {
    fn validate_source(&self, depth: usize) -> Result<(), CanonicalError> {
        if self.envelope_version != ENVELOPE_VERSION {
            return Err(CanonicalError::InvalidProtocol(
                "unsupported envelope version".into(),
            ));
        }
        if private::Sealed::envelope_kind(&self.payload)
            .is_some_and(|expected| self.kind != expected)
        {
            return Err(CanonicalError::InvalidProtocol(
                "envelope kind does not match payload".into(),
            ));
        }
        private::Sealed::validate_source(&self.payload, depth + 1)
    }
}
impl<T: CanonicalSource> CanonicalSource for Envelope<T> {}

impl Envelope<PromotionInput> {
    /// Validate a parsed promotion-input envelope and its payload.
    pub fn validate_input(&self) -> Result<(), CanonicalError> {
        if self.envelope_version != ENVELOPE_VERSION || self.kind != "promotion-input" {
            return Err(CanonicalError::InvalidProtocol(
                "unexpected promotion-input envelope version or kind".into(),
            ));
        }
        self.payload.validate()
    }
}

impl Envelope<PromotionDecision> {
    /// Validate a parsed promotion-decision envelope and its payload.
    pub fn validate_decision(&self) -> Result<(), CanonicalError> {
        if self.envelope_version != ENVELOPE_VERSION || self.kind != "promotion-decision" {
            return Err(CanonicalError::InvalidProtocol(
                "unexpected promotion-decision envelope version or kind".into(),
            ));
        }
        self.payload.validate()
    }
}

/// Parse and validate a complete promotion-input envelope.
pub fn parse_promotion_input_envelope(
    source: &[u8],
) -> Result<Envelope<PromotionInput>, CanonicalError> {
    let envelope: Envelope<PromotionInput> = parse_json_strict(source)?;
    envelope.validate_input()?;
    Ok(envelope)
}

/// Parse and validate a complete promotion-decision envelope.
pub fn parse_promotion_decision_envelope(
    source: &[u8],
) -> Result<Envelope<PromotionDecision>, CanonicalError> {
    let envelope: Envelope<PromotionDecision> = parse_json_strict(source)?;
    envelope.validate_decision()?;
    Ok(envelope)
}
