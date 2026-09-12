# Threat Model

## Assets

- constitutional policy and amendment authority;
- lineage integrity and rollback points;
- hidden evaluators and holdout data;
- secrets and external accounts;
- user/project data;
- compute and monetary budgets;
- artifact authenticity and build provenance;
- trustworthy public claims about project performance.

## Adversaries and failure sources

Variaxiom assumes risk from:

- prompt-injected external content;
- compromised or misaligned model output;
- malicious or vulnerable generated code;
- poisoned skills/plugins/dependencies;
- a candidate exploiting evaluator loopholes;
- a verifier colluding with a proposer;
- maintainer credential compromise;
- accidental misconfiguration;
- stale or false persistent memory;
- resource-exhaustion and agent-spawn storms;
- non-malicious emergent optimization against the wrong metric.

## Trust boundaries

```text
human governance
  | signed grants/amendments
constitutional kernel
  | typed decisions and leases
phenotype/evolution workers (untrusted)
  | brokered effects
external systems (untrusted/partially trusted)

evaluation workers are isolated from candidate workers.
hidden data is isolated from both candidate and proposer.
```

## Major threats and controls

| Threat | Primary controls | Residual risk |
|---|---|---|
| Prompt injection | authority labels, brokered effects, minimal context, sandbox | authorized tool misuse through persuasive content |
| Sandbox escape | WASM/OCI isolation, patching, no host secrets, egress controls | runtime/kernel vulnerabilities |
| Authority escalation | exact capability deltas, signed grants, deny-by-default | policy mis-specification |
| Evaluator gaming | hidden tests, evaluator diversity, external outcomes, adversarial review | unknown loopholes and distribution shift |
| Self-verification | identity separation, minimum verifier diversity | sybil/collusion if identity weak |
| Lineage tampering | content hashes, signatures roadmap, append-only logs, replicas | compromised signing/governance keys |
| Memory poisoning | provenance, TTL, contradiction, revalidation, soma/germline gate | subtle false beliefs passing weak evals |
| Spawn storm | reproduction tokens, quotas, budget, TTL, apoptosis | scheduler bugs or broad grants |
| Cost runaway | hierarchical budgets, hard limits, preemption, cost telemetry | delayed provider billing data |
| Supply-chain compromise | pinned dependencies, SBOM, signatures, isolated builds | trusted upstream compromise |
| Rollback failure | clean-room rebuilds, retained ancestors, periodic drills | external irreversible effects |
| Governance capture | public RFCs, multiple reviewers, transparent releases | social concentration and maintainer burnout |
| Stale lineage writer | global and per-lineage exact-head CAS inside one `BEGIN IMMEDIATE` transaction | denial of service under contention |
| Partial promotion commit | SQLite WAL + FULL synchronous mode; one transaction for event, heads, rollback, receipt, projection, and outbox | faulty storage that violates locking or fsync contracts |
| Retry duplicates | permanent request ID bound to exact canonical operation digest and stored receipt; immutable recorded time is distinct from the fresh per-attempt authority clock | unbounded idempotency-table growth |
| Database rollback/replacement or forged extension | exact empty-state gate before initialization, otherwise mandatory writer-open replay against an operator-retained root plus exact pre-commit pending intent; artifact-complete backup | compromise of database, artifacts, root custodian, and operator capability together |
| Projection poisoning | pure replay from genesis, canonical state digest, shadow rebuild/compare, no silent repair | reducer bugs shared by implementations |
| Outbox confusion | immutable payload identity, delivery only after commit plus durable external-root finalization, at-least-once consumer deduplication | external effect may occur before delivery acknowledgement |
| Rollback abuse | operator-only writer, exact current head, immutable reservation, verified target artifact, append-only rollback event | operator credential or trusted-host compromise |

## Safety invariants not solved by “a critic model”

A separate model can find bugs, but it is not a security boundary. Critics can share blind spots, be prompt-injected, collude through common context, or optimize the same flawed evaluator. Deterministic policy and isolation remain necessary.

## Out-of-scope deployment

Do not deploy the pre-alpha reference with production credentials, unrestricted network access, or authority over safety-critical systems. Do not use it to create autonomous persistence, unbounded replication, or financial self-provisioning.

## M2.2 local persistence boundary

Candidate and evaluator processes must not receive the SQLite directory, a writer connection, or
the opaque Rust writer handle. A valid M2.1 result is intentionally insufficient: the writer
re-verifies raw proposal bytes against the current separately supplied anchor and then compares
both event and lineage heads.

The writer authority is non-cloneable, scoped to one store/lineage/domain and operation set, and
bound to a host-controlled epoch/expiry. Pause and revocation serialize with the short authority
admission point for each COMMIT/root transition through a shared control latch; a stale handle
cannot obtain a new effect permit or start another transaction. An effect admitted first may finish
its already-linearized atomic/durability call after the competing pause, without authorizing a new
effect. Its operator
principal and authorization digest are copied into every event for audit.
An admitted SQLite/root durability call is still bounded by an independent supervisor watchdog;
expiry terminates the dedicated storage process without reporting success, and verified restart
recovery resolves any retained pending intent before another capability is issued.
All other SQLite/VFS and external-root reads are deadline-bounded and must cancel without a
lingering file/lock task or trigger the same supervised process-death path. Their atomic terminal
arbitration publishes only a strictly pre-deadline completion and discards equality/late bytes.
Session and open-cursor
timers close new admission immediately but retain the protected snapshot until every already
admitted operation/cursor use finishes or is cancelled, preventing a second open from racing an
expired live call.
The final open handoff closes the physical SQLite verification snapshot outside the short control
guard while retaining exclusive store ownership; only a later no-I/O atomic state claim may issue
the session. Blocking close, expiry, or pause therefore cannot expose a half-transferred session or
hold the pause lock across VFS work.
Backup/checkpoint/migration and artifact cleanup/GC hold the no-new-leases barrier only within one configured aggregate
maintenance deadline; timeout cancels and discards unpublished output or terminates the supervised
storage process. A separate bounded cleanup phase performs only cancellation and resource/barrier
release; if it cannot prove termination, storage-process death precedes release. Thus a blocked
maintenance backend cannot retain the store-wide barrier forever or publish partial output.
Capabilities, cursors, permits, leases, and responses are generation-bound; storage-child death
atomically invalidates them, rejects late messages, and releases host-side registrations only
after termination proves no later file/root activity. A restarted child cannot inherit them.
Fresh recovery authority is logged by the host control plane but is not yet durably attributed in
lineage/root-custodian history; risk R23 must be closed before production recovery claims include
operator attribution.

The main database, WAL, and shared-memory files form one state unit. Network filesystems and raw
main-file-only copies are unsupported. M2.2 detects mutation, gaps, projection drift, and stale
writers but does not defeat an attacker able to replace the database and every independently kept
root or artifact-complete backup. Repair is offline into a new file and requires explicit operator
replacement. Complete M2.1 anchor states and transitions prevent a later-sequence alternate branch
from washing out prior key ownership or revocation.

Evaluation cannot amend anchor state. A distinct operator permission and append-only event runs one
M2.1 anchor transition. Before any SQLite commit, the external root custodian durably records its
exact operation/event/root intent; it finalizes the new root before acknowledgement or outbox
dispatch. Thus a storage-only attacker cannot present an arbitrary self-consistent extension as a
recoverable commit. Artifact-store cleanup shares a retention lock with streaming verification and
cannot race the transaction that creates a permanent pin.

## Validation plan

- unit tests for every invariant;
- property tests for canonicalization, lineage, and capability set algebra;
- tamper and replay tests;
- fault injection around promotion transactions;
- red-team prompt-injection corpus;
- sandbox escape testing by qualified specialists;
- evaluator-hacking challenge set;
- periodic rollback drills;
- independent review before production claims.
