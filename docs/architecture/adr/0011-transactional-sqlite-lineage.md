# ADR 0011: Local SQLite transactions with exact-head compare-and-swap

- **Status:** proposed
- **Date:** 2026-09-12
- **Decision owner:** bootstrap maintainer under the founder review exception for proposal only
- **Specification:** [`../../specs/m2.2-transactional-sqlite-lineage.md`](../../specs/m2.2-transactional-sqlite-lineage.md)

## Context

M2.1 verifies signed promotion inputs but deliberately returns only non-authorizing evidence. The
next boundary must commit an independently recomputed decision, append-only history, selected head,
rollback reservation, and outbox row without partial state or stale-writer overwrite.

The project is still a single-node modular monolith. Distributed consensus, PostgreSQL, Kafka, and
Kubernetes would add failure modes without solving a measured need. SQLite already provides atomic
transactions and serialized writers, but application-level exact-head checks, canonical event
identity, deterministic projections, and authority separation remain Variaxiom's responsibility.

## Decision

Use one local SQLite database pinned to the reviewed September 2026 baseline, version 3.53.4, in
WAL mode with `synchronous=FULL`. Start mutations with `BEGIN IMMEDIATE`, then enforce explicit
global-event and selected-lineage compare-and-swap inside the same transaction. Store immutable
canonical objects and hash-linked events; maintain current heads as rebuildable,
security-sensitive control projections. Commit the decision, event, head, rollback reservation,
receipt, projection, and outbox atomically.

Expose writes only through an operator-injected Rust `LineageWriter`. The writer re-runs the full
M2.1 verifier from raw attested-proposal bytes and the live trusted anchor. Python remains a
reference oracle and offline reader. A verified M2.1 result is never accepted as a write permit.

Construct a general writer only after complete lineage/projection verification against an
operator-retained external store root; an initialization-only writer is issued solely after direct
verification of the exact empty pre-genesis state and root. A separately scoped `read_lineage`
permission can reopen verified historical evidence without granting mutation or root-recovery
authority. Pre-genesis pending-intent recovery requires the exact combined initialization and
recovery permissions and returns only the initialization-restricted writer after a proven abort.
Recovery and mutation permissions never imply that read permission: clean opening may return a
writer-only carrier, pending evidence includes a `RecoveryReadSession` only with `read_lineage`
and that session exposes only a borrowed `RecoveryReader`, while a recovery-only operation that
resolves an intent returns capability-free evidence.
Bind each operation to a non-cloneable, epoch-scoped
operator authority and shared pause/revoke latch. Store complete M2.1 anchor state and require
byte-identical reuse during evaluation. Anchor changes use a separate
`advance_trusted_anchor` permission, command, and event that runs one exact M2.1 transition;
sequence jumps and anchor forks are invalid.

Register an active control lease continuously across each mutation/recovery operation. A distinct
short commit guard serializes pause/revoke with COMMIT and each root CAS; pause/revoke never waits
for artifact, SQLite, or root resources. Maintenance first blocks new leases, releases the guard,
and then waits for active leases to drain, avoiding inversion. Artifact resolution uses immutable
sized handles, a 256 MiB aggregate per-operation byte bound, bounded streaming chunks, and a
30-second monotonic work deadline before SQLite begins.
Store opening retains that active lease only in an unfinished sealed cursor. A successful open
deregisters it and returns a separate bounded session lease; each later mutation registers a fresh
active operation, while idle sessions do not block the active-operation drain. Every read or
mutation first obtains a private per-call session-operation lease. Session close/expiry blocks new
admission immediately but releases the exclusive store snapshot only after the last admitted call
or retained read cursor has cancelled/completed. Store-open cursor expiry uses the same
close-admission-then-drain rule, so no timer can release a snapshot beneath active verification.

Derive the database identity before initialization from a globally unique, never-reused operator
store-slot token. Initialization and later authorities therefore bind one stable database ID, and
lost-response recovery never needs to reinterpret an initialization command under a new identity.
After finalized genesis, either exact authority that could have received the original
initialization writer (`initialize_lineage` alone, or initialization plus recovery after a proven
pre-genesis abort) may open only a sealed, single-use initialization-retry session when its full
canonical descriptor bytes, digest, and control epoch match genesis; the session binds genesis request/operation. An identical request/operation returns the retained
receipt, a changed operation conflicts, and an absent request fails `lineage.already_initialized`
without starting a mutation. It never yields a general writer or reader.

Before SQLite commit, durably CAS an exact pending-operation intent in a separately protected root
custodian. After commit, finalize that intent into the resulting external root before acknowledging
success, dispatching outbox work, or allowing another write. The same control epoch,
`ControlLatch`, `HealthLatch`, permission, monotonic deadline, and exact intent are rechecked
immediately before ordinary root
finalization under a short control guard. It issues a sealed single-use effect permit and releases
the guard before the blocking call; permit issuance is the authority linearization point. The
`HealthLatch` winning after confirmed SQLite commit retains the pending intent and returns
`storage.root_publish_deferred`; the invalidated session cannot finalize it. The active lease and
permit remain owned by that call, whose durability work may finish after the deadline
but whose state transition can never occur after it returns.
An independent 30-second supervisor watchdog terminates the dedicated storage process if an admitted
SQLite/root durability call does not return; it produces no success result and the next process
performs exact crash recovery. A deployment unable to enforce that isolation remains disabled.
Every other SQLite/VFS and external-root read/reload is also bounded by its applicable absolute
open/read/pre-transaction/transaction/root-phase deadline. It must be synchronously cancelled with
no lingering file/lock task or trigger the same supervised process-death recovery; progress-handler
polling alone is not considered a bound on blocked VFS I/O. Completion and deadline cancellation
share one atomic terminal state; only a strictly pre-deadline winner may publish bytes, while
equality/late completion is discarded or triggers supervised death.
Every session, cursor, lease, effect permit, maintenance barrier, request, and response is bound to
one private storage-process generation. Child death closes transport, rejects late responses,
invalidates all stale proxies, joins calls, and releases host-side counters/leases exactly once
after termination; a fresh generation issues nothing before full verified open/recovery.
Successful store-open handoff is two-phase: the admitted open call closes its SQLite verification
snapshot without holding control-state locks while retaining the exclusive store lease, then a
short no-I/O completion guard atomically rechecks state and transfers that lease into the bounded
session. Snapshot-close failure or intervening invalidation exposes no session.
Loss of authority before that check leaves a non-authorizing pending recovery state for a separately
authorized recovery attempt. Recovery accepts only the exact
one-event extension named by the retained intent; self-consistent unrecognized extensions fail
closed. The pending intent also lists every referenced artifact digest, so cleanup retains possible
committed inputs after process death until recovery finalizes or safely aborts the intent.

Use a permanent request-ID table for exact retry semantics. Return an existing receipt only when
the request ID and the full operation digest match; that digest binds command bytes, immutable
recorded time/live anchor, writer authorization, and control epoch. A fresh per-attempt authority
check time is deliberately outside operation identity and must still prove the same authority is
currently valid. External consumers may run only after
durable root finalization and deduplicate by outbox ID; M2.2 freezes the enqueue/handoff gate but
implements no delivery worker.

Set and verify page size, WAL, FULL synchronous mode, foreign keys, trusted-schema off, defensive
mode, application ID, schema version, bounded busy wait, and a 1 GiB page limit. Prohibit network
filesystems, `ATTACH`, extensions, triggers, caller SQL, and raw main-file-only copies.

Never repair authoritative state in place. Verify/rebuild into a shadow database and require an
operator-controlled replacement after exact root comparison. Backups include the consistent
SQLite destination, external root, and every content-addressed artifact pinned by an event or
rollback reservation. Artifact resolution is streaming and bounded, and a shared retention lease
prevents cleanup between digest verification and transactional pinning. Backup, checkpoint,
migration, artifact cleanup, and GC each use one configured non-resetting,
deployment-benchmarked maintenance deadline over
barrier installation, root reads, SQLite/VFS work, artifact streaming, sync, reopen, verification,
and cleanup. Timeout cancels with no lingering locks/tasks or terminates the supervised storage
process; a separate bounded cleanup phase permits only cancellation, handle/lease/barrier release,
and temporary-output discard or quarantine, never new maintenance or publication. If that cleanup
cannot finish, process death precedes generation-bound barrier release. No partial destination is
publishable.

## Why SQLite 3.53.4

SQLite documents one simultaneous writer, serializable isolation under the selected configuration,
and WAL's local-host/shared-memory requirement. In WAL mode, `synchronous=FULL` syncs each commit;
NORMAL can lose a committed transaction after power loss. SQLite 3.53 fixed the documented
WAL-reset corruption issue, and 3.53.4 is the current maintenance release for the September 2026
baseline. The implementation will pin and report the exact SQLite source ID. A later version
requires an explicit dependency review and complete fixture/fault rerun; `>=` is not an implicit
compatibility claim.

## Consequences

Positive:

- small trusted surface and no service dependency;
- atomic local state transitions and deterministic crash recovery;
- multiple readers with one bounded writer;
- portable fixtures and disposable database files;
- a direct path to fault injection and clean-clone reproduction.

Negative:

- one host and one writer limit scale;
- WAL, shared-memory, and main files must remain together;
- filesystem/fsync correctness remains an environmental assumption;
- v1 lineage facts preserve the original writer but recovery-operator attribution remains
  operational telemetry until a later root-custodian-bound audit log is reviewed;
- permanent receipts/events grow until a later reviewed archival design;
- projection verification and checkpoint management add operational work.

## Alternatives considered

- **PostgreSQL now:** deferred until concurrent multi-node operation is measured; it expands
  deployment and recovery complexity.
- **JSONL only:** retained for the bootstrap demo but insufficient for atomic multi-row CAS,
  idempotency, and outbox state.
- **Kafka/event broker:** rejected; atomicity with a local head would require another coordination
  protocol and operational service.
- **Filesystem rename transactions:** rejected because multiple linked objects, receipts, and
  projections need one consistency boundary.
- **SQLite rollback journal:** valid, but WAL permits concurrent readers and provides a clear local
  deployment profile. FULL synchronous mode and controlled checkpointing preserve the required
  durability target.
- **Trust SQLite locking alone:** rejected because a command can become stale before it obtains the
  writer lock. Exact semantic CAS remains mandatory.
- **Exactly-once outbox delivery:** rejected as an unsafe claim. M2.2 stops at atomic enqueue and
  root-gated handoff; a future worker must use idempotent, at-least-once consumption.

## Security and operational notes

The database is tamper-evident, not tamper-proof against an attacker who can replace the complete
database, pinned artifacts, and operator-retained roots. M2.2 requires independently stored roots
before a writer can open; operational hardening may later place them in signed transparency or
hardware-backed storage. Candidate workers never receive the database directory, writer handle,
artifact resolver, control latch, or external root.

No result type grants authority, no downstream/application effect or telemetry export occurs in
the transaction, and no automatic deployment follows a committed promotion. The external-root
pending-intent CAS is an explicit part of the commit protocol rather than an application effect.
M2.3 supplies the adversarial fault and rollback drill;
production use still requires qualified human security review.

## Rollback

Before release, remove the disabled writer and test databases while preserving schemas and
fixtures. After any durable event exists, do not downgrade or reinterpret it; export verified
events and restore into a new compatible database. There is no in-place downgrade.
