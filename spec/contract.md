# StowQ/1 Contract

StowQ/1 is a brokerless durable-work protocol for object storage. Jobs are
immutable objects whose keys encode identity. Ownership is a chain of
immutable claim objects. State transitions are atomic conditional creations:
never renames, never overwrites. The store is the only authority: for
linearization, for durability, and for time.

Status: draft-1. This document is normative for StowQ/1 implementations.
Sections marked *informative* are not.

## Assumptions

All queue state for one queue resides under one key prefix in one bucket of
one certified object store (see store-profiles.md). Producers, consumers,
sweepers, and administrators with write access to that prefix belong to one
trusted security domain. StowQ/1 does not provide hostile multi-tenant
isolation within a prefix; isolation is the store's access-control problem.

The store satisfies the primitive contract in store-profiles.md. In
particular: atomic put-if-absent, atomic compare-and-swap on overwrite,
strong read-after-write consistency, and strongly consistent listing. Stores
that cannot be certified cannot host a StowQ/1 queue.

At least one producer, consumer, or sweeper eventually performs fair bounded
recovery work (the liveness assumption).

Participants' local wall clocks are untrusted. All wall-time decisions derive
from store-assigned object timestamps (see time.md). Participants' local
monotonic clocks are trusted only for their own in-process deadlines, never
for protocol-visible decisions.

Consumers do not begin processing until `claim()` has returned a committed
claim.

## Guarantees

Supports multiple concurrent producers and consumers across any number of
machines, with at-least-once job execution. A partially written job is never
returned by `claim()`: a job is visible only after its record object exists
in full, and payload integrity is verified by digest before delivery and
again before acknowledgment.

A successful enqueue remains represented by exactly one recoverable or
terminal object graph after any interruption of any participant. Enqueue
durability is the store's PUT durability; StowQ/1 adds no weaker deferred
mode in v1.

At most one *admissible* claim (see records.md, Admissibility) is current for
a job at any store-time instant. Claim generations are strictly monotonic
per job and serve as fencing tokens. A stale generation cannot acknowledge,
renew, retry, or bury over a later generation: every terminal or
custody-affecting write is conditional, and the store — not the worker —
decides the winner.

A successful acknowledgment re-verifies payload evidence and creates a
terminal receipt via put-if-absent. Repeated acknowledgment is
non-destructive and idempotent: if a receipt already exists, acknowledgment
succeeds only if the existing receipt passes the same identity,
generation-evidence, and payload-evidence checks used by recovery and audit
tooling. StowQ/1 exposes no unverified acknowledgment operation.

An unacknowledged committed claim eventually becomes ready or dead, subject
to the liveness assumption. `maximum_attempts` bounds the number of
committed takeover claims, not internal store-operation retries and not
external side effects.

Corrupt, malformed, or structurally ambiguous objects are never delivered.
They are quarantined by reason code (see reasons.md) and excluded from
normal delivery and sweeping.

Recovery and sweeping may be interrupted after any single store operation and
safely rerun by any participant without data loss and without unbounded work
(see recovery.md).

No transition overwrites a distinct active object. The only overwrite in the
entire protocol is the watermark CAS (see time.md), and the only deletes are
retention GC of verified-terminal graphs and consumed advisory index entries
(see recovery.md).

*Informative*: when the job's output is itself an object written under this
protocol's commit rule (see records.md, Acknowledgment), StowQ/1 provides
at-most-once *commit* of that output — exactly-once effect for store-resident
effects — with no coordinator.

## Non-Goals

No exactly-once external side effects outside the store. No transactions
spanning jobs, no atomic batches, no strict FIFO, no priorities, selectors,
or routing expressions. No queue-wide exact counters or mutable indexes. No
transparent online format migration. No transparent deduplication after an
indeterminate enqueue: producers wanting idempotent enqueue must supply a
deterministic `job_id` (see records.md, Enqueue). No authoritative event
history beyond what the immutable object graph itself constitutes.

StowQ/1 is not a message bus and does not carry notifications. A
notification plane may be layered on as a lossy, duplicative, unordered
*doorbell*; no StowQ/1 correctness property may depend on it.

## Terms

**Linearization point** — the store's atomic acceptance of a conditional
write: a put-if-absent that returns success, or a CAS that matches. Exactly
one contender wins; the store is the arbiter.

**Committed** — the linearization point completed and the store acknowledged
the write. Object-store PUTs are atomic and internally durable on
acknowledgment. The commit point and the durability point coincide.

**Not committed** — the implementation can prove the linearization point did
not occur: a precondition-failed response (HTTP 412 or store equivalent), or
a failure provably raised before the request was transmitted.

**Outcome unknown** — the request may have been accepted but its result could
not be established: timeout, connection loss after transmit, ambiguous 5xx.
Outcome-unknown is always *finitely resolvable*: read the target key. Absent
means not committed (safe to retry the conditional write). Present means a
record occupies the key, and because every StowQ object is immutable and
self-verifying, ownership resolves by content: records carrying a
`worker_token` (claims, receipts) compare tokens — match means you
committed, mismatch means another writer committed and you did not; every
other record resolves by re-encoding the record you attempted and comparing
`record_digest` — match means you committed, mismatch means another writer's
record holds the key and you did not. Resolution requires only strong
read-after-write consistency.

**Claim** — an immutable object asserting custody of a job for a bounded
lease, at a specific generation.

**Admissible claim** — a claim whose recorded evidence is consistent with the
store-time record (see records.md, Admissibility). Inadmissible claims are
audit findings, never delivery inputs.

**Terminal** — receipt, dead, or quarantine. Normal recovery does not
reactivate terminal state.

**Store time** — the timestamp the store assigns to an object at creation,
read through the profile's declared timestamp surface (see
store-profiles.md). The sole wall-time authority in the protocol.
