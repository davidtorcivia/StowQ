# StowQ/1 Sweeping, Recovery, and GC

Normative.

## Expired-lease sweep (bounded)

LIST `leases/<b>/` for every expiry bucket `b ≤ current floor bucket` not yet
marked swept, in ascending order. For each index entry: read the
authoritative claim tail; if genuinely expired and non-terminal, either
notify (doorbell) or perform the takeover claim directly; then delete the
index entry. Work per sweep is bounded by index entries in due buckets.
Sweeps are idempotent and safely concurrent: all mutations are conditional,
so two sweepers merely race to the same linearization points. No sweep lock
is required; an optional CAS'd cursor object under `meta/` de-duplicates
effort without protecting correctness.

## Delayed sweep (bounded)

Identically over `delayed/<b>/` for due buckets: verify the job's
authoritative `not_before` / `retry_not_before`, doorbell or claim, delete
the index entry.

## Repair scan (rare, resumable)

Advisory indexes are best-effort (their PUT follows the authoritative PUT
non-atomically), so a low-frequency repair scan LISTs `claims/` and `jobs/`
shard-by-shard with a persisted CAS'd cursor, regenerating missing index
entries (including `termidx/`) and quarantine-flagging grammar violations,
key-tag failures, digest failures, inadmissible claims, and impossible
states. Resumable after any single operation; bounded per invocation by
page count.

## Retention and GC

Terminal graphs are deleted after a configured retention. GC iterates
`termidx/` oldest-bucket-first, verifying each entry against its
authoritative terminal key before acting, in this strict order per job:
advisory indexes → `fails/` → `claims/` → `payloads/` → `jobs/` → the
terminal record (`receipts/` or `dead/`) **last**. The terminal record is
the tombstone; deleting it last makes interrupted GC re-runnable and makes
resurrection impossible (a job record without a terminal record is only
claimable if its claim chain also says so, and the chain outlives the
payload). Orphan payloads are deleted when older than the enqueue-orphan
horizon with no referencing job record. Clock beacons (`meta/clock/`) are
deleted when older than a configured multiple of the floor staleness window;
`FORMAT` and `watermark` are never deleted. Quarantine is never GC'd
automatically.

## Errata (draft-1 implementations)

- Sweeps MAY adopt the evaluate-and-prune posture: re-evaluate each due
  index entry against the authoritative record, prune the consumed
  entry, and leave the job to be found by the ordinary shard scan,
  without performing the takeover claim or sending a doorbell. This is
  a permitted reading of the sweep's obligation: liveness rests on the
  claim path's authoritative scan under the two-plane rule. The
  takeover-or-doorbell wording above describes the timely variant, not
  the only conforming one.
- Orphan-payload collection past the enqueue horizon is implemented
  by the reference implementation (gc takes the horizon; a payload
  whose job record is absent and whose store time predates
  `now - horizon` is deleted). This erratum is resolved.
- Terminal mutual exclusion has a check-then-act window: ack and bury
  write different keys, both put-if-absent, so no store primitive can
  arbitrate between them. The pre-write terminal checks in each path
  minimize the window but cannot close it; a receipt-and-dead pair
  produced by the window is a `duplicate_state_conflict` quarantine
  finding owned by the repair scan.
