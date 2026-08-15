# StowQ/1 Records and Transitions

Normative. Field names below are normative.

## Framing

All records are canonical deterministic CBOR (RFC 8949 §4.2.1). A record is
a seven-element array

```
[magic, major, minor, queue_id, key_tag, record_type, fields]
```

followed by a trailing 32-byte byte string carrying `record_digest`:

```
record_digest = SHA256("StowQ-1-<type>\0" || canonical-encoding-of-the-array)
key_tag       = first_8_bytes(SHA256("StowQ-1-key\0" || queue_id || key))
```

`magic` is the u64 `0x53544f5751312d00`. `major` is 1 and `minor` is 0.
`queue_id` is a 16-byte string, `key_tag` an 8-byte string (see
namespace.md). `record_type`: 1 format, 2 job, 3 claim, 4 fail, 5 receipt,
6 dead, 7 watermark. `fields` is a map with text keys; absent optional
fields are omitted entirely. Unknown fields are rejected in v1;
`required_feature_bits` gates evolution.

`key_tag` is verified on every read, so a record copied to the wrong key or
wrong queue is detected.

Record types: `format`, `job`, `claim`, `fail`, `receipt`, `dead`,
`watermark`.

## Test vectors

Vectors pin the canonical encoding. All use queue_id
`000102030405060708090a0b0c0d0e0f` and key_tag `0707070707070707`.

Job: job_id `101112131415161718191a1b1c1d1e1f`, maximum_attempts 3,
content_type `text/plain`, payload `hello stowq` inline (payload_digest
`896084e74043a1d22eb32d0eb9a63bce64c3792426a2ddd4b97509c68ff5cd38`).

```text
871b53544f5751312d00010050000102030405060708090a0b0c0d0e0f480707070707
07070702a7666a6f625f696450101112131415161718191a1b1c1d1e1f6c636f6e74656e
745f747970656a746578742f706c61696e6e7061796c6f61645f64696765737458208960
84e74043a1d22eb32d0eb9a63bce64c3792426a2ddd4b97509c68ff5cd386e7061796c6f
61645f696e6c696e654b68656c6c6f2073746f77716e7061796c6f61645f6c656e677468
0b706d6178696d756d5f617474656d7074730375637265617465645f73746f72655f7469
6d655f6e730058208b73824ef400fd84f63d7d43f1c443c32089b122731bd49308ac2737
d6015df9
```

record_digest
`8b73824ef400fd84f63d7d43f1c443c32089b122731bd49308ac2737d6015df9`.

Claim (takeover, generation 1): job_id as above, attempt 1, worker_id
`w1`, worker_token `42` × 16, lease_duration 60000000000 ns, all-zero
basis.

```text
871b53544f5751312d00010050000102030405060708090a0b0c0d0e0f480707070707
07070703a8656261736973a370707265765f6475726174696f6e5f6e730072707265765f
73746f72655f74696d655f6e7300756f627365727665645f77617465726d61726b5f6e73
00666a6f625f696450101112131415161718191a1b1c1d1e1f67617474656d7074016977
6f726b65725f69646277316a67656e65726174696f6e016c636f6e74696e756174696f6e
f46c776f726b65725f746f6b656e5042424242424242424242424242424242716c656173
655f6475726174696f6e5f6e731b0000000df84758005820c9f5f3ee7144d8fa17ba9349
8f04c4548667aa9c895864fc85274ad08aeec1ca
```

record_digest
`c9f5f3ee7144d8fa17ba93498f04c4548667aa9c895864fc85274ad08aeec1ca`.

## FORMAT record

Written once at init, immutable. Fields: `queue_id`, `shard_count`, bucket
widths (lease, delay, terminal), digest algorithm (SHA-256 in v1),
`required_feature_bits`.

## Job record and enqueue

The job record contains: `job_id`, `maximum_attempts`, `content_type`,
`created_store_time` (filled by read-back, informative), `not_before`
(optional, wall bucket), `payload_digest`, `payload_length`, and either
`payload_inline` (within the configured inline limit) or a `payload_key`
reference.

Order of operations for detached payloads: PUT `payloads/<job-id>/<digest>`
first (put-if-absent; content-addressed, so contention is benign), then PUT
`jobs/<shard>/<job-id>` (put-if-absent — the enqueue linearization point),
then, if `not_before` is set, PUT the `delayed/` index. A crash between
payload and record leaves an orphan payload (GC'd, see recovery.md); between
record and index leaves a delayed job discoverable only by repair scan. Both
are safe.

Idempotent enqueue: a producer that supplies a deterministic `job_id` and
retries after outcome-unknown either wins the put-if-absent or finds its own
record already present. Random `job_id` + outcome-unknown + blind retry can
duplicate a job; this is the documented at-least-once edge.

## Claim (lease acquisition)

To claim a job, a worker:

1. Reads the job record; verifies `key_tag`, `record_digest`, and — if
   delivery will stream the payload — arranges digest verification on read.
2. Establishes the claim tail: LIST `claims/<shard>/<job-id>/` (strongly
   consistent, lexicographic, so the last key is the highest generation).
   Absent chain means tail generation 0.
3. Evaluates readiness: no receipt/dead record exists for the job; the tail
   claim (if any) is expired per store time (see time.md); any
   `fails/<shard>/<job-id>/<tail>` backoff `not_before` has passed; the
   job's `not_before` has passed; attempts remain.
4. PUTs `claims/<shard>/<job-id>/<tail+1>` with put-if-absent — the claim
   linearization point. Exactly one contender per generation wins; losers
   observe precondition-failed, meaning not committed: refresh tail and
   retry or move on.
5. Best-effort PUTs the `leases/<exp-bucket>/...` index (advisory).

The claim record contains: `job_id`, `generation`, `attempt`, `worker_id`,
`worker_token` (random 16 bytes — the writer token used for outcome-unknown
resolution), `lease_duration_ns`, `continuation` (bool), and exactly one of:
`basis` (takeovers only) or `prev_token` (continuations only).

Claim expiry is defined as `claim_store_time + lease_duration_ns`, where
`claim_store_time` is the store-assigned creation time of the claim object
itself, read back via the profile's declared timestamp surface. The worker's
local clock never defines expiry.

## Admissibility

Admissibility is defined per claim type. A claim at generation *g* > 1 is
either a takeover (`continuation = false`) or a continuation
(`continuation = true`); the two carry different evidence.

A **takeover** is admissible iff its `basis` correctly evidences that
generation *g−1* was expired (or negatively acknowledged) at the time of the
takeover: `basis = { prev_store_time, prev_duration_ns, observed_watermark }`
with `prev_store_time + prev_duration_ns ≤ observed_watermark`, where
`observed_watermark` is a wall floor the claimant had established (see
time.md) before writing.

A **continuation** is admissible iff its `worker_id` matches generation
*g−1* and its `prev_token` equals generation *g−1*'s `worker_token`. It
carries no expiry basis; a continuation written over a different worker's
claim is inadmissible.

Put-if-absent guarantees uniqueness per generation but cannot itself stop a
misbehaving-but-trusted worker from claiming over a live lease. Admissibility
makes that act detectable and attributable: auditors and sweepers verify the
type-appropriate evidence against the store-time record and quarantine-flag
inadmissible claims (reason `0x0010`). Commit-time fencing (Acknowledgment)
ensures an inadmissible claim still cannot destroy anything.

## Renewal, retry, bury

**Renew** — the current holder PUTs `claims/<shard>/<job-id>/<g+1>` with
`continuation = true`, same `worker_id`, and a `prev_token` equal to its
generation-*g* `worker_token` (proof of custody continuity). Continuation
claims do not increment `attempt`. Renewal shares the linearization point
with takeover, so a sweeper-prompted takeover racing a renewal is decided by
the store, and the loser learns immediately. Generations remain the single
monotonic fencing sequence. A renewal that loses its race is lease-lost: the
worker stops acting on the claim. A continuation that wins after its own
generation's expiry is admissible — the custody proof holds — but the worker
MUST re-establish a floor before further wall-sensitive actions; auditors do
not flag it.

**Retry (nack)** — the holder PUTs `fails/<shard>/<job-id>/<g>`
(put-if-absent) recording `reason`, `attempt`, and
`retry_not_before = now_floor + backoff(attempt)` with full jitter. It then
best-effort writes the corresponding `delayed/` index. The next takeover
claim's readiness check honors `retry_not_before`.

**Bury** — the holder PUTs `dead/<shard>/<job-id>` (put-if-absent) with a
reason from the dead registry (see reasons.md). Terminal; same first-wins
and idempotent-verify semantics as receipts.

`maximum_attempts` bounds committed non-continuation claims. A takeover at
`attempt == maximum_attempts` is not written; the actor instead writes
`dead` with reason `attempts_exhausted (0x0004)`.

## Delivery and payload integrity

Delivery = a committed admissible claim + a verified payload. Verification
is SHA-256 against `payload_digest`, either via the store's checksum
machinery (P7) or explicit hash-on-read. Digest mismatch means quarantine
(`payload_corrupt`, `0x0002`), never delivery. Implementations SHOULD offer
a verified positional reader over ranged GETs, using a chunked digest tree so
random access does not force whole-object hashing.

## Acknowledgment and the commit rule

Acknowledgment PUTs `receipts/<shard>/<job-id>` with put-if-absent — the
terminal linearization point. The receipt records `generation`, `attempt`,
`worker_id`, `worker_token`, `payload_digest` (re-verified), and
`output_digests` (if any). First receipt wins; a later acknowledgment
(including a zombie's, or a retry after outcome-unknown) verifies the
existing receipt's evidence and returns success without writing. The ack
(and bury) then best-effort writes its `termidx/` entry; that index drives
GC ordering only.

**Commit rule for store-resident effects** (normative when used): a job's
output objects MUST be written put-if-absent at deterministic keys derived
from `job_id` (not from attempt or generation), and MUST be written *before*
the receipt. Then: duplicate attempts cannot clobber outputs (first output
wins, byte-identical by determinism or detected by digest mismatch ⇒
quarantine `0x0011`); a receipt implies its recorded outputs exist and are
final; and a zombie past its lease can at worst commit *the* correct
first-wins result, never a conflicting one.
