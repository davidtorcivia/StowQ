# StowQ/1 Namespace

Normative. A queue is a prefix. All protocol keys are lowercase,
`/`-delimited, fixed-width hex fields, and self-describing: every protocol
key parses under the grammar in keys.abnf or is a quarantine candidate.
`outputs/` is application space: key shape is chosen by the application, and
the protocol constrains only its write discipline (see records.md, the
commit rule).

```text
<root>/
  meta/
    FORMAT                          Queue identity + configuration (immutable)
    watermark                       Wall floor record (the only CAS'd object)
    clock/<nonce>                   Store-time oracle beacons (ephemeral, GC'd)
  jobs/<shard>/<job-id>             Job record: envelope + inline or referenced payload (immutable)
  payloads/<job-id>/<digest>        Detached payload for large jobs (immutable, optional)
  claims/<shard>/<job-id>/<generation>
                                    Custody chain (immutable, append-only per job)
  fails/<shard>/<job-id>/<generation>
                                    Negative acknowledgment + backoff basis (immutable)
  leases/<exp-bucket>/<shard>/<job-id>.<generation>
                                    Advisory expiry index for bounded sweeping
  delayed/<due-bucket>/<shard>/<job-id>
                                    Advisory due index for delayed delivery
  receipts/<shard>/<job-id>         Terminal success (immutable)
  dead/<shard>/<job-id>             Terminal failure, by reason (immutable)
  termidx/<t-bucket>/<kind>/<shard>/<job-id>
                                    Advisory terminal index for GC order
  quarantine/<t-bucket>/<qid>       Isolated corrupt/ambiguous objects
  outputs/...                       Application output space (see records.md, optional)
```

## Two-plane rule

Objects under `jobs/`, `claims/`, `fails/`, `receipts/`, `dead/` are
**authoritative**. Objects under `leases/`, `delayed/`, and `termidx/` are
**advisory indexes** — hints that make sweeping a bounded LIST rather than a
full scan. An index entry proves nothing; a missing index entry hides
nothing forever (see recovery.md, Repair scan). Correctness never reads an
index; only efficiency does.

## Sharding

`shard = low log2(shard_count) bits of SHA256("StowQ-1-shard\0" || queue_id
|| job_id)`, taken from the first 2 bytes of the hash and formatted as 4 hex
digits. Shard count is a power of two fixed in FORMAT at init.

Keys carry only identity, never mutable state. Keys are stable for the life
of the job. State lives in the immutable record contents, integrity-bound
by digest (see records.md).
