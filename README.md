# StowQ

A brokerless durable-work protocol for object storage. Jobs are immutable
objects whose keys encode identity. Ownership is a chain of immutable claim
objects. State transitions are atomic conditional creations; the only
overwrite in the protocol is a single watermarked clock record.

A queue is a key prefix in one bucket of one certified object store
(Cloudflare R2, Amazon S3, Google GCS, Azure Blob). No daemon, no leader,
no database, no broker. Producers, consumers, and sweepers interact through
conditional writes, and the store is the sole arbiter for linearization,
durability, and time.

At-least-once job execution with takeovers, retries with backoff, burial,
delayed delivery, and garbage collection of terminal jobs. All state is
derived from the immutable object graph; advisory indexes exist only to
bound sweep work and are never trusted for correctness.

## Status

Experimental. Do not use it for workloads where job loss would cause harm.

The protocol and its Rust implementation are complete and continuously
verified: unit and fault-injection suites, an equivalence-checked state
machine, TLA+ models of the claim and terminal paths, fuzzing, a
live-store conformance suite (Cloudflare R2 and MinIO certified; see
`spec/store-profiles.md`), and a soak harness that runs sustained
deliveries under injected transport faults and asserts exact accounting.

## Specification

The normative specification lives in `spec/`:

- `contract.md` — assumptions, guarantees, terms
- `store-profiles.md` — store primitive certification
- `namespace.md` — prefix layout and sharding
- `keys.abnf` — key grammar
- `records.md` — record schemas and transitions
- `time.md` — store time, floors, watermark
- `recovery.md` — sweeping, repair, GC
- `reasons.md` — reason registries

Optional protocol features are gated by FORMAT feature bits: bit 1 (quarantine
records on v1.1 queues), bit 2 (claim-chain tail hints). A client refuses
queues whose FORMAT demands bits it does not know.

## Workspace

- `stowq-keys` — key grammar, sharding, key tags
- `stowq-math` — bucket arithmetic, retry backoff
- `stowq-format` — canonical CBOR records with digest framing
- `stowq-store` — `ObjectStore` trait, error taxonomy, memory fake,
  fault injector
- `stowq-store-s3` — S3-compatible backend (R2, S3, MinIO) and the
  conformance suite
- `stowq-core` — the queue state machine
- `stowq-testkit` — logical oracle, differential driver, interleaving lab
- `stowq-worker` — consumer harness: doorbell hints, batched claiming
  with concurrent probing, renewal heartbeats, delivery metrics
- `stowq-demo` — end-to-end pipeline over a live store with worker-kill
  injection
- `stowq-bench` — protocol operation counts, allocation and latency
  measurement, live throughput, soak testing
- `stowq-cli` — the `stowq` binary

TLA+ models live in `model/`; fuzz targets in `fuzz/`.

## Quick Start

```sh
cargo build --release

./target/release/stowq init myqueue
echo "hello world" | ./target/release/stowq put myqueue - --content-type text/plain
./target/release/stowq claim myqueue > handle.json
./target/release/stowq ack myqueue "$(cat handle.json)"
./target/release/stowq inspect myqueue <job_id>
```

The CLI's default store is memory-backed per invocation with a local
snapshot; the S3-compatible backend (used by the conformance suite)
attaches through `stowq-store-s3`.

## Consumers

The consumer harness in `stowq-worker` turns a lossy doorbell hint into a
delivery: claim, verify the payload digest, execute with renewal heartbeats
at one-third lease intervals, commit outputs through the commit rule, then
acknowledge. Failures nack with backoff or bury. A lease lost mid-execution
stops all further action — the takeover owner decides the job.

Batched claiming (`Queue::claim_many`) claims up to N jobs from one shard
scan with concurrent candidate probing, and the harness delivers the batch
concurrently. Delivery metrics (counters plus a latency histogram) are
optional and cost nothing when off.

## Conformance

The conformance suite in `stowq-store-s3` runs the primitive certification
and the full queue lifecycle against any endpoint:

```sh
STOWQ_CONFORMANCE_ENDPOINT=http://localhost:9000 \
  AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_REGION=... \
  cargo test -p stowq-store-s3 --features conformance
```

A store enters `spec/store-profiles.md` after a passing run.

## Measurement

`stowq-bench` measures protocol cost:

- `ops` — store-operation counts per protocol operation
- `mem` — cycle latency and allocations against the memory store
- `live` / `live-batch` — per-delivery latency and throughput against a
  live store
- `soak` — sustained operation under injected transport faults with
  terminal-state and accounting assertions

Reference figures (single worker, batch of 5, well-hinted shard):

| Store | Round trip | Cycle | Per worker | Ops per job |
| --- | --- | --- | --- | --- |
| In-process memory | — | ~0.2 ms | 5,000+/s | 0 |
| MinIO, same host | <1 ms | ~70 ms | 72/s | 14.2 |
| Cloudflare R2 over WAN | ~65 ms | ~2.8 s | 1.8-2.4/s | 14.2 |
| Cloudflare R2, Worker at the edge | ~1-5 ms (est.) | — | ~30-50/s (est.) | 14.2 |

Per-delivery cost is dominated by store round trips, not protocol
work: the same 14 operations run 30-40x faster from a host adjacent
to the store. Worker throughput scales near-linearly (8 measured
workers, 8.6 jobs/s aggregate on R2 over WAN); batch size 10 captures
most of the batching gain (2.3/s remote, 82/s local).

Allocation cost is independent of placement: roughly 13 KB gross per
enqueue-claim-acknowledge cycle across all setups.

## License

Apache-2.0.
