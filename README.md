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

Reference figures (single worker, Cloudflare R2, well-hinted shard): a
delivery costs 14 store operations; roughly 13 KB of gross allocations per
enqueue-claim-acknowledge cycle; batched claiming sustains 2.4 jobs/s per
worker single-shard, and worker throughput scales near-linearly.

## License

Apache-2.0.
