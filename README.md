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
machine, TLA+ models of the claim and terminal paths, fuzzing, and a
live-store conformance suite (Cloudflare R2 and MinIO certified; see
`spec/store-profiles.md`).

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

## Conformance

The conformance suite in `stowq-store-s3` runs the primitive
certification and the full queue lifecycle against any endpoint:

```sh
STOWQ_CONFORMANCE_ENDPOINT=http://localhost:9000 \
  AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_REGION=... \
  cargo test -p stowq-store-s3 --features conformance
```

A store enters `spec/store-profiles.md` after a passing run.

## License

Apache-2.0.
