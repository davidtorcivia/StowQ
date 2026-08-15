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

Experimental. The protocol specification is frozen at draft-1; implementation has not started. Do not use it for workloads where job loss would cause harm.

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

## License

Apache-2.0.
