# StowQ/1 Store Primitive Contract

Normative. A conforming store MUST provide:

| # | Primitive | Requirement |
| --- | ----------- | ------------- |
| P1 | Put-if-absent | Atomic create; fails with a distinguishable precondition error if the key exists. |
| P2 | Compare-and-swap | Atomic overwrite conditional on the current version/ETag. Required only for the watermark object. |
| P3 | Strong read-after-write | A committed PUT is visible to all subsequent GET/HEAD, from any client. |
| P4 | Strongly consistent LIST | A committed PUT is visible to all subsequent LISTs of its prefix. Lexicographic order. |
| P5 | Atomic whole-object PUT | No torn or partial objects are ever observable. |
| P6 | Server-assigned creation time | Monotone non-decreasing per the store's internal clock discipline; readable on the declared surface. |
| P7 | Content digest | The store verifies a client-supplied SHA-256 on PUT, or the implementation verifies on read-back. |
| P8 | Conditional GET | `If-Match`/`If-None-Match` on reads (used for cheap claim-tail revalidation). Optional; absence costs efficiency, not correctness. |

A conforming profile additionally declares, normatively:

1. **Granularity `G`** — the coarsest timestamp quantum the profile
   certifies. Internal arithmetic stays in ns; profile constraints make
   sub-`G` distinctions unreachable.
2. **Declared timestamp surface** — the single read surface (LIST preferred)
   from which store time is taken. Timestamps obtained from any other
   surface MUST be quantized down to `G` before use, so mixed-surface reads
   cannot move an object across a bucket or expiry boundary.

## Certification profiles

Informative. The gate for adding a store to this table is a passing
conformance run against a named endpoint and version.

| Store | P1 | P2 | P3/P4 | P6 | G | Surface | Notes |
| ------- | ---- | ---- | ------- | ---- | --- | --------- | ------- |
| Cloudflare R2 | `If-None-Match: *` | `If-Match: <etag>` | strong | yes | 1 ms (LIST) / 1 s (HEAD) | LIST | Primary target. |
| Amazon S3 | `If-None-Match: *` (2024-08) | `If-Match` on PUT (2024-11) | strong (2020+) | yes | 1 s | LIST or HEAD | |
| Google GCS | `x-goog-if-generation-match: 0` | generation-match | strong | yes | 1 ms | `updated` | Generations are native fencing. |
| Azure Blob | `If-None-Match: *` | `If-Match` | strong | yes | 1 s | LIST or HEAD | |
| MinIO | `If-None-Match: *` | `If-Match` | strong | yes | 1 s | LIST or HEAD | Certified at RELEASE.2025-09-07T16-13-09Z by the conformance suite. |
| Ceph RGW | version-dependent | version-dependent | version-dependent | yes | per deployment | per deployment | Must be certified per deployment. |

P6 is the load-bearing assumption most likely to be subtle in practice.
StowQ/1 does not require store clocks to be *accurate*, only that the
per-store timestamp order is usable as a wall floor (see time.md).
Multi-region buckets with non-monotone timestamp behavior are outside
profile until certified.

On R2, additional checksums are composite-only (`FULL_OBJECT` is CRC64NVME),
so P7 is satisfied by verification on read-back; `x-amz-checksum-sha256` is
a best-effort adjunct, not a correctness dependency.
