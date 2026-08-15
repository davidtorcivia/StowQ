# Fuzzing

Requires nightly and cargo-fuzz:

```sh
rustup toolchain install nightly
cargo install cargo-fuzz
```

Run a target (60 seconds here):

```sh
cd fuzz
cargo +nightly fuzz run fuzz_cbor_decode -- -max_total_time=60
```

Targets:

- `fuzz_key_parse` — any accepted key round-trips through format and re-parse
- `fuzz_cbor_decode` — canonicality: anything decode accepts, encode reproduces byte-for-byte
- `fuzz_record_roundtrip` — any accepted record re-encodes to exactly the input bytes
- `fuzz_record_construction` — arbitrary records built through the public constructors must encode/decode as inverses
- `fuzz_bucket_arithmetic` — bucket, ceiling, eligibility, floor, and deadline bounds

Corpora hold hand-written seeds plus regression inputs; coverage regrows in
seconds. Artifacts, coverage, and build output are gitignored.

## Long runs

AddressSanitizer accumulates allocator fragmentation over long single-process
runs and eventually trips the RSS limit even though the live heap is flat.
Cap the quarantine and run in fresh-process slices:

```sh
export ASAN_OPTIONS=quarantine_size_mb=64:thread_local_quarantine_size_kb=1024
for i in $(seq 6); do
  cargo +nightly fuzz run fuzz_cbor_decode -- -max_total_time=50 -rss_limit_mb=2560
done
```
