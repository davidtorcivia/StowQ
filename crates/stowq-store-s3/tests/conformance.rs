//! Live-store conformance: the queue lifecycle against a real endpoint.
//! Skipped unless STOWQ_CONFORMANCE_ENDPOINT is set; configuration:
//!
//! - `STOWQ_CONFORMANCE_ENDPOINT` — required to run (e.g.
//!   `http://localhost:9000`)
//! - `STOWQ_CONFORMANCE_BUCKET`   — default `stowq-conformance`
//! - `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION` — the
//!   SDK's standard chain
//!
//! The suite is the gate for adding a store to spec/store-profiles.md:
//! a passing run certifies the primitive semantics named there.

#![cfg(feature = "conformance")]

use bytes::Bytes;
use sha2::{Digest as _, Sha256};
use stowq_core::{
    AckOutcome, ClaimOptions, ClaimOutcome, EnqueueInput, EnqueueOutcome, OpBudget, OpenOptions,
    Queue,
};
use stowq_format::FormatRecord;
use stowq_store::{Key, ObjectStore, PutOutcome, StoreError};
use stowq_store_s3::{S3Config, S3Store};

fn endpoint() -> Option<String> {
    std::env::var("STOWQ_CONFORMANCE_ENDPOINT").ok()
}

/// Unique run suffix: the conformance suite must be idempotent across
/// runs against the same bucket.
fn run_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    format!("{}-{}", std::process::id(), n)
}

fn store() -> S3Store {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let sdk = rt.block_on(aws_config::load_defaults(
        aws_config::BehaviorVersion::latest(),
    ));
    let config = S3Config {
        region: std::env::var("AWS_REGION").unwrap_or_else(|_| "auto".into()),
        endpoint: endpoint(),
        force_path_style: true,
    };
    let bucket =
        std::env::var("STOWQ_CONFORMANCE_BUCKET").unwrap_or_else(|_| "stowq-conformance".into());
    S3Store::new(&sdk, &config, bucket)
}

fn digest(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

fn format() -> FormatRecord {
    FormatRecord {
        shard_count: 4,
        lease_bucket_width_ns: 1_000_000_000,
        delayed_bucket_width_ns: 1_000_000_000,
        terminal_bucket_width_ns: 1_000_000_000,
        inline_limit: 4_096,
        required_feature_bits: 0,
    }
}

/// P1/P2/P5/P6/P7 certification at the primitive level.
#[test]
fn primitives_certification() {
    let Some(_) = endpoint() else { return };
    let s = store();
    let run = run_id();
    let k = Key::new(format!("conformance/prim/{run}/p1"));

    // P1: put-if-absent is atomic; second write rejects.
    let a = s
        .put_if_absent(&k, Bytes::from_static(b"a"), digest(b"a"))
        .unwrap();
    let b = s
        .put_if_absent(&k, Bytes::from_static(b"b"), digest(b"b"))
        .unwrap();
    assert!(matches!(a, PutOutcome::Committed { .. }));
    assert_eq!(b, PutOutcome::Rejected);
    assert_eq!(&s.get(&k, None).unwrap().body[..], b"a");

    // P1 integrity: digest mismatch refuses without writing.
    let k2 = Key::new(format!("conformance/prim/{run}/p1-mismatch"));
    let err = s
        .put_if_absent(&k2, Bytes::from_static(b"x"), digest(b"y"))
        .unwrap_err();
    assert!(matches!(err, StoreError::IntegrityViolation(_)));
    assert_eq!(s.head(&k2).unwrap_err(), StoreError::NotFound);

    // P2: CAS against the current version commits; stale rejects.
    let PutOutcome::Committed { version } = s
        .put_if_absent(&k2, Bytes::from_static(b"v1"), digest(b"v1"))
        .unwrap()
    else {
        panic!()
    };
    let stale = stowq_store::Version("deadbeef".into());
    assert_eq!(
        s.cas(&k2, Bytes::from_static(b"x"), digest(b"x"), &stale)
            .unwrap(),
        PutOutcome::Rejected
    );
    assert!(matches!(
        s.cas(&k2, Bytes::from_static(b"v2"), digest(b"v2"), &version)
            .unwrap(),
        PutOutcome::Committed { .. }
    ));
    assert_eq!(&s.get(&k2, None).unwrap().body[..], b"v2");

    // P3/P6: read-after-write with a nonzero store time.
    let meta = s.head(&k).unwrap();
    assert!(meta.store_time_ns > 0, "P6: server-assigned time");
    assert_eq!(meta.size, 1);

    // P4: listing sees the write; after-marker is exclusive.
    let page = s
        .list(&format!("conformance/prim/{run}/"), None, 10)
        .unwrap();
    assert!(page.items.iter().any(|l| l.key.as_str().ends_with("p1")));
    let after = Key::new(format!("conformance/prim/{run}/p1"));
    let next = s
        .list(&format!("conformance/prim/{run}/"), Some(&after), 10)
        .unwrap();
    assert!(next
        .items
        .iter()
        .all(|l| l.key.as_str() > format!("conformance/prim/{run}/p1").as_str()));

    // Range contract (trait get): half-open [start, end), strictly
    // start < end <= size, identically on every backend. meta.size is
    // the full object size even on a ranged read (the part length is
    // not the object size; 1..2 has part length 1, object size 2).
    let obj = s.get(&k2, Some(1..2)).unwrap();
    assert_eq!(&obj.body[..], b"2");
    assert_eq!(obj.meta.size, 2);
    // Boundary end == size returns the tail through EOF.
    let tail = s.get(&k2, Some(0..2)).unwrap();
    assert_eq!(&tail.body[..], b"v2");
    // Past-EOF end: the store clamps to a 206 partial; the backend
    // reports absence rather than a short slice.
    assert_eq!(s.get(&k2, Some(0..3)).unwrap_err(), StoreError::NotFound);
    // Start past EOF is an unsatisfiable range (416).
    assert_eq!(s.get(&k2, Some(5..6)).unwrap_err(), StoreError::NotFound);
    // Empty and inverted ranges are absence, rejected before the wire.
    assert_eq!(s.get(&k2, Some(1..1)).unwrap_err(), StoreError::NotFound);
    assert_eq!(s.get(&k2, Some(1..0)).unwrap_err(), StoreError::NotFound);
    // Zero-limit listing is an empty terminal page on every backend.
    let zero = s
        .list(&format!("conformance/prim/{run}/"), None, 0)
        .unwrap();
    assert!(zero.items.is_empty());
    assert_eq!(zero.next_after, None);
}

/// The full queue lifecycle over the endpoint.
#[test]
fn lifecycle_certification() {
    let Some(_) = endpoint() else { return };
    let s = store();
    // Unique root per run to avoid cross-run interference.
    let root = format!("cq-{}", std::process::id());

    let q = Queue::init(
        Box::new(store()),
        &root,
        &OpenOptions::new([1; 16]),
        &format(),
    )
    .unwrap();

    let mut b = OpBudget::new(256);
    let out = q
        .enqueue(
            EnqueueInput {
                job_id: None,
                payload: b"conformance",
                content_type: "text/plain".into(),
                maximum_attempts: 2,
                not_before_ns: None,
            },
            &mut b,
        )
        .unwrap();
    let EnqueueOutcome::Committed { job_id } = out else {
        panic!()
    };

    // Claim across the shard space.
    let floor = q.establish_floor(&mut OpBudget::new(16)).unwrap();
    let mut claimed = None;
    for shard in 0..4 {
        let opts = ClaimOptions {
            shard,
            floor_ns: floor,
            lease_duration_ns: 60_000_000_000,
        };
        if let ClaimOutcome::Claimed(c) = q.claim(&opts, &mut OpBudget::new(512)).unwrap() {
            claimed = Some(c);
            break;
        }
    }
    let claim = claimed.expect("job claimable");
    assert_eq!(claim.job_id, job_id);
    assert_eq!(&claim.payload(q.store()).unwrap()[..], b"conformance");

    let ack = q.ack(&claim, &mut b).unwrap();
    assert_eq!(ack, AckOutcome::Acked);
    let reack = q.ack(&claim, &mut b).unwrap();
    assert_eq!(reack, AckOutcome::AlreadyAcked);
}

/// Idempotent enqueue and takeover-after-expiry over the endpoint.
#[test]
fn idempotence_and_takeover_certification() {
    let Some(_) = endpoint() else { return };
    let root = format!("cq-idem-{}", std::process::id());
    let q = Queue::init(
        Box::new(store()),
        &root,
        &OpenOptions::new([1; 16]),
        &format(),
    )
    .unwrap();

    let mut b = OpBudget::new(256);
    let jid = [7; 16];
    for _ in 0..2 {
        let out = q
            .enqueue(
                EnqueueInput {
                    job_id: Some(jid),
                    payload: b"x",
                    content_type: "text/plain".into(),
                    maximum_attempts: 3,
                    not_before_ns: None,
                },
                &mut b,
            )
            .unwrap();
        assert!(matches!(out, EnqueueOutcome::Committed { .. }));
    }

    // Claim with a lease within the second-quantized store clock, then
    // take over after expiry.
    let floor = q.establish_floor(&mut OpBudget::new(16)).unwrap();
    let mut claimed = None;
    for shard in 0..4 {
        let opts = ClaimOptions {
            shard,
            floor_ns: floor,
            lease_duration_ns: 1_000_000_000,
        };
        if let ClaimOutcome::Claimed(c) = q.claim(&opts, &mut OpBudget::new(512)).unwrap() {
            claimed = Some(c);
            break;
        }
    }
    let first = claimed.expect("claim");
    // Store times are second-quantized: wait past the lease. A fresh
    // queue handle models the second worker: its floor cache is empty,
    // so the takeover floor reflects post-sleep store time.
    drop(q);
    std::thread::sleep(std::time::Duration::from_secs(2));
    let q = Queue::init(
        Box::new(store()),
        &root,
        &OpenOptions::new([1; 16]),
        &format(),
    )
    .unwrap();
    let later = q.establish_floor(&mut OpBudget::new(16)).unwrap();
    let mut takeover = None;
    for shard in 0..4 {
        let opts = ClaimOptions {
            shard,
            floor_ns: later,
            lease_duration_ns: 60_000_000_000,
        };
        if let ClaimOutcome::Claimed(c) = q.claim(&opts, &mut OpBudget::new(512)).unwrap() {
            takeover = Some(c);
            break;
        }
    }
    let second = takeover.expect("takeover after expiry");
    assert_eq!(second.generation, first.generation + 1);
    assert_eq!(second.attempt, first.attempt + 1);
}

/// Empirical calibration (implementation-doc open questions 1 and 3):
/// measures timestamp dispersion across read surfaces to size the
/// skew guard, and inline-vs-detached enqueue+deliver cost to pick the
/// inline threshold. Print-only (the CI lane runs --nocapture, so the
/// log is the record); assertions are sanity bounds only.
#[test]
fn calibration_measurements() {
    let Some(_) = endpoint() else { return };
    use std::time::Instant;

    // ---- Skew guard: same-key surface agreement (HEAD vs LIST for
    // one object) and cross-write dispersion (store-time inversions
    // between successive beacon writes — the quantity the guard
    // absorbs; a single sequential client still probes whatever
    // frontends the load balancer selects).
    let s = store();
    let run = run_id();
    let empty: [u8; 32] = Sha256::digest([]).into();
    let mut max_divergence_ns: u64 = 0;
    let mut times: Vec<u64> = Vec::with_capacity(16);
    for i in 0..16 {
        let k = Key::new(format!("conformance/cal/{run}/beacon-{i}"));
        let PutOutcome::Committed { .. } =
            s.put_if_absent(&k, Bytes::from_static(b""), empty).unwrap()
        else {
            panic!("beacon {i}")
        };
        let head = s.head(&k).unwrap();
        times.push(head.store_time_ns);
        let list_page = s
            .list(&format!("conformance/cal/{run}/"), None, 64)
            .unwrap();
        let listed = list_page
            .items
            .iter()
            .find(|l| l.key.as_str() == k.as_str())
            .unwrap_or_else(|| panic!("beacon {i} not listed"));
        let div = listed.meta.store_time_ns.abs_diff(head.store_time_ns);
        max_divergence_ns = max_divergence_ns.max(div);
    }
    // Cross-write dispersion: a later write reporting an earlier store
    // time than its predecessor. P6's monotone discipline makes large
    // inversions a profile violation; small ones are the dispersion
    // the skew guard exists to absorb.
    let max_regression_ns = times
        .windows(2)
        .map(|w| w[0].saturating_sub(w[1]))
        .max()
        .unwrap_or(0);
    // Guard floor: the larger of the two observed quantities, rounded
    // up past the profile granularity (1 s for the S3 family), minimum
    // one G. A floor, not a tuned suggestion: a sequential single
    // client cannot stress multi-frontend PUT storms, so the R2 row
    // should carry these numbers with that caveat.
    let granularity_ns = 1_000_000_000u64;
    let guard_floor_ns = max_divergence_ns
        .max(max_regression_ns)
        .clamp(granularity_ns, u64::MAX)
        .div_ceil(granularity_ns)
        * granularity_ns;
    println!(
        "calibration: skew_guard — same-key LIST-vs-HEAD divergence \
         {max_divergence_ns} ns, max cross-write store-time regression \
         {max_regression_ns} ns over 16 beacons; guard floor (>= G) \
         {guard_floor_ns} ns"
    );
    // Cross-write regression past the granularity is a P6 violation.
    assert!(
        max_regression_ns < granularity_ns,
        "store-time regression {max_regression_ns} ns"
    );
    // Sanity: dispersion far beyond the profile granularity is a
    // profile violation, not noise.
    assert!(
        max_divergence_ns < 60_000_000_000,
        "divergence {max_divergence_ns} ns"
    );

    // ---- Inline threshold: one PUT (record embeds payload) vs two
    // (payload + record), timed through the real queue paths.
    let root = format!("cal-{run}");
    // One shard: the measurement is payload cost, not sharding; a
    // fixed shard keeps the claim loop trivial.
    let cal_format = FormatRecord {
        shard_count: 1,
        inline_limit: u64::MAX,
        ..format()
    };
    let sizes: [(u64, usize); 5] = [
        (1_024, 1),
        (4_096, 2),
        (16_384, 3),
        (65_536, 4),
        (262_144, 5),
    ];
    println!("calibration: inline threshold — enqueue+claim+deliver by payload size (ns):");
    println!(
        "  {:>9} {:>12} {:>12} {:>8}",
        "bytes", "inline", "detached", "ratio"
    );
    for (limit, idx) in sizes {
        let payload = vec![0xA5u8; limit as usize];
        // Palindrome ordering (inline, detached, detached, inline) with
        // min-of-samples per mode: any first-vs-second run effect
        // (cache warming) lands symmetrically on both modes instead of
        // biasing every cell in one direction.
        let mut timings: Vec<(u64, u64)> = Vec::new();
        // Unique root per arm: a reused root's rep-1 claim is still
        // live within its 60 s lease, so rep 3 would claim Empty.
        for (arm, inline_limit) in [limit, 0, 0, limit].into_iter().enumerate() {
            let mut opts = OpenOptions::new([1; 16]);
            opts.max_inline_payload = inline_limit;
            let q = Queue::init(
                Box::new(store()),
                &format!("{root}-{idx}-{arm}"),
                &opts,
                &cal_format,
            )
            .unwrap();
            let mut b = OpBudget::new(256);
            let start = Instant::now();
            let EnqueueOutcome::Committed { job_id } = q
                .enqueue(
                    EnqueueInput {
                        job_id: Some([idx as u8; 16]),
                        payload: &payload,
                        content_type: "application/octet-stream".into(),
                        maximum_attempts: 1,
                        not_before_ns: None,
                    },
                    &mut b,
                )
                .unwrap()
            else {
                panic!()
            };
            let floor = q.establish_floor(&mut OpBudget::new(16)).unwrap();
            let ClaimOutcome::Claimed(claim) = q
                .claim(
                    &ClaimOptions {
                        shard: 0,
                        floor_ns: floor,
                        lease_duration_ns: 60_000_000_000,
                    },
                    &mut OpBudget::new(512),
                )
                .unwrap()
            else {
                panic!("claim {idx}/{inline_limit}")
            };
            let got = claim.payload(q.store()).unwrap();
            assert_eq!(got.len(), payload.len());
            assert_eq!(claim.job_id, job_id);
            let ns = start.elapsed().as_nanos() as u64;
            timings.push(if inline_limit == 0 {
                (u64::MAX, ns)
            } else {
                (ns, u64::MAX)
            });
        }
        let inline_ns = timings.iter().map(|(i, _)| *i).min().unwrap();
        let detached_ns = timings.iter().map(|(_, d)| *d).min().unwrap();
        println!(
            "  {:>9} {:>12} {:>12} {:>8}",
            limit,
            inline_ns,
            detached_ns,
            format!("{:.2}", detached_ns as f64 / inline_ns.max(1) as f64)
        );
    }
    println!(
        "calibration: inline threshold — the crossover row (ratio <~1) is the \
         suggested default below; the current default is 4096"
    );
}
