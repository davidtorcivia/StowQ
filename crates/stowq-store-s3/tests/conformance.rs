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
