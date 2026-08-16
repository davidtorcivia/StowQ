//! Fault-injection tests: every write path resolves outcome-unknown
//! before returning, pre-transmit failures retry transparently, and
//! committed-but-response-lost resolves by content comparison.

use sha2::{Digest as _, Sha256};
use stowq_core::{ClaimOptions, EnqueueInput, EnqueueOutcome, OpBudget, OpenOptions, Queue};
use stowq_format::FormatRecord;
use stowq_store::{Fault, FaultPlan, Injector, MemoryStore, ObjectStore as _, Op, PutOutcome};

fn format() -> FormatRecord {
    FormatRecord {
        shard_count: 1,
        lease_bucket_width_ns: 1_000,
        delayed_bucket_width_ns: 1_000,
        terminal_bucket_width_ns: 1_000,
        inline_limit: 4_096,
        required_feature_bits: 0,
    }
}

fn queue_with(plans: Vec<FaultPlan>) -> Queue {
    let injector = Injector::new(MemoryStore::new(), plans);
    Queue::init(
        Box::new(injector),
        "q",
        &OpenOptions::new([1; 16]),
        &format(),
    )
    .unwrap()
}

fn claim_opts(floor_ns: u64) -> ClaimOptions {
    ClaimOptions {
        shard: 0,
        floor_ns,
        lease_duration_ns: 60_000_000_000,
    }
}

#[test]
fn pre_transmit_fault_on_enqueue_retries_transparently() {
    // Call 0 is FORMAT's put during init; the job put is index 1.
    let q = queue_with(vec![FaultPlan::new(
        Op::PutIfAbsent,
        Fault::PreTransmit,
        [1],
    )]);
    let mut budget = OpBudget::new(64);
    let out = q
        .enqueue(
            EnqueueInput {
                job_id: None,
                payload: b"x",
                content_type: "text/plain".into(),
                maximum_attempts: 3,
                not_before_ns: None,
            },
            &mut budget,
        )
        .unwrap();
    assert!(matches!(out, EnqueueOutcome::Committed { .. }));
}

#[test]
fn unknown_absent_on_enqueue_retries_to_commit() {
    let q = queue_with(vec![FaultPlan::new(
        Op::PutIfAbsent,
        Fault::PostTransmit,
        [1],
    )]);
    let mut budget = OpBudget::new(64);
    let out = q
        .enqueue(
            EnqueueInput {
                job_id: None,
                payload: b"x",
                content_type: "text/plain".into(),
                maximum_attempts: 3,
                not_before_ns: None,
            },
            &mut budget,
        )
        .unwrap();
    assert!(matches!(out, EnqueueOutcome::Committed { .. }));
}

#[test]
fn unknown_committed_on_enqueue_resolves_to_committed() {
    let q = queue_with(vec![FaultPlan::new(
        Op::PutIfAbsent,
        Fault::PostTransmitAfter,
        [1],
    )]);
    let mut budget = OpBudget::new(64);
    let out = q
        .enqueue(
            EnqueueInput {
                job_id: Some([3; 16]),
                payload: b"x",
                content_type: "text/plain".into(),
                maximum_attempts: 3,
                not_before_ns: None,
            },
            &mut budget,
        )
        .unwrap();
    // The resolver reads the key back, finds our record, reports
    // committed; a blind retry would also be safe but is not needed.
    assert!(matches!(out, EnqueueOutcome::Committed { .. }));
    let job_key = stowq_store::Key::new(format!(
        "q/jobs/0000/{}",
        (0..16).map(|_| format!("{:02x}", 3u8)).collect::<String>()
    ));
    let store = q.store();
    assert!(store.head(&job_key).is_ok());
}

#[test]
fn unknown_committed_on_claim_resolves_to_claimed() {
    // Put calls so far: FORMAT(0), job(1); the claim put is index 2.
    let injector = Injector::new(
        MemoryStore::new(),
        vec![FaultPlan::new(
            Op::PutIfAbsent,
            Fault::PostTransmitAfter,
            [2],
        )],
    );
    let q = Queue::init(
        Box::new(injector),
        "q",
        &OpenOptions::new([1; 16]),
        &format(),
    )
    .unwrap();
    let mut budget = OpBudget::new(64);
    q.enqueue(
        EnqueueInput {
            job_id: None,
            payload: b"x",
            content_type: "text/plain".into(),
            maximum_attempts: 3,
            not_before_ns: None,
        },
        &mut budget,
    )
    .unwrap();
    let claimed = q.claim(&claim_opts(0), &mut budget).unwrap();
    match claimed {
        stowq_core::ClaimOutcome::Claimed(claim) => {
            assert_eq!(claim.generation, 1);
        }
        stowq_core::ClaimOutcome::Empty => panic!("claim must resolve to Claimed"),
    }
}

#[test]
fn put_outcome_helper_types_still_behind_trait() {
    // Sanity: the injector passes clean runs through untouched.
    let injector = Injector::new(MemoryStore::new(), vec![]);
    let key = stowq_store::Key::new("k");
    let digest: [u8; 32] = Sha256::digest(b"v").into();
    assert!(matches!(
        injector
            .put_if_absent(&key, bytes::Bytes::from_static(b"v"), digest)
            .unwrap(),
        PutOutcome::Committed { .. }
    ));
}

#[test]
fn transport_on_resolution_read_retries_to_resolve() {
    // Job put (call 1) is committed-but-response-lost; the first
    // resolution HEAD (call 0) fails pre-transmit and is retried.
    let injector = Injector::new(
        MemoryStore::new(),
        vec![
            FaultPlan::new(Op::PutIfAbsent, Fault::PostTransmitAfter, [1]),
            FaultPlan::new(Op::Head, Fault::PreTransmit, [0]),
        ],
    );
    let q = Queue::init(
        Box::new(injector),
        "q",
        &OpenOptions::new([1; 16]),
        &format(),
    )
    .unwrap();
    let mut budget = OpBudget::new(64);
    let out = q
        .enqueue(
            EnqueueInput {
                job_id: Some([4; 16]),
                payload: b"x",
                content_type: "text/plain".into(),
                maximum_attempts: 3,
                not_before_ns: None,
            },
            &mut budget,
        )
        .unwrap();
    assert!(matches!(out, EnqueueOutcome::Committed { .. }));
}

#[test]
fn watermark_unknown_outcome_resolves() {
    // Fault the watermark's creating put (PostTransmitAfter): the write
    // commits but the response is lost; the resolver must re-read and
    // confirm coverage. Call 0 is FORMAT's put; call 1 is the beacon's
    // in establish_floor; call 2 is the watermark create.
    let injector = Injector::new(
        MemoryStore::new(),
        vec![FaultPlan::new(
            Op::PutIfAbsent,
            Fault::PostTransmitAfter,
            [2],
        )],
    );
    let q = Queue::init(
        Box::new(injector),
        "q",
        &OpenOptions::new([1; 16]),
        &format(),
    )
    .unwrap();
    let mut budget = OpBudget::new(64);
    let floor = q.establish_floor(&mut budget).unwrap();
    q.advance_watermark(floor, &mut budget).unwrap();
    let w = q.watermark(&mut budget).unwrap().unwrap();
    assert_eq!(w.highest_observed_wall_bucket, floor / 1_000);
}

#[test]
fn detached_payload_unknown_outcome_resolves() {
    // Put calls: FORMAT(0) during init, payload(1) during enqueue. The
    // payload write is committed-but-response-lost: enqueue must
    // resolve by presence (the key embeds the digest) and the payload
    // must be in place for the claim to deliver.
    let injector = Injector::new(
        MemoryStore::new(),
        vec![FaultPlan::new(
            Op::PutIfAbsent,
            Fault::PostTransmitAfter,
            [1],
        )],
    );
    let mut opts = OpenOptions::new([1; 16]);
    opts.max_inline_payload = 4;
    let q = Queue::init(Box::new(injector), "q", &opts, &format()).unwrap();
    let mut budget = OpBudget::new(64);
    let out = q
        .enqueue(
            EnqueueInput {
                job_id: Some([3; 16]),
                payload: b"detached-payload",
                content_type: "text/plain".into(),
                maximum_attempts: 3,
                not_before_ns: None,
            },
            &mut budget,
        )
        .unwrap();
    assert!(matches!(out, EnqueueOutcome::Committed { .. }));
    let jhex: String = (0..16).map(|_| "03").collect::<String>();
    let page = q
        .store()
        .list(&format!("q/payloads/{jhex}/"), None, 10)
        .unwrap();
    assert!(
        !page.items.is_empty(),
        "resolved payload write must be present"
    );
}

#[test]
fn head_unknown_during_payload_resolution_retries() {
    // The payload put (call 1) is committed-but-response-lost; the
    // resolution head (call 0) itself returns outcome-unknown. Reads
    // have no side effects, so the probe retries and the enqueue
    // resolves instead of leaking the unknown.
    let injector = Injector::new(
        MemoryStore::new(),
        vec![
            FaultPlan::new(Op::PutIfAbsent, Fault::PostTransmitAfter, [1]),
            FaultPlan::new(Op::Head, Fault::PostTransmit, [0]),
        ],
    );
    let mut opts = OpenOptions::new([1; 16]);
    opts.max_inline_payload = 4;
    let q = Queue::init(Box::new(injector), "q", &opts, &format()).unwrap();
    let mut budget = OpBudget::new(64);
    let out = q
        .enqueue(
            EnqueueInput {
                job_id: Some([3; 16]),
                payload: b"detached-payload",
                content_type: "text/plain".into(),
                maximum_attempts: 3,
                not_before_ns: None,
            },
            &mut budget,
        )
        .unwrap();
    assert!(matches!(out, EnqueueOutcome::Committed { .. }));
}

#[test]
fn read_unknown_during_reack_verification_retries() {
    // A committed receipt, then a re-ack whose verification GET (Get
    // call 2, after the FORMAT and job-record reads) returns
    // outcome-unknown: the retry reads the receipt and verifies as
    // AlreadyAcked.
    let injector = Injector::new(
        MemoryStore::new(),
        vec![FaultPlan::new(Op::Get, Fault::PostTransmit, [2])],
    );
    let q = Queue::init(
        Box::new(injector),
        "q",
        &OpenOptions::new([1; 16]),
        &format(),
    )
    .unwrap();
    let mut budget = OpBudget::new(128);
    q.enqueue(
        EnqueueInput {
            job_id: Some([6; 16]),
            payload: b"x",
            content_type: "text/plain".into(),
            maximum_attempts: 3,
            not_before_ns: None,
        },
        &mut budget,
    )
    .unwrap();
    let stowq_core::ClaimOutcome::Claimed(claim) = q
        .claim(
            &ClaimOptions {
                shard: 0,
                floor_ns: 0,
                lease_duration_ns: 60_000_000_000,
            },
            &mut budget,
        )
        .unwrap()
    else {
        panic!("claim")
    };
    assert_eq!(
        q.ack(&claim, &mut budget).unwrap(),
        stowq_core::AckOutcome::Acked
    );
    assert_eq!(
        q.ack(&claim, &mut budget).unwrap(),
        stowq_core::AckOutcome::AlreadyAcked
    );
}

#[test]
fn watermark_resolution_read_unknown_retries() {
    // The watermark create (Put call 2) is committed-but-response-lost;
    // the resolution read that follows (Get call 3, after open's FORMAT
    // read, establish_floor's watermark check, and the CAS loop's own
    // initial read) itself returns outcome-unknown: the retry reads the
    // committed watermark, coverage resolves, and no unknown escapes.
    let injector = Injector::new(
        MemoryStore::new(),
        vec![
            FaultPlan::new(Op::PutIfAbsent, Fault::PostTransmitAfter, [2]),
            FaultPlan::new(Op::Get, Fault::PostTransmit, [3]),
        ],
    );
    let q = Queue::init(
        Box::new(injector),
        "q",
        &OpenOptions::new([1; 16]),
        &format(),
    )
    .unwrap();
    let mut budget = OpBudget::new(64);
    let floor = q.establish_floor(&mut budget).unwrap();
    q.advance_watermark(floor, &mut budget).unwrap();
    let w = q.watermark(&mut budget).unwrap().unwrap();
    assert_eq!(w.highest_observed_wall_bucket, floor / 1_000);
}

#[test]
fn init_rejected_branch_read_unknown_retries() {
    // An identical FORMAT already owns the prefix (init by another
    // participant): the put rejects and init reads the existing record
    // back to compare. That read (Get call 0) returns outcome-unknown;
    // the retry reads it, the records compare equal, and open proceeds.
    let inner = MemoryStore::new();
    let pre = Queue::init(
        Box::new(inner.clone()),
        "q",
        &OpenOptions::new([1; 16]),
        &format(),
    )
    .unwrap();
    drop(pre);
    let injector = Injector::new(
        inner,
        vec![FaultPlan::new(Op::Get, Fault::PostTransmit, [0])],
    );
    Queue::init(
        Box::new(injector),
        "q",
        &OpenOptions::new([1; 16]),
        &format(),
    )
    .unwrap();
}
