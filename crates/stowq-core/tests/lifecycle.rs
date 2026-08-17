//! Lifecycle tests against the memory fake: init, enqueue, claim, renew,
//! ack, nack, bury, takeover, exhaustion, and budgets.

use sha2::Digest as _;
use std::sync::Arc;

use stowq_core::{
    ClaimOptions, ClaimOutcome, EnqueueInput, EnqueueOutcome, Error, OpBudget, OpenOptions, Queue,
};
use stowq_format::FormatRecord;
use stowq_store::{Key, MemoryStore, ObjectStore as _, StoreError};

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

async fn make_queue() -> Queue {
    Queue::init(
        Box::new(MemoryStore::new()),
        "q",
        &OpenOptions::new([1; 16]),
        &format(),
    )
    .await
    .unwrap()
}

async fn make_shared() -> (Queue, MemoryStore) {
    let store = MemoryStore::new();
    let q = Queue::init(
        Box::new(store.clone()),
        "q",
        &OpenOptions::new([1; 16]),
        &format(),
    )
    .await
    .unwrap();
    (q, store)
}

fn claim_opts(floor_ns: u64, lease_ns: u64) -> ClaimOptions {
    ClaimOptions {
        shard: 0,
        floor_ns,
        lease_duration_ns: lease_ns,
    }
}

#[tokio::test]
async fn init_idempotent_then_rejects_conflicting_format() {
    let (q, store) = make_shared().await;
    // Identical format over the same prefix: accepted.
    Queue::init(
        Box::new(store.clone()),
        "q",
        &OpenOptions::new([1; 16]),
        &format(),
    )
    .await
    .unwrap();
    // Conflicting format: rejected.
    let different = FormatRecord {
        shard_count: 2,
        ..format()
    };
    let result = Queue::init(
        Box::new(store.clone()),
        "q",
        &OpenOptions::new([1; 16]),
        &different,
    )
    .await;
    match result {
        Err(stowq_core::Error::QueueIdMismatch) => {}
        _ => panic!("expected QueueIdMismatch"),
    }
    drop(q);
}

#[tokio::test]
async fn enqueue_claim_ack_lifecycle() {
    let q = make_queue().await;
    let mut budget = OpBudget::new(64);
    let out = q
        .enqueue(
            EnqueueInput {
                job_id: None,
                payload: b"hello",
                content_type: "text/plain".into(),
                maximum_attempts: 3,
                not_before_ns: None,
            },
            &mut budget,
        )
        .await
        .unwrap();
    let EnqueueOutcome::Committed { job_id } = out else {
        panic!("commit")
    };

    let claimed = q
        .claim(&claim_opts(0, 60_000_000_000), &mut budget)
        .await
        .unwrap();
    let stowq_core::ClaimOutcome::Claimed(claim) = claimed else {
        panic!("claim")
    };
    assert_eq!(claim.job_id, job_id);
    assert_eq!(claim.generation, 1);
    assert_eq!(claim.attempt, 1);
    let payload = claim.payload(q.store()).await.unwrap();
    assert_eq!(&payload[..], b"hello");

    // Lease held: a second claim at the same floor finds nothing.
    let again = q
        .claim(&claim_opts(0, 60_000_000_000), &mut budget)
        .await
        .unwrap();
    assert!(matches!(again, stowq_core::ClaimOutcome::Empty));

    let ack = q.ack(&claim, &mut budget).await.unwrap();
    assert_eq!(ack, stowq_core::AckOutcome::Acked);

    // Idempotent re-ack verifies existing evidence.
    let reack = q.ack(&claim, &mut budget).await.unwrap();
    assert_eq!(reack, stowq_core::AckOutcome::AlreadyAcked);

    // Terminal: no further claims.
    let post = q
        .claim(&claim_opts(u64::MAX / 4, 60_000_000_000), &mut budget)
        .await
        .unwrap();
    assert!(matches!(post, stowq_core::ClaimOutcome::Empty));
}

#[tokio::test]
async fn detached_payload_round_trips() {
    let mut opts = OpenOptions::new([1; 16]);
    opts.max_inline_payload = 4;
    let q = Queue::init(Box::new(MemoryStore::new()), "q", &opts, &format())
        .await
        .unwrap();
    let mut budget = OpBudget::new(64);
    let big = vec![7u8; 100];
    q.enqueue(
        EnqueueInput {
            job_id: None,
            payload: &big,
            content_type: "application/octet-stream".into(),
            maximum_attempts: 2,
            not_before_ns: None,
        },
        &mut budget,
    )
    .await
    .unwrap();
    let stowq_core::ClaimOutcome::Claimed(claim) = q
        .claim(&claim_opts(0, 60_000_000_000), &mut budget)
        .await
        .unwrap()
    else {
        panic!("claim")
    };
    assert_eq!(&claim.payload(q.store()).await.unwrap()[..], &big[..]);
}

#[tokio::test]
async fn idempotent_enqueue_and_id_taken() {
    let q = make_queue().await;
    let mut budget = OpBudget::new(64);
    let jid = [9; 16];
    let out = q
        .enqueue(
            EnqueueInput {
                job_id: Some(jid),
                payload: b"same",
                content_type: "text/plain".into(),
                maximum_attempts: 2,
                not_before_ns: None,
            },
            &mut budget,
        )
        .await
        .unwrap();
    assert!(matches!(out, EnqueueOutcome::Committed { .. }));
    // Identical retry: committed (our own record already present).
    let out2 = q
        .enqueue(
            EnqueueInput {
                job_id: Some(jid),
                payload: b"same",
                content_type: "text/plain".into(),
                maximum_attempts: 2,
                not_before_ns: None,
            },
            &mut budget,
        )
        .await
        .unwrap();
    assert!(matches!(out2, EnqueueOutcome::Committed { .. }));
    // Different payload under the same id: taken.
    let out3 = q
        .enqueue(
            EnqueueInput {
                job_id: Some(jid),
                payload: b"other",
                content_type: "text/plain".into(),
                maximum_attempts: 2,
                not_before_ns: None,
            },
            &mut budget,
        )
        .await
        .unwrap();
    assert!(matches!(out3, EnqueueOutcome::IdTaken { .. }));
}

#[tokio::test]
async fn takeover_after_expiry_increments_generation_and_attempt() {
    let q = make_queue().await;
    let mut budget = OpBudget::new(128);
    q.enqueue(
        EnqueueInput {
            job_id: None,
            payload: b"x",
            content_type: "text/plain".into(),
            maximum_attempts: 5,
            not_before_ns: None,
        },
        &mut budget,
    )
    .await
    .unwrap();
    let stowq_core::ClaimOutcome::Claimed(first) =
        q.claim(&claim_opts(0, 1_000), &mut budget).await.unwrap()
    else {
        panic!("first claim")
    };
    // Not yet expired (skew guard 0): floor one nanosecond short.
    let expiry = first.claim_store_time_ns + 1_000;
    let held = q
        .claim(&claim_opts(expiry - 1, 1_000), &mut budget)
        .await
        .unwrap();
    assert!(matches!(held, stowq_core::ClaimOutcome::Empty));
    // At and past expiry: takeover (floor >= expiry is expired).
    let stowq_core::ClaimOutcome::Claimed(second) = q
        .claim(&claim_opts(expiry, 1_000), &mut budget)
        .await
        .unwrap()
    else {
        panic!("takeover")
    };
    assert_eq!(second.generation, 2);
    assert_eq!(second.attempt, 2);
    assert_ne!(second.worker_token, first.worker_token);
}

#[tokio::test]
async fn renew_extends_and_loses_to_takeover() {
    let q = make_queue().await;
    let mut budget = OpBudget::new(128);
    q.enqueue(
        EnqueueInput {
            job_id: None,
            payload: b"x",
            content_type: "text/plain".into(),
            maximum_attempts: 5,
            not_before_ns: None,
        },
        &mut budget,
    )
    .await
    .unwrap();
    let stowq_core::ClaimOutcome::Claimed(claim) =
        q.claim(&claim_opts(0, 1_000), &mut budget).await.unwrap()
    else {
        panic!("claim")
    };
    let stowq_core::RenewOutcome::Renewed(renewed) = q.renew(&claim, &mut budget).await.unwrap()
    else {
        panic!("renew")
    };
    assert_eq!(renewed.generation, 2);
    assert_eq!(renewed.attempt, 1); // continuation keeps the attempt
    assert_eq!(renewed.worker_token, claim.worker_token);
    // Old expiry no longer takes the job.
    let old_expiry = claim.claim_store_time_ns + 1_000;
    let held = q
        .claim(&claim_opts(old_expiry, 1_000), &mut budget)
        .await
        .unwrap();
    assert!(matches!(held, stowq_core::ClaimOutcome::Empty));
    // Renewal of the stale claim loses to generation 2 existing.
    let lost = q.renew(&claim, &mut budget).await.unwrap();
    assert!(matches!(lost, stowq_core::RenewOutcome::LeaseLost));
}

#[tokio::test]
async fn nack_gates_claim_until_backoff_elapses() {
    let q = make_queue().await;
    let mut budget = OpBudget::new(256);
    q.enqueue(
        EnqueueInput {
            job_id: None,
            payload: b"x",
            content_type: "text/plain".into(),
            maximum_attempts: 5,
            not_before_ns: None,
        },
        &mut budget,
    )
    .await
    .unwrap();
    let stowq_core::ClaimOutcome::Claimed(claim) =
        q.claim(&claim_opts(0, 1_000), &mut budget).await.unwrap()
    else {
        panic!("claim")
    };
    q.nack(&claim, 0x0001, 0, &mut budget).await.unwrap();
    // Backoff delay at attempt 1 with default policy: 50-100ms.
    let early = q
        .claim(&claim_opts(1_000_000, 1_000), &mut budget)
        .await
        .unwrap();
    assert!(matches!(early, stowq_core::ClaimOutcome::Empty));
    let late = q
        .claim(&claim_opts(200_000_000, 1_000), &mut budget)
        .await
        .unwrap();
    let stowq_core::ClaimOutcome::Claimed(takeover) = late else {
        panic!("takeover")
    };
    assert_eq!(takeover.generation, 2);
    assert_eq!(takeover.attempt, 2);
}

#[tokio::test]
async fn attempts_exhausted_writes_dead() {
    let q = make_queue().await;
    let mut budget = OpBudget::new(256);
    let out = q
        .enqueue(
            EnqueueInput {
                job_id: Some([5; 16]),
                payload: b"x",
                content_type: "text/plain".into(),
                maximum_attempts: 1,
                not_before_ns: None,
            },
            &mut budget,
        )
        .await
        .unwrap();
    let EnqueueOutcome::Committed { job_id } = out else {
        panic!()
    };
    let stowq_core::ClaimOutcome::Claimed(claim) =
        q.claim(&claim_opts(0, 1_000), &mut budget).await.unwrap()
    else {
        panic!("claim")
    };
    // Expire; the next claim attempt must write dead, not claim.
    let floor = claim.claim_store_time_ns + 2_000;
    let out2 = q
        .claim(&claim_opts(floor, 1_000), &mut budget)
        .await
        .unwrap();
    assert!(matches!(out2, stowq_core::ClaimOutcome::Empty));
    let dead_key = Key::new(format!(
        "q/dead/0000/{}",
        job_id
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ));
    let meta = q.store().head(&dead_key).await.unwrap();
    assert!(meta.size > 0);
    // And the job is terminal thereafter.
    let out3 = q
        .claim(&claim_opts(u64::MAX / 4, 1_000), &mut budget)
        .await
        .unwrap();
    assert!(matches!(out3, stowq_core::ClaimOutcome::Empty));
}

#[tokio::test]
async fn bury_makes_job_unclaimable() {
    let q = make_queue().await;
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
    .await
    .unwrap();
    let stowq_core::ClaimOutcome::Claimed(claim) = q
        .claim(&claim_opts(0, 60_000_000_000), &mut budget)
        .await
        .unwrap()
    else {
        panic!("claim")
    };
    q.bury(&claim, 0x0003, &mut budget).await.unwrap();
    let post = q
        .claim(&claim_opts(u64::MAX / 4, 60_000_000_000), &mut budget)
        .await
        .unwrap();
    assert!(matches!(post, stowq_core::ClaimOutcome::Empty));
}

#[tokio::test]
async fn delayed_job_not_claimable_before_floor() {
    let q = make_queue().await;
    let mut budget = OpBudget::new(64);
    q.enqueue(
        EnqueueInput {
            job_id: None,
            payload: b"x",
            content_type: "text/plain".into(),
            maximum_attempts: 3,
            not_before_ns: Some(10_000_000_000),
        },
        &mut budget,
    )
    .await
    .unwrap();
    let early = q
        .claim(&claim_opts(9_999_999_999, 1_000), &mut budget)
        .await
        .unwrap();
    assert!(matches!(early, stowq_core::ClaimOutcome::Empty));
    let late = q
        .claim(&claim_opts(10_000_000_000, 1_000), &mut budget)
        .await
        .unwrap();
    assert!(matches!(late, stowq_core::ClaimOutcome::Claimed(_)));
}

#[tokio::test]
async fn tiny_budget_exhausts() {
    let mut opts = OpenOptions::new([1; 16]);
    opts.max_inline_payload = 4;
    let q = Queue::init(Box::new(MemoryStore::new()), "q", &opts, &format())
        .await
        .unwrap();
    // Budget 1: the detached payload write spends it before the record.
    let mut budget = OpBudget::new(1);
    let err = q
        .enqueue(
            EnqueueInput {
                job_id: None,
                payload: b"detached",
                content_type: "text/plain".into(),
                maximum_attempts: 3,
                not_before_ns: None,
            },
            &mut budget,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, Error::BudgetExhausted));
}

#[tokio::test]
async fn open_rejects_missing_format() {
    let result = Queue::open(Box::new(MemoryStore::new()), "q", OpenOptions::new([1; 16])).await;
    match result {
        Err(Error::Store(StoreError::NotFound)) => {}
        Err(other) => panic!("expected NotFound, got {other:?}"),
        Ok(_) => panic!("open must reject a prefix without FORMAT"),
    }
}

#[tokio::test]
async fn renew_and_ack_refuse_after_exhaustion_dead() {
    let q = make_queue().await;
    let mut budget = OpBudget::new(256);
    q.enqueue(
        EnqueueInput {
            job_id: Some([6; 16]),
            payload: b"x",
            content_type: "text/plain".into(),
            maximum_attempts: 1,
            not_before_ns: None,
        },
        &mut budget,
    )
    .await
    .unwrap();
    let stowq_core::ClaimOutcome::Claimed(claim) =
        q.claim(&claim_opts(0, 1_000), &mut budget).await.unwrap()
    else {
        panic!("claim")
    };
    // Expire; another claimant writes dead at exhaustion.
    let floor = claim.claim_store_time_ns + 2_000;
    let out = q
        .claim(&claim_opts(floor, 1_000), &mut budget)
        .await
        .unwrap();
    assert!(matches!(out, stowq_core::ClaimOutcome::Empty));
    // The zombie holder cannot extend custody or ack over the dead job.
    let renewed = q.renew(&claim, &mut budget).await.unwrap();
    assert!(matches!(renewed, stowq_core::RenewOutcome::LeaseLost));
    let acked = q.ack(&claim, &mut budget).await.unwrap();
    assert_eq!(acked, stowq_core::AckOutcome::SupersededByDead);
    // And no receipt exists.
    let jhex: String = [6u8; 16].iter().map(|b| format!("{b:02x}")).collect();
    let receipt = q
        .store()
        .head(&Key::new(format!("q/receipts/0000/{jhex}")))
        .await;
    assert!(receipt.is_err());
}

#[tokio::test]
async fn floor_and_watermark_lifecycle() {
    let q = make_queue().await;
    let mut budget = OpBudget::new(64);
    // Floor: beacon write + read-back, monotone across refreshes.
    let f1 = q.establish_floor(&mut budget).await.unwrap();
    assert!(f1 > 0);
    let f2 = q.establish_floor(&mut budget).await.unwrap();
    assert_eq!(f1, f2, "cached floor is reused until stale");
    // Watermark: absent -> create; advance; lower bucket is a no-op.
    assert!(q.watermark(&mut budget).await.unwrap().is_none());
    // The method bucketizes with the delayed width (1000 ns here).
    q.advance_watermark(10_000, &mut budget).await.unwrap();
    let w = q.watermark(&mut budget).await.unwrap().unwrap();
    assert_eq!(w.highest_observed_wall_bucket, 10);
    assert_eq!(w.sequence, 0);
    q.advance_watermark(12_000, &mut budget).await.unwrap();
    let w = q.watermark(&mut budget).await.unwrap().unwrap();
    assert_eq!(w.highest_observed_wall_bucket, 12);
    assert_eq!(w.sequence, 1);
    // Same bucket is a no-op.
    q.advance_watermark(12_500, &mut budget).await.unwrap();
    let w = q.watermark(&mut budget).await.unwrap().unwrap();
    assert_eq!(w.sequence, 1);
    // A lower bucket than stored is a lost race or a stale floor: the
    // watermark already covers it; proceed as a no-op.
    q.advance_watermark(5_000, &mut budget).await.unwrap();
    let w = q.watermark(&mut budget).await.unwrap().unwrap();
    assert_eq!(w.highest_observed_wall_bucket, 12);
    assert_eq!(w.sequence, 1);
}

#[tokio::test]
async fn sweeps_evaluate_and_prune_index_entries() {
    let q = make_queue().await;
    let mut budget = OpBudget::new(256);
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
    .await
    .unwrap();
    let stowq_core::ClaimOutcome::Claimed(claim) =
        q.claim(&claim_opts(0, 1_000), &mut budget).await.unwrap()
    else {
        panic!("claim")
    };
    // The lease index entry exists (written at claim).
    let leases = list_all(&q, "q/leases/").await;
    assert_eq!(leases.len(), 1, "claim writes its lease index entry");

    // Before expiry: the entry's expiry bucket is ahead of the floor
    // bucket, so the sweep skips it entirely.
    let report = q
        .sweep_expired_leases(claim.claim_store_time_ns, &mut budget)
        .await
        .unwrap();
    assert_eq!(report.entries, 0);
    assert_eq!(
        list_all(&q, "q/leases/").await.len(),
        1,
        "not-yet-due entries are left in place"
    );

    // After expiry: the entry is due, the tail is genuinely expired, and
    // the consumed entry is deleted.
    let after_expiry = claim.claim_store_time_ns + 1_000;
    let report = q
        .sweep_expired_leases(after_expiry, &mut budget)
        .await
        .unwrap();
    assert_eq!(report.entries, 1);
    assert_eq!(report.reclaimed, 1);
    assert!(
        list_all(&q, "q/leases/").await.is_empty(),
        "sweep deletes consumed entries"
    );
    let retake = q
        .claim(&claim_opts(after_expiry, 1_000), &mut budget)
        .await
        .unwrap();
    let stowq_core::ClaimOutcome::Claimed(second) = retake else {
        panic!("takeover after sweep")
    };
    assert_eq!(second.generation, 2);
}

#[tokio::test]
async fn delayed_sweep_promotes_due_jobs() {
    let q = make_queue().await;
    let mut budget = OpBudget::new(256);
    q.enqueue(
        EnqueueInput {
            job_id: None,
            payload: b"x",
            content_type: "text/plain".into(),
            maximum_attempts: 3,
            not_before_ns: Some(5_000_000),
        },
        &mut budget,
    )
    .await
    .unwrap();
    assert_eq!(list_all(&q, "q/delayed/").await.len(), 1);
    // Before due: entry examined, not promoted, deleted.
    let report = q.sweep_delayed(4_000_000, &mut budget).await.unwrap();
    assert_eq!(report.entries, 0, "future bucket entries are skipped");
    // Due: promoted (the job's not_before has passed).
    let report = q.sweep_delayed(5_000_000, &mut budget).await.unwrap();
    assert!(report.promoted >= 1);
    // The job is claimable at the due floor.
    let claimed = q
        .claim(&claim_opts(5_000_000, 1_000), &mut budget)
        .await
        .unwrap();
    assert!(matches!(claimed, stowq_core::ClaimOutcome::Claimed(_)));
}

#[tokio::test]
async fn gc_deletes_terminal_graphs_and_honors_retention() {
    let q = make_queue().await;
    let mut budget = OpBudget::new(1_024);
    q.enqueue(
        EnqueueInput {
            job_id: Some([8; 16]),
            payload: b"x",
            content_type: "text/plain".into(),
            maximum_attempts: 3,
            not_before_ns: None,
        },
        &mut budget,
    )
    .await
    .unwrap();
    let stowq_core::ClaimOutcome::Claimed(claim) =
        q.claim(&claim_opts(0, 1_000), &mut budget).await.unwrap()
    else {
        panic!("claim")
    };
    q.ack(&claim, &mut budget).await.unwrap();

    // Within retention: nothing deleted.
    let report = q
        .gc(
            claim.claim_store_time_ns + 100,
            1_000_000,
            60_000_000_000,
            &mut budget,
        )
        .await
        .unwrap();
    assert_eq!(report.jobs_deleted, 0);
    let jhex: String = claim.job_id.iter().map(|b| format!("{b:02x}")).collect();
    assert!(q
        .store()
        .head(&Key::new(format!("q/receipts/0000/{jhex}")))
        .await
        .is_ok());

    // Past retention: the whole graph goes, terminal last.
    let report = q.gc(u64::MAX / 4, 1_000, 1_000, &mut budget).await.unwrap();
    assert_eq!(report.jobs_deleted, 1);
    assert!(q
        .store()
        .head(&Key::new(format!("q/receipts/0000/{jhex}")))
        .await
        .is_err());
    assert!(q
        .store()
        .head(&Key::new(format!("q/jobs/0000/{jhex}")))
        .await
        .is_err());
    assert!(list_all(&q, "q/termidx/").await.is_empty());
    assert!(list_all(&q, "q/claims/").await.is_empty());
    assert!(list_all(&q, "q/fails/").await.is_empty());
}

async fn list_all(q: &Queue, prefix: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut after: Option<Key> = None;
    loop {
        let page = q.store().list(prefix, after.as_ref(), 100).await.unwrap();
        if page.items.is_empty() {
            break;
        }
        for item in &page.items {
            out.push(item.key.to_string());
        }
        match page.next_after {
            Some(k) => after = Some(k),
            None => break,
        }
    }
    out
}

#[tokio::test]
async fn fresh_floor_below_watermark_fails_closed() {
    let q = make_queue().await;
    let mut budget = OpBudget::new(64);
    // A watermark record far in the future, written directly (as a
    // legitimate earlier participant would have advanced it).
    let rel = "meta/watermark";
    let tag = stowq_keys::key_tag(&[1; 16], rel);
    let wm = stowq_format::Record::Watermark(stowq_format::WatermarkRecord {
        highest_observed_wall_bucket: 1_000_000_000,
        sequence: 0,
    });
    let body = bytes::Bytes::from(stowq_format::encode(&wm, &[1; 16], &tag));
    let digest: [u8; 32] = {
        use sha2::Digest as _;
        sha2::Sha256::digest(&body).into()
    };
    q.store()
        .put_if_absent(&Key::new(format!("q/{rel}")), body, digest)
        .await
        .unwrap();
    // bucket * delayed_width = 1e9 * 1000 = 1e12 ns ahead of any store
    // time the fake can produce soon; a fresh floor must fail closed.
    let result = q.establish_floor(&mut budget).await;
    match result {
        Err(Error::Store(stowq_store::StoreError::ProfileViolation(msg))) => {
            assert!(msg.contains("regression"), "unexpected violation: {msg}");
        }
        other => panic!("expected ProfileViolation, got {other:?}"),
    }
}

#[tokio::test]
async fn gc_interruption_leaves_terminal_record_last() {
    // Starve the graph deletion mid-flight: each trial runs against a
    // FRESH fixture (partial deletions consume the termidx discovery
    // path, so cumulative trials strand the graph — recovery from that
    // stranding is the repair scan's job, not a second gc pass). A
    // trial whose budget covers the whole graph completes it; smaller
    // budgets leave every intermediate state with the terminal record
    // present and the job unclaimable.
    let jhex: String = [9u8; 16].iter().map(|b| format!("{b:02x}")).collect();
    let mut completed = false;
    for trial in 1..=24 {
        let q = make_queue().await;
        let mut budget = OpBudget::new(1_024);
        q.enqueue(
            EnqueueInput {
                job_id: Some([9; 16]),
                payload: b"x",
                content_type: "text/plain".into(),
                maximum_attempts: 3,
                not_before_ns: None,
            },
            &mut budget,
        )
        .await
        .unwrap();
        let stowq_core::ClaimOutcome::Claimed(claim) =
            q.claim(&claim_opts(0, 1_000), &mut budget).await.unwrap()
        else {
            panic!("claim")
        };
        q.ack(&claim, &mut budget).await.unwrap();

        let mut small = OpBudget::new(trial);
        let _ = q.gc(u64::MAX / 4, 1_000, 1_000, &mut small).await;
        let receipt = q
            .store()
            .head(&Key::new(format!("q/receipts/0000/{jhex}")))
            .await;
        if receipt.is_err() {
            // Deletion completed on this trial: the terminal record is
            // gone because it went LAST; the job must be gone too.
            assert!(
                q.store()
                    .head(&Key::new(format!("q/jobs/0000/{jhex}")))
                    .await
                    .is_err(),
                "job record must not outlive the terminal record"
            );
            completed = true;
            break;
        }
        // Still mid-deletion: terminal record present, job unclaimable.
        let claimed = q
            .claim(&claim_opts(u64::MAX / 4, 1_000), &mut OpBudget::new(64))
            .await
            .unwrap();
        assert!(
            matches!(claimed, stowq_core::ClaimOutcome::Empty),
            "trial {trial}: mid-GC job must be unclaimable while its terminal record exists"
        );
    }
    assert!(
        completed,
        "some trial must complete the deletion to exercise the ordering assert"
    );
}

#[tokio::test]
async fn zombie_bury_after_ack_is_refused() {
    let q = make_queue().await;
    let mut budget = OpBudget::new(256);
    q.enqueue(
        EnqueueInput {
            job_id: Some([11; 16]),
            payload: b"x",
            content_type: "text/plain".into(),
            maximum_attempts: 3,
            not_before_ns: None,
        },
        &mut budget,
    )
    .await
    .unwrap();
    let stowq_core::ClaimOutcome::Claimed(claim) =
        q.claim(&claim_opts(0, 1_000), &mut budget).await.unwrap()
    else {
        panic!("claim")
    };
    q.ack(&claim, &mut budget).await.unwrap();
    // The zombie holder buries late: refused, no second terminal record.
    let out = q.bury(&claim, 0x0003, &mut budget).await.unwrap();
    assert_eq!(out, stowq_core::BuryOutcome::SupersededByReceipt);
    let jhex: String = claim.job_id.iter().map(|b| format!("{b:02x}")).collect();
    assert!(
        q.store()
            .head(&Key::new(format!("q/dead/0000/{jhex}")))
            .await
            .is_err(),
        "no dead record may coexist with a receipt"
    );
}

#[tokio::test]
async fn tail_holder_bury_after_exhaustion_dead_verifies() {
    // The exhaustion-dead try_claim writes carries the tail claim's
    // (generation, attempt): the tail holder's late bury must hit the
    // Lost branch and verify as Buried, not conflicting evidence.
    let q = make_queue().await;
    let mut budget = OpBudget::new(256);
    q.enqueue(
        EnqueueInput {
            job_id: Some([12; 16]),
            payload: b"x",
            content_type: "text/plain".into(),
            maximum_attempts: 1,
            not_before_ns: None,
        },
        &mut budget,
    )
    .await
    .unwrap();
    let stowq_core::ClaimOutcome::Claimed(claim) =
        q.claim(&claim_opts(0, 1_000), &mut budget).await.unwrap()
    else {
        panic!("claim")
    };
    let floor = claim.claim_store_time_ns + 2_000;
    let out = q
        .claim(&claim_opts(floor, 1_000), &mut budget)
        .await
        .unwrap();
    assert!(matches!(out, stowq_core::ClaimOutcome::Empty));
    // The tail holder buries over the exhaustion-dead record: the
    // evidence (generation, attempt) matches, so success.
    let bury = q.bury(&claim, 0x0003, &mut budget).await.unwrap();
    assert_eq!(bury, stowq_core::BuryOutcome::Buried);
}

#[tokio::test]
async fn init_rejects_non_power_of_two_shard_count() {
    let mut f = format();
    f.shard_count = 100;
    let result = Queue::init(
        Box::new(MemoryStore::new()),
        "q",
        &OpenOptions::new([1; 16]),
        &f,
    )
    .await;
    match result {
        Err(Error::Record(_)) => {}
        Err(other) => panic!("expected Record error, got {other:?}"),
        Ok(_) => panic!("expected a Record error, got success"),
    }
    // Bounds are powers of two and accepted.
    f.shard_count = 65_536;
    Queue::init(
        Box::new(MemoryStore::new()),
        "q",
        &OpenOptions::new([1; 16]),
        &f,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn open_rejects_format_with_unknown_required_features() {
    use sha2::{Digest as _, Sha256};
    use stowq_store::ObjectStore as _;

    let store = MemoryStore::new();
    let mut f = format();
    // Bits 1 (v1.1 quarantine) and 2 (v1.2 tail hints) are known;
    // bit 4 is not.
    f.required_feature_bits = 4;
    // Write the record directly, bypassing init's validation: open must
    // reject a v1.1 store whose FORMAT demands unknown features.
    let tag = stowq_keys::key_tag(&[1; 16], "meta/FORMAT");
    let body = bytes::Bytes::from(stowq_format::encode(
        &stowq_format::Record::Format(f),
        &[1; 16],
        &tag,
    ));
    let digest: [u8; 32] = Sha256::digest(&body).into();
    store
        .put_if_absent(&Key::new("q/meta/FORMAT"), body, digest)
        .await
        .unwrap();
    let result = Queue::open(Box::new(store), "q", OpenOptions::new([1; 16])).await;
    match result {
        Err(Error::Record(_)) => {}
        Err(other) => panic!("expected Record error, got {other:?}"),
        Ok(_) => panic!("expected a Record error, got success"),
    }
}

#[tokio::test]
async fn enqueue_rejects_zero_maximum_attempts() {
    let q = make_queue().await;
    let mut budget = OpBudget::new(64);
    let result = q
        .enqueue(
            EnqueueInput {
                job_id: None,
                payload: b"x",
                content_type: "text/plain".into(),
                maximum_attempts: 0,
                not_before_ns: None,
            },
            &mut budget,
        )
        .await;
    match result {
        Err(Error::Record(_)) => {}
        Err(other) => panic!("expected Record error, got {other:?}"),
        Ok(_) => panic!("expected a Record error, got success"),
    }
}

// ---------- Repair scan ----------

use stowq_core::{FindingKind as RK, RepairReport};

async fn repair_all(q: &Queue) -> (RepairReport, Option<u16>) {
    q.repair_scan(0, &mut OpBudget::new(4096)).await.unwrap()
}

#[tokio::test]
async fn repair_regenerates_missing_delayed_index() {
    let q = make_queue().await;
    let mut budget = OpBudget::new(256);
    q.enqueue(
        EnqueueInput {
            job_id: Some([13; 16]),
            payload: b"x",
            content_type: "text/plain".into(),
            maximum_attempts: 3,
            not_before_ns: Some(5_000_000),
        },
        &mut budget,
    )
    .await
    .unwrap();
    let delayed = list_all(&q, "q/delayed/").await;
    assert_eq!(delayed.len(), 1);
    q.store()
        .delete(&Key::new(delayed[0].clone()))
        .await
        .unwrap();
    let (report, resume) = repair_all(&q).await;
    assert!(resume.is_none());
    assert_eq!(report.indexes_regenerated, 1);
    let regen = list_all(&q, "q/delayed/").await;
    assert_eq!(regen.len(), 1);
    assert_eq!(regen[0], delayed[0]);
    // Idempotent: a second run regenerates nothing.
    let (report2, _) = repair_all(&q).await;
    assert_eq!(report2.indexes_regenerated, 0);
    assert!(report2.findings.is_empty());
}

#[tokio::test]
async fn repair_regenerates_missing_lease_index() {
    let q = make_queue().await;
    let mut budget = OpBudget::new(256);
    q.enqueue(
        EnqueueInput {
            job_id: Some([14; 16]),
            payload: b"x",
            content_type: "text/plain".into(),
            maximum_attempts: 3,
            not_before_ns: None,
        },
        &mut budget,
    )
    .await
    .unwrap();
    let stowq_core::ClaimOutcome::Claimed(_) =
        q.claim(&claim_opts(0, 1_000), &mut budget).await.unwrap()
    else {
        panic!("claim")
    };
    let leases = list_all(&q, "q/leases/").await;
    assert_eq!(leases.len(), 1);
    q.store()
        .delete(&Key::new(leases[0].clone()))
        .await
        .unwrap();
    let (report, _) = repair_all(&q).await;
    assert_eq!(report.indexes_regenerated, 1);
    let regen = list_all(&q, "q/leases/").await;
    assert_eq!(regen.len(), 1);
    assert_eq!(regen[0], leases[0]);
}

#[tokio::test]
async fn repair_regenerates_missing_termidx() {
    let q = make_queue().await;
    let mut budget = OpBudget::new(256);
    q.enqueue(
        EnqueueInput {
            job_id: Some([15; 16]),
            payload: b"x",
            content_type: "text/plain".into(),
            maximum_attempts: 3,
            not_before_ns: None,
        },
        &mut budget,
    )
    .await
    .unwrap();
    let stowq_core::ClaimOutcome::Claimed(claim) =
        q.claim(&claim_opts(0, 1_000), &mut budget).await.unwrap()
    else {
        panic!("claim")
    };
    q.ack(&claim, &mut budget).await.unwrap();
    let termidx = list_all(&q, "q/termidx/").await;
    assert_eq!(termidx.len(), 1);
    q.store()
        .delete(&Key::new(termidx[0].clone()))
        .await
        .unwrap();
    let (report, _) = repair_all(&q).await;
    assert_eq!(report.indexes_regenerated, 1);
    let regen = list_all(&q, "q/termidx/").await;
    assert_eq!(regen.len(), 1);
    assert_eq!(regen[0], termidx[0]);
}

#[tokio::test]
async fn repair_reports_grammar_violation_and_skips() {
    let q = make_queue().await;
    let garbage = Key::new("q/jobs/0000/not-hex-at-all");
    let digest: [u8; 32] = {
        use sha2::Digest as _;
        sha2::Sha256::digest(b"junk").into()
    };
    q.store()
        .put_if_absent(&garbage, bytes::Bytes::from_static(b"junk"), digest)
        .await
        .unwrap();
    let (report, _) = repair_all(&q).await;
    assert!(report
        .findings
        .iter()
        .any(|f| f.kind == RK::KeyGrammar && f.reason == 0x0003));
}

#[tokio::test]
async fn repair_reports_claim_without_job() {
    let q = make_queue().await;
    let mut budget = OpBudget::new(256);
    q.enqueue(
        EnqueueInput {
            job_id: Some([16; 16]),
            payload: b"x",
            content_type: "text/plain".into(),
            maximum_attempts: 3,
            not_before_ns: None,
        },
        &mut budget,
    )
    .await
    .unwrap();
    let stowq_core::ClaimOutcome::Claimed(claim) =
        q.claim(&claim_opts(0, 1_000), &mut budget).await.unwrap()
    else {
        panic!("claim")
    };
    // The job record vanishes without GC's ordered deletion (a torn or
    // foreign delete): the chain is orphaned and the scan must say so.
    q.store()
        .delete(&Key::new(format!(
            "q/jobs/0000/{}",
            claim
                .job_id
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        )))
        .await
        .unwrap();
    let (report, _) = repair_all(&q).await;
    assert!(report
        .findings
        .iter()
        .any(|f| f.kind == RK::ClaimWithoutJob && f.reason == 0x0005));
}

#[tokio::test]
async fn repair_reports_duplicate_terminal() {
    let q = make_queue().await;
    let mut budget = OpBudget::new(256);
    let EnqueueOutcome::Committed { job_id } = q
        .enqueue(
            EnqueueInput {
                job_id: Some([17; 16]),
                payload: b"x",
                content_type: "text/plain".into(),
                maximum_attempts: 3,
                not_before_ns: None,
            },
            &mut budget,
        )
        .await
        .unwrap()
    else {
        panic!()
    };
    // The check-then-act window's residue (recovery errata): both
    // terminal records present. Written directly, as the window would.
    use sha2::Digest as _;
    let jhex: String = job_id.iter().map(|b| format!("{b:02x}")).collect();
    for (rel, record) in [
        (
            format!("q/receipts/0000/{jhex}"),
            stowq_format::Record::Receipt(stowq_format::ReceiptRecord {
                job_id,
                generation: 1,
                attempt: 1,
                worker_id: "w".into(),
                worker_token: [1; 16],
                payload_digest: [2; 32],
                output_digests: vec![],
            }),
        ),
        (
            format!("q/dead/0000/{jhex}"),
            stowq_format::Record::Dead(stowq_format::DeadRecord {
                job_id,
                generation: 1,
                attempt: 1,
                reason: 0x0003,
            }),
        ),
    ] {
        let tag = stowq_keys::key_tag(&[1; 16], rel.trim_start_matches("q/"));
        let body = bytes::Bytes::from(stowq_format::encode(&record, &[1; 16], &tag));
        let digest: [u8; 32] = sha2::Sha256::digest(&body).into();
        q.store()
            .put_if_absent(&Key::new(rel), body, digest)
            .await
            .unwrap();
    }
    let (report, _) = repair_all(&q).await;
    assert!(report
        .findings
        .iter()
        .any(|f| f.kind == RK::DuplicateTerminal && f.reason == 0x0007));
}

#[tokio::test]
async fn repair_reports_inadmissible_takeover_basis() {
    let q = make_queue().await;
    let mut budget = OpBudget::new(256);
    let EnqueueOutcome::Committed { job_id } = q
        .enqueue(
            EnqueueInput {
                job_id: Some([18; 16]),
                payload: b"x",
                content_type: "text/plain".into(),
                maximum_attempts: 3,
                not_before_ns: None,
            },
            &mut budget,
        )
        .await
        .unwrap()
    else {
        panic!()
    };
    let stowq_core::ClaimOutcome::Claimed(first) =
        q.claim(&claim_opts(0, 1_000), &mut budget).await.unwrap()
    else {
        panic!("claim")
    };
    // A misbehaving-but-trusted writer takes over at generation 2 with
    // fabricated basis evidence: the recorded prev_store_time does not
    // match generation 1's actual store time (the tag verifies, the
    // digest verifies; only the evidence contradicts the record).
    use sha2::Digest as _;
    let rel = format!(
        "q/claims/0000/{}/00000002",
        job_id
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    let tag = stowq_keys::key_tag(&[1; 16], rel.trim_start_matches("q/"));
    let takeover = stowq_format::Record::Claim(stowq_format::ClaimRecord {
        job_id,
        generation: 2,
        attempt: 2,
        worker_id: "rogue".into(),
        worker_token: [9; 16],
        lease_duration_ns: 1_000,
        continuation: false,
        basis: Some(stowq_format::ClaimBasis {
            prev_store_time_ns: first.claim_store_time_ns + 5_000, // fabricated
            prev_duration_ns: 1_000,
            observed_watermark_ns: first.claim_store_time_ns + 6_000,
        }),
        prev_token: None,
    });
    let body = bytes::Bytes::from(stowq_format::encode(&takeover, &[1; 16], &tag));
    let digest: [u8; 32] = sha2::Sha256::digest(&body).into();
    q.store()
        .put_if_absent(&Key::new(rel), body, digest)
        .await
        .unwrap();
    let (report, _) = repair_all(&q).await;
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.kind == RK::InadmissibleClaim && f.reason == 0x0010),
        "findings: {:?}",
        report.findings
    );
}

#[tokio::test]
async fn repair_resumes_on_budget_boundary() {
    // A two-shard FORMAT with a budget that covers only the first
    // shard (an empty shard costs four list ops: jobs, claims,
    // receipts, dead): the scan returns a resume point, and continuing
    // from it covers the second shard.
    let mut f = format();
    f.shard_count = 2;
    let (q, _store) = {
        let store = MemoryStore::new();
        let q = Queue::init(Box::new(store.clone()), "q", &OpenOptions::new([1; 16]), &f)
            .await
            .unwrap();
        (q, store)
    };
    let mut budget = OpBudget::new(5);
    let (report, resume) = q.repair_scan(0, &mut budget).await.unwrap();
    assert_eq!(report.shards_scanned, 1);
    assert_eq!(resume, Some(1));
    let (report2, resume2) = q
        .repair_scan(resume.unwrap(), &mut OpBudget::new(64))
        .await
        .unwrap();
    assert_eq!(report2.shards_scanned, 1);
    assert!(resume2.is_none());
}

#[tokio::test]
async fn repair_terminates_across_the_full_shard_space() {
    // shard_count 65536 is the validated maximum: the scan must
    // complete the space and report no resume point. A u16 loop
    // counter overflows on the final increment (debug: panic;
    // release: wrap to an infinite rescan).
    let mut f = format();
    f.shard_count = 65_536;
    let q = Queue::init(
        Box::new(MemoryStore::new()),
        "q",
        &OpenOptions::new([1; 16]),
        &f,
    )
    .await
    .unwrap();
    let (report, resume) = q
        .repair_scan(65_530, &mut OpBudget::new(512))
        .await
        .unwrap();
    assert_eq!(report.shards_scanned, 6);
    assert!(resume.is_none());
}

#[tokio::test]
async fn gc_collects_orphan_payload_past_horizon() {
    // The crash window between payload PUT and job-record PUT leaves a
    // payload with no referencing job record (job record deleted here
    // to simulate; the payload was written first by enqueue).
    let mut opts = OpenOptions::new([1; 16]);
    opts.max_inline_payload = 4;
    let q = Queue::init(Box::new(MemoryStore::new()), "q", &opts, &format())
        .await
        .unwrap();
    let mut budget = OpBudget::new(256);
    let EnqueueOutcome::Committed { job_id } = q
        .enqueue(
            EnqueueInput {
                job_id: Some([19; 16]),
                payload: b"detached-orphan",
                content_type: "text/plain".into(),
                maximum_attempts: 3,
                not_before_ns: None,
            },
            &mut budget,
        )
        .await
        .unwrap()
    else {
        panic!()
    };
    let jhex: String = job_id.iter().map(|b| format!("{b:02x}")).collect();
    q.store()
        .delete(&Key::new(format!("q/jobs/0000/{jhex}")))
        .await
        .unwrap();
    // Before the horizon: kept (the enqueue may still be in flight).
    // now is the payload's own store time, so nothing is past a
    // 60-second horizon yet.
    let payload_time = {
        let items = list_all(&q, &format!("q/payloads/{jhex}/")).await;
        assert_eq!(items.len(), 1);
        q.store()
            .head(&Key::new(items[0].clone()))
            .await
            .unwrap()
            .store_time_ns
    };
    let report = q
        .gc(payload_time + 1_000, 1_000, 60_000_000_000, &mut budget)
        .await
        .unwrap();
    assert_eq!(report.orphans_deleted, 0);
    assert_eq!(list_all(&q, &format!("q/payloads/{jhex}/")).await.len(), 1);
    // Past the horizon (horizon 0): the orphan goes.
    let report = q.gc(u64::MAX / 4, 1_000, 0, &mut budget).await.unwrap();
    assert_eq!(report.orphans_deleted, 1);
    assert!(list_all(&q, &format!("q/payloads/{jhex}/"))
        .await
        .is_empty());
}

#[tokio::test]
async fn gc_never_collects_referenced_payloads() {
    let mut opts = OpenOptions::new([1; 16]);
    opts.max_inline_payload = 4;
    let q = Queue::init(Box::new(MemoryStore::new()), "q", &opts, &format())
        .await
        .unwrap();
    let mut budget = OpBudget::new(256);
    let EnqueueOutcome::Committed { job_id } = q
        .enqueue(
            EnqueueInput {
                job_id: Some([20; 16]),
                payload: b"detached-live",
                content_type: "text/plain".into(),
                maximum_attempts: 3,
                not_before_ns: None,
            },
            &mut budget,
        )
        .await
        .unwrap()
    else {
        panic!()
    };
    let jhex: String = job_id.iter().map(|b| format!("{b:02x}")).collect();
    // Horizon 0 with the job record present: the payload is referenced.
    let report = q.gc(u64::MAX / 4, 1_000, 0, &mut budget).await.unwrap();
    assert_eq!(report.orphans_deleted, 0);
    assert_eq!(list_all(&q, &format!("q/payloads/{jhex}/")).await.len(), 1);
}

#[tokio::test]
async fn gc_skips_non_parseable_payload_keys_without_collecting() {
    // A stray object under payloads/ that does not parse is a repair
    // finding, not an orphan: the pass skips it (no delete) and spends
    // no HEAD on it, whatever its age.
    let q = make_queue().await;
    use sha2::Digest as _;
    let junk = Key::new("q/payloads/deadbeef/not-hex");
    let body = bytes::Bytes::from_static(b"junk");
    let digest: [u8; 32] = sha2::Sha256::digest(&body).into();
    q.store().put_if_absent(&junk, body, digest).await.unwrap();
    let mut budget = OpBudget::new(256);
    let report = q.gc(u64::MAX / 4, 1_000, 0, &mut budget).await.unwrap();
    assert_eq!(report.orphans_deleted, 0);
    assert!(
        q.store().head(&junk).await.is_ok(),
        "non-parseable keys are left in place"
    );
}

#[tokio::test]
async fn gc_orphan_pass_propagates_head_errors() {
    // The orphan HEAD failing with anything but NotFound aborts gc
    // loudly rather than treating the error as absence.
    use stowq_store::{Fault, FaultPlan, Injector, Op};
    let inner = MemoryStore::new();
    let injector = Injector::new(
        inner,
        vec![FaultPlan::new(Op::Head, Fault::PostTransmit, [0])],
    );
    let mut opts = OpenOptions::new([1; 16]);
    opts.max_inline_payload = 4;
    let q = Queue::init(Box::new(injector), "q", &opts, &format())
        .await
        .unwrap();
    let mut budget = OpBudget::new(256);
    let EnqueueOutcome::Committed { job_id } = q
        .enqueue(
            EnqueueInput {
                job_id: Some([21; 16]),
                payload: b"detached-orphan",
                content_type: "text/plain".into(),
                maximum_attempts: 3,
                not_before_ns: None,
            },
            &mut budget,
        )
        .await
        .unwrap()
    else {
        panic!()
    };
    let jhex: String = job_id.iter().map(|b| format!("{b:02x}")).collect();
    q.store()
        .delete(&Key::new(format!("q/jobs/0000/{jhex}")))
        .await
        .unwrap();
    // Now 0 with a zero horizon: the payload is due, the first orphan
    // HEAD is faulted post-transmit, and gc must surface the unknown
    // outcome instead of deleting anything.
    let result = q.gc(u64::MAX / 4, 1_000, 0, &mut OpBudget::new(256)).await;
    match result {
        Err(stowq_core::Error::Store(stowq_store::StoreError::OutcomeUnknown(_))) => {}
        other => panic!("expected OutcomeUnknown, got {other:?}"),
    }
    // The payload is untouched: absence of the job record was never
    // proven with a clean read.
    assert_eq!(list_all(&q, &format!("q/payloads/{jhex}/")).await.len(), 1);
}

#[tokio::test]
async fn enqueue_caps_inline_at_the_queues_format_limit() {
    // The client's setting is an upper bound request; the queue's
    // FORMAT inline_limit is the contract. A 64 KiB-capable client on
    // a queue declaring 8 bytes must detach anything larger.
    let mut opts = OpenOptions::new([1; 16]);
    opts.max_inline_payload = 65_536;
    let mut f = format();
    f.inline_limit = 8;
    let q = Queue::init(Box::new(MemoryStore::new()), "q", &opts, &f)
        .await
        .unwrap();
    let mut budget = OpBudget::new(64);
    let EnqueueOutcome::Committed { job_id } = q
        .enqueue(
            EnqueueInput {
                job_id: Some([22; 16]),
                payload: b"0123456789",
                content_type: "text/plain".into(),
                maximum_attempts: 3,
                not_before_ns: None,
            },
            &mut budget,
        )
        .await
        .unwrap()
    else {
        panic!()
    };
    let jhex: String = job_id.iter().map(|b| format!("{b:02x}")).collect();
    // The payload went detached despite the client's 64 KiB setting.
    assert_eq!(
        list_all(&q, &format!("q/payloads/{jhex}/")).await.len(),
        1,
        "payload must detach above the FORMAT inline_limit"
    );
}

// ---------- Deep admissibility audit ----------

#[tokio::test]
async fn repair_audits_a_legitimate_deep_chain_clean() {
    // The false-positive guard: claim -> renew -> expiry takeover ->
    // renew, all through the real paths, must produce zero findings —
    // every writer-encoded basis and custody token audited against the
    // store-time record.
    let q = make_queue().await;
    let mut budget = OpBudget::new(512);
    q.enqueue(
        EnqueueInput {
            job_id: Some([23; 16]),
            payload: b"x",
            content_type: "text/plain".into(),
            maximum_attempts: 5,
            not_before_ns: None,
        },
        &mut budget,
    )
    .await
    .unwrap();
    let stowq_core::ClaimOutcome::Claimed(first) =
        q.claim(&claim_opts(0, 1_000), &mut budget).await.unwrap()
    else {
        panic!("claim")
    };
    let stowq_core::RenewOutcome::Renewed(second) = q.renew(&first, &mut budget).await.unwrap()
    else {
        panic!("renew")
    };
    // Expiry takeover by a fresh floor past second's lease.
    let later = second.claim_store_time_ns + 2_000;
    let stowq_core::ClaimOutcome::Claimed(third) = q
        .claim(&claim_opts(later, 1_000), &mut budget)
        .await
        .unwrap()
    else {
        panic!("takeover")
    };
    let stowq_core::RenewOutcome::Renewed(fourth) = q.renew(&third, &mut budget).await.unwrap()
    else {
        panic!("renew 2")
    };
    assert_eq!(fourth.generation, 4);
    let (report, _) = repair_all(&q).await;
    assert!(
        report.findings.is_empty(),
        "legitimate chain audited dirty: {:?}",
        report.findings
    );
}

#[tokio::test]
async fn repair_flags_forged_continuation_token() {
    // A continuation whose prev_token does not match the previous
    // generation: inadmissible custody. The old tail-only check never
    // saw this (the tail was a continuation, not a takeover).
    let q = make_queue().await;
    let mut budget = OpBudget::new(256);
    let EnqueueOutcome::Committed { job_id } = q
        .enqueue(
            EnqueueInput {
                job_id: Some([24; 16]),
                payload: b"x",
                content_type: "text/plain".into(),
                maximum_attempts: 3,
                not_before_ns: None,
            },
            &mut budget,
        )
        .await
        .unwrap()
    else {
        panic!()
    };
    let stowq_core::ClaimOutcome::Claimed(first) =
        q.claim(&claim_opts(0, 1_000), &mut budget).await.unwrap()
    else {
        panic!("claim")
    };
    // A forged renewal: correct worker shape, wrong custody token.
    use sha2::Digest as _;
    let jhex: String = job_id.iter().map(|b| format!("{b:02x}")).collect();
    let rel = format!("q/claims/0000/{jhex}/00000002");
    let tag = stowq_keys::key_tag(&[1; 16], rel.trim_start_matches("q/"));
    let forged = stowq_format::Record::Claim(stowq_format::ClaimRecord {
        job_id,
        generation: 2,
        attempt: first.attempt,
        worker_id: "worker-1".into(),
        worker_token: [7; 16],
        lease_duration_ns: 1_000,
        continuation: true,
        basis: None,
        prev_token: Some([8; 16]), // not generation 1's token
    });
    let body = bytes::Bytes::from(stowq_format::encode(&forged, &[1; 16], &tag));
    let digest: [u8; 32] = sha2::Sha256::digest(&body).into();
    q.store()
        .put_if_absent(&Key::new(rel), body, digest)
        .await
        .unwrap();
    let (report, _) = repair_all(&q).await;
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.kind == RK::InadmissibleClaim && f.reason == 0x0010),
        "findings: {:?}",
        report.findings
    );
}

#[tokio::test]
async fn repair_flags_watermark_inequality_in_basis() {
    // A takeover whose basis names the correct previous store time and
    // duration, but claims an observed watermark BEFORE that lease
    // expired: inadmissible takeover evidence.
    let q = make_queue().await;
    let mut budget = OpBudget::new(256);
    let EnqueueOutcome::Committed { job_id } = q
        .enqueue(
            EnqueueInput {
                job_id: Some([25; 16]),
                payload: b"x",
                content_type: "text/plain".into(),
                maximum_attempts: 3,
                not_before_ns: None,
            },
            &mut budget,
        )
        .await
        .unwrap()
    else {
        panic!()
    };
    let stowq_core::ClaimOutcome::Claimed(first) =
        q.claim(&claim_opts(0, 60_000), &mut budget).await.unwrap()
    else {
        panic!("claim")
    };
    use sha2::Digest as _;
    let jhex: String = job_id.iter().map(|b| format!("{b:02x}")).collect();
    let rel = format!("q/claims/0000/{jhex}/00000002");
    let tag = stowq_keys::key_tag(&[1; 16], rel.trim_start_matches("q/"));
    let forged = stowq_format::Record::Claim(stowq_format::ClaimRecord {
        job_id,
        generation: 2,
        attempt: 2,
        worker_id: "rogue".into(),
        worker_token: [9; 16],
        lease_duration_ns: 60_000,
        continuation: false,
        basis: Some(stowq_format::ClaimBasis {
            prev_store_time_ns: first.claim_store_time_ns, // correct
            prev_duration_ns: 60_000,                      // correct
            observed_watermark_ns: first.claim_store_time_ns + 1, // before expiry
        }),
        prev_token: None,
    });
    let body = bytes::Bytes::from(stowq_format::encode(&forged, &[1; 16], &tag));
    let digest: [u8; 32] = sha2::Sha256::digest(&body).into();
    q.store()
        .put_if_absent(&Key::new(rel), body, digest)
        .await
        .unwrap();
    let (report, _) = repair_all(&q).await;
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.kind == RK::InadmissibleClaim),
        "findings: {:?}",
        report.findings
    );
}

#[tokio::test]
async fn repair_flags_generation_gap() {
    // A foreign delete of a middle generation leaves a gap: an
    // impossible state the audit must name.
    let q = make_queue().await;
    let mut budget = OpBudget::new(256);
    q.enqueue(
        EnqueueInput {
            job_id: Some([26; 16]),
            payload: b"x",
            content_type: "text/plain".into(),
            maximum_attempts: 5,
            not_before_ns: None,
        },
        &mut budget,
    )
    .await
    .unwrap();
    let stowq_core::ClaimOutcome::Claimed(first) =
        q.claim(&claim_opts(0, 1_000), &mut budget).await.unwrap()
    else {
        panic!("claim")
    };
    let stowq_core::RenewOutcome::Renewed(second) = q.renew(&first, &mut budget).await.unwrap()
    else {
        panic!("renew")
    };
    let later = second.claim_store_time_ns + 2_000;
    let stowq_core::ClaimOutcome::Claimed(third) = q
        .claim(&claim_opts(later, 1_000), &mut budget)
        .await
        .unwrap()
    else {
        panic!("takeover")
    };
    assert_eq!(third.generation, 3);
    let jhex: String = third.job_id.iter().map(|b| format!("{b:02x}")).collect();
    q.store()
        .delete(&Key::new(format!("q/claims/0000/{jhex}/00000002")))
        .await
        .unwrap();
    let (report, _) = repair_all(&q).await;
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.kind == RK::ChainGap && f.reason == 0x0015),
        "findings: {:?}",
        report.findings
    );
}

#[tokio::test]
async fn repair_flags_headless_chain() {
    // Foreign delete of generation 1: the chain's first listed
    // generation is not 1 — the head branch of the gap check, distinct
    // from the mid-chain windows branch.
    let q = make_queue().await;
    let mut budget = OpBudget::new(256);
    q.enqueue(
        EnqueueInput {
            job_id: Some([27; 16]),
            payload: b"x",
            content_type: "text/plain".into(),
            maximum_attempts: 5,
            not_before_ns: None,
        },
        &mut budget,
    )
    .await
    .unwrap();
    let stowq_core::ClaimOutcome::Claimed(first) =
        q.claim(&claim_opts(0, 1_000), &mut budget).await.unwrap()
    else {
        panic!("claim")
    };
    let stowq_core::RenewOutcome::Renewed(second) = q.renew(&first, &mut budget).await.unwrap()
    else {
        panic!("renew")
    };
    let jhex: String = second.job_id.iter().map(|b| format!("{b:02x}")).collect();
    q.store()
        .delete(&Key::new(format!("q/claims/0000/{jhex}/00000001")))
        .await
        .unwrap();
    let (report, _) = repair_all(&q).await;
    let head = report
        .findings
        .iter()
        .find(|f| f.kind == RK::ChainGap)
        .expect("head gap must be flagged");
    assert!(
        head.key.ends_with("/00000002"),
        "keyed at the head: {}",
        head.key
    );
    // The remaining 2..=2 chain is otherwise sound: continuation
    // evidence still matches, no InadmissibleClaim.
    assert!(
        !report
            .findings
            .iter()
            .any(|f| f.kind == RK::InadmissibleClaim),
        "findings: {:?}",
        report.findings
    );
}

#[tokio::test]
async fn repair_audits_around_a_corrupt_middle_generation() {
    // An undecodable middle record must not produce spurious
    // inadmissibility on its neighbors: the evidence check skips
    // pairs with an undecoded side, and the chain audits around the
    // corruption (the corrupt record itself is a RecordCorrupt
    // finding).
    let q = make_queue().await;
    let mut budget = OpBudget::new(256);
    q.enqueue(
        EnqueueInput {
            job_id: Some([28; 16]),
            payload: b"x",
            content_type: "text/plain".into(),
            maximum_attempts: 5,
            not_before_ns: None,
        },
        &mut budget,
    )
    .await
    .unwrap();
    let stowq_core::ClaimOutcome::Claimed(first) =
        q.claim(&claim_opts(0, 1_000), &mut budget).await.unwrap()
    else {
        panic!("claim")
    };
    let stowq_core::RenewOutcome::Renewed(second) = q.renew(&first, &mut budget).await.unwrap()
    else {
        panic!("renew")
    };
    let later = second.claim_store_time_ns + 2_000;
    let stowq_core::ClaimOutcome::Claimed(third) = q
        .claim(&claim_opts(later, 1_000), &mut budget)
        .await
        .unwrap()
    else {
        panic!("takeover")
    };
    assert_eq!(third.generation, 3);
    let jhex: String = third.job_id.iter().map(|b| format!("{b:02x}")).collect();
    // Corrupt generation 2's body in place: delete, then write garbage
    // with a self-consistent digest (the store verifies PUT digests).
    let k = Key::new(format!("q/claims/0000/{jhex}/00000002"));
    q.store().delete(&k).await.unwrap();
    use sha2::Digest as _;
    let junk = bytes::Bytes::from_static(b"garbage-not-a-record");
    let digest: [u8; 32] = sha2::Sha256::digest(&junk).into();
    q.store().put_if_absent(&k, junk, digest).await.unwrap();
    let (report, _) = repair_all(&q).await;
    // The corruption is named...
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.kind == RK::RecordCorrupt && f.key.ends_with("/00000002")),
        "findings: {:?}",
        report.findings
    );
    // ...and nothing spurious fires around it: the takeover at
    // generation 3 has an undecoded predecessor, so its evidence is
    // skipped, not judged.
    assert!(
        !report
            .findings
            .iter()
            .any(|f| f.kind == RK::InadmissibleClaim),
        "findings: {:?}",
        report.findings
    );
}

// ---------- Watermark-raised floors (Option D) ----------

#[tokio::test]
async fn establish_floor_raises_to_the_watermark_bucket() {
    // A watermark above the fresh beacon but within the skew guard:
    // the gate passes on the raw beacon, and the returned floor is
    // raised to the watermark bucket — a proven lower bound, never a
    // regression mask.
    let mut opts = OpenOptions::new([1; 16]);
    opts.skew_guard_ns = 10_000_000_000;
    let q = Queue::init(Box::new(MemoryStore::new()), "q", &opts, &format())
        .await
        .unwrap();
    let mut budget = OpBudget::new(256);
    // delayed width 1000: floor 5_000_000 -> bucket 5000 -> wm 5_000_000.
    q.advance_watermark(5_000_000, &mut budget).await.unwrap();
    let f = q.establish_floor(&mut budget).await.unwrap();
    assert_eq!(f, 5_000_000, "floor raised to the watermark bucket");
    // The cached repeat returns the raised value.
    assert_eq!(q.establish_floor(&mut budget).await.unwrap(), 5_000_000);
}

#[tokio::test]
async fn raised_floor_evaluates_expiry_as_a_normal_floor() {
    // The raised floor is a valid lower bound: a takeover evaluated
    // against it must behave exactly as a beacon floor would, and a
    // fresh handle over the same store inherits the raise. The
    // constants matter: the raise is bounded by skew_guard above the
    // beacon, and expiry needs floor >= claim_time + lease + skew_guard,
    // so the beacon must land at least one lease after the claim.
    let mut opts = OpenOptions::new([1; 16]);
    opts.skew_guard_ns = 1_000_000;
    let store = MemoryStore::new();
    let q = Queue::init(Box::new(store.clone()), "q", &opts, &format())
        .await
        .unwrap();
    let mut budget = OpBudget::new(256);
    q.enqueue(
        EnqueueInput {
            job_id: Some([29; 16]),
            payload: b"x",
            content_type: "text/plain".into(),
            maximum_attempts: 3,
            not_before_ns: None,
        },
        &mut budget,
    )
    .await
    .unwrap();
    let stowq_core::ClaimOutcome::Claimed(first) =
        q.claim(&claim_opts(0, 1_000), &mut budget).await.unwrap()
    else {
        panic!("claim")
    };
    // Advance store time a lease-length past the claim so the beacon
    // clears T1 + lease; then a watermark 50_000 above the guard.
    store.advance_clock_to(first.claim_store_time_ns + 100_000);
    q.advance_watermark(1_050_000, &mut budget).await.unwrap();
    let raised = q.establish_floor(&mut budget).await.unwrap();
    assert_eq!(raised, 1_050_000);
    let stowq_core::ClaimOutcome::Claimed(second) = q
        .claim(&claim_opts(raised, 1_000), &mut budget)
        .await
        .unwrap()
    else {
        panic!("takeover at the raised floor")
    };
    assert_eq!(second.generation, 2);
    // A lower advance is a no-op, and a FRESH handle over the same
    // store still raises to the stored bucket: the watermark is
    // shared state, so floors never go down across participants.
    q.advance_watermark(1_000, &mut budget).await.unwrap();
    let q2 = Queue::open(Box::new(store), "q", opts).await.unwrap();
    assert_eq!(
        q2.establish_floor(&mut OpBudget::new(64)).await.unwrap(),
        1_050_000
    );
}

// ---------- v1.1 quarantine writes ----------

fn v11_format() -> FormatRecord {
    let mut f = format();
    f.required_feature_bits = 1;
    f
}

async fn list_prefix(q: &Queue, prefix: &str) -> Vec<String> {
    list_all(q, prefix).await
}

#[tokio::test]
async fn repair_writes_quarantine_on_v11_queues() {
    use sha2::Digest as _;
    let q = Queue::init(
        Box::new(MemoryStore::new()),
        "q",
        &OpenOptions::new([1; 16]),
        &v11_format(),
    )
    .await
    .unwrap();
    let mut budget = OpBudget::new(256);
    let EnqueueOutcome::Committed { job_id } = q
        .enqueue(
            EnqueueInput {
                job_id: Some([30; 16]),
                payload: b"x",
                content_type: "text/plain".into(),
                maximum_attempts: 3,
                not_before_ns: None,
            },
            &mut budget,
        )
        .await
        .unwrap()
    else {
        panic!()
    };
    let jhex: String = job_id.iter().map(|b| format!("{b:02x}")).collect();
    // Corrupt the job record in place: delete, write self-consistent
    // garbage (the store verifies PUT digests).
    let k = Key::new(format!("q/jobs/0000/{jhex}"));
    q.store().delete(&k).await.unwrap();
    let junk = bytes::Bytes::from_static(b"garbage");
    let digest: [u8; 32] = sha2::Sha256::digest(&junk).into();
    q.store().put_if_absent(&k, junk, digest).await.unwrap();
    let garbage_time = q.store().head(&k).await.unwrap().store_time_ns;

    let (report, _) = repair_all(&q).await;
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.kind == RK::RecordCorrupt && f.reason == 0x0001),
        "findings: {:?}",
        report.findings
    );
    // Exactly one quarantine entry, with the deterministic fields.
    let entries = list_prefix(&q, "q/quarantine/").await;
    assert_eq!(entries.len(), 1, "one entry per (source, reason)");
    let rel: stowq_keys::Key = entries[0]
        .trim_start_matches("q/")
        .parse()
        .expect("quarantine key parses");
    let tag = stowq_keys::key_tag(&[1; 16], &rel.to_string());
    let obj = q
        .store()
        .get(&Key::new(entries[0].clone()), None)
        .await
        .unwrap();
    let rec = match stowq_format::decode(&obj.body, &[1; 16], &tag).unwrap() {
        stowq_format::Record::Quarantine(r) => r,
        other => panic!("expected quarantine, got {other:?}"),
    };
    let expected_rel = format!("jobs/0000/{jhex}");
    assert_eq!(rec.source_key, expected_rel);
    assert_eq!(rec.reason, 0x0001);
    assert_eq!(rec.observed_store_ns, garbage_time);
    assert_eq!(rec.detail, None);
    // Deterministic qid: the domain-separated formula.
    let mut h = sha2::Sha256::new();
    h.update(b"StowQ-1-qid\0");
    h.update([1u8; 16]);
    h.update(expected_rel.as_bytes());
    h.update(0x0001u64.to_be_bytes());
    let want: [u8; 16] = h.finalize()[..16].try_into().unwrap();
    assert_eq!(rec.qid, want);
    match rel {
        stowq_keys::Key::Quarantine { qid, .. } => assert_eq!(qid, want),
        other => panic!("parsed wrong key shape: {other:?}"),
    }
    // Idempotent convergence: a second audit run writes nothing new.
    let (_, _) = repair_all(&q).await;
    assert_eq!(list_prefix(&q, "q/quarantine/").await.len(), 1);
}

#[tokio::test]
async fn repair_writes_nothing_on_v1_queues() {
    use sha2::Digest as _;
    let q = make_queue().await;
    let mut budget = OpBudget::new(256);
    let EnqueueOutcome::Committed { job_id } = q
        .enqueue(
            EnqueueInput {
                job_id: Some([31; 16]),
                payload: b"x",
                content_type: "text/plain".into(),
                maximum_attempts: 3,
                not_before_ns: None,
            },
            &mut budget,
        )
        .await
        .unwrap()
    else {
        panic!()
    };
    let jhex: String = job_id.iter().map(|b| format!("{b:02x}")).collect();
    let k = Key::new(format!("q/jobs/0000/{jhex}"));
    q.store().delete(&k).await.unwrap();
    let junk = bytes::Bytes::from_static(b"garbage");
    let digest: [u8; 32] = sha2::Sha256::digest(&junk).into();
    q.store().put_if_absent(&k, junk, digest).await.unwrap();
    let (report, _) = repair_all(&q).await;
    assert!(report.findings.iter().any(|f| f.kind == RK::RecordCorrupt));
    assert!(
        list_prefix(&q, "q/quarantine/").await.is_empty(),
        "v1 queues write nothing"
    );
}

#[tokio::test]
async fn repair_reports_and_quarantines_missing_referenced_payload() {
    let mut opts = OpenOptions::new([1; 16]);
    opts.max_inline_payload = 4;
    let q = Queue::init(Box::new(MemoryStore::new()), "q", &opts, &v11_format())
        .await
        .unwrap();
    let mut budget = OpBudget::new(256);
    let EnqueueOutcome::Committed { job_id } = q
        .enqueue(
            EnqueueInput {
                job_id: Some([32; 16]),
                payload: b"detached",
                content_type: "text/plain".into(),
                maximum_attempts: 3,
                not_before_ns: None,
            },
            &mut budget,
        )
        .await
        .unwrap()
    else {
        panic!()
    };
    let jhex: String = job_id.iter().map(|b| format!("{b:02x}")).collect();
    // Delete ONLY the payload: the job record references it (0x0014 —
    // distinct from gc's orphan direction, which deletes the job).
    let payload_key = list_prefix(&q, &format!("q/payloads/{jhex}/"))
        .await
        .into_iter()
        .next()
        .expect("payload exists");
    q.store()
        .delete(&Key::new(payload_key.clone()))
        .await
        .unwrap();
    let job_time = q
        .store()
        .head(&Key::new(format!("q/jobs/0000/{jhex}")))
        .await
        .unwrap()
        .store_time_ns;

    let (report, _) = repair_all(&q).await;
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.kind == RK::PayloadMissing && f.reason == 0x0014),
        "findings: {:?}",
        report.findings
    );
    let entries = list_prefix(&q, "q/quarantine/").await;
    assert_eq!(entries.len(), 1);
    let rel: stowq_keys::Key = entries[0].trim_start_matches("q/").parse().unwrap();
    let tag = stowq_keys::key_tag(&[1; 16], &rel.to_string());
    let obj = q
        .store()
        .get(&Key::new(entries[0].clone()), None)
        .await
        .unwrap();
    let rec = match stowq_format::decode(&obj.body, &[1; 16], &tag).unwrap() {
        stowq_format::Record::Quarantine(r) => r,
        other => panic!("expected quarantine, got {other:?}"),
    };
    assert_eq!(rec.reason, 0x0014);
    assert_eq!(rec.observed_store_ns, job_time);
    let payload_rel = payload_key.trim_start_matches("q/").to_string();
    assert_eq!(rec.source_key, payload_rel);
}

// ---------- commit rule: commit_output + ack_with_outputs ----------

/// Enqueues one job and claims it; the standard preamble for the
/// commit-rule tests.
async fn claimed_job(q: &Queue) -> ([u8; 16], stowq_core::Claim) {
    let mut budget = OpBudget::new(128);
    let EnqueueOutcome::Committed { job_id } = q
        .enqueue(
            EnqueueInput {
                job_id: None,
                payload: b"work",
                content_type: "text/plain".into(),
                maximum_attempts: 3,
                not_before_ns: None,
            },
            &mut budget,
        )
        .await
        .unwrap()
    else {
        panic!("commit")
    };
    let stowq_core::ClaimOutcome::Claimed(claim) = q
        .claim(&claim_opts(0, 60_000_000_000), &mut budget)
        .await
        .unwrap()
    else {
        panic!("claim")
    };
    (job_id, claim)
}

fn jhex16(id: &[u8; 16]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

#[tokio::test]
async fn commit_output_then_ack_with_outputs_records_digests() {
    let q = make_queue().await;
    let (job_id, claim) = claimed_job(&q).await;
    let mut budget = OpBudget::new(128);
    let out = q
        .commit_output(
            &claim,
            "result.bin",
            bytes::Bytes::from_static(b"OUT"),
            &mut budget,
        )
        .await
        .unwrap();
    let committed = match &out {
        stowq_core::CommitOutcome::Committed(c) => c.clone(),
        other => panic!("first commit must win, got {other:?}"),
    };
    assert_eq!(
        committed.key,
        format!("q/outputs/{}/result.bin", jhex16(&job_id))
    );
    let ack = q
        .ack_with_outputs(&claim, &[committed], &mut budget)
        .await
        .unwrap();
    assert_eq!(ack, stowq_core::AckOutcome::Acked);
    // The receipt records the output digest; the output object exists.
    let rel = format!("receipts/0000/{}", jhex16(&job_id));
    let obj = q
        .store()
        .get(&Key::new(format!("q/{rel}")), None)
        .await
        .unwrap();
    let tag = stowq_keys::key_tag(&[1; 16], &rel);
    let stowq_format::Record::Receipt(r) = stowq_format::decode(&obj.body, &[1; 16], &tag).unwrap()
    else {
        panic!("receipt")
    };
    assert_eq!(r.output_digests.len(), 1);
    let got: [u8; 32] = sha2::Sha256::digest(b"OUT").into();
    assert_eq!(r.output_digests[0], got);
}

#[tokio::test]
async fn duplicate_commit_converges_on_first_wins_bytes() {
    let q = make_queue().await;
    let (_job_id, claim) = claimed_job(&q).await;
    let mut budget = OpBudget::new(128);
    let first = q
        .commit_output(
            &claim,
            "r",
            bytes::Bytes::from_static(b"first"),
            &mut budget,
        )
        .await
        .unwrap();
    assert!(matches!(first, stowq_core::CommitOutcome::Committed(_)));
    let before = q
        .store()
        .head(&Key::new(format!("q/outputs/{}/r", jhex16(&_job_id))))
        .await
        .unwrap();
    // A duplicate attempt with identical deterministic bytes converges.
    let second = q
        .commit_output(
            &claim,
            "r",
            bytes::Bytes::from_static(b"first"),
            &mut budget,
        )
        .await
        .unwrap();
    let conv = match second {
        stowq_core::CommitOutcome::Converged(c) => c,
        other => panic!("duplicate must converge, got {other:?}"),
    };
    assert_eq!(conv.key, format!("q/outputs/{}/r", jhex16(&_job_id)));
    // First-wins: no rewrite, so version and store time are unchanged.
    let after = q.store().head(&Key::new(conv.key)).await.unwrap();
    assert_eq!(before.version, after.version);
    assert_eq!(before.store_time_ns, after.store_time_ns);
}

#[tokio::test]
async fn conflicting_commit_bytes_is_output_conflict() {
    let q = make_queue().await;
    let (job_id, claim) = claimed_job(&q).await;
    let mut budget = OpBudget::new(128);
    q.commit_output(&claim, "r", bytes::Bytes::from_static(b"mine"), &mut budget)
        .await
        .unwrap();
    let err = q
        .commit_output(
            &claim,
            "r",
            bytes::Bytes::from_static(b"theirs"),
            &mut budget,
        )
        .await
        .unwrap_err();
    // 0x0011 semantics: the error carries the first-wins digest.
    let expected: [u8; 32] = sha2::Sha256::digest(b"mine").into();
    match err {
        Error::OutputConflict(d) => assert_eq!(d, expected),
        other => panic!("expected OutputConflict, got {other:?}"),
    }
    // The store keeps the first-wins bytes.
    let obj = q
        .store()
        .get(&Key::new(format!("q/outputs/{}/r", jhex16(&job_id))), None)
        .await
        .unwrap();
    assert_eq!(&obj.body[..], b"mine");
}

#[tokio::test]
async fn ack_with_outputs_refuses_when_output_is_absent_or_corrupt() {
    let q = make_queue().await;
    let (job_id, claim) = claimed_job(&q).await;
    let mut budget = OpBudget::new(256);
    let committed = match q
        .commit_output(
            &claim,
            "r",
            bytes::Bytes::from_static(b"final"),
            &mut budget,
        )
        .await
        .unwrap()
    {
        stowq_core::CommitOutcome::Committed(c) => c,
        other => panic!("{other:?}"),
    };
    let key = Key::new(committed.key.clone());
    // Absent: fail closed, no receipt.
    q.store().delete(&key).await.unwrap();
    let err = q
        .ack_with_outputs(&claim, std::slice::from_ref(&committed), &mut budget)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::OutputEvidenceMismatch(_)), "{err:?}");
    // Corrupt: different bytes at the key, same failure class.
    let d: [u8; 32] = sha2::Sha256::digest(b"tampered").into();
    q.store()
        .put_if_absent(&key, bytes::Bytes::from_static(b"tampered"), d)
        .await
        .unwrap();
    let err = q
        .ack_with_outputs(&claim, &[committed], &mut budget)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::OutputEvidenceMismatch(_)), "{err:?}");
    // No receipt exists: the terminal write never happened.
    assert_eq!(
        q.store()
            .head(&Key::new(format!("q/receipts/0000/{}", jhex16(&job_id))))
            .await
            .unwrap_err(),
        StoreError::NotFound
    );
}

#[tokio::test]
async fn reack_with_outputs_verifies_recorded_digests() {
    let q = make_queue().await;
    let (_job_id, claim) = claimed_job(&q).await;
    let mut budget = OpBudget::new(256);
    let committed = match q
        .commit_output(&claim, "r", bytes::Bytes::from_static(b"done"), &mut budget)
        .await
        .unwrap()
    {
        stowq_core::CommitOutcome::Committed(c) => c,
        other => panic!("{other:?}"),
    };
    assert_eq!(
        q.ack_with_outputs(&claim, std::slice::from_ref(&committed), &mut budget)
            .await
            .unwrap(),
        stowq_core::AckOutcome::Acked
    );
    // Idempotent re-ack with the same evidence.
    assert_eq!(
        q.ack_with_outputs(&claim, std::slice::from_ref(&committed), &mut budget)
            .await
            .unwrap(),
        stowq_core::AckOutcome::AlreadyAcked
    );
    // A plain ack cannot verify the recorded outputs' evidence.
    match q.ack(&claim, &mut budget).await {
        Err(Error::ReceiptEvidenceMismatch) => {}
        other => panic!("expected ReceiptEvidenceMismatch, got {other:?}"),
    }
}

#[tokio::test]
async fn invalid_output_names_are_rejected() {
    let q = make_queue().await;
    let (_job_id, claim) = claimed_job(&q).await;
    let mut budget = OpBudget::new(64);
    for bad in ["", "/abs", "../escape", "a//b", "a/../b", "."] {
        let err = q
            .commit_output(&claim, bad, bytes::Bytes::new(), &mut budget)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Key(_)), "{bad}: {err:?}");
    }
}

#[tokio::test]
async fn ack_rejects_another_jobs_output() {
    let q = make_queue().await;
    let (_id_a, claim_a) = claimed_job(&q).await;
    let (id_b, claim_b) = claimed_job(&q).await;
    let mut budget = OpBudget::new(256);
    // B commits an output; A attempts to record it on A's receipt.
    let b_out = match q
        .commit_output(&claim_b, "r", bytes::Bytes::from_static(b"b"), &mut budget)
        .await
        .unwrap()
    {
        stowq_core::CommitOutcome::Committed(c) => c,
        other => panic!("{other:?}"),
    };
    match q.ack_with_outputs(&claim_a, &[b_out], &mut budget).await {
        Err(Error::Key(_)) => {}
        other => panic!("expected Error::Key, got {other:?}"),
    }
    // No receipt for A: the terminal write never happened.
    assert_eq!(
        q.store()
            .head(&Key::new(format!("q/receipts/0000/{}", jhex16(&_id_a))))
            .await
            .unwrap_err(),
        StoreError::NotFound
    );
    let _ = id_b;
}

#[tokio::test]
async fn committed_output_persists_without_a_receipt() {
    let q = make_queue().await;
    let (job_id, claim) = claimed_job(&q).await;
    let mut budget = OpBudget::new(256);
    let committed = match q
        .commit_output(&claim, "r", bytes::Bytes::from_static(b"won"), &mut budget)
        .await
        .unwrap()
    {
        stowq_core::CommitOutcome::Committed(c) => c,
        other => panic!("{other:?}"),
    };
    // Nack instead of ack: the job returns to backoff, no receipt.
    let floor = q.establish_floor(&mut budget).await.unwrap();
    q.nack(&claim, 1, floor, &mut budget).await.unwrap();
    assert_eq!(
        q.store()
            .head(&Key::new(format!("q/receipts/0000/{}", jhex16(&job_id))))
            .await
            .unwrap_err(),
        StoreError::NotFound
    );
    // The output is durable first-wins state: still present, unchanged.
    let obj = q.store().get(&Key::new(committed.key), None).await.unwrap();
    assert_eq!(&obj.body[..], b"won");
}

// ---------- claim-scan terminality memo ----------

/// Counts head calls per job hex: terminal-probe attribution for the
/// memo tests (scan heads for the backlog ids must vanish; the live
/// id pays its receipt+dead probes).
struct CountHeads {
    inner: MemoryStore,
    watched: Vec<String>,
    counts: std::sync::Arc<std::sync::Mutex<Vec<u64>>>,
}

#[async_trait::async_trait]
impl stowq_store::ObjectStore for CountHeads {
    async fn put_if_absent(
        &self,
        key: &Key,
        body: bytes::Bytes,
        sha256: [u8; 32],
    ) -> stowq_store::StoreResult<stowq_store::PutOutcome> {
        self.inner.put_if_absent(key, body, sha256).await
    }
    async fn cas(
        &self,
        key: &Key,
        body: bytes::Bytes,
        sha256: [u8; 32],
        if_match: &stowq_store::Version,
    ) -> stowq_store::StoreResult<stowq_store::PutOutcome> {
        self.inner.cas(key, body, sha256, if_match).await
    }
    async fn get(
        &self,
        key: &Key,
        range: Option<std::ops::Range<u64>>,
    ) -> stowq_store::StoreResult<stowq_store::Object> {
        self.inner.get(key, range).await
    }
    async fn head(&self, key: &Key) -> stowq_store::StoreResult<stowq_store::Meta> {
        {
            let k = key.as_str();
            let mut counts = self.counts.lock().unwrap();
            for (i, w) in self.watched.iter().enumerate() {
                if k.contains(w) {
                    counts[i] += 1;
                }
            }
        }
        self.inner.head(key).await
    }
    async fn list(
        &self,
        prefix: &str,
        after: Option<&Key>,
        limit: usize,
    ) -> stowq_store::StoreResult<stowq_store::Page> {
        self.inner.list(prefix, after, limit).await
    }
    async fn delete(&self, key: &Key) -> stowq_store::StoreResult<()> {
        self.inner.delete(key).await
    }
}

/// The memo: after this handle proves jobs terminal, later scans skip
/// their receipt/dead heads; a fresh handle pays the full scan; a live
/// job behind the backlog is still found.
#[tokio::test]
async fn terminal_backlog_scan_is_memoized_per_handle() {
    struct Fixture;

    impl Fixture {
        async fn enqueue(q: &Queue, id: [u8; 16]) {
            let mut b = OpBudget::new(64);
            let out = q
                .enqueue(
                    EnqueueInput {
                        job_id: Some(id),
                        payload: b"x",
                        content_type: "text/plain".into(),
                        maximum_attempts: 3,
                        not_before_ns: None,
                    },
                    &mut b,
                )
                .await
                .unwrap();
            assert!(matches!(out, EnqueueOutcome::Committed { .. }));
        }
    }

    let backlog: Vec<String> = (0..5u8)
        .map(|i| ([i; 16]).iter().map(|b| format!("{b:02x}")).collect())
        .collect();
    let live: String = [0xAAu8; 16].iter().map(|b| format!("{b:02x}")).collect();
    let watched = backlog
        .iter()
        .cloned()
        .chain([live.clone()])
        .collect::<Vec<_>>();

    fn delta_since(
        counts: &std::sync::Arc<std::sync::Mutex<Vec<u64>>>,
        before: &[u64],
    ) -> Vec<u64> {
        // Scoped: the guard drops before any later store call can
        // re-lock it (head tallies inside CountHeads share the mutex).
        let now = counts.lock().unwrap();
        now.iter().zip(before).map(|(a, b)| a - b).collect()
    }
    let mem = MemoryStore::new();
    let counts = Arc::new(std::sync::Mutex::new(vec![0u64; watched.len()]));
    let q = Queue::init(
        Box::new(CountHeads {
            inner: mem.clone(),
            watched: watched.clone(),
            counts: counts.clone(),
        }),
        "q",
        &OpenOptions::new([1; 16]),
        &format(),
    )
    .await
    .unwrap();

    // A backlog of 5 acked jobs.
    for i in 0..5u8 {
        Fixture::enqueue(&q, [i; 16]).await;
        let mut b = OpBudget::new(512);
        let ClaimOutcome::Claimed(c) = q
            .claim(&claim_opts(0, 60_000_000_000), &mut b)
            .await
            .unwrap()
        else {
            panic!("claim {i}")
        };
        q.ack(&c, &mut b).await.unwrap();
    }

    // One live job behind the backlog.
    Fixture::enqueue(&q, [0xAA; 16]).await;
    let mut b = OpBudget::new(512);
    let before: Vec<u64> = counts.lock().unwrap().clone();
    let ClaimOutcome::Claimed(c) = q
        .claim(&claim_opts(0, 60_000_000_000), &mut b)
        .await
        .unwrap()
    else {
        panic!("live job behind backlog must be found")
    };
    assert_eq!(c.job_id, [0xAA; 16]);
    // Memoization is lazy (proves on first post-terminal encounter):
    // jobs 0-3 were encountered during earlier claim rounds and
    // contribute zero heads now; job 4 (claimed then acked last) meets
    // its first scan here and pays its receipt+dead probes — the
    // concurrent gather runs both where the sequential code
    // short-circuited after the receipt hit. The live job pays its
    // terminal probes plus the claims-tail head — winner machinery.
    for (i, d) in delta_since(&counts, &before).into_iter().enumerate() {
        let expect = if i < 4 {
            0
        } else if i == 4 {
            2
        } else {
            3
        };
        assert_eq!(
            d, expect,
            "job {i}: terminal heads vanish after the memoizing encounter"
        );
    }

    // Second round: same shape, memo persists on the handle.
    q.ack(&c, &mut b).await.unwrap();
    let before: Vec<u64> = counts.lock().unwrap().clone();
    let mut b = OpBudget::new(512);
    assert!(matches!(
        q.claim(&claim_opts(0, 60_000_000_000), &mut b).await,
        Ok(ClaimOutcome::Empty)
    ));
    // NOTE: [AA] went claimed -> acked without a scan encounter, so
    // this scan lazily memoizes it: its receipt+dead probes (the
    // concurrent gather runs both), then zero forever after.
    for (i, d) in delta_since(&counts, &before).into_iter().enumerate() {
        let expect = if i < 5 { 0 } else { 2 };
        assert_eq!(d, expect, "job {i}: lazy memoization pays once, then zero");
    }

    // A fresh handle pays the full scan: six terminal jobs now.
    let fresh = Queue::open(
        Box::new(CountHeads {
            inner: mem.clone(),
            watched: watched.clone(),
            counts: counts.clone(),
        }),
        "q",
        OpenOptions::new([1; 16]),
    )
    .await
    .unwrap();
    let before: Vec<u64> = counts.lock().unwrap().clone();
    let mut b = OpBudget::new(512);
    assert!(matches!(
        fresh.claim(&claim_opts(0, 60_000_000_000), &mut b).await,
        Ok(ClaimOutcome::Empty)
    ));
    // Fresh handle, cold memo, concurrent gather: every terminal job
    // pays its receipt+dead pair (the sequential receipt-only
    // short-circuit is gone), overlapping in one round-trip window.
    let d = delta_since(&counts, &before);
    let live_seen = d[5];
    let backlog_seen: u64 = (0..5).map(|i| d[i]).sum();
    assert_eq!(
        backlog_seen, 10,
        "cold memo: each backlog job pays its terminal probe pair"
    );
    assert_eq!(
        live_seen, 2,
        "the acked live job pays its terminal probe pair"
    );
}

/// The memo is keyed by the jobs-entry VERSION: a deleted-then-
/// re-enqueued incarnation (the GC-then-reuse shape) never matches and
/// is re-examined. Kills an id-only-keyed memo mutant.
#[tokio::test]
async fn reenqueued_incarnation_after_graph_delete_is_rescanned() {
    let q = make_queue().await;
    let mut b = OpBudget::new(512);
    let id = [0x5A; 16];
    let out = q
        .enqueue(
            EnqueueInput {
                job_id: Some(id),
                payload: b"x",
                content_type: "text/plain".into(),
                maximum_attempts: 3,
                not_before_ns: None,
            },
            &mut b,
        )
        .await
        .unwrap();
    assert!(matches!(out, EnqueueOutcome::Committed { .. }));
    let ClaimOutcome::Claimed(c) = q
        .claim(&claim_opts(0, 60_000_000_000), &mut b)
        .await
        .unwrap()
    else {
        panic!("claim")
    };
    q.ack(&c, &mut b).await.unwrap();
    // Populate the memo for this job.
    assert!(matches!(
        q.claim(&claim_opts(0, 60_000_000_000), &mut b).await,
        Ok(ClaimOutcome::Empty)
    ));

    // Simulate GC deleting the terminal graph (jobs entry + receipt +
    // index entries), then re-enqueue the SAME id: a fresh incarnation
    // with a new jobs-entry version.
    let hex: String = id.iter().map(|x| format!("{x:02x}")).collect();
    for key in [
        format!("q/jobs/0000/{hex}"),
        format!("q/receipts/0000/{hex}"),
        format!("q/claims/0000/{hex}/00000001"),
    ] {
        q.store().delete(&Key::new(key)).await.unwrap();
    }
    let out = q
        .enqueue(
            EnqueueInput {
                job_id: Some(id),
                payload: b"y",
                content_type: "text/plain".into(),
                maximum_attempts: 3,
                not_before_ns: None,
            },
            &mut b,
        )
        .await
        .unwrap();
    assert!(
        matches!(out, EnqueueOutcome::Committed { .. }),
        "re-enqueue after graph delete must commit"
    );
    let ClaimOutcome::Claimed(c2) = q
        .claim(&claim_opts(0, 60_000_000_000), &mut b)
        .await
        .unwrap()
    else {
        panic!("re-enqueued incarnation must not be falsely skipped by the memo")
    };
    assert_eq!(c2.job_id, id);
    assert_eq!(c2.generation, 1, "fresh incarnation starts a fresh chain");
}

// ---------- claim_many: one scan, independent claims ----------

#[tokio::test]
async fn claim_many_collects_live_jobs_in_scan_order() {
    let q = make_queue().await;
    let mut b = OpBudget::new(1024);
    // Seven jobs; the first three become terminal (claim takes the
    // first live job in scan order), leaving four live behind.
    for i in 1..=7u8 {
        let EnqueueOutcome::Committed { .. } = q
            .enqueue(
                EnqueueInput {
                    job_id: Some([i; 16]),
                    payload: b"x",
                    content_type: "text/plain".into(),
                    maximum_attempts: 3,
                    not_before_ns: None,
                },
                &mut b,
            )
            .await
            .unwrap()
        else {
            panic!()
        };
    }
    for expected in 1..=3u8 {
        let ClaimOutcome::Claimed(c) = q
            .claim(&claim_opts(0, 60_000_000_000), &mut b)
            .await
            .unwrap()
        else {
            panic!("claim")
        };
        assert_eq!(c.job_id, [expected; 16]);
        q.ack(&c, &mut b).await.unwrap();
    }
    let mut b = OpBudget::new(1024);
    let claims = q
        .claim_many(&claim_opts(0, 60_000_000_000), 3, &mut b)
        .await
        .unwrap();
    assert_eq!(
        claims.iter().map(|c| c.job_id).collect::<Vec<_>>(),
        vec![[0x04; 16], [0x05; 16], [0x06; 16]],
        "scan order, terminal jobs skipped"
    );
    // Independent claims: each is a fresh generation-1 chain.
    assert!(claims.iter().all(|c| c.generation == 1));

    // The remaining live job 7 comes back alone; then nothing.
    let mut b = OpBudget::new(1024);
    let rest = q
        .claim_many(&claim_opts(0, 60_000_000_000), 2, &mut b)
        .await
        .unwrap();
    assert_eq!(
        rest.iter().map(|c| c.job_id).collect::<Vec<_>>(),
        vec![[0x07; 16]]
    );
    let mut b = OpBudget::new(1024);
    assert!(q
        .claim_many(&claim_opts(0, 60_000_000_000), 2, &mut b)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn claim_many_of_one_matches_claim() {
    let q = make_queue().await;
    let mut b = OpBudget::new(256);
    let EnqueueOutcome::Committed { .. } = q
        .enqueue(
            EnqueueInput {
                job_id: Some([9; 16]),
                payload: b"x",
                content_type: "text/plain".into(),
                maximum_attempts: 3,
                not_before_ns: None,
            },
            &mut b,
        )
        .await
        .unwrap()
    else {
        panic!()
    };
    let mut b1 = OpBudget::new(256);
    let mut b2 = OpBudget::new(256);
    let single = q.claim(&claim_opts(0, 60_000_000_000), &mut b1).await;
    let batched = q
        .claim_many(&claim_opts(0, 60_000_000_000), 1, &mut b2)
        .await;
    // Whichever ran first holds the claim; the other sees Empty/[] —
    // the shapes correspond.
    match (single, batched) {
        (Ok(ClaimOutcome::Claimed(_)), Ok(v)) => assert_eq!(v.len(), 0),
        (Ok(ClaimOutcome::Empty), Ok(v)) => assert_eq!(v.len(), 1),
        (a, b) => panic!("mismatch: {a:?} vs {b:?}"),
    }
}

#[tokio::test]
async fn claim_many_fills_the_batch_when_the_budget_serves_the_wave() {
    let q = make_queue().await;
    let mut b = OpBudget::new(256);
    for i in 1..=4u8 {
        let EnqueueOutcome::Committed { .. } = q
            .enqueue(
                EnqueueInput {
                    job_id: Some([i; 16]),
                    payload: b"x",
                    content_type: "text/plain".into(),
                    maximum_attempts: 3,
                    not_before_ns: None,
                },
                &mut b,
            )
            .await
            .unwrap()
        else {
            panic!()
        };
    }
    // A budget serving the whole wave (list + 4 full chains + slack)
    // fills the batch in one concurrent probe wave. (Uniform
    // candidate costs make mid-wave partial batches unreachable:
    // equal-split children either complete or exhaust together —
    // partial batches arise at wave and listing boundaries.)
    let mut wave_budget = OpBudget::new(96);
    let claims = q
        .claim_many(&claim_opts(0, 60_000_000_000), 4, &mut wave_budget)
        .await
        .unwrap();
    assert_eq!(claims.len(), 4, "full batch");
    // Each returned claim is real (its claim record exists).
    for c in &claims {
        let hex: String = c.job_id.iter().map(|x| format!("{x:02x}")).collect();
        assert!(q
            .store()
            .head(&Key::new(format!(
                "q/claims/0000/{hex}/{:08x}",
                c.generation
            )))
            .await
            .is_ok());
    }
}

// ---------- concurrent candidate probing: budget split/refund ----------

#[tokio::test]
async fn claim_many_refunds_unspent_child_budget_between_waves() {
    let q = make_queue().await;
    let mut b = OpBudget::new(256);
    for i in [1u8, 2] {
        let EnqueueOutcome::Committed { .. } = q
            .enqueue(
                EnqueueInput {
                    job_id: Some([i; 16]),
                    payload: b"x",
                    content_type: "text/plain".into(),
                    maximum_attempts: 3,
                    not_before_ns: None,
                },
                &mut b,
            )
            .await
            .unwrap()
        else {
            panic!()
        };
    }
    // Terminalize job 1: the scan's first candidate. Its wave child
    // spends only the terminal probes; without the merge-back refund
    // the parent would be empty and the scan would die before the
    // live candidate — this test kills a split-without-merge mutant.
    let ClaimOutcome::Claimed(c) = q
        .claim(&claim_opts(0, 60_000_000_000), &mut b)
        .await
        .unwrap()
    else {
        panic!()
    };
    q.ack(&c, &mut b).await.unwrap();

    // Tight budget: enough for probe(list) + refund + one full claim
    // chain, not enough to waste.
    let mut tight = OpBudget::new(16);
    let out = q
        .claim_many(&claim_opts(0, 60_000_000_000), 1, &mut tight)
        .await
        .unwrap();
    assert_eq!(
        out.len(),
        1,
        "the refund lets the scan continue past the terminal candidate"
    );
    assert_eq!(out[0].job_id, [2; 16]);
}

#[tokio::test]
async fn claim_many_spreads_thin_budgets_across_the_wave() {
    let q = make_queue().await;
    let mut b = OpBudget::new(256);
    for i in 1..=4u8 {
        let EnqueueOutcome::Committed { .. } = q
            .enqueue(
                EnqueueInput {
                    job_id: Some([i; 16]),
                    payload: b"x",
                    content_type: "text/plain".into(),
                    maximum_attempts: 3,
                    not_before_ns: None,
                },
                &mut b,
            )
            .await
            .unwrap()
        else {
            panic!()
        };
    }
    // A budget that would serve candidates sequentially is spread
    // across the wave: the outer listing spends 1, leaving 24; the
    // split gives 24/4 = 6 per child (parent remainder 0) — below the
    // 9 a fresh claim chain costs — so every child exhausts. Budget 25
    // (not 24) pins the exact-zero edge: the merge lands the parent at
    // exactly 0 and the error must STILL surface (a zero-first check
    // would swallow it as an empty partial batch).
    let mut thin = OpBudget::new(25);
    match q
        .claim_many(&claim_opts(0, 60_000_000_000), 4, &mut thin)
        .await
    {
        Err(Error::BudgetExhausted) => {}
        other => panic!("expected BudgetExhausted from the spread, got {other:?}"),
    }
}

// ---------- tail hints (feature bit 2) ----------

fn hints_format() -> FormatRecord {
    FormatRecord {
        required_feature_bits: 2,
        ..format()
    }
}

/// Counts LIST calls on claims/ prefixes — the op the tail hint
/// exists to avoid.
struct CountClaimLists {
    inner: MemoryStore,
    lists: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

#[async_trait::async_trait]
impl stowq_store::ObjectStore for CountClaimLists {
    async fn put_if_absent(
        &self,
        key: &Key,
        body: bytes::Bytes,
        sha256: [u8; 32],
    ) -> stowq_store::StoreResult<stowq_store::PutOutcome> {
        self.inner.put_if_absent(key, body, sha256).await
    }
    async fn cas(
        &self,
        key: &Key,
        body: bytes::Bytes,
        sha256: [u8; 32],
        if_match: &stowq_store::Version,
    ) -> stowq_store::StoreResult<stowq_store::PutOutcome> {
        self.inner.cas(key, body, sha256, if_match).await
    }
    async fn get(
        &self,
        key: &Key,
        range: Option<std::ops::Range<u64>>,
    ) -> stowq_store::StoreResult<stowq_store::Object> {
        self.inner.get(key, range).await
    }
    async fn head(&self, key: &Key) -> stowq_store::StoreResult<stowq_store::Meta> {
        self.inner.head(key).await
    }
    async fn list(
        &self,
        prefix: &str,
        after: Option<&Key>,
        limit: usize,
    ) -> stowq_store::StoreResult<stowq_store::Page> {
        if prefix.contains("/claims/") {
            self.lists.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        self.inner.list(prefix, after, limit).await
    }
    async fn delete(&self, key: &Key) -> stowq_store::StoreResult<()> {
        self.inner.delete(key).await
    }
}

async fn hinted_queue() -> (Queue, MemoryStore) {
    let store = MemoryStore::new();
    let q = Queue::init(
        Box::new(store.clone()),
        "q",
        &OpenOptions::new([1; 16]),
        &hints_format(),
    )
    .await
    .unwrap();
    (q, store)
}

async fn hint_body(store: &MemoryStore, job_id: &[u8; 16]) -> Option<u64> {
    let hex: String = job_id.iter().map(|b| format!("{b:02x}")).collect();
    let obj = store
        .get(&Key::new(format!("q/tails/0000/{hex}")), None)
        .await
        .ok()?;
    Some(u64::from_be_bytes(obj.body.as_ref().try_into().ok()?))
}

/// A takeover claim on a deep chain uses the hint: zero claims-prefix
/// LISTs, and the claim lands on the hinted generation + 1.
#[tokio::test]
async fn hinted_takeover_skips_the_chain_listing() {
    use std::sync::atomic::{AtomicU64, Ordering};
    let (q, store) = hinted_queue().await;
    let mut b = OpBudget::new(2048);
    let out = q
        .enqueue(
            EnqueueInput {
                job_id: Some([3; 16]),
                payload: b"x",
                content_type: "text/plain".into(),
                maximum_attempts: 50,
                not_before_ns: None,
            },
            &mut b,
        )
        .await
        .unwrap();
    let EnqueueOutcome::Committed { job_id } = out else {
        panic!()
    };
    let ClaimOutcome::Claimed(c1) = q
        .claim(&claim_opts(0, 60_000_000_000), &mut b)
        .await
        .unwrap()
    else {
        panic!()
    };
    // Deepen the chain: three renewals.
    let mut c = c1;
    for _ in 0..3 {
        match q.renew(&c, &mut b).await.unwrap() {
            stowq_core::RenewOutcome::Renewed(nc) => c = nc,
            _ => panic!("renew"),
        }
    }
    assert_eq!(
        hint_body(&store, &job_id).await,
        Some(4),
        "renewals advance the hint"
    );

    // Expire and take over through a fresh counting handle.
    store.advance_clock_to(c.claim_store_time_ns + 3_600_000_000_000);
    let lists = Arc::new(AtomicU64::new(0));
    let q2 = Queue::open(
        Box::new(CountClaimLists {
            inner: store.clone(),
            lists: lists.clone(),
        }),
        "q",
        OpenOptions::new([1; 16]),
    )
    .await
    .unwrap();
    let mut b2 = OpBudget::new(1024);
    let floor = q2.establish_floor(&mut b2).await.unwrap();
    let ClaimOutcome::Claimed(c2) = q2
        .claim(&claim_opts(floor, 60_000_000_000), &mut b2)
        .await
        .unwrap()
    else {
        panic!("takeover")
    };
    assert_eq!(c2.generation, 5, "continues past the hinted tail 4");
    assert_eq!(
        lists.load(Ordering::SeqCst),
        0,
        "the hint replaced the chain listing entirely"
    );
    assert_eq!(hint_body(&store, &job_id).await, Some(5));
}

/// A stale-backward hint (renewals outran it) makes the claim put
/// reject; the fallback listing recovers and the claim lands on the
/// authoritative tail + 1, refreshing the hint.
#[tokio::test]
async fn stale_backward_hint_falls_back_and_recovers() {
    let (q, store) = hinted_queue().await;
    let mut b = OpBudget::new(2048);
    let EnqueueOutcome::Committed { job_id } = q
        .enqueue(
            EnqueueInput {
                job_id: Some([4; 16]),
                payload: b"x",
                content_type: "text/plain".into(),
                maximum_attempts: 50,
                not_before_ns: None,
            },
            &mut b,
        )
        .await
        .unwrap()
    else {
        panic!()
    };
    let ClaimOutcome::Claimed(c1) = q
        .claim(&claim_opts(0, 60_000_000_000), &mut b)
        .await
        .unwrap()
    else {
        panic!()
    };
    let mut c = c1;
    for _ in 0..3 {
        match q.renew(&c, &mut b).await.unwrap() {
            stowq_core::RenewOutcome::Renewed(nc) => c = nc,
            _ => panic!("renew"),
        }
    }
    // Regress the hint to generation 1 (a lost write's stand-in).
    let hex: String = job_id.iter().map(|x| format!("{x:02x}")).collect();
    let key = Key::new(format!("q/tails/0000/{hex}"));
    let obj = store.get(&key, None).await.unwrap();
    store
        .cas(
            &key,
            bytes::Bytes::copy_from_slice(&1u64.to_be_bytes()),
            sha2::Sha256::digest(1u64.to_be_bytes()).into(),
            &obj.meta.version,
        )
        .await
        .unwrap();
    // Expire the real tail and take over.
    store.advance_clock_to(c.claim_store_time_ns + 3_600_000_000_000);
    // A fresh handle for the post-advance floor (the old handle's
    // cached floor predates the clock jump).
    let qf = Queue::open(Box::new(store.clone()), "q", OpenOptions::new([1; 16]))
        .await
        .unwrap();
    let mut b2 = OpBudget::new(1024);
    let floor = qf.establish_floor(&mut b2).await.unwrap();
    let ClaimOutcome::Claimed(c2) = qf
        .claim(&claim_opts(floor, 60_000_000_000), &mut b2)
        .await
        .unwrap()
    else {
        panic!("takeover")
    };
    assert_eq!(c2.generation, 5, "authoritative tail 4 + 1");
    assert_eq!(hint_body(&store, &job_id).await, Some(5), "hint refreshed");
}

/// A stale-forward hint (points past the real chain) 404s at the
/// hinted generation; the fallback listing recovers.
#[tokio::test]
async fn stale_forward_hint_falls_back() {
    let (q, store) = hinted_queue().await;
    let mut b = OpBudget::new(2048);
    let EnqueueOutcome::Committed { job_id } = q
        .enqueue(
            EnqueueInput {
                job_id: Some([5; 16]),
                payload: b"x",
                content_type: "text/plain".into(),
                maximum_attempts: 50,
                not_before_ns: None,
            },
            &mut b,
        )
        .await
        .unwrap()
    else {
        panic!()
    };
    let ClaimOutcome::Claimed(c1) = q
        .claim(&claim_opts(0, 60_000_000_000), &mut b)
        .await
        .unwrap()
    else {
        panic!()
    };
    // Point the hint at a nonexistent generation 99.
    let hex: String = job_id.iter().map(|x| format!("{x:02x}")).collect();
    let key = Key::new(format!("q/tails/0000/{hex}"));
    let obj = store.get(&key, None).await.unwrap();
    store
        .cas(
            &key,
            bytes::Bytes::copy_from_slice(&99u64.to_be_bytes()),
            sha2::Sha256::digest(99u64.to_be_bytes()).into(),
            &obj.meta.version,
        )
        .await
        .unwrap();
    store.advance_clock_to(c1.claim_store_time_ns + 3_600_000_000_000);
    let qf = Queue::open(Box::new(store.clone()), "q", OpenOptions::new([1; 16]))
        .await
        .unwrap();
    let mut b2 = OpBudget::new(1024);
    let floor = qf.establish_floor(&mut b2).await.unwrap();
    let ClaimOutcome::Claimed(c2) = qf
        .claim(&claim_opts(floor, 60_000_000_000), &mut b2)
        .await
        .unwrap()
    else {
        panic!("takeover")
    };
    assert_eq!(c2.generation, 2);
    assert_eq!(hint_body(&store, &job_id).await, Some(2));
}

/// GC removes the hint with the terminal graph; a disabled queue
/// never writes one.
#[tokio::test]
async fn gc_cleans_hints_and_disabled_queues_write_none() {
    let (q, store) = hinted_queue().await;
    let mut b = OpBudget::new(2048);
    let EnqueueOutcome::Committed { job_id } = q
        .enqueue(
            EnqueueInput {
                job_id: Some([6; 16]),
                payload: b"x",
                content_type: "text/plain".into(),
                maximum_attempts: 3,
                not_before_ns: None,
            },
            &mut b,
        )
        .await
        .unwrap()
    else {
        panic!()
    };
    let ClaimOutcome::Claimed(c) = q
        .claim(&claim_opts(0, 60_000_000_000), &mut b)
        .await
        .unwrap()
    else {
        panic!()
    };
    q.ack(&c, &mut b).await.unwrap();
    assert!(hint_body(&store, &job_id).await.is_some());
    let floor = q.establish_floor(&mut b).await.unwrap();
    q.gc(floor, 0, 0, &mut b).await.unwrap();
    assert_eq!(
        hint_body(&store, &job_id).await,
        None,
        "gc deletes the hint with the graph"
    );

    // Feature off: no hint keys ever.
    let plain = make_queue().await;
    let mut b = OpBudget::new(256);
    let EnqueueOutcome::Committed { .. } = plain
        .enqueue(
            EnqueueInput {
                job_id: Some([7; 16]),
                payload: b"x",
                content_type: "text/plain".into(),
                maximum_attempts: 3,
                not_before_ns: None,
            },
            &mut b,
        )
        .await
        .unwrap()
    else {
        panic!()
    };
    let ClaimOutcome::Claimed(c) = plain
        .claim(&claim_opts(0, 60_000_000_000), &mut b)
        .await
        .unwrap()
    else {
        panic!()
    };
    plain.ack(&c, &mut b).await.unwrap();
    let page = plain.store().list("q/tails/", None, 8).await.unwrap();
    assert!(page.items.is_empty(), "bit off: no hint keys");
}

/// The deep-chain measurement, deterministic: at 70 generations a
/// bit-0 takeover LISTs 2 pages (70 > 64/page); a bit-2 takeover
/// LISTs nothing — the hint replaces the listing entirely.
#[tokio::test]
async fn deep_chain_takeover_hint_vs_listing() {
    use std::sync::atomic::Ordering;
    async fn scenario(bits: u64) -> (u64, u64) {
        let f = FormatRecord {
            required_feature_bits: bits,
            ..format()
        };
        let store = MemoryStore::new();
        let q = Queue::init(Box::new(store.clone()), "q", &OpenOptions::new([1; 16]), &f)
            .await
            .unwrap();
        let mut b = OpBudget::new(8192);
        let EnqueueOutcome::Committed { job_id } = q
            .enqueue(
                EnqueueInput {
                    job_id: Some([9; 16]),
                    payload: b"x",
                    content_type: "text/plain".into(),
                    maximum_attempts: 500,
                    not_before_ns: None,
                },
                &mut b,
            )
            .await
            .unwrap()
        else {
            panic!()
        };
        let mut c = match q
            .claim(&claim_opts(0, 60_000_000_000), &mut b)
            .await
            .unwrap()
        {
            ClaimOutcome::Claimed(c) => c,
            ClaimOutcome::Empty => panic!("initial claim"),
        };
        for _ in 0..69 {
            match q.renew(&c, &mut b).await.unwrap() {
                stowq_core::RenewOutcome::Renewed(nc) => c = nc,
                _ => panic!("renewals"),
            }
        }
        store.advance_clock_to(c.claim_store_time_ns + 3_600_000_000_000);
        let lists = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let q2 = Queue::open(
            Box::new(CountClaimLists {
                inner: store.clone(),
                lists: lists.clone(),
            }),
            "q",
            OpenOptions::new([1; 16]),
        )
        .await
        .unwrap();
        let mut b2 = OpBudget::new(2048);
        let floor = q2.establish_floor(&mut b2).await.unwrap();
        let ClaimOutcome::Claimed(t) = q2
            .claim(&claim_opts(floor, 60_000_000_000), &mut b2)
            .await
            .unwrap()
        else {
            panic!("takeover")
        };
        assert_eq!(t.generation, 71);
        let _ = job_id;
        (lists.load(Ordering::SeqCst), t.generation)
    }
    let (hint_lists, _) = scenario(2).await;
    let (plain_lists, _) = scenario(0).await;
    assert_eq!(hint_lists, 0, "hint path: no chain listing");
    assert!(
        plain_lists >= 2,
        "listing path paginates past 64 generations (got {plain_lists})"
    );
}

/// F1 regression: the exhaustion-dead must never fire on unfenced
/// hint evidence. A stale hint on a job whose authoritative tail is
/// UNexpired, with maximum_attempts exhausted per the stale
/// evidence's attempt count — the claim returns Empty (no dead), and
/// the live holder still acks.
#[tokio::test]
async fn stale_hint_cannot_write_premature_dead() {
    let (q, store) = hinted_queue().await;
    let mut b = OpBudget::new(2048);
    let EnqueueOutcome::Committed { .. } = q
        .enqueue(
            EnqueueInput {
                job_id: Some([0xA1; 16]),
                payload: b"x",
                content_type: "text/plain".into(),
                maximum_attempts: 1,
                not_before_ns: None,
            },
            &mut b,
        )
        .await
        .unwrap()
    else {
        panic!()
    };
    let ClaimOutcome::Claimed(c1) = q.claim(&claim_opts(0, 5_000), &mut b).await.unwrap() else {
        panic!()
    };
    // Renewals deepen the chain while the gen-1 evidence would read
    // as expired.
    let gen1_store_time = c1.claim_store_time_ns;
    let mut c = c1;
    for _ in 0..3 {
        match q.renew(&c, &mut b).await.unwrap() {
            stowq_core::RenewOutcome::Renewed(nc) => c = nc,
            _ => panic!("renew"),
        }
    }
    // Stale the hint to generation 1.
    let jhex: String = c.job_id.iter().map(|x| format!("{x:02x}")).collect();
    let key = Key::new(format!("q/tails/0000/{jhex}"));
    let obj = store.get(&key, None).await.unwrap();
    store
        .cas(
            &key,
            bytes::Bytes::copy_from_slice(&1u64.to_be_bytes()),
            sha2::Sha256::digest(1u64.to_be_bytes()).into(),
            &obj.meta.version,
        )
        .await
        .unwrap();
    // A floor past gen-1's expiry but before gen-4's: the stale
    // evidence reads expired+exhausted, the authoritative tail is live.
    let qf = Queue::open(Box::new(store.clone()), "q", OpenOptions::new([1; 16]))
        .await
        .unwrap();
    let mut b2 = OpBudget::new(1024);
    store.advance_clock_to(gen1_store_time + 5_001);
    let floor = qf.establish_floor(&mut b2).await.unwrap();
    match qf.claim(&claim_opts(floor, 5_000), &mut b2).await.unwrap() {
        ClaimOutcome::Empty => {}
        ClaimOutcome::Claimed(_) => panic!("live tail must not be claimable"),
    }
    assert!(
        store
            .head(&Key::new(format!("q/dead/0000/{jhex}")))
            .await
            .is_err(),
        "no premature dead from stale hint evidence"
    );
    // The live holder acks: the delivery survives.
    assert_eq!(
        q.ack(&c, &mut b).await.unwrap(),
        stowq_core::AckOutcome::Acked
    );
}

/// F2/F3 regression: corrupt hint bodies (wrong width; out-of-range
/// generation) fall back to the listing, claim succeeds, and the
/// commit repairs the hint.
#[tokio::test]
async fn corrupt_hint_bodies_fall_back_and_repair() {
    for body in [
        bytes::Bytes::from_static(b"short"), // width
        bytes::Bytes::copy_from_slice(&(0x1_0000_0001u64).to_be_bytes()), // > u32::MAX
    ] {
        let (q, store) = hinted_queue().await;
        let mut b = OpBudget::new(2048);
        let EnqueueOutcome::Committed { .. } = q
            .enqueue(
                EnqueueInput {
                    job_id: Some([0xB2; 16]),
                    payload: b"x",
                    content_type: "text/plain".into(),
                    maximum_attempts: 3,
                    not_before_ns: None,
                },
                &mut b,
            )
            .await
            .unwrap()
        else {
            panic!()
        };
        // Plant the corrupt hint at the deterministic key.
        let jhex: String = [0xB2u8; 16].iter().map(|x| format!("{x:02x}")).collect();
        let key = Key::new(format!("q/tails/0000/{jhex}"));
        let digest = sha2::Sha256::digest(body.as_ref()).into();
        store.put_if_absent(&key, body, digest).await.unwrap();
        // Claim succeeds through the listing fallback.
        let ClaimOutcome::Claimed(c) = q
            .claim(&claim_opts(0, 60_000_000_000), &mut b)
            .await
            .unwrap()
        else {
            panic!("claim through corrupt hint")
        };
        assert_eq!(c.generation, 1);
        // The commit repaired the hint.
        assert_eq!(hint_body(&store, &c.job_id).await, Some(1));
    }
}

// ---------- depth + metrics ----------

#[tokio::test]
async fn depth_counts_each_plane() {
    let q = make_queue().await;
    let mut b = OpBudget::new(1024);
    for i in 1..=3u8 {
        let EnqueueOutcome::Committed { .. } = q
            .enqueue(
                EnqueueInput {
                    job_id: Some([i; 16]),
                    payload: b"x",
                    content_type: "text/plain".into(),
                    maximum_attempts: 3,
                    not_before_ns: None,
                },
                &mut b,
            )
            .await
            .unwrap()
        else {
            panic!()
        };
    }
    // Two acked, one claimed-and-held, one... we have three: ack one,
    // hold one, nack one.
    let ClaimOutcome::Claimed(c1) = q
        .claim(&claim_opts(0, 60_000_000_000), &mut b)
        .await
        .unwrap()
    else {
        panic!()
    };
    let ClaimOutcome::Claimed(c2) = q
        .claim(&claim_opts(0, 60_000_000_000), &mut b)
        .await
        .unwrap()
    else {
        panic!()
    };
    q.ack(&c1, &mut b).await.unwrap();
    let floor = q.establish_floor(&mut b).await.unwrap();
    q.nack(&c2, 1, floor, &mut b).await.unwrap();

    let mut b2 = OpBudget::new(256);
    let d = q.depth(0, &mut b2).await.unwrap();
    assert_eq!(d.jobs, 3);
    assert_eq!(d.receipts, 1);
    assert_eq!(d.dead, 0);
    // Claims: gen-1 records for c1 and c2 exist (c1's survives ack —
    // GC owns deletion); nack's gen-1 also. Total: 2 claim records.
    assert_eq!(d.claims, 2, "gen-1 records for both claimed jobs");
}
