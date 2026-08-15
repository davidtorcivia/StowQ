//! Lifecycle tests against the memory fake: init, enqueue, claim, renew,
//! ack, nack, bury, takeover, exhaustion, and budgets.

use stowq_core::{ClaimOptions, EnqueueInput, EnqueueOutcome, Error, OpBudget, OpenOptions, Queue};
use stowq_format::FormatRecord;
use stowq_store::{Key, MemoryStore, StoreError};

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

fn make_queue() -> Queue {
    Queue::init(
        Box::new(MemoryStore::new()),
        "q",
        &OpenOptions::new([1; 16]),
        &format(),
    )
    .unwrap()
}

fn make_shared() -> (Queue, MemoryStore) {
    let store = MemoryStore::new();
    let q = Queue::init(
        Box::new(store.clone()),
        "q",
        &OpenOptions::new([1; 16]),
        &format(),
    )
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

#[test]
fn init_idempotent_then_rejects_conflicting_format() {
    let (q, store) = make_shared();
    // Identical format over the same prefix: accepted.
    Queue::init(
        Box::new(store.clone()),
        "q",
        &OpenOptions::new([1; 16]),
        &format(),
    )
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
    );
    match result {
        Err(stowq_core::Error::QueueIdMismatch) => {}
        _ => panic!("expected QueueIdMismatch"),
    }
    drop(q);
}

#[test]
fn enqueue_claim_ack_lifecycle() {
    let q = make_queue();
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
        .unwrap();
    let EnqueueOutcome::Committed { job_id } = out else {
        panic!("commit")
    };

    let claimed = q
        .claim(&claim_opts(0, 60_000_000_000), &mut budget)
        .unwrap();
    let stowq_core::ClaimOutcome::Claimed(claim) = claimed else {
        panic!("claim")
    };
    assert_eq!(claim.job_id, job_id);
    assert_eq!(claim.generation, 1);
    assert_eq!(claim.attempt, 1);
    let payload = claim.payload(q.store()).unwrap();
    assert_eq!(&payload[..], b"hello");

    // Lease held: a second claim at the same floor finds nothing.
    let again = q
        .claim(&claim_opts(0, 60_000_000_000), &mut budget)
        .unwrap();
    assert!(matches!(again, stowq_core::ClaimOutcome::Empty));

    let ack = q.ack(&claim, &mut budget).unwrap();
    assert_eq!(ack, stowq_core::AckOutcome::Acked);

    // Idempotent re-ack verifies existing evidence.
    let reack = q.ack(&claim, &mut budget).unwrap();
    assert_eq!(reack, stowq_core::AckOutcome::AlreadyAcked);

    // Terminal: no further claims.
    let post = q
        .claim(&claim_opts(u64::MAX / 4, 60_000_000_000), &mut budget)
        .unwrap();
    assert!(matches!(post, stowq_core::ClaimOutcome::Empty));
}

#[test]
fn detached_payload_round_trips() {
    let mut opts = OpenOptions::new([1; 16]);
    opts.max_inline_payload = 4;
    let q = Queue::init(Box::new(MemoryStore::new()), "q", &opts, &format()).unwrap();
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
    .unwrap();
    let stowq_core::ClaimOutcome::Claimed(claim) = q
        .claim(&claim_opts(0, 60_000_000_000), &mut budget)
        .unwrap()
    else {
        panic!("claim")
    };
    assert_eq!(&claim.payload(q.store()).unwrap()[..], &big[..]);
}

#[test]
fn idempotent_enqueue_and_id_taken() {
    let q = make_queue();
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
        .unwrap();
    assert!(matches!(out3, EnqueueOutcome::IdTaken { .. }));
}

#[test]
fn takeover_after_expiry_increments_generation_and_attempt() {
    let q = make_queue();
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
    .unwrap();
    let stowq_core::ClaimOutcome::Claimed(first) =
        q.claim(&claim_opts(0, 1_000), &mut budget).unwrap()
    else {
        panic!("first claim")
    };
    // Not yet expired (skew guard 0): floor one nanosecond short.
    let expiry = first.claim_store_time_ns + 1_000;
    let held = q
        .claim(&claim_opts(expiry - 1, 1_000), &mut budget)
        .unwrap();
    assert!(matches!(held, stowq_core::ClaimOutcome::Empty));
    // At and past expiry: takeover (floor >= expiry is expired).
    let stowq_core::ClaimOutcome::Claimed(second) =
        q.claim(&claim_opts(expiry, 1_000), &mut budget).unwrap()
    else {
        panic!("takeover")
    };
    assert_eq!(second.generation, 2);
    assert_eq!(second.attempt, 2);
    assert_ne!(second.worker_token, first.worker_token);
}

#[test]
fn renew_extends_and_loses_to_takeover() {
    let q = make_queue();
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
    .unwrap();
    let stowq_core::ClaimOutcome::Claimed(claim) =
        q.claim(&claim_opts(0, 1_000), &mut budget).unwrap()
    else {
        panic!("claim")
    };
    let stowq_core::RenewOutcome::Renewed(renewed) = q.renew(&claim, &mut budget).unwrap() else {
        panic!("renew")
    };
    assert_eq!(renewed.generation, 2);
    assert_eq!(renewed.attempt, 1); // continuation keeps the attempt
    assert_eq!(renewed.worker_token, claim.worker_token);
    // Old expiry no longer takes the job.
    let old_expiry = claim.claim_store_time_ns + 1_000;
    let held = q
        .claim(&claim_opts(old_expiry, 1_000), &mut budget)
        .unwrap();
    assert!(matches!(held, stowq_core::ClaimOutcome::Empty));
    // Renewal of the stale claim loses to generation 2 existing.
    let lost = q.renew(&claim, &mut budget).unwrap();
    assert!(matches!(lost, stowq_core::RenewOutcome::LeaseLost));
}

#[test]
fn nack_gates_claim_until_backoff_elapses() {
    let q = make_queue();
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
    .unwrap();
    let stowq_core::ClaimOutcome::Claimed(claim) =
        q.claim(&claim_opts(0, 1_000), &mut budget).unwrap()
    else {
        panic!("claim")
    };
    q.nack(&claim, 0x0001, 0, &mut budget).unwrap();
    // Backoff delay at attempt 1 with default policy: 50-100ms.
    let early = q.claim(&claim_opts(1_000_000, 1_000), &mut budget).unwrap();
    assert!(matches!(early, stowq_core::ClaimOutcome::Empty));
    let late = q
        .claim(&claim_opts(200_000_000, 1_000), &mut budget)
        .unwrap();
    let stowq_core::ClaimOutcome::Claimed(takeover) = late else {
        panic!("takeover")
    };
    assert_eq!(takeover.generation, 2);
    assert_eq!(takeover.attempt, 2);
}

#[test]
fn attempts_exhausted_writes_dead() {
    let q = make_queue();
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
        .unwrap();
    let EnqueueOutcome::Committed { job_id } = out else {
        panic!()
    };
    let stowq_core::ClaimOutcome::Claimed(claim) =
        q.claim(&claim_opts(0, 1_000), &mut budget).unwrap()
    else {
        panic!("claim")
    };
    // Expire; the next claim attempt must write dead, not claim.
    let floor = claim.claim_store_time_ns + 2_000;
    let out2 = q.claim(&claim_opts(floor, 1_000), &mut budget).unwrap();
    assert!(matches!(out2, stowq_core::ClaimOutcome::Empty));
    let dead_key = Key::new(format!(
        "q/dead/0000/{}",
        job_id
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ));
    let meta = q.store().head(&dead_key).unwrap();
    assert!(meta.size > 0);
    // And the job is terminal thereafter.
    let out3 = q
        .claim(&claim_opts(u64::MAX / 4, 1_000), &mut budget)
        .unwrap();
    assert!(matches!(out3, stowq_core::ClaimOutcome::Empty));
}

#[test]
fn bury_makes_job_unclaimable() {
    let q = make_queue();
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
    let stowq_core::ClaimOutcome::Claimed(claim) = q
        .claim(&claim_opts(0, 60_000_000_000), &mut budget)
        .unwrap()
    else {
        panic!("claim")
    };
    q.bury(&claim, 0x0003, &mut budget).unwrap();
    let post = q
        .claim(&claim_opts(u64::MAX / 4, 60_000_000_000), &mut budget)
        .unwrap();
    assert!(matches!(post, stowq_core::ClaimOutcome::Empty));
}

#[test]
fn delayed_job_not_claimable_before_floor() {
    let q = make_queue();
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
    .unwrap();
    let early = q
        .claim(&claim_opts(9_999_999_999, 1_000), &mut budget)
        .unwrap();
    assert!(matches!(early, stowq_core::ClaimOutcome::Empty));
    let late = q
        .claim(&claim_opts(10_000_000_000, 1_000), &mut budget)
        .unwrap();
    assert!(matches!(late, stowq_core::ClaimOutcome::Claimed(_)));
}

#[test]
fn tiny_budget_exhausts() {
    let mut opts = OpenOptions::new([1; 16]);
    opts.max_inline_payload = 4;
    let q = Queue::init(Box::new(MemoryStore::new()), "q", &opts, &format()).unwrap();
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
        .unwrap_err();
    assert!(matches!(err, Error::BudgetExhausted));
}

#[test]
fn open_rejects_missing_format() {
    let result = Queue::open(Box::new(MemoryStore::new()), "q", OpenOptions::new([1; 16]));
    match result {
        Err(Error::Store(StoreError::NotFound)) => {}
        Err(other) => panic!("expected NotFound, got {other:?}"),
        Ok(_) => panic!("open must reject a prefix without FORMAT"),
    }
}

#[test]
fn renew_and_ack_refuse_after_exhaustion_dead() {
    let q = make_queue();
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
    .unwrap();
    let stowq_core::ClaimOutcome::Claimed(claim) =
        q.claim(&claim_opts(0, 1_000), &mut budget).unwrap()
    else {
        panic!("claim")
    };
    // Expire; another claimant writes dead at exhaustion.
    let floor = claim.claim_store_time_ns + 2_000;
    let out = q.claim(&claim_opts(floor, 1_000), &mut budget).unwrap();
    assert!(matches!(out, stowq_core::ClaimOutcome::Empty));
    // The zombie holder cannot extend custody or ack over the dead job.
    let renewed = q.renew(&claim, &mut budget).unwrap();
    assert!(matches!(renewed, stowq_core::RenewOutcome::LeaseLost));
    let acked = q.ack(&claim, &mut budget).unwrap();
    assert_eq!(acked, stowq_core::AckOutcome::SupersededByDead);
    // And no receipt exists.
    let jhex: String = [6u8; 16].iter().map(|b| format!("{b:02x}")).collect();
    let receipt = q.store().head(&Key::new(format!("q/receipts/0000/{jhex}")));
    assert!(receipt.is_err());
}

#[test]
fn floor_and_watermark_lifecycle() {
    let q = make_queue();
    let mut budget = OpBudget::new(64);
    // Floor: beacon write + read-back, monotone across refreshes.
    let f1 = q.establish_floor(&mut budget).unwrap();
    assert!(f1 > 0);
    let f2 = q.establish_floor(&mut budget).unwrap();
    assert_eq!(f1, f2, "cached floor is reused until stale");
    // Watermark: absent -> create; advance; lower bucket is a no-op.
    assert!(q.watermark(&mut budget).unwrap().is_none());
    // The method bucketizes with the delayed width (1000 ns here).
    q.advance_watermark(10_000, &mut budget).unwrap();
    let w = q.watermark(&mut budget).unwrap().unwrap();
    assert_eq!(w.highest_observed_wall_bucket, 10);
    assert_eq!(w.sequence, 0);
    q.advance_watermark(12_000, &mut budget).unwrap();
    let w = q.watermark(&mut budget).unwrap().unwrap();
    assert_eq!(w.highest_observed_wall_bucket, 12);
    assert_eq!(w.sequence, 1);
    // Same bucket is a no-op.
    q.advance_watermark(12_500, &mut budget).unwrap();
    let w = q.watermark(&mut budget).unwrap().unwrap();
    assert_eq!(w.sequence, 1);
    // A lower bucket than stored is a lost race or a stale floor: the
    // watermark already covers it; proceed as a no-op.
    q.advance_watermark(5_000, &mut budget).unwrap();
    let w = q.watermark(&mut budget).unwrap().unwrap();
    assert_eq!(w.highest_observed_wall_bucket, 12);
    assert_eq!(w.sequence, 1);
}

#[test]
fn sweeps_evaluate_and_prune_index_entries() {
    let q = make_queue();
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
    .unwrap();
    let stowq_core::ClaimOutcome::Claimed(claim) =
        q.claim(&claim_opts(0, 1_000), &mut budget).unwrap()
    else {
        panic!("claim")
    };
    // The lease index entry exists (written at claim).
    let jhex: String = claim.job_id.iter().map(|b| format!("{b:02x}")).collect();
    let leases = list_all(&q, "q/leases/");
    assert_eq!(leases.len(), 1, "claim writes its lease index entry");

    // Before expiry: the entry's expiry bucket is ahead of the floor
    // bucket, so the sweep skips it entirely.
    let report = q
        .sweep_expired_leases(claim.claim_store_time_ns, &mut budget)
        .unwrap();
    assert_eq!(report.entries, 0);
    assert_eq!(
        list_all(&q, "q/leases/").len(),
        1,
        "not-yet-due entries are left in place"
    );

    // After expiry: the entry is due, the tail is genuinely expired, and
    // the consumed entry is deleted.
    let after_expiry = claim.claim_store_time_ns + 1_000;
    let report = q.sweep_expired_leases(after_expiry, &mut budget).unwrap();
    assert_eq!(report.entries, 1);
    assert_eq!(report.reclaimed, 1);
    assert!(
        list_all(&q, "q/leases/").is_empty(),
        "sweep deletes consumed entries"
    );
    let retake = q
        .claim(&claim_opts(after_expiry, 1_000), &mut budget)
        .unwrap();
    let stowq_core::ClaimOutcome::Claimed(second) = retake else {
        panic!("takeover after sweep")
    };
    assert_eq!(second.generation, 2);
    drop(jhex);
}

#[test]
fn delayed_sweep_promotes_due_jobs() {
    let q = make_queue();
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
    .unwrap();
    assert_eq!(list_all(&q, "q/delayed/").len(), 1);
    // Before due: entry examined, not promoted, deleted.
    let report = q.sweep_delayed(4_000_000, &mut budget).unwrap();
    assert_eq!(report.entries, 0, "future bucket entries are skipped");
    // Due: promoted (the job's not_before has passed).
    let report = q.sweep_delayed(5_000_000, &mut budget).unwrap();
    assert!(report.promoted >= 1);
    // The job is claimable at the due floor.
    let claimed = q.claim(&claim_opts(5_000_000, 1_000), &mut budget).unwrap();
    assert!(matches!(claimed, stowq_core::ClaimOutcome::Claimed(_)));
}

#[test]
fn gc_deletes_terminal_graphs_and_honors_retention() {
    let q = make_queue();
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
    .unwrap();
    let stowq_core::ClaimOutcome::Claimed(claim) =
        q.claim(&claim_opts(0, 1_000), &mut budget).unwrap()
    else {
        panic!("claim")
    };
    q.ack(&claim, &mut budget).unwrap();

    // Within retention: nothing deleted.
    let report = q
        .gc(claim.claim_store_time_ns + 100, 1_000_000, &mut budget)
        .unwrap();
    assert_eq!(report.jobs_deleted, 0);
    let jhex: String = claim.job_id.iter().map(|b| format!("{b:02x}")).collect();
    assert!(q
        .store()
        .head(&Key::new(format!("q/receipts/0000/{jhex}")))
        .is_ok());

    // Past retention: the whole graph goes, terminal last.
    let report = q.gc(u64::MAX / 4, 1_000, &mut budget).unwrap();
    assert_eq!(report.jobs_deleted, 1);
    assert!(q
        .store()
        .head(&Key::new(format!("q/receipts/0000/{jhex}")))
        .is_err());
    assert!(q
        .store()
        .head(&Key::new(format!("q/jobs/0000/{jhex}")))
        .is_err());
    assert!(list_all(&q, "q/termidx/").is_empty());
    assert!(list_all(&q, "q/claims/").is_empty());
    assert!(list_all(&q, "q/fails/").is_empty());
}

fn list_all(q: &Queue, prefix: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut after: Option<Key> = None;
    loop {
        let page = q.store().list(prefix, after.as_ref(), 100).unwrap();
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

#[test]
fn fresh_floor_below_watermark_fails_closed() {
    let q = make_queue();
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
        .unwrap();
    // bucket * delayed_width = 1e9 * 1000 = 1e12 ns ahead of any store
    // time the fake can produce soon; a fresh floor must fail closed.
    let result = q.establish_floor(&mut budget);
    match result {
        Err(Error::Store(stowq_store::StoreError::ProfileViolation(msg))) => {
            assert!(msg.contains("regression"), "unexpected violation: {msg}");
        }
        other => panic!("expected ProfileViolation, got {other:?}"),
    }
}

#[test]
fn gc_interruption_leaves_terminal_record_last() {
    let q = make_queue();
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
    .unwrap();
    let stowq_core::ClaimOutcome::Claimed(claim) =
        q.claim(&claim_opts(0, 1_000), &mut budget).unwrap()
    else {
        panic!("claim")
    };
    q.ack(&claim, &mut budget).unwrap();
    let jhex: String = claim.job_id.iter().map(|b| format!("{b:02x}")).collect();

    // Starve the graph deletion mid-flight: a tiny budget exhausts
    // inside delete_terminal_graph. Whatever partial state results,
    // the terminal record must still exist and the job must be
    // unclaimable.
    for trial in 1..=8 {
        let mut small = OpBudget::new(trial);
        let _ = q.gc(u64::MAX / 4, 1_000, &mut small);
        let receipt = q.store().head(&Key::new(format!("q/receipts/0000/{jhex}")));
        if receipt.is_err() {
            // Deletion completed on this trial: the terminal record is
            // gone because it went LAST; the job must be gone too.
            assert!(
                q.store()
                    .head(&Key::new(format!("q/jobs/0000/{jhex}")))
                    .is_err(),
                "job record must not outlive the terminal record"
            );
            break;
        }
        // Still mid-deletion: terminal record present, job unclaimable.
        let claimed = q
            .claim(&claim_opts(u64::MAX / 4, 1_000), &mut OpBudget::new(64))
            .unwrap();
        assert!(
            matches!(claimed, stowq_core::ClaimOutcome::Empty),
            "trial {trial}: mid-GC job must be unclaimable while its terminal record exists"
        );
    }
}
