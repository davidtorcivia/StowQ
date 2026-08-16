//! Interleaving lab: multiple workers over one shared store, a seeded
//! scheduler interleaving their operations, and invariant checks at
//! every quiescent point. The adversary is concurrency plus ambiguity,
//! not partial persistence — so the lab races real `Queue` instances
//! (Arc-shared MemoryStore clones) and asserts the protocol's
//! structural invariants after every scheduled step.
//!
//! Invariants (per job, checked after each step):
//! - at most one terminal record exists (receipt XOR dead, never both);
//! - claim generations are strictly increasing and unique per step;
//! - no two workers hold a live claim at the same generation.

use crate::driver::Rng;
use stowq_core::{
    AckOutcome, Claim, ClaimOptions, ClaimOutcome, EnqueueInput, OpBudget, OpenOptions, Queue,
    RenewOutcome,
};
use stowq_format::FormatRecord;
use stowq_store::{Key, MemoryStore};

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

fn job_id(i: usize) -> [u8; 16] {
    let mut id = [0u8; 16];
    id[..8].copy_from_slice(&(i as u64).to_be_bytes());
    id
}

fn jhex(id: [u8; 16]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

/// What one worker can do in a scheduled step.
#[derive(Debug, Clone, Copy)]
enum Step {
    Enqueue(usize),
    Claim,
    Renew(usize),
    Ack(usize),
    Bury(usize),
    AdvanceClock(u64),
}

/// Checks the structural invariants of one job in the store.
async fn check_invariants(q: &Queue, jobs: usize, _step_index: usize) {
    for j in 0..jobs {
        let id = job_id(j);
        let h = jhex(id);
        let receipt = q
            .store()
            .head(&Key::new(format!("q/receipts/0000/{h}")))
            .await;
        let dead = q.store().head(&Key::new(format!("q/dead/0000/{h}"))).await;
        // At most one terminal record.
        if receipt.is_ok() && dead.is_ok() {
            panic!("job {j}: both receipt and dead exist");
        }
        // Claim generations strictly increasing in the listing.
        let prefix = format!("q/claims/0000/{h}/");
        let mut after: Option<Key> = None;
        let mut gens: Vec<u64> = Vec::new();
        loop {
            let page = q.store().list(&prefix, after.as_ref(), 64).await.unwrap();
            if page.items.is_empty() {
                break;
            }
            for item in &page.items {
                if let Some(seg) = item.key.as_str().rsplit('/').next() {
                    if let Ok(g) = u64::from_str_radix(seg, 16) {
                        gens.push(g);
                    }
                }
            }
            match page.next_after {
                Some(k) => after = Some(k),
                None => break,
            }
        }
        let mut sorted = gens.clone();
        sorted.sort_unstable();
        sorted.dedup();
        if sorted.len() != gens.len() {
            panic!("job {j}: duplicate generation in claim chain");
        }
        // Keys are 8-hex zero-padded: listing order is numeric order.
        if gens != sorted {
            panic!("job {j}: generations not strictly increasing in listing order");
        }
    }
}

/// Runs one seeded interleaving. Workers hold real claims; the
/// scheduler picks which worker acts each step. Invariants are checked
/// after every step.
pub async fn run_interleaving(seed: u64, jobs: usize, steps: usize) {
    let store = MemoryStore::new();
    let mut queues: Vec<Queue> = Vec::new();
    for w in 0..2 {
        let mut opts = OpenOptions::new([1; 16]);
        opts.worker_id = format!("worker-{w}");
        let q = Queue::init(Box::new(store.clone()), "q", &opts, &format())
            .await
            .unwrap();
        queues.push(q);
    }
    // init happened twice over the shared store; the second put was
    // rejected and verified identical — fine.

    let mut rng = Rng::new(seed);
    let mut held: Vec<Vec<Option<Claim>>> = queues.iter().map(|_| vec![None; jobs]).collect();
    // The scheduler's logical clock: the max of all advances. Claim
    // floors come from it; store write times advance with it, so it is
    // always a sound floor.
    let mut clock: u64 = 0;

    for step in 0..steps {
        let worker = (rng.next_u64() % queues.len() as u64) as usize;
        let job = (rng.below(jobs as u64)) as usize;
        let q = &queues[worker];
        let mut budget = OpBudget::new(512);
        let step_kind = match rng.below(6) {
            0 => Step::Enqueue(job),
            1 => Step::Claim,
            2 if held[worker][job].is_some() => Step::Renew(job),
            3 if held[worker][job].is_some() => Step::Ack(job),
            4 if held[worker][job].is_some() => Step::Bury(job),
            _ => Step::AdvanceClock((1u64 << rng.below(31)) - 1),
        };
        match step_kind {
            Step::Enqueue(j) => {
                let _ = q
                    .enqueue(
                        EnqueueInput {
                            job_id: Some(job_id(j)),
                            payload: b"x",
                            content_type: "text/plain".into(),
                            maximum_attempts: 3,
                            not_before_ns: None,
                        },
                        &mut budget,
                    )
                    .await
                    .unwrap();
            }
            Step::Claim => {
                // Any worker's claim races any other's.
                let opts = ClaimOptions {
                    shard: 0,
                    floor_ns: clock,
                    lease_duration_ns: 1_000,
                };
                if let ClaimOutcome::Claimed(c) = q.claim(&opts, &mut budget).await.unwrap() {
                    let j = claimed_index(&c);
                    // A committed claim proves the previous lease ended:
                    // any other worker's handle for this job is a zombie
                    // (their generation is below the new tail). Model
                    // what those workers would learn — custody
                    // transferred.
                    for (other_w, other_held) in held.iter_mut().enumerate() {
                        if other_w != worker {
                            if let Some(existing) = &other_held[j] {
                                assert!(
                                    existing.generation < c.generation,
                                    "step {step}: workers {other_w} and {worker} both hold \
                                     live generation {} on job {j}",
                                    c.generation
                                );
                            }
                            other_held[j] = None;
                        }
                    }
                    held[worker][j] = Some(c);
                }
            }
            Step::Renew(j) => {
                let claim = held[worker][j].clone().unwrap();
                match q.renew(&claim, &mut budget).await.unwrap() {
                    RenewOutcome::Renewed(renewed) => held[worker][j] = Some(renewed),
                    RenewOutcome::LeaseLost => held[worker][j] = None,
                }
            }
            Step::Ack(j) => {
                let claim = held[worker][j].take().unwrap();
                let out = q.ack(&claim, &mut budget).await.unwrap();
                assert!(matches!(
                    out,
                    AckOutcome::Acked | AckOutcome::AlreadyAcked | AckOutcome::SupersededByDead
                ));
            }
            Step::Bury(j) => {
                let claim = held[worker][j].take().unwrap();
                q.bury(&claim, 0x0003, &mut budget).await.unwrap();
            }
            Step::AdvanceClock(to) => {
                clock = clock.max(to);
                store.advance_clock_to(to);
            }
        }
        check_invariants(&queues[0], jobs, step).await;
    }
}

fn claimed_index(c: &Claim) -> usize {
    let mut b = [0u8; 8];
    b.copy_from_slice(&c.job_id[..8]);
    u64::from_be_bytes(b) as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn interleaving_corpus_green() {
        for seed in 1..=25u64 {
            run_interleaving(seed, 3, 150).await;
        }
    }

    /// Zombie ack race: worker A claims, expires; worker B takes over;
    /// A acks late. At most one terminal record must exist.
    #[tokio::test]
    async fn adversarial_zombie_ack_race() {
        let store = MemoryStore::new();
        let mk = |w: usize| {
            let mut opts = OpenOptions::new([1; 16]);
            opts.worker_id = format!("z{w}");
            let store = store.clone();
            async move {
                Queue::init(Box::new(store), "q", &opts, &format())
                    .await
                    .unwrap()
            }
        };
        let qa = mk(0).await;
        let qb = mk(1).await;
        let mut b = OpBudget::new(256);
        qa.enqueue(
            EnqueueInput {
                job_id: Some(job_id(0)),
                payload: b"x",
                content_type: "text/plain".into(),
                maximum_attempts: 3,
                not_before_ns: None,
            },
            &mut b,
        )
        .await
        .unwrap();
        let a_claim = match qa
            .claim(
                &ClaimOptions {
                    shard: 0,
                    floor_ns: 0,
                    lease_duration_ns: 1_000,
                },
                &mut b,
            )
            .await
            .unwrap()
        {
            ClaimOutcome::Claimed(c) => c,
            ClaimOutcome::Empty => panic!("first claim"),
        };
        // A expires; B takes over.
        let later = a_claim.claim_store_time_ns + 1_000;
        let b_claim = match qb
            .claim(
                &ClaimOptions {
                    shard: 0,
                    floor_ns: later,
                    lease_duration_ns: 1_000,
                },
                &mut b,
            )
            .await
            .unwrap()
        {
            ClaimOutcome::Claimed(c) => c,
            ClaimOutcome::Empty => panic!("takeover"),
        };
        assert_eq!(b_claim.generation, a_claim.generation + 1);
        // Zombie A acks late: accepted (first terminal wins), must not
        // produce a second terminal record, and must fence B's custody.
        let _ = qa.ack(&a_claim, &mut b).await.unwrap();
        check_invariants(&qa, 1, 0).await;
        // The receipt terminalizes the job: B cannot renew.
        let renewed = qb.renew(&b_claim, &mut b).await.unwrap();
        assert!(
            matches!(renewed, RenewOutcome::LeaseLost),
            "receipt must fence the live claim's renewal"
        );
        // B's ack against A's receipt: the receipt holds generation-1
        // evidence while B holds generation 2, so the idempotent-verify
        // fails the generation check and errors (quarantine finding
        // 0x0013). The job is terminal either way; no second record.
        let out = qb.ack(&b_claim, &mut b).await;
        assert!(
            matches!(out, Err(stowq_core::Error::ReceiptEvidenceMismatch)),
            "cross-generation ack must fail the receipt evidence check"
        );
        check_invariants(&qa, 1, 1).await;
    }

    /// Renewal vs takeover race at the same next generation.
    #[tokio::test]
    async fn adversarial_renewal_vs_takeover() {
        let store = MemoryStore::new();
        let mk = |w: usize| {
            let mut opts = OpenOptions::new([1; 16]);
            opts.worker_id = format!("r{w}");
            let store = store.clone();
            async move {
                Queue::init(Box::new(store), "q", &opts, &format())
                    .await
                    .unwrap()
            }
        };
        let qa = mk(0).await;
        let qb = mk(1).await;
        let mut b = OpBudget::new(256);
        qa.enqueue(
            EnqueueInput {
                job_id: Some(job_id(0)),
                payload: b"x",
                content_type: "text/plain".into(),
                maximum_attempts: 3,
                not_before_ns: None,
            },
            &mut b,
        )
        .await
        .unwrap();
        let a = match qa
            .claim(
                &ClaimOptions {
                    shard: 0,
                    floor_ns: 0,
                    lease_duration_ns: 1_000,
                },
                &mut b,
            )
            .await
            .unwrap()
        {
            ClaimOutcome::Claimed(c) => c,
            ClaimOutcome::Empty => panic!("claim"),
        };
        // Renewal wins generation 2...
        let RenewOutcome::Renewed(renewed) = qa.renew(&a, &mut b).await.unwrap() else {
            panic!("renew")
        };
        assert_eq!(renewed.generation, 2);
        // ...so the within-lease takeover attempt by B must lose:
        // floor equals the renewed tail's own store time, strictly
        // inside its lease.
        let later = renewed.claim_store_time_ns;
        let raced = qb
            .claim(
                &ClaimOptions {
                    shard: 0,
                    floor_ns: later,
                    lease_duration_ns: 1_000,
                },
                &mut b,
            )
            .await
            .unwrap();
        assert!(
            matches!(raced, ClaimOutcome::Empty),
            "within-lease takeover must be refused"
        );
        check_invariants(&qa, 1, 0).await;
    }

    /// Sweeper idempotence, sequentially: a second sweep over the
    /// pruned index consumes nothing. (The lab cannot interleave inside
    /// an operation; concurrent safety rests on idempotent deletes and
    /// authoritative re-verification.)
    #[tokio::test]
    async fn sequential_sweeper_idempotence() {
        let store = MemoryStore::new();
        let mk = |w: usize| {
            let mut opts = OpenOptions::new([1; 16]);
            opts.worker_id = format!("s{w}");
            let store = store.clone();
            async move {
                Queue::init(Box::new(store), "q", &opts, &format())
                    .await
                    .unwrap()
            }
        };
        let q1 = mk(0).await;
        let q2 = mk(1).await;
        let mut b = OpBudget::new(512);
        q1.enqueue(
            EnqueueInput {
                job_id: Some(job_id(0)),
                payload: b"x",
                content_type: "text/plain".into(),
                maximum_attempts: 3,
                not_before_ns: None,
            },
            &mut b,
        )
        .await
        .unwrap();
        let claim = match q1
            .claim(
                &ClaimOptions {
                    shard: 0,
                    floor_ns: 0,
                    lease_duration_ns: 1_000,
                },
                &mut b,
            )
            .await
            .unwrap()
        {
            ClaimOutcome::Claimed(c) => c,
            ClaimOutcome::Empty => panic!("claim"),
        };
        let later = claim.claim_store_time_ns + 2_000;
        // Two sweepers race; both must succeed and both must see a
        // consistent store afterwards.
        let r1 = q1.sweep_expired_leases(later, &mut b).await.unwrap();
        let r2 = q2.sweep_expired_leases(later, &mut b).await.unwrap();
        assert_eq!(r1.entries + r2.entries, 1, "entry consumed exactly once");
        check_invariants(&q1, 1, 0).await;
    }

    /// GC before and after a late ack, sequentially: non-terminal
    /// graphs are never collected; the late ack succeeds; past
    /// retention the full graph goes. (Mid-flight interleaving of gc
    /// and ack is not exercisable at the lab's step granularity.)
    #[tokio::test]
    async fn gc_around_a_late_ack() {
        let store = MemoryStore::new();
        let mk = |w: usize| {
            let mut opts = OpenOptions::new([1; 16]);
            opts.worker_id = format!("g{w}");
            let store = store.clone();
            async move {
                Queue::init(Box::new(store), "q", &opts, &format())
                    .await
                    .unwrap()
            }
        };
        let qa = mk(0).await;
        let qg = mk(1).await;
        let mut b = OpBudget::new(512);
        qa.enqueue(
            EnqueueInput {
                job_id: Some(job_id(0)),
                payload: b"x",
                content_type: "text/plain".into(),
                maximum_attempts: 3,
                not_before_ns: None,
            },
            &mut b,
        )
        .await
        .unwrap();
        let a = match qa
            .claim(
                &ClaimOptions {
                    shard: 0,
                    floor_ns: 0,
                    lease_duration_ns: 1_000,
                },
                &mut b,
            )
            .await
            .unwrap()
        {
            ClaimOutcome::Claimed(c) => c,
            ClaimOutcome::Empty => panic!("claim"),
        };
        // GC first: the job is not terminal, so nothing is deleted.
        let report = qg
            .gc(a.claim_store_time_ns + 100, 1_000, 60_000_000_000, &mut b)
            .await
            .unwrap();
        assert_eq!(report.jobs_deleted, 0, "non-terminal job must not be GC'd");
        // The late ack then succeeds normally.
        let out = qa.ack(&a, &mut b).await.unwrap();
        assert_eq!(out, AckOutcome::Acked);
        // A subsequent GC past retention deletes the graph; the
        // claimant is gone with it.
        let report = qg.gc(u64::MAX / 4, 1_000, 1_000, &mut b).await.unwrap();
        assert_eq!(report.jobs_deleted, 1);
        check_invariants(&qa, 1, 0).await;
    }
}
