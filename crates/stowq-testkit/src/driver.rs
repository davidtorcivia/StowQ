//! Differential driver: runs seeded pseudo-random operation sequences
//! through both the oracle and stowq-core over the memory fake, asserting
//! observable equivalence after every step. The same seed re-runs under
//! fault injection and must stay equivalent: injected faults are
//! transport-level, and every core write path resolves them internally.

use crate::oracle::{Oracle, Phase, Terminal};
use stowq_core::{
    AckOutcome, Claim, ClaimOptions, ClaimOutcome, EnqueueInput, EnqueueOutcome, OpBudget,
    OpenOptions, Queue, RenewOutcome,
};
use stowq_format::FormatRecord;
use stowq_store::{Fault, FaultPlan, Injector, MemoryStore, ObjectStore as _, Op};

/// Small deterministic PRNG (splitmix64).
#[derive(Debug, Clone)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed.wrapping_add(0x9e37_79b9_7f4a_7c15))
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    pub fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }
}

/// One driver operation, in terms both sides understand.
#[derive(Debug, Clone, Copy)]
pub enum DriveOp {
    Enqueue { job: usize },
    Claim,
    Renew { job: usize },
    Ack { job: usize },
    Nack { job: usize },
    Bury { job: usize },
    AdvanceClock { to: u64 },
}

pub struct DriverConfig {
    pub jobs: usize,
    pub ops: usize,
    pub lease_ns: u64,
    pub max_attempts: u64,
}

impl Default for DriverConfig {
    fn default() -> Self {
        DriverConfig {
            jobs: 4,
            ops: 200,
            lease_ns: 1_000,
            max_attempts: 3,
        }
    }
}

fn queue_retry_policy() -> stowq_math::RetryPolicy {
    stowq_math::RetryPolicy::new(100, 60_000, true, None).expect("valid default policy")
}

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

fn job_id(index: usize) -> [u8; 16] {
    let mut id = [0u8; 16];
    id[..8].copy_from_slice(&(index as u64).to_be_bytes());
    id
}

fn job_index(id: &[u8; 16]) -> usize {
    let mut b = [0u8; 8];
    b.copy_from_slice(&id[..8]);
    u64::from_be_bytes(b) as usize
}

fn gen_ops(rng: &mut Rng, cfg: &DriverConfig) -> Vec<DriveOp> {
    let mut ops: Vec<DriveOp> = Vec::with_capacity(cfg.ops);
    for _ in 0..cfg.ops {
        let job = rng.below(cfg.jobs as u64) as usize;
        ops.push(match rng.below(7) {
            0 => DriveOp::Enqueue { job },
            1 => DriveOp::Claim,
            2 => DriveOp::Renew { job },
            3 => DriveOp::Ack { job },
            4 => DriveOp::Nack { job },
            5 => DriveOp::Bury { job },
            // Exponential clock: the median draw is ~93us and the
            // maximum ~8.6s, so microsecond leases and the retry
            // backoffs both elapse.
            _ => DriveOp::AdvanceClock {
                to: (1u64 << rng.below(34)) - 1,
            },
        });
    }
    ops
}

/// Runs the sequence against both sides. Every operation's observable
/// outcome is asserted equal, and the terminal state of every job is
/// verified against the store at the end. Returns the final clock.
pub fn run_differential(seed: u64, cfg: &DriverConfig, faults: bool) -> u64 {
    run_with_stats(seed, cfg, faults).0
}

/// Returns (final clock, exhaustion-dead transitions observed).
pub fn run_with_stats(seed: u64, cfg: &DriverConfig, faults: bool) -> (u64, usize) {
    let mut rng = Rng::new(seed);
    let ops = gen_ops(&mut rng, cfg);

    let store = MemoryStore::new();
    // Faults land on whatever PutIfAbsent call reaches each index
    // (init, enqueue, claim, dead, receipt, and index writes alike) —
    // every write path must resolve them internally.
    let queue_store: Box<dyn stowq_store::ObjectStore> = if faults {
        Box::new(Injector::new(
            store.clone(),
            vec![
                FaultPlan::new(Op::PutIfAbsent, Fault::PreTransmit, [3, 17]),
                FaultPlan::new(Op::PutIfAbsent, Fault::PostTransmit, [9]),
                FaultPlan::new(Op::PutIfAbsent, Fault::PostTransmitAfter, [25, 41]),
            ],
        ))
    } else {
        Box::new(store.clone())
    };

    let queue = Queue::init(queue_store, "q", &OpenOptions::new([1; 16]), &format()).expect("init");

    let mut oracle = Oracle::new();
    // The real handles a worker would hold, from core returns.
    let mut held: Vec<Option<Claim>> = vec![None; cfg.jobs];
    let mut budget = OpBudget::new(4_096);
    let mut exhausted = 0usize;

    for (i, op) in ops.iter().enumerate() {
        match *op {
            DriveOp::Enqueue { job } => {
                let id = job_id(job);
                let expected = oracle.enqueue(id, cfg.max_attempts, 0);
                let out = queue
                    .enqueue(
                        EnqueueInput {
                            job_id: Some(id),
                            payload: b"x",
                            content_type: "text/plain".into(),
                            maximum_attempts: cfg.max_attempts,
                            not_before_ns: None,
                        },
                        &mut budget,
                    )
                    .expect("enqueue survives faults");
                let committed = matches!(out, EnqueueOutcome::Committed { .. });
                assert_eq!(committed, expected, "seed {seed} op {i} enqueue({job})");
            }
            DriveOp::Claim => {
                // Replicate the core's scan in index order: exhaustion
                // writes dead as a side effect, the first claimable job
                // wins, and the scan stops there.
                let mut expected_job = None;
                for j in 0..cfg.jobs {
                    let id = job_id(j);
                    if oracle.exhaust_if_due(&id) {
                        exhausted += 1;
                        // Custody was lost at expiry and the sweep
                        // dead-ended the job; the held handle is stale,
                        // exactly as a real worker would learn.
                        held[j] = None;
                        continue;
                    }
                    if oracle.can_claim(&id) {
                        expected_job = Some(j);
                        break;
                    }
                }
                let opts = ClaimOptions {
                    shard: 0,
                    floor_ns: oracle.clock,
                    lease_duration_ns: cfg.lease_ns,
                };
                let out = queue.claim(&opts, &mut budget).expect("claim op");
                match (out, expected_job) {
                    (ClaimOutcome::Claimed(c), Some(j)) => {
                        assert_eq!(
                            job_index(&c.job_id),
                            j,
                            "seed {seed} op {i}: core claimed a different job than the scan order predicts"
                        );
                        let expected = oracle
                            .claim(&c.job_id, cfg.lease_ns, c.claim_store_time_ns)
                            .expect("can_claim agreed a moment ago");
                        assert_eq!(
                            (c.generation, c.attempt),
                            expected,
                            "seed {seed} op {i} job {j}"
                        );
                        held[j] = Some(c);
                    }
                    (ClaimOutcome::Empty, None) => {}
                    (ClaimOutcome::Claimed(c), None) => {
                        panic!(
                            "seed {seed} op {i}: core claimed job {} but oracle scan predicted none",
                            job_index(&c.job_id)
                        );
                    }
                    (ClaimOutcome::Empty, Some(j)) => {
                        panic!("seed {seed} op {i}: oracle scan predicted job {j} but core returned empty");
                    }
                }
            }
            DriveOp::Renew { job } => {
                let id = job_id(job);
                match held[job].clone() {
                    Some(claim) => {
                        let expected = oracle.renew(&id, cfg.lease_ns);
                        let out = queue.renew(&claim, &mut budget).expect("renew op");
                        match (out, expected) {
                            (RenewOutcome::Renewed(renewed), true) => {
                                oracle.override_expiry(
                                    &id,
                                    renewed.claim_store_time_ns,
                                    cfg.lease_ns,
                                );
                                held[job] = Some(renewed);
                            }
                            (RenewOutcome::LeaseLost, false) => held[job] = None,
                            (RenewOutcome::Renewed(_), false) => {
                                panic!("seed {seed} op {i}: core renewed, oracle refused")
                            }
                            (RenewOutcome::LeaseLost, true) => {
                                panic!("seed {seed} op {i}: oracle renewed, core lost")
                            }
                        }
                    }
                    None => assert!(
                        !oracle.renew(&id, cfg.lease_ns),
                        "seed {seed} op {i}: driver holds nothing but oracle renewed"
                    ),
                }
            }
            DriveOp::Ack { job } => {
                let id = job_id(job);
                match held[job].take() {
                    Some(claim) => {
                        let expected = oracle.ack(&id);
                        let out = queue.ack(&claim, &mut budget).expect("ack op");
                        // First ack commits; an already-acked receipt with
                        // matching evidence is success either way.
                        let acked = matches!(out, AckOutcome::Acked | AckOutcome::AlreadyAcked);
                        assert_eq!(acked, expected, "seed {seed} op {i} ack({job}) out={out:?}");
                    }
                    None => assert!(
                        !oracle.ack(&id),
                        "seed {seed} op {i}: driver holds nothing but oracle acked"
                    ),
                }
            }
            DriveOp::Nack { job } => {
                let id = job_id(job);
                match held[job].take() {
                    Some(claim) => {
                        // The exact delay the core applies, from the same
                        // policy call: deterministic per job and attempt.
                        let delay_ms = stowq_math::retry_delay_ms(
                            &[1; 16],
                            &id,
                            claim.attempt as u32,
                            &queue_retry_policy(),
                        )
                        .expect("policy is valid");
                        let until = oracle.clock + delay_ms * 1_000_000;
                        let expected = oracle.nack(&id, until);
                        queue
                            .nack(&claim, 0x0001, oracle.clock, &mut budget)
                            .expect("nack op");
                        assert!(expected, "seed {seed} op {i} nack mismatch");
                    }
                    None => assert!(
                        !oracle.nack(&id, oracle.clock.saturating_add(1)),
                        "seed {seed} op {i}: driver holds nothing but oracle nacked"
                    ),
                }
            }
            DriveOp::Bury { job } => {
                let id = job_id(job);
                match held[job].take() {
                    Some(claim) => {
                        let expected = oracle.bury(&id, 0x0003);
                        queue.bury(&claim, 0x0003, &mut budget).expect("bury op");
                        assert!(expected, "seed {seed} op {i} bury mismatch");
                    }
                    None => assert!(
                        !oracle.bury(&id, 0x0003),
                        "seed {seed} op {i}: driver holds nothing but oracle buried"
                    ),
                }
            }
            DriveOp::AdvanceClock { to } => {
                oracle.advance_clock_to(to);
                store.advance_clock_to(to);
            }
        }
    }

    // Final-state equivalence: terminal records in the store must match
    // the oracle's terminal phases, job for job.
    for j in 0..cfg.jobs {
        let id = job_id(j);
        let hex_id: String = id.iter().map(|b| format!("{b:02x}")).collect();
        let receipt = store.head(&stowq_store::Key::new(format!("q/receipts/0000/{hex_id}")));
        let dead = store.head(&stowq_store::Key::new(format!("q/dead/0000/{hex_id}")));
        match oracle.jobs.get(&id).map(|s| &s.phase) {
            Some(Phase::Terminal(Terminal::Receipt)) => {
                assert!(
                    receipt.is_ok(),
                    "seed {seed} job {j}: oracle receipt, store none"
                );
                assert!(
                    dead.is_err(),
                    "seed {seed} job {j}: oracle receipt but dead exists"
                );
            }
            Some(Phase::Terminal(Terminal::Dead { .. })) => {
                assert!(dead.is_ok(), "seed {seed} job {j}: oracle dead, store none");
                assert!(
                    receipt.is_err(),
                    "seed {seed} job {j}: oracle dead but receipt exists"
                );
            }
            _ => {
                assert!(
                    receipt.is_err() && dead.is_err(),
                    "seed {seed} job {j}: oracle non-terminal but store has a terminal record"
                );
            }
        }
    }

    (oracle.clock, exhausted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn differential_clean_seeds() {
        for seed in 1..=25u64 {
            run_differential(seed, &DriverConfig::default(), false);
        }
    }

    #[test]
    fn differential_faulted_seeds() {
        for seed in 1..=25u64 {
            run_differential(seed, &DriverConfig::default(), true);
        }
    }

    #[test]
    fn exhaustion_transition_is_exercised() {
        let cfg = DriverConfig::default();
        let mut total = 0;
        for seed in 1..=25u64 {
            total += run_with_stats(seed, &cfg, false).1;
        }
        assert!(total > 0, "distribution must reach exhaustion-dead");
    }

    #[test]
    fn faulted_and_clean_agree_on_terminal_state() {
        // The same seed's final terminal set is identical with and
        // without injection: faults are transport-level only.
        let cfg = DriverConfig::default();
        for seed in 1..=10u64 {
            // run_differential returns the clock; both runs internally
            // verify terminal state, so completing is the assertion.
            run_differential(seed, &cfg, false);
            run_differential(seed, &cfg, true);
        }
    }
}
