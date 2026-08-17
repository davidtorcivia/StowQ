//! stowq-worker: the native consumer harness (M5 Phase A).
//!
//! The doorbell rule (spec contract.md): hints are lossy, duplicative,
//! and unordered; they are never correctness-bearing. A delivery is
//! claim -> verified payload -> execute (with renewal heartbeats) ->
//! commit_output for every store-resident effect -> ack. The store, not
//! the doorbell, decides who works.
//!
//! Invariants owned here: no action after LeaseLost; no terminal write
//! without re-verified payload evidence; every store-resident effect
//! through commit_output before ack. Duplicate doorbells are safe
//! because two harness instances converge on the store's put-if-absent
//! races — the loser learns Empty or LeaseLost and exits cleanly.

use async_trait::async_trait;
use bytes::Bytes;
use sha2::{Digest as _, Sha256};
use std::collections::VecDeque;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use stowq_core::{
    AckOutcome, BuryOutcome, ClaimOptions, ClaimOutcome, CommitOutcome, CommittedOutput, Error,
    OpBudget, Queue, RenewOutcome,
};

// ---------- Doorbell ----------

/// A lossy work hint: work MAY exist on these shards. An empty shard
/// list is a sweep hint (try every shard).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoorbellMsg {
    pub shards: Vec<u16>,
}

impl DoorbellMsg {
    pub fn shard(shard: u16) -> Self {
        DoorbellMsg {
            shards: vec![shard],
        }
    }

    pub fn sweep() -> Self {
        DoorbellMsg { shards: vec![] }
    }
}

/// The notification plane. Producers ring; the harness receives.
/// Lossy, duplicative, unordered by design — a missed hint only delays
/// work until the sweeper's scan finds it.
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
pub trait Doorbell: Send + Sync {
    async fn ring(&self, msg: DoorbellMsg);
    async fn recv(&self) -> Option<DoorbellMsg>;
}

/// In-memory stub: one FIFO of pending hints. Unbounded — a
/// test and demo surface, not a production plane.
#[derive(Default)]
pub struct StubDoorbell {
    pending: Mutex<VecDeque<DoorbellMsg>>,
}

impl StubDoorbell {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Doorbell for StubDoorbell {
    async fn ring(&self, msg: DoorbellMsg) {
        self.pending.lock().unwrap().push_back(msg);
    }

    async fn recv(&self) -> Option<DoorbellMsg> {
        self.pending.lock().unwrap().pop_front()
    }
}

/// A doorbell that logs every ring and receive to stderr, then
/// delegates. For demos and debugging.
pub struct LogDoorbell {
    inner: Box<dyn Doorbell>,
    label: String,
}

impl LogDoorbell {
    pub fn new(label: impl Into<String>, inner: Box<dyn Doorbell>) -> Self {
        LogDoorbell {
            inner,
            label: label.into(),
        }
    }
}

#[async_trait]
impl Doorbell for LogDoorbell {
    async fn ring(&self, msg: DoorbellMsg) {
        eprintln!("[doorbell {}] ring {:?}", self.label, msg.shards);
        self.inner.ring(msg).await;
    }

    async fn recv(&self) -> Option<DoorbellMsg> {
        let msg = self.inner.recv().await;
        eprintln!(
            "[doorbell {}] recv {:?}",
            self.label,
            msg.as_ref().map(|m| &m.shards)
        );
        msg
    }
}

// ---------- Executor ----------

/// One store-resident effect an executor produces; the harness commits
/// it through the commit rule at a deterministic job-derived key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutorOutput {
    pub name: String,
    pub body: Bytes,
}

/// Why an executor failed, and what the harness owes the job next:
/// a retryable failure nacks (backoff honored); a permanent one buries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionFailure {
    Retryable { reason: u64 },
    Permanent { reason: u64 },
}

/// Application work: verified payload in, named outputs out. The
/// future is dropped on lease loss, so implementations must be
/// cancellation-safe (no effects outside the store plane).
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
pub trait Executor: Send + Sync {
    async fn run(
        &self,
        job_id: [u8; 16],
        payload: Bytes,
    ) -> Result<Vec<ExecutorOutput>, ExecutionFailure>;
}

// ---------- Harness ----------

/// Delivery metrics: plain atomic counters, no dependencies, Send +
/// Sync. Share one via `Arc<Metrics>` and pass it to the `_with`
/// harness variants; the plain variants cost nothing. Snapshot for
/// reporting.
#[derive(Default)]
pub struct Metrics {
    /// Doorbell hints consumed by harness runs.
    pub hints: AtomicU64,
    /// Hints that found no claimable work.
    pub no_work: AtomicU64,
    /// Jobs delivered to terminal receipt (or verified-equivalent).
    pub delivered: AtomicU64,
    /// Executor failures that nacked (retryable).
    pub failed_retryable: AtomicU64,
    /// Executor failures that buried (permanent).
    pub failed_permanent: AtomicU64,
    /// Deliveries that observed a lost lease (takeover).
    pub lost_lease: AtomicU64,
    /// Successful renewal heartbeats.
    pub renewals: AtomicU64,
    /// Renewals that observed a takeover (LeaseLost).
    pub renewals_lost: AtomicU64,
    /// Store errors surfaced from harness operations.
    pub store_errors: AtomicU64,
    /// Delivery wall-time distribution, milliseconds, half-open
    /// buckets: [0,10) [10,50) [50,100) [100,250) [250,500)
    /// [500,1k) [1k,2.5k) [2.5k,5k) [5k,+inf).
    pub delivery_ms: [AtomicU64; 9],
}

impl Metrics {
    fn bucket_idx(ms: u128) -> usize {
        match ms {
            0..=9 => 0,
            10..=49 => 1,
            50..=99 => 2,
            100..=249 => 3,
            250..=499 => 4,
            500..=999 => 5,
            1_000..=2_499 => 6,
            2_500..=4_999 => 7,
            _ => 8,
        }
    }

    fn record_delivery(&self, elapsed: std::time::Duration) {
        let ms = elapsed.as_millis();
        self.delivery_ms[Self::bucket_idx(ms)].fetch_add(1, Ordering::Relaxed);
    }

    /// A plain-value copy for reporting.
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            hints: self.hints.load(Ordering::Relaxed),
            no_work: self.no_work.load(Ordering::Relaxed),
            delivered: self.delivered.load(Ordering::Relaxed),
            failed_retryable: self.failed_retryable.load(Ordering::Relaxed),
            failed_permanent: self.failed_permanent.load(Ordering::Relaxed),
            lost_lease: self.lost_lease.load(Ordering::Relaxed),
            renewals: self.renewals.load(Ordering::Relaxed),
            renewals_lost: self.renewals_lost.load(Ordering::Relaxed),
            store_errors: self.store_errors.load(Ordering::Relaxed),
            delivery_ms: self
                .delivery_ms
                .each_ref()
                .map(|c| c.load(Ordering::Relaxed)),
        }
    }
}

/// A printable copy of [`Metrics`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MetricsSnapshot {
    pub hints: u64,
    pub no_work: u64,
    pub delivered: u64,
    pub failed_retryable: u64,
    pub failed_permanent: u64,
    pub lost_lease: u64,
    pub renewals: u64,
    pub renewals_lost: u64,
    pub store_errors: u64,
    pub delivery_ms: [u64; 9],
}

impl fmt::Display for MetricsSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "hints {} (no-work {}) | delivered {} | failed {} retryable / {} permanent | lost-lease {} | renewals {} (lost {}) | store-errors {}",
            self.hints,
            self.no_work,
            self.delivered,
            self.failed_retryable,
            self.failed_permanent,
            self.lost_lease,
            self.renewals,
            self.renewals_lost,
            self.store_errors,
        )?;
        write!(
            f,
            "delivery ms [ <10 {} | 10-50 {} | 50-100 {} | 100-250 {} | 250-500 {} | 0.5-1k {} | 1-2.5k {} | 2.5-5k {} | >5k {} ]",
            self.delivery_ms[0], self.delivery_ms[1], self.delivery_ms[2],
            self.delivery_ms[3], self.delivery_ms[4], self.delivery_ms[5],
            self.delivery_ms[6], self.delivery_ms[7], self.delivery_ms[8],
        )
    }
}

/// Store ops allowed for one delivery: claim across hinted shards,
/// floor establishment, execution renewals, output commits, ack.
/// A sweep hint claims shard by shard, so a queue with more shards
/// than the budget allows fails `Err(BudgetExhausted)` mid-scan with
/// no claim held (the spend precedes every op) — the hint is simply
/// not fully served; retry it or let the sweeper find the work.
/// Exhaustion after a taken claim leaves that claim outstanding (it
/// expires; the sweeper reclaims) beside any already-committed
/// outputs, which are idempotent and converge on redelivery.
pub const DELIVERY_BUDGET_OPS: usize = 1024;

/// What one doorbell delivery came to.
#[derive(Debug)]
pub enum DeliveryReport {
    /// The hint was lossy or another worker took the work: nothing
    /// claimed, nothing owed.
    NoWork,
    /// The job executed, its outputs committed through the rule, and
    /// the receipt is written (or verified on a duplicate ack).
    Delivered { outputs: Vec<CommittedOutput> },
    /// Execution failed: nacked (backoff honored) or buried per the
    /// failure class.
    Failed {
        failure: ExecutionFailure,
        buried: bool,
    },
    /// The lease was lost mid-delivery (takeover): no further action —
    /// another worker owns the job now.
    LostLease,
}

/// Turns one doorbell delivery into at most one delivery of one job.
/// A floor session backs the claim; nack re-establishes (a cache hit
/// within the staleness window, a fresh beacon past it) so the backoff
/// never derives from a floor older than the window.
pub async fn run_delivery(
    q: &Queue,
    msg: &DoorbellMsg,
    exec: &dyn Executor,
    lease_duration_ns: u64,
) -> Result<DeliveryReport, Error> {
    run_delivery_with(q, msg, exec, lease_duration_ns, None).await
}

/// [`run_delivery`] with optional metrics collection.
pub async fn run_delivery_with(
    q: &Queue,
    msg: &DoorbellMsg,
    exec: &dyn Executor,
    lease_duration_ns: u64,
    metrics: Option<&Metrics>,
) -> Result<DeliveryReport, Error> {
    if let Some(m) = metrics {
        m.hints.fetch_add(1, Ordering::Relaxed);
    }
    let start = Instant::now();
    let report = match run_delivery_inner(q, msg, exec, lease_duration_ns, metrics).await {
        Ok(r) => r,
        Err(e) => {
            if let Some(m) = metrics {
                m.store_errors.fetch_add(1, Ordering::Relaxed);
            }
            return Err(e);
        }
    };
    if let Some(m) = metrics {
        m.record_delivery(start.elapsed());
        match &report {
            DeliveryReport::NoWork => m.no_work.fetch_add(1, Ordering::Relaxed),
            DeliveryReport::Delivered { .. } => m.delivered.fetch_add(1, Ordering::Relaxed),
            DeliveryReport::Failed { buried, .. } => {
                if *buried {
                    m.failed_permanent.fetch_add(1, Ordering::Relaxed)
                } else {
                    m.failed_retryable.fetch_add(1, Ordering::Relaxed)
                }
            }
            DeliveryReport::LostLease => m.lost_lease.fetch_add(1, Ordering::Relaxed),
        };
    }
    Ok(report)
}

async fn run_delivery_inner(
    q: &Queue,
    msg: &DoorbellMsg,
    exec: &dyn Executor,
    lease_duration_ns: u64,
    metrics: Option<&Metrics>,
) -> Result<DeliveryReport, Error> {
    let mut budget = OpBudget::new(DELIVERY_BUDGET_OPS);
    let floor = q.establish_floor(&mut budget).await?;

    let shards: Vec<u16> = if msg.shards.is_empty() {
        (0..q.format().shard_count).map(|s| s as u16).collect()
    } else {
        msg.shards.clone()
    };
    let mut claim = None;
    for shard in shards {
        let opts = ClaimOptions {
            shard,
            floor_ns: floor,
            lease_duration_ns,
        };
        match q.claim(&opts, &mut budget).await? {
            ClaimOutcome::Claimed(c) => {
                claim = Some(c);
                break;
            }
            ClaimOutcome::Empty => continue,
        }
    }
    let Some(claim) = claim else {
        return Ok(DeliveryReport::NoWork);
    };
    deliver_one(q, claim, exec, lease_duration_ns, &mut budget, metrics).await
}

/// One claimed job through execution (with renewal heartbeats) to its
/// terminal or lost-lease report. The executor future is dropped on
/// lease loss; no store action follows.
async fn deliver_one(
    q: &Queue,
    mut claim: stowq_core::Claim,
    exec: &dyn Executor,
    lease_duration_ns: u64,
    budget: &mut OpBudget,
    metrics: Option<&Metrics>,
) -> Result<DeliveryReport, Error> {
    // Delivery = committed claim + verified payload (spec records.md):
    // payload() verifies the digest, so the executor never sees
    // unverified bytes.
    let payload = claim.payload(q.store()).await?;
    let payload_digest: [u8; 32] = Sha256::digest(&payload).into();

    // Renewal cadence: lease/3 wall-clock, floored at 1ms so a
    // sub-millisecond lease cannot busy-loop renewals. The store clock
    // governs expiry; this timer only keeps custody current.
    let interval = Duration::from_nanos(lease_duration_ns / 3).max(Duration::from_millis(1));
    let mut exec_fut = Box::pin(exec.run(claim.job_id, payload));
    loop {
        tokio::select! {
            out = &mut exec_fut => {
                return finish_delivery(q, &claim, out, payload_digest, budget).await;
            }
            _ = tokio::time::sleep(interval) => {
                match q.renew(&claim, budget).await? {
                    RenewOutcome::Renewed(c) => {
                        if let Some(m) = metrics {
                            m.renewals.fetch_add(1, Ordering::Relaxed);
                        }
                        claim = c;
                    }
                    // No action after LeaseLost: no nack, no ack, no
                    // commits — the new owner decides the job's fate.
                    RenewOutcome::LeaseLost => {
                        if let Some(m) = metrics {
                            m.renewals_lost.fetch_add(1, Ordering::Relaxed);
                        }
                        return Ok(DeliveryReport::LostLease);
                    }
                }
            }
        }
    }
}

/// The batch shape: one floor session, one scan per hinted shard
/// claiming up to `batch` jobs ([`Queue::claim_many`]), then each job
/// delivered in claim order. Only the job under execution is renewed;
/// queued claims age, and one whose lease was taken over by the time
/// its turn comes reports [`DeliveryReport::LostLease`] — the ordinary
/// takeover rules decide the job, never the batch. Batch size should
/// fit within lease / per-job execution time.
pub async fn run_batch(
    q: &Queue,
    msg: &DoorbellMsg,
    exec: &dyn Executor,
    lease_duration_ns: u64,
    batch: usize,
) -> Result<Vec<DeliveryReport>, Error> {
    run_batch_with(q, msg, exec, lease_duration_ns, batch, None).await
}

/// [`run_batch`] with optional metrics collection (per-delivery).
pub async fn run_batch_with(
    q: &Queue,
    msg: &DoorbellMsg,
    exec: &dyn Executor,
    lease_duration_ns: u64,
    batch: usize,
    metrics: Option<&Metrics>,
) -> Result<Vec<DeliveryReport>, Error> {
    if let Some(m) = metrics {
        m.hints.fetch_add(1, Ordering::Relaxed);
    }
    run_batch_inner(q, msg, exec, lease_duration_ns, batch, metrics).await
}

async fn run_batch_inner(
    q: &Queue,
    msg: &DoorbellMsg,
    exec: &dyn Executor,
    lease_duration_ns: u64,
    batch: usize,
    metrics: Option<&Metrics>,
) -> Result<Vec<DeliveryReport>, Error> {
    let mut budget = OpBudget::new(DELIVERY_BUDGET_OPS);
    let floor = q.establish_floor(&mut budget).await?;
    let shards: Vec<u16> = if msg.shards.is_empty() {
        (0..q.format().shard_count).map(|s| s as u16).collect()
    } else {
        msg.shards.clone()
    };
    let mut claims: Vec<stowq_core::Claim> = Vec::new();
    for shard in shards {
        if claims.len() >= batch {
            break;
        }
        let opts = ClaimOptions {
            shard,
            floor_ns: floor,
            lease_duration_ns,
        };
        claims.extend(
            q.claim_many(&opts, batch - claims.len(), &mut budget)
                .await?,
        );
    }
    // Deliveries run CONCURRENTLY: independent claims, independent
    // renewal heartbeats, overlapping round trips — the batch's wall
    // time is the slowest delivery, not the sum. Reports preserve
    // claim (scan) order.
    type DeliveryFut<'a> = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<DeliveryReport, Error>> + Send + 'a>,
    >;
    let futs: Vec<DeliveryFut> = claims
        .into_iter()
        .map(|claim| {
            let mut budget = OpBudget::new(DELIVERY_BUDGET_OPS);
            let start = Instant::now();
            let fut: DeliveryFut = Box::pin(async move {
                let report =
                    deliver_one(q, claim, exec, lease_duration_ns, &mut budget, metrics).await?;
                if let Some(m) = metrics {
                    m.record_delivery(start.elapsed());
                    match &report {
                        DeliveryReport::NoWork => m.no_work.fetch_add(1, Ordering::Relaxed),
                        DeliveryReport::Delivered { .. } => {
                            m.delivered.fetch_add(1, Ordering::Relaxed)
                        }
                        DeliveryReport::Failed { buried, .. } => {
                            if *buried {
                                m.failed_permanent.fetch_add(1, Ordering::Relaxed)
                            } else {
                                m.failed_retryable.fetch_add(1, Ordering::Relaxed)
                            }
                        }
                        DeliveryReport::LostLease => m.lost_lease.fetch_add(1, Ordering::Relaxed),
                    };
                }
                Ok(report)
            });
            fut
        })
        .collect();
    let results = futures::future::join_all(futs).await;
    let mut reports = Vec::with_capacity(results.len());
    for r in results {
        reports.push(r?);
    }
    Ok(reports)
}

async fn finish_delivery(
    q: &Queue,
    claim: &stowq_core::Claim,
    executed: Result<Vec<ExecutorOutput>, ExecutionFailure>,
    payload_digest: [u8; 32],
    budget: &mut OpBudget,
) -> Result<DeliveryReport, Error> {
    match executed {
        Ok(outputs) => {
            // Every store-resident effect through the commit rule
            // BEFORE the receipt: deterministic keys, first-wins, and
            // the ack verifies presence and digests.
            let mut committed = Vec::with_capacity(outputs.len());
            for out in outputs {
                let out = match q.commit_output(claim, &out.name, out.body, budget).await? {
                    CommitOutcome::Committed(c) | CommitOutcome::Converged(c) => c,
                };
                committed.push(out);
            }
            match q.ack_with_outputs(claim, &committed, budget).await {
                Ok(AckOutcome::Acked | AckOutcome::AlreadyAcked) => {
                    Ok(DeliveryReport::Delivered { outputs: committed })
                }
                // A dead record terminalized the job while we held a
                // stale claim: not ours to decide anymore.
                Ok(AckOutcome::SupersededByDead) => Ok(DeliveryReport::LostLease),
                // A foreign receipt under a different claim's
                // generation can hold the SAME completed state (a
                // duplicate-doorbell zombie converging on the same
                // deterministic outputs): success-equivalent. The
                // receipt's payload and output digests decide.
                Err(Error::ReceiptEvidenceMismatch) => {
                    let equivalent = match q.receipt_for(claim, budget).await? {
                        Some(r) => {
                            r.payload_digest == payload_digest
                                && r.output_digests
                                    == committed.iter().map(|o| o.digest).collect::<Vec<_>>()
                        }
                        None => false,
                    };
                    if equivalent {
                        Ok(DeliveryReport::Delivered { outputs: committed })
                    } else {
                        Err(Error::ReceiptEvidenceMismatch)
                    }
                }
                Err(e) => Err(e),
            }
        }
        Err(failure) => {
            match &failure {
                ExecutionFailure::Retryable { reason } => {
                    // Re-establish rather than reuse the session floor:
                    // within the staleness window this is a cache hit
                    // (zero ops, the sanctioned reuse), past it a fresh
                    // beacon, so `retry_not_before` never derives from
                    // a floor older than the window (spec records.md,
                    // Renewal).
                    let floor = q.establish_floor(budget).await?;
                    q.nack(claim, *reason, floor, budget).await?;
                    Ok(DeliveryReport::Failed {
                        failure,
                        buried: false,
                    })
                }
                ExecutionFailure::Permanent { reason } => {
                    match q.bury(claim, *reason, budget).await? {
                        BuryOutcome::Buried => Ok(DeliveryReport::Failed {
                            failure,
                            buried: true,
                        }),
                        // SupersededByReceipt: the job completed via
                        // another path; no dead record exists, and our
                        // failure report still stands.
                        BuryOutcome::SupersededByReceipt => Ok(DeliveryReport::Failed {
                            failure,
                            buried: false,
                        }),
                    }
                }
            }
        }
    }
}

// ---------- Cron sweeper ----------

/// One sweeper pass: expired-lease reclamation and delayed promotion
/// over the queue's floors. Idempotent; safe to run concurrently.
pub async fn sweep_once(
    q: &Queue,
    budget: &mut OpBudget,
) -> Result<stowq_core::SweepReport, Error> {
    let floor = q.establish_floor(budget).await?;
    let leases = q.sweep_expired_leases(floor, budget).await?;
    let delayed = q.sweep_delayed(floor, budget).await?;
    Ok(stowq_core::SweepReport {
        entries: leases.entries + delayed.entries,
        reclaimed: leases.reclaimed,
        promoted: delayed.promoted,
    })
}

/// Runs [`sweep_once`] every `period` until `stop` observes `true`.
/// This is the doorbell-less posture's safety net: whatever a missed
/// hint delays, the sweeper's scan eventually finds.
pub async fn run_sweeper(
    q: std::sync::Arc<Queue>,
    period: Duration,
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> Result<(), Error> {
    loop {
        if *stop.borrow() {
            return Ok(());
        }
        let mut budget = OpBudget::new(4096);
        sweep_once(&q, &mut budget).await?;
        tokio::select! {
            _ = tokio::time::sleep(period) => {}
            _ = stop.changed() => return Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use stowq_core::{EnqueueInput, EnqueueOutcome, OpenOptions};
    use stowq_format::FormatRecord;
    use stowq_store::{MemoryStore, ObjectStore as _, StoreError};

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

    async fn queue(store: &MemoryStore) -> Queue {
        Queue::open(Box::new(store.clone()), "q", OpenOptions::new([1; 16]))
            .await
            .unwrap()
    }

    pub(crate) async fn queue_with_job() -> (Queue, MemoryStore, [u8; 16]) {
        let store = MemoryStore::new();
        let q = Queue::init(
            Box::new(store.clone()),
            "q",
            &OpenOptions::new([1; 16]),
            &format(),
        )
        .await
        .unwrap();
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
        (q, store, job_id)
    }

    fn jhex(id: &[u8; 16]) -> String {
        id.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// An executor producing fixed output.
    pub(crate) struct Fixed(pub Vec<ExecutorOutput>);

    #[async_trait]
    impl Executor for Fixed {
        async fn run(
            &self,
            _job_id: [u8; 16],
            _payload: Bytes,
        ) -> Result<Vec<ExecutorOutput>, ExecutionFailure> {
            Ok(self.0.clone())
        }
    }

    /// An executor that performs a takeover (as worker 2 would) and
    /// then stalls past the first renewal tick.
    struct TakeoverDuringExecution {
        store: MemoryStore,
        lease_ns: u64,
        stall: Duration,
    }

    #[async_trait]
    impl Executor for TakeoverDuringExecution {
        async fn run(
            &self,
            _job_id: [u8; 16],
            _payload: Bytes,
        ) -> Result<Vec<ExecutorOutput>, ExecutionFailure> {
            // Force store time past the first claim's lease, then take
            // over as a second worker would.
            self.store.advance_clock_to(u64::MAX / 4);
            let q2 = queue(&self.store).await;
            let later = q2.establish_floor(&mut OpBudget::new(64)).await.unwrap();
            let opts = ClaimOptions {
                shard: 0,
                floor_ns: later,
                lease_duration_ns: self.lease_ns,
            };
            let ClaimOutcome::Claimed(_c2) =
                q2.claim(&opts, &mut OpBudget::new(512)).await.unwrap()
            else {
                panic!("takeover claim")
            };
            tokio::time::sleep(self.stall).await;
            Ok(vec![])
        }
    }

    async fn enqueue_job(q: &Queue, id: [u8; 16]) {
        let mut b = OpBudget::new(128);
        let stowq_core::EnqueueOutcome::Committed { .. } = q
            .enqueue(
                EnqueueInput {
                    job_id: Some(id),
                    payload: b"work",
                    content_type: "text/plain".into(),
                    maximum_attempts: 5,
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

    #[tokio::test]
    async fn batch_delivers_all_in_claim_order() {
        let store = MemoryStore::new();
        let q = Queue::init(
            Box::new(store.clone()),
            "q",
            &OpenOptions::new([1; 16]),
            &format(),
        )
        .await
        .unwrap();
        for i in 1..=4u8 {
            enqueue_job(&q, [i; 16]).await;
        }
        let reports = run_batch(
            &q,
            &DoorbellMsg::sweep(),
            &Fixed(vec![ExecutorOutput {
                name: "r".into(),
                body: Bytes::from_static(b"done"),
            }]),
            60_000_000_000,
            8,
        )
        .await
        .unwrap();
        assert_eq!(reports.len(), 4, "all four jobs in one batch");
        assert!(reports
            .iter()
            .all(|r| matches!(r, DeliveryReport::Delivered { .. })));
        for i in 1..=4u8 {
            let hex: String = [i; 16].iter().map(|b| format!("{b:02x}")).collect();
            assert!(store
                .head(&stowq_store::Key::new(format!("q/receipts/0000/{hex}")))
                .await
                .is_ok());
        }
    }

    /// Executor that, while processing job 1 of the batch, ages store
    /// time past every lease and lets a rival claim jobs 1 and 2 (scan
    /// order; no acks). Job 2 then outlives one renewal tick, so its
    /// turn observes the takeover: the honest LostLease-by-turn path.
    struct StealQueued {
        store: MemoryStore,
    }

    #[async_trait]
    impl Executor for StealQueued {
        async fn run(
            &self,
            job_id: [u8; 16],
            _payload: Bytes,
        ) -> Result<Vec<ExecutorOutput>, ExecutionFailure> {
            if job_id == [1; 16] {
                self.store.advance_clock_to(u64::MAX / 4);
                let r = Queue::open(Box::new(self.store.clone()), "q", OpenOptions::new([1; 16]))
                    .await
                    .unwrap();
                let mut b = OpBudget::new(256);
                let floor = r.establish_floor(&mut b).await.unwrap();
                for want in [1u8, 2u8] {
                    let ClaimOutcome::Claimed(c) = r
                        .claim(
                            &ClaimOptions {
                                shard: 0,
                                floor_ns: floor,
                                lease_duration_ns: 60_000_000_000,
                            },
                            &mut b,
                        )
                        .await
                        .unwrap()
                    else {
                        panic!("rival claim")
                    };
                    assert_eq!(c.job_id, [want; 16], "scan order");
                }
            }
            if job_id == [2; 16] {
                // Outlive one renewal tick so the takeover is observed
                // by OUR renewal, not swallowed by an instant finish.
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
            Ok(vec![ExecutorOutput {
                name: "r".into(),
                body: Bytes::from_static(b"out"),
            }])
        }
    }

    #[tokio::test]
    async fn stolen_queued_claim_reports_lost_and_converges() {
        let store = MemoryStore::new();
        let q = Queue::init(
            Box::new(store.clone()),
            "q",
            &OpenOptions::new([1; 16]),
            &format(),
        )
        .await
        .unwrap();
        for i in 1..=3u8 {
            enqueue_job(&q, [i; 16]).await;
        }
        // Wall lease 300ms (3e8 ns) -> renewal ticks at 100ms, before
        // job 2's 150ms executor sleep; the store-time aging and the
        // rival takeover happen inside job 1's executor.
        let reports = run_batch(
            &q,
            &DoorbellMsg::sweep(),
            &StealQueued {
                store: store.clone(),
            },
            300_000_000,
            3,
        )
        .await
        .unwrap();
        assert_eq!(reports.len(), 3);
        // Job 1: our zombie ack wrote the first-wins receipt (the rival
        // claimed but never acked) — Delivered, exactly one receipt.
        assert!(matches!(reports[0], DeliveryReport::Delivered { .. }));
        // Job 2: our renewal observed the rival's generation-2 claim —
        // no further action, the takeover owns the job.
        assert!(
            matches!(reports[1], DeliveryReport::LostLease),
            "{:?}",
            reports
        );
        // Job 3: untouched by the rival, delivered normally.
        assert!(matches!(reports[2], DeliveryReport::Delivered { .. }));
        for (i, expect) in [(1u8, 1usize), (2, 0), (3, 1)] {
            let hex: String = [i; 16].iter().map(|b| format!("{b:02x}")).collect();
            let n = store
                .list(&format!("q/receipts/0000/{hex}"), None, 4)
                .await
                .unwrap()
                .items
                .len();
            assert_eq!(
                n, expect,
                "job {i}: jobs 1 and 3 terminal; 2 is the rival's in flight"
            );
        }
    }

    #[tokio::test]
    async fn stub_doorbell_is_fifo_and_empty_recv_is_none() {
        let d = StubDoorbell::new();
        assert!(d.recv().await.is_none());
        d.ring(DoorbellMsg::shard(3)).await;
        d.ring(DoorbellMsg::sweep()).await;
        assert_eq!(d.recv().await, Some(DoorbellMsg::shard(3)));
        assert_eq!(d.recv().await, Some(DoorbellMsg::sweep()));
        assert!(d.recv().await.is_none());
    }

    #[tokio::test]
    async fn log_doorbell_delegates() {
        let d = LogDoorbell::new("test", Box::new(StubDoorbell::new()));
        d.ring(DoorbellMsg::shard(1)).await;
        assert_eq!(d.recv().await, Some(DoorbellMsg::shard(1)));
        assert!(d.recv().await.is_none());
    }

    #[tokio::test]
    async fn delivery_commits_outputs_and_acks() {
        let (q, store, job_id) = queue_with_job().await;
        let report = run_delivery(
            &q,
            &DoorbellMsg::sweep(),
            &Fixed(vec![ExecutorOutput {
                name: "result".into(),
                body: Bytes::from_static(b"done"),
            }]),
            60_000_000_000,
        )
        .await
        .unwrap();
        let DeliveryReport::Delivered { outputs } = report else {
            panic!("expected Delivered, got {report:?}")
        };
        assert_eq!(outputs.len(), 1);
        // Output object at the deterministic key; receipt records it.
        let obj = store
            .get(
                &stowq_store::Key::new(format!("q/outputs/{}/result", jhex(&job_id))),
                None,
            )
            .await
            .unwrap();
        assert_eq!(&obj.body[..], b"done");
        assert!(store
            .head(&stowq_store::Key::new(format!(
                "q/receipts/0000/{}",
                jhex(&job_id)
            )))
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn lossy_hint_is_no_work() {
        let (q, _store, _id) = queue_with_job().await;
        // Empty queue store: a hint with no work behind it.
        let empty = MemoryStore::new();
        let qe = Queue::init(Box::new(empty), "q", &OpenOptions::new([1; 16]), &format())
            .await
            .unwrap();
        let _ = q;
        let report = run_delivery(&qe, &DoorbellMsg::sweep(), &Fixed(vec![]), 60_000_000_000)
            .await
            .unwrap();
        assert!(matches!(report, DeliveryReport::NoWork));
    }

    #[tokio::test]
    async fn duplicate_hint_finds_no_work() {
        let (q, _store, _id) = queue_with_job().await;
        let exec = Fixed(vec![]);
        let first = run_delivery(&q, &DoorbellMsg::sweep(), &exec, 60_000_000_000)
            .await
            .unwrap();
        assert!(matches!(first, DeliveryReport::Delivered { .. }));
        // The duplicate doorbell is safe: the job is terminal, the
        // second claim finds nothing.
        let second = run_delivery(&q, &DoorbellMsg::sweep(), &exec, 60_000_000_000)
            .await
            .unwrap();
        assert!(matches!(second, DeliveryReport::NoWork));
    }

    struct Fail(ExecutionFailure);

    #[async_trait]
    impl Executor for Fail {
        async fn run(
            &self,
            _job_id: [u8; 16],
            _payload: Bytes,
        ) -> Result<Vec<ExecutorOutput>, ExecutionFailure> {
            Err(self.0.clone())
        }
    }

    #[tokio::test]
    async fn retryable_failure_nacks() {
        let (q, store, job_id) = queue_with_job().await;
        let report = run_delivery(
            &q,
            &DoorbellMsg::sweep(),
            &Fail(ExecutionFailure::Retryable { reason: 0x0001 }),
            60_000_000_000,
        )
        .await
        .unwrap();
        match report {
            DeliveryReport::Failed {
                failure,
                buried: false,
            } => assert_eq!(failure, ExecutionFailure::Retryable { reason: 0x0001 }),
            other => panic!("expected Failed/nack, got {other:?}"),
        }
        let hex = jhex(&job_id);
        // No terminal record; the fail counter advanced (backoff path).
        assert_eq!(
            store
                .head(&stowq_store::Key::new(format!("q/receipts/0000/{hex}")))
                .await
                .unwrap_err(),
            StoreError::NotFound
        );
        assert_eq!(
            store
                .head(&stowq_store::Key::new(format!("q/dead/0000/{hex}")))
                .await
                .unwrap_err(),
            StoreError::NotFound
        );
        let page = store
            .list(&format!("q/fails/0000/{hex}"), None, 4)
            .await
            .unwrap();
        assert!(!page.items.is_empty(), "nack writes the fail record");
    }

    #[tokio::test]
    async fn permanent_failure_buries() {
        let (q, store, job_id) = queue_with_job().await;
        let report = run_delivery(
            &q,
            &DoorbellMsg::sweep(),
            &Fail(ExecutionFailure::Permanent { reason: 0x0003 }),
            60_000_000_000,
        )
        .await
        .unwrap();
        match report {
            DeliveryReport::Failed { buried: true, .. } => {}
            other => panic!("expected Failed/bury, got {other:?}"),
        }
        assert!(store
            .head(&stowq_store::Key::new(format!(
                "q/dead/0000/{}",
                jhex(&job_id)
            )))
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn permanent_failure_after_foreign_ack_reports_unburied() {
        let (q, store, job_id) = queue_with_job().await;
        let report = run_delivery(
            &q,
            &DoorbellMsg::sweep(),
            &AckThenPermanent {
                store: store.clone(),
            },
            60_000_000_000,
        )
        .await
        .unwrap();
        match report {
            DeliveryReport::Failed {
                failure: ExecutionFailure::Permanent { .. },
                buried: false,
            } => {}
            other => panic!("expected Failed/unburied, got {other:?}"),
        }
        // The receipt from the second worker is the terminal record;
        // no dead record exists.
        assert!(store
            .head(&stowq_store::Key::new(format!(
                "q/receipts/0000/{}",
                jhex(&job_id)
            )))
            .await
            .is_ok());
        assert!(
            store
                .head(&stowq_store::Key::new(format!(
                    "q/dead/0000/{}",
                    jhex(&job_id)
                )))
                .await
                .unwrap_err()
                == StoreError::NotFound
        );
    }

    /// A second worker delivers the same deterministic output while
    /// the first stalls; the first's late ack must verify the foreign
    /// receipt's completed state and report Delivered (equivalence).
    struct DeliverThenStall {
        store: MemoryStore,
    }

    #[async_trait]
    impl Executor for DeliverThenStall {
        async fn run(
            &self,
            _job_id: [u8; 16],
            _payload: Bytes,
        ) -> Result<Vec<ExecutorOutput>, ExecutionFailure> {
            self.store.advance_clock_to(u64::MAX / 4);
            let q2 = queue(&self.store).await;
            let mut b = OpBudget::new(256);
            let floor = q2.establish_floor(&mut b).await.unwrap();
            let ClaimOutcome::Claimed(c2) = q2
                .claim(
                    &ClaimOptions {
                        shard: 0,
                        floor_ns: floor,
                        lease_duration_ns: 60_000_000_000,
                    },
                    &mut b,
                )
                .await
                .unwrap()
            else {
                panic!("takeover claim")
            };
            let out = q2
                .commit_output(&c2, "r", Bytes::from_static(b"same"), &mut b)
                .await
                .unwrap();
            let committed = match out {
                stowq_core::CommitOutcome::Committed(c)
                | stowq_core::CommitOutcome::Converged(c) => c,
            };
            assert_eq!(
                q2.ack_with_outputs(&c2, &[committed], &mut b)
                    .await
                    .unwrap(),
                AckOutcome::Acked
            );
            tokio::time::sleep(Duration::from_millis(80)).await;
            Ok(vec![ExecutorOutput {
                name: "r".into(),
                body: Bytes::from_static(b"same"),
            }])
        }
    }

    #[tokio::test]
    async fn zombie_convergence_reports_delivered() {
        let (q, store, job_id) = queue_with_job().await;
        let report = run_delivery(
            &q,
            &DoorbellMsg::sweep(),
            &DeliverThenStall {
                store: store.clone(),
            },
            60_000_000_000,
        )
        .await
        .unwrap();
        let DeliveryReport::Delivered { outputs } = report else {
            panic!("expected Delivered, got {report:?}")
        };
        assert_eq!(outputs.len(), 1);
        // Exactly one receipt (the second worker's), first-wins output.
        assert!(store
            .head(&stowq_store::Key::new(format!(
                "q/receipts/0000/{}",
                jhex(&job_id)
            )))
            .await
            .is_ok());
        let obj = store
            .get(
                &stowq_store::Key::new(format!("q/outputs/{}/r", jhex(&job_id))),
                None,
            )
            .await
            .unwrap();
        assert_eq!(&obj.body[..], b"same");
    }

    #[tokio::test]
    async fn takeover_during_execution_stops_all_action() {
        tokio::time::pause();
        let (q, store, job_id) = queue_with_job().await;
        // Lease 150ms -> renewal ticks at 50ms; the executor takes over
        // at ~0ms and stalls 200ms, so the first renewal MUST observe
        // the takeover before the executor finishes.
        let report = run_delivery(
            &q,
            &DoorbellMsg::sweep(),
            &TakeoverDuringExecution {
                store: store.clone(),
                lease_ns: 150_000_000,
                stall: Duration::from_millis(200),
            },
            150_000_000,
        )
        .await
        .unwrap();
        assert!(matches!(report, DeliveryReport::LostLease), "{report:?}");
        let hex = jhex(&job_id);
        // No terminal record from us and no fail record (no nack): the
        // job is still owned by the takeover's claim.
        assert_eq!(
            store
                .head(&stowq_store::Key::new(format!("q/receipts/0000/{hex}")))
                .await
                .unwrap_err(),
            StoreError::NotFound
        );
        assert_eq!(
            store
                .head(&stowq_store::Key::new(format!("q/dead/0000/{hex}")))
                .await
                .unwrap_err(),
            StoreError::NotFound
        );
        let page = store
            .list(&format!("q/fails/0000/{hex}"), None, 4)
            .await
            .unwrap();
        assert!(page.items.is_empty(), "no nack after LeaseLost");
        // Generation 2 exists: the takeover's claim is intact.
        let page = store
            .list(&format!("q/claims/0000/{hex}/"), None, 4)
            .await
            .unwrap();
        assert!(page.items.len() >= 2, "claim chain advanced by takeover");
    }

    /// Acknowledges the job as a second worker mid-execution, then
    /// fails permanently: the bury must be refused by the receipt.
    struct AckThenPermanent {
        store: MemoryStore,
    }

    #[async_trait]
    impl Executor for AckThenPermanent {
        async fn run(
            &self,
            job_id: [u8; 16],
            _payload: Bytes,
        ) -> Result<Vec<ExecutorOutput>, ExecutionFailure> {
            // Expire the harness's lease in store time, then take the
            // job over and ack it as a second worker.
            self.store.advance_clock_to(u64::MAX / 4);
            let q2 = queue(&self.store).await;
            let mut b = OpBudget::new(256);
            let ClaimOutcome::Claimed(c2) = q2
                .claim(
                    &ClaimOptions {
                        shard: 0,
                        floor_ns: q2.establish_floor(&mut b).await.unwrap(),
                        lease_duration_ns: 60_000_000_000,
                    },
                    &mut b,
                )
                .await
                .unwrap()
            else {
                panic!("second claim for the acking worker")
            };
            assert_eq!(
                q2.ack(&c2, &mut b).await.unwrap(),
                AckOutcome::Acked,
                "second worker acks"
            );
            let _ = job_id;
            Err(ExecutionFailure::Permanent { reason: 0x0003 })
        }
    }

    /// Stalls past two renewal ticks, then succeeds.
    struct SlowOk {
        stall: Duration,
    }

    #[async_trait]
    impl Executor for SlowOk {
        async fn run(
            &self,
            _job_id: [u8; 16],
            _payload: Bytes,
        ) -> Result<Vec<ExecutorOutput>, ExecutionFailure> {
            tokio::time::sleep(self.stall).await;
            Ok(vec![ExecutorOutput {
                name: "result".into(),
                body: Bytes::from_static(b"slow"),
            }])
        }
    }

    #[tokio::test]
    async fn renewal_heartbeats_keep_custody() {
        // Paused clock: ticks at 150ms/300ms and completion at 330ms
        // fire in a fixed order, so the generation count is exact.
        tokio::time::pause();
        let (q, store, job_id) = queue_with_job().await;
        // Lease 450ms -> ticks at 150ms; the executor stalls 330ms, so
        // two renewals fire before completion and the receipt must
        // record the final (continuation) generation, not 1.
        let report = run_delivery(
            &q,
            &DoorbellMsg::sweep(),
            &SlowOk {
                stall: Duration::from_millis(330),
            },
            450_000_000,
        )
        .await
        .unwrap();
        assert!(
            matches!(report, DeliveryReport::Delivered { .. }),
            "{report:?}"
        );
        let rel = format!("receipts/0000/{}", jhex(&job_id));
        let obj = store
            .get(&stowq_store::Key::new(format!("q/{rel}")), None)
            .await
            .unwrap();
        let tag = stowq_keys::key_tag(&[1; 16], &rel);
        let stowq_format::Record::Receipt(r) =
            stowq_format::decode(&obj.body, &[1; 16], &tag).unwrap()
        else {
            panic!("receipt")
        };
        assert!(
            r.generation >= 3,
            "two renewals must have advanced the claim; got generation {}",
            r.generation
        );
    }

    #[tokio::test]
    async fn sweep_once_reclaims_and_promotes() {
        let store = MemoryStore::new();
        let q = Queue::init(
            Box::new(store.clone()),
            "q",
            &OpenOptions::new([1; 16]),
            &format(),
        )
        .await
        .unwrap();
        let mut budget = OpBudget::new(256);
        // A delayed job far in the future: not claimable, promoted only
        // once the floor passes its not_before.
        q.enqueue(
            EnqueueInput {
                job_id: Some([1; 16]),
                payload: b"x",
                content_type: "text/plain".into(),
                maximum_attempts: 3,
                not_before_ns: Some(1_000),
            },
            &mut budget,
        )
        .await
        .unwrap();
        // A ready job whose lease will expire.
        q.enqueue(
            EnqueueInput {
                job_id: Some([2; 16]),
                payload: b"x",
                content_type: "text/plain".into(),
                maximum_attempts: 3,
                not_before_ns: None,
            },
            &mut budget,
        )
        .await
        .unwrap();
        let floor = q.establish_floor(&mut budget).await.unwrap();
        let ClaimOutcome::Claimed(claimed) = q
            .claim(
                &ClaimOptions {
                    shard: 0,
                    floor_ns: floor,
                    lease_duration_ns: 10,
                },
                &mut budget,
            )
            .await
            .unwrap()
        else {
            panic!("claim")
        };
        // Advance past BOTH the lease expiry and the delayed
        // not_before; a fresh handle establishes a floor that sees it
        // (the first handle's cache would mask the advance).
        store.advance_clock_to(claimed.claim_store_time_ns.max(1_000) + 10);
        let q2 = queue(&store).await;
        let report = sweep_once(&q2, &mut budget).await.unwrap();
        assert_eq!(report.reclaimed, 1, "expired lease reclaimed");
        assert_eq!(report.promoted, 1, "due delayed job promoted");
    }

    #[tokio::test]
    async fn sweeper_stops_on_signal() {
        let store = MemoryStore::new();
        let q = std::sync::Arc::new(
            Queue::init(Box::new(store), "q", &OpenOptions::new([1; 16]), &format())
                .await
                .unwrap(),
        );
        let (tx, rx) = tokio::sync::watch::channel(false);
        let handle = tokio::spawn(run_sweeper(q.clone(), Duration::from_millis(50), rx));
        tokio::time::sleep(Duration::from_millis(120)).await;
        tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("sweeper exits")
            .unwrap()
            .unwrap();
    }
}

#[cfg(test)]
mod metrics_tests {
    use super::*;
    use crate::tests::{queue_with_job as setup, Fixed};
    use std::sync::atomic::Ordering;

    #[tokio::test]
    async fn metrics_count_the_happy_path() {
        let (q, _store, _id) = setup().await;
        let m = Metrics::default();
        let report = run_delivery_with(
            &q,
            &DoorbellMsg::sweep(),
            &Fixed(vec![ExecutorOutput {
                name: "r".into(),
                body: Bytes::from_static(b"done"),
            }]),
            60_000_000_000,
            Some(&m),
        )
        .await
        .unwrap();
        assert!(matches!(report, DeliveryReport::Delivered { .. }));
        let s = m.snapshot();
        assert_eq!(s.hints, 1);
        assert_eq!(s.delivered, 1);
        assert_eq!(s.no_work, 0);
        // The delivery histogram recorded one sample under 10ms
        // (memory store, instant executor).
        let total: u64 = s.delivery_ms.iter().sum();
        assert_eq!(total, 1, "one delivery recorded");
        assert_eq!(s.delivery_ms[0], 1, "fast bucket");
    }

    #[tokio::test]
    async fn metrics_count_no_work_and_failures() {
        let (q, _store, _id) = setup().await;
        let m = Metrics::default();
        // First delivery consumes the job.
        run_delivery_with(
            &q,
            &DoorbellMsg::sweep(),
            &Fixed(vec![]),
            60_000_000_000,
            Some(&m),
        )
        .await
        .unwrap();
        // Second hint finds nothing.
        run_delivery_with(
            &q,
            &DoorbellMsg::sweep(),
            &Fixed(vec![]),
            60_000_000_000,
            Some(&m),
        )
        .await
        .unwrap();
        let s = m.snapshot();
        assert_eq!(s.hints, 2);
        assert_eq!(s.delivered, 1);
        assert_eq!(s.no_work, 1);
        assert_eq!(m.delivery_ms[0].load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn metrics_snapshot_display_is_machine_parseable() {
        let m = Metrics::default();
        m.renewals.fetch_add(3, Ordering::Relaxed);
        m.lost_lease.fetch_add(1, Ordering::Relaxed);
        let text = m.snapshot().to_string();
        assert!(text.contains("renewals 3"), "{text}");
        assert!(text.contains("lost-lease 1"), "{text}");
        assert!(text.contains("delivery ms [ <10 0"), "{text}");
    }
}
