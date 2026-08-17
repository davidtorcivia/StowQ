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
use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Duration;
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

/// Store ops allowed for one delivery: claim across hinted shards,
/// floor establishment, execution renewals, output commits, ack.
/// A sweep hint claims shard by shard, so a queue with more shards
/// than the budget allows fails `Err(BudgetExhausted)` mid-scan —
/// fail-safe: no partial delivery happens (the spend precedes every
/// op), and the hint is simply not fully served. Retry it or let the
/// sweeper find the work.
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
    let Some(mut claim) = claim else {
        return Ok(DeliveryReport::NoWork);
    };

    // Delivery = committed claim + verified payload (spec records.md):
    // payload() verifies the digest, so the executor never sees
    // unverified bytes.
    let payload = claim.payload(q.store()).await?;

    // Renewal cadence: lease/3 wall-clock, floored at 1ms so a
    // sub-millisecond lease cannot busy-loop renewals. The store clock
    // governs expiry; this timer only keeps custody current.
    let interval = Duration::from_nanos(lease_duration_ns / 3).max(Duration::from_millis(1));
    let mut exec_fut = Box::pin(exec.run(claim.job_id, payload));
    loop {
        tokio::select! {
            out = &mut exec_fut => {
                return finish_delivery(q, &claim, out, &mut budget).await;
            }
            _ = tokio::time::sleep(interval) => {
                match q.renew(&claim, &mut budget).await? {
                    RenewOutcome::Renewed(c) => claim = c,
                    // No action after LeaseLost: no nack, no ack, no
                    // commits — the new owner decides the job's fate.
                    RenewOutcome::LeaseLost => return Ok(DeliveryReport::LostLease),
                }
            }
        }
    }
}

async fn finish_delivery(
    q: &Queue,
    claim: &stowq_core::Claim,
    executed: Result<Vec<ExecutorOutput>, ExecutionFailure>,
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
            match q.ack_with_outputs(claim, &committed, budget).await? {
                AckOutcome::Acked | AckOutcome::AlreadyAcked => {
                    Ok(DeliveryReport::Delivered { outputs: committed })
                }
                // A dead record terminalized the job while we held a
                // stale claim: not ours to decide anymore.
                AckOutcome::SupersededByDead => Ok(DeliveryReport::LostLease),
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

    async fn queue_with_job() -> (Queue, MemoryStore, [u8; 16]) {
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
    struct Fixed(Vec<ExecutorOutput>);

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
