//! Chaos corpus: adversarial scenarios over the consumer harness.
//! Every scenario ends in the same assertions — exactly one terminal
//! record, first-wins output bytes, contiguous claim chains, and a
//! repair scan with no findings (the v1.1 durable audit) — because
//! chaos may change WHO delivers, never WHAT is true afterward.

use async_trait::async_trait;
use bytes::Bytes;
use sha2::Digest as _;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use stowq_core::{
    ClaimOptions, ClaimOutcome, EnqueueInput, EnqueueOutcome, Error, OpBudget, OpenOptions, Queue,
    RepairReport,
};
use stowq_format::FormatRecord;
use stowq_store::{Key, MemoryStore, ObjectStore, StoreError, StoreResult};
use stowq_worker::{DeliveryReport, DoorbellMsg, ExecutionFailure, Executor, ExecutorOutput};

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

fn opts() -> OpenOptions {
    OpenOptions::new([1; 16])
}

async fn init_store() -> MemoryStore {
    let store = MemoryStore::new();
    Queue::init(Box::new(store.clone()), "q", &opts(), &format())
        .await
        .unwrap();
    store
}

async fn enqueue(store: &MemoryStore, payload: &[u8]) -> [u8; 16] {
    let q = Queue::open(Box::new(store.clone()), "q", opts())
        .await
        .unwrap();
    let mut b = OpBudget::new(128);
    let EnqueueOutcome::Committed { job_id } = q
        .enqueue(
            EnqueueInput {
                job_id: None,
                payload,
                content_type: "text/plain".into(),
                maximum_attempts: 5,
                not_before_ns: None,
            },
            &mut b,
        )
        .await
        .unwrap()
    else {
        panic!("commit")
    };
    job_id
}

fn jhex(id: &[u8; 16]) -> String {
    id.iter().map(|x| format!("{x:02x}")).collect()
}

/// The deterministic executor every scenario uses: output bytes are a
/// pure function of the payload, so every attempt of every worker
/// converges on identical first-wins bytes.
struct Deterministic;

#[async_trait]
impl Executor for Deterministic {
    async fn run(
        &self,
        _job_id: [u8; 16],
        payload: Bytes,
    ) -> Result<Vec<ExecutorOutput>, ExecutionFailure> {
        let mut body = payload.to_vec();
        body.extend_from_slice(b"-processed");
        Ok(vec![ExecutorOutput {
            name: "result".into(),
            body: Bytes::from(body),
        }])
    }
}

fn expected_output(payload: &[u8]) -> Vec<u8> {
    let mut v = payload.to_vec();
    v.extend_from_slice(b"-processed");
    v
}

/// End-state truth: exactly one receipt, no dead record, first-wins
/// output bytes at the deterministic key, a contiguous claim chain,
/// and a clean repair scan.
async fn assert_converged(store: &MemoryStore, job_id: &[u8; 16], payload: &[u8]) {
    let hex = jhex(job_id);
    let receipts = store
        .list(&format!("q/receipts/0000/{hex}"), None, 4)
        .await
        .unwrap();
    assert_eq!(receipts.items.len(), 1, "exactly one receipt");
    assert_eq!(
        store
            .head(&Key::new(format!("q/dead/0000/{hex}")))
            .await
            .unwrap_err(),
        StoreError::NotFound,
        "no dead record"
    );
    let out = store
        .get(&Key::new(format!("q/outputs/{hex}/result")), None)
        .await
        .expect("output object exists");
    assert_eq!(
        &out.body[..],
        &expected_output(payload)[..],
        "first-wins bytes"
    );
    // Contiguous claim generations 1..=tail (the audit's invariant).
    let page = store
        .list(&format!("q/claims/0000/{hex}/"), None, 1024)
        .await
        .unwrap();
    let gens_raw: Vec<String> = page
        .items
        .iter()
        .map(|l| l.key.as_str().rsplit('/').next().unwrap().to_string())
        .collect();
    let mut gens: Vec<u64> = gens_raw
        .iter()
        .map(|g| u64::from_str_radix(g, 16).expect("claim key generation"))
        .collect();
    gens.sort_unstable();
    assert!(!gens.is_empty(), "at least one claim generation exists");
    assert!(
        gens.iter().enumerate().all(|(i, g)| *g == i as u64 + 1),
        "claim chain contiguous, got {gens:?}"
    );
    // The v1.1 durable audit: no violations after chaos.
    let q = Queue::open(Box::new(store.clone()), "q", opts())
        .await
        .unwrap();
    let mut b = OpBudget::new(8192);
    let (report, _) = q.repair_scan(0, &mut b).await.unwrap();
    assert!(
        report.findings.is_empty(),
        "repair clean after chaos: {:?}",
        report.findings
    );
    let _ = RepairReport::default();
}

// ---------- Kill injection ----------

/// A store wrapper that panics at the k-th store call from
/// construction: the op-level stand-in for process death. Everything
/// before op k persists; nothing after runs.
struct KillAt {
    inner: MemoryStore,
    ops: AtomicUsize,
    kill: Option<usize>,
}

impl KillAt {
    fn new(inner: MemoryStore, kill: Option<usize>) -> Self {
        KillAt {
            inner,
            ops: AtomicUsize::new(0),
            kill,
        }
    }

    fn gate(&self) {
        if let Some(k) = self.kill {
            let n = self.ops.fetch_add(1, Ordering::SeqCst);
            if n == k {
                panic!("chaos kill at op {n}");
            }
        }
    }
}

#[async_trait::async_trait]
impl ObjectStore for KillAt {
    async fn put_if_absent(
        &self,
        key: &Key,
        body: Bytes,
        sha256: [u8; 32],
    ) -> StoreResult<stowq_store::PutOutcome> {
        self.gate();
        self.inner.put_if_absent(key, body, sha256).await
    }

    async fn cas(
        &self,
        key: &Key,
        body: Bytes,
        sha256: [u8; 32],
        if_match: &stowq_store::Version,
    ) -> StoreResult<stowq_store::PutOutcome> {
        self.gate();
        self.inner.cas(key, body, sha256, if_match).await
    }

    async fn get(
        &self,
        key: &Key,
        range: Option<std::ops::Range<u64>>,
    ) -> StoreResult<stowq_store::Object> {
        self.gate();
        self.inner.get(key, range).await
    }

    async fn head(&self, key: &Key) -> StoreResult<stowq_store::Meta> {
        self.gate();
        self.inner.head(key).await
    }

    async fn list(
        &self,
        prefix: &str,
        after: Option<&Key>,
        limit: usize,
    ) -> StoreResult<stowq_store::Page> {
        self.gate();
        self.inner.list(prefix, after, limit).await
    }

    async fn delete(&self, key: &Key) -> StoreResult<()> {
        self.gate();
        self.inner.delete(key).await
    }
}

/// Kill the delivery at every op index in turn; restart and assert
/// convergence. Kill indexes beyond a delivery's op count simply
/// complete — the assertions then check the completed state directly.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kill_injection_corpus() {
    const PAYLOAD: &[u8] = b"chaos-kill-payload";
    const MAX_KILLS: usize = 64;
    for k in 0..MAX_KILLS {
        let store = init_store().await;
        let job_id = enqueue(&store, PAYLOAD).await;

        // The killed delivery: everything inside the task dies at op k.
        let killed_store = store.clone();
        let handle = tokio::spawn(async move {
            let q = Queue::open(Box::new(KillAt::new(killed_store, Some(k))), "q", opts())
                .await
                .unwrap();
            stowq_worker::run_delivery(&q, &DoorbellMsg::sweep(), &Deterministic, 60_000_000_000)
                .await
        });
        let killed = handle.await;

        match killed {
            // k fell beyond the delivery's op count: the job completed
            // in the "killed" task; the state assertions cover it.
            Ok(Ok(_)) => {}
            // The kill fired mid-op: restart. A kill mid-lease leaves
            // the dead worker's lease live in STORE time; real recovery
            // waits out the lease — modeled by advancing the logical
            // clock past it — then delivers as the takeover worker.
            Err(_join_panic) => {
                store.advance_clock_to(u64::MAX / 4);
                let q = Queue::open(Box::new(store.clone()), "q", opts())
                    .await
                    .unwrap();
                let report = stowq_worker::run_delivery(
                    &q,
                    &DoorbellMsg::sweep(),
                    &Deterministic,
                    60_000_000_000,
                )
                .await
                .unwrap_or_else(|e| panic!("kill {k}: restart delivery failed: {e:?}"));
                assert!(
                    matches!(
                        report,
                        DeliveryReport::Delivered { .. } | DeliveryReport::NoWork
                    ),
                    "kill {k}: restart must deliver or find the job terminal, got {report:?}"
                );
            }
            Ok(Err(e)) => panic!("kill {k}: delivery failed without dying: {e:?}"),
        }
        assert_converged(&store, &job_id, PAYLOAD).await;
    }
}

// ---------- Duplicate doorbells ----------

/// N harness instances race one hint with overlapping leases: slow
/// first claimant, instant rivals. Whoever wins, the store sees
/// exactly one delivery.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn duplicate_doorbell_corpus() {
    const ITERS: usize = 25;
    const WORKERS: usize = 4;
    const PAYLOAD: &[u8] = b"chaos-duplicate-payload";

    for s in 0..ITERS {
        let store = init_store().await;
        let job_id = enqueue(&store, PAYLOAD).await;
        // Leases are tiny in STORE time (MemoryStore ticks 1ns per
        // op), so a rival's beacon+scan+claim can genuinely lapse a
        // live lease: takeovers and zombie convergence interleave with
        // straight deliveries across iterations.
        let lease_ns = 50 + (s % 5) as u64 * 10;

        struct SlowThenDeliver(Duration);

        #[async_trait]
        impl Executor for SlowThenDeliver {
            async fn run(
                &self,
                _job_id: [u8; 16],
                payload: Bytes,
            ) -> Result<Vec<ExecutorOutput>, ExecutionFailure> {
                tokio::time::sleep(self.0).await;
                let mut body = payload.to_vec();
                body.extend_from_slice(b"-processed");
                Ok(vec![ExecutorOutput {
                    name: "result".into(),
                    body: Bytes::from(body),
                }])
            }
        }

        let mut handles = Vec::new();
        for w in 0..WORKERS {
            let ws = store.clone();
            handles.push(tokio::spawn(async move {
                let q = Queue::open(Box::new(ws), "q", opts()).await.unwrap();
                let exec: Box<dyn Executor> = if w == 0 {
                    Box::new(SlowThenDeliver(Duration::from_millis(30)))
                } else {
                    Box::new(Deterministic)
                };
                stowq_worker::run_delivery(&q, &DoorbellMsg::sweep(), exec.as_ref(), lease_ns).await
            }));
        }
        let mut delivered = 0;
        for h in handles {
            let report = h
                .await
                .unwrap_or_else(|e| panic!("iter {s}: worker task died: {e}"))
                .unwrap_or_else(|e| panic!("iter {s}: worker errored: {e:?}"));
            match report {
                DeliveryReport::Delivered { .. } => delivered += 1,
                DeliveryReport::NoWork | DeliveryReport::LostLease => {}
                other => panic!("iter {s}: unexpected report {other:?}"),
            }
        }
        assert!(delivered >= 1, "iter {s}: nobody delivered");
        assert_converged(&store, &job_id, PAYLOAD).await;
    }
}

// ---------- Floor regression fails closed ----------

/// A watermark claiming a future store time must gate every later
/// floor: establish_floor fails ProfileViolation, and run_delivery
/// fails BEFORE any claim is taken — the fail-closed posture.
#[tokio::test]
async fn floor_regression_fails_closed() {
    let store = init_store().await;
    let job_id = enqueue(&store, b"chaos-skew-payload").await;
    let q = Queue::open(Box::new(store.clone()), "q", opts())
        .await
        .unwrap();
    let mut b = OpBudget::new(256);
    let floor = q.establish_floor(&mut b).await.unwrap();
    q.advance_watermark(floor, &mut b).await.unwrap();

    // A foreign participant recorded a far-future watermark bucket
    // (hand-written the way a skewing store would surface it).
    let key = Key::new("q/meta/watermark");
    let meta = store.head(&key).await.unwrap();
    let tag = stowq_keys::key_tag(&[1; 16], "meta/watermark");
    let record = stowq_format::Record::Watermark(stowq_format::WatermarkRecord {
        highest_observed_wall_bucket: 1 << 40,
        sequence: 1,
    });
    let body = Bytes::from(stowq_format::encode(&record, &[1; 16], &tag));
    let digest: [u8; 32] = sha2::Sha256::digest(&body).into();
    store.cas(&key, body, digest, &meta.version).await.unwrap();

    // The next floor gate trips: fresh beacons sit far below the
    // recorded watermark bucket. A FRESH participant handle is the
    // honest scenario — the first handle's cached floor predates the
    // corruption and is sanctioned for its staleness window.
    let q2 = Queue::open(Box::new(store.clone()), "q", opts())
        .await
        .unwrap();
    let mut b = OpBudget::new(256);
    match q2.establish_floor(&mut b).await {
        Err(Error::Store(stowq_store::StoreError::ProfileViolation(_))) => {}
        other => panic!("expected fail-closed ProfileViolation, got {other:?}"),
    }
    let report =
        stowq_worker::run_delivery(&q2, &DoorbellMsg::sweep(), &Deterministic, 60_000_000_000)
            .await;
    assert!(
        matches!(
            report,
            Err(Error::Store(stowq_store::StoreError::ProfileViolation(_)))
        ),
        "delivery must fail closed under regression, got {report:?}"
    );
    // Nothing was claimed: no claim chain, no output, no terminal.
    let hex = jhex(&job_id);
    assert!(store
        .list(&format!("q/claims/0000/{hex}/"), None, 8)
        .await
        .unwrap()
        .items
        .is_empty());
    assert_eq!(
        store
            .head(&Key::new(format!("q/outputs/{hex}/result")))
            .await
            .unwrap_err(),
        StoreError::NotFound
    );
}

// ---------- Renewal starvation ----------

/// Renewals keep winning while a rival keeps failing to take over,
/// then the rival finally succeeds mid-execution: the displaced worker
/// stops acting, the chain stays contiguous, the taker delivers.
#[tokio::test]
async fn renewal_starvation_corpus() {
    tokio::time::pause();
    let store = init_store().await;
    let job_id = enqueue(&store, b"chaos-starve-payload").await;

    // Lease 300ms (tick 100ms). The executor survives two renewals,
    // defeats one takeover attempt (the rival claims BEFORE a
    // renewal extends the lease — renewal wins the CAS), then loses
    // to a second takeover after the lease truly lapses.
    struct Starved {
        store: MemoryStore,
    }

    #[async_trait]
    impl Executor for Starved {
        async fn run(
            &self,
            _job_id: [u8; 16],
            _payload: Bytes,
        ) -> Result<Vec<ExecutorOutput>, ExecutionFailure> {
            // Two renewal ticks pass: generations 2 and 3 commit.
            tokio::time::sleep(Duration::from_millis(250)).await;
            // Rival 1: too early — the last renewal (tick 200ms)
            // extended the lease; the takeover claim finds the lease
            // live and returns Empty.
            let r1 = queue(&self.store).await;
            let mut b = OpBudget::new(256);
            let floor = r1.establish_floor(&mut b).await.unwrap();
            let taken = r1
                .claim(
                    &ClaimOptions {
                        shard: 0,
                        floor_ns: floor,
                        lease_duration_ns: 60_000_000_000,
                    },
                    &mut b,
                )
                .await
                .unwrap();
            assert!(matches!(taken, ClaimOutcome::Empty), "early rival refused");
            // Rival 2: force store time past the live lease.
            self.store.advance_clock_to(u64::MAX / 4);
            let r2 = queue(&self.store).await;
            let floor = r2.establish_floor(&mut b).await.unwrap();
            let ClaimOutcome::Claimed(_c) = r2
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
                panic!("starved lease taken over")
            };
            // The taker completes the delivery itself: deterministic
            // output through the commit rule, then ack.
            let out = r2
                .commit_output(
                    &_c,
                    "result",
                    Bytes::from(expected_output(b"chaos-starve-payload")),
                    &mut b,
                )
                .await
                .unwrap();
            let committed = match out {
                stowq_core::CommitOutcome::Committed(c)
                | stowq_core::CommitOutcome::Converged(c) => c,
            };
            r2.ack_with_outputs(&_c, &[committed], &mut b)
                .await
                .unwrap();
            // Stall past the displaced worker's next renewal tick; the
            // executor future is dropped here when its renewal loses.
            tokio::time::sleep(Duration::from_millis(150)).await;
            Ok(vec![])
        }
    }

    async fn queue(store: &MemoryStore) -> Queue {
        Queue::open(Box::new(store.clone()), "q", opts())
            .await
            .unwrap()
    }

    let q = queue(&store).await;
    let report = stowq_worker::run_delivery(
        &q,
        &DoorbellMsg::sweep(),
        &Starved {
            store: store.clone(),
        },
        300_000_000,
    )
    .await
    .unwrap();
    assert!(matches!(report, DeliveryReport::LostLease), "{report:?}");
    assert_converged(&store, &job_id, b"chaos-starve-payload").await;
}

/// Sanity anchor for the corpus: one clean delivery converges too.
#[tokio::test]
async fn clean_delivery_converges() {
    let store = init_store().await;
    let job_id = enqueue(&store, b"chaos-clean-payload").await;
    let q = Queue::open(Box::new(store.clone()), "q", opts())
        .await
        .unwrap();
    let report =
        stowq_worker::run_delivery(&q, &DoorbellMsg::sweep(), &Deterministic, 60_000_000_000)
            .await
            .unwrap();
    assert!(matches!(report, DeliveryReport::Delivered { .. }));
    assert_converged(&store, &job_id, b"chaos-clean-payload").await;
    // The unused-arc pattern keeps the store alive across awaits.
    let _keep = Arc::new(());
}
