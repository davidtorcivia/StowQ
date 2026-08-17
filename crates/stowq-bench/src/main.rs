//! Performance baseline instrumentation: exact store-op counts per
//! protocol operation, CPU-side latency against the memory fake, and
//! live end-to-end latency/throughput against an S3-family store.
//!
//! Modes:
//! - `ops` — deterministic store-op counts per protocol operation
//!   (the optimization target list, measured not guessed)
//! - `mem` — protocol-cycle latency and allocations against the memory
//!   fake (CPU overhead: key formatting, CBOR, clones)
//! - `live` — env-gated (the conformance configuration): per-phase
//!   latency, cycle throughput, and observed op counts against
//!   R2/MinIO
//!
//! The bench is a tool, not a test: it prints numbers; it asserts
//! nothing beyond its own sanity.

use async_trait::async_trait;
use bytes::Bytes;
use std::ops::Range;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use stowq_core::{
    AckOutcome, BuryOutcome, ClaimOptions, ClaimOutcome, CommitOutcome, EnqueueInput,
    EnqueueOutcome, OpBudget, OpenOptions, Queue, RenewOutcome,
};
use stowq_format::FormatRecord;
use stowq_store::{
    Key, MemoryStore, Object, ObjectStore, Page, PutOutcome, StoreError, StoreResult, Version,
};
use stowq_worker::{DoorbellMsg, Executor};

// ---------- counting store ----------

#[derive(Default)]
pub struct OpCounts {
    pub put_if_absent: AtomicU64,
    pub cas: AtomicU64,
    pub get: AtomicU64,
    pub head: AtomicU64,
    pub list: AtomicU64,
    pub delete: AtomicU64,
}

impl OpCounts {
    pub fn total(&self) -> u64 {
        self.put_if_absent.load(Ordering::Relaxed)
            + self.cas.load(Ordering::Relaxed)
            + self.get.load(Ordering::Relaxed)
            + self.head.load(Ordering::Relaxed)
            + self.list.load(Ordering::Relaxed)
            + self.delete.load(Ordering::Relaxed)
    }

    fn snapshot(&self) -> [u64; 6] {
        [
            self.put_if_absent.load(Ordering::Relaxed),
            self.cas.load(Ordering::Relaxed),
            self.get.load(Ordering::Relaxed),
            self.head.load(Ordering::Relaxed),
            self.list.load(Ordering::Relaxed),
            self.delete.load(Ordering::Relaxed),
        ]
    }
}

/// A plain-value per-phase difference.
struct OpDiff {
    put_if_absent: u64,
    cas: u64,
    get: u64,
    head: u64,
    list: u64,
    delete: u64,
}

impl OpDiff {
    fn delta(before: [u64; 6], after: [u64; 6]) -> OpDiff {
        OpDiff {
            put_if_absent: after[0] - before[0],
            cas: after[1] - before[1],
            get: after[2] - before[2],
            head: after[3] - before[3],
            list: after[4] - before[4],
            delete: after[5] - before[5],
        }
    }

    fn total(&self) -> u64 {
        self.put_if_absent + self.cas + self.get + self.head + self.list + self.delete
    }

    fn line(&self) -> String {
        format!(
            "{} total (put {} / cas {} / get {} / head {} / list {} / delete {})",
            self.total(),
            self.put_if_absent,
            self.cas,
            self.get,
            self.head,
            self.list,
            self.delete
        )
    }
}

/// Wraps any ObjectStore, tallying op kinds. Read-only instrumentation.
pub struct CountingStore<S> {
    inner: S,
    counts: Arc<OpCounts>,
}

impl<S> CountingStore<S> {
    pub fn new(inner: S) -> (Self, Arc<OpCounts>) {
        let counts = Arc::new(OpCounts::default());
        (
            CountingStore {
                inner,
                counts: counts.clone(),
            },
            counts,
        )
    }
}

macro_rules! tally {
    ($self:expr, $field:ident, $e:expr) => {{
        $self.counts.$field.fetch_add(1, Ordering::Relaxed);
        $e
    }};
}

#[async_trait]
impl<S: ObjectStore> ObjectStore for CountingStore<S> {
    async fn put_if_absent(
        &self,
        key: &Key,
        body: Bytes,
        sha256: [u8; 32],
    ) -> StoreResult<PutOutcome> {
        tally!(
            self,
            put_if_absent,
            self.inner.put_if_absent(key, body, sha256).await
        )
    }
    async fn cas(
        &self,
        key: &Key,
        body: Bytes,
        sha256: [u8; 32],
        if_match: &Version,
    ) -> StoreResult<PutOutcome> {
        tally!(self, cas, self.inner.cas(key, body, sha256, if_match).await)
    }
    async fn get(&self, key: &Key, range: Option<Range<u64>>) -> StoreResult<Object> {
        tally!(self, get, self.inner.get(key, range).await)
    }
    async fn head(&self, key: &Key) -> StoreResult<stowq_store::Meta> {
        tally!(self, head, self.inner.head(key).await)
    }
    async fn list(&self, prefix: &str, after: Option<&Key>, limit: usize) -> StoreResult<Page> {
        tally!(self, list, self.inner.list(prefix, after, limit).await)
    }
    async fn delete(&self, key: &Key) -> StoreResult<()> {
        tally!(self, delete, self.inner.delete(key).await)
    }
}

// ---------- shared config ----------

fn format() -> FormatRecord {
    FormatRecord {
        // Spread shards so concurrent bench processes parallelize like
        // real workers; a single shard serializes every claimant onto
        // one index page and measures contention, not the queue.
        // STOWQ_BENCH_SHARDS=1 reproduces the pre-sharding shape for
        // single-shard A/B comparisons.
        shard_count: std::env::var("STOWQ_BENCH_SHARDS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(16),
        lease_bucket_width_ns: 1_000_000_000,
        delayed_bucket_width_ns: 1_000_000_000,
        terminal_bucket_width_ns: 1_000_000_000,
        inline_limit: 65_536,
        required_feature_bits: 0,
    }
}

fn opts(worker: &str) -> OpenOptions {
    let mut o = OpenOptions::new([1; 16]);
    o.worker_id = worker.into();
    o
}

// ---------- ops mode ----------

#[allow(unused_assignments)]
async fn ops_mode() -> Result<(), String> {
    let mem = MemoryStore::new();
    let (store, mut counts) = CountingStore::new(mem.clone());
    let q = Queue::init(Box::new(store), "q", &opts("ops"), &format())
        .await
        .map_err(|e| e.to_string())?;
    let mut b = OpBudget::new(64_000);
    let mut before = counts.snapshot();

    macro_rules! phase {
        ($name:expr, $body:expr) => {{
            let r = $body.await;
            let after = counts.snapshot();
            let d = OpDiff::delta(before, after);
            before = after;
            println!("{:<26} {}", $name, d.line());
            r
        }};
    }

    phase!("enqueue (inline)", async {
        let EnqueueOutcome::Committed { .. } = q
            .enqueue(
                EnqueueInput {
                    job_id: Some([7; 16]),
                    payload: b"bench-payload",
                    content_type: "text/plain".into(),
                    maximum_attempts: 5,
                    not_before_ns: None,
                },
                &mut b,
            )
            .await
            .map_err(|e| e.to_string())?
        else {
            return Err("enqueue rejected".to_string());
        };
        Ok::<(), String>(())
    })?;

    let floor = phase!("establish_floor (fresh)", async {
        q.establish_floor(&mut b).await.map_err(|e| e.to_string())
    })?;
    phase!("establish_floor (cached)", async {
        q.establish_floor(&mut b).await.map_err(|e| e.to_string())
    })?;

    let claim = phase!("claim", async {
        match q
            .claim(
                &ClaimOptions {
                    shard: 0,
                    floor_ns: floor,
                    lease_duration_ns: 60_000_000_000,
                },
                &mut b,
            )
            .await
            .map_err(|e| e.to_string())?
        {
            ClaimOutcome::Claimed(c) => Ok::<stowq_core::Claim, String>(c),
            ClaimOutcome::Empty => Err("empty".into()),
        }
    })?;

    let claim = phase!("renew", async {
        match q.renew(&claim, &mut b).await.map_err(|e| e.to_string())? {
            RenewOutcome::Renewed(c) => Ok::<stowq_core::Claim, String>(c),
            RenewOutcome::LeaseLost => Err("lease lost".into()),
        }
    })?;

    let committed = phase!("commit_output", async {
        match q
            .commit_output(&claim, "r", Bytes::from_static(b"out"), &mut b)
            .await
            .map_err(|e| e.to_string())?
        {
            CommitOutcome::Committed(c) => Ok::<stowq_core::CommittedOutput, String>(c),
            CommitOutcome::Converged(_) => Err("unexpected convergence".into()),
        }
    })?;

    phase!("ack_with_outputs", async {
        match q
            .ack_with_outputs(&claim, &[committed], &mut b)
            .await
            .map_err(|e| e.to_string())?
        {
            AckOutcome::Acked => Ok::<(), String>(()),
            other => Err(format!("{other:?}")),
        }
    })?;

    // A second job exercises nack and bury.
    phase!("enqueue #2", async {
        let EnqueueOutcome::Committed { .. } = q
            .enqueue(
                EnqueueInput {
                    job_id: Some([8; 16]),
                    payload: b"bench-payload-2",
                    content_type: "text/plain".into(),
                    maximum_attempts: 5,
                    not_before_ns: None,
                },
                &mut b,
            )
            .await
            .map_err(|e| e.to_string())?
        else {
            return Err("enqueue #2 rejected".to_string());
        };
        Ok::<(), String>(())
    })?;
    let claim2 = phase!("claim #2", async {
        match q
            .claim(
                &ClaimOptions {
                    shard: 0,
                    floor_ns: floor,
                    lease_duration_ns: 60_000_000_000,
                },
                &mut b,
            )
            .await
            .map_err(|e| e.to_string())?
        {
            ClaimOutcome::Claimed(c) => Ok::<stowq_core::Claim, String>(c),
            ClaimOutcome::Empty => Err("empty".into()),
        }
    })?;
    phase!("nack", async {
        q.nack(&claim2, 1, floor, &mut b)
            .await
            .map_err(|e| e.to_string())
    })?;

    // Backoff: advance the fake clock far past retry_not_before, then
    // continue on a fresh handle (its floor re-beacons past the
    // advance; the old handle's cache would sit below it).
    mem.advance_clock_to(u64::MAX / 4);
    // Rebind the SAME bindings (macro hygiene resolves `counts` and
    // `before` at the macro definition site).
    let (s2, counts2) = CountingStore::new(mem.clone());
    counts = counts2;
    let q = Queue::open(Box::new(s2), "q", opts("ops2"))
        .await
        .map_err(|e| e.to_string())?;
    before = counts.snapshot();
    let floor = phase!("establish_floor (post-backoff)", async {
        q.establish_floor(&mut b).await.map_err(|e| e.to_string())
    })?;

    let claim2 = phase!("claim #2 (after nack)", async {
        match q
            .claim(
                &ClaimOptions {
                    shard: 0,
                    floor_ns: floor,
                    lease_duration_ns: 60_000_000_000,
                },
                &mut b,
            )
            .await
            .map_err(|e| e.to_string())?
        {
            ClaimOutcome::Claimed(c) => Ok::<stowq_core::Claim, String>(c),
            ClaimOutcome::Empty => Err("empty after nack".into()),
        }
    })?;
    phase!("bury", async {
        match q
            .bury(&claim2, 0x0003, &mut b)
            .await
            .map_err(|e| e.to_string())?
        {
            BuryOutcome::Buried => Ok::<(), String>(()),
            other => Err(format!("{other:?}")),
        }
    })?;

    phase!("sweep_expired_leases", async {
        q.sweep_expired_leases(floor, &mut b)
            .await
            .map_err(|e| e.to_string())
    })?;
    phase!("sweep_delayed", async {
        q.sweep_delayed(floor, &mut b)
            .await
            .map_err(|e| e.to_string())
    })?;
    phase!("repair_scan (2 jobs)", async {
        q.repair_scan(0, &mut b).await.map_err(|e| e.to_string())
    })?;
    phase!("gc", async {
        q.gc(floor, 0, 0, &mut b).await.map_err(|e| e.to_string())
    })?;
    Ok(())
}

// ---------- mem mode ----------

/// Counting global allocator: bytes allocated per protocol cycle.
static ALLOCED: AtomicU64 = AtomicU64::new(0);

struct CountingAlloc;

unsafe impl std::alloc::GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, l: std::alloc::Layout) -> *mut u8 {
        ALLOCED.fetch_add(l.size() as u64, Ordering::Relaxed);
        unsafe { std::alloc::System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: std::alloc::Layout) {
        unsafe { std::alloc::System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: std::alloc::Layout, n: usize) -> *mut u8 {
        ALLOCED.fetch_add(n as u64, Ordering::Relaxed);
        unsafe { std::alloc::System.realloc(p, l, n) }
    }
}

#[global_allocator]
static GLOBAL: CountingAlloc = CountingAlloc;

fn median(v: &mut [u128]) -> u128 {
    v.sort_unstable();
    v[v.len() / 2]
}
fn p95(v: &mut [u128]) -> u128 {
    v.sort_unstable();
    v[(v.len() as f64 * 0.95) as usize % v.len().max(1)]
}

async fn one_cycle(q: &Queue, floor: u64, i: usize, b: &mut OpBudget) -> Result<(), String> {
    let EnqueueOutcome::Committed { .. } = q
        .enqueue(
            EnqueueInput {
                job_id: Some((i as u128).to_be_bytes()),
                payload: b"bench-payload",
                content_type: "text/plain".into(),
                maximum_attempts: 5,
                not_before_ns: None,
            },
            b,
        )
        .await
        .map_err(|e| e.to_string())?
    else {
        return Err("enqueue rejected".into());
    };
    // The well-hinted worker shape: a doorbell names the shard, and
    // the bench knows each job's id, so it claims the computed shard
    // directly — one probe, no empty-shard scanning (what the probe
    // loop costs is precisely what doorbell hints exist to avoid).
    let id = (i as u128).to_be_bytes();
    let shard = stowq_keys::compute_shard(&[1; 16], &id, q.format().shard_count);
    let c = match q
        .claim(
            &ClaimOptions {
                shard,
                floor_ns: floor,
                lease_duration_ns: 60_000_000_000,
            },
            b,
        )
        .await
        .map_err(|e| e.to_string())?
    {
        ClaimOutcome::Claimed(c) => c,
        ClaimOutcome::Empty => return Ok(()), // a prior cycle's lease may still nominally hold
    };
    q.ack(&c, b).await.map_err(|e| e.to_string())?;
    Ok(())
}

async fn mem_mode(cycles: usize) -> Result<(), String> {
    // Batch cycles per store so init amortizes; scan growth within a
    // batch is bounded by the batch size.
    const PER_STORE: usize = 50;
    let mut cyc: Vec<u128> = Vec::with_capacity(cycles);
    let mut allocs: Vec<u64> = Vec::with_capacity(cycles);
    let mut done = 0;
    while done < cycles {
        let (store, _counts) = CountingStore::new(MemoryStore::new());
        let q = Queue::init(Box::new(store), "q", &opts("mem"), &format())
            .await
            .map_err(|e| e.to_string())?;
        let mut b = OpBudget::new(64_000);
        let floor = q.establish_floor(&mut b).await.map_err(|e| e.to_string())?;
        for _ in 0..PER_STORE {
            if done >= cycles {
                break;
            }
            let a0 = ALLOCED.load(Ordering::Relaxed);
            let t0 = Instant::now();
            one_cycle(&q, floor, done, &mut b).await?;
            cyc.push(t0.elapsed().as_nanos());
            allocs.push(ALLOCED.load(Ordering::Relaxed) - a0);
            done += 1;
        }
    }
    let cyc_us: Vec<f64> = cyc.iter().map(|n| *n as f64 / 1000.0).collect();
    let mut cyc2: Vec<u128> = cyc.clone();
    println!(
        "memory cycle (enqueue+claim+ack): median {:.1}us / p95 {:.1}us over {cycles} cycles",
        median(&mut cyc2) as f64 / 1000.0,
        p95(&mut cyc) as f64 / 1000.0,
    );
    let _ = cyc_us;
    let mut a2 = allocs.clone();
    println!(
        "bytes allocated per cycle (gross, incl. runtime overhead): median {:.0} / p95 {:.0}",
        median_u64(&mut a2),
        p95_u64(&mut allocs),
    );
    Ok(())
}

fn median_u64(v: &mut [u64]) -> f64 {
    v.sort_unstable();
    v[v.len() / 2] as f64
}
fn p95_u64(v: &mut [u64]) -> f64 {
    v.sort_unstable();
    v[(v.len() as f64 * 0.95) as usize % v.len().max(1)] as f64
}

// ---------- live mode ----------

async fn live_store() -> Result<stowq_store_s3::S3Store, String> {
    let endpoint = std::env::var("STOWQ_CONFORMANCE_ENDPOINT")
        .map_err(|_| "STOWQ_CONFORMANCE_ENDPOINT is required for live mode".to_string())?;
    let sdk = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let config = stowq_store_s3::S3Config {
        region: std::env::var("AWS_REGION").unwrap_or_else(|_| "auto".into()),
        endpoint: Some(endpoint),
        force_path_style: true,
    };
    let bucket =
        std::env::var("STOWQ_CONFORMANCE_BUCKET").unwrap_or_else(|_| "stowq-conformance".into());
    Ok(stowq_store_s3::S3Store::new(&sdk, &config, bucket))
}

/// A batched cycle: enqueue `n` jobs, claim them in one scan
/// (claim_many), ack each. Reports total ops and per-job ops — the
/// batch amortization measurement.
async fn batch_cycle(q: &Queue, n: usize, i: usize, b: &mut OpBudget) -> Result<usize, String> {
    // All jobs land on shard 0 (the well-hinted batch shape: one
    // scan serves the whole batch), so scan candidate ids upward and
    // keep those whose shard hash is 0.
    let shard_count = q.format().shard_count.max(1);
    let mut ids = Vec::with_capacity(n);
    let mut cand = i as u128 * 1024;
    while ids.len() < n {
        let id = cand.to_be_bytes();
        cand += 1;
        if stowq_keys::compute_shard(&[1; 16], &id, shard_count) == 0 {
            ids.push(id);
        }
    }
    for id in ids {
        let EnqueueOutcome::Committed { .. } = q
            .enqueue(
                EnqueueInput {
                    job_id: Some(id),
                    payload: b"bench-payload",
                    content_type: "text/plain".into(),
                    maximum_attempts: 5,
                    not_before_ns: None,
                },
                b,
            )
            .await
            .map_err(|e| e.to_string())?
        else {
            return Err("enqueue rejected".into());
        };
    }
    let floor = q.establish_floor(b).await.map_err(|e| e.to_string())?;
    let opts = ClaimOptions {
        shard: 0,
        floor_ns: floor,
        lease_duration_ns: 60_000_000_000,
    };
    let claims = q.claim_many(&opts, n, b).await.map_err(|e| e.to_string())?;
    // Terminal writes overlap like the harness's concurrent
    // deliveries; each carries its own budget (the worker shape).
    let mut budgets: Vec<_> = claims.iter().map(|_| OpBudget::new(1024)).collect();
    let acks: Vec<_> = claims
        .iter()
        .zip(&mut budgets)
        .map(|(c, b)| q.ack(c, b))
        .collect();
    let results = futures::future::join_all(acks).await;
    for r in results {
        r.map_err(|e| e.to_string())?;
    }
    Ok(claims.len())
}

async fn live_batch_mode(cycles: usize, batch: usize) -> Result<(), String> {
    let root = format!("benchb-{}", std::process::id());
    let (store, counts) = CountingStore::new(live_store().await?);
    let q = Queue::init(Box::new(store), &root, &opts("liveb"), &format())
        .await
        .map_err(|e| e.to_string())?;
    println!("root: {root}  ({cycles} cycles x batch {batch})");
    let mut b = OpBudget::new(64_000);
    let t_all = Instant::now();
    for i in 0..cycles {
        let c0 = counts.snapshot();
        let t0 = Instant::now();
        let claimed = batch_cycle(&q, batch, i, &mut b).await?;
        let dt = t0.elapsed().as_secs_f64() * 1000.0;
        let d = OpDiff::delta(c0, counts.snapshot());
        println!(
            "cycle {i:>3}: {dt:7.1}ms  {} claims  {}  ({:.1} ops/job)",
            claimed,
            d.line(),
            d.total() as f64 / batch as f64
        );
    }
    let wall = t_all.elapsed().as_secs_f64();
    println!(
        "live batch: {:.2} jobs/s (batch {batch}, {cycles} cycles)",
        (cycles * batch) as f64 / wall
    );
    Ok(())
}

async fn live_mode(cycles: usize) -> Result<(), String> {
    let root = format!("bench-{}", std::process::id());
    let (store, counts) = CountingStore::new(live_store().await?);
    let q = Queue::init(Box::new(store), &root, &opts("live"), &format())
        .await
        .map_err(|e| e.to_string())?;
    println!("root: {root}  ({cycles} inline cycles)");

    let mut b = OpBudget::new(64_000);
    let mut cyc_ms: Vec<f64> = Vec::with_capacity(cycles);
    let t_all = Instant::now();
    for i in 0..cycles {
        let c0 = counts.snapshot();
        let t0 = Instant::now();
        one_cycle(&q, 0, i, &mut b).await?;
        let dt = t0.elapsed().as_secs_f64() * 1000.0;
        cyc_ms.push(dt);
        let d = OpDiff::delta(c0, counts.snapshot());
        println!("cycle {i:>3}: {dt:7.1}ms  {}", d.line());
    }
    let wall = t_all.elapsed().as_secs_f64();
    let mut sorted = cyc_ms.clone();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    println!(
        "live cycle: median {:.0}ms / p95 {:.0}ms / throughput {:.2} cycles/s",
        sorted[sorted.len() / 2],
        sorted[(sorted.len() as f64 * 0.95) as usize % sorted.len()],
        cycles as f64 / wall
    );
    Ok(())
}

// ---------- soak ----------

/// Rate-based flaky transport: each store op independently faults
/// pre-transmit (safe retry) with probability `p_pre` or
/// post-transmit-ambiguous (outcome unknown, present-or-absent) with
/// probability `p_post`, from a seeded PRNG. The core paths resolve
/// both classes internally — the soak proves sustained correctness
/// under sustained transport chaos.
struct FlakyStore<S> {
    inner: S,
    state: std::sync::Mutex<u64>,                   // rng state
    faults: std::sync::Arc<(AtomicU64, AtomicU64)>, // (pre, post) counts
    p_pre: u64,
    p_post: u64,
}

impl<S> FlakyStore<S> {
    fn new(
        inner: S,
        seed: u64,
        fault_percent: u64,
        faults: std::sync::Arc<(AtomicU64, AtomicU64)>,
    ) -> Self {
        // fault_percent splits 60/40 pre/post; probabilities in
        // per-million for granularity.
        let pm = fault_percent * 10_000;
        FlakyStore {
            inner,
            state: std::sync::Mutex::new(seed),
            p_pre: pm * 6 / 10,
            p_post: pm * 4 / 10,
            faults,
        }
    }

    /// Returns (pre_fault, post_fault) for this op, advancing the RNG.
    fn draw(&self) -> (bool, bool) {
        let mut st = self.state.lock().unwrap();
        // splitmix64 step
        *st = st.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = *st;
        drop(st);
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^= z >> 31;
        let v = z % 1_000_000;
        let pre = v < self.p_pre;
        let post = !pre && v < self.p_pre + self.p_post;
        if pre {
            self.faults.0.fetch_add(1, Ordering::Relaxed);
        }
        if post {
            self.faults.1.fetch_add(1, Ordering::Relaxed);
        }
        (pre, post)
    }
}

#[async_trait]
impl<S: ObjectStore + Send + Sync> ObjectStore for FlakyStore<S> {
    async fn put_if_absent(
        &self,
        key: &Key,
        body: Bytes,
        sha256: [u8; 32],
    ) -> StoreResult<stowq_store::PutOutcome> {
        match self.draw() {
            (true, _) => Err(StoreError::Transport(
                stowq_store::TransportClass::PreTransmit,
            )),
            (false, false) => self.inner.put_if_absent(key, body, sha256).await,
            (false, true) => {
                let r = self.inner.put_if_absent(key, body, sha256).await;
                r.map(|_| {
                    stowq_store::PutOutcome::Rejected // hidden outcome shape
                })
            }
        }
    }
    async fn cas(
        &self,
        key: &Key,
        body: Bytes,
        sha256: [u8; 32],
        if_match: &Version,
    ) -> StoreResult<stowq_store::PutOutcome> {
        match self.draw() {
            (true, _) => Err(StoreError::Transport(
                stowq_store::TransportClass::PreTransmit,
            )),
            (false, false) => self.inner.cas(key, body, sha256, if_match).await,
            (false, true) => self
                .inner
                .cas(key, body, sha256, if_match)
                .await
                .map(|_| stowq_store::PutOutcome::Rejected),
        }
    }
    async fn get(&self, key: &Key, range: Option<Range<u64>>) -> StoreResult<stowq_store::Object> {
        match self.draw() {
            (true, _) => Err(StoreError::Transport(
                stowq_store::TransportClass::PreTransmit,
            )),
            (false, false) => self.inner.get(key, range).await,
            (false, true) => Err(StoreError::OutcomeUnknown(
                stowq_store::Ambiguity::ConnectionLost,
            )),
        }
    }
    async fn head(&self, key: &Key) -> StoreResult<stowq_store::Meta> {
        match self.draw() {
            (true, _) => Err(StoreError::Transport(
                stowq_store::TransportClass::PreTransmit,
            )),
            (false, false) => self.inner.head(key).await,
            (false, true) => Err(StoreError::OutcomeUnknown(
                stowq_store::Ambiguity::ConnectionLost,
            )),
        }
    }
    async fn list(
        &self,
        prefix: &str,
        after: Option<&Key>,
        limit: usize,
    ) -> StoreResult<stowq_store::Page> {
        match self.draw() {
            (true, _) => Err(StoreError::Transport(
                stowq_store::TransportClass::PreTransmit,
            )),
            (false, false) => self.inner.list(prefix, after, limit).await,
            (false, true) => Err(StoreError::OutcomeUnknown(
                stowq_store::Ambiguity::ConnectionLost,
            )),
        }
    }
    async fn delete(&self, key: &Key) -> StoreResult<()> {
        match self.draw() {
            (true, _) => Err(StoreError::Transport(
                stowq_store::TransportClass::PreTransmit,
            )),
            (false, _) => self.inner.delete(key).await,
        }
    }
}

/// A realistic executor mix: most jobs succeed with deterministic
/// output, a fraction fails retryably (nack+backoff), a small
/// fraction permanently (bury). Simulates think time well under the
/// lease so renewals are rare but nonzero on slow paths.
struct SoakExecutor {
    fail_retryable_pct: u64,
    fail_permanent_pct: u64,
    counter: std::sync::atomic::AtomicU64,
}

#[async_trait]
impl Executor for SoakExecutor {
    async fn run(
        &self,
        _job_id: [u8; 16],
        payload: Bytes,
    ) -> Result<Vec<stowq_worker::ExecutorOutput>, stowq_worker::ExecutionFailure> {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        let v = n % 100;
        if v < self.fail_permanent_pct {
            return Err(stowq_worker::ExecutionFailure::Permanent { reason: 0x0003 });
        }
        if v < self.fail_permanent_pct + self.fail_retryable_pct {
            return Err(stowq_worker::ExecutionFailure::Retryable { reason: 0x0001 });
        }
        let mut body = payload.to_vec();
        body.extend_from_slice(b"-soaked");
        Ok(vec![stowq_worker::ExecutorOutput {
            name: "result".into(),
            body: Bytes::from(body),
        }])
    }
}

/// The soak: producers enqueue at a target depth; workers deliver
/// through faulting transport; a sweeper runs periodically; metrics
/// print per window; the run ends with drain + convergence + drift
/// assertions. Exit nonzero on any violation.
async fn soak_mode(
    minutes: u64,
    workers: usize,
    fault_percent: u64,
    seed: u64,
) -> Result<(), String> {
    use stowq_worker::Metrics;
    let t0 = Instant::now();
    let mem = MemoryStore::new();
    // Single shard: the soak targets sustained correctness under
    // transport chaos, not shard fan-out, and one shard keeps the
    // depth/terminal probes complete (one prefix to count).
    let soak_format = FormatRecord {
        shard_count: 1,
        ..format()
    };
    // Init through a clean store: initialization is not under soak.
    let _q = Queue::init(Box::new(mem.clone()), "q", &opts("soak-init"), &soak_format)
        .await
        .map_err(|e| e.to_string())?;

    let metrics = std::sync::Arc::new(Metrics::default());
    let faults = std::sync::Arc::new((AtomicU64::new(0), AtomicU64::new(0)));
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let (producer_stop_flag, producer_stop_rx) = tokio::sync::watch::channel(false);

    // Producer: keep depth around `target` (10) jobs.
    let target: u64 = 10;
    let producer_q = Queue::open(
        Box::new(FlakyStore::new(
            mem.clone(),
            seed ^ 0x1,
            fault_percent,
            faults.clone(),
        )),
        "q",
        opts("soak-producer"),
    )
    .await
    .map_err(|e| e.to_string())?;
    let producer_stop = producer_stop_rx;
    let producer = tokio::spawn(async move {
        let mut i: u64 = 0;
        loop {
            if *producer_stop.borrow() {
                break;
            }
            let mut b = OpBudget::new(1024);
            let d = producer_q.depth(0, &mut b).await.unwrap_or_default();
            // In-flight = non-terminal jobs (job records persist
            // until GC; raw jobs would fill once and stop).
            let inflight = d.jobs.saturating_sub(d.receipts + d.dead);
            while inflight < target && i < 100_000 {
                let r = producer_q
                    .enqueue(
                        EnqueueInput {
                            job_id: Some((i as u128).to_be_bytes()),
                            payload: b"soak-payload",
                            content_type: "text/plain".into(),
                            maximum_attempts: 10,
                            not_before_ns: None,
                        },
                        &mut b,
                    )
                    .await;
                i += 1;
                if r.is_err() {
                    break; // budget/transport: the next poll retries
                }
                if i.is_multiple_of(target) {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        i
    });

    // Workers: batched deliveries through faulting transport.
    let exec = std::sync::Arc::new(SoakExecutor {
        fail_retryable_pct: 10,
        fail_permanent_pct: 2,
        counter: std::sync::atomic::AtomicU64::new(0),
    });
    let mut handles = Vec::new();
    for w in 0..workers {
        let store = FlakyStore::new(
            mem.clone(),
            seed ^ (w as u64 + 2),
            fault_percent,
            faults.clone(),
        );
        let m = metrics.clone();
        let exec = exec.clone();
        let rx = stop_rx.clone();
        handles.push(tokio::spawn(async move {
            let q = Queue::open(Box::new(store), "q", opts(&format!("soak-w{w}")))
                .await
                .map_err(|e| e.to_string())?;
            let mut nowork = 0u32;
            loop {
                if *rx.borrow() {
                    return Ok(()) as Result<(), String>;
                }
                match stowq_worker::run_batch_with(
                    &q,
                    &DoorbellMsg::sweep(),
                    exec.as_ref(),
                    2_000_000_000, // 2s leases: renewals occasionally matter
                    4,
                    Some(&m),
                )
                .await
                {
                    Ok(reports) => {
                        if reports.is_empty() {
                            nowork += 1;
                            if nowork > 8 {
                                tokio::time::sleep(Duration::from_millis(300)).await;
                            }
                        } else {
                            nowork = 0;
                        }
                    }
                    Err(_) => {
                        // Transport exhaustion under soak: brief pause.
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        nowork = 0;
                    }
                }
            }
        }));
    }

    // Clock driver: the memory store's clock advances only on
    // writes, but backoffs and lease expiries are wall-clock-scale;
    // without driving it, nacked jobs freeze in backoff forever.
    // Advance store time at wall rate (a real store's clock ticks).
    let clock_mem = mem.clone();
    let clock_stop = stop_rx.clone();
    let clock_driver = tokio::spawn(async move {
        let mut sim_ns: u64 = 0;
        loop {
            tokio::time::sleep(Duration::from_millis(250)).await;
            if *clock_stop.borrow() {
                return;
            }
            sim_ns += 250_000_000;
            clock_mem.advance_clock_to(sim_ns);
        }
    });

    // Sweeper: every 5s.
    let sweep_q = Queue::open(
        Box::new(FlakyStore::new(
            mem.clone(),
            seed ^ 0xff,
            fault_percent,
            faults.clone(),
        )),
        "q",
        opts("soak-sweeper"),
    )
    .await
    .map_err(|e| e.to_string())?;
    let sweeper_stop = stop_rx.clone();
    let sweeper = tokio::spawn(async move {
        loop {
            if *sweeper_stop.borrow() {
                return;
            }
            let mut b = OpBudget::new(8192);
            let _ = stowq_worker::sweep_once(&sweep_q, &mut b).await;
            // GC past the terminal horizon keeps the jobs prefix
            // bounded for long soaks (retention 0: collect now).
            let floor = sweep_q.establish_floor(&mut b).await.unwrap_or(0);
            let _ = sweep_q.gc(floor, 0, 0, &mut b).await;
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });

    // Periodic reporting.
    let report_metrics = metrics.clone();
    let reporter_stop = stop_rx.clone();
    let reporter = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
            if *reporter_stop.borrow() {
                return;
            }
            eprintln!(
                "[soak +{:>4}s] {}",
                t0.elapsed().as_secs(),
                report_metrics.snapshot()
            );
        }
    });

    // Run the soak duration (a 0-minute smoke floor of 5s).
    let duration_s = if minutes == 0 { 5 } else { minutes * 60 };
    tokio::time::sleep(Duration::from_secs(duration_s)).await;

    // Drain order matters: stop the PRODUCER first, let the workers
    // consume the remaining backlog to quiescence (NoWork streak),
    // then stop them. The reporter and sweeper run through the drain.
    let _drain_rx = stop_rx.clone();
    producer_stop_flag.send(true).map_err(|e| e.to_string())?;
    let total_enqueued = producer.await.map_err(|e| e.to_string())?;

    // Quiescence: metrics quiet for 2s AND every enqueued job
    // terminal (backoff retries keep jobs mid-flight with quiet
    // metrics between their attempts). Metric quiet alone drains too
    // early; terminal completeness alone never fires if a worker is
    // stuck. Require both, with a deadline.
    let probe = Queue::open(Box::new(mem.clone()), "q", opts("soak-probe"))
        .await
        .map_err(|e| e.to_string())?;
    let mut last_done = 0u64;
    let mut stable = 0u8;
    let drain_deadline = Instant::now() + Duration::from_secs(90);
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let done = metrics.delivered.load(Ordering::Relaxed)
            + metrics.failed_permanent.load(Ordering::Relaxed);
        let mut pb = OpBudget::new(256);
        let d = probe.depth(0, &mut pb).await.unwrap_or_default();
        let all_terminal = d.jobs == d.receipts + d.dead;
        if done == last_done && all_terminal {
            stable += 1;
        } else {
            stable = 0;
            last_done = done;
        }
        if stable >= 2 || Instant::now() > drain_deadline {
            break;
        }
    }
    stop_tx.send(true).map_err(|e| e.to_string())?;
    let _ = reporter.await;
    let _ = sweeper.await;
    let _ = clock_driver.await;
    for h in handles {
        let _ = h.await;
    }

    // Final assertions on a clean handle.
    let verify = Queue::open(Box::new(mem.clone()), "q", opts("soak-verify"))
        .await
        .map_err(|e| e.to_string())?;
    let mut b = OpBudget::new(8192);
    // One final gc pass collects any last-window race artifact
    // before the repair scan sees it (structural close, not timing).
    let floor = verify.establish_floor(&mut b).await.unwrap_or(0);
    let _ = verify.gc(floor, 0, 0, &mut b).await;
    let d = verify.depth(0, &mut b).await.map_err(|e| e.to_string())?;
    let (report, _) = verify
        .repair_scan(0, &mut b)
        .await
        .map_err(|e| e.to_string())?;
    let final_metrics = metrics.snapshot();

    println!(
        "soak complete: {} min, {} fault% (seed {seed}), workers {workers}",
        minutes, fault_percent
    );
    println!("enqueued: {total_enqueued}");
    println!(
        "final depth: jobs {} claims {} receipts {} dead {}",
        d.jobs, d.claims, d.receipts, d.dead
    );
    println!("final metrics: {}", final_metrics);
    println!(
        "faults drawn: pre {} post {}",
        faults.0.load(Ordering::Relaxed),
        faults.1.load(Ordering::Relaxed)
    );

    // Assertions.
    let mut failures = Vec::new();
    if !report.findings.is_empty() {
        failures.push(format!("repair findings: {:?}", report.findings));
    }
    // Every enqueued job must be terminal: jobs == receipts + dead.
    if d.jobs != d.receipts + d.dead {
        failures.push(format!(
            "non-terminal jobs: jobs {} vs receipts {} + dead {}",
            d.jobs, d.receipts, d.dead
        ));
    }
    // Delivered + permanently failed should account for every job
    // (retryable failures eventually succeed within 10 attempts).
    let accounted = final_metrics.delivered + final_metrics.failed_permanent;
    if accounted < total_enqueued {
        failures.push(format!(
            "accounting gap: delivered {} + permanent {} < enqueued {}",
            final_metrics.delivered, final_metrics.failed_permanent, total_enqueued
        ));
    }
    if !failures.is_empty() {
        for f in &failures {
            eprintln!("SOAK VIOLATION: {f}");
        }
        return Err(format!("{} soak violations", failures.len()));
    }
    println!("SOAK CLEAN");
    Ok(())
}

// ---------- main ----------

fn parse() -> Result<(String, Vec<String>), String> {
    let mut it = std::env::args().skip(1);
    let mode = it
        .next()
        .ok_or("usage: stowq-bench ops|mem|live|live-batch|soak [args...]")?;
    let rest: Vec<String> = it.collect();
    Ok((mode, rest))
}

#[tokio::main]
async fn main() {
    let (mode, rest) = parse().unwrap_or_else(|e| {
        eprintln!("error: {e}");
        std::process::exit(2);
    });
    let num =
        |i: usize, d: usize| -> usize { rest.get(i).and_then(|s| s.parse().ok()).unwrap_or(d) };
    let r = match mode.as_str() {
        "ops" => ops_mode().await,
        "mem" => mem_mode(num(0, 1000)).await,
        "live" => live_mode(num(0, 500).min(500)).await,
        "live-batch" => live_batch_mode(num(0, 100).min(200), num(1, 5).clamp(1, 64)).await,
        "soak" => {
            // soak [minutes] [workers] [fault-percent] [seed]
            soak_mode(
                num(0, 2) as u64,
                num(1, 4).clamp(1, 16),
                num(2, 1).min(20) as u64,
                num(3, 42) as u64,
            )
            .await
        }
        m => Err(format!("unknown mode {m}")),
    };
    if let Err(e) = r {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes as B;
    use stowq_store::StoreError;

    #[tokio::test]
    async fn counting_store_tallies_every_kind() {
        use sha2::Digest as _;
        let (s, c) = CountingStore::new(MemoryStore::new());
        let k = Key::new("a");
        let d: [u8; 32] = sha2::Sha256::digest(b"x").into();
        s.put_if_absent(&k, B::from_static(b"x"), d).await.unwrap();
        s.get(&k, None).await.unwrap();
        s.head(&k).await.unwrap();
        s.list("", None, 10).await.unwrap();
        s.delete(&k).await.unwrap();
        let v = stowq_store::Version("1".into());
        assert_eq!(
            s.cas(
                &k,
                B::from_static(b"y"),
                sha2::Sha256::digest(b"y").into(),
                &v
            )
            .await
            .unwrap_err(),
            StoreError::NotFound
        );
        assert_eq!(c.put_if_absent.load(Ordering::Relaxed), 1);
        assert_eq!(c.cas.load(Ordering::Relaxed), 1);
        assert_eq!(c.get.load(Ordering::Relaxed), 1);
        assert_eq!(c.head.load(Ordering::Relaxed), 1);
        assert_eq!(c.list.load(Ordering::Relaxed), 1);
        assert_eq!(c.delete.load(Ordering::Relaxed), 1);
        assert_eq!(c.total(), 6);
    }
}
