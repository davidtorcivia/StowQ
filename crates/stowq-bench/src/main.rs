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
use std::time::Instant;
use stowq_core::{
    AckOutcome, BuryOutcome, ClaimOptions, ClaimOutcome, CommitOutcome, EnqueueInput,
    EnqueueOutcome, OpBudget, OpenOptions, Queue, RenewOutcome,
};
use stowq_format::FormatRecord;
use stowq_store::{Key, MemoryStore, Object, ObjectStore, Page, PutOutcome, StoreResult, Version};

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
        shard_count: 1,
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
    let ClaimOutcome::Claimed(c) = q
        .claim(
            &ClaimOptions {
                shard: 0,
                floor_ns: floor,
                lease_duration_ns: 60_000_000_000,
            },
            b,
        )
        .await
        .map_err(|e| e.to_string())?
    else {
        return Ok(()); // a prior cycle's lease may still nominally hold
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

// ---------- main ----------

fn parse() -> Result<(String, usize), String> {
    let mut it = std::env::args().skip(1);
    let mode = it
        .next()
        .ok_or("usage: stowq-bench ops|mem|live [cycles]")?;
    let cycles: usize = it
        .next()
        .map(|s| s.parse().map_err(|_| "cycles".to_string()))
        .transpose()?
        .unwrap_or(1000);
    Ok((mode, cycles))
}

#[tokio::main]
async fn main() {
    let (mode, cycles) = parse().unwrap_or_else(|e| {
        eprintln!("error: {e}");
        std::process::exit(2);
    });
    let r = match mode.as_str() {
        "ops" => ops_mode().await,
        "mem" => mem_mode(cycles).await,
        "live" => live_mode(cycles.min(500)).await,
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
