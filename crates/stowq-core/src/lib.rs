//! The queue state machine over an `ObjectStore`.
//!
//! Every mutation is a conditional write; the store is the only arbiter.
//! Outcome-unknown never escapes unresolved: each write path resolves by
//! re-reading the target key and comparing writer tokens or record
//! digests before returning. Long-running entry points take an explicit
//! [`OpBudget`] so bounded work is a type-level fact.

use bytes::Bytes;
use sha2::{Digest as _, Sha256};
use stowq_format::{
    ClaimBasis, ClaimRecord, DeadRecord, FailRecord, JobRecord, ReceiptRecord, Record,
};
use stowq_keys::{compute_shard, key_tag, Key as RelKey};
use stowq_math::RetryPolicy;
use stowq_store::{Digest, Key, Meta, ObjectStore, PutOutcome, StoreError, Version};
use thiserror::Error;

// ---------- Options and outcomes ----------

#[derive(Debug, Clone)]
pub struct OpenOptions {
    pub queue_id: [u8; 16],
    pub worker_id: String,
    pub retry: RetryPolicy,
    /// Per-profile constant absorbing store clock dispersion; see
    /// spec/time.md. Enforced >= the profile granularity by the caller.
    pub skew_guard_ns: u64,
    pub max_inline_payload: u64,
}

impl OpenOptions {
    pub fn new(queue_id: [u8; 16]) -> Self {
        OpenOptions {
            queue_id,
            worker_id: "worker-1".into(),
            retry: RetryPolicy::new(100, 60_000, true, None).expect("valid default policy"),
            skew_guard_ns: 0,
            max_inline_payload: 65_536,
        }
    }
}

/// Bounds the store operations one entry point may spend.
#[derive(Debug, Clone, Copy)]
pub struct OpBudget {
    pub max_ops: usize,
}

impl OpBudget {
    pub fn new(max_ops: usize) -> Self {
        OpBudget { max_ops }
    }

    fn spend(&mut self) -> Result<(), Error> {
        if self.max_ops == 0 {
            return Err(Error::BudgetExhausted);
        }
        self.max_ops -= 1;
        Ok(())
    }

    /// Divides the remaining budget into `n` independent child
    /// budgets (`remaining / n` each); the division remainder stays
    /// here. Children are refunded with [`OpBudget::merge`], so the
    /// total work bound holds across the split's lifetime.
    pub fn split(&mut self, n: usize) -> Vec<OpBudget> {
        if n == 0 {
            return Vec::new();
        }
        let each = self.max_ops / n;
        self.max_ops -= each * n;
        (0..n).map(|_| OpBudget { max_ops: each }).collect()
    }

    /// Refunds unspent child ops to this budget. Children are left
    /// empty; a merged child must not be spent from again.
    pub fn merge(&mut self, children: &mut [OpBudget]) {
        self.max_ops += children
            .iter_mut()
            .map(|c| std::mem::take(&mut c.max_ops))
            .sum::<usize>();
    }
}

impl Default for OpBudget {
    fn default() -> Self {
        OpBudget { max_ops: 64 }
    }
}

#[derive(Debug, Clone)]
pub struct EnqueueInput<'a> {
    /// Deterministic id for idempotent enqueue; generated when absent.
    pub job_id: Option<[u8; 16]>,
    pub payload: &'a [u8],
    pub content_type: String,
    pub maximum_attempts: u64,
    /// Wall-time floor (store time) before which the job must not be
    /// delivered; None when not delayed.
    pub not_before_ns: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnqueueOutcome {
    /// The job record committed (or was already present, byte-identical,
    /// from our own earlier attempt).
    Committed { job_id: [u8; 16] },
    /// Another producer's record holds the key with different content.
    IdTaken { job_id: [u8; 16] },
}

#[derive(Debug, Clone)]
pub struct ClaimOptions {
    /// Which shard to scan.
    pub shard: u16,
    /// The claimant's wall floor in store time. Callers establish this
    /// per spec/time.md; the queue never consults a local clock.
    pub floor_ns: u64,
    pub lease_duration_ns: u64,
}

#[derive(Debug)]
pub enum ClaimOutcome {
    Claimed(Claim),
    /// No ready job found within the budget.
    Empty,
}

/// Custody of one job at one generation. Carries the worker token;
/// only the holder can act on it.
#[derive(Clone)]
pub struct Claim {
    pub job_id: [u8; 16],
    pub shard: u16,
    pub generation: u64,
    pub attempt: u64,
    pub worker_token: [u8; 16],
    pub lease_duration_ns: u64,
    /// Store time of the claim object, read back after commit.
    pub claim_store_time_ns: u64,
    payload: PayloadRef,
}

impl Claim {
    /// Builds a claim handle whose payload reference is reconstructed
    /// from the job record: inline bytes come from the record; a
    /// detached payload is fetched by its key and verified against the
    /// record's digest. For tooling that rebuilds handles from
    /// persisted state.
    #[allow(clippy::too_many_arguments)]
    pub async fn detached_or_inline(
        job_id: [u8; 16],
        shard: u16,
        generation: u64,
        attempt: u64,
        worker_token: [u8; 16],
        lease_duration_ns: u64,
        claim_store_time_ns: u64,
        queue_root: &str,
        store: &dyn ObjectStore,
    ) -> Result<Claim, Error> {
        let rel = RelKey::Job { shard, job_id };
        let abs = Key::new(format!("{queue_root}/{}", rel));
        let tag = stowq_keys::key_tag(&QUEUE_ID_FOR_TOOLING, &rel.to_string());
        let obj = match store.get(&abs, None).await {
            Ok(obj) => obj,
            Err(StoreError::NotFound) => {
                return Err(Error::Record("job record not found for handle".into()))
            }
            Err(e) => return Err(e.into()),
        };
        let job = match stowq_format::decode(&obj.body, &QUEUE_ID_FOR_TOOLING, &tag)? {
            Record::Job(j) => j,
            _ => return Err(Error::Record("job key holds a non-job record".into())),
        };
        let payload = match (&job.payload_inline, &job.payload_key) {
            (Some(b), _) => PayloadRef::Inline(Bytes::from(b.clone())),
            (None, Some(k)) => {
                let key = Key::new(format!("{queue_root}/{k}"));
                let obj = store.get(&key, None).await?;
                let got: Digest = Sha256::digest(&obj.body).into();
                if got != job.payload_digest || obj.body.len() as u64 != job.payload_length {
                    return Err(Error::PayloadCorrupt);
                }
                PayloadRef::Detached {
                    key,
                    digest: job.payload_digest,
                    length: job.payload_length,
                }
            }
            _ => return Err(Error::Record("job payload reference invalid".into())),
        };
        Ok(Claim {
            job_id,
            shard,
            generation,
            attempt,
            worker_token,
            lease_duration_ns,
            claim_store_time_ns,
            payload,
        })
    }

    /// The inline payload bytes, when the claim carries them.
    pub fn payload_preview(&self) -> Option<&[u8]> {
        match &self.payload {
            PayloadRef::Inline(b) => Some(b),
            PayloadRef::Detached { .. } => None,
        }
    }
}

impl std::fmt::Debug for Claim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Claim")
            .field("job_id", &hex(&self.job_id))
            .field("shard", &self.shard)
            .field("generation", &self.generation)
            .field("attempt", &self.attempt)
            .field("worker_token", &hex(&self.worker_token))
            .field("lease_duration_ns", &self.lease_duration_ns)
            .field("claim_store_time_ns", &self.claim_store_time_ns)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
enum PayloadRef {
    Inline(Bytes),
    Detached {
        key: Key,
        digest: Digest,
        length: u64,
    },
}

impl Claim {
    /// The payload bytes, digest-verified. Detached payloads are fetched
    /// and hashed; a mismatch is an integrity error, never delivery.
    pub async fn payload(&self, store: &dyn ObjectStore) -> Result<Bytes, Error> {
        match &self.payload {
            PayloadRef::Inline(b) => Ok(b.clone()),
            PayloadRef::Detached {
                key,
                digest,
                length,
            } => {
                let obj = store.get(key, None).await?;
                if obj.body.len() as u64 != *length {
                    return Err(Error::PayloadCorrupt);
                }
                let got: Digest = Sha256::digest(&obj.body).into();
                if &got != digest {
                    return Err(Error::PayloadCorrupt);
                }
                Ok(obj.body)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AckOutcome {
    /// The receipt committed.
    Acked,
    /// A receipt already existed and its evidence matches this claim.
    AlreadyAcked,
    /// A dead record terminalized the job first; the ack refused.
    SupersededByDead,
}

/// A store-resident effect committed through the commit rule
/// (spec records.md): put-if-absent at a deterministic job-derived key
/// under `outputs/`, written before the receipt. Produced by
/// `Queue::commit_output` and passed back verbatim to
/// `ack_with_outputs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedOutput {
    /// Absolute store key of the output object.
    pub key: String,
    pub digest: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitOutcome {
    /// This call's put-if-absent won; the stored bytes are ours.
    Committed(CommittedOutput),
    /// The key already held byte-identical content (a duplicate
    /// attempt converging on the first-wins result); nothing written.
    Converged(CommittedOutput),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuryOutcome {
    /// The dead record committed.
    Buried,
    /// A receipt terminalized the job first; the bury refused.
    SupersededByReceipt,
}

#[derive(Debug, Clone)]
pub enum RenewOutcome {
    /// The continuation claim committed.
    Renewed(Claim),
    /// Another writer holds a later generation.
    LeaseLost,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("store: {0}")]
    Store(#[from] StoreError),
    #[error("record: {0}")]
    Record(String),
    #[error("key grammar: {0}")]
    Key(String),
    #[error("budget exhausted before completion")]
    BudgetExhausted,
    #[error("transport retries exhausted")]
    TransportExhausted,
    #[error("queue id mismatch")]
    QueueIdMismatch,
    #[error("payload digest mismatch")]
    PayloadCorrupt,
    #[error("receipt evidence mismatch")]
    ReceiptEvidenceMismatch,
    #[error("output key holds different bytes (output_digest_conflict, 0x0011); first-wins digest: {}", hex(.0))]
    OutputConflict(Digest),
    #[error("output evidence mismatch: {0}")]
    OutputEvidenceMismatch(String),
    #[error("operation budget hit an internal invariant; report this")]
    Internal(String),
}

impl From<stowq_format::RecordError> for Error {
    fn from(e: stowq_format::RecordError) -> Self {
        Error::Record(e.to_string())
    }
}

/// Output names select a key under `outputs/<job-id>/`. `outputs/` is
/// application space (spec namespace.md); the only protocol constraint
/// is that a name cannot escape the job's prefix.
fn valid_output_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('/')
        && !name.contains('\\')
        && !name.contains('\0')
        && name
            .split('/')
            .all(|seg| !seg.is_empty() && seg != "." && seg != "..")
}

/// Classifies the bytes found at an output key against the digest we
/// intended to write: identical bytes are convergence on the
/// first-wins result; different bytes are an output conflict.
fn classify_output(
    obj: &stowq_store::Object,
    digest: Digest,
    out: CommittedOutput,
) -> Result<CommitOutcome, Error> {
    let got: Digest = Sha256::digest(&obj.body).into();
    if got == digest {
        Ok(CommitOutcome::Converged(out))
    } else {
        Err(Error::OutputConflict(got))
    }
}

// ---------- Writer tokens ----------

fn fresh_token() -> [u8; 16] {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).expect("entropy source unavailable");
    b
}

fn hex(b: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    // One allocation, no per-byte intermediates: this runs for every
    // claim scan, output key, and terminal probe.
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push(HEX[(x >> 4) as usize] as char);
        s.push(HEX[(x & 0x0f) as usize] as char);
    }
    s
}

// ---------- Queue ----------

pub struct Queue {
    store: Box<dyn ObjectStore>,
    root: String,
    opts: OpenOptions,
    format: stowq_format::FormatRecord,
    /// Cached wall floor (store time) and when it was established; see
    /// establish_floor.
    floor: std::sync::Mutex<FloorCache>,
    /// Scan-proven terminal jobs, keyed by the jobs index entry's
    /// version with a staleness deadline; see memoize_terminal.
    terminal_memo: std::sync::Mutex<TerminalMemo>,
    clock: std::sync::Arc<dyn ElapsedClock>,
}

/// The terminality memo's entry cap: on overflow it is cleared
/// wholesale and the scan re-proves lazily. Bounded memory; the worst
/// case is one full re-scan per cap-overflow, never a wrong skip.
/// Jobs this handle has proven terminal: (shard, job_id) to the
/// jobs-entry version at proof time and the proof's clock reading.
type TerminalMemo = std::collections::HashMap<(u16, [u8; 16]), (Version, u64)>;

const TERMINAL_MEMO_CAP: usize = 65_536;

/// A memo entry is honored for at most this long (the floor-staleness
/// philosophy: staleness only delays work). Versions are not
/// incarnation proofs on every backend — content-addressed stores
/// (S3-family ETags) repeat versions across byte-identical
/// re-enqueues after GC — so a stale entry is re-proven after the
/// window; the version key still catches every input-changing
/// re-enqueue immediately.
const TERMINAL_MEMO_TTL_NS: u64 = 30 * 1_000_000_000;

/// Elapsed time since an arbitrary fixed anchor, monotone. The floor
/// cache trusts local time only for its staleness deadline, never for
/// protocol decisions; targets without a std clock supply their own.
pub trait ElapsedClock: Send + Sync {
    fn elapsed_ns(&self) -> u64;
}

/// Native clock anchored at construction.
pub struct NativeElapsedClock {
    anchor: std::time::Instant,
}

impl NativeElapsedClock {
    pub fn new() -> Self {
        NativeElapsedClock {
            anchor: std::time::Instant::now(),
        }
    }
}

impl Default for NativeElapsedClock {
    fn default() -> Self {
        Self::new()
    }
}

/// Test clock: settable reading.
#[cfg(test)]
pub(crate) struct FakeClock {
    now: std::sync::atomic::AtomicU64,
}

#[cfg(test)]
impl FakeClock {
    pub(crate) fn new() -> Self {
        FakeClock {
            now: std::sync::atomic::AtomicU64::new(0),
        }
    }
    pub(crate) fn advance_ns(&self, ns: u64) {
        self.now.fetch_add(ns, std::sync::atomic::Ordering::Relaxed);
    }
}

#[cfg(test)]
impl ElapsedClock for FakeClock {
    fn elapsed_ns(&self) -> u64 {
        self.now.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl ElapsedClock for NativeElapsedClock {
    fn elapsed_ns(&self) -> u64 {
        self.anchor.elapsed().as_nanos() as u64
    }
}

#[derive(Debug, Clone)]
struct FloorCache {
    floor_ns: u64,
    /// Clock reading at establishment; see ElapsedClock.
    established_at_ns: u64,
}

/// A floor is reused for at most this long before re-establishment;
/// staleness only delays work, never delivers early.
const FLOOR_STALENESS_NS: u64 = 30 * 1_000_000_000;

const RETRY_TRANSPORT_MAX: usize = 4;

/// Queue id for handle-reconstruction tooling built on the dev
/// convention (OpenOptions::new([1; 16])).
const QUEUE_ID_FOR_TOOLING: [u8; 16] = [1; 16];

impl Queue {
    /// Opens an initialized queue: reads and verifies `meta/FORMAT`.
    pub async fn open(
        store: Box<dyn ObjectStore>,
        root: &str,
        opts: OpenOptions,
    ) -> Result<Self, Error> {
        Self::open_with_clock(
            store,
            root,
            opts,
            std::sync::Arc::new(NativeElapsedClock::new()),
        )
        .await
    }

    /// [`Queue::open`] with an injected elapsed clock — for tests that
    /// advance time past staleness windows.
    pub async fn open_with_clock(
        store: Box<dyn ObjectStore>,
        root: &str,
        opts: OpenOptions,
        clock: std::sync::Arc<dyn ElapsedClock>,
    ) -> Result<Self, Error> {
        let root = format!("{}/", root.trim_end_matches('/'));
        let mut q = Queue {
            store,
            root,
            opts,
            format: stowq_format::FormatRecord {
                shard_count: 0,
                lease_bucket_width_ns: 1,
                delayed_bucket_width_ns: 1,
                terminal_bucket_width_ns: 1,
                inline_limit: 0,
                required_feature_bits: 0,
            },
            floor: std::sync::Mutex::new(FloorCache {
                floor_ns: 0,
                established_at_ns: 0,
            }),
            terminal_memo: std::sync::Mutex::new(std::collections::HashMap::new()),
            clock,
        };
        let key = q.absolute(&RelKey::Format);
        let tag = key_tag(&q.opts.queue_id, "meta/FORMAT");
        let obj = q.store.get(&key, None).await?;
        let record = stowq_format::decode(&obj.body, &q.opts.queue_id, &tag)?;
        let Record::Format(format) = record else {
            return Err(Error::Record("meta/FORMAT is not a format record".into()));
        };
        format.validate()?;
        q.format = format;
        Ok(q)
    }

    /// Initializes a queue prefix: writes `meta/FORMAT` (put-if-absent;
    /// an existing identical record is accepted, a different one is an
    /// error).
    pub async fn init(
        store: Box<dyn ObjectStore>,
        root: &str,
        opts: &OpenOptions,
        format: &stowq_format::FormatRecord,
    ) -> Result<Self, Error> {
        format.validate()?;
        let root = format!("{}/", root.trim_end_matches('/'));
        let key = format!("{root}meta/FORMAT");
        let key = Key::new(key);
        let tag = key_tag(&opts.queue_id, "meta/FORMAT");
        let body = Bytes::from(stowq_format::encode(
            &Record::Format(format.clone()),
            &opts.queue_id,
            &tag,
        ));
        let digest: Digest = Sha256::digest(&body).into();
        match store.put_if_absent(&key, body, digest).await? {
            PutOutcome::Committed { .. } => {}
            PutOutcome::Rejected => {
                // A different format may already own the prefix: read
                // it back and compare. This is a post-write resolution
                // read, so outcome-unknown retries rather than leaking
                // (init predates the budget; the retry counter alone
                // bounds the loop).
                let mut retries = 0;
                let obj = loop {
                    match store.get(&key, None).await {
                        Ok(obj) => break obj,
                        Err(StoreError::Transport(_)) | Err(StoreError::OutcomeUnknown(_)) => {
                            retries += 1;
                            if retries > RETRY_TRANSPORT_MAX {
                                return Err(Error::TransportExhausted);
                            }
                            continue;
                        }
                        Err(e) => return Err(e.into()),
                    }
                };
                let existing = stowq_format::decode(&obj.body, &opts.queue_id, &tag)?;
                if existing != Record::Format(format.clone()) {
                    return Err(Error::QueueIdMismatch);
                }
            }
        }
        Self::open(store, &root, opts.clone()).await
    }

    pub fn format(&self) -> &stowq_format::FormatRecord {
        &self.format
    }

    /// The underlying store, for inspection and audit tooling.
    pub fn store(&self) -> &dyn ObjectStore {
        self.store.as_ref()
    }

    fn is_memoized_terminal(&self, shard: u16, job_id: [u8; 16], version: &Version) -> bool {
        self.terminal_memo
            .lock()
            .unwrap()
            .get(&(shard, job_id))
            .is_some_and(|(v, at)| {
                v == version && self.clock.elapsed_ns().saturating_sub(*at) < TERMINAL_MEMO_TTL_NS
            })
    }

    /// Records that this handle proved the job terminal while its jobs
    /// index entry had this version. Terminality is monotone (receipts
    /// and dead records are never un-written; GC removes the whole
    /// graph including the jobs entry), and a version mismatch always
    /// re-examines — but a version match is not an incarnation proof
    /// on content-addressed backends (identical-input re-enqueues
    /// repeat etags), so entries carry a staleness deadline and are
    /// re-proven once per window.
    fn memoize_terminal(&self, shard: u16, job_id: [u8; 16], version: Version) {
        let mut memo = self.terminal_memo.lock().unwrap();
        if memo.len() >= TERMINAL_MEMO_CAP {
            memo.clear();
        }
        memo.insert((shard, job_id), (version, self.clock.elapsed_ns()));
    }

    /// Establishes a wall floor (spec time.md): PUT a beacon, read it
    /// back, take the store-assigned time. The floor is a proven lower
    /// bound on store time. Cached until stale; staleness only delays
    /// work, never delivers early.
    pub async fn establish_floor(&self, budget: &mut OpBudget) -> Result<u64, Error> {
        {
            let cache = self.floor.lock().unwrap();
            if cache.floor_ns > 0
                && self
                    .clock
                    .elapsed_ns()
                    .saturating_sub(cache.established_at_ns)
                    < FLOOR_STALENESS_NS
            {
                return Ok(cache.floor_ns);
            }
        }
        let body = Bytes::from_static(b"");
        let digest: Digest = Sha256::digest([]).into();
        let mut floor_ns = 0;
        for _ in 0..=RETRY_TRANSPORT_MAX {
            // Beacons are content-free: on a nonce collision or an
            // unknown outcome, a fresh nonce is always correct.
            let nonce = fresh_token();
            let rel = RelKey::Beacon { nonce };
            let abs = self.absolute(&rel);
            budget.spend()?;
            match self.store.put_if_absent(&abs, body.clone(), digest).await {
                Ok(PutOutcome::Committed { .. }) => {
                    budget.spend()?;
                    let meta = self.store.head(&abs).await?;
                    floor_ns = meta.store_time_ns;
                    break;
                }
                Ok(PutOutcome::Rejected) => continue,
                Err(StoreError::Transport(_)) | Err(StoreError::OutcomeUnknown(_)) => {
                    // A lost beacon write is unobservable either way:
                    // the nonce is fresh next iteration regardless.
                    continue;
                }
                Err(e) => return Err(e.into()),
            }
        }
        if floor_ns == 0 {
            return Err(Error::TransportExhausted);
        }
        // A fresh floor below the watermark means store time moved
        // backwards: the watermark only ever holds buckets derived from
        // earlier floors. Fail closed; the skew guard absorbs the
        // profile's timestamp dispersion and granularity (skew_guard
        // >= G). The gate runs on the RAW beacon — before the raise
        // below — so raising can never mask a regression. The
        // watermark read is best-effort — its absence is not a
        // regression.
        if let Some(w) = self.watermark(budget).await? {
            let wm_ns = w
                .highest_observed_wall_bucket
                .saturating_mul(self.format.delayed_bucket_width_ns);
            if floor_ns.saturating_add(self.opts.skew_guard_ns) < wm_ns {
                return Err(Error::Store(StoreError::ProfileViolation(
                    "store time regression".into(),
                )));
            }
            // Raise to the watermark bucket (time.md): the bucket was
            // derived from an earlier proven floor, so it is itself a
            // proven lower bound on store time, and the max of two
            // lower bounds is a lower bound. The gate above bounded
            // the gap to skew_guard, so the raise is at most that.
            floor_ns = stowq_math::effective_floor(
                floor_ns,
                w.highest_observed_wall_bucket,
                self.format.delayed_bucket_width_ns,
            )
            .ok_or_else(|| Error::Internal("floor raise overflow".into()))?;
        }
        *self.floor.lock().unwrap() = FloorCache {
            floor_ns,
            established_at_ns: self.clock.elapsed_ns(),
        };
        Ok(floor_ns)
    }

    /// Shard depth: object counts per plane prefix. A monitoring
    /// probe, not a protocol operation — four bounded listings.
    pub async fn depth(&self, shard: u16, budget: &mut OpBudget) -> Result<DepthReport, Error> {
        let mut report = DepthReport::default();
        for (prefix, slot) in [
            ("jobs", 0usize),
            ("claims", 1),
            ("receipts", 2),
            ("dead", 3),
        ] {
            let p = format!("{}{}/{shard:04x}/", self.root, prefix);
            let mut after: Option<Key> = None;
            loop {
                budget.spend()?;
                let page = self.store.list(&p, after.as_ref(), 1024).await?;
                let n = page.items.len() as u64;
                match slot {
                    0 => report.jobs += n,
                    1 => report.claims += n,
                    2 => report.receipts += n,
                    _ => report.dead += n,
                }
                match page.next_after {
                    Some(k) => after = Some(k),
                    None => break,
                }
            }
        }
        Ok(report)
    }

    /// Reads and verifies the watermark record, if present.
    pub async fn watermark(
        &self,
        budget: &mut OpBudget,
    ) -> Result<Option<stowq_format::WatermarkRecord>, Error> {
        let rel = RelKey::Watermark;
        let abs = self.absolute(&rel);
        let tag = self.tag_for(&rel);
        // read_retrying spends the budget; this read also backs the
        // watermark CAS's outcome resolution, so it must not leak an
        // unknown outcome upward.
        match self.read_retrying(&abs, budget).await {
            Ok(obj) => match stowq_format::decode(&obj.body, &self.opts.queue_id, &tag)? {
                Record::Watermark(w) => Ok(Some(w)),
                _ => Err(Error::Record(
                    "watermark key holds a non-watermark record".into(),
                )),
            },
            Err(Error::Store(StoreError::NotFound)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Reads and verifies this job's receipt, if present. For callers
    /// (the consumer harness) comparing a foreign receipt's completed
    /// state against their own delivery.
    pub async fn receipt_for(
        &self,
        claim: &Claim,
        budget: &mut OpBudget,
    ) -> Result<Option<stowq_format::ReceiptRecord>, Error> {
        let rel = RelKey::Receipt {
            shard: claim.shard,
            job_id: claim.job_id,
        };
        let abs = self.absolute(&rel);
        let tag = self.tag_for(&rel);
        match self.read_retrying(&abs, budget).await {
            Ok(obj) => match stowq_format::decode(&obj.body, &self.opts.queue_id, &tag)? {
                Record::Receipt(r) => Ok(Some(r)),
                _ => Err(Error::Record(
                    "receipt key holds a non-receipt record".into(),
                )),
            },
            Err(Error::Store(StoreError::NotFound)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Advances the watermark monotonically (spec time.md): If-Match CAS;
    /// a lost race means someone advanced it further — the stored value
    /// then already covers our bucket and the call proceeds. A bucket at
    /// or below the stored one is a no-op. Genuine regression (a fresh
    /// floor below the watermark) is detected by fail-closed promotion.
    pub async fn advance_watermark(
        &self,
        floor_ns: u64,
        budget: &mut OpBudget,
    ) -> Result<(), Error> {
        let width = self.format.delayed_bucket_width_ns;
        let Some(bucket) = stowq_math::bucket_number(floor_ns, width) else {
            return Err(Error::Internal("zero delayed width".into()));
        };
        loop {
            let current = self.watermark(budget).await?;
            let exists = current.is_some();
            let next = match current {
                None => stowq_format::WatermarkRecord {
                    highest_observed_wall_bucket: bucket,
                    sequence: 0,
                },
                Some(w) => {
                    // A stored bucket above ours means someone advanced
                    // further (a lost race or a stale cached floor): the
                    // watermark already covers us; proceed. Genuine
                    // regression is detected where a fresh floor is
                    // compared against the watermark (fail-closed
                    // promotion), not here.
                    if bucket <= w.highest_observed_wall_bucket {
                        return Ok(());
                    }
                    stowq_format::WatermarkRecord {
                        highest_observed_wall_bucket: bucket,
                        sequence: w.sequence + 1,
                    }
                }
            };
            let rel = RelKey::Watermark;
            let abs = self.absolute(&rel);
            let tag = self.tag_for(&rel);
            let body = Bytes::from(stowq_format::encode(
                &Record::Watermark(next),
                &self.opts.queue_id,
                &tag,
            ));
            let digest: Digest = Sha256::digest(&body).into();
            budget.spend()?;
            // The watermark is the one CAS'd object in the protocol:
            // create-if-absent when missing, overwrite-if-unchanged when
            // present. A lost create race re-reads; a lost version race
            // also re-reads (someone advanced further).
            let outcome = if exists {
                // Read the current version and CAS against it.
                budget.spend()?;
                let meta = self.store.head(&abs).await?;
                self.store
                    .cas(&abs, body.clone(), digest, &meta.version)
                    .await
            } else {
                self.store.put_if_absent(&abs, body.clone(), digest).await
            };
            // Resolve unknown outcomes by re-reading: our record (or any
            // record covering our bucket) means done; anything else
            // re-reads the loop.
            let outcome = match outcome {
                Ok(o) => o,
                Err(StoreError::OutcomeUnknown(_)) => {
                    if self.watermark_covers(bucket, budget).await? {
                        return Ok(());
                    }
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            match outcome {
                PutOutcome::Committed { .. } => return Ok(()),
                PutOutcome::Rejected => continue,
            }
        }
    }

    /// True when the stored watermark already covers `bucket`.
    async fn watermark_covers(&self, bucket: u64, budget: &mut OpBudget) -> Result<bool, Error> {
        Ok(match self.watermark(budget).await? {
            Some(w) => w.highest_observed_wall_bucket >= bucket,
            None => false,
        })
    }

    fn absolute(&self, rel: &RelKey) -> Key {
        Key::new(format!("{}{}", self.root, rel))
    }

    fn tag_for(&self, rel: &RelKey) -> [u8; 8] {
        key_tag(&self.opts.queue_id, &rel.to_string())
    }

    // ---------- enqueue ----------

    pub async fn enqueue(
        &self,
        input: EnqueueInput<'_>,
        budget: &mut OpBudget,
    ) -> Result<EnqueueOutcome, Error> {
        // A zero-attempt job would be dead on its first claim scan; the
        // producer gets the error instead.
        if input.maximum_attempts == 0 {
            return Err(Error::Record("maximum_attempts must be positive".into()));
        }
        let job_id = input.job_id.unwrap_or_else(fresh_token);
        let shard = compute_shard(&self.opts.queue_id, &job_id, self.format.shard_count.max(1));
        let payload_digest: Digest = Sha256::digest(input.payload).into();
        // The queue's FORMAT declares the inline bound for all clients
        // (it bounds claim-scan amplification queue-wide); a client may
        // configure lower, never above the queue's limit.
        let inline_limit = self.opts.max_inline_payload.min(self.format.inline_limit);
        let inline = (input.payload.len() as u64) <= inline_limit;

        let (payload_inline, payload_key) = if inline {
            (Some(input.payload.to_vec()), None)
        } else {
            let rel = RelKey::Payload {
                job_id,
                digest: payload_digest,
            };
            let abs = self.absolute(&rel);
            let body = Bytes::copy_from_slice(input.payload);
            // Content-addressed: losing this race means identical bytes,
            // and an unknown outcome resolves by presence — the key
            // embeds the digest and the store verified the body hash at
            // PUT, so present at the key means the payload is in place.
            self.put_bytes_resolving(&abs, body, payload_digest, budget)
                .await?;
            (None, Some(rel.to_string()))
        };

        let record = Record::Job(JobRecord {
            job_id,
            maximum_attempts: input.maximum_attempts,
            content_type: input.content_type,
            created_store_time_ns: 0,
            not_before_ns: input.not_before_ns,
            payload_digest,
            payload_length: input.payload.len() as u64,
            payload_inline,
            payload_key,
        });
        let rel = RelKey::Job { shard, job_id };
        let abs = self.absolute(&rel);
        let tag = self.tag_for(&rel);
        let body = Bytes::from(stowq_format::encode(&record, &self.opts.queue_id, &tag));
        let digest: Digest = Sha256::digest(&body).into();
        budget.spend()?;
        let outcome = self
            .put_resolving(&abs, body, digest, &record, &rel, budget)
            .await?;
        match outcome {
            Resolved::NotCommitted => {
                Err(Error::Internal("enqueue not committed after retry".into()))
            }
            Resolved::Committed => {
                if let Some(nb) = input.not_before_ns {
                    let bucket = stowq_math::bucket_number(nb, self.format.delayed_bucket_width_ns)
                        .ok_or(Error::Internal("zero delayed width".into()))?;
                    let idx = self.absolute(&RelKey::DelayIndex {
                        bucket,
                        shard,
                        job_id,
                    });
                    budget.spend()?;
                    let _ = self
                        .store
                        .put_if_absent(&idx, Bytes::new(), Sha256::digest([]).into())
                        .await;
                }
                Ok(EnqueueOutcome::Committed { job_id })
            }
            Resolved::Lost => {
                // Someone's record holds the key: ours if identical
                // (idempotent enqueue), theirs otherwise.
                let tag = self.tag_for(&rel);
                let obj = self.read_retrying(&abs, budget).await?;
                // An undecodable record is provably not ours.
                match stowq_format::decode(&obj.body, &self.opts.queue_id, &tag) {
                    Ok(found) if found == record => Ok(EnqueueOutcome::Committed { job_id }),
                    _ => Ok(EnqueueOutcome::IdTaken { job_id }),
                }
            }
        }
    }

    /// The outcome-unknown resolver for content-addressed payload
    /// writes: transport retries and unknown outcomes never escape.
    /// Presence at the key proves the payload is in place (the store
    /// verified the body hash at PUT; the key embeds the digest).
    async fn put_bytes_resolving(
        &self,
        abs: &Key,
        body: Bytes,
        digest: Digest,
        budget: &mut OpBudget,
    ) -> Result<(), Error> {
        let mut transport_retries = 0;
        loop {
            budget.spend()?;
            match self.store.put_if_absent(abs, body.clone(), digest).await {
                Ok(PutOutcome::Committed { .. }) | Ok(PutOutcome::Rejected) => return Ok(()),
                Err(StoreError::Transport(_)) => {
                    transport_retries += 1;
                    if transport_retries > RETRY_TRANSPORT_MAX {
                        return Err(Error::TransportExhausted);
                    }
                    continue;
                }
                Err(StoreError::OutcomeUnknown(_)) => {
                    match self.resolve_presence(abs, budget).await? {
                        // Present means committed (possibly by us before
                        // the response was lost); absent means retry.
                        true => return Ok(()),
                        false => {
                            transport_retries += 1;
                            if transport_retries > RETRY_TRANSPORT_MAX {
                                return Err(Error::TransportExhausted);
                            }
                            continue;
                        }
                    }
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// Head-only presence probe with transport retries.
    async fn resolve_presence(&self, abs: &Key, budget: &mut OpBudget) -> Result<bool, Error> {
        let mut transport_retries = 0;
        loop {
            budget.spend()?;
            match self.store.head(abs).await {
                Ok(_) => return Ok(true),
                Err(StoreError::NotFound) => return Ok(false),
                Err(StoreError::Transport(_)) | Err(StoreError::OutcomeUnknown(_)) => {
                    transport_retries += 1;
                    if transport_retries > RETRY_TRANSPORT_MAX {
                        return Err(Error::TransportExhausted);
                    }
                    continue;
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// A full read with transport retries. Reads have no side effects,
    /// so an outcome-unknown read (an S3 5xx or timeout on GET) is as
    /// safe to retry as a pre-transmit failure; bounded like every
    /// other retry. Used by the post-write resolution reads so
    /// outcome-unknown never escapes a write path.
    async fn read_retrying(
        &self,
        abs: &Key,
        budget: &mut OpBudget,
    ) -> Result<stowq_store::Object, Error> {
        let mut transport_retries = 0;
        loop {
            budget.spend()?;
            match self.store.get(abs, None).await {
                Ok(obj) => return Ok(obj),
                Err(StoreError::Transport(_)) | Err(StoreError::OutcomeUnknown(_)) => {
                    transport_retries += 1;
                    if transport_retries > RETRY_TRANSPORT_MAX {
                        return Err(Error::TransportExhausted);
                    }
                    continue;
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// The outcome-unknown resolver shared by every conditional write:
    /// re-read the key; absent means not committed (bounded retry), present
    /// means committed by someone (compare evidence).
    async fn put_resolving(
        &self,
        abs: &Key,
        body: Bytes,
        digest: Digest,
        intended: &Record,
        rel: &RelKey,
        budget: &mut OpBudget,
    ) -> Result<Resolved, Error> {
        let mut transport_retries = 0;
        loop {
            budget.spend()?;
            let result = self.store.put_if_absent(abs, body.clone(), digest).await;
            match result {
                Ok(PutOutcome::Committed { .. }) => return Ok(Resolved::Committed),
                Ok(PutOutcome::Rejected) => return Ok(Resolved::Lost),
                Err(StoreError::Transport(_)) => {
                    transport_retries += 1;
                    if transport_retries > RETRY_TRANSPORT_MAX {
                        return Err(Error::TransportExhausted);
                    }
                    continue;
                }
                Err(StoreError::OutcomeUnknown(_)) => {
                    match self.resolve_unknown(abs, intended, rel, budget).await? {
                        Resolved::Committed => return Ok(Resolved::Committed),
                        Resolved::Lost => return Ok(Resolved::Lost),
                        // Absent after an unknown outcome: the write
                        // provably never happened; retry it.
                        Resolved::NotCommitted => {
                            transport_retries += 1;
                            if transport_retries > RETRY_TRANSPORT_MAX {
                                return Err(Error::TransportExhausted);
                            }
                            continue;
                        }
                    }
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    async fn resolve_unknown(
        &self,
        abs: &Key,
        intended: &Record,
        rel: &RelKey,
        budget: &mut OpBudget,
    ) -> Result<Resolved, Error> {
        let mut transport_retries = 0;
        loop {
            budget.spend()?;
            match self.store.head(abs).await {
                Ok(_) => {
                    let obj = self.read_retrying(abs, budget).await?;
                    let tag = self.tag_for(rel);
                    // Present but undecodable is not ours: lost (the
                    // repair scan owns quarantine).
                    match stowq_format::decode(&obj.body, &self.opts.queue_id, &tag) {
                        Ok(found) if &found == intended => return Ok(Resolved::Committed),
                        Ok(_) => return Ok(Resolved::Lost),
                        Err(_) => return Ok(Resolved::Lost),
                    }
                }
                Err(StoreError::NotFound) => return Ok(Resolved::NotCommitted),
                Err(StoreError::Transport(_)) | Err(StoreError::OutcomeUnknown(_)) => {
                    transport_retries += 1;
                    if transport_retries > RETRY_TRANSPORT_MAX {
                        return Err(Error::TransportExhausted);
                    }
                    continue;
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    // ---------- claim ----------

    pub async fn claim(
        &self,
        opts: &ClaimOptions,
        budget: &mut OpBudget,
    ) -> Result<ClaimOutcome, Error> {
        let mut claims = self.claim_many(opts, 1, budget).await?;
        match claims.pop() {
            Some(c) => Ok(ClaimOutcome::Claimed(c)),
            None => Ok(ClaimOutcome::Empty),
        }
    }

    /// Claims up to `max` jobs from one shard scan, in scan order.
    /// Candidates are probed in concurrent waves — each wave's probes
    /// overlap their round trips, each candidate carrying its own
    /// slice of the budget (split conserves the total work bound;
    /// unspent slices refund between waves). Each claim is an
    /// independent protocol claim — its own generation, lease, and
    /// fencing. Stops at `max`, at scan end, or when the budget runs
    /// dry: a partial batch is returned, an empty one propagates the
    /// error (for `max == 1` the observable behavior is exactly
    /// [`Queue::claim`]'s). An error in a wave does not prevent
    /// wave-mates' claims from being taken and returned; the erroring
    /// candidate is not memoized and re-surfaces on the next scan.
    /// The budget must serve the WHOLE wave —
    /// equal-split children that are individually too small exhaust
    /// together (size budgets to the batch, not to one claim chain).
    /// A claimant holding several leases keeps
    /// renewing only the one it is executing; the rest age out and are
    /// taken over per the ordinary rules — batch size should fit
    /// within lease / per-job execution time.
    pub async fn claim_many(
        &self,
        opts: &ClaimOptions,
        max: usize,
        budget: &mut OpBudget,
    ) -> Result<Vec<Claim>, Error> {
        struct Candidate {
            job_id: [u8; 16],
            shard: u16,
            version: Version,
        }
        let shard_prefix = format!("{}jobs/{:04x}/", self.root, opts.shard);
        let mut after: Option<Key> = None;
        let mut pending: std::collections::VecDeque<Candidate> = Default::default();
        let mut claims: Vec<Claim> = Vec::with_capacity(max.min(64));
        let mut scan_done = false;
        loop {
            // Probe waves until the batch fills or candidates run out.
            while !pending.is_empty() && claims.len() < max {
                let take = pending.len().min(max - claims.len());
                let wave: Vec<Candidate> = pending.drain(..take).collect();
                // Concurrent candidate probing: each candidate carries
                // its own child budget (the split conserves the total
                // work bound; unspent ops refund after the wave). On
                // immediately-ready stores join_all runs the futures
                // to completion in declaration order, so the fault
                // injector's positional op indexes stay stable.
                let mut children = budget.split(wave.len());
                let futs = wave
                    .iter()
                    .zip(children.iter_mut())
                    .map(|(c, b)| self.try_claim(c.job_id, c.shard, &c.version, opts, b));
                let results = futures::future::join_all(futs).await;
                let mut first_err: Option<Error> = None;
                let mut any_exhausted = false;
                for r in results {
                    match r {
                        Ok(Some(c)) => claims.push(c),
                        Ok(None) => {}
                        Err(Error::BudgetExhausted) => any_exhausted = true,
                        Err(e) => {
                            if first_err.is_none() {
                                first_err = Some(e);
                            }
                        }
                    }
                }
                budget.merge(&mut children);
                if claims.len() >= max {
                    return Ok(claims);
                }
                // Child errors surface before the budget boundary:
                // with the merge landing the parent at exactly zero,
                // an exhausted child's error must still propagate (the
                // zero check alone would swallow it as an empty
                // partial batch).
                if let Some(e) = first_err {
                    return if claims.is_empty() {
                        Err(e)
                    } else {
                        Ok(claims)
                    };
                }
                if any_exhausted {
                    return if claims.is_empty() {
                        Err(Error::BudgetExhausted)
                    } else {
                        Ok(claims)
                    };
                }
                // The scan's budget boundary is a partial batch, not
                // an error — the caller resumes with a fresh budget.
                if budget.max_ops == 0 {
                    return Ok(claims);
                }
            }
            if scan_done || claims.len() >= max {
                return Ok(claims);
            }
            if let Err(e) = budget.spend() {
                return if claims.is_empty() {
                    Err(e)
                } else {
                    Ok(claims)
                };
            }
            let page = match self.store.list(&shard_prefix, after.as_ref(), 1024).await {
                Ok(p) => p,
                Err(e) => {
                    let e: Error = e.into();
                    return if claims.is_empty() {
                        Err(e)
                    } else {
                        Ok(claims)
                    };
                }
            };
            if page.items.is_empty() {
                return Ok(claims);
            }
            for listing in &page.items {
                // A key that does not parse is skipped; the repair scan
                // owns quarantine.
                let Some(RelKey::Job { shard, job_id }) = listing
                    .key
                    .as_str()
                    .strip_prefix(&self.root)
                    .and_then(|s| s.parse().ok())
                else {
                    continue;
                };
                // Skip jobs this handle already proved terminal (same
                // jobs-entry version): the receipt/dead heads would
                // only re-confirm. A fresh handle pays the full scan.
                if self.is_memoized_terminal(shard, job_id, &listing.meta.version) {
                    continue;
                }
                pending.push_back(Candidate {
                    job_id,
                    shard,
                    version: listing.meta.version.clone(),
                });
            }
            match page.next_after {
                Some(k) => after = Some(k),
                None => scan_done = true,
            }
        }
    }

    fn hints_enabled(&self) -> bool {
        self.format.required_feature_bits & 2 != 0
    }

    /// Best-effort advisory tail-hint write (feature bit 2): body is
    /// the 8-byte big-endian generation. `known` is the hint state
    /// this handle last observed (from the claim gather): absent
    /// becomes a put-if-absent, a stale generation a single CAS, a
    /// current one a skip. Errors are swallowed — the hint is pure
    /// optimization; absence or staleness falls back to the
    /// authoritative chain listing.
    async fn write_tail_hint(
        &self,
        shard: u16,
        job_id: [u8; 16],
        generation: u64,
        known: &Option<(Version, u64)>,
        budget: &mut OpBudget,
    ) {
        if !self.hints_enabled() {
            return;
        }
        let rel = RelKey::Tail { shard, job_id };
        let abs = self.absolute(&rel);
        let body = Bytes::copy_from_slice(&generation.to_be_bytes());
        let digest: Digest = Sha256::digest(&body).into();
        match known {
            None => {
                if budget.spend().is_ok() {
                    let _ = self.store.put_if_absent(&abs, body, digest).await;
                }
            }
            Some((version, gen)) => {
                if *gen >= generation {
                    return; // already at least as new
                }
                if budget.spend().is_ok() {
                    let _ = self.store.cas(&abs, body, digest, version).await;
                }
            }
        }
    }

    /// Reads and decodes a generation's claim record: attempt and
    /// lease-duration bookkeeping for the expiry basis.
    async fn tail_record(
        &self,
        shard: u16,
        job_id: [u8; 16],
        generation: u64,
        budget: &mut OpBudget,
    ) -> Result<(u64, u64), Error> {
        budget.spend()?;
        let rel = RelKey::Claim {
            shard,
            job_id,
            generation: generation as u32,
        };
        let abs = self.absolute(&rel);
        let tag = self.tag_for(&rel);
        let obj = self.store.get(&abs, None).await?;
        match stowq_format::decode(&obj.body, &self.opts.queue_id, &tag)? {
            Record::Claim(c) => Ok((c.attempt, c.lease_duration_ns)),
            _ => Err(Error::Record("claim key holds a non-claim record".into())),
        }
    }

    /// The authoritative chain-tail discovery: pages the claims
    /// prefix and keeps the highest generation. O(pages) in chain
    /// depth — what the tail hint exists to avoid on deep chains.
    async fn list_tail(
        &self,
        claims_prefix: &str,
        budget: &mut OpBudget,
    ) -> Result<Option<(u64, Meta)>, Error> {
        let mut tail: Option<(u64, Meta)> = None;
        let mut after: Option<Key> = None;
        loop {
            budget.spend()?;
            let page = self.store.list(claims_prefix, after.as_ref(), 64).await?;
            for item in page.items {
                // Grammar violations in the chain are skipped; the
                // repair scan owns quarantine.
                if let Some(g) = parse_generation(&item.key) {
                    tail = Some((g, item.meta));
                }
            }
            match page.next_after {
                Some(k) => after = Some(k),
                None => return Ok(tail),
            }
        }
    }

    /// Renewal's hint refresh: observe then write (the renewal did
    /// not gather the hint state). Two ops, best-effort.
    async fn update_tail_hint(
        &self,
        shard: u16,
        job_id: [u8; 16],
        generation: u64,
        budget: &mut OpBudget,
    ) {
        if !self.hints_enabled() {
            return;
        }
        // Advisory: a failed observation just skips the refresh.
        if let Ok(known) = self.read_tail_hint(shard, job_id, budget).await {
            self.write_tail_hint(shard, job_id, generation, &known, budget)
                .await;
        }
    }

    /// Reads the advisory tail hint: the generation, or None when
    /// absent (fresh job, feature off on the writer, or lost write —
    /// every case falls back to the chain listing).
    async fn read_tail_hint(
        &self,
        shard: u16,
        job_id: [u8; 16],
        budget: &mut OpBudget,
    ) -> Result<Option<(Version, u64)>, Error> {
        let rel = RelKey::Tail { shard, job_id };
        let abs = self.absolute(&rel);
        budget.spend()?;
        match self.store.get(&abs, None).await {
            Ok(obj) => {
                // A body that is not exactly 8 bytes, or a generation
                // outside the protocol's u32 space, is corrupt-hint
                // garbage: the generation-0 sentinel routes the caller
                // to the listing fallback and marks the hint for
                // overwrite at commit (a range-valid body must never
                // alias a real generation through truncation).
                if let Ok(arr) = obj.body.as_ref().try_into() {
                    let gen = u64::from_be_bytes(arr);
                    if (1..=u32::MAX as u64).contains(&gen) {
                        return Ok(Some((obj.meta.version, gen)));
                    }
                }
                Ok(Some((obj.meta.version, 0)))
            }
            Err(StoreError::NotFound) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn try_claim(
        &self,
        job_id: [u8; 16],
        shard: u16,
        jobs_version: &Version,
        opts: &ClaimOptions,
        budget: &mut OpBudget,
    ) -> Result<Option<Claim>, Error> {
        // Readiness + tail evidence, gathered concurrently: the receipt
        // and dead probes and the chain listing are independent, so
        // they share one round-trip window. Only NotFound proves
        // terminal absence; any other error aborts the scan loudly
        // rather than delivering past an unknown terminal state. The
        // spends precede the join; on immediately-ready stores the ops
        // run in declaration order (the fault injector's positional
        // indexes are stable).
        budget.spend()?;
        budget.spend()?;
        budget.spend()?;
        let receipt_rel = RelKey::Receipt { shard, job_id };
        let dead_rel = RelKey::Dead { shard, job_id };
        let claims_prefix = format!("{}claims/{shard:04x}/{}/", self.root, hex(&job_id));
        let store = self.store.as_ref();
        let receipt_abs = self.absolute(&receipt_rel);
        let dead_abs = self.absolute(&dead_rel);
        // With tail hints enabled (feature bit 2) the chain listing is
        // replaced by the hint read: one GET of tails/<shard>/<job>
        // plus one GET of the hinted generation — O(1) in chain depth
        // where the listing is O(pages). A missing or stale hint
        // falls back to the authoritative listing inside the branch;
        // the put-if-absent claim fence catches anything the hint
        // missed, and that arm retries once on the listing's
        // evidence.
        let mut hint_state: Option<(Version, u64)> = None;
        let mut hint_rec: Option<Record> = None;
        let (receipt, dead, tail) =
            tokio::join!(store.head(&receipt_abs), store.head(&dead_abs), async {
                if !self.hints_enabled() {
                    return self.list_tail(claims_prefix.as_str(), budget).await;
                }
                match self.read_tail_hint(shard, job_id, budget).await? {
                    Some((version, gen)) if gen > 0 && gen <= u32::MAX as u64 => {
                        let rel = RelKey::Claim {
                            shard,
                            job_id,
                            generation: gen as u32,
                        };
                        let abs = self.absolute(&rel);
                        let tag = self.tag_for(&rel);
                        budget.spend()?;
                        match store.get(&abs, None).await {
                            Ok(obj) => {
                                match stowq_format::decode(&obj.body, &self.opts.queue_id, &tag) {
                                    Ok(r @ Record::Claim(_)) => {
                                        hint_state = Some((version, gen));
                                        hint_rec = Some(r);
                                        Ok(Some((gen, obj.meta)))
                                    }
                                    // A corrupt hint is advisory
                                    // garbage: fall back to the listing and
                                    // mark for overwrite.
                                    _ => {
                                        hint_state = Some((version, 0));
                                        self.list_tail(claims_prefix.as_str(), budget).await
                                    }
                                }
                            }
                            // Stale-forward (hint past the real tail):
                            // fall back to the listing. The hint is
                            // PROVEN garbage — mark it (gen 0) so the
                            // commit-time write overwrites rather than
                            // skipping as "current".
                            Err(StoreError::NotFound) => {
                                hint_state = Some((version, 0));
                                self.list_tail(claims_prefix.as_str(), budget).await
                            }
                            Err(e) => Err(e.into()),
                        }
                    }
                    // Corrupt hint (generation-0 sentinel from
                    // read_tail_hint, or an out-of-range body if that
                    // clamp ever changes): fall back to the listing
                    // and mark for overwrite at commit.
                    Some((version, _)) => {
                        hint_state = Some((version, 0));
                        self.list_tail(claims_prefix.as_str(), budget).await
                    }
                    // Absent hint: fresh-job shape, discover by listing.
                    None => self.list_tail(claims_prefix.as_str(), budget).await,
                }
            });
        match (receipt, dead) {
            (Err(StoreError::NotFound), Err(StoreError::NotFound)) => {}
            (Ok(_), _) | (_, Ok(_)) => {
                self.memoize_terminal(shard, job_id, jobs_version.clone());
                return Ok(None);
            }
            // Receipt absent: the dead probe's error class must
            // propagate verbatim — a transient transport failure on it
            // is not the receipt's NotFound.
            (Err(StoreError::NotFound), Err(e)) => return Err(e.into()),
            (Err(e), _) => return Err(e.into()),
        }
        let tail = tail?;

        let (mut tail_gen, mut tail_meta) = tail.unwrap_or((
            0,
            Meta {
                version: Version("0".into()),
                store_time_ns: 0,
                size: 0,
            },
        ));

        // Tail claim record for attempt bookkeeping and expiry basis.
        let (mut tail_attempt, mut tail_duration) = if tail_gen == 0 {
            (0, 0)
        } else if let Some(Record::Claim(c)) = &hint_rec {
            (c.attempt, c.lease_duration_ns)
        } else {
            self.tail_record(shard, job_id, tail_gen, budget).await?
        };

        // A stale-backward hint surfaces here as a rejected claim put
        // (the hinted G+1 already exists): re-discover the tail
        // authoritatively and retry once. The put-if-absent remains
        // the linearization point either way.
        let mut hint_used = hint_rec.is_some();
        loop {
            let expired = tail_gen == 0
                || opts.floor_ns
                    >= tail_meta
                        .store_time_ns
                        .saturating_add(tail_duration)
                        .saturating_add(self.opts.skew_guard_ns);

            // Backoff: the newest fail record for the tail generation gates
            // readiness.
            if tail_gen > 0 {
                budget.spend()?;
                let rel = RelKey::Fail {
                    shard,
                    job_id,
                    generation: tail_gen as u32,
                };
                let fail = match self.store.get(&self.absolute(&rel), None).await {
                    Ok(obj) => {
                        let tag = self.tag_for(&rel);
                        match stowq_format::decode(&obj.body, &self.opts.queue_id, &tag)? {
                            Record::Fail(f) => Some(f),
                            _ => {
                                return Err(Error::Record(
                                    "fail key holds a non-fail record".into(),
                                ))
                            }
                        }
                    }
                    Err(StoreError::NotFound) => None,
                    Err(e) => return Err(e.into()),
                };
                if let Some(f) = fail {
                    if opts.floor_ns < f.retry_not_before_ns {
                        return Ok(None);
                    }
                }
            }

            if !expired {
                return Ok(None);
            }

            // Attempt accounting: a takeover increments the tail's attempt,
            // whether the tail was itself a takeover or a continuation.
            let attempt = tail_attempt + 1;

            // Job record for maximum_attempts and payload reference.
            budget.spend()?;
            let job_rel = RelKey::Job { shard, job_id };
            let job_abs = self.absolute(&job_rel);
            let job_tag = self.tag_for(&job_rel);
            let job_obj = match self.store.get(&job_abs, None).await {
                Ok(obj) => obj,
                // GC may remove a terminal job between listing and read;
                // the candidate is gone, not errored.
                Err(StoreError::NotFound) => return Ok(None),
                Err(e) => return Err(e.into()),
            };
            let job = match stowq_format::decode(&job_obj.body, &self.opts.queue_id, &job_tag)? {
                Record::Job(j) => j,
                _ => return Err(Error::Record("job key holds a non-job record".into())),
            };
            if let Some(nb) = job.not_before_ns {
                if opts.floor_ns < nb {
                    return Ok(None);
                }
            }

            if attempt > job.maximum_attempts {
                // The exhaustion-dead writes a TERMINAL record before
                // any put-if-absent could fence the evidence — a
                // stale hint must not kill a live delivery here.
                // Re-verify on the authoritative tail; the retried
                // pass (hint_used now false) writes the dead only on
                // verified evidence.
                if hint_used {
                    let t = self
                        .list_tail(
                            &format!("{}claims/{shard:04x}/{}/", self.root, hex(&job_id)),
                            budget,
                        )
                        .await?;
                    let (g, m) = t.unwrap_or((
                        0,
                        Meta {
                            version: Version("0".into()),
                            store_time_ns: 0,
                            size: 0,
                        },
                    ));
                    tail_gen = g;
                    tail_meta = m;
                    let (a, d) = if tail_gen == 0 {
                        (0, 0)
                    } else {
                        self.tail_record(shard, job_id, tail_gen, budget).await?
                    };
                    tail_attempt = a;
                    tail_duration = d;
                    hint_used = false;
                    continue;
                }
                let dead = Record::Dead(DeadRecord {
                    job_id,
                    generation: tail_gen,
                    attempt: tail_attempt,
                    reason: 0x0004, // attempts_exhausted
                });
                let rel = RelKey::Dead { shard, job_id };
                let abs = self.absolute(&rel);
                let tag = self.tag_for(&rel);
                let body = Bytes::from(stowq_format::encode(&dead, &self.opts.queue_id, &tag));
                budget.spend()?;
                let body_digest: Digest = Sha256::digest(&body).into();
                if let Resolved::Committed = self
                    .put_resolving(&abs, body, body_digest, &dead, &rel, budget)
                    .await?
                {
                    self.write_termidx(stowq_keys::TermKind::Dead, shard, job_id, budget)
                        .await;
                }
                return Ok(None);
            }

            if tail_gen >= u32::MAX as u64 {
                return Err(Error::Internal("generation space exhausted".into()));
            }
            let worker_token = fresh_token();
            let record = Record::Claim(ClaimRecord {
                job_id,
                generation: tail_gen + 1,
                attempt,
                worker_id: self.opts.worker_id.clone(),
                worker_token,
                lease_duration_ns: opts.lease_duration_ns,
                continuation: false,
                basis: Some(ClaimBasis {
                    prev_store_time_ns: tail_meta.store_time_ns,
                    prev_duration_ns: tail_duration,
                    observed_watermark_ns: opts.floor_ns,
                }),
                prev_token: None,
            });
            let rel = RelKey::Claim {
                shard,
                job_id,
                generation: (tail_gen + 1) as u32,
            };
            let abs = self.absolute(&rel);
            let tag = self.tag_for(&rel);
            let body = Bytes::from(stowq_format::encode(&record, &self.opts.queue_id, &tag));
            let digest: Digest = Sha256::digest(&body).into();
            budget.spend()?;
            match self
                .put_resolving(&abs, body, digest, &record, &rel, budget)
                .await?
            {
                Resolved::Committed => {
                    budget.spend()?;
                    let meta = self.store.head(&abs).await?;
                    let payload = match (&job.payload_inline, &job.payload_key) {
                        (Some(b), _) => PayloadRef::Inline(Bytes::from(b.clone())),
                        (None, Some(k)) => PayloadRef::Detached {
                            key: Key::new(format!("{}{}", self.root, k)),
                            digest: job.payload_digest,
                            length: job.payload_length,
                        },
                        _ => return Err(Error::Record("job payload reference invalid".into())),
                    };
                    // Best-effort tail hint (feature bit 2): the gather's
                    // hint state makes this one op (put-if-absent when the
                    // hint was missing, a single CAS when stale, a skip
                    // when current).
                    self.write_tail_hint(shard, job_id, tail_gen + 1, &hint_state, budget)
                        .await;
                    // Best-effort lease index.
                    let expiry = meta.store_time_ns.saturating_add(opts.lease_duration_ns);
                    if let Some(bucket) =
                        stowq_math::bucket_number(expiry, self.format.lease_bucket_width_ns)
                    {
                        let idx = self.absolute(&RelKey::LeaseIndex {
                            bucket,
                            shard,
                            job_id,
                            generation: (tail_gen + 1) as u32,
                        });
                        budget.spend()?;
                        let _ = self
                            .store
                            .put_if_absent(&idx, Bytes::new(), Sha256::digest([]).into())
                            .await;
                    }
                    return Ok(Some(Claim {
                        job_id,
                        shard,
                        generation: tail_gen + 1,
                        attempt,
                        worker_token,
                        lease_duration_ns: opts.lease_duration_ns,
                        claim_store_time_ns: meta.store_time_ns,
                        payload,
                    }));
                }
                Resolved::Lost | Resolved::NotCommitted if hint_used => {
                    // The hint was stale-backward: the authoritative chain
                    // is longer than it said. Re-discover and retry once.
                    let t = self
                        .list_tail(
                            &format!("{}claims/{shard:04x}/{}/", self.root, hex(&job_id)),
                            budget,
                        )
                        .await?;
                    let (g, m) = t.unwrap_or((
                        0,
                        Meta {
                            version: Version("0".into()),
                            store_time_ns: 0,
                            size: 0,
                        },
                    ));
                    tail_gen = g;
                    tail_meta = m;
                    let (a, d) = if tail_gen == 0 {
                        (0, 0)
                    } else {
                        self.tail_record(shard, job_id, tail_gen, budget).await?
                    };
                    tail_attempt = a;
                    tail_duration = d;
                    hint_used = false;
                    continue;
                }
                Resolved::Lost | Resolved::NotCommitted => return Ok(None),
            }
        }
    }

    // ---------- renew ----------

    pub async fn renew(&self, claim: &Claim, budget: &mut OpBudget) -> Result<RenewOutcome, Error> {
        if claim.generation >= u32::MAX as u64 {
            return Err(Error::Internal("generation space exhausted".into()));
        }
        // A terminal job cannot extend its custody chain: without this
        // check a zombie renewal after an exhaustion-dead would append a
        // generation and enable a second terminal record.
        for rel in [
            RelKey::Receipt {
                shard: claim.shard,
                job_id: claim.job_id,
            },
            RelKey::Dead {
                shard: claim.shard,
                job_id: claim.job_id,
            },
        ] {
            budget.spend()?;
            match self.store.head(&self.absolute(&rel)).await {
                Ok(_) => return Ok(RenewOutcome::LeaseLost),
                Err(StoreError::NotFound) => {}
                Err(e) => return Err(e.into()),
            }
        }
        let record = Record::Claim(ClaimRecord {
            job_id: claim.job_id,
            generation: claim.generation + 1,
            attempt: claim.attempt,
            worker_id: self.opts.worker_id.clone(),
            worker_token: claim.worker_token,
            lease_duration_ns: claim.lease_duration_ns,
            continuation: true,
            basis: None,
            prev_token: Some(claim.worker_token),
        });
        let rel = RelKey::Claim {
            shard: claim.shard,
            job_id: claim.job_id,
            generation: (claim.generation + 1) as u32,
        };
        let abs = self.absolute(&rel);
        let tag = self.tag_for(&rel);
        let body = Bytes::from(stowq_format::encode(&record, &self.opts.queue_id, &tag));
        let digest: Digest = Sha256::digest(&body).into();
        budget.spend()?;
        match self
            .put_resolving(&abs, body, digest, &record, &rel, budget)
            .await?
        {
            Resolved::Committed => {
                budget.spend()?;
                let meta = self.store.head(&abs).await?;
                self.update_tail_hint(claim.shard, claim.job_id, claim.generation + 1, budget)
                    .await;
                Ok(RenewOutcome::Renewed(Claim {
                    job_id: claim.job_id,
                    shard: claim.shard,
                    generation: claim.generation + 1,
                    attempt: claim.attempt,
                    worker_token: claim.worker_token,
                    lease_duration_ns: claim.lease_duration_ns,
                    claim_store_time_ns: meta.store_time_ns,
                    payload: claim.payload.clone(),
                }))
            }
            Resolved::Lost | Resolved::NotCommitted => Ok(RenewOutcome::LeaseLost),
        }
    }

    // ---------- ack ----------

    /// Commits a store-resident effect through the commit rule (spec
    /// records.md): put-if-absent at `<root>outputs/<job-id>/<name>` —
    /// a deterministic key derived from `job_id`, never from attempt
    /// or generation — with the digest verified by the store (P7).
    /// Duplicate attempts converge on the first-wins bytes
    /// (`Converged`); different bytes already at the key are
    /// `OutputConflict` (the 0x0011 semantics, surfaced to the
    /// caller). Write outputs through this BEFORE the receipt:
    /// `ack_with_outputs` verifies and records them, so a receipt
    /// implies its outputs exist and are final.
    pub async fn commit_output(
        &self,
        claim: &Claim,
        name: &str,
        body: Bytes,
        budget: &mut OpBudget,
    ) -> Result<CommitOutcome, Error> {
        if !valid_output_name(name) {
            return Err(Error::Key(format!("invalid output name {name:?}")));
        }
        let digest: Digest = Sha256::digest(&body).into();
        let abs = Key::new(format!(
            "{}outputs/{}/{}",
            self.root,
            hex(&claim.job_id),
            name
        ));
        let out = CommittedOutput {
            key: abs.0.clone(),
            digest,
        };
        let mut transport_retries = 0;
        loop {
            budget.spend()?;
            match self.store.put_if_absent(&abs, body.clone(), digest).await {
                Ok(PutOutcome::Committed { .. }) => return Ok(CommitOutcome::Committed(out)),
                Ok(PutOutcome::Rejected) => {
                    // First-wins: the bytes already at the key decide.
                    let obj = self.read_retrying(&abs, budget).await?;
                    return classify_output(&obj, digest, out);
                }
                Err(StoreError::Transport(_)) => {
                    transport_retries += 1;
                    if transport_retries > RETRY_TRANSPORT_MAX {
                        return Err(Error::TransportExhausted);
                    }
                    continue;
                }
                Err(StoreError::OutcomeUnknown(_)) => {
                    // Present means committed (possibly by us before the
                    // response was lost); absent means retry the put.
                    match self.read_retrying(&abs, budget).await {
                        Ok(obj) => return classify_output(&obj, digest, out),
                        Err(Error::Store(StoreError::NotFound)) => {
                            transport_retries += 1;
                            if transport_retries > RETRY_TRANSPORT_MAX {
                                return Err(Error::TransportExhausted);
                            }
                            continue;
                        }
                        Err(e) => return Err(e),
                    }
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// Acknowledges, recording no outputs (the v1 shape; identical to
    /// `ack_with_outputs(&[])`).
    pub async fn ack(&self, claim: &Claim, budget: &mut OpBudget) -> Result<AckOutcome, Error> {
        self.ack_inner(claim, &[], budget).await
    }

    /// Acknowledges with committed outputs: each output is re-read and
    /// digest-verified before the receipt write, and the receipt
    /// records their digests. The commit rule ordering (outputs before
    /// receipt) is the caller's; this verifies the result.
    pub async fn ack_with_outputs(
        &self,
        claim: &Claim,
        outputs: &[CommittedOutput],
        budget: &mut OpBudget,
    ) -> Result<AckOutcome, Error> {
        self.ack_inner(claim, outputs, budget).await
    }

    async fn ack_inner(
        &self,
        claim: &Claim,
        outputs: &[CommittedOutput],
        budget: &mut OpBudget,
    ) -> Result<AckOutcome, Error> {
        // Dead-record refusal and payload re-verification are
        // independent reads: they share one round-trip window. A dead
        // record present means at most one terminal record per job
        // ever exists; the payload digest is re-verified before the
        // terminal write either way.
        budget.spend()?;
        budget.spend()?;
        let dead_abs = self.absolute(&RelKey::Dead {
            shard: claim.shard,
            job_id: claim.job_id,
        });
        let (dead, payload) = tokio::join!(
            self.store.head(&dead_abs),
            claim.payload(self.store.as_ref())
        );
        match dead {
            Ok(_) => return Ok(AckOutcome::SupersededByDead),
            Err(StoreError::NotFound) => {}
            Err(e) => return Err(e.into()),
        }
        let payload = payload?;
        let digest: Digest = Sha256::digest(&payload).into();

        // Commit rule: verify every recorded output exists with its
        // committed digest before the terminal write; a receipt
        // implies its outputs exist and are final. Each output must
        // live under THIS job's outputs prefix — a CommittedOutput
        // from another job must never verify here.
        let output_prefix = format!("{}outputs/{}/", self.root, hex(&claim.job_id));
        for out in outputs {
            if !out.key.starts_with(&output_prefix) {
                return Err(Error::Key(format!(
                    "output {} is not job {}'s output",
                    out.key,
                    hex(&claim.job_id)
                )));
            }
            match self.read_retrying(&Key::new(out.key.clone()), budget).await {
                Ok(obj) => {
                    let got: Digest = Sha256::digest(&obj.body).into();
                    if got != out.digest {
                        return Err(Error::OutputEvidenceMismatch(format!(
                            "output {} body does not match its committed digest",
                            out.key
                        )));
                    }
                }
                Err(Error::Store(StoreError::NotFound)) => {
                    return Err(Error::OutputEvidenceMismatch(format!(
                        "output {} absent at ack",
                        out.key
                    )));
                }
                Err(e) => return Err(e),
            }
        }

        let output_digests: Vec<Digest> = outputs.iter().map(|o| o.digest).collect();
        let record = Record::Receipt(ReceiptRecord {
            job_id: claim.job_id,
            generation: claim.generation,
            attempt: claim.attempt,
            worker_id: self.opts.worker_id.clone(),
            worker_token: claim.worker_token,
            payload_digest: digest,
            output_digests: output_digests.clone(),
        });
        let rel = RelKey::Receipt {
            shard: claim.shard,
            job_id: claim.job_id,
        };
        let abs = self.absolute(&rel);
        let tag = self.tag_for(&rel);
        let body = Bytes::from(stowq_format::encode(&record, &self.opts.queue_id, &tag));
        let body_digest: Digest = Sha256::digest(&body).into();
        budget.spend()?;
        match self
            .put_resolving(&abs, body, body_digest, &record, &rel, budget)
            .await?
        {
            Resolved::Committed => {
                self.write_termidx(
                    stowq_keys::TermKind::Receipt,
                    claim.shard,
                    claim.job_id,
                    budget,
                )
                .await;
                Ok(AckOutcome::Acked)
            }
            Resolved::Lost | Resolved::NotCommitted => {
                // A receipt exists: idempotent-verify its evidence
                // (identity is the key; generation, attempt, and the
                // re-verified payload digest must match this claim).
                let obj = self.read_retrying(&abs, budget).await?;
                let tag = self.tag_for(&rel);
                match stowq_format::decode(&obj.body, &self.opts.queue_id, &tag)? {
                    Record::Receipt(r)
                        if r.job_id == claim.job_id
                            && r.generation == claim.generation
                            && r.attempt == claim.attempt
                            && r.payload_digest == digest
                            && r.output_digests == output_digests =>
                    {
                        Ok(AckOutcome::AlreadyAcked)
                    }
                    Record::Receipt(_) => Err(Error::ReceiptEvidenceMismatch),
                    _ => Err(Error::Record(
                        "receipt key holds a non-receipt record".into(),
                    )),
                }
            }
        }
    }

    // ---------- nack ----------

    pub async fn nack(
        &self,
        claim: &Claim,
        reason: u64,
        floor_ns: u64,
        budget: &mut OpBudget,
    ) -> Result<(), Error> {
        // The policy hashes the attempt into its jitter stream, so a
        // u64 attempt beyond the u32 policy domain is clamped, never
        // wrapped (a wrapped attempt would shrink the backoff).
        let delay_ms = stowq_math::retry_delay_ms(
            &self.opts.queue_id,
            &claim.job_id,
            claim.attempt.min(u32::MAX as u64) as u32,
            &self.opts.retry,
        )
        .map_err(|e| Error::Internal(e.to_string()))?;
        let not_before = stowq_math::retry_not_before(floor_ns, delay_ms * 1_000_000)
            .ok_or_else(|| Error::Internal("retry_not_before overflow".into()))?;
        let record = Record::Fail(FailRecord {
            job_id: claim.job_id,
            generation: claim.generation,
            reason,
            attempt: claim.attempt,
            retry_not_before_ns: not_before,
        });
        let rel = RelKey::Fail {
            shard: claim.shard,
            job_id: claim.job_id,
            generation: claim.generation as u32,
        };
        let abs = self.absolute(&rel);
        let tag = self.tag_for(&rel);
        let body = Bytes::from(stowq_format::encode(&record, &self.opts.queue_id, &tag));
        let digest: Digest = Sha256::digest(&body).into();
        budget.spend()?;
        match self
            .put_resolving(&abs, body, digest, &record, &rel, budget)
            .await?
        {
            Resolved::Committed | Resolved::Lost => {}
            // NotCommitted only arises from an absent key after an
            // unknown outcome, which the resolver retries internally.
            Resolved::NotCommitted => return Err(Error::Internal("nack not committed".into())),
        }
        // Best-effort delayed index.
        if let Some(bucket) =
            stowq_math::bucket_number(not_before, self.format.delayed_bucket_width_ns)
        {
            let idx = self.absolute(&RelKey::DelayIndex {
                bucket,
                shard: claim.shard,
                job_id: claim.job_id,
            });
            budget.spend()?;
            let _ = self
                .store
                .put_if_absent(&idx, Bytes::new(), Sha256::digest([]).into())
                .await;
        }
        Ok(())
    }

    // ---------- bury ----------

    pub async fn bury(
        &self,
        claim: &Claim,
        reason: u64,
        budget: &mut OpBudget,
    ) -> Result<BuryOutcome, Error> {
        // A receipt terminalized the job first; refuse so at most one
        // terminal record per job ever exists — the symmetric guard to
        // ack's dead check.
        budget.spend()?;
        match self
            .store
            .head(&self.absolute(&RelKey::Receipt {
                shard: claim.shard,
                job_id: claim.job_id,
            }))
            .await
        {
            Ok(_) => return Ok(BuryOutcome::SupersededByReceipt),
            Err(StoreError::NotFound) => {}
            Err(e) => return Err(e.into()),
        }
        let record = Record::Dead(DeadRecord {
            job_id: claim.job_id,
            generation: claim.generation,
            attempt: claim.attempt,
            reason,
        });
        let rel = RelKey::Dead {
            shard: claim.shard,
            job_id: claim.job_id,
        };
        let abs = self.absolute(&rel);
        let tag = self.tag_for(&rel);
        let body = Bytes::from(stowq_format::encode(&record, &self.opts.queue_id, &tag));
        let digest: Digest = Sha256::digest(&body).into();
        budget.spend()?;
        match self
            .put_resolving(&abs, body, digest, &record, &rel, budget)
            .await?
        {
            Resolved::Committed => {
                self.write_termidx(
                    stowq_keys::TermKind::Dead,
                    claim.shard,
                    claim.job_id,
                    budget,
                )
                .await;
                Ok(BuryOutcome::Buried)
            }
            Resolved::Lost => {
                // First-wins: an existing dead record with this claim's
                // evidence (identity is the key; generation and attempt
                // must match) is success. Any other dead record is a
                // conflicting-terminal finding.
                let obj = self.read_retrying(&abs, budget).await?;
                let tag = self.tag_for(&rel);
                match stowq_format::decode(&obj.body, &self.opts.queue_id, &tag)? {
                    Record::Dead(d)
                        if d.generation == claim.generation && d.attempt == claim.attempt =>
                    {
                        Ok(BuryOutcome::Buried)
                    }
                    _ => Err(Error::Record("dead key holds conflicting evidence".into())),
                }
            }
            Resolved::NotCommitted => Err(Error::Internal("bury not committed".into())),
        }
    }

    /// Best-effort terminal index entry; drives GC ordering only.
    async fn write_termidx(
        &self,
        kind: stowq_keys::TermKind,
        shard: u16,
        job_id: [u8; 16],
        budget: &mut OpBudget,
    ) {
        if budget.spend().is_err() {
            return;
        }
        // The bucket derives from the handle's floor (a proven lower
        // bound on the terminal record's store time) instead of a
        // read-back of the just-written record: on the S3 family a PUT
        // returns no store time, so the read-back cost a round trip
        // per terminal write. Within the floor staleness window this
        // is a cache hit (zero ops). The bucket may under-estimate by
        // up to the window, making a graph GC-eligible marginally
        // early; retention is policy, and repair regenerates termidx
        // from authoritative times regardless.
        let Ok(floor) = self.establish_floor(budget).await else {
            return;
        };
        if let Some(bucket) = stowq_math::bucket_number(floor, self.format.terminal_bucket_width_ns)
        {
            let idx = self.absolute(&RelKey::TermIndex {
                bucket,
                kind,
                shard,
                job_id,
            });
            if budget.spend().is_ok() {
                let _ = self
                    .store
                    .put_if_absent(&idx, Bytes::new(), Sha256::digest([]).into())
                    .await;
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Resolved {
    Committed,
    /// Someone else's record holds the key.
    Lost,
    /// Resolution proved the write never happened.
    NotCommitted,
}

fn parse_generation(key: &Key) -> Option<u64> {
    let segment = key.as_str().rsplit('/').next()?;
    if segment.len() != 8 || !segment.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(segment, 16).ok()
}

// ---------- Sweeping, repair, and GC ----------

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SweepReport {
    /// Index entries examined.
    pub entries: usize,
    /// Expired leases found by authoritative re-evaluation. The sweep
    /// prunes their index entries; the jobs become claimable through
    /// the ordinary shard scan (this is the doorbell-less posture; a
    /// notification plane would wake workers instead).
    pub reclaimed: usize,
    /// Due delayed jobs found by authoritative re-evaluation, same
    /// posture as reclaimed.
    pub promoted: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GcReport {
    /// Terminal job graphs fully deleted.
    pub jobs_deleted: usize,
    /// Orphan claim records collected (GC-vs-claim race artifacts).
    pub claim_orphans_deleted: usize,
    /// Clock beacons deleted.
    pub beacons_deleted: usize,
    /// Orphan payloads deleted past the enqueue horizon.
    pub orphans_deleted: usize,
}

/// Shard depth: object counts per plane (monitoring probe).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DepthReport {
    pub jobs: u64,
    pub claims: u64,
    pub receipts: u64,
    pub dead: u64,
}

/// One repair-scan finding: a violation with its quarantine reason
/// code (spec reasons.md). Findings are reported to the caller; writing
/// quarantine objects awaits a v1.1 record-schema decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub kind: FindingKind,
    /// The offending object's absolute key.
    pub key: String,
    pub reason: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingKind {
    /// A key under an authoritative prefix that does not parse.
    KeyGrammar,
    /// A record that fails digest, envelope, or field decoding.
    RecordCorrupt,
    /// A claim chain whose job record is absent.
    ClaimWithoutJob,
    /// A takeover whose basis contradicts the store-time record.
    InadmissibleClaim,
    /// Both a receipt and a dead record exist for one job.
    DuplicateTerminal,
    /// A claim chain missing generations (a gap or a nonzero head).
    ChainGap,
    /// A detached job whose payload object is absent (0x0014).
    PayloadMissing,
}

/// Deterministic quarantine qid (spec records.md, Quarantine record):
/// first 16 bytes of a domain-separated hash over the queue, the
/// offending RELATIVE key, and the reason.
fn quarantine_qid(queue_id: &[u8; 16], rel_key: &str, reason: u64) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(b"StowQ-1-qid\0");
    hasher.update(queue_id);
    hasher.update(rel_key.as_bytes());
    hasher.update(reason.to_be_bytes());
    hasher.finalize()[..16].try_into().unwrap()
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RepairReport {
    pub shards_scanned: u32,
    pub jobs_scanned: usize,
    pub claim_chains_scanned: usize,
    pub indexes_regenerated: usize,
    pub findings: Vec<Finding>,
}

impl Queue {
    /// Repair scan (spec recovery.md): shard-by-shard, regenerate
    /// missing advisory index entries (`delayed/`, `leases/`, `termidx/`)
    /// and report grammar, corruption, and impossible-state findings.
    /// Idempotent and safely concurrent: every regeneration is a
    /// put-if-absent against an absence just proven by HEAD. Resumable:
    /// the report's caller persists the returned next-unscanned shard
    /// as its cursor; a shard's scan leaves no partial state a rerun
    /// would misread. Stops before the budget runs dry mid-shard.
    pub async fn repair_scan(
        &self,
        start_shard: u16,
        budget: &mut OpBudget,
    ) -> Result<(RepairReport, Option<u16>), Error> {
        let shard_count = self.format.shard_count;
        let mut report = RepairReport::default();
        // u32 counter: shard_count may be 65536, where a u16 counter
        // overflows on the final increment.
        let mut next = start_shard as u32;
        while next < shard_count {
            self.repair_shard(next as u16, &mut report, budget).await?;
            report.shards_scanned += 1;
            next += 1;
            if budget.max_ops <= 4 {
                break;
            }
        }
        let resume = (next < shard_count).then_some(next as u16);
        Ok((report, resume))
    }

    /// Expired-lease sweep (spec recovery.md): walk `leases/<b>/` for
    /// buckets at or below the floor bucket, in ascending order; for
    /// each entry, re-evaluate the authoritative tail and delete the
    /// index entry. The index is advisory; correctness never reads it,
    /// and a missing entry hides nothing forever (repair scan).
    pub async fn sweep_expired_leases(
        &self,
        floor_ns: u64,
        budget: &mut OpBudget,
    ) -> Result<SweepReport, Error> {
        let width = self.format.lease_bucket_width_ns;
        let Some(max_bucket) = stowq_math::bucket_number(floor_ns, width) else {
            return Err(Error::Internal("zero lease width".into()));
        };
        let mut report = SweepReport::default();
        // Iterate buckets ascending from 0 is unbounded; the index only
        // ever holds buckets <= current, so walk from the smallest
        // present bucket: list the whole leases/ prefix and filter.
        let prefix = format!("{}leases/", self.root);
        let mut after: Option<Key> = None;
        loop {
            budget.spend()?;
            let page = self.store.list(&prefix, after.as_ref(), 64).await?;
            if page.items.is_empty() {
                break;
            }
            for item in &page.items {
                // entries/<bucket>/<shard>/<job>.<generation>
                let rel_str = item.key.as_str().strip_prefix(&self.root).unwrap_or("");
                let mut parts = rel_str.strip_prefix("leases/").unwrap_or("").splitn(2, '/');
                let bucket_str = parts.next().unwrap_or("");
                let rest = parts.next().unwrap_or("");
                let Ok(bucket) = u64::from_str_radix(bucket_str, 16) else {
                    continue; // repair owns quarantine
                };
                if bucket > max_bucket {
                    continue;
                }
                report.entries += 1;
                // Authoritative re-evaluation: find the job's tail.
                let Some((shard, job_id, _gen)) = parse_lease_entry(rest) else {
                    continue;
                };
                if self
                    .lease_reclaimable(shard, job_id, floor_ns, budget)
                    .await?
                {
                    report.reclaimed += 1;
                }
                budget.spend()?;
                let _ = self.store.delete(&item.key).await;
            }
            match page.next_after {
                Some(k) => after = Some(k),
                None => break,
            }
        }
        Ok(report)
    }

    /// Delayed sweep (spec recovery.md): walk `delayed/<b>/` for due
    /// buckets; verify the authoritative not_before; delete the entry.
    pub async fn sweep_delayed(
        &self,
        floor_ns: u64,
        budget: &mut OpBudget,
    ) -> Result<SweepReport, Error> {
        let width = self.format.delayed_bucket_width_ns;
        let Some(max_bucket) = stowq_math::bucket_number(floor_ns, width) else {
            return Err(Error::Internal("zero delayed width".into()));
        };
        let mut report = SweepReport::default();
        let prefix = format!("{}delayed/", self.root);
        let mut after: Option<Key> = None;
        loop {
            budget.spend()?;
            let page = self.store.list(&prefix, after.as_ref(), 64).await?;
            if page.items.is_empty() {
                break;
            }
            for item in &page.items {
                let rel_str = item.key.as_str().strip_prefix(&self.root).unwrap_or("");
                let mut parts = rel_str
                    .strip_prefix("delayed/")
                    .unwrap_or("")
                    .splitn(2, '/');
                let bucket_str = parts.next().unwrap_or("");
                let rest = parts.next().unwrap_or("");
                let Ok(bucket) = u64::from_str_radix(bucket_str, 16) else {
                    continue;
                };
                if bucket > max_bucket {
                    continue;
                }
                report.entries += 1;
                let Some((shard, job_id)) = parse_delay_entry(rest) else {
                    continue;
                };
                // Authoritative gate: job not_before and any tail fail's
                // retry_not_before must have passed.
                if self.job_promotable(shard, job_id, floor_ns, budget).await? {
                    report.promoted += 1;
                }
                budget.spend()?;
                let _ = self.store.delete(&item.key).await;
            }
            match page.next_after {
                Some(k) => after = Some(k),
                None => break,
            }
        }
        Ok(report)
    }

    async fn lease_reclaimable(
        &self,
        shard: u16,
        job_id: [u8; 16],
        floor_ns: u64,
        budget: &mut OpBudget,
    ) -> Result<bool, Error> {
        // Terminal jobs are not reclaimable.
        for rel in [
            RelKey::Receipt { shard, job_id },
            RelKey::Dead { shard, job_id },
        ] {
            budget.spend()?;
            match self.store.head(&self.absolute(&rel)).await {
                Ok(_) => return Ok(false),
                Err(StoreError::NotFound) => {}
                Err(e) => return Err(e.into()),
            }
        }
        // Tail expiry: read the claim chain's last generation.
        let (gen, meta, duration) = self.claim_tail(shard, job_id, budget).await?;
        if gen == 0 {
            return Ok(false); // nothing held
        }
        Ok(floor_ns
            >= meta
                .store_time_ns
                .saturating_add(duration)
                .saturating_add(self.opts.skew_guard_ns))
    }

    async fn job_promotable(
        &self,
        shard: u16,
        job_id: [u8; 16],
        floor_ns: u64,
        budget: &mut OpBudget,
    ) -> Result<bool, Error> {
        budget.spend()?;
        let job_rel = RelKey::Job { shard, job_id };
        let job = match self.store.get(&self.absolute(&job_rel), None).await {
            Ok(obj) => {
                let tag = self.tag_for(&job_rel);
                match stowq_format::decode(&obj.body, &self.opts.queue_id, &tag)? {
                    Record::Job(j) => j,
                    _ => return Ok(false),
                }
            }
            Err(StoreError::NotFound) => return Ok(false),
            Err(e) => return Err(e.into()),
        };
        if let Some(nb) = job.not_before_ns {
            if floor_ns < nb {
                return Ok(false);
            }
        }
        // Backoff gate at the tail generation.
        let (gen, _meta, _duration) = self.claim_tail(shard, job_id, budget).await?;
        if gen > 0 {
            budget.spend()?;
            let rel = RelKey::Fail {
                shard,
                job_id,
                generation: gen as u32,
            };
            match self.store.get(&self.absolute(&rel), None).await {
                Ok(obj) => {
                    let tag = self.tag_for(&rel);
                    if let Record::Fail(f) =
                        stowq_format::decode(&obj.body, &self.opts.queue_id, &tag)?
                    {
                        if floor_ns < f.retry_not_before_ns {
                            return Ok(false);
                        }
                    }
                }
                Err(StoreError::NotFound) => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(true)
    }

    /// The tail of the claim chain: (generation, meta, lease_duration).
    async fn claim_tail(
        &self,
        shard: u16,
        job_id: [u8; 16],
        budget: &mut OpBudget,
    ) -> Result<(u64, Meta, u64), Error> {
        let prefix = format!("{}claims/{shard:04x}/{}/", self.root, hex(&job_id));
        let mut after: Option<Key> = None;
        let mut tail: Option<(u64, Meta)> = None;
        loop {
            budget.spend()?;
            let page = self.store.list(&prefix, after.as_ref(), 64).await?;
            for item in page.items {
                if let Some(g) = parse_generation(&item.key) {
                    tail = Some((g, item.meta));
                }
            }
            match page.next_after {
                Some(k) => after = Some(k),
                None => break,
            }
        }
        match tail {
            None => Ok((0, empty_meta(), 0)),
            Some((gen, meta)) => {
                budget.spend()?;
                let rel = RelKey::Claim {
                    shard,
                    job_id,
                    generation: gen as u32,
                };
                let obj = match self.store.get(&self.absolute(&rel), None).await {
                    Ok(obj) => obj,
                    Err(StoreError::NotFound) => return Ok((gen, meta, 0)),
                    Err(e) => return Err(e.into()),
                };
                let tag = self.tag_for(&rel);
                match stowq_format::decode(&obj.body, &self.opts.queue_id, &tag)? {
                    Record::Claim(c) => Ok((gen, meta, c.lease_duration_ns)),
                    _ => Ok((gen, meta, 0)),
                }
            }
        }
    }

    /// Retention GC (spec recovery.md): iterate `termidx/`, verify
    /// against the authoritative terminal key, delete the graph in
    /// strict order (indexes, fails, claims, payloads, jobs, terminal
    /// last) when the terminal record's store time is older than
    /// `retention_ns` relative to `now_ns`. Stale beacons are collected,
    /// and orphan payloads (a payload whose job record is absent, older
    /// than `orphan_horizon_ns` relative to `now_ns` — the crash window
    /// between payload PUT and job-record PUT) are deleted.
    pub async fn gc(
        &self,
        now_ns: u64,
        retention_ns: u64,
        orphan_horizon_ns: u64,
        budget: &mut OpBudget,
    ) -> Result<GcReport, Error> {
        let mut report = GcReport::default();
        let cutoff = now_ns.saturating_sub(retention_ns);
        let orphan_cutoff = now_ns.saturating_sub(orphan_horizon_ns);

        // Orphan payloads: the payload key carries the job id; the job
        // record lives at jobs/<shard>/<job> with the shard derived
        // from the queue identity. Referenced payloads are never
        // touched; a job record present at any later time wins over
        // the horizon (the enqueue is in flight, not orphaned).
        let payload_prefix = format!("{}payloads/", self.root);
        let mut after: Option<Key> = None;
        loop {
            budget.spend()?;
            let page = self.store.list(&payload_prefix, after.as_ref(), 64).await?;
            if page.items.is_empty() {
                break;
            }
            for item in &page.items {
                if item.meta.store_time_ns >= orphan_cutoff {
                    continue;
                }
                let rel = item
                    .key
                    .as_str()
                    .strip_prefix(&self.root)
                    .and_then(|s| s.parse().ok());
                let Some(RelKey::Payload { job_id, .. }) = rel else {
                    continue; // repair owns quarantine findings
                };
                let shard = compute_shard(&self.opts.queue_id, &job_id, self.format.shard_count);
                budget.spend()?;
                match self
                    .store
                    .head(&self.absolute(&RelKey::Job { shard, job_id }))
                    .await
                {
                    Ok(_) => {}
                    Err(StoreError::NotFound) => {
                        // Re-head the payload: same ABA discipline as
                        // the claims pass (a re-enqueue with the same
                        // content recreates the content-addressed key).
                        budget.spend()?;
                        match self.store.head(&item.key).await {
                            Ok(now) if now.store_time_ns == item.meta.store_time_ns => {
                                budget.spend()?;
                                let _ = self.store.delete(&item.key).await;
                                report.orphans_deleted += 1;
                            }
                            Ok(_) => {}
                            Err(StoreError::NotFound) => {
                                report.orphans_deleted += 1;
                            }
                            Err(e) => return Err(e.into()),
                        }
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            match page.next_after {
                Some(k) => after = Some(k),
                None => break,
            }
        }

        // Orphan claims: a claimant can pass every check and commit a
        // claim while GC concurrently deletes the terminal graph (the
        // race window is job-read to claim-put); the surviving claim
        // references a deleted job and nothing else would collect it.
        // Same horizon discipline as payloads: old enough to predate
        // any in-flight enqueue, and the job record is absent NOW.
        let claims_prefix = format!("{}claims/", self.root);
        let mut after: Option<Key> = None;
        loop {
            budget.spend()?;
            let page = self.store.list(&claims_prefix, after.as_ref(), 64).await?;
            if page.items.is_empty() {
                break;
            }
            for item in &page.items {
                if item.meta.store_time_ns >= orphan_cutoff {
                    continue;
                }
                let rel = item
                    .key
                    .as_str()
                    .strip_prefix(&self.root)
                    .and_then(|s| s.parse().ok());
                let Some(RelKey::Claim { shard, job_id, .. }) = rel else {
                    continue; // repair owns quarantine findings
                };
                budget.spend()?;
                match self
                    .store
                    .head(&self.absolute(&RelKey::Job { shard, job_id }))
                    .await
                {
                    Ok(_) => {}
                    Err(StoreError::NotFound) => {
                        // Re-head the claim itself: the listing was
                        // check-then-act, and a concurrent re-enqueue
                        // at a colliding generation can recreate the
                        // exact key between the listing and this
                        // delete. The store time distinguishes them
                        // (a fresh claim writes a later time).
                        budget.spend()?;
                        match self.store.head(&item.key).await {
                            Ok(now) if now.store_time_ns == item.meta.store_time_ns => {
                                budget.spend()?;
                                let _ = self.store.delete(&item.key).await;
                                report.claim_orphans_deleted += 1;
                            }
                            Ok(_) => {} // recreated: a live claim now
                            Err(StoreError::NotFound) => {
                                report.claim_orphans_deleted += 1;
                            }
                            Err(e) => return Err(e.into()),
                        }
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            match page.next_after {
                Some(k) => after = Some(k),
                None => break,
            }
        }

        // Beacons: metadata is tiny; collect those older than 10x the
        // floor staleness window.
        let beacon_cutoff = now_ns.saturating_sub(FLOOR_STALENESS_NS.saturating_mul(10));
        let beacon_prefix = format!("{}meta/clock/", self.root);
        let mut after: Option<Key> = None;
        loop {
            budget.spend()?;
            let page = self.store.list(&beacon_prefix, after.as_ref(), 64).await?;
            if page.items.is_empty() {
                break;
            }
            for item in &page.items {
                if item.meta.store_time_ns < beacon_cutoff {
                    budget.spend()?;
                    let _ = self.store.delete(&item.key).await;
                    report.beacons_deleted += 1;
                }
            }
            match page.next_after {
                Some(k) => after = Some(k),
                None => break,
            }
        }

        // Terminal graphs, oldest bucket first: termidx keys sort by
        // bucket in hex, which is not numeric order; walk all and
        // filter by the authoritative terminal time.
        let term_prefix = format!("{}termidx/", self.root);
        let mut after: Option<Key> = None;
        loop {
            budget.spend()?;
            let page = self.store.list(&term_prefix, after.as_ref(), 64).await?;
            if page.items.is_empty() {
                break;
            }
            for item in &page.items {
                // termidx/<bucket>/<kind>/<shard>/<job>
                let rel_str = item.key.as_str().strip_prefix(&self.root).unwrap_or("");
                let Some((kind, shard, job_id)) = parse_term_entry(rel_str) else {
                    continue;
                };
                let terminal_rel = match kind {
                    'r' => RelKey::Receipt { shard, job_id },
                    _ => RelKey::Dead { shard, job_id },
                };
                let terminal_abs = self.absolute(&terminal_rel);
                budget.spend()?;
                let meta = match self.store.head(&terminal_abs).await {
                    Ok(meta) => meta,
                    // Only NotFound proves the authoritative record is
                    // gone; other errors abort loudly rather than
                    // pruning a live graph's index entry.
                    Err(StoreError::NotFound) => {
                        budget.spend()?;
                        let _ = self.store.delete(&item.key).await;
                        continue;
                    }
                    Err(e) => return Err(e.into()),
                };
                if meta.store_time_ns >= cutoff {
                    continue; // still within retention
                }
                if self
                    .delete_terminal_graph(shard, job_id, &terminal_rel, &item.key, budget)
                    .await?
                {
                    report.jobs_deleted += 1;
                }
            }
            match page.next_after {
                Some(k) => after = Some(k),
                None => break,
            }
        }
        Ok(report)
    }

    /// Deletes one job's terminal graph in the strict spec order.
    #[allow(clippy::too_many_arguments)]
    async fn delete_terminal_graph(
        &self,
        shard: u16,
        job_id: [u8; 16],
        terminal_rel: &RelKey,
        index_key: &Key,
        budget: &mut OpBudget,
    ) -> Result<bool, Error> {
        let jhex = hex(&job_id);
        // Advisory indexes first.
        let prefixes = [
            format!("{}leases/", self.root),
            format!("{}delayed/", self.root),
        ];
        for prefix in prefixes {
            // Only the exact job's entries matter; scanning prefixes
            // would be unbounded. Index entries for this job are
            // addressable by shard: leases/<b>/<shard>/<job>.<g> and
            // delayed/<b>/<shard>/<job>. List the shard's slice per
            // bucket is not addressable; instead scan the job slice via
            // the shard: too broad. Practical approach: delete the
            // known-shard entries by listing each prefix filtered by
            // shard segment and matching job id.
            let mut after: Option<Key> = None;
            loop {
                budget.spend()?;
                let page = self.store.list(&prefix, after.as_ref(), 64).await?;
                if page.items.is_empty() {
                    break;
                }
                for item in &page.items {
                    if item.key.as_str().contains(&format!("/{shard:04x}/{jhex}")) {
                        budget.spend()?;
                        let _ = self.store.delete(&item.key).await;
                    }
                }
                match page.next_after {
                    Some(k) => after = Some(k),
                    None => break,
                }
            }
        }
        // termidx entry.
        budget.spend()?;
        let _ = self.store.delete(index_key).await;
        // Tail hint (feature bit 2): addressed directly, best-effort.
        budget.spend()?;
        let _ = self
            .store
            .delete(&self.absolute(&RelKey::Tail { shard, job_id }))
            .await;
        // Fails, claims.
        for prefix in [
            format!("{}fails/{shard:04x}/{jhex}/", self.root),
            format!("{}claims/{shard:04x}/{jhex}/", self.root),
        ] {
            let mut after: Option<Key> = None;
            loop {
                budget.spend()?;
                let page = self.store.list(&prefix, after.as_ref(), 64).await?;
                if page.items.is_empty() {
                    break;
                }
                for item in &page.items {
                    budget.spend()?;
                    let _ = self.store.delete(&item.key).await;
                }
                match page.next_after {
                    Some(k) => after = Some(k),
                    None => break,
                }
            }
        }
        // Payloads are content-addressed: payloads/<job>/<digest>.
        let payload_prefix = format!("{}payloads/{jhex}/", self.root);
        let mut after: Option<Key> = None;
        loop {
            budget.spend()?;
            let page = self.store.list(&payload_prefix, after.as_ref(), 64).await?;
            if page.items.is_empty() {
                break;
            }
            for item in &page.items {
                budget.spend()?;
                let _ = self.store.delete(&item.key).await;
            }
            match page.next_after {
                Some(k) => after = Some(k),
                None => break,
            }
        }
        // Job record.
        budget.spend()?;
        let _ = self
            .store
            .delete(&self.absolute(&RelKey::Job { shard, job_id }))
            .await;
        // Terminal record last: the tombstone.
        budget.spend()?;
        let _ = self.store.delete(&self.absolute(terminal_rel)).await;
        Ok(true)
    }

    // ---------- Repair scan ----------

    /// Writes one finding as a durable quarantine record on v1.1
    /// queues (FORMAT feature bit 1). Deterministic key and body per
    /// (queue, source, reason), so independent auditors converge
    /// byte-identically; put-if-absent with outcome resolution. On v1
    /// queues this is a no-op — findings are report-only there.
    async fn write_quarantine(
        &self,
        rel_key: &str,
        reason: u64,
        observed_store_ns: u64,
        detail: Option<u64>,
        budget: &mut OpBudget,
    ) -> Result<(), Error> {
        if self.format.required_feature_bits & 1 == 0 {
            return Ok(());
        }
        let qid = quarantine_qid(&self.opts.queue_id, rel_key, reason);
        let bucket =
            stowq_math::bucket_number(observed_store_ns, self.format.terminal_bucket_width_ns)
                .ok_or_else(|| Error::Internal("zero terminal width".into()))?;
        let rel = RelKey::Quarantine { bucket, qid };
        let abs = self.absolute(&rel);
        let tag = self.tag_for(&rel);
        let record = Record::Quarantine(stowq_format::QuarantineRecord {
            qid,
            source_key: rel_key.to_string(),
            reason,
            observed_store_ns,
            detail,
        });
        let body = Bytes::from(stowq_format::encode(&record, &self.opts.queue_id, &tag));
        let digest: Digest = Sha256::digest(&body).into();
        self.put_bytes_resolving(&abs, body, digest, budget).await
    }

    /// Lists a prefix fully, spending the budget per page.
    async fn list_authoritative(
        &self,
        prefix: &str,
        budget: &mut OpBudget,
    ) -> Result<Vec<stowq_store::Listing>, Error> {
        let mut out = Vec::new();
        let mut after: Option<Key> = None;
        loop {
            budget.spend()?;
            let page = self.store.list(prefix, after.as_ref(), 64).await?;
            if page.items.is_empty() {
                break;
            }
            out.extend(page.items);
            match page.next_after {
                Some(k) => after = Some(k),
                None => break,
            }
        }
        Ok(out)
    }

    /// Ensures an advisory index entry exists: present means done;
    /// absent means put-if-absent (a racing repairer's identical entry
    /// is benign). Returns true when the entry was missing.
    async fn ensure_index(&self, idx: &Key, budget: &mut OpBudget) -> Result<bool, Error> {
        match self.store.head(idx).await {
            Ok(_) => Ok(false),
            Err(StoreError::NotFound) => {
                budget.spend()?;
                let _ = self
                    .store
                    .put_if_absent(idx, Bytes::new(), Sha256::digest([]).into())
                    .await;
                Ok(true)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Records an inadmissible claim finding and writes its quarantine
    /// object (0x0010).
    async fn quarantine_inadmissible(
        &self,
        shard: u16,
        job_id: [u8; 16],
        chain: &[(u64, Meta)],
        report: &mut RepairReport,
        budget: &mut OpBudget,
        gen: u64,
    ) -> Result<(), Error> {
        let rel = RelKey::Claim {
            shard,
            job_id,
            generation: gen as u32,
        };
        report.findings.push(Finding {
            kind: FindingKind::InadmissibleClaim,
            key: self.absolute(&rel).0.clone(),
            reason: 0x0010,
        });
        let observed = chain
            .iter()
            .find(|(g, _)| *g == gen)
            .map(|(_, m)| m.store_time_ns)
            .unwrap_or(0);
        self.write_quarantine(&rel.to_string(), 0x0010, observed, Some(gen), budget)
            .await?;
        Ok(())
    }

    /// Full-chain admissibility audit (spec records.md, Admissibility):
    /// decodes every generation and verifies the type-appropriate
    /// evidence against the store-time record — a takeover's basis must
    /// name the previous generation's actual store time and lease
    /// duration with prev_store_time + prev_duration <= observed
    /// watermark; a continuation's worker_id and prev_token must match
    /// the previous generation. Generation gaps are impossible-state
    /// findings. Undecodable records are reported and skipped; the
    /// chain still audits around them. Costs one GET per generation —
    /// budget exhaustion propagates and the shard reruns idempotently.
    /// Returns (tail_generation, tail_meta, tail_lease_duration); the
    /// duration is 0 when the tail record is unavailable.
    async fn audit_claim_chain(
        &self,
        shard: u16,
        job_id: [u8; 16],
        chain: &[(u64, Meta)],
        report: &mut RepairReport,
        budget: &mut OpBudget,
    ) -> Result<(u64, Meta, u64), Error> {
        // Contiguity: generations must run 1..=tail with no gaps (a gap
        // is a missing object — foreign deletion or corruption).
        let first = chain.first().expect("chain is nonempty").0;
        for pair in chain.windows(2) {
            if pair[1].0 != pair[0].0 + 1 {
                let missing = pair[0].0 + 1;
                report.findings.push(Finding {
                    kind: FindingKind::ChainGap,
                    key: self
                        .absolute(&RelKey::Claim {
                            shard,
                            job_id,
                            generation: missing as u32,
                        })
                        .0
                        .clone(),
                    reason: 0x0015,
                });
                let rel = RelKey::Claim {
                    shard,
                    job_id,
                    generation: missing as u32,
                };
                self.write_quarantine(
                    &rel.to_string(),
                    0x0015,
                    pair[0].1.store_time_ns,
                    Some(missing),
                    budget,
                )
                .await?;
            }
        }
        if first != 1 {
            report.findings.push(Finding {
                kind: FindingKind::ChainGap,
                key: self
                    .absolute(&RelKey::Claim {
                        shard,
                        job_id,
                        generation: first as u32,
                    })
                    .0
                    .clone(),
                reason: 0x0015,
            });
            let rel = RelKey::Claim {
                shard,
                job_id,
                generation: first as u32,
            };
            // A head gap has no predecessor; the head entry's own store
            // time is the deterministic choice (records.md).
            let head_time = chain.first().expect("chain is nonempty").1.store_time_ns;
            self.write_quarantine(&rel.to_string(), 0x0015, head_time, Some(first), budget)
                .await?;
        }
        // Decode every generation; keep (index-aligned) decoded records.
        let mut decoded: Vec<Option<stowq_format::ClaimRecord>> = Vec::with_capacity(chain.len());
        for (g, _meta) in chain {
            let rel = RelKey::Claim {
                shard,
                job_id,
                generation: *g as u32,
            };
            let abs = self.absolute(&rel);
            budget.spend()?;
            match self.store.get(&abs, None).await {
                Ok(obj) => {
                    let tag = self.tag_for(&rel);
                    match stowq_format::decode(&obj.body, &self.opts.queue_id, &tag) {
                        Ok(Record::Claim(c)) => decoded.push(Some(c)),
                        Ok(_) => {
                            report.findings.push(Finding {
                                kind: FindingKind::RecordCorrupt,
                                key: abs.0.clone(),
                                reason: 0x0005,
                            });
                            self.write_quarantine(
                                &rel.to_string(),
                                0x0005,
                                _meta.store_time_ns,
                                None,
                                budget,
                            )
                            .await?;
                            decoded.push(None);
                        }
                        Err(e) => {
                            let reason = record_violation_reason(&e);
                            report.findings.push(Finding {
                                kind: FindingKind::RecordCorrupt,
                                key: abs.0.clone(),
                                reason,
                            });
                            self.write_quarantine(
                                &rel.to_string(),
                                reason,
                                _meta.store_time_ns,
                                None,
                                budget,
                            )
                            .await?;
                            decoded.push(None);
                        }
                    }
                }
                Err(StoreError::NotFound) => decoded.push(None),
                Err(e) => return Err(e.into()),
            }
        }
        // Evidence: each generation above 1 vs its predecessor.
        for i in 1..chain.len() {
            let (Some(rec), Some(prev)) = (&decoded[i], &decoded[i - 1]) else {
                continue;
            };
            let gen = chain[i].0;
            if rec.continuation {
                let custody =
                    rec.worker_id == prev.worker_id && rec.prev_token == Some(prev.worker_token);
                if !custody {
                    self.quarantine_inadmissible(shard, job_id, chain, report, budget, gen)
                        .await?;
                }
            } else {
                let Some(basis) = &rec.basis else {
                    // Unreachable through decode (evidence exclusivity
                    // is enforced at the format layer); defensive.
                    self.quarantine_inadmissible(shard, job_id, chain, report, budget, gen)
                        .await?;
                    continue;
                };
                let evidence = basis.prev_store_time_ns == chain[i - 1].1.store_time_ns
                    && basis.prev_duration_ns == prev.lease_duration_ns
                    && basis
                        .prev_store_time_ns
                        .saturating_add(basis.prev_duration_ns)
                        <= basis.observed_watermark_ns;
                if !evidence {
                    self.quarantine_inadmissible(shard, job_id, chain, report, budget, gen)
                        .await?;
                }
            }
        }
        let (tail_gen, tail_meta) = chain.last().expect("chain is nonempty");
        let tail_duration = decoded
            .last()
            .and_then(|c| c.as_ref())
            .map_or(0, |c| c.lease_duration_ns);
        Ok((*tail_gen, tail_meta.clone(), tail_duration))
    }

    async fn repair_shard(
        &self,
        shard: u16,
        report: &mut RepairReport,
        budget: &mut OpBudget,
    ) -> Result<(), Error> {
        use std::collections::{HashMap, HashSet};

        // Jobs: delayed-index regeneration plus decode findings. The
        // parsed job set cross-references the claim scan below.
        let mut job_ids: HashSet<[u8; 16]> = HashSet::new();
        for listing in self
            .list_authoritative(&format!("{}jobs/{shard:04x}/", self.root), budget)
            .await?
        {
            report.jobs_scanned += 1;
            let stripped = listing.key.as_str().strip_prefix(&self.root).unwrap_or("");
            let rel = stripped.parse().ok();
            let Some(RelKey::Job { job_id, .. }) = rel else {
                report.findings.push(Finding {
                    kind: FindingKind::KeyGrammar,
                    key: listing.key.0.clone(),
                    reason: 0x0003,
                });
                self.write_quarantine(stripped, 0x0003, listing.meta.store_time_ns, None, budget)
                    .await?;
                continue;
            };
            job_ids.insert(job_id);
            let job_rel = RelKey::Job { shard, job_id };
            match self.store.get(&self.absolute(&job_rel), None).await {
                Ok(obj) => {
                    let tag = self.tag_for(&job_rel);
                    match stowq_format::decode(&obj.body, &self.opts.queue_id, &tag) {
                        Ok(Record::Job(j)) => {
                            // 0x0014: a detached job whose payload object
                            // is absent (the referenced-payload half of
                            // the orphan story; gc owns the other half).
                            if let Some(pk) = j.payload_key.clone() {
                                let abs_payload = Key::new(format!("{}{}", self.root, pk));
                                budget.spend()?;
                                match self.store.head(&abs_payload).await {
                                    Ok(_) => {}
                                    Err(StoreError::NotFound) => {
                                        report.findings.push(Finding {
                                            kind: FindingKind::PayloadMissing,
                                            key: abs_payload.0.clone(),
                                            reason: 0x0014,
                                        });
                                        self.write_quarantine(
                                            &pk,
                                            0x0014,
                                            listing.meta.store_time_ns,
                                            None,
                                            budget,
                                        )
                                        .await?;
                                    }
                                    Err(e) => return Err(e.into()),
                                }
                            }
                            if let Some(nb) = j.not_before_ns {
                                if let Some(bucket) = stowq_math::bucket_number(
                                    nb,
                                    self.format.delayed_bucket_width_ns,
                                ) {
                                    let idx = self.absolute(&RelKey::DelayIndex {
                                        bucket,
                                        shard,
                                        job_id,
                                    });
                                    if self.ensure_index(&idx, budget).await? {
                                        report.indexes_regenerated += 1;
                                    }
                                }
                            }
                        }
                        Ok(_) => {
                            report.findings.push(Finding {
                                kind: FindingKind::RecordCorrupt,
                                key: listing.key.0.clone(),
                                reason: 0x0005,
                            });
                            self.write_quarantine(
                                &job_rel.to_string(),
                                0x0005,
                                listing.meta.store_time_ns,
                                None,
                                budget,
                            )
                            .await?;
                        }
                        Err(e) => {
                            let reason = record_violation_reason(&e);
                            report.findings.push(Finding {
                                kind: FindingKind::RecordCorrupt,
                                key: listing.key.0.clone(),
                                reason,
                            });
                            self.write_quarantine(
                                &job_rel.to_string(),
                                reason,
                                listing.meta.store_time_ns,
                                None,
                                budget,
                            )
                            .await?;
                        }
                    }
                }
                // Listed but gone: GC raced between LIST and GET; the
                // graph is terminal and deleted, nothing to regenerate.
                Err(StoreError::NotFound) => {}
                Err(e) => return Err(e.into()),
            }
        }

        // Claim chains: leases-index regeneration from each tail, plus
        // basis evidence checked against the listing's store times.
        let mut chains: HashMap<[u8; 16], Vec<(u64, Meta)>> = HashMap::new();
        for listing in self
            .list_authoritative(&format!("{}claims/{shard:04x}/", self.root), budget)
            .await?
        {
            let rel = listing
                .key
                .as_str()
                .strip_prefix(&self.root)
                .and_then(|s| s.parse().ok());
            let Some(RelKey::Claim {
                job_id, generation, ..
            }) = rel
            else {
                report.findings.push(Finding {
                    kind: FindingKind::KeyGrammar,
                    key: listing.key.0.clone(),
                    reason: 0x0003,
                });
                let stripped = listing.key.as_str().strip_prefix(&self.root).unwrap_or("");
                self.write_quarantine(stripped, 0x0003, listing.meta.store_time_ns, None, budget)
                    .await?;
                continue;
            };
            chains
                .entry(job_id)
                .or_default()
                .push((generation as u64, listing.meta));
        }
        for (job_id, mut chain) in chains {
            report.claim_chains_scanned += 1;
            let orphaned = !job_ids.contains(&job_id);
            if orphaned {
                report.findings.push(Finding {
                    kind: FindingKind::ClaimWithoutJob,
                    key: self.absolute(&RelKey::Job { shard, job_id }).0.clone(),
                    reason: 0x0005,
                });
            }
            // Generations are fixed-width hex: listing order is
            // numeric order, so ascending sort yields the chain.
            chain.sort_by_key(|(g, _)| *g);
            let (tail_gen, tail_meta, tail_duration) = self
                .audit_claim_chain(shard, job_id, &chain, report, budget)
                .await?;
            if orphaned {
                // Convention: the chain tail's store time (records.md).
                let job_rel = RelKey::Job { shard, job_id };
                self.write_quarantine(
                    &job_rel.to_string(),
                    0x0005,
                    tail_meta.store_time_ns,
                    None,
                    budget,
                )
                .await?;
            }
            let duration = tail_duration;
            if let Some(bucket) = stowq_math::bucket_number(
                tail_meta.store_time_ns.saturating_add(duration),
                self.format.lease_bucket_width_ns,
            ) {
                let idx = self.absolute(&RelKey::LeaseIndex {
                    bucket,
                    shard,
                    job_id,
                    generation: tail_gen as u32,
                });
                if self.ensure_index(&idx, budget).await? {
                    report.indexes_regenerated += 1;
                }
            }
        }

        // Terminals: termidx regeneration plus the receipt-and-dead
        // mutual-exclusion finding (the check-then-act window's residue;
        // the repair scan owns it per the recovery errata).
        let mut receipt_jobs: HashMap<[u8; 16], u64> = HashMap::new();
        let mut dead_jobs: HashMap<[u8; 16], u64> = HashMap::new();
        for (kind_char, prefix, set) in [
            (
                'r',
                format!("{}receipts/{shard:04x}/", self.root),
                &mut receipt_jobs,
            ),
            (
                'd',
                format!("{}dead/{shard:04x}/", self.root),
                &mut dead_jobs,
            ),
        ] {
            for listing in self.list_authoritative(&prefix, budget).await? {
                let rel = listing
                    .key
                    .as_str()
                    .strip_prefix(&self.root)
                    .and_then(|s| s.parse().ok());
                let (job_id, term_kind) = match rel {
                    Some(RelKey::Receipt { job_id, .. }) => (job_id, stowq_keys::TermKind::Receipt),
                    Some(RelKey::Dead { job_id, .. }) => (job_id, stowq_keys::TermKind::Dead),
                    _ => {
                        report.findings.push(Finding {
                            kind: FindingKind::KeyGrammar,
                            key: listing.key.0.clone(),
                            reason: 0x0003,
                        });
                        let stripped = listing.key.as_str().strip_prefix(&self.root).unwrap_or("");
                        self.write_quarantine(
                            stripped,
                            0x0003,
                            listing.meta.store_time_ns,
                            None,
                            budget,
                        )
                        .await?;
                        continue;
                    }
                };
                let _ = kind_char;
                set.insert(job_id, listing.meta.store_time_ns);
                if let Some(bucket) = stowq_math::bucket_number(
                    listing.meta.store_time_ns,
                    self.format.terminal_bucket_width_ns,
                ) {
                    let idx = self.absolute(&RelKey::TermIndex {
                        bucket,
                        kind: term_kind,
                        shard,
                        job_id,
                    });
                    if self.ensure_index(&idx, budget).await? {
                        report.indexes_regenerated += 1;
                    }
                }
            }
        }
        let duplicates: Vec<[u8; 16]> = receipt_jobs
            .keys()
            .filter(|j| dead_jobs.contains_key(*j))
            .copied()
            .collect();
        for job_id in duplicates {
            report.findings.push(Finding {
                kind: FindingKind::DuplicateTerminal,
                key: self.absolute(&RelKey::Receipt { shard, job_id }).0.clone(),
                reason: 0x0007,
            });
            // Convention: the receipts/ key with the receipt's store
            // time (records.md).
            let rel = RelKey::Receipt { shard, job_id };
            self.write_quarantine(
                &rel.to_string(),
                0x0007,
                receipt_jobs[&job_id],
                None,
                budget,
            )
            .await?;
        }
        Ok(())
    }
}

/// Maps a decode failure to its quarantine reason code (spec
/// reasons.md): key-tag failure is distinguishable from digest and
/// envelope corruption.
fn record_violation_reason(e: &stowq_format::RecordError) -> u64 {
    match e {
        stowq_format::RecordError::Field("queue binding") => 0x0004,
        _ => 0x0001,
    }
}

fn empty_meta() -> Meta {
    Meta {
        version: Version("0".into()),
        store_time_ns: 0,
        size: 0,
    }
}

/// leases/<bucket>/<shard>/<job>.<generation> entry parser.
fn parse_lease_entry(rest: &str) -> Option<(u16, [u8; 16], u32)> {
    let (shard_str, tail) = rest.split_once('/')?;

    let (job_str, gen_str) = tail.rsplit_once('.')?;
    let shard = u16::from_str_radix(shard_str, 16).ok()?;
    if shard_str.len() != 4 || job_str.len() != 32 || gen_str.len() != 8 {
        return None;
    }
    let mut job_id = [0u8; 16];
    for (i, b) in job_id.iter_mut().enumerate() {
        *b = u8::from_str_radix(&job_str[2 * i..2 * i + 2], 16).ok()?;
    }
    let generation = u32::from_str_radix(gen_str, 16).ok()?;
    Some((shard, job_id, generation))
}

/// delayed/<bucket>/<shard>/<job> entry parser.
fn parse_delay_entry(rest: &str) -> Option<(u16, [u8; 16])> {
    let (shard_str, job_str) = rest.split_once('/')?;

    if shard_str.len() != 4 || job_str.len() != 32 {
        return None;
    }
    let shard = u16::from_str_radix(shard_str, 16).ok()?;
    let mut job_id = [0u8; 16];
    for (i, b) in job_id.iter_mut().enumerate() {
        *b = u8::from_str_radix(&job_str[2 * i..2 * i + 2], 16).ok()?;
    }
    Some((shard, job_id))
}

/// termidx/<bucket>/<kind>/<shard>/<job> entry parser.
fn parse_term_entry(rel_str: &str) -> Option<(char, u16, [u8; 16])> {
    let rest = rel_str.strip_prefix("termidx/")?;
    let mut parts = rest.splitn(4, '/');
    let _bucket = parts.next()?;
    let kind = parts.next()?.chars().next()?;
    let shard_str = parts.next()?;
    let job_str = parts.next()?;
    if shard_str.len() != 4 || job_str.len() != 32 || !matches!(kind, 'r' | 'd') {
        return None;
    }
    let shard = u16::from_str_radix(shard_str, 16).ok()?;
    let mut job_id = [0u8; 16];
    for (i, b) in job_id.iter_mut().enumerate() {
        *b = u8::from_str_radix(&job_str[2 * i..2 * i + 2], 16).ok()?;
    }
    Some((kind, shard, job_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use stowq_store::MemoryStore;

    fn format() -> stowq_format::FormatRecord {
        stowq_format::FormatRecord {
            shard_count: 1,
            lease_bucket_width_ns: 1_000,
            delayed_bucket_width_ns: 1_000,
            terminal_bucket_width_ns: 1_000,
            inline_limit: 4_096,
            required_feature_bits: 0,
        }
    }

    // The receipt-evidence-mismatch branch is unreachable through the
    // public claim path (a foreign receipt makes the job terminal and
    // unclaimable), so the claim handle is built in-crate.
    #[tokio::test]
    async fn ack_against_conflicting_receipt_evidence_errors() {
        let q = Queue::init(
            Box::new(MemoryStore::new()),
            "q",
            &OpenOptions::new([1; 16]),
            &format(),
        )
        .await
        .unwrap();
        let mut budget = OpBudget::new(64);
        let EnqueueOutcome::Committed { job_id } = q
            .enqueue(
                EnqueueInput {
                    job_id: Some([7; 16]),
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
        let _jhex: String = job_id.iter().map(|b| format!("{b:02x}")).collect();
        let rel = RelKey::Receipt { shard: 0, job_id };
        let tag = q.tag_for(&rel);
        let receipt = Record::Receipt(ReceiptRecord {
            job_id,
            generation: 9,
            attempt: 9,
            worker_id: "other".into(),
            worker_token: [0x99; 16],
            payload_digest: [0x99; 32],
            output_digests: vec![],
        });
        let body = Bytes::from(stowq_format::encode(&receipt, &[1; 16], &tag));
        let digest: Digest = Sha256::digest(&body).into();
        q.store
            .put_if_absent(&q.absolute(&rel), body, digest)
            .await
            .unwrap();
        let claim = Claim {
            job_id,
            shard: 0,
            generation: 1,
            attempt: 1,
            worker_token: [1; 16],
            lease_duration_ns: 60_000_000_000,
            claim_store_time_ns: 0,
            payload: PayloadRef::Inline(Bytes::from_static(b"x")),
        };
        let err = q.ack(&claim, &mut budget).await.unwrap_err();
        assert!(matches!(err, Error::ReceiptEvidenceMismatch));
    }

    // Same payload digest, different generation: the generation-evidence
    // check must still fail the idempotent-verify (spec records.md,
    // Acknowledgment; quarantine 0x0013).
    #[tokio::test]
    async fn ack_against_same_digest_foreign_generation_receipt_errors() {
        let q = Queue::init(
            Box::new(MemoryStore::new()),
            "q",
            &OpenOptions::new([1; 16]),
            &format(),
        )
        .await
        .unwrap();
        let mut budget = OpBudget::new(64);
        let EnqueueOutcome::Committed { job_id } = q
            .enqueue(
                EnqueueInput {
                    job_id: Some([7; 16]),
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
        let rel = RelKey::Receipt { shard: 0, job_id };
        let tag = q.tag_for(&rel);
        let payload_digest: Digest = Sha256::digest(b"x").into();
        let receipt = Record::Receipt(ReceiptRecord {
            job_id,
            generation: 2,
            attempt: 2,
            worker_id: "other".into(),
            worker_token: [0x99; 16],
            payload_digest,
            output_digests: vec![],
        });
        let body = Bytes::from(stowq_format::encode(&receipt, &[1; 16], &tag));
        let digest: Digest = Sha256::digest(&body).into();
        q.store
            .put_if_absent(&q.absolute(&rel), body, digest)
            .await
            .unwrap();
        let claim = Claim {
            job_id,
            shard: 0,
            generation: 1,
            attempt: 1,
            worker_token: [1; 16],
            lease_duration_ns: 60_000_000_000,
            claim_store_time_ns: 0,
            payload: PayloadRef::Inline(Bytes::from_static(b"x")),
        };
        let err = q.ack(&claim, &mut budget).await.unwrap_err();
        assert!(matches!(err, Error::ReceiptEvidenceMismatch));
    }

    // Bury's idempotent-verify: matching evidence is success, a
    // foreign-generation dead record is a conflicting-terminal error.
    // Both branches are unreachable through the public claim path (a
    // dead record makes the job terminal and unclaimable), so the
    // handles are built in-crate.
    #[tokio::test]
    async fn bury_against_dead_evidence_verified_by_generation() {
        let q = Queue::init(
            Box::new(MemoryStore::new()),
            "q",
            &OpenOptions::new([1; 16]),
            &format(),
        )
        .await
        .unwrap();
        let mut budget = OpBudget::new(64);
        let EnqueueOutcome::Committed { job_id } = q
            .enqueue(
                EnqueueInput {
                    job_id: Some([7; 16]),
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
        let rel = RelKey::Dead { shard: 0, job_id };
        let tag = q.tag_for(&rel);
        let dead = Record::Dead(DeadRecord {
            job_id,
            generation: 2,
            attempt: 2,
            reason: 0x0003,
        });
        let body = Bytes::from(stowq_format::encode(&dead, &[1; 16], &tag));
        let digest: Digest = Sha256::digest(&body).into();
        q.store
            .put_if_absent(&q.absolute(&rel), body, digest)
            .await
            .unwrap();
        let holder = Claim {
            job_id,
            shard: 0,
            generation: 2,
            attempt: 2,
            worker_token: [1; 16],
            lease_duration_ns: 60_000_000_000,
            claim_store_time_ns: 0,
            payload: PayloadRef::Inline(Bytes::from_static(b"x")),
        };
        let zombie = Claim {
            generation: 1,
            attempt: 1,
            ..holder.clone()
        };
        // The tail holder at the dead record's own generation: success.
        assert_eq!(
            q.bury(&holder, 0x0003, &mut budget).await.unwrap(),
            BuryOutcome::Buried
        );
        // A stale-generation holder: conflicting evidence, an error.
        let err = q.bury(&zombie, 0x0003, &mut budget).await.unwrap_err();
        assert!(matches!(err, Error::Record(_)));
    }
}

#[cfg(test)]
mod handle_tests {
    use super::*;
    use stowq_store::MemoryStore;

    fn format() -> stowq_format::FormatRecord {
        stowq_format::FormatRecord {
            shard_count: 1,
            lease_bucket_width_ns: 1_000,
            delayed_bucket_width_ns: 1_000,
            terminal_bucket_width_ns: 1_000,
            inline_limit: 4,
            required_feature_bits: 0,
        }
    }

    async fn detached_queue() -> (Queue, MemoryStore) {
        let store = MemoryStore::new();
        let mut opts = OpenOptions::new([1; 16]);
        opts.max_inline_payload = 4;
        let q = Queue::init(Box::new(store.clone()), "q", &opts, &format())
            .await
            .unwrap();
        (q, store)
    }

    #[tokio::test]
    async fn detached_handle_reconstruction_verifies_payload() {
        let (q, store) = detached_queue().await;
        let mut b = OpBudget::new(64);
        let payload = vec![7u8; 64];
        let EnqueueOutcome::Committed { job_id } = q
            .enqueue(
                EnqueueInput {
                    job_id: Some([3; 16]),
                    payload: &payload,
                    content_type: "application/octet-stream".into(),
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
        let claim = Claim::detached_or_inline(job_id, 0, 1, 1, [9; 16], 1_000, 0, "q", &store)
            .await
            .unwrap();
        assert_eq!(&claim.payload(&store).await.unwrap()[..], &payload[..]);
        // A stale (pre-write) handle for an absent job errors.
        let err = Claim::detached_or_inline([4; 16], 0, 1, 1, [9; 16], 1_000, 0, "q", &store)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Record(_)));
    }

    #[tokio::test]
    async fn terminal_memo_entries_expire_past_the_ttl() {
        use stowq_store::MemoryStore;
        let clock = std::sync::Arc::new(FakeClock::new());
        let mem = MemoryStore::new();
        Queue::init(
            Box::new(mem.clone()),
            "q",
            &OpenOptions::new([1; 16]),
            &stowq_format::FormatRecord {
                shard_count: 1,
                lease_bucket_width_ns: 1_000,
                delayed_bucket_width_ns: 1_000,
                terminal_bucket_width_ns: 1_000,
                inline_limit: 4_096,
                required_feature_bits: 0,
            },
        )
        .await
        .unwrap();
        let q =
            Queue::open_with_clock(Box::new(mem), "q", OpenOptions::new([1; 16]), clock.clone())
                .await
                .unwrap();
        let v = Version("v1".into());
        q.memoize_terminal(0, [9; 16], v.clone());
        assert!(
            q.is_memoized_terminal(0, [9; 16], &v),
            "fresh entry is honored"
        );
        clock.advance_ns(super::TERMINAL_MEMO_TTL_NS);
        assert!(
            !q.is_memoized_terminal(0, [9; 16], &v),
            "an entry past the TTL is re-proven (content-addressed backends repeat versions across byte-identical re-enqueues)"
        );
        // A different version never matches at any age.
        q.memoize_terminal(0, [9; 16], Version("v2".into()));
        assert!(!q.is_memoized_terminal(0, [9; 16], &v));
    }

    #[tokio::test]
    async fn detached_handle_reconstruction_rejects_tampered_payload() {
        let (q, store) = detached_queue().await;
        let mut b = OpBudget::new(64);
        let payload = vec![7u8; 64];
        let EnqueueOutcome::Committed { job_id } = q
            .enqueue(
                EnqueueInput {
                    job_id: Some([5; 16]),
                    payload: &payload,
                    content_type: "application/octet-stream".into(),
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
        // Corrupt the detached payload object in place.
        let jhex: String = job_id.iter().map(|x| format!("{x:02x}")).collect();
        let prefix = format!("q/payloads/{jhex}/");
        let page = store.list(&prefix, None, 10).await.unwrap();
        let key = page.items[0].key.clone();
        let digest: Digest = Sha256::digest(vec![0u8; 64].as_slice()).into();
        let _ = store.delete(&key).await;
        store
            .put_if_absent(&key, bytes::Bytes::from(vec![0u8; 64]), digest)
            .await
            .unwrap();
        let err = Claim::detached_or_inline(job_id, 0, 1, 1, [9; 16], 1_000, 0, "q", &store)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::PayloadCorrupt));
    }
}
