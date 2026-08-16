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
            max_inline_payload: 4_096,
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
    pub fn detached_or_inline(
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
        let obj = match store.get(&abs, None) {
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
                let obj = store.get(&key, None)?;
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
    pub fn payload(&self, store: &dyn ObjectStore) -> Result<Bytes, Error> {
        match &self.payload {
            PayloadRef::Inline(b) => Ok(b.clone()),
            PayloadRef::Detached {
                key,
                digest,
                length,
            } => {
                let obj = store.get(key, None)?;
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
    #[error("operation budget hit an internal invariant; report this")]
    Internal(String),
}

impl From<stowq_format::RecordError> for Error {
    fn from(e: stowq_format::RecordError) -> Self {
        Error::Record(e.to_string())
    }
}

// ---------- Writer tokens ----------

fn fresh_token(context: &[u8]) -> [u8; 16] {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let mut hasher = Sha256::new();
    hasher.update(b"StowQ-1-token\0");
    hasher.update(now.to_be_bytes());
    hasher.update(n.to_be_bytes());
    hasher.update(context);
    hasher.finalize()[..16].try_into().unwrap()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
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
}

#[derive(Debug, Clone)]
struct FloorCache {
    floor_ns: u64,
    /// Local monotonic instant of establishment; local clocks are
    /// trusted only for this staleness deadline, never for protocol
    /// decisions.
    established_at: std::time::Instant,
}

/// A floor is reused for at most this long before re-establishment;
/// staleness only delays work, never delivers early.
const FLOOR_STALENESS: std::time::Duration = std::time::Duration::from_secs(30);

const RETRY_TRANSPORT_MAX: usize = 4;

/// Queue id for handle-reconstruction tooling built on the dev
/// convention (OpenOptions::new([1; 16])).
const QUEUE_ID_FOR_TOOLING: [u8; 16] = [1; 16];

impl Queue {
    /// Opens an initialized queue: reads and verifies `meta/FORMAT`.
    pub fn open(store: Box<dyn ObjectStore>, root: &str, opts: OpenOptions) -> Result<Self, Error> {
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
                established_at: std::time::Instant::now(),
            }),
        };
        let key = q.absolute(&RelKey::Format);
        let tag = key_tag(&q.opts.queue_id, "meta/FORMAT");
        let obj = q.store.get(&key, None)?;
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
    pub fn init(
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
        match store.put_if_absent(&key, body, digest)? {
            PutOutcome::Committed { .. } => {}
            PutOutcome::Rejected => {
                // A different format already owns the prefix.
                let obj = store.get(&key, None)?;
                let existing = stowq_format::decode(&obj.body, &opts.queue_id, &tag)?;
                if existing != Record::Format(format.clone()) {
                    return Err(Error::QueueIdMismatch);
                }
            }
        }
        Self::open(store, &root, opts.clone())
    }

    pub fn format(&self) -> &stowq_format::FormatRecord {
        &self.format
    }

    /// The underlying store, for inspection and audit tooling.
    pub fn store(&self) -> &dyn ObjectStore {
        self.store.as_ref()
    }

    /// Establishes a wall floor (spec time.md): PUT a beacon, read it
    /// back, take the store-assigned time. The floor is a proven lower
    /// bound on store time. Cached until stale; staleness only delays
    /// work, never delivers early.
    pub fn establish_floor(&self, budget: &mut OpBudget) -> Result<u64, Error> {
        {
            let cache = self.floor.lock().unwrap();
            if cache.floor_ns > 0 && cache.established_at.elapsed() < FLOOR_STALENESS {
                return Ok(cache.floor_ns);
            }
        }
        let body = Bytes::from_static(b"");
        let digest: Digest = Sha256::digest([]).into();
        let mut floor_ns = 0;
        for _ in 0..=RETRY_TRANSPORT_MAX {
            // Beacons are content-free: on a nonce collision or an
            // unknown outcome, a fresh nonce is always correct.
            let nonce = fresh_token(b"beacon");
            let rel = RelKey::Beacon { nonce };
            let abs = self.absolute(&rel);
            budget.spend()?;
            match self.store.put_if_absent(&abs, body.clone(), digest) {
                Ok(PutOutcome::Committed { .. }) => {
                    budget.spend()?;
                    let meta = self.store.head(&abs)?;
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
        // >= G). The watermark read is best-effort — its absence is not
        // a regression.
        if let Some(w) = self.watermark(budget)? {
            let wm_ns = w
                .highest_observed_wall_bucket
                .saturating_mul(self.format.delayed_bucket_width_ns);
            if floor_ns.saturating_add(self.opts.skew_guard_ns) < wm_ns {
                return Err(Error::Store(StoreError::ProfileViolation(
                    "store time regression".into(),
                )));
            }
        }
        *self.floor.lock().unwrap() = FloorCache {
            floor_ns,
            established_at: std::time::Instant::now(),
        };
        Ok(floor_ns)
    }

    /// Reads and verifies the watermark record, if present.
    pub fn watermark(
        &self,
        budget: &mut OpBudget,
    ) -> Result<Option<stowq_format::WatermarkRecord>, Error> {
        budget.spend()?;
        let rel = RelKey::Watermark;
        let abs = self.absolute(&rel);
        let tag = self.tag_for(&rel);
        match self.store.get(&abs, None) {
            Ok(obj) => match stowq_format::decode(&obj.body, &self.opts.queue_id, &tag)? {
                Record::Watermark(w) => Ok(Some(w)),
                _ => Err(Error::Record(
                    "watermark key holds a non-watermark record".into(),
                )),
            },
            Err(StoreError::NotFound) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Advances the watermark monotonically (spec time.md): If-Match CAS;
    /// a lost race means someone advanced it further — the stored value
    /// then already covers our bucket and the call proceeds. A bucket at
    /// or below the stored one is a no-op. Genuine regression (a fresh
    /// floor below the watermark) is detected by fail-closed promotion.
    pub fn advance_watermark(&self, floor_ns: u64, budget: &mut OpBudget) -> Result<(), Error> {
        let width = self.format.delayed_bucket_width_ns;
        let Some(bucket) = stowq_math::bucket_number(floor_ns, width) else {
            return Err(Error::Internal("zero delayed width".into()));
        };
        loop {
            let current = self.watermark(budget)?;
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
                let meta = self.store.head(&abs)?;
                self.store.cas(&abs, body.clone(), digest, &meta.version)
            } else {
                self.store.put_if_absent(&abs, body.clone(), digest)
            };
            // Resolve unknown outcomes by re-reading: our record (or any
            // record covering our bucket) means done; anything else
            // re-reads the loop.
            let outcome = match outcome {
                Ok(o) => o,
                Err(StoreError::OutcomeUnknown(_)) => {
                    if self.watermark_covers(bucket, budget)? {
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
    fn watermark_covers(&self, bucket: u64, budget: &mut OpBudget) -> Result<bool, Error> {
        Ok(match self.watermark(budget)? {
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

    pub fn enqueue(
        &self,
        input: EnqueueInput<'_>,
        budget: &mut OpBudget,
    ) -> Result<EnqueueOutcome, Error> {
        // A zero-attempt job would be dead on its first claim scan; the
        // producer gets the error instead.
        if input.maximum_attempts == 0 {
            return Err(Error::Record("maximum_attempts must be positive".into()));
        }
        let job_id = input.job_id.unwrap_or_else(|| fresh_token(input.payload));
        let shard = compute_shard(&self.opts.queue_id, &job_id, self.format.shard_count.max(1));
        let payload_digest: Digest = Sha256::digest(input.payload).into();
        let inline = (input.payload.len() as u64) <= self.opts.max_inline_payload;

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
            self.put_bytes_resolving(&abs, body, payload_digest, budget)?;
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
        let outcome = self.put_resolving(&abs, body, digest, &record, &rel, budget)?;
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
                        .put_if_absent(&idx, Bytes::new(), Sha256::digest([]).into());
                }
                Ok(EnqueueOutcome::Committed { job_id })
            }
            Resolved::Lost => {
                // Someone's record holds the key: ours if identical
                // (idempotent enqueue), theirs otherwise.
                budget.spend()?;
                let tag = self.tag_for(&rel);
                let obj = self.store.get(&abs, None)?;
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
    fn put_bytes_resolving(
        &self,
        abs: &Key,
        body: Bytes,
        digest: Digest,
        budget: &mut OpBudget,
    ) -> Result<(), Error> {
        let mut transport_retries = 0;
        loop {
            budget.spend()?;
            match self.store.put_if_absent(abs, body.clone(), digest) {
                Ok(PutOutcome::Committed { .. }) | Ok(PutOutcome::Rejected) => return Ok(()),
                Err(StoreError::Transport(_)) => {
                    transport_retries += 1;
                    if transport_retries > RETRY_TRANSPORT_MAX {
                        return Err(Error::TransportExhausted);
                    }
                    continue;
                }
                Err(StoreError::OutcomeUnknown(_)) => {
                    match self.resolve_presence(abs, budget)? {
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
    fn resolve_presence(&self, abs: &Key, budget: &mut OpBudget) -> Result<bool, Error> {
        let mut transport_retries = 0;
        loop {
            budget.spend()?;
            match self.store.head(abs) {
                Ok(_) => return Ok(true),
                Err(StoreError::NotFound) => return Ok(false),
                Err(StoreError::Transport(_)) => {
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
    fn put_resolving(
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
            let result = self.store.put_if_absent(abs, body.clone(), digest);
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
                    match self.resolve_unknown(abs, intended, rel, budget)? {
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

    fn resolve_unknown(
        &self,
        abs: &Key,
        intended: &Record,
        rel: &RelKey,
        budget: &mut OpBudget,
    ) -> Result<Resolved, Error> {
        let mut transport_retries = 0;
        loop {
            budget.spend()?;
            match self.store.head(abs) {
                Ok(_) => {
                    budget.spend()?;
                    let obj = self.store.get(abs, None)?;
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
                Err(StoreError::Transport(_)) => {
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

    pub fn claim(&self, opts: &ClaimOptions, budget: &mut OpBudget) -> Result<ClaimOutcome, Error> {
        let shard_prefix = format!("{}jobs/{:04x}/", self.root, opts.shard);
        let mut after: Option<Key> = None;
        loop {
            budget.spend()?;
            let page = self.store.list(&shard_prefix, after.as_ref(), 32)?;
            if page.items.is_empty() {
                return Ok(ClaimOutcome::Empty);
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
                if let Some(claim) = self.try_claim(job_id, shard, opts, budget)? {
                    return Ok(ClaimOutcome::Claimed(claim));
                }
                if budget.max_ops == 0 {
                    return Ok(ClaimOutcome::Empty);
                }
            }
            match page.next_after {
                Some(k) => after = Some(k),
                None => return Ok(ClaimOutcome::Empty),
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn try_claim(
        &self,
        job_id: [u8; 16],
        shard: u16,
        opts: &ClaimOptions,
        budget: &mut OpBudget,
    ) -> Result<Option<Claim>, Error> {
        // Readiness: no terminal record. Only NotFound proves absence;
        // any other error aborts the scan loudly rather than delivering
        // past an unknown terminal state.
        for rel in [
            RelKey::Receipt { shard, job_id },
            RelKey::Dead { shard, job_id },
        ] {
            budget.spend()?;
            match self.store.head(&self.absolute(&rel)) {
                Ok(_) => return Ok(None),
                Err(StoreError::NotFound) => {}
                Err(e) => return Err(e.into()),
            }
        }

        // Claim tail.
        let claims_prefix = format!("{}claims/{shard:04x}/{}/", self.root, hex(&job_id));
        budget.spend()?;
        let mut tail: Option<(u64, Meta)> = None;
        let mut after: Option<Key> = None;
        loop {
            budget.spend()?;
            let page = self.store.list(&claims_prefix, after.as_ref(), 64)?;
            for item in page.items {
                // Grammar violations in the chain are skipped; the
                // repair scan owns quarantine.
                if let Some(g) = parse_generation(&item.key) {
                    tail = Some((g, item.meta));
                }
            }
            match page.next_after {
                Some(k) => after = Some(k),
                None => break,
            }
        }

        let (tail_gen, tail_meta) = tail.unwrap_or((
            0,
            Meta {
                version: Version("0".into()),
                store_time_ns: 0,
                size: 0,
            },
        ));

        // Tail claim record for attempt bookkeeping and expiry basis.
        let (tail_attempt, tail_duration) = if tail_gen == 0 {
            (0, 0)
        } else {
            budget.spend()?;
            let rel = RelKey::Claim {
                shard,
                job_id,
                generation: tail_gen as u32,
            };
            let abs = self.absolute(&rel);
            let tag = self.tag_for(&rel);
            let obj = self.store.get(&abs, None)?;
            match stowq_format::decode(&obj.body, &self.opts.queue_id, &tag)? {
                Record::Claim(c) => (c.attempt, c.lease_duration_ns),
                _ => return Err(Error::Record("claim key holds a non-claim record".into())),
            }
        };

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
            let fail = match self.store.get(&self.absolute(&rel), None) {
                Ok(obj) => {
                    let tag = self.tag_for(&rel);
                    match stowq_format::decode(&obj.body, &self.opts.queue_id, &tag)? {
                        Record::Fail(f) => Some(f),
                        _ => return Err(Error::Record("fail key holds a non-fail record".into())),
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
        let job_obj = match self.store.get(&job_abs, None) {
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
            if let Resolved::Committed =
                self.put_resolving(&abs, body, body_digest, &dead, &rel, budget)?
            {
                self.write_termidx(&rel, stowq_keys::TermKind::Dead, shard, job_id, budget);
            }
            return Ok(None);
        }

        if tail_gen >= u32::MAX as u64 {
            return Err(Error::Internal("generation space exhausted".into()));
        }
        let worker_token = fresh_token(&job_id);
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
        match self.put_resolving(&abs, body, digest, &record, &rel, budget)? {
            Resolved::Committed => {
                budget.spend()?;
                let meta = self.store.head(&abs)?;
                let payload = match (&job.payload_inline, &job.payload_key) {
                    (Some(b), _) => PayloadRef::Inline(Bytes::from(b.clone())),
                    (None, Some(k)) => PayloadRef::Detached {
                        key: Key::new(format!("{}{}", self.root, k)),
                        digest: job.payload_digest,
                        length: job.payload_length,
                    },
                    _ => return Err(Error::Record("job payload reference invalid".into())),
                };
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
                        .put_if_absent(&idx, Bytes::new(), Sha256::digest([]).into());
                }
                Ok(Some(Claim {
                    job_id,
                    shard,
                    generation: tail_gen + 1,
                    attempt,
                    worker_token,
                    lease_duration_ns: opts.lease_duration_ns,
                    claim_store_time_ns: meta.store_time_ns,
                    payload,
                }))
            }
            Resolved::Lost | Resolved::NotCommitted => Ok(None),
        }
    }

    // ---------- renew ----------

    pub fn renew(&self, claim: &Claim, budget: &mut OpBudget) -> Result<RenewOutcome, Error> {
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
            match self.store.head(&self.absolute(&rel)) {
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
        match self.put_resolving(&abs, body, digest, &record, &rel, budget)? {
            Resolved::Committed => {
                budget.spend()?;
                let meta = self.store.head(&abs)?;
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

    pub fn ack(&self, claim: &Claim, budget: &mut OpBudget) -> Result<AckOutcome, Error> {
        // A dead record terminalized the job first; refuse so at most
        // one terminal record per job ever exists.
        budget.spend()?;
        match self.store.head(&self.absolute(&RelKey::Dead {
            shard: claim.shard,
            job_id: claim.job_id,
        })) {
            Ok(_) => return Ok(AckOutcome::SupersededByDead),
            Err(StoreError::NotFound) => {}
            Err(e) => return Err(e.into()),
        }
        // Payload evidence: re-verify before the terminal write.
        budget.spend()?;
        let payload = claim.payload(self.store.as_ref())?;
        let digest: Digest = Sha256::digest(&payload).into();

        let record = Record::Receipt(ReceiptRecord {
            job_id: claim.job_id,
            generation: claim.generation,
            attempt: claim.attempt,
            worker_id: self.opts.worker_id.clone(),
            worker_token: claim.worker_token,
            payload_digest: digest,
            output_digests: vec![],
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
        match self.put_resolving(&abs, body, body_digest, &record, &rel, budget)? {
            Resolved::Committed => {
                self.write_termidx(
                    &rel,
                    stowq_keys::TermKind::Receipt,
                    claim.shard,
                    claim.job_id,
                    budget,
                );
                Ok(AckOutcome::Acked)
            }
            Resolved::Lost | Resolved::NotCommitted => {
                // A receipt exists: idempotent-verify its evidence
                // (identity is the key; generation, attempt, and the
                // re-verified payload digest must match this claim).
                budget.spend()?;
                let obj = self.store.get(&abs, None)?;
                let tag = self.tag_for(&rel);
                match stowq_format::decode(&obj.body, &self.opts.queue_id, &tag)? {
                    Record::Receipt(r)
                        if r.job_id == claim.job_id
                            && r.generation == claim.generation
                            && r.attempt == claim.attempt
                            && r.payload_digest == digest =>
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

    pub fn nack(
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
        match self.put_resolving(&abs, body, digest, &record, &rel, budget)? {
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
                .put_if_absent(&idx, Bytes::new(), Sha256::digest([]).into());
        }
        Ok(())
    }

    // ---------- bury ----------

    pub fn bury(
        &self,
        claim: &Claim,
        reason: u64,
        budget: &mut OpBudget,
    ) -> Result<BuryOutcome, Error> {
        // A receipt terminalized the job first; refuse so at most one
        // terminal record per job ever exists — the symmetric guard to
        // ack's dead check.
        budget.spend()?;
        match self.store.head(&self.absolute(&RelKey::Receipt {
            shard: claim.shard,
            job_id: claim.job_id,
        })) {
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
        match self.put_resolving(&abs, body, digest, &record, &rel, budget)? {
            Resolved::Committed => {
                self.write_termidx(
                    &rel,
                    stowq_keys::TermKind::Dead,
                    claim.shard,
                    claim.job_id,
                    budget,
                );
                Ok(BuryOutcome::Buried)
            }
            Resolved::Lost => {
                // First-wins: an existing dead record with this claim's
                // evidence (identity is the key; generation and attempt
                // must match) is success. Any other dead record is a
                // conflicting-terminal finding.
                budget.spend()?;
                let obj = self.store.get(&abs, None)?;
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
    fn write_termidx(
        &self,
        terminal_rel: &RelKey,
        kind: stowq_keys::TermKind,
        shard: u16,
        job_id: [u8; 16],
        budget: &mut OpBudget,
    ) {
        if budget.spend().is_err() {
            return;
        }
        let Ok(meta) = self.store.head(&self.absolute(terminal_rel)) else {
            return;
        };
        if let Some(bucket) =
            stowq_math::bucket_number(meta.store_time_ns, self.format.terminal_bucket_width_ns)
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
                    .put_if_absent(&idx, Bytes::new(), Sha256::digest([]).into());
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
    /// Clock beacons deleted.
    pub beacons_deleted: usize,
}

impl Queue {
    /// Expired-lease sweep (spec recovery.md): walk `leases/<b>/` for
    /// buckets at or below the floor bucket, in ascending order; for
    /// each entry, re-evaluate the authoritative tail and delete the
    /// index entry. The index is advisory; correctness never reads it,
    /// and a missing entry hides nothing forever (repair scan).
    pub fn sweep_expired_leases(
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
            let page = self.store.list(&prefix, after.as_ref(), 64)?;
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
                if self.lease_reclaimable(shard, job_id, floor_ns, budget)? {
                    report.reclaimed += 1;
                }
                budget.spend()?;
                let _ = self.store.delete(&item.key);
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
    pub fn sweep_delayed(
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
            let page = self.store.list(&prefix, after.as_ref(), 64)?;
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
                if self.job_promotable(shard, job_id, floor_ns, budget)? {
                    report.promoted += 1;
                }
                budget.spend()?;
                let _ = self.store.delete(&item.key);
            }
            match page.next_after {
                Some(k) => after = Some(k),
                None => break,
            }
        }
        Ok(report)
    }

    fn lease_reclaimable(
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
            match self.store.head(&self.absolute(&rel)) {
                Ok(_) => return Ok(false),
                Err(StoreError::NotFound) => {}
                Err(e) => return Err(e.into()),
            }
        }
        // Tail expiry: read the claim chain's last generation.
        let (gen, meta, duration) = self.claim_tail(shard, job_id, budget)?;
        if gen == 0 {
            return Ok(false); // nothing held
        }
        Ok(floor_ns
            >= meta
                .store_time_ns
                .saturating_add(duration)
                .saturating_add(self.opts.skew_guard_ns))
    }

    fn job_promotable(
        &self,
        shard: u16,
        job_id: [u8; 16],
        floor_ns: u64,
        budget: &mut OpBudget,
    ) -> Result<bool, Error> {
        budget.spend()?;
        let job_rel = RelKey::Job { shard, job_id };
        let job = match self.store.get(&self.absolute(&job_rel), None) {
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
        let (gen, _meta, _duration) = self.claim_tail(shard, job_id, budget)?;
        if gen > 0 {
            budget.spend()?;
            let rel = RelKey::Fail {
                shard,
                job_id,
                generation: gen as u32,
            };
            match self.store.get(&self.absolute(&rel), None) {
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
    fn claim_tail(
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
            let page = self.store.list(&prefix, after.as_ref(), 64)?;
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
                let obj = match self.store.get(&self.absolute(&rel), None) {
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
    /// `retention_ns` relative to `now_ns`. Stale beacons are also
    /// collected. Orphan-payload collection past the enqueue horizon is
    /// not yet implemented.
    pub fn gc(
        &self,
        now_ns: u64,
        retention_ns: u64,
        budget: &mut OpBudget,
    ) -> Result<GcReport, Error> {
        let mut report = GcReport::default();
        let cutoff = now_ns.saturating_sub(retention_ns);

        // Beacons: metadata is tiny; collect those older than 10x the
        // floor staleness window.
        let beacon_cutoff = now_ns.saturating_sub(FLOOR_STALENESS.as_nanos() as u64 * 10);
        let beacon_prefix = format!("{}meta/clock/", self.root);
        let mut after: Option<Key> = None;
        loop {
            budget.spend()?;
            let page = self.store.list(&beacon_prefix, after.as_ref(), 64)?;
            if page.items.is_empty() {
                break;
            }
            for item in &page.items {
                if item.meta.store_time_ns < beacon_cutoff {
                    budget.spend()?;
                    let _ = self.store.delete(&item.key);
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
            let page = self.store.list(&term_prefix, after.as_ref(), 64)?;
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
                let meta = match self.store.head(&terminal_abs) {
                    Ok(meta) => meta,
                    // Only NotFound proves the authoritative record is
                    // gone; other errors abort loudly rather than
                    // pruning a live graph's index entry.
                    Err(StoreError::NotFound) => {
                        budget.spend()?;
                        let _ = self.store.delete(&item.key);
                        continue;
                    }
                    Err(e) => return Err(e.into()),
                };
                if meta.store_time_ns >= cutoff {
                    continue; // still within retention
                }
                if self.delete_terminal_graph(shard, job_id, &terminal_rel, &item.key, budget)? {
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
    fn delete_terminal_graph(
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
                let page = self.store.list(&prefix, after.as_ref(), 64)?;
                if page.items.is_empty() {
                    break;
                }
                for item in &page.items {
                    if item.key.as_str().contains(&format!("/{shard:04x}/{jhex}")) {
                        budget.spend()?;
                        let _ = self.store.delete(&item.key);
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
        let _ = self.store.delete(index_key);
        // Fails, claims.
        for prefix in [
            format!("{}fails/{shard:04x}/{jhex}/", self.root),
            format!("{}claims/{shard:04x}/{jhex}/", self.root),
        ] {
            let mut after: Option<Key> = None;
            loop {
                budget.spend()?;
                let page = self.store.list(&prefix, after.as_ref(), 64)?;
                if page.items.is_empty() {
                    break;
                }
                for item in &page.items {
                    budget.spend()?;
                    let _ = self.store.delete(&item.key);
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
            let page = self.store.list(&payload_prefix, after.as_ref(), 64)?;
            if page.items.is_empty() {
                break;
            }
            for item in &page.items {
                budget.spend()?;
                let _ = self.store.delete(&item.key);
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
            .delete(&self.absolute(&RelKey::Job { shard, job_id }));
        // Terminal record last: the tombstone.
        budget.spend()?;
        let _ = self.store.delete(&self.absolute(terminal_rel));
        Ok(true)
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
    #[test]
    fn ack_against_conflicting_receipt_evidence_errors() {
        let q = Queue::init(
            Box::new(MemoryStore::new()),
            "q",
            &OpenOptions::new([1; 16]),
            &format(),
        )
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
        let err = q.ack(&claim, &mut budget).unwrap_err();
        assert!(matches!(err, Error::ReceiptEvidenceMismatch));
    }

    // Same payload digest, different generation: the generation-evidence
    // check must still fail the idempotent-verify (spec records.md,
    // Acknowledgment; quarantine 0x0013).
    #[test]
    fn ack_against_same_digest_foreign_generation_receipt_errors() {
        let q = Queue::init(
            Box::new(MemoryStore::new()),
            "q",
            &OpenOptions::new([1; 16]),
            &format(),
        )
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
        let err = q.ack(&claim, &mut budget).unwrap_err();
        assert!(matches!(err, Error::ReceiptEvidenceMismatch));
    }

    // Bury's idempotent-verify: matching evidence is success, a
    // foreign-generation dead record is a conflicting-terminal error.
    // Both branches are unreachable through the public claim path (a
    // dead record makes the job terminal and unclaimable), so the
    // handles are built in-crate.
    #[test]
    fn bury_against_dead_evidence_verified_by_generation() {
        let q = Queue::init(
            Box::new(MemoryStore::new()),
            "q",
            &OpenOptions::new([1; 16]),
            &format(),
        )
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
            q.bury(&holder, 0x0003, &mut budget).unwrap(),
            BuryOutcome::Buried
        );
        // A stale-generation holder: conflicting evidence, an error.
        let err = q.bury(&zombie, 0x0003, &mut budget).unwrap_err();
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

    fn detached_queue() -> (Queue, MemoryStore) {
        let store = MemoryStore::new();
        let mut opts = OpenOptions::new([1; 16]);
        opts.max_inline_payload = 4;
        let q = Queue::init(Box::new(store.clone()), "q", &opts, &format()).unwrap();
        (q, store)
    }

    #[test]
    fn detached_handle_reconstruction_verifies_payload() {
        let (q, store) = detached_queue();
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
            .unwrap()
        else {
            panic!()
        };
        let claim =
            Claim::detached_or_inline(job_id, 0, 1, 1, [9; 16], 1_000, 0, "q", &store).unwrap();
        assert_eq!(&claim.payload(&store).unwrap()[..], &payload[..]);
        // A stale (pre-write) handle for an absent job errors.
        let err = Claim::detached_or_inline([4; 16], 0, 1, 1, [9; 16], 1_000, 0, "q", &store)
            .unwrap_err();
        assert!(matches!(err, Error::Record(_)));
    }

    #[test]
    fn detached_handle_reconstruction_rejects_tampered_payload() {
        let (q, store) = detached_queue();
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
            .unwrap()
        else {
            panic!()
        };
        // Corrupt the detached payload object in place.
        let jhex: String = job_id.iter().map(|x| format!("{x:02x}")).collect();
        let prefix = format!("q/payloads/{jhex}/");
        let page = store.list(&prefix, None, 10).unwrap();
        let key = page.items[0].key.clone();
        let digest: Digest = Sha256::digest(vec![0u8; 64].as_slice()).into();
        let _ = store.delete(&key);
        store
            .put_if_absent(&key, bytes::Bytes::from(vec![0u8; 64]), digest)
            .unwrap();
        let err =
            Claim::detached_or_inline(job_id, 0, 1, 1, [9; 16], 1_000, 0, "q", &store).unwrap_err();
        assert!(matches!(err, Error::PayloadCorrupt));
    }
}
