//! The store boundary: the trait, the error taxonomy, an in-memory fake,
//! and a fault injector.
//!
//! Every backend classifies transport results into the taxonomy below
//! before they cross this boundary. Expected protocol outcomes (a lost
//! precondition race) are `Ok` values; failures (ambiguity, transport,
//! integrity, profile breakage) are `Err`.

pub mod injector;
pub mod memory;

pub use injector::{Fault, FaultPlan, Injector, Op};
pub use memory::MemoryStore;

use bytes::Bytes;
use std::fmt;
use std::ops::Range;
use thiserror::Error;

pub type Digest = [u8; 32];

/// Opaque store version token (ETag or equivalent).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Version(pub String);

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Store key. A newtype over the string form; grammar validation is the
/// caller's concern (see stowq-keys).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Key(pub String);

impl Key {
    pub fn new(s: impl Into<String>) -> Self {
        Key(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Object {
    pub meta: Meta,
    pub body: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Meta {
    pub version: Version,
    /// Store-assigned creation time via the profile's declared surface.
    pub store_time_ns: u64,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listing {
    pub key: Key,
    pub meta: Meta,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    pub items: Vec<Listing>,
    /// Set when more keys may follow; pass as `after` to continue.
    pub next_after: Option<Key>,
}

/// Outcome of a conditional write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PutOutcome {
    /// The linearization point completed; the store acknowledged the write.
    Committed { version: Version },
    /// The precondition failed: someone else won the race, or the version
    /// did not match. Provably not committed.
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum Ambiguity {
    #[error("timed out after transmit")]
    Timeout,
    #[error("connection lost after transmit")]
    ConnectionLost,
    #[error("server returned an ambiguous error")]
    AmbiguousResponse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TransportClass {
    /// Provably raised before the request was transmitted; a blind retry
    /// is safe.
    #[error("connection failed before transmit")]
    PreTransmit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum IntegrityKind {
    #[error("object body does not match its digest")]
    DigestMismatch,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum StoreError {
    /// The write may or may not have committed; the caller must resolve
    /// (re-read the target key) before retrying.
    #[error("outcome unknown: {0}")]
    OutcomeUnknown(Ambiguity),
    #[error("key not found")]
    NotFound,
    #[error("integrity violation: {0}")]
    IntegrityViolation(IntegrityKind),
    /// The store broke a certified primitive promise; fail loud.
    #[error("store profile violation: {0}")]
    ProfileViolation(String),
    #[error("transport failure: {0}")]
    Transport(TransportClass),
}

pub type StoreResult<T> = Result<T, StoreError>;

/// The store primitive contract (see spec/store-profiles.md). Object-safe;
/// backends and wrappers (injector, future caching layers) share one type.
pub trait ObjectStore: Send + Sync {
    /// Atomic create. `sha256` is verified against `body` (P7); a mismatch
    /// fails with `IntegrityViolation` without writing.
    fn put_if_absent(&self, key: &Key, body: Bytes, sha256: Digest) -> StoreResult<PutOutcome>;

    /// Atomic overwrite conditional on the current version (P2).
    fn cas(
        &self,
        key: &Key,
        body: Bytes,
        sha256: Digest,
        if_match: &Version,
    ) -> StoreResult<PutOutcome>;

    /// Reads the object, or a byte range of it. The range is half-open
    /// `[start, end)` and must satisfy `start < end <= size`: an
    /// empty, inverted, or past-EOF range is `NotFound`, on every
    /// backend. A backend that would clamp a past-EOF end (an HTTP
    /// 206 partial) reports `NotFound` rather than returning fewer
    /// bytes than requested.
    fn get(&self, key: &Key, range: Option<Range<u64>>) -> StoreResult<Object>;

    fn head(&self, key: &Key) -> StoreResult<Meta>;

    /// Strongly consistent listing in lexicographic order (P4), starting
    /// strictly after `after` when given.
    fn list(&self, prefix: &str, after: Option<&Key>, limit: usize) -> StoreResult<Page>;

    /// Idempotent delete (GC only).
    fn delete(&self, key: &Key) -> StoreResult<()>;
}
