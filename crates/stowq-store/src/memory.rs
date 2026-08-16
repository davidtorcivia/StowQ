//! In-memory fake conforming to the primitive contract. Assigns strictly
//! monotone nanosecond store times from a logical clock; the step is
//! configurable so tests can control ordering granularity.

use crate::{
    Digest, Key, Listing, Meta, Object, ObjectStore, Page, PutOutcome, StoreError, StoreResult,
    Version,
};
use async_trait::async_trait;
use bytes::Bytes;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::ops::Range;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// A persisted object: key, body, version, store time.
pub type SnapshotEntry = (String, Vec<u8>, u64, u64);

struct Stored {
    body: Bytes,
    version: u64,
    store_time_ns: u64,
}

/// Clones share state: one logical store, many handles.
#[derive(Clone)]
pub struct MemoryStore {
    objects: Arc<Mutex<BTreeMap<String, Stored>>>,
    version_counter: Arc<AtomicU64>,
    clock: Arc<AtomicU64>,
    tick_step_ns: u64,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::with_tick_step_ns(1)
    }

    /// Store times advance by `tick_step_ns` per write. Panics on zero:
    /// a zero step cannot satisfy strict monotonicity.
    pub fn with_tick_step_ns(tick_step_ns: u64) -> Self {
        assert!(tick_step_ns > 0, "tick step must be positive");
        MemoryStore {
            objects: Arc::new(Mutex::new(BTreeMap::new())),
            version_counter: Arc::new(AtomicU64::new(1)),
            clock: Arc::new(AtomicU64::new(1)),
            tick_step_ns,
        }
    }

    /// Full-state snapshot: (key, body, version, store_time_ns) per
    /// object, plus the version counter and clock. For persistence and
    /// test tooling.
    pub fn snapshot_raw(&self) -> (Vec<SnapshotEntry>, u64, u64) {
        let objects = self.objects.lock().unwrap();
        let out = objects
            .iter()
            .map(|(k, s)| (k.clone(), s.body.to_vec(), s.version, s.store_time_ns))
            .collect();
        (
            out,
            self.version_counter.load(Ordering::SeqCst),
            self.clock.load(Ordering::SeqCst),
        )
    }

    /// Replaces the store's contents from a snapshot. Only for fresh
    /// stores (init paths); merging into a live store is unsupported.
    pub fn restore_raw(
        &self,
        objects: Vec<(String, Vec<u8>, u64, u64)>,
        next_version: u64,
        clock: u64,
    ) {
        let mut map = self.objects.lock().unwrap();
        for (k, body, version, store_time_ns) in objects {
            map.insert(
                k,
                Stored {
                    body: Bytes::from(body),
                    version,
                    store_time_ns,
                },
            );
        }
        self.version_counter.store(next_version, Ordering::SeqCst);
        self.clock.store(clock, Ordering::SeqCst);
    }

    /// Raises the logical clock so the next write's store time is at
    /// least `ns + tick_step_ns`. Lower values are ignored; the clock
    /// never moves backwards.
    pub fn advance_clock_to(&self, ns: u64) {
        self.clock.fetch_max(ns, Ordering::SeqCst);
    }

    fn next_version(&self) -> u64 {
        self.version_counter.fetch_add(1, Ordering::SeqCst)
    }

    fn next_time(&self) -> u64 {
        self.clock.fetch_add(self.tick_step_ns, Ordering::SeqCst) + self.tick_step_ns
    }

    fn verify(body: &Bytes, sha256: &Digest) -> StoreResult<()> {
        let mut hasher = Sha256::new();
        hasher.update(body);
        let got: Digest = hasher.finalize().into();
        if &got != sha256 {
            return Err(StoreError::IntegrityViolation(
                crate::IntegrityKind::DigestMismatch,
            ));
        }
        Ok(())
    }
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ObjectStore for MemoryStore {
    async fn put_if_absent(
        &self,
        key: &Key,
        body: Bytes,
        sha256: Digest,
    ) -> StoreResult<PutOutcome> {
        Self::verify(&body, &sha256)?;
        let mut objects = self.objects.lock().unwrap();
        if objects.contains_key(&key.0) {
            return Ok(PutOutcome::Rejected);
        }
        let version = self.next_version();
        let store_time_ns = self.next_time();
        objects.insert(
            key.0.clone(),
            Stored {
                body,
                version,
                store_time_ns,
            },
        );
        Ok(PutOutcome::Committed {
            version: Version(version.to_string()),
        })
    }

    async fn cas(
        &self,
        key: &Key,
        body: Bytes,
        sha256: Digest,
        if_match: &Version,
    ) -> StoreResult<PutOutcome> {
        Self::verify(&body, &sha256)?;
        let mut objects = self.objects.lock().unwrap();
        match objects.get_mut(&key.0) {
            None => Err(StoreError::NotFound),
            Some(stored) => {
                if stored.version.to_string() != if_match.0 {
                    return Ok(PutOutcome::Rejected);
                }
                let version = self.next_version();
                let store_time_ns = self.next_time();
                stored.body = body;
                stored.version = version;
                stored.store_time_ns = store_time_ns;
                Ok(PutOutcome::Committed {
                    version: Version(version.to_string()),
                })
            }
        }
    }

    async fn get(&self, key: &Key, range: Option<Range<u64>>) -> StoreResult<Object> {
        let objects = self.objects.lock().unwrap();
        let stored = objects.get(&key.0).ok_or(StoreError::NotFound)?;
        let size = stored.body.len() as u64;
        let body = match range {
            None => stored.body.clone(),
            Some(r) => {
                // Strict half-open contract: start < end <= size. This
                // subsumes start-past-EOF (end would exceed size) and
                // rejects empty and inverted ranges.
                if r.start >= r.end || r.end > size {
                    return Err(StoreError::NotFound);
                }
                stored.body.slice(r.start as usize..r.end as usize)
            }
        };
        Ok(Object {
            meta: Meta {
                version: Version(stored.version.to_string()),
                store_time_ns: stored.store_time_ns,
                size,
            },
            body,
        })
    }

    async fn head(&self, key: &Key) -> StoreResult<Meta> {
        let objects = self.objects.lock().unwrap();
        let stored = objects.get(&key.0).ok_or(StoreError::NotFound)?;
        Ok(Meta {
            version: Version(stored.version.to_string()),
            store_time_ns: stored.store_time_ns,
            size: stored.body.len() as u64,
        })
    }

    async fn list(&self, prefix: &str, after: Option<&Key>, limit: usize) -> StoreResult<Page> {
        let objects = self.objects.lock().unwrap();
        let mut items = Vec::new();
        let mut last_key = None;
        for (k, stored) in objects.range(after.map(|a| a.0.as_str()).unwrap_or("").to_string()..) {
            if let Some(a) = after {
                if k <= &a.0 {
                    continue;
                }
            }
            if !k.starts_with(prefix) {
                // Keys are sorted; a miss past the prefix range can stop
                // the scan only when k > prefix's upper bound, but a
                // simple starts_with filter is correct and cheap enough
                // for a fake.
                continue;
            }
            if items.len() == limit {
                return Ok(Page {
                    items,
                    next_after: last_key,
                });
            }
            items.push(Listing {
                key: Key(k.clone()),
                meta: Meta {
                    version: Version(stored.version.to_string()),
                    store_time_ns: stored.store_time_ns,
                    size: stored.body.len() as u64,
                },
            });
            last_key = Some(Key(k.clone()));
        }
        Ok(Page {
            items,
            next_after: None,
        })
    }

    async fn delete(&self, key: &Key) -> StoreResult<()> {
        self.objects.lock().unwrap().remove(&key.0);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(b: &[u8]) -> Digest {
        let mut h = Sha256::new();
        h.update(b);
        h.finalize().into()
    }

    #[tokio::test]
    async fn put_if_absent_first_wins() {
        let store = MemoryStore::new();
        let k = Key::new("jobs/0001/a");
        let a = store
            .put_if_absent(&k, Bytes::from_static(b"one"), digest(b"one"))
            .await
            .unwrap();
        let b = store
            .put_if_absent(&k, Bytes::from_static(b"two"), digest(b"two"))
            .await
            .unwrap();
        assert!(matches!(a, PutOutcome::Committed { .. }));
        assert_eq!(b, PutOutcome::Rejected);
        assert_eq!(store.get(&k, None).await.unwrap().body, &b"one"[..]);
    }

    #[tokio::test]
    async fn put_rejects_digest_mismatch_without_writing() {
        let store = MemoryStore::new();
        let k = Key::new("jobs/0001/a");
        let err = store
            .put_if_absent(&k, Bytes::from_static(b"one"), digest(b"other"))
            .await
            .unwrap_err();
        assert_eq!(
            err,
            StoreError::IntegrityViolation(crate::IntegrityKind::DigestMismatch)
        );
        assert_eq!(store.head(&k).await.unwrap_err(), StoreError::NotFound);
    }

    #[tokio::test]
    async fn cas_requires_matching_version() {
        let store = MemoryStore::new();
        let k = Key::new("meta/watermark");
        let PutOutcome::Committed { version } = store
            .put_if_absent(&k, Bytes::from_static(b"v1"), digest(b"v1"))
            .await
            .unwrap()
        else {
            panic!("first put must commit");
        };
        let stale = Version("999".into());
        assert_eq!(
            store
                .cas(&k, Bytes::from_static(b"x"), digest(b"x"), &stale)
                .await
                .unwrap(),
            PutOutcome::Rejected
        );
        let ok = store
            .cas(&k, Bytes::from_static(b"v2"), digest(b"v2"), &version)
            .await
            .unwrap();
        let PutOutcome::Committed { version: v2 } = ok else {
            panic!("cas must commit");
        };
        assert_ne!(version, v2);
        assert_eq!(store.get(&k, None).await.unwrap().body, &b"v2"[..]);
    }

    #[tokio::test]
    async fn cas_missing_key_is_not_found() {
        let store = MemoryStore::new();
        let err = store
            .cas(
                &Key::new("meta/watermark"),
                Bytes::from_static(b"v"),
                digest(b"v"),
                &Version("1".into()),
            )
            .await
            .unwrap_err();
        assert_eq!(err, StoreError::NotFound);
    }

    #[tokio::test]
    async fn store_times_are_strictly_monotone() {
        let store = MemoryStore::new();
        let times: Vec<u64> = {
            let mut v = Vec::new();
            for i in 0..5 {
                let k = Key::new(format!("jobs/0001/{i}"));
                store
                    .put_if_absent(&k, Bytes::from_static(b"x"), digest(b"x"))
                    .await
                    .unwrap();
                v.push(store.head(&k).await.unwrap().store_time_ns);
            }
            v
        };
        assert!(times.windows(2).all(|w| w[0] < w[1]));
    }

    #[tokio::test]
    async fn advance_clock_raises_and_never_lowers() {
        let store = MemoryStore::with_tick_step_ns(10);
        let k1 = Key::new("a");
        store
            .put_if_absent(&k1, Bytes::from_static(b"x"), digest(b"x"))
            .await
            .unwrap();
        let t1 = store.head(&k1).await.unwrap().store_time_ns;
        // Advancing above the clock pins the next write past it.
        store.advance_clock_to(t1 + 1000);
        let k2 = Key::new("b");
        store
            .put_if_absent(&k2, Bytes::from_static(b"x"), digest(b"x"))
            .await
            .unwrap();
        let t2 = store.head(&k2).await.unwrap().store_time_ns;
        assert!(t2 > t1 + 1000, "t2 {t2} must exceed the advanced clock");
        // Advancing below the clock is ignored.
        store.advance_clock_to(t1);
        let k3 = Key::new("c");
        store
            .put_if_absent(&k3, Bytes::from_static(b"x"), digest(b"x"))
            .await
            .unwrap();
        assert!(store.head(&k3).await.unwrap().store_time_ns > t2);
    }

    #[test]
    #[should_panic(expected = "tick step must be positive")]
    fn zero_tick_step_panics() {
        let _ = MemoryStore::with_tick_step_ns(0);
    }

    #[tokio::test]
    async fn overwrite_gets_a_new_time_and_version() {
        let store = MemoryStore::new();
        let k = Key::new("meta/watermark");
        let PutOutcome::Committed { version } = store
            .put_if_absent(&k, Bytes::from_static(b"1"), digest(b"1"))
            .await
            .unwrap()
        else {
            panic!()
        };
        let t1 = store.head(&k).await.unwrap().store_time_ns;
        store
            .cas(&k, Bytes::from_static(b"2"), digest(b"2"), &version)
            .await
            .unwrap();
        let meta = store.head(&k).await.unwrap();
        assert!(meta.store_time_ns > t1);
        assert_eq!(meta.version, Version("2".into()));
    }

    #[tokio::test]
    async fn list_paginates_in_lexicographic_order() {
        let store = MemoryStore::new();
        for name in [
            "claims/0001/a/1",
            "claims/0001/a/2",
            "claims/0001/a/3",
            "dead/0001/a",
        ] {
            let k = Key::new(name);
            store
                .put_if_absent(&k, Bytes::from_static(b"x"), digest(b"x"))
                .await
                .unwrap();
        }
        let page1 = store.list("claims/", None, 2).await.unwrap();
        assert_eq!(page1.items.len(), 2);
        assert_eq!(page1.items[0].key.as_str(), "claims/0001/a/1");
        assert_eq!(page1.items[1].key.as_str(), "claims/0001/a/2");
        let after = page1.next_after.clone().unwrap();
        let page2 = store.list("claims/", Some(&after), 2).await.unwrap();
        assert_eq!(page2.items.len(), 1);
        assert_eq!(page2.items[0].key.as_str(), "claims/0001/a/3");
        assert_eq!(page2.next_after, None);
    }

    #[tokio::test]
    async fn list_after_excludes_the_marker() {
        let store = MemoryStore::new();
        for i in 1..=3 {
            let k = Key::new(format!("claims/0001/a/{i}"));
            store
                .put_if_absent(&k, Bytes::from_static(b"x"), digest(b"x"))
                .await
                .unwrap();
        }
        let after = Key::new("claims/0001/a/1");
        let page = store.list("claims/", Some(&after), 10).await.unwrap();
        assert_eq!(page.items.len(), 2);
        assert_eq!(page.items[0].key.as_str(), "claims/0001/a/2");
    }

    #[tokio::test]
    async fn get_range_slices() {
        let store = MemoryStore::new();
        let k = Key::new("payloads/a/d");
        store
            .put_if_absent(
                &k,
                Bytes::from_static(b"hello stowq"),
                digest(b"hello stowq"),
            )
            .await
            .unwrap();
        let obj = store.get(&k, Some(6..11)).await.unwrap();
        assert_eq!(obj.body, &b"stowq"[..]);
        assert_eq!(obj.meta.size, 11);
        assert_eq!(
            store.get(&k, Some(5..12)).await.unwrap_err(),
            StoreError::NotFound
        );
    }

    #[tokio::test]
    async fn get_range_rejects_bad_bounds() {
        let store = MemoryStore::new();
        let k = Key::new("payloads/a/d");
        store
            .put_if_absent(
                &k,
                Bytes::from_static(b"hello stowq"),
                digest(b"hello stowq"),
            )
            .await
            .unwrap();
        // The range contract is start < end <= size: empty, inverted,
        // and past-EOF ranges are all absence.
        assert_eq!(
            store.get(&k, Some(5..5)).await.unwrap_err(),
            StoreError::NotFound
        );
        assert_eq!(
            store.get(&k, Some(11..11)).await.unwrap_err(),
            StoreError::NotFound
        );
        assert_eq!(
            store.get(&k, Some(12..12)).await.unwrap_err(),
            StoreError::NotFound
        );
        assert_eq!(
            store
                .get(&k, Some(Range { start: 5, end: 2 }))
                .await
                .unwrap_err(),
            StoreError::NotFound
        );
        assert_eq!(
            store.get(&k, Some(0..12)).await.unwrap_err(),
            StoreError::NotFound
        );
        // The boundary end == size returns the tail through EOF.
        let obj = store.get(&k, Some(6..11)).await.unwrap();
        assert_eq!(&obj.body[..], b"stowq");
        assert_eq!(obj.meta.size, 11);
    }

    #[tokio::test]
    async fn list_with_limit_zero_is_empty_and_terminal() {
        let store = MemoryStore::new();
        let k = Key::new("claims/0001/a/1");
        store
            .put_if_absent(&k, Bytes::from_static(b"x"), digest(b"x"))
            .await
            .unwrap();
        let page = store.list("claims/", None, 0).await.unwrap();
        assert!(page.items.is_empty());
        assert_eq!(page.next_after, None);
    }

    #[tokio::test]
    async fn delete_is_idempotent() {
        let store = MemoryStore::new();
        let k = Key::new("jobs/0001/a");
        store
            .put_if_absent(&k, Bytes::from_static(b"x"), digest(b"x"))
            .await
            .unwrap();
        store.delete(&k).await.unwrap();
        store.delete(&k).await.unwrap();
        assert_eq!(store.head(&k).await.unwrap_err(), StoreError::NotFound);
    }
}
