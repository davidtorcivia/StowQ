//! In-memory fake conforming to the primitive contract. Assigns strictly
//! monotone nanosecond store times from a logical clock; the step is
//! configurable so tests can control ordering granularity.

use crate::{
    Digest, Key, Listing, Meta, Object, ObjectStore, Page, PutOutcome, StoreError, StoreResult,
    Version,
};
use bytes::Bytes;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::ops::Range;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

struct Stored {
    body: Bytes,
    version: u64,
    store_time_ns: u64,
}

pub struct MemoryStore {
    objects: Mutex<BTreeMap<String, Stored>>,
    version_counter: AtomicU64,
    clock: AtomicU64,
    tick_step_ns: u64,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::with_tick_step_ns(1)
    }

    /// Store times advance by `tick_step_ns` per write.
    pub fn with_tick_step_ns(tick_step_ns: u64) -> Self {
        MemoryStore {
            objects: Mutex::new(BTreeMap::new()),
            version_counter: AtomicU64::new(1),
            clock: AtomicU64::new(1),
            tick_step_ns,
        }
    }

    /// Forces the next write's store time. The clock only moves forward:
    /// a lower value is ignored.
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

impl ObjectStore for MemoryStore {
    fn put_if_absent(&self, key: &Key, body: Bytes, sha256: Digest) -> StoreResult<PutOutcome> {
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

    fn cas(
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

    fn get(&self, key: &Key, range: Option<Range<u64>>) -> StoreResult<Object> {
        let objects = self.objects.lock().unwrap();
        let stored = objects.get(&key.0).ok_or(StoreError::NotFound)?;
        let size = stored.body.len() as u64;
        let body = match range {
            None => stored.body.clone(),
            Some(r) => {
                if r.start >= size || r.end > size || r.start > r.end {
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

    fn head(&self, key: &Key) -> StoreResult<Meta> {
        let objects = self.objects.lock().unwrap();
        let stored = objects.get(&key.0).ok_or(StoreError::NotFound)?;
        Ok(Meta {
            version: Version(stored.version.to_string()),
            store_time_ns: stored.store_time_ns,
            size: stored.body.len() as u64,
        })
    }

    fn list(&self, prefix: &str, after: Option<&Key>, limit: usize) -> StoreResult<Page> {
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

    fn delete(&self, key: &Key) -> StoreResult<()> {
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

    #[test]
    fn put_if_absent_first_wins() {
        let store = MemoryStore::new();
        let k = Key::new("jobs/0001/a");
        let a = store
            .put_if_absent(&k, Bytes::from_static(b"one"), digest(b"one"))
            .unwrap();
        let b = store
            .put_if_absent(&k, Bytes::from_static(b"two"), digest(b"two"))
            .unwrap();
        assert!(matches!(a, PutOutcome::Committed { .. }));
        assert_eq!(b, PutOutcome::Rejected);
        assert_eq!(store.get(&k, None).unwrap().body, &b"one"[..]);
    }

    #[test]
    fn put_rejects_digest_mismatch_without_writing() {
        let store = MemoryStore::new();
        let k = Key::new("jobs/0001/a");
        let err = store
            .put_if_absent(&k, Bytes::from_static(b"one"), digest(b"other"))
            .unwrap_err();
        assert_eq!(
            err,
            StoreError::IntegrityViolation(crate::IntegrityKind::DigestMismatch)
        );
        assert_eq!(store.head(&k).unwrap_err(), StoreError::NotFound);
    }

    #[test]
    fn cas_requires_matching_version() {
        let store = MemoryStore::new();
        let k = Key::new("meta/watermark");
        let PutOutcome::Committed { version } = store
            .put_if_absent(&k, Bytes::from_static(b"v1"), digest(b"v1"))
            .unwrap()
        else {
            panic!("first put must commit");
        };
        let stale = Version("999".into());
        assert_eq!(
            store
                .cas(&k, Bytes::from_static(b"x"), digest(b"x"), &stale)
                .unwrap(),
            PutOutcome::Rejected
        );
        let ok = store
            .cas(&k, Bytes::from_static(b"v2"), digest(b"v2"), &version)
            .unwrap();
        let PutOutcome::Committed { version: v2 } = ok else {
            panic!("cas must commit");
        };
        assert_ne!(version, v2);
        assert_eq!(store.get(&k, None).unwrap().body, &b"v2"[..]);
    }

    #[test]
    fn cas_missing_key_is_not_found() {
        let store = MemoryStore::new();
        let err = store
            .cas(
                &Key::new("meta/watermark"),
                Bytes::from_static(b"v"),
                digest(b"v"),
                &Version("1".into()),
            )
            .unwrap_err();
        assert_eq!(err, StoreError::NotFound);
    }

    #[test]
    fn store_times_are_strictly_monotone() {
        let store = MemoryStore::new();
        let times: Vec<u64> = (0..5)
            .map(|i| {
                let k = Key::new(format!("jobs/0001/{i}"));
                store
                    .put_if_absent(&k, Bytes::from_static(b"x"), digest(b"x"))
                    .unwrap();
                store.head(&k).unwrap().store_time_ns
            })
            .collect();
        assert!(times.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn advance_clock_never_moves_backwards() {
        let store = MemoryStore::with_tick_step_ns(10);
        let k1 = Key::new("a");
        store
            .put_if_absent(&k1, Bytes::from_static(b"x"), digest(b"x"))
            .unwrap();
        let t1 = store.head(&k1).unwrap().store_time_ns;
        store.advance_clock_to(t1 - 5);
        let k2 = Key::new("b");
        store
            .put_if_absent(&k2, Bytes::from_static(b"x"), digest(b"x"))
            .unwrap();
        assert!(store.head(&k2).unwrap().store_time_ns > t1);
    }

    #[test]
    fn overwrite_gets_a_new_time_and_version() {
        let store = MemoryStore::new();
        let k = Key::new("meta/watermark");
        let PutOutcome::Committed { version } = store
            .put_if_absent(&k, Bytes::from_static(b"1"), digest(b"1"))
            .unwrap()
        else {
            panic!()
        };
        let t1 = store.head(&k).unwrap().store_time_ns;
        store
            .cas(&k, Bytes::from_static(b"2"), digest(b"2"), &version)
            .unwrap();
        let meta = store.head(&k).unwrap();
        assert!(meta.store_time_ns > t1);
        assert_eq!(meta.version, Version("2".into()));
    }

    #[test]
    fn list_paginates_in_lexicographic_order() {
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
                .unwrap();
        }
        let page1 = store.list("claims/", None, 2).unwrap();
        assert_eq!(page1.items.len(), 2);
        assert_eq!(page1.items[0].key.as_str(), "claims/0001/a/1");
        assert_eq!(page1.items[1].key.as_str(), "claims/0001/a/2");
        let after = page1.next_after.clone().unwrap();
        let page2 = store.list("claims/", Some(&after), 2).unwrap();
        assert_eq!(page2.items.len(), 1);
        assert_eq!(page2.items[0].key.as_str(), "claims/0001/a/3");
        assert_eq!(page2.next_after, None);
    }

    #[test]
    fn list_after_excludes_the_marker() {
        let store = MemoryStore::new();
        for i in 1..=3 {
            let k = Key::new(format!("claims/0001/a/{i}"));
            store
                .put_if_absent(&k, Bytes::from_static(b"x"), digest(b"x"))
                .unwrap();
        }
        let after = Key::new("claims/0001/a/1");
        let page = store.list("claims/", Some(&after), 10).unwrap();
        assert_eq!(page.items.len(), 2);
        assert_eq!(page.items[0].key.as_str(), "claims/0001/a/2");
    }

    #[test]
    fn get_range_slices() {
        let store = MemoryStore::new();
        let k = Key::new("payloads/a/d");
        store
            .put_if_absent(
                &k,
                Bytes::from_static(b"hello stowq"),
                digest(b"hello stowq"),
            )
            .unwrap();
        let obj = store.get(&k, Some(6..11)).unwrap();
        assert_eq!(obj.body, &b"stowq"[..]);
        assert_eq!(obj.meta.size, 11);
        assert_eq!(
            store.get(&k, Some(5..12)).unwrap_err(),
            StoreError::NotFound
        );
    }

    #[test]
    fn delete_is_idempotent() {
        let store = MemoryStore::new();
        let k = Key::new("jobs/0001/a");
        store
            .put_if_absent(&k, Bytes::from_static(b"x"), digest(b"x"))
            .unwrap();
        store.delete(&k).unwrap();
        store.delete(&k).unwrap();
        assert_eq!(store.head(&k).unwrap_err(), StoreError::NotFound);
    }
}
