//! Live-store conformance for the fetch-based backend: the same
//! certification the SDK backend passes, against the same endpoints
//! (MinIO in CI, R2 for re-certification). This is the authority for
//! the hand-rolled SigV4: a passing run means the signer, the
//! conditional-write mapping, the range contract, and the list XML
//! parsing are all byte-compatible with a real store.
//!
//! Configuration is the conformance suite's standard environment.

#![cfg(feature = "native")]

use bytes::Bytes;
use sha2::{Digest as _, Sha256};
use stowq_store::{Key, ObjectStore, PutOutcome, StoreError};

fn endpoint() -> Option<String> {
    std::env::var("STOWQ_CONFORMANCE_ENDPOINT").ok()
}

async fn store() -> stowq_store_http::HttpStore<stowq_store_http::native::ReqwestTransport> {
    let endpoint = endpoint().expect("STOWQ_CONFORMANCE_ENDPOINT");
    let cfg = stowq_store_http::HttpStoreConfig {
        region: std::env::var("AWS_REGION").unwrap_or_else(|_| "auto".into()),
        endpoint,
        force_path_style: true,
        bucket: std::env::var("STOWQ_CONFORMANCE_BUCKET")
            .unwrap_or_else(|_| "stowq-conformance".into()),
        access_key: std::env::var("AWS_ACCESS_KEY_ID").expect("AWS_ACCESS_KEY_ID"),
        secret_key: std::env::var("AWS_SECRET_ACCESS_KEY").expect("AWS_SECRET_ACCESS_KEY"),
        session_token: None,
    };
    stowq_store_http::HttpStore::new(
        stowq_store_http::native::ReqwestTransport::new(),
        cfg,
        std::sync::Arc::new(stowq_store_http::SystemSigningClock),
    )
}

fn digest(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

fn run_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    format!(
        "{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    )
}

#[tokio::test]
async fn primitives_certification() {
    let Some(_) = endpoint() else { return };
    let s = store().await;
    let run = run_id();

    // P1: put-if-absent atomic; second write rejects.
    let k = Key::new(format!("conformance/http/{run}/p1"));
    let a = s
        .put_if_absent(&k, Bytes::from_static(b"a"), digest(b"a"))
        .await
        .unwrap();
    let b = s
        .put_if_absent(&k, Bytes::from_static(b"b"), digest(b"b"))
        .await
        .unwrap();
    assert!(matches!(a, PutOutcome::Committed { .. }));
    assert_eq!(b, PutOutcome::Rejected);
    assert_eq!(&s.get(&k, None).await.unwrap().body[..], b"a");

    // P1 integrity: digest mismatch refuses without writing.
    let k2 = Key::new(format!("conformance/http/{run}/p1-mismatch"));
    let err = s
        .put_if_absent(&k2, Bytes::from_static(b"x"), digest(b"y"))
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::IntegrityViolation(_)));
    assert_eq!(s.head(&k2).await.unwrap_err(), StoreError::NotFound);

    // P2: CAS commits against the current version; stale rejects.
    let PutOutcome::Committed { version } = s
        .put_if_absent(&k2, Bytes::from_static(b"v1"), digest(b"v1"))
        .await
        .unwrap()
    else {
        panic!()
    };
    let stale = stowq_store::Version("deadbeef".into());
    assert_eq!(
        s.cas(&k2, Bytes::from_static(b"x"), digest(b"x"), &stale)
            .await
            .unwrap(),
        PutOutcome::Rejected
    );
    assert!(matches!(
        s.cas(&k2, Bytes::from_static(b"v2"), digest(b"v2"), &version)
            .await
            .unwrap(),
        PutOutcome::Committed { .. }
    ));
    assert_eq!(&s.get(&k2, None).await.unwrap().body[..], b"v2");

    // P3/P6: read-after-write with a nonzero store time.
    let meta = s.head(&k).await.unwrap();
    assert!(meta.store_time_ns > 0, "P6: server-assigned time");
    assert_eq!(meta.size, 1);

    // P4: listing sees the writes; after-marker is exclusive.
    let prefix = format!("conformance/http/{run}/");
    let page = s.list(&prefix, None, 10).await.unwrap();
    assert!(page.items.iter().any(|l| l.key.as_str().ends_with("p1")));
    let after = Key::new(format!("conformance/http/{run}/p1"));
    let next = s.list(&prefix, Some(&after), 10).await.unwrap();
    assert!(next
        .items
        .iter()
        .all(|l| l.key.as_str() > format!("conformance/http/{run}/p1").as_str()));

    // Range contract: meta.size is the FULL size on ranged reads
    // (1..2 on a 2-byte object distinguishes part-length from size).
    let obj = s.get(&k2, Some(1..2)).await.unwrap();
    assert_eq!(&obj.body[..], b"2");
    assert_eq!(obj.meta.size, 2);
    let tail = s.get(&k2, Some(0..2)).await.unwrap();
    assert_eq!(&tail.body[..], b"v2");
    assert_eq!(
        s.get(&k2, Some(0..3)).await.unwrap_err(),
        StoreError::NotFound
    );
    assert_eq!(
        s.get(&k2, Some(5..6)).await.unwrap_err(),
        StoreError::NotFound
    );
    assert_eq!(
        s.get(&k2, Some(1..1)).await.unwrap_err(),
        StoreError::NotFound
    );
    let zero = s.list(&prefix, None, 0).await.unwrap();
    assert!(zero.items.is_empty());
    assert_eq!(zero.next_after, None);

    // Cleanup for reruns.
    let _ = s.delete(&k).await;
    let _ = s.delete(&k2).await;
}

#[tokio::test]
async fn keys_with_special_characters_roundtrip() {
    let Some(_) = endpoint() else { return };
    let s = store().await;
    let run = run_id();
    // The uri-encoding path exercised end-to-end: spaces, unicode, and
    // XML-escapable characters in the key.
    let k = Key::new(format!("conformance/http/{run}/a b&c+d=ü"));
    s.put_if_absent(&k, Bytes::from_static(b"enc"), digest(b"enc"))
        .await
        .unwrap();
    assert_eq!(&s.get(&k, None).await.unwrap().body[..], b"enc");
    let page = s
        .list(&format!("conformance/http/{run}/"), None, 10)
        .await
        .unwrap();
    let found = page
        .items
        .iter()
        .find(|l| l.key.as_str().contains("a b&c"))
        .expect("escaped key listed with unescaped name");
    assert_eq!(found.meta.size, 3);
    let _ = s.delete(&k).await;
}
