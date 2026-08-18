//! Full queue lifecycle over the fetch-based backend: the same
//! lifecycle the SDK-backend conformance runs, through every core
//! path (init, enqueue detached, claim, deliver, ack, idempotent
//! re-ack). Env-gated like the rest of the conformance suite.

#![cfg(feature = "native")]

use stowq_core::{
    AckOutcome, ClaimOptions, ClaimOutcome, EnqueueInput, EnqueueOutcome, OpBudget, OpenOptions,
    Queue,
};
use stowq_format::FormatRecord;

fn endpoint() -> Option<String> {
    std::env::var("STOWQ_CONFORMANCE_ENDPOINT").ok()
}

fn format() -> FormatRecord {
    FormatRecord {
        shard_count: 4,
        lease_bucket_width_ns: 1_000_000_000,
        delayed_bucket_width_ns: 1_000_000_000,
        terminal_bucket_width_ns: 1_000_000_000,
        inline_limit: 4_096,
        required_feature_bits: 0,
    }
}

async fn open(root: &str, max_inline: u64) -> Queue {
    let cfg = stowq_store_http::HttpStoreConfig {
        region: std::env::var("AWS_REGION").unwrap_or_else(|_| "auto".into()),
        endpoint: endpoint().expect("endpoint"),
        force_path_style: true,
        bucket: std::env::var("STOWQ_CONFORMANCE_BUCKET")
            .unwrap_or_else(|_| "stowq-conformance".into()),
        access_key: std::env::var("AWS_ACCESS_KEY_ID").expect("key"),
        secret_key: std::env::var("AWS_SECRET_ACCESS_KEY").expect("secret"),
        session_token: None,
    };
    let store = stowq_store_http::HttpStore::new(
        stowq_store_http::native::ReqwestTransport::new(),
        cfg,
        std::sync::Arc::new(stowq_store_http::SystemSigningClock),
    );
    let mut opts = OpenOptions::new([1; 16]);
    opts.max_inline_payload = max_inline;
    Queue::open(Box::new(store), root, opts).await.unwrap()
}

async fn init(root: &str) {
    let cfg = stowq_store_http::HttpStoreConfig {
        region: std::env::var("AWS_REGION").unwrap_or_else(|_| "auto".into()),
        endpoint: endpoint().expect("endpoint"),
        force_path_style: true,
        bucket: std::env::var("STOWQ_CONFORMANCE_BUCKET")
            .unwrap_or_else(|_| "stowq-conformance".into()),
        access_key: std::env::var("AWS_ACCESS_KEY_ID").expect("key"),
        secret_key: std::env::var("AWS_SECRET_ACCESS_KEY").expect("secret"),
        session_token: None,
    };
    let store = stowq_store_http::HttpStore::new(
        stowq_store_http::native::ReqwestTransport::new(),
        cfg,
        std::sync::Arc::new(stowq_store_http::SystemSigningClock),
    );
    let mut opts = OpenOptions::new([1; 16]);
    opts.max_inline_payload = 4_096;
    Queue::init(Box::new(store), root, &opts, &format())
        .await
        .unwrap();
}

#[tokio::test]
async fn lifecycle_certification() {
    let Some(_) = endpoint() else { return };
    let root = format!("httpc-{}", std::process::id());
    init(&root).await;
    let q = open(&root, 4).await;

    let mut b = OpBudget::new(512);
    let EnqueueOutcome::Committed { job_id } = q
        .enqueue(
            EnqueueInput {
                job_id: None,
                payload: b"http-backend-lifecycle",
                content_type: "text/plain".into(),
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

    let floor = q.establish_floor(&mut OpBudget::new(64)).await.unwrap();
    let mut claimed = None;
    for shard in 0..4u16 {
        let opts = ClaimOptions {
            shard,
            floor_ns: floor,
            lease_duration_ns: 60_000_000_000,
        };
        if let ClaimOutcome::Claimed(c) = q.claim(&opts, &mut OpBudget::new(512)).await.unwrap() {
            claimed = Some(c);
            break;
        }
    }
    let claim = claimed.expect("claimable");
    assert_eq!(claim.job_id, job_id);
    use stowq_store::ObjectStore as _;
    let payload = claim.payload(q.store()).await.unwrap();
    assert_eq!(&payload[..], b"http-backend-lifecycle");

    assert_eq!(q.ack(&claim, &mut b).await.unwrap(), AckOutcome::Acked);
    assert_eq!(
        q.ack(&claim, &mut b).await.unwrap(),
        AckOutcome::AlreadyAcked
    );
}
