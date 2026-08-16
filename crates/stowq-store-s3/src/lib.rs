//! S3-compatible backend: R2, S3, MinIO. Conditional writes map to
//! `If-None-Match: *` (P1) and `If-Match` (P2); every transport result
//! is classified into the store taxonomy before it crosses this
//! boundary.
//!
//! Store time is quantized to whole seconds on every surface: the
//! S3-family profile declares G = 1s, and providers differ in which
//! surface exposes sub-second precision, so all times are truncated to
//! the profile granularity for consistency. Lease arithmetic is in
//! nanoseconds; `skew_guard >= G` absorbs the quantization.
//!
//! The bridge is synchronous over the async SDK through a dedicated
//! runtime: do not construct `S3Store` from an async context on the
//! same runtime thread. The CLI and the conformance harness are sync
//! callers.

use aws_sdk_s3::error::SdkError;
use aws_sdk_s3::primitives::ByteStream;
use std::ops::Range;
use std::time::Duration;
use stowq_store::{
    Ambiguity, Digest, Key, Listing, Meta, Object, ObjectStore, Page, PutOutcome, StoreError,
    StoreResult, TransportClass, Version,
};

const SECOND_NS: u64 = 1_000_000_000;

pub struct S3Config {
    pub region: String,
    pub endpoint: Option<String>,
    /// Path-style addressing (MinIO); virtual-host style otherwise.
    pub force_path_style: bool,
}

pub struct S3Store {
    client: aws_sdk_s3::Client,
    bucket: String,
    runtime: tokio::runtime::Runtime,
}

fn quantize(nanos: i128) -> u64 {
    (nanos.div_euclid(SECOND_NS as i128) * SECOND_NS as i128) as u64
}

fn base64_std(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[(n >> 18) as usize & 0x3f] as char);
        out.push(TABLE[(n >> 12) as usize & 0x3f] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(n >> 6) as usize & 0x3f] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[n as usize & 0x3f] as char
        } else {
            '='
        });
    }
    out
}

fn status_of<E>(e: &SdkError<E>) -> Option<u16> {
    match e {
        SdkError::ServiceError(svc) => Some(svc.raw().status().as_u16()),
        _ => None,
    }
}

/// Read-path errors: 404 is absence; 5xx is transient server state on
/// an idempotent operation (unknown — callers re-read); other service
/// errors are protocol failures; the rest classify by transport class.
fn read_err<E>(e: SdkError<E>) -> StoreError {
    match status_of(&e) {
        Some(404) => StoreError::NotFound,
        Some(status) if status >= 500 => StoreError::OutcomeUnknown(Ambiguity::AmbiguousResponse),
        Some(_) => StoreError::ProfileViolation(format!("read rejected: {e}")),
        None => classify_send_err(&e),
    }
}

fn classify_send_err<E>(e: &SdkError<E>) -> StoreError {
    match e {
        // The request was transmitted and no verdict arrived: unknown.
        SdkError::TimeoutError(_) | SdkError::ResponseError(_) => {
            StoreError::OutcomeUnknown(Ambiguity::Timeout)
        }
        SdkError::DispatchFailure(d) if d.is_timeout() => {
            StoreError::OutcomeUnknown(Ambiguity::ConnectionLost)
        }
        // Never transmitted (construction, credentials): safe retry.
        SdkError::DispatchFailure(d) if d.is_user() => {
            StoreError::Transport(TransportClass::PreTransmit)
        }
        // Connector failure without a verdict: unknown.
        SdkError::DispatchFailure(_) => StoreError::OutcomeUnknown(Ambiguity::ConnectionLost),
        _ => StoreError::ProfileViolation(format!("unexpected sdk error class: {e}")),
    }
}

impl S3Store {
    pub fn new(config: &aws_config::SdkConfig, s3: &S3Config, bucket: impl Into<String>) -> Self {
        let region = config
            .region()
            .map(|r| r.to_string())
            .unwrap_or_else(|| s3.region.clone());
        let mut builder = aws_sdk_s3::config::Builder::from(config)
            .behavior_version(aws_sdk_s3::config::BehaviorVersion::latest())
            .region(aws_sdk_s3::config::Region::new(region))
            .timeout_config(
                aws_sdk_s3::config::timeout::TimeoutConfig::builder()
                    .operation_timeout(Duration::from_secs(30))
                    .build(),
            );
        if let Some(endpoint) = &s3.endpoint {
            builder = builder.endpoint_url(endpoint);
        }
        builder = builder.force_path_style(s3.force_path_style);
        S3Store {
            client: aws_sdk_s3::Client::from_conf(builder.build()),
            bucket: bucket.into(),
            runtime: tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("tokio runtime"),
        }
    }

    async fn put_conditional(
        &self,
        key: &Key,
        body: bytes::Bytes,
        sha256: &Digest,
        if_match: Option<&Version>,
    ) -> StoreResult<PutOutcome> {
        use sha2::Digest as _;
        let got: Digest = sha2::Sha256::digest(&body).into();
        if &got != sha256 {
            return Err(StoreError::IntegrityViolation(
                stowq_store::IntegrityKind::DigestMismatch,
            ));
        }
        let mut req = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(key.as_str())
            .body(ByteStream::from(body))
            .checksum_sha256(base64_std(sha256));
        if let Some(v) = if_match {
            req = req.if_match(&v.0);
        } else {
            req = req.if_none_match("*");
        }
        match req.send().await {
            Ok(out) => {
                let etag = out.e_tag().unwrap_or_default().to_string();
                Ok(PutOutcome::Committed {
                    version: Version(etag),
                })
            }
            Err(e) => match status_of(&e) {
                Some(412) => Ok(PutOutcome::Rejected),
                Some(status) if status >= 500 => {
                    // A 5xx may have applied the write: unknown.
                    Err(StoreError::OutcomeUnknown(Ambiguity::AmbiguousResponse))
                }
                Some(_) => Err(StoreError::ProfileViolation(format!("put rejected: {e}"))),
                None => Err(classify_send_err(&e)),
            },
        }
    }
}

impl ObjectStore for S3Store {
    fn put_if_absent(
        &self,
        key: &Key,
        body: bytes::Bytes,
        sha256: Digest,
    ) -> StoreResult<PutOutcome> {
        self.runtime
            .block_on(self.put_conditional(key, body, &sha256, None))
    }

    fn cas(
        &self,
        key: &Key,
        body: bytes::Bytes,
        sha256: Digest,
        if_match: &Version,
    ) -> StoreResult<PutOutcome> {
        self.runtime
            .block_on(self.put_conditional(key, body, &sha256, Some(if_match)))
    }

    fn get(&self, key: &Key, range: Option<Range<u64>>) -> StoreResult<Object> {
        self.runtime.block_on(async {
            let mut req = self
                .client
                .get_object()
                .bucket(&self.bucket)
                .key(key.as_str());
            if let Some(r) = &range {
                // Inclusive end byte.
                req = req.range(format!("bytes={}-{}", r.start, r.end.saturating_sub(1)));
            }
            match req.send().await {
                Ok(out) => {
                    let meta = Meta {
                        version: Version(out.e_tag.clone().unwrap_or_default()),
                        store_time_ns: out
                            .last_modified
                            .map(|t| quantize(t.as_nanos()))
                            .unwrap_or(0),
                        size: out.content_length.unwrap_or(0) as u64,
                    };
                    let body = out
                        .body
                        .collect()
                        .await
                        .map_err(|_| StoreError::OutcomeUnknown(Ambiguity::ConnectionLost))?
                        .into_bytes();
                    Ok(Object { meta, body })
                }
                Err(e) => Err(read_err(e)),
            }
        })
    }

    fn head(&self, key: &Key) -> StoreResult<Meta> {
        self.runtime.block_on(async {
            match self
                .client
                .head_object()
                .bucket(&self.bucket)
                .key(key.as_str())
                .send()
                .await
            {
                Ok(out) => Ok(Meta {
                    version: Version(out.e_tag.clone().unwrap_or_default()),
                    store_time_ns: out
                        .last_modified
                        .map(|t| quantize(t.as_nanos()))
                        .unwrap_or(0),
                    size: out.content_length.unwrap_or(0) as u64,
                }),
                Err(e) => Err(read_err(e)),
            }
        })
    }

    fn list(&self, prefix: &str, after: Option<&Key>, limit: usize) -> StoreResult<Page> {
        self.runtime.block_on(async {
            let mut req = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(prefix)
                .max_keys((limit as i32).clamp(1, 1000));
            if let Some(a) = after {
                req = req.start_after(a.as_str());
            }
            match req.send().await {
                Ok(out) => {
                    let mut items = Vec::new();
                    for o in out.contents() {
                        let Some(k) = o.key() else { continue };
                        // start_after is inclusive; the contract is
                        // exclusive-after.
                        if let Some(a) = after {
                            if k <= a.as_str() {
                                continue;
                            }
                        }
                        items.push(Listing {
                            key: Key::new(k),
                            meta: Meta {
                                version: Version(o.e_tag.clone().unwrap_or_default()),
                                store_time_ns: o
                                    .last_modified
                                    .map(|t| quantize(t.as_nanos()))
                                    .unwrap_or(0),
                                size: o.size.unwrap_or(0) as u64,
                            },
                        });
                    }
                    let next_after = if out.is_truncated().unwrap_or(false) {
                        items.last().map(|l| l.key.clone())
                    } else {
                        None
                    };
                    Ok(Page { items, next_after })
                }
                Err(e) => Err(classify_send_err(&e)),
            }
        })
    }

    fn delete(&self, key: &Key) -> StoreResult<()> {
        self.runtime.block_on(async {
            match self
                .client
                .delete_object()
                .bucket(&self.bucket)
                .key(key.as_str())
                .send()
                .await
            {
                // S3 delete is idempotent: a missing key is success.
                Ok(_) => Ok(()),
                Err(e) => match status_of(&e) {
                    Some(404) => Ok(()),
                    _ => Err(read_err(e)),
                },
            }
        })
    }
}
