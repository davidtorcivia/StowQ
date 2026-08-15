//! StowQ/1 record encoding and decoding.
//!
//! Every record is a canonical CBOR array
//! `[magic, major, minor, queue_id, key_tag, record_type, fields]` closed by
//! `record_digest = SHA256("StowQ-1-<type>\0" || canonical-cbor-of-the-array-
//! without-the-digest)`. Decoding verifies the digest before any field is
//! trusted and rejects unknown fields in v1.

pub mod cbor;

use cbor::Value;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

pub const MAGIC: u64 = 0x5354_4f57_5131_2d00;
pub const MAJOR: u64 = 1;
pub const MINOR: u64 = 0;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RecordError {
    #[error("cbor layer rejected the bytes")]
    Cbor(#[from] cbor::Error),
    #[error("bad magic")]
    Magic,
    #[error("unsupported version {0}.{1}")]
    Version(u64, u64),
    #[error("unexpected envelope length")]
    Envelope,
    #[error("unknown record type")]
    Type,
    #[error("digest mismatch")]
    Digest,
    #[error("malformed field: {0}")]
    Field(&'static str),
    #[error("unknown field: {0}")]
    UnknownField(String),
    #[error("missing field: {0}")]
    MissingField(&'static str),
}

fn type_name(t: u64) -> Option<&'static str> {
    Some(match t {
        1 => "format",
        2 => "job",
        3 => "claim",
        4 => "fail",
        5 => "receipt",
        6 => "dead",
        7 => "watermark",
        _ => return None,
    })
}

fn record_digest(type_str: &str, body: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(format!("StowQ-1-{type_str}\0").as_bytes());
    hasher.update(body);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

// ---------- Field helpers ----------

fn get_u64(map: &[(Value, Value)], key: &'static str) -> Result<u64, RecordError> {
    match map.iter().find(|(k, _)| k == &Value::Text(key.into())) {
        Some((_, Value::Uint(n))) => Ok(*n),
        Some(_) => Err(RecordError::Field("uint")),
        None => Err(RecordError::MissingField(key)),
    }
}

fn get_opt_u64(map: &[(Value, Value)], key: &str) -> Result<Option<u64>, RecordError> {
    match map.iter().find(|(k, _)| k == &Value::Text(key.into())) {
        Some((_, Value::Uint(n))) => Ok(Some(*n)),
        Some(_) => Err(RecordError::Field("uint")),
        None => Ok(None),
    }
}

fn get_bytes<const N: usize>(
    map: &[(Value, Value)],
    key: &'static str,
) -> Result<[u8; N], RecordError> {
    match map.iter().find(|(k, _)| k == &Value::Text(key.into())) {
        Some((_, Value::Bytes(b))) => b
            .len()
            .eq(&N)
            .then(|| {
                let mut out = [0u8; N];
                out.copy_from_slice(b);
                out
            })
            .ok_or(RecordError::Field("byte width")),
        Some(_) => Err(RecordError::Field("bytes")),
        None => Err(RecordError::MissingField(key)),
    }
}

fn get_text(map: &[(Value, Value)], key: &'static str) -> Result<String, RecordError> {
    match map.iter().find(|(k, _)| k == &Value::Text(key.into())) {
        Some((_, Value::Text(t))) => Ok(t.clone()),
        Some(_) => Err(RecordError::Field("text")),
        None => Err(RecordError::MissingField(key)),
    }
}

fn get_bool(map: &[(Value, Value)], key: &'static str) -> Result<bool, RecordError> {
    match map.iter().find(|(k, _)| k == &Value::Text(key.into())) {
        Some((_, Value::Bool(b))) => Ok(*b),
        Some(_) => Err(RecordError::Field("bool")),
        None => Err(RecordError::MissingField(key)),
    }
}

fn expect_keys(map: &[(Value, Value)], allowed: &[&str]) -> Result<(), RecordError> {
    for (k, _) in map {
        if let Value::Text(t) = k {
            if !allowed.contains(&t.as_str()) {
                return Err(RecordError::UnknownField(t.clone()));
            }
        } else {
            return Err(RecordError::Field("text key"));
        }
    }
    Ok(())
}

fn kv_u64(out: &mut Vec<(Value, Value)>, key: &str, v: u64) {
    out.push((Value::Text(key.into()), Value::Uint(v)));
}

fn kv_bytes<const N: usize>(out: &mut Vec<(Value, Value)>, key: &str, v: &[u8; N]) {
    out.push((Value::Text(key.into()), Value::Bytes(v.to_vec())));
}

fn kv_text(out: &mut Vec<(Value, Value)>, key: &str, v: &str) {
    out.push((Value::Text(key.into()), Value::Text(v.into())));
}

fn kv_bool(out: &mut Vec<(Value, Value)>, key: &str, v: bool) {
    out.push((Value::Text(key.into()), Value::Bool(v)));
}

// ---------- Records ----------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormatRecord {
    pub shard_count: u32,
    pub lease_bucket_width_ns: u64,
    pub delayed_bucket_width_ns: u64,
    pub terminal_bucket_width_ns: u64,
    pub inline_limit: u64,
    pub required_feature_bits: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobRecord {
    pub job_id: [u8; 16],
    pub maximum_attempts: u64,
    pub content_type: String,
    /// Store-assigned creation time, filled by read-back; 0 when absent.
    pub created_store_time_ns: u64,
    /// Wall-bucket floor for delayed delivery; None when not delayed.
    pub not_before_ns: Option<u64>,
    pub payload_digest: [u8; 32],
    pub payload_length: u64,
    /// Present iff the payload is inline and within the inline limit.
    pub payload_inline: Option<Vec<u8>>,
    /// Present iff the payload is detached.
    pub payload_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimBasis {
    pub prev_store_time_ns: u64,
    pub prev_duration_ns: u64,
    pub observed_watermark_ns: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimRecord {
    pub job_id: [u8; 16],
    pub generation: u64,
    pub attempt: u64,
    pub worker_id: String,
    pub worker_token: [u8; 16],
    pub lease_duration_ns: u64,
    pub continuation: bool,
    /// Takeover evidence; required iff continuation is false.
    pub basis: Option<ClaimBasis>,
    /// Custody evidence; required iff continuation is true.
    pub prev_token: Option<[u8; 16]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailRecord {
    pub job_id: [u8; 16],
    pub generation: u64,
    pub reason: u64,
    pub attempt: u64,
    pub retry_not_before_ns: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptRecord {
    pub job_id: [u8; 16],
    pub generation: u64,
    pub attempt: u64,
    pub worker_id: String,
    pub worker_token: [u8; 16],
    pub payload_digest: [u8; 32],
    pub output_digests: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeadRecord {
    pub job_id: [u8; 16],
    pub generation: u64,
    pub attempt: u64,
    pub reason: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatermarkRecord {
    pub highest_observed_wall_bucket: u64,
    pub sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    Format(FormatRecord),
    Job(JobRecord),
    Claim(ClaimRecord),
    Fail(FailRecord),
    Receipt(ReceiptRecord),
    Dead(DeadRecord),
    Watermark(WatermarkRecord),
}

impl Record {
    pub fn type_number(&self) -> u64 {
        match self {
            Record::Format(_) => 1,
            Record::Job(_) => 2,
            Record::Claim(_) => 3,
            Record::Fail(_) => 4,
            Record::Receipt(_) => 5,
            Record::Dead(_) => 6,
            Record::Watermark(_) => 7,
        }
    }

    fn fields(&self) -> Vec<(Value, Value)> {
        let mut m = Vec::new();
        match self {
            Record::Format(r) => {
                kv_u64(&mut m, "shard_count", r.shard_count as u64);
                kv_u64(&mut m, "lease_bucket_width_ns", r.lease_bucket_width_ns);
                kv_u64(&mut m, "delayed_bucket_width_ns", r.delayed_bucket_width_ns);
                kv_u64(
                    &mut m,
                    "terminal_bucket_width_ns",
                    r.terminal_bucket_width_ns,
                );
                kv_u64(&mut m, "inline_limit", r.inline_limit);
                kv_u64(&mut m, "required_feature_bits", r.required_feature_bits);
            }
            Record::Job(r) => {
                kv_bytes(&mut m, "job_id", &r.job_id);
                kv_u64(&mut m, "maximum_attempts", r.maximum_attempts);
                kv_text(&mut m, "content_type", &r.content_type);
                kv_u64(&mut m, "created_store_time_ns", r.created_store_time_ns);
                if let Some(nb) = r.not_before_ns {
                    kv_u64(&mut m, "not_before_ns", nb);
                }
                kv_bytes(&mut m, "payload_digest", &r.payload_digest);
                kv_u64(&mut m, "payload_length", r.payload_length);
                if let Some(inline) = &r.payload_inline {
                    m.push((
                        Value::Text("payload_inline".into()),
                        Value::Bytes(inline.clone()),
                    ));
                }
                if let Some(key) = &r.payload_key {
                    kv_text(&mut m, "payload_key", key);
                }
            }
            Record::Claim(r) => {
                kv_bytes(&mut m, "job_id", &r.job_id);
                kv_u64(&mut m, "generation", r.generation);
                kv_u64(&mut m, "attempt", r.attempt);
                kv_text(&mut m, "worker_id", &r.worker_id);
                kv_bytes(&mut m, "worker_token", &r.worker_token);
                kv_u64(&mut m, "lease_duration_ns", r.lease_duration_ns);
                kv_bool(&mut m, "continuation", r.continuation);
                if let Some(b) = &r.basis {
                    let mut bm = Vec::new();
                    kv_u64(&mut bm, "prev_store_time_ns", b.prev_store_time_ns);
                    kv_u64(&mut bm, "prev_duration_ns", b.prev_duration_ns);
                    kv_u64(&mut bm, "observed_watermark_ns", b.observed_watermark_ns);
                    m.push((Value::Text("basis".into()), Value::Map(bm)));
                }
                if let Some(pt) = &r.prev_token {
                    kv_bytes(&mut m, "prev_token", pt);
                }
            }
            Record::Fail(r) => {
                kv_bytes(&mut m, "job_id", &r.job_id);
                kv_u64(&mut m, "generation", r.generation);
                kv_u64(&mut m, "reason", r.reason);
                kv_u64(&mut m, "attempt", r.attempt);
                kv_u64(&mut m, "retry_not_before_ns", r.retry_not_before_ns);
            }
            Record::Receipt(r) => {
                kv_bytes(&mut m, "job_id", &r.job_id);
                kv_u64(&mut m, "generation", r.generation);
                kv_u64(&mut m, "attempt", r.attempt);
                kv_text(&mut m, "worker_id", &r.worker_id);
                kv_bytes(&mut m, "worker_token", &r.worker_token);
                kv_bytes(&mut m, "payload_digest", &r.payload_digest);
                if !r.output_digests.is_empty() {
                    let items = r
                        .output_digests
                        .iter()
                        .map(|d| Value::Bytes(d.to_vec()))
                        .collect();
                    m.push((Value::Text("output_digests".into()), Value::Array(items)));
                }
            }
            Record::Dead(r) => {
                kv_bytes(&mut m, "job_id", &r.job_id);
                kv_u64(&mut m, "generation", r.generation);
                kv_u64(&mut m, "attempt", r.attempt);
                kv_u64(&mut m, "reason", r.reason);
            }
            Record::Watermark(r) => {
                kv_u64(
                    &mut m,
                    "highest_observed_wall_bucket",
                    r.highest_observed_wall_bucket,
                );
                kv_u64(&mut m, "sequence", r.sequence);
            }
        }
        m
    }

    fn from_fields(t: u64, map: &[(Value, Value)]) -> Result<Record, RecordError> {
        let m = map;
        Ok(match t {
            1 => {
                expect_keys(
                    m,
                    &[
                        "shard_count",
                        "lease_bucket_width_ns",
                        "delayed_bucket_width_ns",
                        "terminal_bucket_width_ns",
                        "inline_limit",
                        "required_feature_bits",
                    ],
                )?;
                Record::Format(FormatRecord {
                    shard_count: get_u64(m, "shard_count")? as u32,
                    lease_bucket_width_ns: get_u64(m, "lease_bucket_width_ns")?,
                    delayed_bucket_width_ns: get_u64(m, "delayed_bucket_width_ns")?,
                    terminal_bucket_width_ns: get_u64(m, "terminal_bucket_width_ns")?,
                    inline_limit: get_u64(m, "inline_limit")?,
                    required_feature_bits: get_u64(m, "required_feature_bits")?,
                })
            }
            2 => {
                let mut allowed: Vec<&str> = vec![
                    "job_id",
                    "maximum_attempts",
                    "content_type",
                    "created_store_time_ns",
                    "payload_digest",
                    "payload_length",
                ];
                if map
                    .iter()
                    .any(|(k, _)| k == &Value::Text("not_before_ns".into()))
                {
                    allowed.push("not_before_ns");
                }
                if map
                    .iter()
                    .any(|(k, _)| k == &Value::Text("payload_inline".into()))
                {
                    allowed.push("payload_inline");
                }
                if map
                    .iter()
                    .any(|(k, _)| k == &Value::Text("payload_key".into()))
                {
                    allowed.push("payload_key");
                }
                expect_keys(m, &allowed)?;
                let payload_inline = match map
                    .iter()
                    .find(|(k, _)| k == &Value::Text("payload_inline".into()))
                {
                    Some((_, Value::Bytes(b))) => Some(b.clone()),
                    Some(_) => return Err(RecordError::Field("payload_inline")),
                    None => None,
                };
                let payload_key = match map
                    .iter()
                    .find(|(k, _)| k == &Value::Text("payload_key".into()))
                {
                    Some((_, Value::Text(t))) => Some(t.clone()),
                    Some(_) => return Err(RecordError::Field("payload_key")),
                    None => None,
                };
                if payload_inline.is_some() == payload_key.is_some() {
                    return Err(RecordError::Field("payload inline xor key"));
                }
                Record::Job(JobRecord {
                    job_id: get_bytes(m, "job_id")?,
                    maximum_attempts: get_u64(m, "maximum_attempts")?,
                    content_type: get_text(m, "content_type")?,
                    created_store_time_ns: get_u64(m, "created_store_time_ns")?,
                    not_before_ns: get_opt_u64(m, "not_before_ns")?,
                    payload_digest: get_bytes(m, "payload_digest")?,
                    payload_length: get_u64(m, "payload_length")?,
                    payload_inline,
                    payload_key,
                })
            }
            3 => {
                expect_keys(
                    m,
                    &[
                        "job_id",
                        "generation",
                        "attempt",
                        "worker_id",
                        "worker_token",
                        "lease_duration_ns",
                        "continuation",
                        "basis",
                        "prev_token",
                    ],
                )?;
                let continuation = get_bool(m, "continuation")?;
                let basis = match map.iter().find(|(k, _)| k == &Value::Text("basis".into())) {
                    Some((_, Value::Map(bm))) => {
                        expect_keys(
                            bm,
                            &[
                                "prev_store_time_ns",
                                "prev_duration_ns",
                                "observed_watermark_ns",
                            ],
                        )?;
                        Some(ClaimBasis {
                            prev_store_time_ns: get_u64(bm, "prev_store_time_ns")?,
                            prev_duration_ns: get_u64(bm, "prev_duration_ns")?,
                            observed_watermark_ns: get_u64(bm, "observed_watermark_ns")?,
                        })
                    }
                    Some(_) => return Err(RecordError::Field("basis")),
                    None => None,
                };
                let prev_token = match map
                    .iter()
                    .find(|(k, _)| k == &Value::Text("prev_token".into()))
                {
                    Some((_, Value::Bytes(b))) => Some(
                        b.len()
                            .eq(&16)
                            .then(|| {
                                let mut out = [0u8; 16];
                                out.copy_from_slice(b);
                                out
                            })
                            .ok_or(RecordError::Field("byte width"))?,
                    ),
                    Some(_) => return Err(RecordError::Field("prev_token")),
                    None => None,
                };
                if continuation == (basis.is_some())
                    || continuation != prev_token.is_some()
                    || basis.is_some() == prev_token.is_some()
                {
                    return Err(RecordError::Field("basis xor prev_token"));
                }
                Record::Claim(ClaimRecord {
                    job_id: get_bytes(m, "job_id")?,
                    generation: get_u64(m, "generation")?,
                    attempt: get_u64(m, "attempt")?,
                    worker_id: get_text(m, "worker_id")?,
                    worker_token: get_bytes(m, "worker_token")?,
                    lease_duration_ns: get_u64(m, "lease_duration_ns")?,
                    continuation,
                    basis,
                    prev_token,
                })
            }
            4 => {
                expect_keys(
                    m,
                    &[
                        "job_id",
                        "generation",
                        "reason",
                        "attempt",
                        "retry_not_before_ns",
                    ],
                )?;
                Record::Fail(FailRecord {
                    job_id: get_bytes(m, "job_id")?,
                    generation: get_u64(m, "generation")?,
                    reason: get_u64(m, "reason")?,
                    attempt: get_u64(m, "attempt")?,
                    retry_not_before_ns: get_u64(m, "retry_not_before_ns")?,
                })
            }
            5 => {
                expect_keys(
                    m,
                    &[
                        "job_id",
                        "generation",
                        "attempt",
                        "worker_id",
                        "worker_token",
                        "payload_digest",
                        "output_digests",
                    ],
                )?;
                let output_digests = match map
                    .iter()
                    .find(|(k, _)| k == &Value::Text("output_digests".into()))
                {
                    Some((_, Value::Array(items))) => {
                        if items.is_empty() {
                            // The encoder omits the field when empty; an
                            // explicit empty array is non-canonical.
                            return Err(RecordError::Field("output_digests"));
                        }
                        let mut out = Vec::new();
                        for item in items {
                            match item {
                                Value::Bytes(b) if b.len() == 32 => {
                                    let mut d = [0u8; 32];
                                    d.copy_from_slice(b);
                                    out.push(d);
                                }
                                _ => return Err(RecordError::Field("output_digests")),
                            }
                        }
                        out
                    }
                    Some(_) => return Err(RecordError::Field("output_digests")),
                    None => Vec::new(),
                };
                Record::Receipt(ReceiptRecord {
                    job_id: get_bytes(m, "job_id")?,
                    generation: get_u64(m, "generation")?,
                    attempt: get_u64(m, "attempt")?,
                    worker_id: get_text(m, "worker_id")?,
                    worker_token: get_bytes(m, "worker_token")?,
                    payload_digest: get_bytes(m, "payload_digest")?,
                    output_digests,
                })
            }
            6 => {
                expect_keys(m, &["job_id", "generation", "attempt", "reason"])?;
                Record::Dead(DeadRecord {
                    job_id: get_bytes(m, "job_id")?,
                    generation: get_u64(m, "generation")?,
                    attempt: get_u64(m, "attempt")?,
                    reason: get_u64(m, "reason")?,
                })
            }
            7 => {
                expect_keys(m, &["highest_observed_wall_bucket", "sequence"])?;
                Record::Watermark(WatermarkRecord {
                    highest_observed_wall_bucket: get_u64(m, "highest_observed_wall_bucket")?,
                    sequence: get_u64(m, "sequence")?,
                })
            }
            _ => return Err(RecordError::Type),
        })
    }
}

/// Encodes a record against a queue identity and its canonical key. The
/// `key_tag` binds the record to the key (see stowq-keys).
pub fn encode(record: &Record, queue_id: &[u8; 16], key_tag: &[u8; 8]) -> Vec<u8> {
    let body = Value::Array(vec![
        Value::Uint(MAGIC),
        Value::Uint(MAJOR),
        Value::Uint(MINOR),
        Value::Bytes(queue_id.to_vec()),
        Value::Bytes(key_tag.to_vec()),
        Value::Uint(record.type_number()),
        Value::Map(record.fields()),
    ]);
    let body_bytes = cbor::encode(&body);
    let digest = record_digest(type_name(record.type_number()).unwrap(), &body_bytes);
    let mut out = body_bytes.clone();
    // The digest is appended as a trailing byte string, outside the digested
    // body: appending keeps the digest input a valid standalone CBOR value.
    let mut digest_enc = Vec::with_capacity(33);
    digest_enc.push(0x58);
    digest_enc.push(32);
    digest_enc.extend_from_slice(&digest);
    out.extend_from_slice(&digest_enc);
    out
}

/// Decodes and fully verifies a record: envelope shape, version, digest,
/// and field-level strictness. Unknown fields are rejected.
pub fn decode(data: &[u8], queue_id: &[u8; 16], key_tag: &[u8; 8]) -> Result<Record, RecordError> {
    // Split the trailing 34-byte digest (2-byte head + 32 bytes).
    if data.len() < 34 {
        return Err(RecordError::Envelope);
    }
    let (body, tail) = data.split_at(data.len() - 34);
    if tail[0] != 0x58 || tail[1] != 32 {
        return Err(RecordError::Envelope);
    }
    let body_value = cbor::decode(body)?;
    let envelope = match body_value {
        Value::Array(items) => items,
        _ => return Err(RecordError::Envelope),
    };
    if envelope.len() != 7 {
        return Err(RecordError::Envelope);
    }
    let (magic, major, minor, qid, tag, rtype, fields) = match (
        &envelope[0],
        &envelope[1],
        &envelope[2],
        &envelope[3],
        &envelope[4],
        &envelope[5],
        &envelope[6],
    ) {
        (
            Value::Uint(magic),
            Value::Uint(major),
            Value::Uint(minor),
            Value::Bytes(qid),
            Value::Bytes(tag),
            Value::Uint(rtype),
            Value::Map(fields),
        ) => (magic, major, minor, qid, tag, rtype, fields),
        _ => return Err(RecordError::Envelope),
    };
    if *magic != MAGIC {
        return Err(RecordError::Magic);
    }
    if *major != MAJOR || *minor != MINOR {
        return Err(RecordError::Version(*major, *minor));
    }
    // Digest before binding: no field is trusted on an unverifiable body.
    let type_str = type_name(*rtype).ok_or(RecordError::Type)?;
    let expected = record_digest(type_str, body);
    if expected[..] != tail[2..] {
        return Err(RecordError::Digest);
    }
    if qid.as_slice() != queue_id || tag.as_slice() != key_tag {
        return Err(RecordError::Field("queue binding"));
    }
    Record::from_fields(*rtype, fields)
}

#[cfg(test)]
mod tests {
    use super::*;

    const Q: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    const TAG: [u8; 8] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22];

    fn job_record() -> Record {
        Record::Job(JobRecord {
            job_id: [0x10; 16],
            maximum_attempts: 5,
            content_type: "application/octet-stream".into(),
            created_store_time_ns: 0,
            not_before_ns: None,
            payload_digest: [0xab; 32],
            payload_length: 4,
            payload_inline: Some(vec![1, 2, 3, 4]),
            payload_key: None,
        })
    }

    fn takeover_claim() -> Record {
        Record::Claim(ClaimRecord {
            job_id: [0x10; 16],
            generation: 2,
            attempt: 2,
            worker_id: "worker-1".into(),
            worker_token: [0xcd; 16],
            lease_duration_ns: 60_000_000_000,
            continuation: false,
            basis: Some(ClaimBasis {
                prev_store_time_ns: 1_000,
                prev_duration_ns: 60_000_000_000,
                observed_watermark_ns: 61_000_000_000,
            }),
            prev_token: None,
        })
    }

    #[test]
    fn all_record_types_round_trip() {
        let records = vec![
            Record::Format(FormatRecord {
                shard_count: 256,
                lease_bucket_width_ns: 60_000_000_000,
                delayed_bucket_width_ns: 300_000_000_000,
                terminal_bucket_width_ns: 3_600_000_000_000,
                inline_limit: 4_096,
                required_feature_bits: 0,
            }),
            job_record(),
            takeover_claim(),
            Record::Claim(ClaimRecord {
                job_id: [0x10; 16],
                generation: 3,
                attempt: 2,
                worker_id: "worker-1".into(),
                worker_token: [0xcd; 16],
                lease_duration_ns: 60_000_000_000,
                continuation: true,
                basis: None,
                prev_token: Some([0xcd; 16]),
            }),
            Record::Fail(FailRecord {
                job_id: [0x10; 16],
                generation: 1,
                reason: 0x0001,
                attempt: 1,
                retry_not_before_ns: 123_456,
            }),
            Record::Receipt(ReceiptRecord {
                job_id: [0x10; 16],
                generation: 2,
                attempt: 2,
                worker_id: "worker-1".into(),
                worker_token: [0xcd; 16],
                payload_digest: [0xab; 32],
                output_digests: vec![[0x99; 32]],
            }),
            Record::Dead(DeadRecord {
                job_id: [0x10; 16],
                generation: 5,
                attempt: 5,
                reason: 0x0004,
            }),
            Record::Watermark(WatermarkRecord {
                highest_observed_wall_bucket: 42,
                sequence: 7,
            }),
        ];
        for record in records {
            let bytes = encode(&record, &Q, &TAG);
            assert_eq!(decode(&bytes, &Q, &TAG), Ok(record), "round trip failed");
        }
    }

    #[test]
    fn encoding_is_deterministic() {
        let a = encode(&job_record(), &Q, &TAG);
        let b = encode(&job_record(), &Q, &TAG);
        assert_eq!(a, b);
    }

    #[test]
    fn digest_mismatch_rejected() {
        let mut bytes = encode(&job_record(), &Q, &TAG);
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        assert_eq!(decode(&bytes, &Q, &TAG), Err(RecordError::Digest));
    }

    #[test]
    fn wrong_queue_or_tag_rejected() {
        let bytes = encode(&job_record(), &Q, &TAG);
        let other = [0xff; 16];
        assert_eq!(
            decode(&bytes, &other, &TAG),
            Err(RecordError::Field("queue binding"))
        );
        let other_tag = [0xff; 8];
        assert_eq!(
            decode(&bytes, &Q, &other_tag),
            Err(RecordError::Field("queue binding"))
        );
    }

    #[test]
    fn tampered_body_rejected_by_digest() {
        let mut bytes = encode(&job_record(), &Q, &TAG);
        // Flip a bit inside the fields map, not the trailing digest.
        bytes[30] ^= 0x01;
        assert_eq!(decode(&bytes, &Q, &TAG), Err(RecordError::Digest));
    }

    #[test]
    fn unknown_field_rejected() {
        let record = job_record();
        let mut fields = record.fields();
        fields.push((Value::Text("future_field".into()), Value::Uint(1)));
        let body = Value::Array(vec![
            Value::Uint(MAGIC),
            Value::Uint(MAJOR),
            Value::Uint(MINOR),
            Value::Bytes(Q.to_vec()),
            Value::Bytes(TAG.to_vec()),
            Value::Uint(2),
            Value::Map(fields),
        ]);
        let body_bytes = cbor::encode(&body);
        let digest = record_digest("job", &body_bytes);
        let mut out = body_bytes;
        out.push(0x58);
        out.push(32);
        out.extend_from_slice(&digest);
        assert_eq!(
            decode(&out, &Q, &TAG),
            Err(RecordError::UnknownField("future_field".into()))
        );
    }

    #[test]
    fn claim_evidence_exclusivity_enforced() {
        // continuation=true but basis present instead of prev_token.
        let bad = ClaimRecord {
            job_id: [0x10; 16],
            generation: 3,
            attempt: 2,
            worker_id: "worker-1".into(),
            worker_token: [0xcd; 16],
            lease_duration_ns: 60_000_000_000,
            continuation: true,
            basis: Some(ClaimBasis {
                prev_store_time_ns: 1_000,
                prev_duration_ns: 60_000_000_000,
                observed_watermark_ns: 61_000_000_000,
            }),
            prev_token: None,
        };
        let bytes = encode(&Record::Claim(bad), &Q, &TAG);
        assert_eq!(
            decode(&bytes, &Q, &TAG),
            Err(RecordError::Field("basis xor prev_token"))
        );

        // continuation=false with neither basis nor prev_token.
        let bad2 = ClaimRecord {
            continuation: false,
            basis: None,
            prev_token: None,
            ..match takeover_claim() {
                Record::Claim(c) => c,
                _ => unreachable!(),
            }
        };
        let bytes2 = encode(&Record::Claim(bad2), &Q, &TAG);
        assert_eq!(
            decode(&bytes2, &Q, &TAG),
            Err(RecordError::Field("basis xor prev_token"))
        );

        // continuation=true with prev_token absent: no custody proof.
        let bad3 = ClaimRecord {
            continuation: true,
            basis: None,
            prev_token: None,
            ..match takeover_claim() {
                Record::Claim(c) => c,
                _ => unreachable!(),
            }
        };
        let bytes3 = encode(&Record::Claim(bad3), &Q, &TAG);
        assert_eq!(
            decode(&bytes3, &Q, &TAG),
            Err(RecordError::Field("basis xor prev_token"))
        );

        // takeover carrying both basis and prev_token.
        let bad4 = ClaimRecord {
            prev_token: Some([0xcd; 16]),
            ..match takeover_claim() {
                Record::Claim(c) => c,
                _ => unreachable!(),
            }
        };
        let bytes4 = encode(&Record::Claim(bad4), &Q, &TAG);
        assert_eq!(
            decode(&bytes4, &Q, &TAG),
            Err(RecordError::Field("basis xor prev_token"))
        );
    }

    #[test]
    fn empty_output_digests_array_rejected() {
        // Hand-build a valid-digest receipt whose output_digests is an
        // empty array: the encoder omits the field when empty, so an
        // explicit empty array is non-canonical.
        let receipt = Record::Receipt(ReceiptRecord {
            job_id: [0x10; 16],
            generation: 2,
            attempt: 2,
            worker_id: "worker-1".into(),
            worker_token: [0xcd; 16],
            payload_digest: [0xab; 32],
            output_digests: vec![],
        });
        let mut fields = receipt.fields();
        fields.push((Value::Text("output_digests".into()), Value::Array(vec![])));
        let body = Value::Array(vec![
            Value::Uint(MAGIC),
            Value::Uint(MAJOR),
            Value::Uint(MINOR),
            Value::Bytes(Q.to_vec()),
            Value::Bytes(TAG.to_vec()),
            Value::Uint(5),
            Value::Map(fields),
        ]);
        let body_bytes = cbor::encode(&body);
        let digest = record_digest("receipt", &body_bytes);
        let mut out = body_bytes;
        out.push(0x58);
        out.push(32);
        out.extend_from_slice(&digest);
        assert_eq!(
            decode(&out, &Q, &TAG),
            Err(RecordError::Field("output_digests"))
        );
    }

    #[test]
    fn truncated_and_garbage_rejected() {
        let bytes = encode(&job_record(), &Q, &TAG);
        assert_eq!(decode(&bytes[..10], &Q, &TAG), Err(RecordError::Envelope));
        // Short garbage fails the envelope length guard before CBOR parsing.
        assert_eq!(decode(&[0xff, 0xff], &Q, &TAG), Err(RecordError::Envelope));
        // Garbage with a well-formed digest tail reaches the CBOR layer.
        let mut garbage = vec![0xff; 6];
        garbage.extend_from_slice(&[0x58, 0x20]);
        garbage.extend_from_slice(&[0x00; 32]);
        assert_eq!(
            decode(&garbage, &Q, &TAG),
            Err(RecordError::Cbor(cbor::Error::IndefiniteLength))
        );
    }

    #[test]
    fn job_payload_exactly_one_of_inline_or_key() {
        let base = match job_record() {
            Record::Job(j) => j,
            _ => unreachable!(),
        };
        // Key set, inline absent: round trips.
        let key_only = Record::Job(JobRecord {
            payload_inline: None,
            payload_key: Some("payloads/<j>/<d>".into()),
            ..base.clone()
        });
        let bytes = encode(&key_only, &Q, &TAG);
        assert_eq!(decode(&bytes, &Q, &TAG), Ok(key_only));
        // Both set: rejected on decode.
        let both = Record::Job(JobRecord {
            payload_key: Some("payloads/<j>/<d>".into()),
            ..base.clone()
        });
        let bytes = encode(&both, &Q, &TAG);
        assert_eq!(
            decode(&bytes, &Q, &TAG),
            Err(RecordError::Field("payload inline xor key"))
        );
        // Neither set: rejected on decode.
        let neither = Record::Job(JobRecord {
            payload_inline: None,
            ..base
        });
        let bytes = encode(&neither, &Q, &TAG);
        assert_eq!(
            decode(&bytes, &Q, &TAG),
            Err(RecordError::Field("payload inline xor key"))
        );
    }

    #[test]
    fn bad_version_rejected() {
        let body = Value::Array(vec![
            Value::Uint(MAGIC),
            Value::Uint(2),
            Value::Uint(MINOR),
            Value::Bytes(Q.to_vec()),
            Value::Bytes(TAG.to_vec()),
            Value::Uint(2),
            Value::Map(job_record().fields()),
        ]);
        let body_bytes = cbor::encode(&body);
        let digest = record_digest("job", &body_bytes);
        let mut out = body_bytes;
        out.push(0x58);
        out.push(32);
        out.extend_from_slice(&digest);
        assert_eq!(decode(&out, &Q, &TAG), Err(RecordError::Version(2, 0)));
    }
}
