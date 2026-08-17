//! The direct record decoder: bytes to `Record` with no intermediate
//! `Value` tree (the mirror of the direct encoder). Wire acceptance is
//! IDENTICAL to the value path — the differential test decodes every
//! record shape through both and asserts equality of results and
//! errors; the invalid-record suite exercises the reject side. Key
//! order is validated against each record type's static canonical
//! table (encoded-byte order — the writer's emission order), which
//! enforces the same sorted-unique-known rules the value decoder
//! checks over the built map.

use crate::{
    cbor, ClaimBasis, ClaimRecord, DeadRecord, FailRecord, FormatRecord, JobRecord,
    QuarantineRecord, ReceiptRecord, Record, RecordError, WatermarkRecord, MAGIC, MAJOR, MINOR,
};

/// Canonical field order per record type (encoded-key bytewise order;
/// identical to the direct writer's emission order). `pos` in each
/// table is the canonical position used for the strictly-increasing
/// check.
const FORMAT_KEYS: &[&str] = &[
    "shard_count",
    "inline_limit",
    "lease_bucket_width_ns",
    "required_feature_bits",
    "delayed_bucket_width_ns",
    "terminal_bucket_width_ns",
];
const JOB_KEYS: &[&str] = &[
    "job_id",
    "payload_key",
    "content_type",
    "not_before_ns",
    "payload_digest",
    "payload_inline",
    "payload_length",
    "maximum_attempts",
    "created_store_time_ns",
];
const CLAIM_KEYS: &[&str] = &[
    "basis",
    "job_id",
    "attempt",
    "worker_id",
    "generation",
    "prev_token",
    "continuation",
    "worker_token",
    "lease_duration_ns",
];
const BASIS_KEYS: &[&str] = &[
    "prev_duration_ns",
    "prev_store_time_ns",
    "observed_watermark_ns",
];
const FAIL_KEYS: &[&str] = &[
    "job_id",
    "reason",
    "attempt",
    "generation",
    "retry_not_before_ns",
];
const RECEIPT_KEYS: &[&str] = &[
    "job_id",
    "attempt",
    "worker_id",
    "generation",
    "worker_token",
    "output_digests",
    "payload_digest",
];
const DEAD_KEYS: &[&str] = &["job_id", "reason", "attempt", "generation"];
const WATERMARK_KEYS: &[&str] = &["sequence", "highest_observed_wall_bucket"];
const QUARANTINE_KEYS: &[&str] = &["qid", "detail", "reason", "source_key", "observed_store_ns"];

fn table_pos(table: &[&str], key: &str) -> Option<usize> {
    table.iter().position(|k| *k == key)
}

// ---------- primitive item readers (error classes match the value
// path: canonical heads enforced by the shared Reader; wrong shapes
// become the same RecordError variants) ----------

fn read_uint(r: &mut cbor::Reader<'_>) -> Result<u64, RecordError> {
    let (major, v) = r.head().map_err(RecordError::Cbor)?;
    if major != 0 {
        return Err(RecordError::Field("uint"));
    }
    Ok(v)
}

/// Envelope items: a wrong shape is an envelope error (the value
/// path's tuple match), not a field-type error.
fn env_uint(r: &mut cbor::Reader<'_>) -> Result<u64, RecordError> {
    let (major, v) = r.head().map_err(RecordError::Cbor)?;
    if major != 0 {
        return Err(RecordError::Envelope);
    }
    Ok(v)
}

fn env_bytes<'a>(r: &mut cbor::Reader<'a>) -> Result<&'a [u8], RecordError> {
    let (major, len) = r.head().map_err(RecordError::Cbor)?;
    if major != 2 {
        return Err(RecordError::Envelope);
    }
    r.take(len as usize).map_err(RecordError::Cbor)
}

fn read_bool(r: &mut cbor::Reader<'_>) -> Result<bool, RecordError> {
    let (major, v) = r.head().map_err(RecordError::Cbor)?;
    if major == 7 && v == 20 {
        return Ok(false);
    }
    if major == 7 && v == 21 {
        return Ok(true);
    }
    Err(RecordError::Field("bool"))
}

fn read_borrowed_bytes<'a>(r: &mut cbor::Reader<'a>) -> Result<&'a [u8], RecordError> {
    let (major, len) = r.head().map_err(RecordError::Cbor)?;
    if major != 2 {
        return Err(RecordError::Field("bytes"));
    }
    r.take(len as usize).map_err(RecordError::Cbor)
}

fn read_borrowed_text<'a>(r: &mut cbor::Reader<'a>) -> Result<&'a str, RecordError> {
    let (major, len) = r.head().map_err(RecordError::Cbor)?;
    if major != 3 {
        return Err(RecordError::Field("text"));
    }
    let b = r.take(len as usize).map_err(RecordError::Cbor)?;
    std::str::from_utf8(b).map_err(|_| RecordError::Cbor(cbor::Error::InvalidUtf8))
}

fn fixed<const N: usize>(b: &[u8]) -> Result<[u8; N], RecordError> {
    let mut out = [0u8; N];
    if b.len() != N {
        return Err(RecordError::Field("byte width"));
    }
    out.copy_from_slice(b);
    Ok(out)
}

/// Reads the map header and then the field pairs, validating key
/// order/uniqueness/known-ness against `table` and parsing each value
/// with `value_reader(key, reader)`. `value_reader` receives keys in
/// canonical order and stores what it needs; missing-required checks
/// are the reader's job (mirror of the getters' MissingField).
fn read_map<F>(
    r: &mut cbor::Reader<'_>,
    table: &[&str],
    non_map_err: RecordError,
    mut value_reader: F,
) -> Result<(), RecordError>
where
    F: FnMut(&str, &mut cbor::Reader<'_>) -> Result<(), RecordError>,
{
    let (major, n) = r.head().map_err(RecordError::Cbor)?;
    if major != 5 {
        return Err(non_map_err);
    }
    let mut prev_pos: Option<usize> = None;
    for _ in 0..n {
        let key = read_borrowed_text(r)?;
        let pos = match table_pos(table, key) {
            Some(p) => p,
            None => return Err(RecordError::UnknownField(key.to_string())),
        };
        match prev_pos {
            Some(p) if p == pos => {
                return Err(RecordError::Cbor(cbor::Error::DuplicateMapKey));
            }
            Some(p) if pos < p => {
                return Err(RecordError::Cbor(cbor::Error::UnsortedMapKeys));
            }
            _ => {}
        }
        prev_pos = Some(pos);
        value_reader(key, r)?;
    }
    Ok(())
}

pub(super) fn decode_record(
    data: &[u8],
    queue_id: &[u8; 16],
    key_tag: &[u8; 8],
) -> Result<Record, RecordError> {
    if data.len() < 34 {
        return Err(RecordError::Envelope);
    }
    let (body, tail) = data.split_at(data.len() - 34);
    if tail[0] != 0x58 || tail[1] != 32 {
        return Err(RecordError::Envelope);
    }
    let mut r = cbor::Reader::new(body);
    let (major, n) = r.head().map_err(RecordError::Cbor)?;
    if major != 4 || n != 7 {
        return Err(RecordError::Envelope);
    }
    let magic = env_uint(&mut r)?;
    let ver_major = env_uint(&mut r)?;
    let ver_minor = env_uint(&mut r)?;
    let qid = env_bytes(&mut r)?;
    let tag = env_bytes(&mut r)?;
    let rtype = env_uint(&mut r)?;
    if magic != MAGIC {
        return Err(RecordError::Magic);
    }
    if ver_major != MAJOR || ver_minor != MINOR {
        return Err(RecordError::Version(ver_major, ver_minor));
    }
    // Digest before binding: no field is trusted on an unverifiable
    // body.
    let type_str = crate::type_name(rtype).ok_or(RecordError::Type)?;
    let expected = crate::record_digest(type_str, body);
    if expected[..] != tail[2..] {
        return Err(RecordError::Digest);
    }
    if qid != queue_id || tag != key_tag {
        return Err(RecordError::Field("queue binding"));
    }
    // The fields map is the 7th envelope item; everything after it
    // must be nothing (one value over the whole body, as the value
    // path enforces with TrailingBytes).
    let record = parse_fields(rtype, &mut r)?;
    if !r.done() {
        return Err(RecordError::Cbor(cbor::Error::TrailingBytes));
    }
    Ok(record)
}

fn parse_fields(t: u64, r: &mut cbor::Reader<'_>) -> Result<Record, RecordError> {
    match t {
        1 => {
            let mut f = FormatRecord {
                shard_count: 0,
                lease_bucket_width_ns: 0,
                delayed_bucket_width_ns: 0,
                terminal_bucket_width_ns: 0,
                inline_limit: 0,
                required_feature_bits: 0,
            };
            let mut seen = [false; 6];
            read_map(r, FORMAT_KEYS, RecordError::Envelope, |key, r| {
                let v = read_uint(r)?;
                match key {
                    "shard_count" => {
                        f.shard_count = v as u32;
                        seen[0] = true;
                        Ok(())
                    }
                    "inline_limit" => {
                        f.inline_limit = v;
                        seen[1] = true;
                        Ok(())
                    }
                    "lease_bucket_width_ns" => {
                        f.lease_bucket_width_ns = v;
                        seen[2] = true;
                        Ok(())
                    }
                    "required_feature_bits" => {
                        f.required_feature_bits = v;
                        seen[3] = true;
                        Ok(())
                    }
                    "delayed_bucket_width_ns" => {
                        f.delayed_bucket_width_ns = v;
                        seen[4] = true;
                        Ok(())
                    }
                    "terminal_bucket_width_ns" => {
                        f.terminal_bucket_width_ns = v;
                        seen[5] = true;
                        Ok(())
                    }
                    _ => unreachable!(),
                }
            })?;
            for (i, k) in FORMAT_KEYS.iter().enumerate() {
                if !seen[i] {
                    return Err(RecordError::MissingField(k));
                }
            }
            // The shard field is 4 hex digits; reject rather than
            // silently truncate a wider value.
            if f.shard_count as u64 > 65_536 {
                return Err(RecordError::Field("shard_count"));
            }
            Ok(Record::Format(f))
        }
        2 => {
            let mut job_id = None;
            let mut maximum_attempts = None;
            let mut content_type: Option<String> = None;
            let mut created_store_time_ns = None;
            let mut not_before_ns = None;
            let mut payload_digest = None;
            let mut payload_length = None;
            let mut payload_inline: Option<Vec<u8>> = None;
            let mut payload_key: Option<String> = None;
            read_map(r, JOB_KEYS, RecordError::Envelope, |key, r| match key {
                "job_id" => {
                    job_id = Some(fixed::<16>(read_borrowed_bytes(r)?)?);
                    Ok(())
                }
                "maximum_attempts" => {
                    maximum_attempts = Some(read_uint(r)?);
                    Ok(())
                }
                "content_type" => {
                    content_type = Some(read_borrowed_text(r)?.to_string());
                    Ok(())
                }
                "created_store_time_ns" => {
                    created_store_time_ns = Some(read_uint(r)?);
                    Ok(())
                }
                "not_before_ns" => {
                    not_before_ns = Some(read_uint(r)?);
                    Ok(())
                }
                "payload_digest" => {
                    payload_digest = Some(fixed::<32>(read_borrowed_bytes(r)?)?);
                    Ok(())
                }
                "payload_length" => {
                    payload_length = Some(read_uint(r)?);
                    Ok(())
                }
                "payload_inline" => {
                    payload_inline = Some(read_borrowed_bytes(r)?.to_vec());
                    Ok(())
                }
                "payload_key" => {
                    payload_key = Some(read_borrowed_text(r)?.to_string());
                    Ok(())
                }
                _ => unreachable!(),
            })?;
            if payload_inline.is_some() == payload_key.is_some() {
                return Err(RecordError::Field("payload inline xor key"));
            }
            Ok(Record::Job(JobRecord {
                job_id: job_id.ok_or(RecordError::MissingField("job_id"))?,
                maximum_attempts: maximum_attempts
                    .ok_or(RecordError::MissingField("maximum_attempts"))?,
                content_type: content_type.ok_or(RecordError::MissingField("content_type"))?,
                created_store_time_ns: created_store_time_ns
                    .ok_or(RecordError::MissingField("created_store_time_ns"))?,
                not_before_ns,
                payload_digest: payload_digest
                    .ok_or(RecordError::MissingField("payload_digest"))?,
                payload_length: payload_length
                    .ok_or(RecordError::MissingField("payload_length"))?,
                payload_inline,
                payload_key,
            }))
        }
        3 => {
            let mut job_id = None;
            let mut generation = None;
            let mut attempt = None;
            let mut worker_id: Option<String> = None;
            let mut worker_token = None;
            let mut lease_duration_ns = None;
            let mut continuation = None;
            let mut basis: Option<ClaimBasis> = None;
            let mut prev_token = None;
            read_map(r, CLAIM_KEYS, RecordError::Envelope, |key, r| match key {
                "basis" => {
                    let mut b = ClaimBasis {
                        prev_store_time_ns: 0,
                        prev_duration_ns: 0,
                        observed_watermark_ns: 0,
                    };
                    let mut seen = [false; 3];
                    read_map(r, BASIS_KEYS, RecordError::Field("basis"), |bkey, r| {
                        let v = read_uint(r)?;
                        match bkey {
                            "prev_duration_ns" => {
                                b.prev_duration_ns = v;
                                seen[0] = true;
                            }
                            "prev_store_time_ns" => {
                                b.prev_store_time_ns = v;
                                seen[1] = true;
                            }
                            "observed_watermark_ns" => {
                                b.observed_watermark_ns = v;
                                seen[2] = true;
                            }
                            _ => unreachable!(),
                        }
                        Ok(())
                    })?;
                    for (i, k) in BASIS_KEYS.iter().enumerate() {
                        if !seen[i] {
                            return Err(RecordError::MissingField(k));
                        }
                    }
                    basis = Some(b);
                    Ok(())
                }
                "job_id" => {
                    job_id = Some(fixed::<16>(read_borrowed_bytes(r)?)?);
                    Ok(())
                }
                "attempt" => {
                    attempt = Some(read_uint(r)?);
                    Ok(())
                }
                "worker_id" => {
                    worker_id = Some(read_borrowed_text(r)?.to_string());
                    Ok(())
                }
                "generation" => {
                    generation = Some(read_uint(r)?);
                    Ok(())
                }
                "prev_token" => {
                    prev_token = Some(fixed::<16>(read_borrowed_bytes(r)?)?);
                    Ok(())
                }
                "continuation" => {
                    continuation = Some(read_bool(r)?);
                    Ok(())
                }
                "worker_token" => {
                    worker_token = Some(fixed::<16>(read_borrowed_bytes(r)?)?);
                    Ok(())
                }
                "lease_duration_ns" => {
                    lease_duration_ns = Some(read_uint(r)?);
                    Ok(())
                }
                _ => unreachable!(),
            })?;
            let continuation = continuation.ok_or(RecordError::MissingField("continuation"))?;
            if continuation == (basis.is_some())
                || continuation != prev_token.is_some()
                || basis.is_some() == prev_token.is_some()
            {
                return Err(RecordError::Field("basis xor prev_token"));
            }
            Ok(Record::Claim(ClaimRecord {
                job_id: job_id.ok_or(RecordError::MissingField("job_id"))?,
                generation: generation.ok_or(RecordError::MissingField("generation"))?,
                attempt: attempt.ok_or(RecordError::MissingField("attempt"))?,
                worker_id: worker_id.ok_or(RecordError::MissingField("worker_id"))?,
                worker_token: worker_token.ok_or(RecordError::MissingField("worker_token"))?,
                lease_duration_ns: lease_duration_ns
                    .ok_or(RecordError::MissingField("lease_duration_ns"))?,
                continuation,
                basis,
                prev_token,
            }))
        }
        4 => {
            let mut v = (None, None, None, None, None);
            read_map(r, FAIL_KEYS, RecordError::Envelope, |key, r| match key {
                "job_id" => {
                    v.0 = Some(fixed::<16>(read_borrowed_bytes(r)?)?);
                    Ok(())
                }
                "reason" => {
                    v.1 = Some(read_uint(r)?);
                    Ok(())
                }
                "attempt" => {
                    v.2 = Some(read_uint(r)?);
                    Ok(())
                }
                "generation" => {
                    v.3 = Some(read_uint(r)?);
                    Ok(())
                }
                "retry_not_before_ns" => {
                    v.4 = Some(read_uint(r)?);
                    Ok(())
                }
                _ => unreachable!(),
            })?;
            Ok(Record::Fail(FailRecord {
                job_id: v.0.ok_or(RecordError::MissingField("job_id"))?,
                generation: v.3.ok_or(RecordError::MissingField("generation"))?,
                reason: v.1.ok_or(RecordError::MissingField("reason"))?,
                attempt: v.2.ok_or(RecordError::MissingField("attempt"))?,
                retry_not_before_ns: v
                    .4
                    .ok_or(RecordError::MissingField("retry_not_before_ns"))?,
            }))
        }
        5 => {
            let mut job_id = None;
            let mut generation = None;
            let mut attempt = None;
            let mut worker_id: Option<String> = None;
            let mut worker_token = None;
            let mut payload_digest = None;
            let mut output_digests: Option<Vec<[u8; 32]>> = None;
            read_map(r, RECEIPT_KEYS, RecordError::Envelope, |key, r| match key {
                "job_id" => {
                    job_id = Some(fixed::<16>(read_borrowed_bytes(r)?)?);
                    Ok(())
                }
                "attempt" => {
                    attempt = Some(read_uint(r)?);
                    Ok(())
                }
                "worker_id" => {
                    worker_id = Some(read_borrowed_text(r)?.to_string());
                    Ok(())
                }
                "generation" => {
                    generation = Some(read_uint(r)?);
                    Ok(())
                }
                "worker_token" => {
                    worker_token = Some(fixed::<16>(read_borrowed_bytes(r)?)?);
                    Ok(())
                }
                "output_digests" => {
                    let (major, n) = r.head().map_err(RecordError::Cbor)?;
                    if major != 4 {
                        return Err(RecordError::Field("output_digests"));
                    }
                    if n == 0 {
                        // The encoder omits the field when empty; an
                        // explicit empty array is non-canonical.
                        return Err(RecordError::Field("output_digests"));
                    }
                    let mut out = Vec::with_capacity(n as usize);
                    for _ in 0..n {
                        out.push(fixed::<32>(read_borrowed_bytes(r)?)?);
                    }
                    output_digests = Some(out);
                    Ok(())
                }
                "payload_digest" => {
                    payload_digest = Some(fixed::<32>(read_borrowed_bytes(r)?)?);
                    Ok(())
                }
                _ => unreachable!(),
            })?;
            Ok(Record::Receipt(ReceiptRecord {
                job_id: job_id.ok_or(RecordError::MissingField("job_id"))?,
                generation: generation.ok_or(RecordError::MissingField("generation"))?,
                attempt: attempt.ok_or(RecordError::MissingField("attempt"))?,
                worker_id: worker_id.ok_or(RecordError::MissingField("worker_id"))?,
                worker_token: worker_token.ok_or(RecordError::MissingField("worker_token"))?,
                payload_digest: payload_digest
                    .ok_or(RecordError::MissingField("payload_digest"))?,
                output_digests: output_digests.unwrap_or_default(),
            }))
        }
        6 => {
            let mut v = (None, None, None, None);
            read_map(r, DEAD_KEYS, RecordError::Envelope, |key, r| match key {
                "job_id" => {
                    v.0 = Some(fixed::<16>(read_borrowed_bytes(r)?)?);
                    Ok(())
                }
                "reason" => {
                    v.1 = Some(read_uint(r)?);
                    Ok(())
                }
                "attempt" => {
                    v.2 = Some(read_uint(r)?);
                    Ok(())
                }
                "generation" => {
                    v.3 = Some(read_uint(r)?);
                    Ok(())
                }
                _ => unreachable!(),
            })?;
            Ok(Record::Dead(DeadRecord {
                job_id: v.0.ok_or(RecordError::MissingField("job_id"))?,
                generation: v.3.ok_or(RecordError::MissingField("generation"))?,
                attempt: v.2.ok_or(RecordError::MissingField("attempt"))?,
                reason: v.1.ok_or(RecordError::MissingField("reason"))?,
            }))
        }
        7 => {
            let mut highest_observed_wall_bucket = None;
            let mut sequence = None;
            read_map(
                r,
                WATERMARK_KEYS,
                RecordError::Envelope,
                |key, r| match key {
                    "sequence" => {
                        sequence = Some(read_uint(r)?);
                        Ok(())
                    }
                    "highest_observed_wall_bucket" => {
                        highest_observed_wall_bucket = Some(read_uint(r)?);
                        Ok(())
                    }
                    _ => unreachable!(),
                },
            )?;
            Ok(Record::Watermark(WatermarkRecord {
                highest_observed_wall_bucket: highest_observed_wall_bucket
                    .ok_or(RecordError::MissingField("highest_observed_wall_bucket"))?,
                sequence: sequence.ok_or(RecordError::MissingField("sequence"))?,
            }))
        }
        8 => {
            let mut qid = None;
            let mut source_key: Option<String> = None;
            let mut reason = None;
            let mut observed_store_ns = None;
            let mut detail = None;
            read_map(
                r,
                QUARANTINE_KEYS,
                RecordError::Envelope,
                |key, r| match key {
                    "qid" => {
                        qid = Some(fixed::<16>(read_borrowed_bytes(r)?)?);
                        Ok(())
                    }
                    "detail" => {
                        detail = Some(read_uint(r)?);
                        Ok(())
                    }
                    "reason" => {
                        reason = Some(read_uint(r)?);
                        Ok(())
                    }
                    "source_key" => {
                        source_key = Some(read_borrowed_text(r)?.to_string());
                        Ok(())
                    }
                    "observed_store_ns" => {
                        observed_store_ns = Some(read_uint(r)?);
                        Ok(())
                    }
                    _ => unreachable!(),
                },
            )?;
            Ok(Record::Quarantine(QuarantineRecord {
                qid: qid.ok_or(RecordError::MissingField("qid"))?,
                source_key: source_key.ok_or(RecordError::MissingField("source_key"))?,
                reason: reason.ok_or(RecordError::MissingField("reason"))?,
                observed_store_ns: observed_store_ns
                    .ok_or(RecordError::MissingField("observed_store_ns"))?,
                detail,
            }))
        }
        _ => Err(RecordError::Type),
    }
}
