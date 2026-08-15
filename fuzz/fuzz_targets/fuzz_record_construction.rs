#![no_main]

use libfuzzer_sys::fuzz_target;
use stowq_format::{
    ClaimBasis, ClaimRecord, DeadRecord, FailRecord, FormatRecord, JobRecord, ReceiptRecord,
    Record, WatermarkRecord,
};

const Q: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];
const TAG: [u8; 8] = [0x07; 8];

fn u64_at(data: &[u8], i: usize) -> u64 {
    let mut buf = [0u8; 8];
    for (k, b) in buf.iter_mut().enumerate() {
        *b = data.get((i + k) % data.len().max(1)).copied().unwrap_or(0);
    }
    u64::from_be_bytes(buf)
}

fn bytes16_at(data: &[u8], i: usize) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (k, b) in out.iter_mut().enumerate() {
        *b = data.get((i + k) % data.len().max(1)).copied().unwrap_or(0);
    }
    out
}

fn ascii_at(data: &[u8], i: usize, len: usize) -> String {
    (0..len)
        .map(|k| {
            let b = data
                .get((i + k) % data.len().max(1))
                .copied()
                .unwrap_or(b'a');
            (b'a' + (b % 26)) as char
        })
        .collect()
}

fn record_from(data: &[u8]) -> Record {
    match data.first().copied().unwrap_or(0) % 7 {
        0 => Record::Format(FormatRecord {
            shard_count: (u64_at(data, 0) % 65_537) as u32,
            lease_bucket_width_ns: u64_at(data, 8).max(1),
            delayed_bucket_width_ns: u64_at(data, 16).max(1),
            terminal_bucket_width_ns: u64_at(data, 24).max(1),
            inline_limit: u64_at(data, 32) % 65_536,
            required_feature_bits: 0,
        }),
        1 => {
            let inline = u64_at(data, 32) % 2 == 0;
            let payload_len = (u64_at(data, 40) % 8) as usize;
            Record::Job(JobRecord {
                job_id: bytes16_at(data, 0),
                maximum_attempts: u64_at(data, 8) % 1_000 + 1,
                content_type: ascii_at(data, 16, (u64_at(data, 24) % 8 + 1) as usize),
                created_store_time_ns: u64_at(data, 32),
                not_before_ns: if u64_at(data, 40) % 2 == 0 {
                    Some(u64_at(data, 48))
                } else {
                    None
                },
                payload_digest: {
                    let mut d = [0u8; 32];
                    for (k, b) in d.iter_mut().enumerate() {
                        *b = data.get((56 + k) % data.len().max(1)).copied().unwrap_or(0);
                    }
                    d
                },
                payload_length: payload_len as u64,
                payload_inline: if inline {
                    Some(data[..payload_len.min(data.len())].to_vec())
                } else {
                    None
                },
                payload_key: if inline {
                    None
                } else {
                    Some(ascii_at(data, 48, 8))
                },
            })
        }
        2 => {
            let continuation = u64_at(data, 32) % 2 == 0;
            Record::Claim(ClaimRecord {
                job_id: bytes16_at(data, 0),
                generation: u64_at(data, 8),
                attempt: u64_at(data, 16) % 1_000,
                worker_id: ascii_at(data, 24, (u64_at(data, 32) % 6 + 1) as usize),
                worker_token: bytes16_at(data, 40),
                lease_duration_ns: u64_at(data, 48).max(1),
                continuation,
                basis: if continuation {
                    None
                } else {
                    Some(ClaimBasis {
                        prev_store_time_ns: u64_at(data, 56),
                        prev_duration_ns: u64_at(data, 64),
                        observed_watermark_ns: u64_at(data, 72),
                    })
                },
                prev_token: if continuation {
                    Some(bytes16_at(data, 56))
                } else {
                    None
                },
            })
        }
        3 => Record::Fail(FailRecord {
            job_id: bytes16_at(data, 0),
            generation: u64_at(data, 8),
            reason: u64_at(data, 16) % 0x1_0000,
            attempt: u64_at(data, 24) % 1_000,
            retry_not_before_ns: u64_at(data, 32),
        }),
        4 => {
            let n = (u64_at(data, 32) % 4) as usize;
            Record::Receipt(ReceiptRecord {
                job_id: bytes16_at(data, 0),
                generation: u64_at(data, 8),
                attempt: u64_at(data, 16) % 1_000,
                worker_id: ascii_at(data, 24, 4),
                worker_token: bytes16_at(data, 40),
                payload_digest: {
                    let mut d = [0u8; 32];
                    for (k, b) in d.iter_mut().enumerate() {
                        *b = data.get((48 + k) % data.len().max(1)).copied().unwrap_or(0);
                    }
                    d
                },
                output_digests: (0..n)
                    .map(|i| {
                        let mut d = [0u8; 32];
                        for (k, b) in d.iter_mut().enumerate() {
                            *b = data
                                .get((80 + i * 32 + k) % data.len().max(1))
                                .copied()
                                .unwrap_or(0);
                        }
                        d
                    })
                    .collect(),
            })
        }
        5 => Record::Dead(DeadRecord {
            job_id: bytes16_at(data, 0),
            generation: u64_at(data, 8),
            attempt: u64_at(data, 16) % 1_000,
            reason: u64_at(data, 24) % 0x1_0000,
        }),
        _ => Record::Watermark(WatermarkRecord {
            highest_observed_wall_bucket: u64_at(data, 0),
            sequence: u64_at(data, 8),
        }),
    }
}

// Construction-space coverage: arbitrary bytes build a record through the
// public constructors, and encode/decode must be inverse and deterministic.
// This reaches the field-level codec that the digest gate keeps byte-space
// mutation away from.
fuzz_target!(|data: &[u8]| {
    let record = record_from(data);
    let bytes = stowq_format::encode(&record, &Q, &TAG);
    assert_eq!(stowq_format::encode(&record, &Q, &TAG), bytes);
    assert_eq!(stowq_format::decode(&bytes, &Q, &TAG), Ok(record));
});
