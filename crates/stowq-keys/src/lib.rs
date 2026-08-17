//! Canonical key parsing and formatting for StowQ/1.
//!
//! Keys are lowercase, `/`-delimited, fixed-width hex fields per the
//! grammar in `spec/keys.abnf`. Parsing is strict: anything that does not
//! match the grammar is an error and a quarantine candidate at the store
//! layer. Numeric fields are big-endian so lexicographic key order matches
//! numeric order.

use sha2::{Digest as _, Sha256};
use std::fmt;
use thiserror::Error;

// ---------- Hex ----------

fn from_hex_digit_lower(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

fn hex_decode_fixed<const N: usize>(s: &str) -> Option<[u8; N]> {
    let b = s.as_bytes();
    if b.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for i in 0..N {
        let hi = from_hex_digit_lower(b[2 * i])?;
        let lo = from_hex_digit_lower(b[2 * i + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_decode_u64(s: &str) -> Option<u64> {
    Some(u64::from_be_bytes(hex_decode_fixed::<8>(s)?))
}

fn hex_decode_u32(s: &str) -> Option<u32> {
    Some(u32::from_be_bytes(hex_decode_fixed::<4>(s)?))
}

fn hex_decode_u16(s: &str) -> Option<u16> {
    Some(u16::from_be_bytes(hex_decode_fixed::<2>(s)?))
}

fn push_hex(out: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
}

// ---------- Shard derivation and key tag ----------

/// shard = low log2(shard_count) bits of SHA256("StowQ-1-shard\0" ||
/// queue_id || job_id), taken from the first 2 hash bytes.
/// `shard_count` must be a power of two between 1 and 65536 (enforced
/// by FORMAT validation; the assert guards direct callers).
pub fn compute_shard(queue_id: &[u8; 16], job_id: &[u8; 16], shard_count: u32) -> u16 {
    assert!(
        shard_count.is_power_of_two() && shard_count <= 65_536,
        "shard_count must be a power of two up to 65536"
    );
    let k = shard_count.trailing_zeros();
    let mut hasher = Sha256::new();
    hasher.update(b"StowQ-1-shard\0");
    hasher.update(queue_id);
    hasher.update(job_id);
    let result = hasher.finalize();
    let val = u16::from_be_bytes([result[0], result[1]]);
    if k >= 16 {
        val
    } else {
        val & ((1u16 << k) - 1)
    }
}

/// key_tag = first 8 bytes of SHA256("StowQ-1-key\0" || queue_id || key).
/// Binds a record to its key and queue; verified on every read.
pub fn key_tag(queue_id: &[u8; 16], key: &str) -> [u8; 8] {
    let mut hasher = Sha256::new();
    hasher.update(b"StowQ-1-key\0");
    hasher.update(queue_id);
    hasher.update(key.as_bytes());
    let result = hasher.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&result[..8]);
    out
}

// ---------- Keys ----------

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("unknown key prefix")]
    UnknownPrefix,
    #[error("wrong segment count")]
    SegmentCount,
    #[error("malformed field: {0}")]
    Field(&'static str),
    #[error("unknown terminal kind")]
    Kind,
}

/// Terminal record kind encoded in `termidx/` keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TermKind {
    Receipt,
    Dead,
}

impl TermKind {
    fn as_char(self) -> char {
        match self {
            TermKind::Receipt => 'r',
            TermKind::Dead => 'd',
        }
    }

    fn from_char(c: &str) -> Option<Self> {
        match c {
            "r" => Some(TermKind::Receipt),
            "d" => Some(TermKind::Dead),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Key {
    Job {
        shard: u16,
        job_id: [u8; 16],
    },
    Payload {
        job_id: [u8; 16],
        digest: [u8; 32],
    },
    Claim {
        shard: u16,
        job_id: [u8; 16],
        generation: u32,
    },
    Fail {
        shard: u16,
        job_id: [u8; 16],
        generation: u32,
    },
    LeaseIndex {
        bucket: u64,
        shard: u16,
        job_id: [u8; 16],
        generation: u32,
    },
    DelayIndex {
        bucket: u64,
        shard: u16,
        job_id: [u8; 16],
    },
    Receipt {
        shard: u16,
        job_id: [u8; 16],
    },
    Dead {
        shard: u16,
        job_id: [u8; 16],
    },
    TermIndex {
        bucket: u64,
        kind: TermKind,
        shard: u16,
        job_id: [u8; 16],
    },
    Quarantine {
        bucket: u64,
        qid: [u8; 16],
    },
    /// Advisory tail hint: `tails/<shard>/<job>`, body = 8-byte
    /// big-endian generation of the claim-chain tail (feature bit 2).
    Tail {
        shard: u16,
        job_id: [u8; 16],
    },
    Beacon {
        nonce: [u8; 16],
    },
    Format,
    Watermark,
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = String::new();
        match self {
            Key::Job { shard, job_id } => {
                s.push_str("jobs/");
                push_hex(&mut s, &shard.to_be_bytes());
                s.push('/');
                push_hex(&mut s, job_id);
            }
            Key::Payload { job_id, digest } => {
                s.push_str("payloads/");
                push_hex(&mut s, job_id);
                s.push('/');
                push_hex(&mut s, digest);
            }
            Key::Claim {
                shard,
                job_id,
                generation,
            } => {
                s.push_str("claims/");
                push_hex(&mut s, &shard.to_be_bytes());
                s.push('/');
                push_hex(&mut s, job_id);
                s.push('/');
                push_hex(&mut s, &generation.to_be_bytes());
            }
            Key::Fail {
                shard,
                job_id,
                generation,
            } => {
                s.push_str("fails/");
                push_hex(&mut s, &shard.to_be_bytes());
                s.push('/');
                push_hex(&mut s, job_id);
                s.push('/');
                push_hex(&mut s, &generation.to_be_bytes());
            }
            Key::LeaseIndex {
                bucket,
                shard,
                job_id,
                generation,
            } => {
                s.push_str("leases/");
                push_hex(&mut s, &bucket.to_be_bytes());
                s.push('/');
                push_hex(&mut s, &shard.to_be_bytes());
                s.push('/');
                push_hex(&mut s, job_id);
                s.push('.');
                push_hex(&mut s, &generation.to_be_bytes());
            }
            Key::DelayIndex {
                bucket,
                shard,
                job_id,
            } => {
                s.push_str("delayed/");
                push_hex(&mut s, &bucket.to_be_bytes());
                s.push('/');
                push_hex(&mut s, &shard.to_be_bytes());
                s.push('/');
                push_hex(&mut s, job_id);
            }
            Key::Receipt { shard, job_id } => {
                s.push_str("receipts/");
                push_hex(&mut s, &shard.to_be_bytes());
                s.push('/');
                push_hex(&mut s, job_id);
            }
            Key::Dead { shard, job_id } => {
                s.push_str("dead/");
                push_hex(&mut s, &shard.to_be_bytes());
                s.push('/');
                push_hex(&mut s, job_id);
            }
            Key::TermIndex {
                bucket,
                kind,
                shard,
                job_id,
            } => {
                s.push_str("termidx/");
                push_hex(&mut s, &bucket.to_be_bytes());
                s.push('/');
                s.push(kind.as_char());
                s.push('/');
                push_hex(&mut s, &shard.to_be_bytes());
                s.push('/');
                push_hex(&mut s, job_id);
            }
            Key::Quarantine { bucket, qid } => {
                s.push_str("quarantine/");
                push_hex(&mut s, &bucket.to_be_bytes());
                s.push('/');
                push_hex(&mut s, qid);
            }
            Key::Beacon { nonce } => {
                s.push_str("meta/clock/");
                push_hex(&mut s, nonce);
            }
            Key::Tail { shard, job_id } => {
                s.push_str("tails/");
                push_hex(&mut s, &shard.to_be_bytes());
                s.push('/');
                push_hex(&mut s, job_id);
            }
            Key::Format => s.push_str("meta/FORMAT"),
            Key::Watermark => s.push_str("meta/watermark"),
        }
        f.write_str(&s)
    }
}

impl std::str::FromStr for Key {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse(s)
    }
}

fn field<T>(name: &'static str, v: Option<T>) -> Result<T, ParseError> {
    v.ok_or(ParseError::Field(name))
}

/// Parses a canonical key. Strict: exact widths, lowercase hex, exact
/// segment counts, no trailing separators.
pub fn parse(s: &str) -> Result<Key, ParseError> {
    let parts: Vec<&str> = s.split('/').collect();
    let seg = |n: usize| -> Result<(), ParseError> {
        if parts.len() == n {
            Ok(())
        } else {
            Err(ParseError::SegmentCount)
        }
    };
    match parts.first().copied() {
        Some("jobs") => {
            seg(3)?;
            Ok(Key::Job {
                shard: field("shard", hex_decode_u16(parts[1]))?,
                job_id: field("job-id", hex_decode_fixed(parts[2]))?,
            })
        }
        Some("payloads") => {
            seg(3)?;
            Ok(Key::Payload {
                job_id: field("job-id", hex_decode_fixed(parts[1]))?,
                digest: field("digest", hex_decode_fixed(parts[2]))?,
            })
        }
        Some("claims") | Some("fails") => {
            seg(4)?;
            let shard = field("shard", hex_decode_u16(parts[1]))?;
            let job_id = field("job-id", hex_decode_fixed(parts[2]))?;
            let generation = field("generation", hex_decode_u32(parts[3]))?;
            Ok(if parts[0] == "claims" {
                Key::Claim {
                    shard,
                    job_id,
                    generation,
                }
            } else {
                Key::Fail {
                    shard,
                    job_id,
                    generation,
                }
            })
        }
        Some("leases") => {
            seg(4)?;
            let last = parts[3];
            let (job_s, gen_s) = last
                .split_once('.')
                .ok_or(ParseError::Field("lease suffix"))?;
            Ok(Key::LeaseIndex {
                bucket: field("bucket", hex_decode_u64(parts[1]))?,
                shard: field("shard", hex_decode_u16(parts[2]))?,
                job_id: field("job-id", hex_decode_fixed(job_s))?,
                generation: field("generation", hex_decode_u32(gen_s))?,
            })
        }
        Some("delayed") => {
            seg(4)?;
            Ok(Key::DelayIndex {
                bucket: field("bucket", hex_decode_u64(parts[1]))?,
                shard: field("shard", hex_decode_u16(parts[2]))?,
                job_id: field("job-id", hex_decode_fixed(parts[3]))?,
            })
        }
        Some("receipts") | Some("dead") => {
            seg(3)?;
            let shard = field("shard", hex_decode_u16(parts[1]))?;
            let job_id = field("job-id", hex_decode_fixed(parts[2]))?;
            Ok(if parts[0] == "receipts" {
                Key::Receipt { shard, job_id }
            } else {
                Key::Dead { shard, job_id }
            })
        }
        Some("termidx") => {
            seg(5)?;
            Ok(Key::TermIndex {
                bucket: field("bucket", hex_decode_u64(parts[1]))?,
                kind: TermKind::from_char(parts[2]).ok_or(ParseError::Kind)?,
                shard: field("shard", hex_decode_u16(parts[3]))?,
                job_id: field("job-id", hex_decode_fixed(parts[4]))?,
            })
        }
        Some("quarantine") => {
            seg(3)?;
            Ok(Key::Quarantine {
                bucket: field("bucket", hex_decode_u64(parts[1]))?,
                qid: field("qid", hex_decode_fixed(parts[2]))?,
            })
        }
        Some("tails") => {
            seg(3)?;
            Ok(Key::Tail {
                shard: field("shard", hex_decode_u16(parts[1]))?,
                job_id: field("job-id", hex_decode_fixed(parts[2]))?,
            })
        }
        Some("meta") => match parts.get(1).copied() {
            Some("FORMAT") if parts.len() == 2 => Ok(Key::Format),
            Some("watermark") if parts.len() == 2 => Ok(Key::Watermark),
            Some("clock") => {
                seg(3)?;
                Ok(Key::Beacon {
                    nonce: field("nonce", hex_decode_fixed(parts[2]))?,
                })
            }
            _ => Err(ParseError::UnknownPrefix),
        },
        _ => Err(ParseError::UnknownPrefix),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_16(bytes: &[u8; 16]) -> String {
        let mut s = String::with_capacity(32);
        push_hex(&mut s, bytes);
        s
    }

    fn hex_32(bytes: &[u8; 32]) -> String {
        let mut s = String::with_capacity(64);
        push_hex(&mut s, bytes);
        s
    }

    const Q: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    const J: [u8; 16] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f,
    ];
    const D: [u8; 32] = [
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae,
        0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd,
        0xbe, 0xbf,
    ];

    fn corpus() -> Vec<Key> {
        vec![
            Key::Job {
                shard: 0x0f0e,
                job_id: J,
            },
            Key::Payload {
                job_id: J,
                digest: D,
            },
            Key::Claim {
                shard: 1,
                job_id: J,
                generation: 7,
            },
            Key::Fail {
                shard: 1,
                job_id: J,
                generation: 7,
            },
            Key::LeaseIndex {
                bucket: 42,
                shard: 1,
                job_id: J,
                generation: 7,
            },
            Key::DelayIndex {
                bucket: 42,
                shard: 1,
                job_id: J,
            },
            Key::Receipt {
                shard: 1,
                job_id: J,
            },
            Key::Dead {
                shard: 1,
                job_id: J,
            },
            Key::TermIndex {
                bucket: 42,
                kind: TermKind::Receipt,
                shard: 1,
                job_id: J,
            },
            Key::TermIndex {
                bucket: 42,
                kind: TermKind::Dead,
                shard: 1,
                job_id: J,
            },
            Key::Quarantine { bucket: 42, qid: J },
            Key::Beacon { nonce: Q },
            Key::Format,
            Key::Watermark,
        ]
    }

    #[test]
    fn round_trip_corpus() {
        for key in corpus() {
            let s = key.to_string();
            assert_eq!(
                s.parse::<Key>(),
                Ok(key.clone()),
                "round trip failed for {s}"
            );
        }
    }

    #[test]
    fn canonical_strings() {
        let j = hex_16(&J);
        let d = hex_32(&D);
        let q = hex_16(&Q);
        assert_eq!(
            Key::Job {
                shard: 0x0f0e,
                job_id: J
            }
            .to_string(),
            format!("jobs/0f0e/{j}")
        );
        assert_eq!(
            Key::Payload {
                job_id: J,
                digest: D
            }
            .to_string(),
            format!("payloads/{j}/{d}")
        );
        assert_eq!(
            Key::Claim {
                shard: 1,
                job_id: J,
                generation: 7
            }
            .to_string(),
            format!("claims/0001/{j}/00000007")
        );
        assert_eq!(
            Key::LeaseIndex {
                bucket: 42,
                shard: 1,
                job_id: J,
                generation: 7
            }
            .to_string(),
            format!("leases/000000000000002a/0001/{j}.00000007")
        );
        assert_eq!(
            Key::TermIndex {
                bucket: 42,
                kind: TermKind::Dead,
                shard: 1,
                job_id: J
            }
            .to_string(),
            format!("termidx/000000000000002a/d/0001/{j}")
        );
        assert_eq!(
            Key::Beacon { nonce: Q }.to_string(),
            format!("meta/clock/{q}")
        );
        assert_eq!(Key::Format.to_string(), "meta/FORMAT");
        assert_eq!(Key::Watermark.to_string(), "meta/watermark");
    }

    #[test]
    fn rejects_uppercase_hex() {
        let upper = format!("jobs/0f0e/{}", hex_16(&J).to_uppercase());
        assert_eq!(upper.parse::<Key>(), Err(ParseError::Field("job-id")));
    }

    #[test]
    fn rejects_wrong_widths() {
        let j = hex_16(&J);
        assert_eq!(
            format!("jobs/0f0/{}", j).parse::<Key>(),
            Err(ParseError::Field("shard"))
        );
        assert_eq!(
            "jobs/0f0e/short".parse::<Key>(),
            Err(ParseError::Field("job-id"))
        );
        assert_eq!(
            format!("claims/0001/{}/7", j).parse::<Key>(),
            Err(ParseError::Field("generation"))
        );
        assert_eq!(
            format!("termidx/000000000000002a/x/0001/{}", j).parse::<Key>(),
            Err(ParseError::Kind)
        );
    }

    #[test]
    fn rejects_segment_count_and_prefix() {
        assert_eq!("".parse::<Key>(), Err(ParseError::UnknownPrefix));
        assert_eq!("jobs".parse::<Key>(), Err(ParseError::SegmentCount));
        assert_eq!("jobs/0f0e".parse::<Key>(), Err(ParseError::SegmentCount));
        assert_eq!(
            format!("jobs/0f0e/{}/extra", hex_16(&J)).parse::<Key>(),
            Err(ParseError::SegmentCount)
        );
        assert_eq!(
            format!("jobs/0f0e/{}/", hex_16(&J)).parse::<Key>(),
            Err(ParseError::SegmentCount)
        );
        assert_eq!(
            "meta/FORMAT/x".parse::<Key>(),
            Err(ParseError::UnknownPrefix)
        );
        assert_eq!(
            "meta/unknown".parse::<Key>(),
            Err(ParseError::UnknownPrefix)
        );
        assert_eq!(
            "unknown/0001/x".parse::<Key>(),
            Err(ParseError::UnknownPrefix)
        );
    }

    #[test]
    fn rejects_bad_lease_suffix() {
        let j = hex_16(&J);
        assert_eq!(
            format!("leases/000000000000002a/0001/{}", j).parse::<Key>(),
            Err(ParseError::Field("lease suffix"))
        );
        assert_eq!(
            format!("leases/000000000000002a/0001/{}.00000007.extra", j).parse::<Key>(),
            Err(ParseError::Field("generation"))
        );
    }

    #[test]
    fn non_ascii_key_does_not_panic() {
        assert_eq!("\u{2603}".parse::<Key>(), Err(ParseError::UnknownPrefix));
        assert_eq!(
            "jobs/0f0e/\u{2603}".parse::<Key>(),
            Err(ParseError::Field("job-id"))
        );
    }

    // SHA256("StowQ-1-shard\0" || Q || J), first 2 bytes big-endian.
    const SHARD_RAW: u16 = 0x8c3e;

    #[test]
    fn shard_known_value() {
        assert_eq!(compute_shard(&Q, &J, 65536), SHARD_RAW);
        assert_eq!(compute_shard(&Q, &J, 256), SHARD_RAW & 0xff);
        assert_eq!(compute_shard(&Q, &J, 1), 0);
    }

    #[test]
    fn shard_is_deterministic_and_queue_scoped() {
        assert_eq!(compute_shard(&Q, &J, 65536), compute_shard(&Q, &J, 65536));
        assert_ne!(compute_shard(&Q, &J, 65536), compute_shard(&J, &J, 65536));
    }

    // SHA256("StowQ-1-key\0" || Q || "meta/FORMAT"), first 8 bytes.
    const TAG_FORMAT: [u8; 8] = [0xa5, 0xaf, 0x76, 0x59, 0xa5, 0x14, 0x5e, 0x19];

    #[test]
    fn key_tag_known_value() {
        assert_eq!(key_tag(&Q, "meta/FORMAT"), TAG_FORMAT);
    }

    #[test]
    fn key_tag_binds_key_and_queue() {
        let j = Key::Job {
            shard: 1,
            job_id: J,
        }
        .to_string();
        let c = Key::Claim {
            shard: 1,
            job_id: J,
            generation: 2,
        }
        .to_string();
        assert_ne!(key_tag(&Q, &j), key_tag(&Q, &c));
        assert_ne!(key_tag(&Q, &j), key_tag(&J, &j));
    }
}
