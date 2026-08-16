//! Bucket arithmetic, retry backoff with equal jitter, and checked time
//! conversions for StowQ/1.
//!
//! All timestamps are store-time nanoseconds. All division-based helpers
//! return `None` on zero widths or overflow rather than panicking.

use sha2::{Digest as _, Sha256};
use thiserror::Error;

// ---------- Bucket arithmetic ----------

/// floor(timestamp_ns / bucket_width_ns).
pub fn bucket_number(timestamp_ns: u64, bucket_width_ns: u64) -> Option<u64> {
    if bucket_width_ns == 0 {
        return None;
    }
    Some(timestamp_ns / bucket_width_ns)
}

/// ceil(timestamp_ns / bucket_width_ns).
pub fn ceiling_bucket(timestamp_ns: u64, bucket_width_ns: u64) -> Option<u64> {
    if bucket_width_ns == 0 {
        return None;
    }
    let q = timestamp_ns / bucket_width_ns;
    let r = timestamp_ns % bucket_width_ns;
    if r != 0 {
        q.checked_add(1)
    } else {
        Some(q)
    }
}

/// Rounded-up eligibility bucket for delayed scheduling:
/// bucket = ceil(requested_ns / width), ns = bucket * width (checked).
pub fn eligibility_bucket_and_ns(requested_ns: u64, bucket_width_ns: u64) -> Option<(u64, u64)> {
    let bucket = ceiling_bucket(requested_ns, bucket_width_ns)?;
    let ns = bucket.checked_mul(bucket_width_ns)?;
    Some((bucket, ns))
}

/// bucket * width.
pub fn bucket_start_ns(bucket: u64, bucket_width_ns: u64) -> Option<u64> {
    bucket.checked_mul(bucket_width_ns)
}

/// bucket_start_ns + width.
pub fn bucket_end_ns(bucket: u64, bucket_width_ns: u64) -> Option<u64> {
    bucket_start_ns(bucket, bucket_width_ns)?.checked_add(bucket_width_ns)
}

// ---------- Retry backoff ----------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetryPolicy {
    base_ms: u64,
    cap_ms: u64,
    use_jitter: bool,
    max_delay_ms: Option<u64>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RetryError {
    #[error("base_ms must be positive")]
    ZeroBase,
    #[error("cap_ms must be >= base_ms")]
    CapTooSmall,
    #[error("deadline overflow")]
    Overflow,
}

impl RetryPolicy {
    pub fn new(
        base_ms: u64,
        cap_ms: u64,
        use_jitter: bool,
        max_delay_ms: Option<u64>,
    ) -> Result<Self, RetryError> {
        let policy = RetryPolicy {
            base_ms,
            cap_ms,
            use_jitter,
            max_delay_ms,
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn base_ms(&self) -> u64 {
        self.base_ms
    }

    pub fn cap_ms(&self) -> u64 {
        self.cap_ms
    }

    pub fn use_jitter(&self) -> bool {
        self.use_jitter
    }

    pub fn max_delay_ms(&self) -> Option<u64> {
        self.max_delay_ms
    }

    pub fn validate(&self) -> Result<(), RetryError> {
        if self.base_ms == 0 {
            return Err(RetryError::ZeroBase);
        }
        if self.effective_cap_ms() < self.base_ms {
            return Err(RetryError::CapTooSmall);
        }
        Ok(())
    }

    pub fn effective_cap_ms(&self) -> u64 {
        match self.max_delay_ms {
            Some(max) => self.cap_ms.min(max),
            None => self.cap_ms,
        }
    }
}

/// Saturating base * 2^(exp-1).
fn saturating_double(base: u64, exp: u32) -> u64 {
    if exp == 0 || base == 0 {
        return base;
    }
    if exp > 64 {
        return u64::MAX;
    }
    let shift = exp - 1;
    if base > (u64::MAX >> shift) {
        u64::MAX
    } else {
        base << shift
    }
}

/// Retry delay in milliseconds for a given attempt.
/// For attempt >= 1: ceiling = min(cap, saturating(base * 2^(attempt-1)));
/// lower = ceil(ceiling / 2); span = ceiling - lower + 1; with jitter the
/// offset is rejection-sampled from SHA256("StowQ-1-jitter\0" || queue_id
/// || job_id || attempt || counter) so it is deterministic per job.
pub fn retry_delay_ms(
    queue_id: &[u8; 16],
    job_id: &[u8; 16],
    attempt: u32,
    policy: &RetryPolicy,
) -> Result<u64, RetryError> {
    policy.validate()?;

    if attempt == 0 {
        return Ok(0);
    }

    let cap = policy.effective_cap_ms();
    let ceiling = cap.min(saturating_double(policy.base_ms, attempt));

    if !policy.use_jitter() {
        return Ok(ceiling);
    }

    let lower = ceiling.div_ceil(2);
    let span = ceiling - lower + 1;
    let offset = sample_offset(span, |counter| {
        let mut hasher = Sha256::new();
        hasher.update(b"StowQ-1-jitter\0");
        hasher.update(queue_id);
        hasher.update(job_id);
        hasher.update(attempt.to_be_bytes());
        hasher.update(counter.to_be_bytes());
        let result = hasher.finalize();
        u64::from_be_bytes(result[..8].try_into().unwrap())
    });
    Ok(lower + offset)
}

/// Rejection-sampled offset in [0, span). `draw` maps a rejection counter
/// to a u64 sample; samples below `threshold` are biased and rejected.
/// After 64 rejections the span midpoint is returned, which is also
/// unbiased.
fn sample_offset(span: u64, mut draw: impl FnMut(u32) -> u64) -> u64 {
    let threshold = span.wrapping_neg() % span;
    let mut counter = 0u32;
    loop {
        let x = draw(counter);
        if x >= threshold {
            return x % span;
        }
        counter += 1;
        if counter >= 64 {
            return span / 2;
        }
    }
}

/// retry_not_before = floor_ns + delay_ns, bounded to i64::MAX so the
/// value survives conversion to signed wall-clock domains.
pub fn retry_not_before(floor_ns: u64, delay_ns: u64) -> Option<u64> {
    let deadline = floor_ns.checked_add(delay_ns)?;
    if deadline > i64::MAX as u64 {
        return None;
    }
    Some(deadline)
}

/// max(floor_ns, watermark_bucket * width): the watermark can only raise a
/// floor, never lower it.
pub fn effective_floor(floor_ns: u64, watermark_bucket: u64, bucket_width_ns: u64) -> Option<u64> {
    if bucket_width_ns == 0 {
        return None;
    }
    let watermark_ns = watermark_bucket.checked_mul(bucket_width_ns)?;
    Some(floor_ns.max(watermark_ns))
}

#[cfg(test)]
mod tests {
    use super::*;

    const Q: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    const J: [u8; 16] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f,
    ];

    #[test]
    fn bucket_number_floors() {
        let width = 10_000_000_000u64; // 10s
        assert_eq!(bucket_number(0, width), Some(0));
        assert_eq!(bucket_number(width, width), Some(1));
        assert_eq!(bucket_number(width - 1, width), Some(0));
        assert_eq!(bucket_number(2 * width + 1, width), Some(2));
        assert_eq!(bucket_number(5, 0), None);
    }

    #[test]
    fn ceiling_bucket_rounds_up() {
        let width = 10u64;
        assert_eq!(ceiling_bucket(0, width), Some(0));
        assert_eq!(ceiling_bucket(1, width), Some(1));
        assert_eq!(ceiling_bucket(10, width), Some(1));
        assert_eq!(ceiling_bucket(11, width), Some(2));
        assert_eq!(ceiling_bucket(u64::MAX, 1), Some(u64::MAX));
        // ceil(ts/w) <= ts, so ceiling division never overflows for u64.
        assert_eq!(ceiling_bucket(u64::MAX, 2), Some(1 << 63));
        assert_eq!(ceiling_bucket(0, 0), None);
    }

    #[test]
    fn eligibility_rounds_up_and_remultiplies() {
        let width = 10u64;
        assert_eq!(eligibility_bucket_and_ns(0, width), Some((0, 0)));
        assert_eq!(eligibility_bucket_and_ns(1, width), Some((1, 10)));
        assert_eq!(eligibility_bucket_and_ns(25, width), Some((3, 30)));
        assert_eq!(eligibility_bucket_and_ns(1, 0), None);
        // bucket = ceil(u64::MAX / 2) = 2^63; 2^63 * 2 overflows.
        assert_eq!(eligibility_bucket_and_ns(u64::MAX, 2), None);
    }

    #[test]
    fn bucket_bounds_are_consistent() {
        let width = 1_000u64;
        for bucket in [0u64, 1, 7, 1_000] {
            let start = bucket_start_ns(bucket, width).unwrap();
            let end = bucket_end_ns(bucket, width).unwrap();
            assert_eq!(end - start, width);
            assert_eq!(bucket_number(start, width), Some(bucket));
        }
        assert_eq!(bucket_end_ns(u64::MAX, width), None);
        // start fits, start + width overflows.
        assert_eq!(bucket_end_ns(18_446_744_073_709_551, 1_000), None);
    }

    fn policy(base: u64, cap: u64, jitter: bool) -> RetryPolicy {
        RetryPolicy::new(base, cap, jitter, None).unwrap()
    }

    #[test]
    fn policy_validation() {
        assert_eq!(
            RetryPolicy::new(0, 100, true, None).unwrap_err(),
            RetryError::ZeroBase
        );
        assert_eq!(
            RetryPolicy::new(200, 100, true, None).unwrap_err(),
            RetryError::CapTooSmall
        );
        // max_delay below cap lowers the effective cap.
        let p = RetryPolicy::new(10, 100, false, Some(50)).unwrap();
        assert_eq!(p.effective_cap_ms(), 50);
        assert_eq!(
            RetryPolicy::new(60, 100, false, Some(50)).unwrap_err(),
            RetryError::CapTooSmall
        );
    }

    #[test]
    fn delay_without_jitter_doubles_then_caps() {
        let p = policy(100, 1_600, false);
        assert_eq!(retry_delay_ms(&Q, &J, 0, &p).unwrap(), 0);
        assert_eq!(retry_delay_ms(&Q, &J, 1, &p).unwrap(), 100);
        assert_eq!(retry_delay_ms(&Q, &J, 2, &p).unwrap(), 200);
        assert_eq!(retry_delay_ms(&Q, &J, 3, &p).unwrap(), 400);
        assert_eq!(retry_delay_ms(&Q, &J, 5, &p).unwrap(), 1_600);
        // Saturates at cap forever after.
        assert_eq!(retry_delay_ms(&Q, &J, 40, &p).unwrap(), 1_600);
    }

    #[test]
    fn delay_with_jitter_stays_in_upper_half() {
        let p = policy(100, 1_600, true);
        // Equal jitter: delay lies in [ceiling/2, ceiling].
        assert_eq!(retry_delay_ms(&Q, &J, 0, &p).unwrap(), 0);
        let d1 = retry_delay_ms(&Q, &J, 1, &p).unwrap();
        assert!((50..=100).contains(&d1), "attempt 1 delay {d1}");
        let d5 = retry_delay_ms(&Q, &J, 5, &p).unwrap();
        assert!((800..=1_600).contains(&d5), "attempt 5 delay {d5}");
        // Deterministic per (queue, job, attempt).
        assert_eq!(d1, retry_delay_ms(&Q, &J, 1, &p).unwrap());
        // Different job, different draw (with overwhelming probability).
        assert_ne!(
            retry_delay_ms(&Q, &Q, 1, &p).unwrap(),
            retry_delay_ms(&Q, &J, 1, &p).unwrap()
        );
    }

    #[test]
    fn delay_max_delay_tightens_cap() {
        // cap 1600, max_delay 300: attempt 5 would be 1600 without the
        // clamp; with it the ceiling (and no-jitter delay) is 300.
        let p = RetryPolicy::new(100, 1_600, false, Some(300)).unwrap();
        assert_eq!(retry_delay_ms(&Q, &J, 5, &p).unwrap(), 300);
        let pj = RetryPolicy::new(100, 1_600, true, Some(300)).unwrap();
        let d = retry_delay_ms(&Q, &J, 5, &pj).unwrap();
        assert!((150..=300).contains(&d), "attempt 5 delay {d}");
    }

    // SHA256("StowQ-1-jitter\0" || Q || J || attempt=1 BE || counter=0 BE),
    // first 8 bytes big-endian.
    const JITTER_X: u64 = 0xa56cdc89987e2da1;

    #[test]
    fn jitter_draw_known_value() {
        // attempt 1, base 100, cap 1600: ceiling=100, lower=50, span=51.
        // offset = JITTER_X % 51, delay = 50 + offset.
        let expected = 50 + (JITTER_X % 51);
        let p = policy(100, 1_600, true);
        assert_eq!(retry_delay_ms(&Q, &J, 1, &p).unwrap(), expected);
    }

    #[test]
    fn jitter_odd_ceiling_uses_div_ceil_lower_bound() {
        // base 101, cap 151, attempt 1: odd ceiling 101, lower must be
        // ceil(101/2) = 51 and span = 51. A truncating-div mutant lowers
        // lower to 50 and span to 52, changing this delay to 95.
        let p = policy(101, 151, true);
        assert_eq!(retry_delay_ms(&Q, &J, 1, &p).unwrap(), 51 + (JITTER_X % 51));
    }

    #[test]
    fn sampler_accepts_first_draw_and_rejects_below_threshold() {
        // span 4: threshold = (-4) % 4 = 2^64 % 4 = 0, so every draw is
        // accepted; offset = draw % 4.
        assert_eq!(sample_offset(4, |_| 11), 3);
        // span 6: threshold = 2^64 % 6 = 4; draw 3 is rejected, draw 9
        // accepted on the second call.
        let mut calls = 0;
        assert_eq!(
            sample_offset(6, |c| {
                calls += 1;
                if c == 0 {
                    3
                } else {
                    9
                }
            }),
            3
        );
        assert_eq!(calls, 2);
    }

    #[test]
    fn sampler_falls_back_to_midpoint_after_64_rejections() {
        // threshold for span 3 is 2^64 % 3 = 1; draw 0 is always rejected.
        let mut calls = 0;
        assert_eq!(
            sample_offset(3, |c| {
                calls += 1;
                let _ = c;
                0
            }),
            1
        );
        assert_eq!(calls, 64);
    }

    #[test]
    fn retry_not_before_bounded() {
        assert_eq!(retry_not_before(100, 200), Some(300));
        assert_eq!(retry_not_before(u64::MAX, 1), None);
        assert_eq!(retry_not_before(i64::MAX as u64, 0), Some(i64::MAX as u64));
        assert_eq!(retry_not_before(i64::MAX as u64, 1), None);
    }

    #[test]
    fn effective_floor_takes_the_max() {
        let width = 10_000_000_000u64;
        assert_eq!(effective_floor(50, 0, width), Some(50));
        assert_eq!(effective_floor(50, 10, width), Some(100_000_000_000));
        // watermark_bucket * width overflows.
        assert_eq!(effective_floor(0, u64::MAX, width), None);
        assert_eq!(effective_floor(0, 0, 0), None);
    }

    #[test]
    fn saturating_double_edges() {
        assert_eq!(saturating_double(0, 10), 0);
        assert_eq!(saturating_double(5, 0), 5);
        assert_eq!(saturating_double(5, 1), 5);
        assert_eq!(saturating_double(5, 2), 10);
        assert_eq!(saturating_double(u64::MAX / 2 + 1, 2), u64::MAX);
        assert_eq!(saturating_double(1, 64), 1 << 63);
        assert_eq!(saturating_double(1, 65), u64::MAX);
        assert_eq!(saturating_double(1, 100), u64::MAX);
    }
}
