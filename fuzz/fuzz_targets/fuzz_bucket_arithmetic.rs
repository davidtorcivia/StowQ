#![no_main]

use libfuzzer_sys::fuzz_target;
use stowq_math::{
    bucket_end_ns, bucket_number, bucket_start_ns, ceiling_bucket, effective_floor,
    eligibility_bucket_and_ns, retry_not_before,
};

fn u64_at(data: &[u8], i: usize) -> u64 {
    let mut buf = [0u8; 8];
    for (k, b) in buf.iter_mut().enumerate() {
        *b = data.get((i + k) % data.len().max(1)).copied().unwrap_or(0);
    }
    u64::from_be_bytes(buf)
}

fuzz_target!(|data: &[u8]| {
    let ts = u64_at(data, 0);
    let width = u64_at(data, 8).max(1);

    if let Some(b) = bucket_number(ts, width) {
        assert!(b <= ts / width);
    }
    if let Some(c) = ceiling_bucket(ts, width) {
        let q = ts / width;
        assert!(c >= q);
        assert!(c.saturating_sub(q) <= 1);
    }
    if let Some((b, ns)) = eligibility_bucket_and_ns(ts, width) {
        assert!(ns >= ts);
        assert_eq!(bucket_number(ns, width), Some(b));
    }
    if let Some(s) = bucket_start_ns(u64_at(data, 16), width) {
        if let Some(e) = bucket_end_ns(u64_at(data, 16), width) {
            assert!(e >= s);
        }
    }
    if let Some(f) = effective_floor(ts, u64_at(data, 16), width) {
        assert!(f >= ts);
    }
    if let Some(d) = retry_not_before(ts, width) {
        assert!(d >= ts);
        assert!(d <= i64::MAX as u64);
    }
});
