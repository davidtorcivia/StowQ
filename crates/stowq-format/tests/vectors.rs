//! Pins the committed encoding vectors from spec/records.md. Any change to
//! the canonical encoding breaks these tests.

use stowq_format::*;

const JOB_HEX: &str = "871b53544f5751312d00010050000102030405060708090a0b0c0d0e0f48070707070707070702a7666a6f625f696450101112131415161718191a1b1c1d1e1f6c636f6e74656e745f747970656a746578742f706c61696e6e7061796c6f61645f6469676573745820896084e74043a1d22eb32d0eb9a63bce64c3792426a2ddd4b97509c68ff5cd386e7061796c6f61645f696e6c696e654b68656c6c6f2073746f77716e7061796c6f61645f6c656e6774680b706d6178696d756d5f617474656d7074730375637265617465645f73746f72655f74696d655f6e730058208b73824ef400fd84f63d7d43f1c443c32089b122731bd49308ac2737d6015df9";

const CLAIM_HEX: &str = "871b53544f5751312d00010050000102030405060708090a0b0c0d0e0f48070707070707070703a8656261736973a370707265765f6475726174696f6e5f6e730072707265765f73746f72655f74696d655f6e7300756f627365727665645f77617465726d61726b5f6e7300666a6f625f696450101112131415161718191a1b1c1d1e1f67617474656d70740169776f726b65725f69646277316a67656e65726174696f6e016c636f6e74696e756174696f6ef46c776f726b65725f746f6b656e5042424242424242424242424242424242716c656173655f6475726174696f6e5f6e731b0000000df84758005820c9f5f3ee7144d8fa17ba93498f04c4548667aa9c895864fc85274ad08aeec1ca";

const Q: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];
const TAG: [u8; 8] = [0x07; 8];
const J: [u8; 16] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn job_record() -> Record {
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&unhex(
        "896084e74043a1d22eb32d0eb9a63bce64c3792426a2ddd4b97509c68ff5cd38",
    ));
    Record::Job(JobRecord {
        job_id: J,
        maximum_attempts: 3,
        content_type: "text/plain".into(),
        created_store_time_ns: 0,
        not_before_ns: None,
        payload_digest: digest,
        payload_length: 11,
        payload_inline: Some(b"hello stowq".to_vec()),
        payload_key: None,
    })
}

fn claim_record() -> Record {
    Record::Claim(ClaimRecord {
        job_id: J,
        generation: 1,
        attempt: 1,
        worker_id: "w1".into(),
        worker_token: [0x42; 16],
        lease_duration_ns: 60_000_000_000,
        continuation: false,
        basis: Some(ClaimBasis {
            prev_store_time_ns: 0,
            prev_duration_ns: 0,
            observed_watermark_ns: 0,
        }),
        prev_token: None,
    })
}

#[test]
fn job_vector_round_trips_both_directions() {
    let bytes = unhex(JOB_HEX);
    assert_eq!(decode(&bytes, &Q, &TAG), Ok(job_record()));
    assert_eq!(encode(&job_record(), &Q, &TAG), bytes);
}

#[test]
fn claim_vector_round_trips_both_directions() {
    let bytes = unhex(CLAIM_HEX);
    assert_eq!(decode(&bytes, &Q, &TAG), Ok(claim_record()));
    assert_eq!(encode(&claim_record(), &Q, &TAG), bytes);
}

const QUARANTINE_HEX: &str = "871b53544f5751312d00010050000102030405060708090a0b0c0d0e0f48070707070707070708a56371696450101010101010101010101010101010106664657461696c0266726561736f6e106a736f757263655f6b65797835636c61696d732f303030312f31303131313231333134313531363137313831393161316231633164316531662f3030303030303032716f627365727665645f73746f72655f6e7319138858209a9f89b5a1c7027b560c8b657b9e85dc2886e1e901c5c6d9bff9e7d423527107";

fn quarantine_record() -> Record {
    Record::Quarantine(QuarantineRecord {
        qid: [0x10; 16],
        source_key: "claims/0001/101112131415161718191a1b1c1d1e1f/00000002".into(),
        reason: 0x0010,
        observed_store_ns: 5_000,
        detail: Some(2),
    })
}

#[test]
fn quarantine_vector_round_trips_both_directions() {
    let bytes = unhex(QUARANTINE_HEX);
    assert_eq!(decode(&bytes, &Q, &TAG), Ok(quarantine_record()));
    assert_eq!(encode(&quarantine_record(), &Q, &TAG), bytes);
}

#[test]
fn record_digests_match_spec() {
    let job_digest = &unhex(JOB_HEX)[unhex(JOB_HEX).len() - 32..];
    assert_eq!(
        hex(job_digest),
        "8b73824ef400fd84f63d7d43f1c443c32089b122731bd49308ac2737d6015df9"
    );
    let claim_digest = &unhex(CLAIM_HEX)[unhex(CLAIM_HEX).len() - 32..];
    assert_eq!(
        hex(claim_digest),
        "c9f5f3ee7144d8fa17ba93498f04c4548667aa9c895864fc85274ad08aeec1ca"
    );
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
