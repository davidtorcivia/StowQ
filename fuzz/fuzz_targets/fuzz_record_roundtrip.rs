#![no_main]

use libfuzzer_sys::fuzz_target;
use stowq_format::{decode, encode};

const Q: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];
const TAG: [u8; 8] = [0x07; 8];

// Any accepted record re-encodes to exactly the input bytes.
fuzz_target!(|data: &[u8]| {
    if let Ok(record) = decode(data, &Q, &TAG) {
        assert_eq!(encode(&record, &Q, &TAG), data);
    }
});
