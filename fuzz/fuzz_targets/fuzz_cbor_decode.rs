#![no_main]

use libfuzzer_sys::fuzz_target;
use stowq_format::cbor;

// Canonicality contract: anything decode accepts, encode reproduces
// byte-for-byte, and decode accepts its own re-encoding.
fuzz_target!(|data: &[u8]| {
    if let Ok(value) = cbor::decode(data) {
        let encoded = cbor::encode(&value);
        assert_eq!(encoded, data);
        assert_eq!(cbor::decode(&encoded), Ok(value));
    }
});
