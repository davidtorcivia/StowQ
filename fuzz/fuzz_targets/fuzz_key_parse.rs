#![no_main]

use libfuzzer_sys::fuzz_target;
use std::str::FromStr;

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    if let Ok(key) = stowq_keys::Key::from_str(&s) {
        let re = key.to_string();
        assert_eq!(stowq_keys::Key::from_str(&re), Ok(key));
    }
});
