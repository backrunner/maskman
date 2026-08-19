#![no_main]

use libfuzzer_sys::fuzz_target;
use maskman_protocol::capsule::{CapsuleLimits, Decoder};

fuzz_target!(|data: &[u8]| {
    let mut decoder = Decoder::new(CapsuleLimits::uniform(4096));
    for chunk in data.chunks(17) {
        let _ = decoder.push(chunk);
    }
    let _ = decoder.finish();
});
