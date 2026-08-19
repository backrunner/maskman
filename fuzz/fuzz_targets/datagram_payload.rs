#![no_main]

use libfuzzer_sys::fuzz_target;
use maskman_protocol::capsule::{decode_datagram, validate_udp_payload};

fuzz_target!(|data: &[u8]| {
    if let Ok(datagram) = decode_datagram(data) {
        let _ = validate_udp_payload(&datagram);
    }
});
