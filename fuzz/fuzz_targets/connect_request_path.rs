#![no_main]

use libfuzzer_sys::fuzz_target;
use maskman_protocol::connect::{parse_ip_path, parse_udp_path};

fuzz_target!(|data: &[u8]| {
    if let Ok(path) = std::str::from_utf8(data) {
        let _ = parse_udp_path(path, "/.well-known/masque");
        let _ = parse_ip_path(path, "/.well-known/masque");
    }
});
