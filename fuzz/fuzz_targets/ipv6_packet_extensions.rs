#![no_main]

use libfuzzer_sys::fuzz_target;
use maskman_protocol::packet::Ipv6Packet;

fuzz_target!(|data: &[u8]| {
    let _ = Ipv6Packet::parse(data);
});
