#![no_main]

use libfuzzer_sys::fuzz_target;
use maskman_protocol::packet::Ipv4Packet;

fuzz_target!(|data: &[u8]| {
    let _ = Ipv4Packet::parse(data);
});
