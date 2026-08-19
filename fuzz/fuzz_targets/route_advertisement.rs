#![no_main]

use libfuzzer_sys::fuzz_target;
use maskman_protocol::capsule::decode_route_advertisement;

fuzz_target!(|data: &[u8]| {
    let _ = decode_route_advertisement(data);
});
