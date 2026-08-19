#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    if let Ok(document) = serde_json::from_slice::<maskman_config::ConfigDocument>(input) {
        let _ = maskman_config::validate(&document);
    }
});
