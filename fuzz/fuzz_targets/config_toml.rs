#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    if let Ok(text) = std::str::from_utf8(input) {
        if let Ok(document) = toml::from_str::<maskman_config::ConfigDocument>(text) {
            let _ = maskman_config::validate(&document);
        }
    }
});
