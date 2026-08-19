# M2 Protocol Compliance Evidence

## Scope

M2 implements the sans-I/O protocol core for the declared v1 HTTP/3-only
profile. It does not claim authentication, DNS, socket forwarding, TUN, or
platform service support; those are M3-M5 deliverables.

Implemented protocol boundaries:

- RFC 9297 incremental Capsule decoder and encoder;
- bounded unknown/oversized Capsule skipping;
- RFC 9298 CONNECT-UDP path and Context ID 0 payload validation;
- RFC 9484 wildcard `%2A`, IP scope, ADDRESS and ROUTE codecs;
- IPv4 checksum/length validation;
- bounded IPv6 extension walking and outer protocol extraction;
- atomic ADDRESS_ASSIGN and ROUTE_ADVERTISEMENT replacement;
- default-deny classification for non-global destinations.

## Evidence

The repository contains:

- `compliance/rfc.toml`: 27 machine-readable M2 requirements;
- `xtask compliance --check-only`: matrix/schema/source/test reference check;
- `xtask compliance`: matrix check followed by protocol and transport tests;
- `crates/maskman-protocol/tests/compliance.rs`: 13 golden and negative tests;
- `crates/maskman-protocol/tests/properties.rs`: 6 bounded property tests;
- `fuzz/fuzz_targets/`: capsule, datagram, path, IPv4, IPv6, and route targets.

## Gate result

On 2026-08-20:

```text
cargo test --workspace --locked       52 passed
cargo clippy --workspace ...          clean
cargo fmt --all -- --check            clean
cargo deny check                      passed with duplicate-version warnings
cargo audit                           passed
cargo xtask compliance                passed
cargo check --manifest-path fuzz/Cargo.toml --all-targets  passed
```

The referenced `quick_validate.py` mentioned by the guard workflow is not
present in this checkout, so that optional skill-validator command could not
be run. No protocol or runtime change relies on that missing script.
