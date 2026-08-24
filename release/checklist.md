# Maskman release checklist

This checklist is intentionally evidence-driven. A checked local unit test is
not a substitute for a privileged target or an independent interoperability
run.

- [x] `cargo fmt --all -- --check` (local, 2026-08-20)
- [x] stable and Rust 1.88 `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- [x] Rust 1.88 `cargo test --workspace --locked` (89 tests)
- [x] `cargo deny check` and `cargo audit` with the documented `paste` allow
- [x] `cargo machete 0.9.2` reports no unused direct dependencies
- [x] `cargo xtask compliance` (43 cumulative requirements)
- [x] Surge Basic-authenticated CONNECT-UDP server forwarding test
- [x] all eight fuzz targets completed 100,000 runs with bounded RSS and allocation limits
- [x] codec/packet benchmark smoke recorded in `.agents/12-m8-evidence.md`
- [ ] release benchmark compared with the previous release on a fixed host
- [ ] Linux namespace dual-stack smoke recorded (deferred for the Surge server-only scope; required before CONNECT-IP/TUN release)
- [ ] macOS arm64 utun/route privileged smoke recorded
- [ ] independent MASQUE interoperability record attached
- [ ] 24-hour soak report attached
- [x] all three release binaries built from locked dependencies with Rust 1.88
- [ ] all three target archives built from locked dependencies
- [ ] SHA-256 files and independent Ed25519 signatures verified on a clean host
- [ ] SBOM and provenance attestations uploaded
- [ ] update install, staged validation, health check, and rollback exercised
- [ ] setup -> install -> start -> status -> stop run recorded

Any unchecked target or external gate keeps the GitHub release in draft.
