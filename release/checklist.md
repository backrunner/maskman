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
- [x] release benchmark compared with the previous release on a fixed host (rc.1 vs 0.1.0 on the same Mac, 2026-08-28; small-payload deltas are run-to-run noise, see `.agents/12-m8-evidence.md`)
- [x] all three release binaries built from locked dependencies with Rust 1.88
- [x] all three target archives built from locked dependencies (release workflow run 32767328768, 2026-08-24)
- [x] SBOM and provenance attestations uploaded (SPDX assets on the draft release; build-provenance attestations in the repository attestation store)

Deferred gates, not part of the Surge server-only rc profile:

- Linux namespace dual-stack smoke and target-machine managed NAT
  apply/rollback: required before any CONNECT-IP/TUN release claim
  (see `.agents/12-m8-evidence.md`).
- Independent MASQUE interoperability record: required before the v1.0
  release.

Waived for the rc track by maintainer decision (2026-08-28), required again
before v1.0:

- macOS arm64 utun/route privileged smoke;
- 24-hour soak report;
- clean-host SHA-256 and Ed25519 signature verification;
- update install, staged validation, health check, and rollback exercise;
- setup -> install -> start -> status -> stop record.

This waiver overrides the maskman-guard hard stop on publishing without an
exercised update signature/rollback path; the decision and the guard's
objection are recorded in `.agents/12-m8-evidence.md`.

The release benchmark comparison remains the only open gate for the rc
track; v0.1.0-rc.1 was published with it open per the same decision.
