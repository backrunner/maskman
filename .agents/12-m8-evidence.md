# M8 质量与发布证据

本文件区分本 checkout 已执行的本地验证、CI 中可重复的自动门禁和仍需
目标环境的 release blocker。记录日期为 2026-08-20，基线提交为
`dc02e4ae368f`，M8 改动尚未提交。

## 本地已验证

| 项目 | 结果 |
| --- | --- |
| 格式与静态检查 | `cargo fmt --all -- --check`、ShellCheck、actionlint、shell syntax、workflow YAML 和 `git diff --check` 通过 |
| Workspace | stable 与 Rust 1.88 clippy 通过；Rust 1.88 `cargo test --workspace --locked` 通过，共 89 tests |
| 依赖 | `cargo deny check` 通过；`cargo audit` 仅保留已记录的 `paste` unmaintained allow；`cargo machete 0.9.2` 未发现 unused dependencies |
| Compliance | `cargo xtask compliance` 通过，共 43 条 cumulative requirements |
| Fuzz | 8 个 target 各完成 100,000 runs，`rss_limit_mb=1024`、`malloc_limit_mb=64`，无 crash |
| Codec benchmark | Rust 1.88 release、100,000 iterations、8 ms、36,466,591 combined codec/packet ops/s；这是本机 smoke，不是端到端容量承诺 |
| Signing command | 临时 Ed25519 key 完成 OpenSSL `pkeyutl -sign/-verify -rawin`，并验证 DER 末 32 字节公钥提取；临时 key 已删除；未注入生产公钥的构建会禁用 update |
| Target compile | Rust 1.88 locked release build 通过：x86_64 Linux musl、aarch64 Linux musl、aarch64 macOS |

Linux cross-build 发现并修复了 `maskman-platform` 对
`netlink-packet-route` 的漏声明直接依赖。Linux 使用本机 Zig 0.16.0；CI 和
release workflow 固定 Zig 0.14.1，因此 workflow 仍需在 GitHub runner 上执行。

最初的 `capsule_decoder` 长 fuzz 在旧的 512 MiB RSS 上限触发 macOS ASan
quarantine/coverage 内存增长，目标 live heap 约 24 MiB。生成输入单次回放在
64 MiB allocation limit 下通过，没有形成 crash regression；生成 corpus 与
artifact 已删除。随后全部 target 使用修订后的双重限制完成 100,000 runs。

## 已加入的可重复入口

- `cargo xtask benchmark --iterations N` 覆盖 capsule、HTTP Datagram 和 IPv4
  packet parse，并输出固定字段。
- `fuzz/` 包含 capsule、datagram、CONNECT path、IPv4、IPv6、route 和
  TOML/JSON config targets，以及小型 checked-in seed corpus。
- `scripts/namespace-smoke.sh` 创建 Linux client/proxy/target 双栈拓扑，但
  明确不把 routed ping 当作 Maskman TUN/session forwarding 证据。
- `scripts/macos-arm64-smoke.sh`、`scripts/soak.sh` 和
  `tests/interop/README.md` 固定目标 runner、长稳和互操作记录入口。
- `.github/workflows/ci.yml`、`.github/workflows/release.yml` 和
  `release/runbook.md` 固定 MSRV、三目标构建、签名、SBOM、provenance、draft
  release 与 operator rollback 流程。

## 未执行的 release blocker

- 真实 Linux namespace 双栈 Maskman TUN forwarding；
- macOS arm64 utun、route 和 pf 特权转发；
- 独立 MASQUE client 与外部 mTLS 互操作；
- 24 小时 mixed-traffic soak；
- managed NAT backend；
- 生产 Ed25519 key、clean-host archive/signature/SBOM/provenance 验证；
- setup -> install -> start -> status -> stop 完整记录；
- clean-host update、checksum、signature、health-check 和 rollback 演练。

任一 blocker 未完成时，GitHub release 必须保持 draft，README 不得标记 v1.0
完成。
