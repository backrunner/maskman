# M8 质量与发布证据

本文件区分本 checkout 已执行的本地验证、CI 中可重复的自动门禁和仍需
目标环境的 release blocker。记录日期为 2026-08-22；当前 checkout 包含
supervisor/worker、journal transaction 和平台 hardening 改动。本记录不等同于
release gate 通过。

## 本地已验证

| 项目 | 结果 |
| --- | --- |
| 格式与静态检查 | `cargo fmt --all -- --check`、ShellCheck、actionlint、shell syntax、workflow YAML 和 `git diff --check` 通过 |
| Workspace | stable clippy 通过；`cargo test --workspace --locked --all-targets` 通过，共 137 tests |
| 依赖 | `cargo deny check` 通过；`cargo audit` 仅保留已记录的 `paste` unmaintained allow；`cargo machete 0.9.2` 未发现 unused dependencies |
| Compliance | `cargo xtask compliance` 通过，共 43 条 cumulative requirements |
| Fuzz | 8 个 target 各完成 100,000 runs，`rss_limit_mb=1024`、`malloc_limit_mb=64`，无 crash |
| Codec benchmark | Rust 1.97.1 release、扩展后的 HTTP/video/mixed payload matrix（含 64B 至 65,527B）、p50/p95/p99、ops/s 和 bytes/s 已写入 `benchmarks/baseline.csv`；这是本机 codec/packet pipeline smoke，不是端到端容量承诺 |
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

- `cargo xtask benchmark --iterations N --profiles http,video,mixed --payloads
  64,512,1200 --output benchmarks/baseline.csv` 覆盖 HTTP/TCP、video/UDP、mixed
  TCP/UDP 的合成流量形状，并输出可追溯 CSV 基线；CPU、governor、RSS 通过
  `MASKMAN_BENCH_*` 环境变量记录。
- `fuzz/` 包含 capsule、datagram、CONNECT path、IPv4、IPv6、route 和
  TOML/JSON config targets，以及小型 checked-in seed corpus。
- `scripts/namespace-smoke.sh` 创建 Linux client/proxy/target 双栈拓扑，但
  明确不把 routed ping 当作 Maskman TUN/session forwarding 证据。
- Surge 服务端路径已通过 `maskman-server` 的
  `surge_basic_auth_connect_udp_forwards_to_connected_socket` 端到端测试：
  HTTP/3 CONNECT-UDP、Basic token credentials、UDP target forwarding 和
  response datagram path 均通过；该测试不替代真实 Surge 设备互操作记录。
- `scripts/macos-arm64-smoke.sh`、`scripts/soak.sh` 和
  `tests/interop/README.md` 固定目标 runner、长稳和互操作记录入口。
- `.github/workflows/ci.yml`、`.github/workflows/release.yml` 和
  `release/runbook.md` 固定 MSRV、三目标构建、签名、SBOM、provenance、draft
  release 与 operator rollback 流程。

## 未执行的 release blocker

2026-08-28 范围修订：三目标 archive、SBOM 和 build-provenance attestation
已由 release workflow run 32767328768（2026-08-24）完成并上传，不再列为
blocker。Linux namespace 双栈 smoke 与目标机 managed NAT 移出 rc blocker，
仅作为 CONNECT-IP/TUN release 的前置要求；独立 MASQUE 互操作记录降级为
v1.0 的 gate。

2026-08-28 第二次修订（maintainer 决定）：为轻量敏捷迭代，以下门禁对 rc
track 全部豁免，v0.1.0-rc.1 在它们未完成的情况下发布；v1.0 前必须恢复：

- macOS arm64 utun、route 和 pf 特权转发；
- 24 小时 mixed-traffic soak；
- clean-host archive/SHA-256/Ed25519 签名验证；
- setup -> install -> start -> status -> stop 完整记录；
- clean-host update、checksum、signature、health-check 和 rollback 演练。

注意：豁免 update 签名/回滚演练命中 maskman-guard 的 hard stop，guard 已
明确反对并记录在案；这是 maintainer 的决定。

## rc.1 benchmark 对比（2026-08-28）

`benchmarks/baseline.csv` 已替换为 rc.1（commit 950f102）在同一台 Mac
（Apple M4, aarch64-apple-darwin）上的 release 运行，toolchain 由 1.97.1
变为 1.98.0。与 0.1.0 基线（commit 8a61384）对比：17 行中 10 行提升、
7 行下降；大 payload（16KiB+）吞吐量各行均在 ±7% 以内，checksum 完全一致。
小 payload 行的 ±20-50% 波动经同机同二进制背靠背重跑验证为 run-to-run
噪声（重跑时 http/tcp/64B 回升 +36.2%），不是 codec 回归。结论：无可行动
的性能回归，benchmark 对比门禁关闭。

Linux namespace smoke 当前按 Surge server-only 范围 deferred；在重新声明
CONNECT-IP/TUN 或完整 release profile 前必须恢复并取得特权 runner 证据。

README 不得标记 v1.0 完成；v1.0 前上述豁免与 deferred 项必须全部补齐。

本地新增验证包括 control socket 协议版本、0600 权限、过长路径、残留非
socket 路径、原子 reload 拒绝、metrics endpoint、严格 journal 校验、nft/pf
规则渲染、更新互斥锁、staged binary 超时，以及 development setup ->
config validate -> foreground serve -> status --json -> Ctrl-C 生命周期。
这些测试不能替代特权目标机和 clean-host release 证据。
