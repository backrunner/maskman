# 质量、验证与发布

## 1. 测试分层

### Unit

- config format detection、strict serde、duration/size/CIDR parsing；
- URI path target/ipproto decoding，包括 RFC 9484 errata 8444 的 %2A；
- QUIC varint、capsule framing、incremental decode；
- ADDRESS_ASSIGN/REQUEST、ROUTE_ADVERTISEMENT encode/decode；
- IPv4/IPv6 header、extension chain、scope、TTL/Hop Limit；
- token hashing、constant-time comparison、expiry；
- token bucket、quota 和 session state transition。

### Property

- 任意随机 capsule 不 panic，消费位置单调；
- encode(decode(x)) 在规范允许的非最小 varint 范围内等价；
- route advertisement 排序和 overlap invariant；
- 地址池分配/释放不会重复或泄漏；
- compiled config 对同一输入 deterministic；
- unknown capsule 不改变已提交的地址/路由状态。

### Fuzz

建议 fuzz target：

- capsule_decoder；
- datagram_payload；
- connect_request_path；
- ipv4_packet；
- ipv6_packet_extensions；
- route_advertisement；
- config_toml；
- config_json；
- control_socket_frame。

每个 fuzz target 设 memory/time budget。corpus 与 crash artifact 版本化；修复先加 regression test 再更新 corpus。

### Integration

- h3 client/server over Quinn；
- authenticated CONNECT-UDP echo；
- authenticated CONNECT-IP using network namespace/TUN；
- concurrent streams/datagrams；
- malformed request 和 capsule 错误码；
- disconnect、GOAWAY、reload、graceful drain；
- DNS timeout、private destination、quota、PMTU；
- systemd/launchd install dry-run。

### Interoperability

至少包含：

- 一个 Rust/quinn client；
- Chromium/平台 HTTP/3 client（若能发送 MASQUE）或独立 MASQUE client；
- Pasque 作为 RFC 9298/9484 参考实现；
- h3-masque 只作为 CONNECT-UDP 参考，不视为规范 oracle。

每次互操作记录：commit、TLS cert mode、ALPN、settings、request headers、capsule/datagram path、payload sizes、expected/observed。

## 2. RFC compliance harness

xtask compliance 读取一个机器可读矩阵，执行：

- header/profile checks；
- capsule golden vectors；
- malformed input expectations；
- context/session lifecycle；
- MTU and oversize behavior；
- Proxy-Status mapping。

每条 MUST/SHALL 有：

- requirement id；
- RFC section；
- source module；
- test name；
- status（implemented、partial、not-applicable with reason）。

CI 不允许把 partial 当作通过。HTTP/1.1 与 HTTP/2 可标记 not-applicable only because v1 profile explicitly says HTTP/3-only。

## 3. 网络测试环境

Linux CI 用 network namespaces：

~~~text
client-ns -- veth -- proxy-ns -- veth -- target-ns
                         |
                         +-- tun maskman0
~~~

测试可以控制：

- route、MTU、丢包、延迟和 reordering；
- IPv4/IPv6 双栈；
- private/link-local/multicast target；
- ICMP Packet Too Big；
- source address spoof；
- service restart 和 orphan resource cleanup。

macOS integration 运行在 arm64 runner，涉及 utun/pf 的测试分级：

- 非特权 parser/state tests 在所有 runner；
- privileged utun/route tests 在签名的专用 runner；
- 没有足够权限时 CI 明确报告 skipped，不伪装为 passed。

## 4. 性能与长稳

### Benchmark

Criterion/自有 harness 分开：

- codec-only：capsule、datagram、IP parse；
- in-process forwarding：mock UDP/TUN；
- end-to-end：real QUIC over loopback/network namespace。

固定变量：target triple、Rust toolchain、CPU governor、MTU、TLS resumption、payload size、streams、duration。

### Soak

- 至少 24 小时 mixed UDP/IP traffic；
- 连接 churn、token rotation、config reload、log rotation、packet loss；
- 检查 RSS、fd、session registry、address lease、task count 是否单调增长；
- 使用 heap profiling 或 allocator stats 定期采样。

## 5. 静态和供应链检查

每个 PR：

- cargo fmt --check；
- cargo clippy --workspace --all-targets --all-features -- -D warnings；
- cargo test --workspace；
- cargo deny check；
- cargo audit；
- cargo machete 或等价的 unused dependency 检查；
- rustsec、license、source allowlist；
- RUSTFLAGS=-Dwarnings 的最小 MSRV lane；
- secret scanning 和 release key 路径检查。

unsafe、shell、privilege 和 firewall 变更需 CODEOWNERS 或两人 review。核心 protocol、auth、update 和 platform 变更不能只由同一作者自审。

## 6. CI target matrix

| target | 用途 |
| --- | --- |
| x86_64-unknown-linux-musl | Linux x64 release |
| aarch64-unknown-linux-musl | Linux arm64 release |
| aarch64-apple-darwin | macOS arm64 release |

使用 cargo-dist 生成 GitHub Actions pipeline，但 target toolchain、signing、attestation 和 smoke test 保留在仓库配置中。每个 release job：

1. 构建 locked dependencies；
2. 运行 target-native 或 cross smoke；
3. 生成 archive、SHA256SUMS、SBOM、SLSA provenance；
4. 用 release signing key 签名；
5. 上传 draft release；
6. 独立 verify job 下载并验证；
7. 才提升为 public release。

Linux musl 减少 glibc 依赖，但 TUN、netlink 和 kernel behavior 仍要在目标 distro smoke test。

## 7. 发布和回滚

版本使用 SemVer：

- breaking config/protocol/CLI：major；
- 向后兼容新能力：minor；
- bug/security fix：patch。

建议 tag 与提交格式：

- 功能：feat(server): add connect-ip route enforcement
- 修复：fix(protocol): reject truncated route capsule
- 文档：docs(agents): define HTTP/3-only profile
- 构建：build(release): add aarch64 musl artifact
- 安全：security(auth): rotate bearer token verifier
- 重构：refactor(platform): isolate tun ownership

格式严格为 xxx(comp): desc，其中 xxx 为小写 type，comp 为小写组件，desc 为简洁英文祈使/陈述句；不要在 subject 中放句号或换行。

Git 身份必须是：

BackRunner <dev@backrunner.top>

发布前生成 changelog，明确区分 RFC compliance、security、operational 和 breaking changes。不要把未通过的实验功能写成支持。

## 8. Release gates

发布前必须为 green：

- lockfile 与依赖审计；
- compliance matrix；
- unit/property/fuzz regression；
- interop；
- Linux network namespace；
- macOS arm64 privileged smoke；
- 24h soak（安全修复可缩短但要记录）；
- benchmark 无未解释回归；
- update install/checksum/signature/rollback；
- setup -> install -> start -> status -> stop 全流程；
- 产物 SHA256、签名、SBOM、provenance。

任一 gate 失败时，版本停留 draft。不得靠修改文档中的“支持”字样绕过 gate。

## 9. 事故响应

- 认证绕过、源地址欺骗、任意内网访问、更新签名绕过：立即撤回 release、吊销 token/key、发布 security patch。
- 数据面 crash 或内存放大：先设置默认 deny/限额和 service rollback，再修复。
- service install 破坏用户防火墙：停止自动 cleanup，保存 journal 和复现信息，提供显式 repair 命令。
- 每次事故补充 threat model、regression test 和 guard 规则，避免把一次事件变成没有边界的永久禁令。
