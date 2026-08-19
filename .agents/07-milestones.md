# 里程碑与实施计划

计划按可验证能力拆分，不按“写了多少代码”计量。时间是一个 2 至 4 人 Rust/networking 小组的参考估计；协议 spike 或平台权限阻塞时必须重新估算。

## M0：仓库与工程基线（1 周）

产出：

- workspace、Rust toolchain、fmt/clippy/test、deny/audit；
- maskman 单 binary skeleton；
- .agents 文档与 maskman-guard；
- commit identity/subject hook；
- cargo-dist target matrix 草稿；
- error/logging/output 基础类型。

验收：

- 三个目标可构建 hello/version；
- CI 能运行最小检查；
- maskman-guard validator 通过；
- 首次提交使用 BackRunner <dev@backrunner.top>。

## M1：协议 transport spike（1 至 2 周）

产出：

- Quinn endpoint + rustls TLS；
- h3 server Extended CONNECT；
- ENABLE_CONNECT_PROTOCOL、SETTINGS_H3_DATAGRAM；
- h3-datagram QUIC path；
- request stream/capsule adapter；
- 两个独立 client 的最小 CONNECT-UDP handshake。

验收门槛：

- 多 stream datagram 不串流；
- datagram too large、connection close、GOAWAY 可观测；
- 若 h3 API 不足，记录固定 patch；
- 未通过不得开始 TUN 或宣传高性能。

## M2：protocol codec 与 compliance core（2 周）

产出：

- RFC 9297 incremental capsule parser；
- RFC 9298 URI/context/datagram codec；
- RFC 9484 ADDRESS/ROUTE capsule；
- IPv4/IPv6 parser、scope、extension header rules；
- property/fuzz/golden vectors；
- compliance matrix 初版。

验收：

- 规范 MUST/SHALL codec 条目全有测试；
- RFC 9484 errata 8444 回归通过；
- malformed input 无 panic、无无界分配；
- protocol crate 不依赖 runtime/platform。

## M3：认证、授权与 CONNECT-UDP（2 至 3 周）

产出：

- bearer + mTLS principal；
- role/policy compiler；
- DNS resolver 与固定 SocketAddr；
- connected UDP socket；
- quota/rate limit/backpressure；
- RFC 9298 response/proxy-status。

验收：

- 未认证永远不能触发 target socket；
- private/loopback/link-local 默认拒绝；
- DNS failure、oversize、idle close、source validation 通过；
- authenticated UDP echo interop。

## M4：Linux CONNECT-IP 数据面（3 至 4 周）

产出：

- supervisor/worker privilege split；
- TUN + netlink route；
- address pool lease；
- RFC 9484 datagram forwarding；
- source validation、TTL、ICMP/MTU；
- Linux namespace test harness。

验收：

- dual-stack TUN round trip；
- multiple principals address isolation；
- route advertisement replace semantics；
- source spoof、private route、MTU failure、worker crash cleanup 通过；
- 至少一个独立 CONNECT-IP client 互通。

## M5：macOS arm64 platform 与 service（2 周）

产出：

- utun adapter；
- route/pf anchor；
- launchd plist；
- systemd unit hardening；
- install/start/stop/status/reload；
- platform inspect/cleanup journal。

验收：

- aarch64-apple-darwin 原生构建；
- arm64 macOS privileged utun smoke；
- 重复 install 幂等；
- stop/restart 不遗留 TUN、route 或 pf anchor；
- status --json schema 稳定。

## M6：CLI setup 与运维 UX（1 至 2 周）

产出：

- setup 交互/非交互；
- TOML/JSON round-trip；
- token create/revoke/list；
- config validate；
- color/NO_COLOR/TTY handling；
- shell completions。

验收：

- 新用户从空目录完成 setup -> validate -> serve；
- secret 只显示一次且不出现在日志；
- 非交互 CI 无 prompt hang；
- 错误包含字段、路径和下一步。

## M7：更新供应链与跨平台发布（2 周）

产出：

- GitHub release manifest；
- target-specific artifacts；
- SHA256、Ed25519/zipsign signature、SBOM、provenance；
- staged validate、atomic replace、health check、rollback；
- update --check / --yes。

验收：

- 篡改 digest、签名、archive traversal 都被拒绝；
- service 健康失败自动恢复；
- Linux x64/arm64 和 macOS arm64 安装升级 smoke；
- 保留一个可用旧版本。

## M8：性能、长稳与 1.0（2 至 4 周）

产出：

- end-to-end benchmark baseline；
- 24h soak；
- fuzz corpus review；
- interop report；
- threat model review；
- release checklist 与 runbook。

验收：

- .agents/README.md 的 v1 完成定义全部为证据支持；
- release gates 全绿；
- 未支持 HTTP/1.1/HTTP/2 明确标注；
- operator 能根据 runbook 诊断、回滚和吊销 token。

## 依赖与风险

| 风险 | 触发信号 | 处理 |
| --- | --- | --- |
| h3/h3-datagram API 不足 | spike 无法取得稳定 datagram/request mapping | 维护最小 patch，或切换 quiche adapter；不直接引入早期 MASQUE crate |
| TUN/pf 权限差异 | macOS CI 无法可靠创建 utun | 分离 parser/state 与 privileged smoke，准备人工签名 runner |
| IP forwarding 复杂度超出 v1 | MTU/ICMP/extension header 长期不稳定 | 先发布 CONNECT-UDP，CONNECT-IP 保持 preview，不降低合规标准 |
| update signing 运维困难 | key rotation/rollback 演练失败 | 延迟 public update，保留 manual signed install |
| 性能回归 | p99/CPU 超门槛 | profile 后拆数据面热点，禁止盲目增加 batch 或无界 queue |
| config 演进破坏 | round-trip 或旧 schema 失败 | schema_version + migrate，禁止 silent fallback |

## 建议排期

并行上限：

- protocol/transport：1 人；
- server/auth/data plane：1 至 2 人；
- platform/CLI/release：1 人。

M0 与研究文档完成后，M1 和配置模型可并行；M4 依赖 M2/M3；M5、M6 可与 M4 后半段并行；M7 必须等 service 和 artifact layout 稳定；M8 是独立 release gate，不应和功能开发混为“最后收尾”。
