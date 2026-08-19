# 协议调研与技术范围

## 1. 先纠正 RFC 边界

“MASQUE”不是单一 RFC。Maskman 的协议栈关系如下：

| 标准 | 作用 | v1 |
| --- | --- | --- |
| RFC 9000 | QUIC transport | 必须 |
| RFC 9114 | HTTP/3 | 必须 |
| RFC 9220 | HTTP/3 Extended CONNECT | 必须 |
| RFC 9221 | QUIC DATAGRAM | 必须 |
| RFC 9297 | HTTP Datagram 与 Capsule Protocol | 必须 |
| RFC 9298 | CONNECT-UDP，UDP over HTTP | 必须 |
| RFC 9484 | CONNECT-IP，IP over HTTP；更新 RFC 9298 的 well-known URI 注册 | 核心目标 |
| RFC 9209 | Proxy-Status 错误信息 | 必须用于可表达的失败 |
| RFC 6169 | IP tunnel 安全指导 | 安全基线 |
| BCP 38 / RFC 2827 | 源地址反欺骗 | 必须 |

RFC 9484 定义的是 connect-ip，不是 connect-udp。Maskman 会同时支持两者，但不得在文档或帮助信息中混用名称。

## 2. 支持 profile

v1 采用 HTTP/3-only profile：

- ALPN 为 h3，TLS 1.3 由 QUIC 提供。
- 服务端发送 ENABLE_CONNECT_PROTOCOL 与 SETTINGS_H3_DATAGRAM。
- 支持 :protocol = connect-ip 和 :protocol = connect-udp。
- QUIC DATAGRAM 可用时走不可靠快速路径。
- QUIC DATAGRAM 不可用或双方未完成协商时，走请求流上的 DATAGRAM Capsule。
- 不实现 HTTP/1.1 Upgrade 和 HTTP/2。它们是后续兼容 profile，不是 v1 的隐藏承诺。

RFC 9484 描述了多种 HTTP 版本，但实现可以只提供其中一种传输。Maskman 只能声明“RFC 9484 over HTTP/3”，不能笼统声称支持 RFC 中所有 HTTP 版本。

## 3. RFC 9484 合规矩阵

以下项目必须在实现阶段映射到代码、测试和日志错误码：

| 规范点 | 实现要求 | 主要验证 |
| --- | --- | --- |
| 加密 | CONNECT-IP 只在 QUIC/TLS 上运行 | 拒绝错误 ALPN；TLS 集成测试 |
| Extended CONNECT | 方法 CONNECT，protocol 为 connect-ip，scheme/path 非空，authority 指向 proxy | 请求表驱动测试 |
| 默认 URI | 暴露 /.well-known/masque/ip/{target}/{ipproto}/ | 互操作测试 |
| Errata 8444 | 通配符星号必须以 %2A 传输 | 回归测试，不接受裸星号的规范化歧义 |
| Capsule 协商 | 成功响应为 2xx，并携带 capsule-protocol: ?1 | header 测试 |
| Context ID | 0 表示完整 IP packet；未知 context 丢弃或短时有界缓冲 | codec、状态机、fuzz |
| ADDRESS_REQUEST | 至少一个条目；空列表必须中止流；Request ID 必须对应响应 | 状态机测试 |
| ADDRESS_ASSIGN | 每个 capsule 是当前完整分配集合，后一个替代前一个 | 属性测试 |
| ROUTE_ADVERTISEMENT | 每个 capsule 是完整路由集合；排序、重叠和 protocol 规则必须验证 | 属性测试与恶意输入 |
| IP packet | payload 从 IP version 字段开始，长度和版本必须一致 | packet parser fuzz |
| 源地址 | 只接受分配给该 tunnel 的源 prefix，执行 BCP 38 | namespace 集成测试 |
| request scope | target、prefix、DNS 和 ipproto 必须逐包强制执行 | ACL 与 DNS 测试 |
| IPv6 扩展头 | 为 ipproto scope 查找最外层非扩展协议；解析有界 | fuzz 与扩展头 corpus |
| 路由语义 | forwarding 时 TTL/Hop Limit 恰好递减一次 | network namespace 测试 |
| MTU | IPv6 tunnel 必须能承载至少 1280 字节；不能满足则中止流 | PMTU 故障注入 |
| 错误信号 | 无路由、策略拒绝和 MTU 错误尽量返回适当 ICMP | packet golden tests |
| 生命周期 | 地址、路由和资源绑定到 request stream；关闭流即释放 | 取消与断线测试 |
| 安全 | 认证、按 principal 限速、反欺骗、ICMP 隔离 | 安全测试 |

ADDRESS_ASSIGN 的 capsule type 为 0x01，ADDRESS_REQUEST 为 0x02，ROUTE_ADVERTISEMENT 为 0x03。IP 与 UDP 普通 payload 的 Context ID 均为 0。

## 4. RFC 9298 合规要点

- 默认 URI 为 /.well-known/masque/udp/{target_host}/{target_port}/。
- target_host 可以是 DNS、IPv4 或百分号编码后的 IPv6；target_port 必须是 1 到 65535。
- DNS 名称必须在返回成功响应前解析。
- 解析结果先经过 policy，再固定为具体 IP；后续 socket 连接不得再次按 hostname 解析。
- 每个 tunnel 使用 connected UDP socket。若平台退化为 unconnected socket，必须逐包验证源 IP 和端口。
- socket 生命周期与 request stream 一致；空闲回收低于两分钟不符合 RFC 建议。
- 不得主动引入 IP fragmentation；IPv4 尽可能设置 DF。
- 单个 context-0 UDP payload 最大 65527 字节，但实际还必须服从 QUIC PMTU；过大数据报丢弃并记指标。
- 不为了批量发送而增加 burstiness，也不关闭外层 QUIC congestion control。

## 5. HTTP Datagram 与 Capsule

RFC 9297 带来两条承载路径：

1. QUIC DATAGRAM frame：payload 先包含 Quarter Stream ID，再包含扩展自己的 Context ID 和 payload。
2. DATAGRAM Capsule：type 为 0x00，位于对应请求流中，capsule value 直接是扩展自己的 HTTP Datagram Payload，不再包含 Quarter Stream ID。

Capsule parser 必须是增量式的。不能根据攻击者提供的 62-bit length 一次性分配内存；已知过大 capsule 要流式跳过，未知 capsule 必须安全忽略。解析中断、冗余长度不一致和截断必须按 RFC 9297 终止相应请求或连接。

## 6. Rust 协议栈选型

调研时观察到的版本仅用于说明生态状态，真正实现时由 Cargo.lock 固定并重新审计。

| 方案 | 观察版本 | 优点 | 风险 | 结论 |
| --- | --- | --- | --- | --- |
| quinn + h3 + h3-quinn + h3-datagram | 0.11.11 / 0.0.8 / 0.0.10 / 0.0.2 | Rust API、Tokio 友好、QUIC 性能好、模块边界清楚 | h3 与 h3-datagram 官方仍标为 experimental | 主方案，先做能力 spike |
| Cloudflare quiche | 0.29.3 | QUIC/H3 成熟、低层控制充分、有现实部署 | vendored BoringSSL/C 构建复杂，事件循环和跨平台封装工作大 | 备选，不作为默认 |
| h3-masque | 0.1.0 | 已有 CONNECT-UDP 概念实现 | README 明确称 early prototype，绑定 MsQuic，测试和错误处理不足 | 只作参考 |
| pasque | 0.3.0 | 同时演示 RFC 9298/9484 与 TUN | 基于 quiche，IP tunnel 主要在 Linux 测试，产品化能力不足 | 互操作与设计参考 |
| wtransport | 0.7.2 | HTTP/3 Datagram 生态活跃 | 目标是 WebTransport，不是 MASQUE | 不采用 |

主方案不是直接依赖某个 MASQUE 成品 crate，而是在 h3/h3-datagram 上实现小而清晰的 RFC 9298/9484 codec 和状态机。协议 crate 必须保持 sans-I/O，网络 runtime 只负责搬运 Bytes。

## 7. 必须先通过的技术 spike

进入正式功能开发前，必须用固定 revision 验证：

1. h3 server 能发送 Extended CONNECT 与 H3_DATAGRAM settings。
2. server 能取得 request stream ID，并把 QUIC DATAGRAM 正确关联到该流。
3. 同一连接上多个 CONNECT stream 的 Datagram 不串流。
4. 请求流能并行承载 Capsule 控制消息和 DATAGRAM Capsule。
5. 流关闭、连接迁移、GOAWAY 和 datagram-too-large 的错误可以被上层可靠观察。
6. Quinn 的 max_datagram_size、PMTU 变化和 backpressure 能被数据面使用。
7. 至少与两个独立客户端实现完成 CONNECT-UDP round trip；CONNECT-IP 与至少一个独立实现互通。

如果第 1 至 6 项存在上游 API 缺口，允许维护一个最小 patch，并固定 git revision 与补丁测试。不得 fork 整个 HTTP/3 栈，也不得让 h3 类型泄漏到 protocol、auth、policy 和 platform crate。

## 8. 其他关键依赖方向

- tokio：异步 runtime。
- rustls：TLS 配置；crypto provider 选择以审计状态和 Quinn 兼容性为准。
- bytes：数据面 buffer。
- serde、toml、toml_edit、serde_json：双格式严格配置；toml_edit 只用于 token/配置修改时保留 TOML 注释。
- rand、sha2、subtle、secrecy：生成 bearer secret、hash、constant-time compare 和内存暴露边界。
- hickory-resolver：显式、可测试的 DNS resolution。
- ipnet、etherparse：prefix 与 IP packet 解析。
- tun-rs：Linux TUN 与 macOS utun 的初始抽象；平台行为仍需原生测试。
- clap、anstyle、dialoguer、indicatif：CLI、颜色、提示和进度。
- tracing、tracing-subscriber、metrics：日志与指标。
- service-manager：service 安装/启停的适配起点；status 与 hardening 仍由平台模块补足。
- self_update 或等价的窄封装：下载和原子替换；zipsign 或 ed25519-dalek 负责独立签名验证。只有在签名、回滚和 system install 流程全部验证后才能采用。

依赖必须固定在 Cargo.lock。实验性核心依赖升级要单独提交，并重新跑互操作、fuzz corpus 和 benchmark。

## 9. 权威资料

访问日期均为 2026-08-20：

- RFC 9484: https://www.rfc-editor.org/rfc/rfc9484
- RFC 9484 verified errata 8444: https://www.rfc-editor.org/errata/eid8444
- RFC 9298: https://www.rfc-editor.org/rfc/rfc9298
- RFC 9297: https://www.rfc-editor.org/rfc/rfc9297
- RFC 9114: https://www.rfc-editor.org/rfc/rfc9114
- RFC 9220: https://www.rfc-editor.org/rfc/rfc9220
- RFC 9221: https://www.rfc-editor.org/rfc/rfc9221
- RFC 9209: https://www.rfc-editor.org/rfc/rfc9209
- RFC 6169: https://www.rfc-editor.org/rfc/rfc6169
- hyperium/h3 status and source: https://github.com/hyperium/h3
- Quinn: https://github.com/quinn-rs/quinn
- quiche: https://github.com/cloudflare/quiche
- h3-masque prototype: https://github.com/masa-koz/h3-masque
- Pasque reference: https://github.com/PasiSa/pasque
- cargo-dist: https://github.com/axodotdev/cargo-dist
- self_update: https://github.com/jaemk/self_update
- service-manager: https://github.com/chipsenkbeil/service-manager-rs
- tun-rs: https://github.com/tun-rs/tun-rs

任何与 RFC 原文冲突的第三方 README、博客或现有实现都不能作为合规依据。
