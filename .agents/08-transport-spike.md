# M1 HTTP/3 transport spike report

记录日期：2026-08-20。

## 1. 范围与结论

M1 只验证 HTTP/3 MASQUE transport，不实现真实代理。当前生产入口始终使用
`RejectUntilAuthentication`，合法 CONNECT-UDP 在认证模块接入前返回 503；不会解析 DNS、创建
target socket、TUN 或路由。`EchoDatagrams` 只由测试和
`crates/maskman-server/examples/transport_spike.rs` 使用，不由发布 CLI 选择。

已经验证：

- QUIC/TLS 1.3 与 ALPN `h3`；
- HTTP/3 Extended CONNECT、`ENABLE_CONNECT_PROTOCOL` 与 `H3_DATAGRAM` settings；
- CONNECT-UDP 请求的 method、protocol、scheme、authority、path 与 Capsule-Protocol 最小检查；
- Quarter Stream ID 编解码和多 request stream demultiplex；
- QUIC DATAGRAM 与 request stream 上 DATAGRAM Capsule 两条路径；
- QUIC endpoint rebind 后 datagram round trip；
- oversized datagram、production pre-auth rejection、GOAWAY/drain 和 H3_NO_ERROR close；
- 配置中的多个 listen address 都会 bind，不会静默忽略后续 listener。

M1 通过的含义是 transport API 可作为 M2/M3 的基础，不代表 CONNECT-UDP forwarding、
CONNECT-IP 或认证已经可用。

## 2. 固定依赖与上游缺口

主 transport 使用 Quinn 0.11.11、rustls 0.23 和 hyperium/h3。h3 与 h3-quinn 固定为：

```text
repository: https://github.com/hyperium/h3
revision:   1f3d5295833ad454343f25d55633fb6bee1027b2
date:       2026-08-13
```

选择该 revision 的原因：

- crates.io 的 h3 0.0.8 尚无公开 `Protocol::CONNECT_IP`，后续 M2/M4 需要它；
- h3-datagram 0.0.2 的 `Datagram::encode` 虽然把 Quarter Stream ID 写入局部
  `buffer`，却把 `EncodedDatagram.stream_id` 初始化为全零，导致所有非零 request stream
  被编码为 stream 0；
- 固定 revision 已将该字段改为实际的 `buffer` 并带回归测试。

Maskman 暂不依赖 h3-datagram 的实验 API，而是在 server transport adapter 内维护一个很小的
RFC 9297 Quarter Stream ID codec。它只负责 raw Quinn datagram 与 request stream ID 的转换，
不会泄漏 h3/Quinn 类型到 protocol crate。Cargo.toml 同时指定 semver 和 git revision，
`cargo deny` 保持全局 wildcard deny。

TLS PEM 使用 `rustls-pki-types::PemObject`。没有使用已停止维护的 rustls-pemfile；证书链为空和
私钥缺失分别报错。ALPN 只包含 `h3`。

## 3. Transport resource profile

配置映射如下：

| 资源 | 实现 |
| --- | --- |
| QUIC connections | endpoint open connection count 受 `max_connections` 限制 |
| bidi request streams | `max_requests_per_connection` |
| uni control streams | 固定 16 |
| field section | `max_header_bytes` |
| idle | `idle_timeout` |
| QUIC datagram receive/send buffer | 各 4 MiB，有界 |
| pre-active datagrams | production mode 解码 stream ID 后丢弃，不缓冲 |
| capsule value in spike echo | 65,535 bytes，有界增量 decoder |
| shutdown | 先 H3 GOAWAY，在 `drain_timeout` 后关闭 endpoint |

每个 QUIC connection 一个长期 task；每个 request 一个受 QUIC stream limit 约束的 task。
packet/datagram path 不按 packet spawn task，也没有无界 packet queue。

## 4. 自动化证据

`maskman-server` 测试覆盖：

| 场景 | 结果 |
| --- | --- |
| 两个 CONNECT-UDP request stream 同时发送不同 payload | 回包保持各自 Quarter Stream ID，无串流 |
| DATAGRAM Capsule 在 request stream 上往返 | type 0x00 与 value 字节一致 |
| client endpoint 更换 UDP socket | path validation 后继续完成 datagram round trip |
| datagram 大于 Quinn 当前 max_datagram_size | `send_datagram` 返回错误 |
| production mode 合法 CONNECT-UDP | 在任何代理副作用前返回 503 |
| shutdown handle | 发送 GOAWAY，drain 后客户端观察 H3_NO_ERROR close |
| TLS | 自签根验证成功，ALPN 固定为 h3 |

验证命令：

```text
rtk cargo test -p maskman-server --all-targets
rtk cargo clippy -p maskman-server -p maskman --all-targets --all-features -- -D warnings
rtk cargo deny check
rtk cargo audit
```

## 5. 独立客户端互操作

### Quinn/h3 client

仓库测试客户端通过 h3-quinn 建立 TLS/QUIC/H3，发送 Extended CONNECT，验证 200、
`capsule-protocol: ?1`、两个 stream 的 QUIC DATAGRAM、DATAGRAM Capsule、migration 和
oversize 行为。这是与 server adapter 分离的 client API 路径。

### Pasque/quiche client

使用 Pasque 0.3.0 和上游 commit `61cc6457a947a428ac8a770be65dce10d03ee827`。
未修改客户端首先失败，服务端严格返回 `H3_MESSAGE_ERROR (0x10e)`。原因是 Pasque 把
`:protocol` 放在 `user-agent` 和 `capsule-protocol` 普通首部之后，违反伪首部必须先出现的
HTTP/3 规则。Maskman 没有放宽 parser。

在 `/tmp` 客户端副本中只把 `:protocol` 移到普通首部之前，随后完成：

```text
CONNECT-UDP status: 200
transport:           QUIC DATAGRAM
local UDP input:     maskman-pasque-roundtrip
local UDP output:    maskman-pasque-roundtrip
```

测试 URI 的 endpoint prefix 为 `/udp/`，target 为 `127.0.0.1:9000`。spike echo 不访问该
target，只验证 HTTP/3 request 和 datagram wire interoperability。该临时客户端补丁不在
Maskman 仓库或发布物内；Pasque 不能作为规范 oracle。

### h3-masque/MsQuic probe

h3-masque 0.1.0 在本机 aarch64 macOS 无法编译。其 msquic-async 0.4.1 在
`listener.rs` 将 `u16` 写入本目标为 `u8` 的 `sin_family`，Rust 报 E0308。该失败属于独立
客户端构建兼容性，不是 Maskman handshake 失败，因此不计作成功互操作证据。

## 6. M1 gate 与后续边界

M1 以 Quinn/h3 client 和 Pasque/quiche client 两套 QUIC/H3 实现完成最小 CONNECT-UDP
handshake 与 datagram round trip。Pasque 需要上述已记录的一行语义补丁；原始失败也保留为
strict-header regression 的证据。

仍未实现，且不得在当前版本宣称支持：

- bearer 或 mTLS authentication、principal 和 authorization policy；
- DNS resolution、connected UDP target socket 和真实 CONNECT-UDP forwarding；
- CONNECT-IP request、ADDRESS_ASSIGN/REQUEST、ROUTE_ADVERTISEMENT 与 IP packet forwarding；
- TUN/utun、route、NAT、supervisor/worker privilege split；
- daemon service control、signed update、release artifacts、performance/soak gates；
- HTTP/1.1 或 HTTP/2 MASQUE profile。

M2 从 sans-I/O protocol crate 开始，不把 transport echo 逻辑扩展为生产代理。
