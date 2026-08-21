# 运行架构

## 1. 架构目标

Maskman 的设计优先级依次为：

1. 对已声明 profile 的协议正确性。
2. 默认安全、可限制、可审计。
3. 稳定的长驻运行和可恢复升级。
4. 有界资源与可度量的高性能。
5. 简单配置和一致的跨平台 CLI。

不以“支持尽可能多的 HTTP 版本”为 v1 目标，也不在 v1 内实现通用 VPN 控制平面、用户数据库、Web 管理后台或集群状态同步。

## 2. 单二进制，多角色

发布物只有一个 maskman，但运行时分为三种角色：

~~~text
用户终端
   |
   | setup/install/start/stop/status/update
   v
maskman CLI -------------------- GitHub Releases
   |
   | service-manager
   v
特权 supervisor
   |  创建 TUN、路由、防火墙/NAT、监听 socket、运行目录
   |  传递已打开 fd + 私有 socketpair
   v
非特权 worker
   |  QUIC/H3、认证、授权、协议状态机、UDP/IP 转发
   v
目标网络
~~~

service manager 负责守护进程生命周期，Maskman 自身不 double-fork：

- Linux：systemd system service。
- macOS：launchd system daemon。
- 开发模式：maskman serve，不安装 service；仅安装后的 service 环境设置
  `MASKMAN_ROLE=supervisor`。

supervisor 必须在 Tokio 多线程 runtime 创建前完成特权初始化和 worker spawn，避免多线程进程 fork 的未定义状态。worker 使用专用 maskman 系统用户；supervisor 只保留网络资源管理、worker 监控和清理职责，不解析远端 HTTP 或 packet payload。

## 3. 逻辑组件

~~~mermaid
flowchart LR
    Client[MASQUE client] --> QUIC[Quinn endpoint]
    QUIC --> H3[HTTP/3 adapter]
    H3 --> Router[CONNECT request router]
    Router --> Auth[Authentication]
    Auth --> Policy[Authorization and limits]
    Policy --> UDP[CONNECT-UDP session]
    Policy --> IP[CONNECT-IP session]
    UDP --> DNS[Resolver]
    UDP --> Socket[Connected UDP socket]
    IP --> Codec[RFC 9484 capsules and packet checks]
    IP --> Tun[Shared TUN/utun]
    Tun --> Kernel[Kernel routing and NAT]
    Socket --> Target[UDP target]
    Kernel --> Target
    Router --> Control[Local control and metrics]
~~~

HTTP/3 依赖只能出现在 transport adapter 中。protocol codec 不认识 Quinn、Tokio、TUN 或配置文件；policy 不认识 h3 header 的具体 Rust 类型。

## 4. 连接与请求状态机

每条 CONNECT request 都有独立状态：

~~~text
Accepted
  -> HeadersValidated
  -> Authenticated
  -> Authorized
  -> Provisioning
  -> Active
  -> Draining
  -> Closed
~~~

- HeadersValidated：检查 method、protocol、scheme、authority、path、Capsule-Protocol 和 header 大小。
- Authenticated：得到不可伪造的 PrincipalId；失败返回 401。
- Authorized：固定 DNS 结果并编译该 request 的 EffectivePolicy；失败返回 403。
- Provisioning：
  - UDP：创建并 connect UDP socket。
  - IP：分配地址 lease，确认 TUN/路由可用并建立 session 映射。
- Active：只有资源就绪后才发送 2xx。随后可发送 ADDRESS_ASSIGN 和 ROUTE_ADVERTISEMENT。
- Draining：停止接收新 payload，排空必要的控制消息；数据报不做无限等待。
- Closed：删除 registry、释放地址和 socket，并生成一次终结指标。

在 request 尚未进入 Active 时到达的 optimistic datagram 默认丢弃。可以配置极小的每连接有界缓冲，但 v1 默认不缓冲，避免资源放大。

## 5. CONNECT-UDP 数据流

### Client 到 target

1. connection-level datagram reader 解析 Quarter Stream ID。
2. registry 查找对应 Active UDP session。
3. session 解析 Context ID；v1 只接受 0。
4. 检查 payload 长度、principal token bucket、session quota 和当前 PMTU。
5. 将 Bytes 发给 connected UDP socket。

### Target 到 client

1. session 的 UDP receive loop 从已连接 socket 收包。
2. 检查反向速率限制和最大 payload。
3. 编码 Context ID 0。
4. 优先发送 QUIC DATAGRAM；未协商时编码 DATAGRAM Capsule。
5. TooLarge 不得静默改走可靠 Capsule 以掩盖 PMTU；丢弃并计数。

一个 tunnel 只有固定数量的长期 task，不为每个 packet spawn task。socket 必须 connected，DNS 只在 provisioning 阶段解析一次。

## 6. CONNECT-IP 数据流

### Client 到外部网络

1. datagram demux 定位 IP session，解析 Context ID 0。
2. 借用式解析 IPv4/IPv6 header，不复制 packet。
3. 验证：
   - version、header 与 total length；
   - source 属于当前 session 的 Assigned Address；
   - destination 和最外层非扩展 IP protocol 属于 request scope 与 principal policy；
   - 不允许的 loopback、link-local、multicast、broadcast、本机地址；
   - IPv6 extension header 链长度在上限内。
4. 通过 rate limit 后写入共享 TUN。
5. kernel 完成路由、TTL/Hop Limit 处理和 NAT。

### 外部网络到 client

1. 单一 TUN reader 读取完整 IP packet。
2. 以 destination assigned address 在 lock-minimized registry 中查找 session。
3. 再次检查 reverse route、protocol 与 session 状态。
4. 编码 Context ID 0，通过该 request 的 H3 datagram sender 发送。

共享 TUN 比每 session 一个接口更节省 fd 和内核对象。每个 session 分配唯一 /32 和 /128，registry 由目标地址进行 O(1) 或 radix lookup。地址 lease 默认不跨重启持久化，这也符合 RFC 9484 对避免持久客户端标识的隐私建议。

## 7. TUN、路由与 NAT

### Linux

- supervisor 创建单个 TUN，例如 maskman0。
- 使用 netlink 配置地址、MTU、route 和 forwarding。
- managed NAT 使用独立 nftables table/chain，名称固定且操作幂等。
- systemd capability bounding set 仅保留初始化需要的 CAP_NET_ADMIN、CAP_NET_BIND_SERVICE、CAP_SETUID 和 CAP_SETGID。
- worker 得到监听 UDP fd 和 TUN fd 后降为 maskman 用户，并启用 no_new_privs。

### macOS arm64

- supervisor 创建 utun，platform adapter 去除或添加 utun 的 address-family 前缀。
- route 使用系统 route 接口或受控命令。
- NAT 只修改专用 pf anchor，不覆盖用户 pf.conf。
- launchd 以前台进程方式管理 root supervisor，worker 降为专用 `maskman` 系统用户。

所有平台操作都要有幂等 apply、inspect 和 cleanup。启动时只回收带 Maskman 标识且能由 state file 证明归属的残留资源，不能模糊匹配或删除用户规则。

## 8. Capsule 控制面

request stream 同时承载：

- DATAGRAM Capsule；
- ADDRESS_ASSIGN；
- ADDRESS_REQUEST；
- ROUTE_ADVERTISEMENT；
- 未来未知 capsule。

Capsule decoder 是增量 parser，输出借用或小对象事件。状态更新必须原子化：

- 完整解析并验证新 ADDRESS_ASSIGN 后，才替换旧集合。
- 完整解析并验证新 ROUTE_ADVERTISEMENT 后，才替换旧集合。
- malformed capsule 不得留下部分 route/address 状态。
- 未知 capsule 按 RFC 忽略，但长度跳过仍受字节预算约束。

## 9. 认证、授权和限制的执行顺序

远端输入必须按以下顺序处理：

~~~text
连接级廉价限制
  -> header 大小和语法
  -> authentication
  -> request-level authorization
  -> DNS resolution
  -> 对每个解析 IP 再做 authorization
  -> 创建系统资源
  -> 发送成功响应
  -> 每 packet enforcement
~~~

这样可以避免未认证请求触发 DNS、socket、TUN lease 等昂贵工作。详细策略见 [05-security.md](05-security.md)。

## 10. 并发与 backpressure

- 全局 connection、每 IP connection 的 request 数、每 principal 的 active tunnel 数均使用 semaphore。
- Datagram 是有损语义：队列满时按策略丢弃并记录 reason，不等待到放大延迟。
- Capsule 控制消息是可靠语义：使用小型有界队列，超限关闭 request。
- 不使用无界 mpsc。
- 不持有 map lock 跨 await。
- Session registry 以 connection shard 和 assigned-IP shard 分开，避免所有 packet 争用单锁。
- DNS concurrency 有独立上限和 deadline。
- UDP fd、buffer memory、pending handshake 和 pre-active datagram 都有全局上限。
- 日志与 metrics exporter 不能阻塞 packet path。

建议 task 拓扑：

- 每个 endpoint 一个 accept loop。
- 每个 QUIC connection 一个 H3 driver 和一个 datagram demux loop。
- 每个 CONNECT request 一个 lifecycle task。
- 每个 UDP session 一个 target receive loop；发送由 session task 串行化。
- 每个 TUN 一个 read loop 和一个 write dispatcher。

## 11. 性能路径

- packet buffer 使用 Bytes/BytesMut 和池化缓冲，protocol parser 尽量借用。
- 禁止每 packet 分配 String、构建 tracing span 或做 DNS/policy 编译。
- QUIC 层利用 Quinn/quinn-udp 已有的 GSO/GRO 能力。
- UDP target 初版使用 Tokio socket；只有 benchmark 证明 syscall 是瓶颈后，才增加 Linux recvmmsg/sendmmsg backend。
- 不为了 batching 人为排队，遵守 RFC 9298/9484 的 burstiness 建议。
- metrics label 只用有限枚举，不把 principal、hostname、IP 或 stream ID 放入 label。

初始性能门槛不是营销吞吐数字，而是可重复基线：

- 每个 release 在固定 Linux 裸机 profile 上运行 64B、512B、1200B payload。
- 覆盖 1、64、1024 active tunnel 和 10,000 idle tunnel。
- 记录 p50/p95/p99 forwarding latency、pps、Gbps、CPU、RSS、drop reason。
- 相对最近稳定版：同 profile 吞吐下降超过 5% 或 p99 上升超过 10% 时阻止 release，除非有书面性能例外。
- 在 M6 建立首个绝对容量目标，不能在没有硬件基线时虚构“百万并发”承诺。

## 12. 配置 reload 与优雅关闭

SIGHUP 或 control socket reload 使用 parse -> validate -> compile -> atomic swap：

可热更新：

- bearer token、mTLS principal 映射；
- ACL、rate limit、quota；
- 日志级别；
- 新连接使用的 TLS certificate。

需要重启：

- listen address；
- TUN 名称、地址池、MTU；
- NAT mode；
- service user 和路径。

关闭流程：

1. 停止接受新 QUIC connection。
2. 向 H3 发送 GOAWAY。
3. 拒绝新 CONNECT request。
4. 在 drain timeout 内结束控制消息；datagram 不无限排空。
5. 关闭 session 并释放 lease/socket。
6. worker 退出，supervisor 清理网络资源。

## 13. 本地控制面

status 和 reload 通过本地 Unix domain socket，不开放远程管理 HTTP：

- Linux：/run/maskman/control.sock。
- macOS：/var/run/maskman/control.sock。
- socket 当前默认以 daemon owner 创建，权限 0600；reload 还会检查 peer UID。后续 supervisor 可将它交给 `maskman-admin` group 扩展只读运维访问。
- 协议为带 version 的长度前缀 JSON；所有字段有大小上限。
- status --json 输出稳定 schema，普通 status 输出彩色摘要。

stop 仍优先通过 systemd/launchd，使 service manager 保持真实状态。control socket 不接受远端 token，也不复用 MASQUE 监听端口。

metrics 仅绑定 `observability.metrics_listen` 的本机聚合端点，使用固定的
Prometheus 文本字段和有界 HTTP/1.1 适配；它不属于远程代理 profile，也不
接受配置或控制命令。
