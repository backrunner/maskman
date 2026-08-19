# 模块与目录设计

## 1. Workspace 结构

一个二进制不等于一个巨型 crate。建议从一开始使用下列 workspace：

~~~text
maskman/
├── Cargo.toml
├── Cargo.lock
├── rust-toolchain.toml
├── deny.toml
├── dist-workspace.toml
├── crates/
│   ├── maskman/
│   │   └── src/
│   │       ├── main.rs
│   │       ├── cli.rs
│   │       ├── exit.rs
│   │       ├── output.rs
│   │       └── command/
│   │           ├── setup.rs
│   │           ├── install.rs
│   │           ├── lifecycle.rs
│   │           ├── status.rs
│   │           ├── update.rs
│   │           └── serve.rs
│   ├── maskman-config/
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── load.rs
│   │       ├── validate.rs
│   │       ├── compile.rs
│   │       ├── error.rs
│   │       └── model/
│   │           ├── server.rs
│   │           ├── tls.rs
│   │           ├── auth.rs
│   │           ├── policy.rs
│   │           ├── proxy.rs
│   │           └── observability.rs
│   ├── maskman-protocol/
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── error.rs
│   │       ├── varint.rs
│   │       ├── capsule/
│   │       │   ├── decoder.rs
│   │       │   ├── encoder.rs
│   │       │   ├── datagram.rs
│   │       │   ├── address.rs
│   │       │   └── route.rs
│   │       ├── connect/
│   │       │   ├── request.rs
│   │       │   ├── udp.rs
│   │       │   └── ip.rs
│   │       └── packet/
│   │           ├── ipv4.rs
│   │           ├── ipv6.rs
│   │           └── scope.rs
│   ├── maskman-server/
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── runtime.rs
│   │       ├── shutdown.rs
│   │       ├── transport/
│   │       │   ├── endpoint.rs
│   │       │   ├── connection.rs
│   │       │   ├── request.rs
│   │       │   ├── datagram.rs
│   │       │   └── capsule.rs
│   │       ├── auth/
│   │       │   ├── authenticator.rs
│   │       │   ├── bearer.rs
│   │       │   ├── mtls.rs
│   │       │   └── principal.rs
│   │       ├── policy/
│   │       │   ├── authorize.rs
│   │       │   ├── destination.rs
│   │       │   ├── rate_limit.rs
│   │       │   └── quota.rs
│   │       ├── session/
│   │       │   ├── registry.rs
│   │       │   ├── state.rs
│   │       │   ├── udp.rs
│   │       │   └── ip.rs
│   │       ├── proxy/
│   │       │   ├── resolver.rs
│   │       │   ├── udp_socket.rs
│   │       │   ├── address_pool.rs
│   │       │   ├── tun_dispatch.rs
│   │       │   └── mtu.rs
│   │       ├── control/
│   │       │   ├── server.rs
│   │       │   ├── protocol.rs
│   │       │   └── status.rs
│   │       └── telemetry/
│   │           ├── logging.rs
│   │           └── metrics.rs
│   ├── maskman-platform/
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── paths.rs
│   │       ├── process.rs
│   │       ├── privilege/
│   │       │   ├── supervisor.rs
│   │       │   ├── worker.rs
│   │       │   └── fd.rs
│   │       ├── service/
│   │       │   ├── manager.rs
│   │       │   ├── systemd.rs
│   │       │   └── launchd.rs
│   │       └── net/
│   │           ├── manager.rs
│   │           ├── linux.rs
│   │           ├── macos.rs
│   │           └── state.rs
│   ├── maskman-update/
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── release.rs
│   │       ├── target.rs
│   │       ├── verify.rs
│   │       ├── install.rs
│   │       └── rollback.rs
│   └── maskman-test-support/
│       └── src/
│           ├── lib.rs
│           ├── client.rs
│           ├── cert.rs
│           └── packet.rs
├── tests/
│   ├── interop/
│   ├── network/
│   └── fixtures/
├── benches/
│   ├── codec.rs
│   └── forwarding.rs
├── fuzz/
│   └── fuzz_targets/
└── xtask/
    └── src/
        ├── main.rs
        ├── compliance.rs
        └── release.rs
~~~

真实开发中只在一个职责开始独立增长时创建对应文件；树是边界设计，不要求第一天生成所有空文件。

## 2. Crate 职责

| crate | 职责 | 明确禁止 |
| --- | --- | --- |
| maskman | Clap 命令、交互输出、角色启动和退出码 | 协议解析、packet 转发、平台 syscall |
| maskman-config | serde model、TOML/JSON load、validation、compiled config | 网络 I/O、service mutation |
| maskman-protocol | RFC codec、状态转换、URI 参数和 packet scope；sans-I/O | Tokio、Quinn、文件系统、DNS |
| maskman-server | H3 adapter、auth/policy/session、UDP/TUN 数据面、control、telemetry | 安装 service、直接修改系统防火墙 |
| maskman-platform | 路径、service manager、权限拆分、TUN/route/NAT 平台实现 | RFC request 和 auth 逻辑 |
| maskman-update | release 查询、target 选择、签名校验、原子替换与回滚 | service 平台细节、协议逻辑 |
| maskman-test-support | 测试 client、证书、packet builder | 生产依赖 |

依赖方向：

~~~text
maskman
  -> maskman-config
  -> maskman-server
  -> maskman-platform
  -> maskman-update

maskman-server
  -> maskman-config
  -> maskman-protocol
  -> maskman-platform (仅 runtime handle，不执行 install)

maskman-platform -> maskman-config 的最小只读平台配置
maskman-protocol -> bytes/http/ipnet 等纯模型依赖
~~~

禁止 protocol 反向依赖 server，禁止 config 依赖任何 runtime crate，禁止 platform 调用 CLI。

## 3. 核心领域类型

跨模块只传递经过验证的类型，减少重复检查：

- RawConnectRequest：transport adapter 刚提取的 header。
- ValidatedConnectRequest：method、protocol、authority 和 path 已符合 profile。
- PrincipalId：认证后的稳定内部 ID，不包含 secret。
- EffectivePolicy：把 role、request scope 和 DNS 结果合并后的不可变策略。
- AuthorizedTarget：已经固定到具体 SocketAddr 的 UDP 目标。
- SessionId：随机、进程内唯一，不复用 QUIC stream ID。
- AddressLease：唯一 assigned address 集合，Drop 不直接做异步清理。
- ActiveSession：只有 provisioning 完成后才能构造。
- PacketView：借用原始 Bytes 的已验证 IP header view。
- DropReason：有限枚举，用于 metrics 和 debug log。

Raw string、hostname 或 h3 header 不得越过 authorization 边界进入 socket/TUN 层。

## 4. 协议实现方式

maskman-protocol 采用纯函数和显式状态：

- decode 接受受限 buffer，返回 NeedMore、Event 或 ProtocolError。
- encode 写入调用方 buffer，返回需要的长度。
- VarInt 统一实现并共享，不在每个 capsule 重写。
- ADDRESS 与 ROUTE 更新先解析到临时集合，验证成功后生成 Replace 事件。
- URI route 只支持 Maskman 定义的 base_path 和标准变量位置，不实现任意 RFC 6570 server-side matcher。
- 配置向客户端展示完整 URI Template；服务端内部用结构化 path segment 解码。

这种设计允许 unit、property、fuzz 和 differential test 不启动网络。

## 5. Transport adapter

transport 模块是 h3 实验 API 的防火墙：

- endpoint.rs 只负责 Quinn Endpoint 和 transport limits。
- connection.rs 驱动 H3 control stream、GOAWAY 和 connection metadata。
- request.rs 把 h3 request 转换为 RawConnectRequest。
- datagram.rs 处理 Quarter Stream ID，并把 payload 交给 session registry。
- capsule.rs 把 H3 DATA stream 适配为增量 capsule decoder。

不得在业务模块中保存 h3::server::RequestStream。使用内部 RequestIo trait/newtype 暴露 send_response、send_capsule、recv_capsule、close 等最小操作。这个抽象是为了隔离不稳定上游 API，不是为了同时支持任意 HTTP stack。

## 6. Platform 边界

NetManager 的生产实现按 target_os 编译：

- prepare：检查并创建 TUN、route、NAT，返回 handles 和可回滚 journal。
- inspect：读取当前由 Maskman 管理的系统状态。
- cleanup：只撤销 journal 中由本次实例拥有的资源。

ServiceManager 负责 install/start/stop/query，不负责 worker 健康。status command 合并 service 状态和 control socket 健康。

platform crate 是唯一允许少量 unsafe 的 crate。其他 production crate 在 crate root 使用 forbid(unsafe_code)。platform 中每个 unsafe block 必须有 SAFETY 注释、最小封装和平台测试；能用 rustix、socket2、tun-rs 或 netlink 安全 API 时不得自行 syscall。

## 7. 文件与函数规模

- production Rust 文件目标不超过 350 行逻辑代码。
- 超过 500 行必须先拆分，或在同一变更中记录不能拆分的具体理由。
- generated code、固定测试向量和平台常量表可例外，但要单独目录。
- 函数以单一职责为原则；超过约 60 行或出现多层状态分支时优先提取解析、校验或 transition 函数。
- lib.rs 和 main.rs 只做公开 API、wiring 和高层错误处理。
- 不使用 common.rs、utils.rs、helpers.rs 作为无边界收纳箱；文件名必须表达领域。

行数是维护性告警，不是鼓励把同一逻辑机械切成碎片。拆分必须形成可解释的 ownership。

## 8. 错误模型

- library crate 使用 thiserror 定义有语义的 error enum。
- anyhow 只允许在 binary command 顶层聚合上下文。
- 远端输入错误不能 panic；production path 不使用 unwrap/expect，除非是编译期或先前验证保证的不变量，并有短注释。
- ProtocolError 区分 request error、stream error 和 connection error，以便选择正确的 H3 code。
- 用户可修复的 CLI 错误要包含 path、字段和下一步；不得打印 token、private key 或完整 Authorization header。

## 9. Feature 与 target 规则

- 用 target_os cfg 选择 Linux/macOS 实现，不让用户手工组合 platform feature。
- test-only、fuzz 和 benchmark feature 不进入发布 binary。
- 实验功能默认关闭，并在 config schema 中标明 experimental；不能影响默认 RFC profile。
- all-features CI 必须有意义，不能因为互斥 platform feature 组合而天然失败。

## 10. 模块演进规则

只有满足以下至少一项才新增 crate：

- 需要独立 forbid unsafe 或依赖边界；
- 需要独立 fuzz/bench 和极小依赖图；
- 同一能力被 CLI 与 server 复用；
- 平台条件编译开始污染上层。

只被一个父模块使用、不到数百行的实现留在 crate 内。不要提前创建 service locator、插件系统或通用 dependency injection framework。
