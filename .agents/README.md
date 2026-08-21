# Maskman 实现方案索引

状态：M0-M3、M6 与 M7 的核心能力已有本地实现和测试；M4/M5 已加入 CONNECT-IP/session、受限 control/metrics、Linux nftables 与 macOS route/pf 适配、持久化资源 journal、supervisor/worker fd 隔离和服务 hardening；目标机特权转发、macOS utun/pf smoke 和外部 release gate 仍未完成；M8 本地质量门禁已验证，目标机、长稳和外部互操作证据仍待执行
调研基线：2026-08-20
目标：单一 Rust 二进制，作为长期运行的 MASQUE daemon，同时提供安装、配置、生命周期管理和自更新 CLI。

## 已确定的产品边界

- v1 的规范主目标是 RFC 9484 CONNECT-IP。
- 同时实现 RFC 9298 CONNECT-UDP，先用它打通 HTTP/3 Datagram 数据面，再复用到 CONNECT-IP。
- v1 只声明 HTTP/3 支持。HTTP/1.1 Upgrade 与 HTTP/2 Extended CONNECT 不在 v1 支持声明中。
- HTTP/3 下同时支持 QUIC DATAGRAM 快速路径和 RFC 9297 DATAGRAM Capsule 回退路径。
- 服务端应用代码使用 Rust；不编写自有 C/C++ 或 FFI。TLS/密码学依赖可以包含经过审计的汇编或原生实现，不能为了字面上的“纯 Rust”改用 alpha 级密码学 provider。
- 一个发布二进制 maskman，内部可运行 CLI、特权 supervisor 和非特权 worker 三种角色。
- 首发目标为：
  - x86_64-unknown-linux-musl
  - aarch64-unknown-linux-musl
  - aarch64-apple-darwin
- 默认必须认证，默认拒绝访问本机、私网、链路本地、组播和广播目标。
- 配置文件支持 TOML 与 JSON，字段语义完全一致，拒绝未知字段。

## 文档地图

- [01-research-and-scope.md](01-research-and-scope.md)：RFC 关系、合规矩阵、Rust 生态对比和技术选型。
- [02-architecture.md](02-architecture.md)：进程模型、控制面、数据面、状态机、TUN 和性能设计。
- [03-modules.md](03-modules.md)：workspace、crate、目录、文件职责和依赖边界。
- [04-configuration-and-cli.md](04-configuration-and-cli.md)：配置模型、setup、service、update 和 CLI 契约。
- [05-security.md](05-security.md)：认证、授权、滥用防护、权限隔离和更新供应链。
- [06-quality-and-release.md](06-quality-and-release.md)：测试、互操作、性能、CI 和发布流程。
- [07-milestones.md](07-milestones.md)：阶段、验收门槛、工期和风险。
- [08-transport-spike.md](08-transport-spike.md)：M1 固定依赖、transport gate、互操作结果和已知上游缺口。
- [09-protocol-compliance.md](09-protocol-compliance.md)：M2 codec、属性/fuzz/golden 证据和执行门禁结果。
- [10-auth-and-udp.md](10-auth-and-udp.md)：M3 authentication、policy、DNS 固定解析和 CONNECT-UDP 数据面证据。
- [11-connect-ip.md](11-connect-ip.md)：M4 CONNECT-IP session、地址池、packet enforcement、TUN 边界和 Linux netlink 证据。
- [12-m8-evidence.md](12-m8-evidence.md)：M8 benchmark、fuzz、网络/平台 smoke、soak、interop 和发布门禁证据。
- [13-threat-model.md](13-threat-model.md)：资产、信任边界、滥用路径和剩余 release blocker。
- [skills/maskman-guard/SKILL.md](skills/maskman-guard/SKILL.md)：后续开发和审查必须使用的工程 guard。

## v1 完成定义

只有同时满足下列条件，版本才能标记为 1.0：

1. RFC 9484、9297、9298 的适用 MUST/SHALL 已进入可追踪合规矩阵并有自动化测试。
2. CONNECT-IP 在 Linux 和 macOS arm64 上完成真实 TUN、双栈地址分配、路由通告、源地址校验和 MTU/ICMP 处理。
3. CONNECT-UDP 完成 DNS 固定解析、目标 ACL、connected UDP socket 和双向转发。
4. Bearer token 与 mTLS 均可用于认证，授权、速率限制和配额按 principal 生效。
5. setup、install、start、stop、status、update 均支持交互和非交互模式。
6. 三个发布目标经过原生或受控的跨架构测试，产物有校验和、独立签名、SBOM 和 provenance。
7. 模糊测试、故障注入、长稳测试、互操作测试和性能回归门槛全部通过。

本目录描述的是实施合同和当前证据，不代表目标机或外部互操作 gate 已通过。任何发布说明必须以实际通过的合规矩阵和 release checklist 为准。
