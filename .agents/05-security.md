# 安全设计

## 1. 威胁模型

保护资产：

- 代理主机本身、内核网络栈、TUN、路由和 NAT 规则。
- 上游网络的可用性、带宽和源地址信誉。
- bearer secret、TLS private key、mTLS trust roots 和 update signing key。
- 不同 principal 之间的地址、流量和错误信息隔离。
- daemon 的完整性和可回滚更新状态。

攻击者能力：

- 未认证的 Internet client，可发送任意 QUIC Initial、HTTP/3 header、Capsule 和 datagram。
- 已认证但恶意的 principal，可尝试绕过 target scope、伪造 IP source、耗尽连接/内存/带宽或探测内网。
- 被入侵的目标 UDP service 或返回恶意 packet 的外部网络。
- 本机低权限用户，可能读取错误权限的 config、socket、日志或触发 CLI。
- GitHub release、CDN 或网络路径被篡改，但不持有 Maskman release signing key。

不把 kernel、rustls、Quinn、GitHub、DNS resolver 或 service manager 的漏洞假设为“不可能”；通过边界、版本固定、最小权限和回滚降低影响。

## 2. 认证

支持两种独立机制：

### Bearer

- Header 只接受 Authorization: Bearer <token>，拒绝 query、path 或 cookie token。
- 先解析 public token ID，再对 secret 做 SHA-256，使用 constant-time compare。
- token expiry、enabled、principal 和 config generation 都在验证中。
- 认证失败统一返回 401，Proxy-Status 不泄露 token 是否存在。
- 日志只记录 auth outcome、principal（若允许）和 reason enum，不记录 token。
- token rotation 采用新建、验证、撤销旧 token；不原地替换正在使用的 secret。

### mTLS

- QUIC TLS client certificate 在 transport handshake 期间验证。
- application auth 只从受信任证书链和 SAN/fingerprint 映射 principal。
- trust store 按 config generation 原子替换；旧连接可按策略继续直到 drain。
- setup 生成的 private key 初始为 mode 0600；安装 service 后由 root:maskman
  以 mode 0640 共享给已降权 worker，root 仍保留 owner，worker 仅有读取权限。
  私有 CA 文件同样为 mode 0640、owner root:maskman。
- mTLS 与 bearer 同时启用时按配置要求 all-of 或 any-of；默认 bearer-or-mtls。

不要自己解析 TLS record 或实现密码学。只用受支持的 rustls API，并在 release 前锁定 crypto provider 与审计版本。

## 3. 授权

授权输入：

- principal roles/capabilities；
- request protocol 和 path scope；
- decoded target、ipproto；
- DNS 结果中的每个 IP；
- 连接、session、principal 的当前 quota；
- 本地 destination deny list。

授权输出是不可变 EffectivePolicy。它包含：

- capability；
- allow/deny prefix set；
- allowed IP protocol set；
- target address set；
- max payload；
- byte/packet/session token buckets；
- source address lease namespace。

DNS 名称解析得到的每个 A/AAAA 记录必须单独检查，任何不允许的地址都不能通过“hostname 已允许”绕过 policy。默认拒绝：

- 127.0.0.0/8、::1；
- RFC 1918、RFC 6598、RFC 5735、RFC 4193 等私有/保留范围；
- link-local、multicast、broadcast、unspecified；
- server 所有本地接口地址和 management/control 地址；
- IPv6 过渡和保留范围，按定期维护的 ipnet policy table。

allow private/internal 必须按 role 显式开启，并要求 operator 在 config 中写 reason/comment。

## 4. RFC 9484 packet enforcement

IP proxy 不是“验一次 request 就全放行”：

1. 解析完整 IP header，防止截断和 length overflow。
2. 检查 source address 是当前 session 的 assigned prefix；不匹配丢弃并计 source_spoof。
3. 找到最外层非 extension protocol，检查 ipproto scope。
4. 检查 destination route、deny prefixes 和 session route advertisement。
5. 禁止不允许的 link-local traffic 离开接收 link。
6. 在发送到外部链路前递减 TTL/Hop Limit 一次；接收方向不重复递减。
7. MTU 不足时生成适当 ICMP Packet Too Big（若平台能力允许），不能把大包塞进可靠 Capsule 伪装成功。

收到 ICMP 错误时，若 shared external address 存在多个 session，必须检查 ICMP 中携带的 invoking packet，并只转发给 scope 匹配的 session，避免跨租户泄露。

## 5. RFC 9298 packet enforcement

- 只把 URI target_host/target_port 解析为结构化值；拒绝空值、非法 port、zone id 和未规范化 percent encoding。
- DNS 解析在 response 前完成，固定 IP 后连接 socket。
- 优先 connected UDP socket；退化路径逐包检查 source IP/port。
- context-0 payload > 65527 直接终止 request stream。
- 目标为本机、localhost、link-local、multicast、broadcast 或管理网段时拒绝。
- socket idle timeout 不低于两分钟；默认五分钟。
- 不主动 fragment，超 PMTU 丢包并记录。
- 每 principal 有 ingress/egress bytes、pps、active sessions 和 new sessions limit。

## 6. 资源防护

每一层都要有显式预算：

| 资源 | 默认基线 | 超限行为 |
| --- | --- | --- |
| QUIC connection | max_connections | 丢弃 Initial/拒绝新连接 |
| request headers | 16 KiB | H3 request error |
| active requests/connection | 64 | 429 或拒绝 stream |
| active sessions/principal | 32 | 429 + Proxy-Status |
| pending DNS | 256 | 503/拒绝 |
| pre-active datagrams | 0 | 丢弃 |
| capsule length | extension-specific budget | 流式跳过或 abort |
| per-session queued bytes | 4 MiB | drop datagram/abort control |
| TUN write queue | bounded | drop with metric |
| log queue | bounded | sample/drop debug logs |

所有上限是 config 编译结果，packet path 不读未经验证的 atomic 字符串配置。

## 7. 特权隔离与本地面

### supervisor

- root 只用于 bind privileged port、创建 TUN、配置 route/NAT 和设置 fd。
- 不读取 bearer secret，除非配置读取需要；推荐由 worker 读取被 supervisor 通过 fd/目录权限保护的 compiled config。
- 关闭时只清理自己的 journal 资源。
- 不能接受远程 admin command。

### worker

- 降权到专用 UID/GID。
- no_new_privs，清理环境变量和继承 fd。
- 不允许 ptrace、core dump 或写 system config。
- seccomp/apparmor/profile 作为 Linux hardening 增量，不阻塞开发 foreground。

### 本地 control socket

- daemon owner 0600（可由未来 supervisor 转交给 maskman-admin group）。
- 每条 command 带 protocol version、request id 和 max body。
- status 可读；reload/stop/update-required operations 做 peer UID/GID 检查。
- 不把它绑定到 TCP 或 MASQUE authority。

## 8. DNS 安全

- resolver 使用显式超时、并发上限和 response size 上限。
- 禁止把客户端提供的 hostname 直接交给 shell 或系统命令。
- 可选 DNS cache 必须有 TTL、负缓存上限和 config generation 隔离。
- 解析结果按 IP policy 检查，防止 DNS rebinding；session 后续只使用固定 SocketAddr。
- 对目标解析失败返回 Proxy-Status dns_error，但不把内部 resolver 细节返回客户端。

## 9. 观测与隐私

- 默认不记录完整 URI target、authority、Authorization、certificate、packet payload 或 private address。
- principal、destination prefix 和 route 只在 operator 显式开启时记录，并做脱敏/采样。
- metrics label 使用 protocol、status、drop_reason、auth_method 等有限枚举。
- audit log 记录 config generation、token create/revoke、service install、update verify/rollback 和 privilege errors。
- status 对普通用户只暴露聚合数；debug endpoint 不作为 v1 产品承诺。

## 10. 更新供应链

- release archive 必须同时有 SHA-256 和独立签名。
- signing public key 编译进 binary；key rotation 需要发布带 old+new key 的过渡版本。
- manifest 选择按固定 target triple，不根据任意用户输入拼 URL。
- 解包拒绝绝对路径、.. traversal、符号链接越界和超大文件。
- staged binary 先执行 --version、config validate 和签名/权限检查，再替换运行 binary。
- 原子替换前保留最近一个 old binary；启动失败自动 rollback。
- 更新期间不自动 sudo；权限不足明确提示。
- GitHub release actor 只能改变可用性，不应能改变信任，因为没有 signing key。

## 11. 检查清单

每个协议或系统变更在合并前回答：

- 新输入是否经过长度、语法、语义三层验证？
- 是否可能触发 DNS、socket、TUN 或文件系统操作后才发现未认证？
- 是否能影响另一 principal 的地址、route、ICMP、统计或日志？
- 超限是拒绝、丢弃还是关闭流？是否符合 RFC 语义？
- 任何 unwrap、unsafe、shell invocation、setuid 和 firewall mutation 是否有可审计理由？
- update artifact 是否独立签名且可回滚？
- 失败日志是否泄露 secret、内部地址或跨租户信息？
