# 配置、CLI 与运维契约

## 1. 配置原则

- TOML 与 JSON 使用同一个 serde model，不存在功能差异。
- 根据扩展名识别格式，只接受 .toml 和 .json，不猜测。
- 根字段 schema_version 必填；v1 只接受值 1。
- 所有配置 struct 使用 deny_unknown_fields，拼错字段直接报错。
- load 分为 parse、semantic validate、compile 三步。
- 相对路径以配置文件所在目录解析，不以 daemon 当前工作目录解析。
- duration、byte size、CIDR、socket address 和 RFC3339 时间使用强类型解析。
- 主配置和认证变更通过同目录临时文件、fsync、rename 原子写入。
- secret 不允许出现在命令行参数、日志或 environment dump 中。

默认位置：

| 用途 | Linux | macOS system daemon |
| --- | --- | --- |
| 配置 | /etc/maskman/config.toml | /Library/Application Support/Maskman/config.toml |
| 状态 | /var/lib/maskman | /Library/Application Support/Maskman/state |
| runtime | /run/maskman | /var/run/maskman |
| binary | /usr/local/bin/maskman | /usr/local/bin/maskman |
| service | maskman.service | top.backrunner.maskman |

开发模式可通过 --config 指向任意可读文件，不自动写系统目录。

## 2. 建议 TOML

以下示例展示 schema 形状，不是可直接上线的 secret：

~~~toml
schema_version = 1

[server]
listen = ["0.0.0.0:443", "[::]:443"]
base_path = "/.well-known/masque"
worker_threads = 0
idle_timeout = "5m"
drain_timeout = "20s"
max_connections = 20000
max_requests_per_connection = 64
max_header_bytes = 16384

[tls]
certificate_file = "/etc/maskman/tls/fullchain.pem"
private_key_file = "/etc/maskman/tls/private-key.pem"
client_ca_file = "/etc/maskman/tls/client-ca.pem"

[auth]
required = true
mode = "bearer-or-mtls"

[[auth.principals]]
id = "admin"
roles = ["default"]
# Replace this placeholder with the SHA-256 digest of an allowed client certificate.
certificate_sha256 = ["0000000000000000000000000000000000000000000000000000000000000000"]

[[auth.bearer_tokens]]
id = "tok_01"
principal = "admin"
secret_sha256 = "HEX_ENCODED_SHA256_OF_32_BYTE_RANDOM_SECRET"
expires_at = "2027-08-20T00:00:00Z"
enabled = true

[[policy.roles]]
name = "default"
capabilities = ["connect-udp", "connect-ip"]
allow_destinations = ["0.0.0.0/0", "::/0"]
deny_private = true
allowed_ip_protocols = ["*"]

[policy.roles.limits]
active_tunnels = 32
new_tunnels_per_minute = 120
ingress_bytes_per_second = 104857600
egress_bytes_per_second = 104857600
burst_bytes = 4194304

[proxy.udp]
enabled = true
socket_idle_timeout = "5m"
max_payload_bytes = 65527
prefer_ipv6 = true

[proxy.ip]
enabled = true
interface_name = "maskman0"
mtu = 1280
client_ipv4_pool = "100.96.0.0/11"
client_ipv6_pool = "fd42:6d61:736b::/64"
advertise_routes = ["0.0.0.0/0", "::/0"]

[proxy.ip.nat]
mode = "managed"
egress_interface = "auto"

[observability]
log_format = "json"
log_level = "info"
metrics_listen = "127.0.0.1:9464"
include_principal_in_logs = false

[update]
channel = "stable"
repository = "backrunner/maskman"
check_interval = "24h"
~~~

JSON 使用相同 snake_case 字段与数组结构。setup 通过 serde model 生成 JSON，不能维护第二份手写默认值。

## 3. 关键验证规则

### Server 与 TLS

- listen 至少一个地址，端口不能为 0。
- base_path 必须是规范化 absolute path，不含 query、fragment、dot segment 或百分号编码斜线。
- certificate/private key 必须可读、匹配、支持 TLS 1.3。
- 若 auth mode 包含 mTLS，client_ca_file 必须存在。
- header、connection、request 和 timeout 必须处于内建安全上下限。

### Auth 与 policy

- auth.required 默认为 true；false 只允许显式配置，并打印高等级告警。
- 每个 token ID、principal ID 和 role name 唯一。
- bearer secret 必须由 setup 生成的至少 256-bit 随机值产生 hash。
- token expiry 必须是 UTC；过期 token 在 load 时保留为 revoked 状态，不导致 daemon 无法启动。
- 每个 principal 引用的 role 必须存在。
- allow 和 deny CIDR 必须规范化；deny 优先。
- deny_private 默认 true，关闭它必须是显式字段。
- capability 与已启用 proxy 必须一致。

### CONNECT-IP

- IPv4/IPv6 pool 不得和 server listen、本机接口、advertise route 或另一 pool 冲突。
- pool 必须至少容纳配置的最大 active IP tunnel 数及保留地址。
- IPv6 启用时 MTU 不得低于 1280。
- managed NAT 必须能确定 egress interface；auto 解析失败时启动失败，不猜测。
- advertise route 必须被全局 policy 允许。

compile 阶段产生 CompiledConfig，包括 prefix set、token lookup、role policy、duration 和 byte limit，packet path 不再解析字符串。

## 4. Bearer token 格式

setup 生成：

~~~text
mm_<public-token-id>_<base64url-encoded-32-random-bytes>
~~~

配置只保存 public token ID 和 secret 部分的 SHA-256。高熵 secret 不需要昂贵的 password KDF；查找 token ID 后对提交 secret 求 hash，并 constant-time 比较。若未来支持人类密码，必须单独使用 Argon2id，不能复用 bearer token verifier。

token 明文只显示一次。交互 setup 可以：

- 显示到当前 TTY；
- 或按用户明确指定写入 mode 0600 的文件。

不得把 token 写进 shell history、service unit、日志或 status。

## 5. CLI 命令树

~~~text
maskman setup
maskman config validate
maskman auth token create
maskman auth token revoke
maskman auth token list
maskman install
maskman uninstall
maskman start
maskman stop
maskman status
maskman reload
maskman update
maskman serve
maskman completions
maskman version
~~~

### setup

默认交互流程：

1. 选择 TOML 或 JSON 和输出路径。
2. 选择 listen address/port。
3. 选择已有 certificate/key；只有 --development 才生成 self-signed certificate。
4. 选择 bearer、mTLS 或两者。
5. 生成首个 principal 和 bearer token。
6. 选择启用 CONNECT-UDP、CONNECT-IP 或两者。
7. 若启用 IP，选择双栈 pool、advertise route 和 NAT mode。
8. 展示风险摘要和将写入的路径。
9. 写入后立即执行 config validate。
10. 提示下一条 install 或 serve 命令。

setup 必须支持 --non-interactive、--format、--output 和完整 flags。缺少必需输入时返回错误，不在 CI 中等待 prompt。

### config validate

读取、解析、语义校验 certificate、auth、ACL、pool 和 platform prerequisites。默认不修改系统；--check-system 可以只读检查 TUN/NAT/service 能力。

### auth token

- create：生成新 token、原子更新配置、显示明文一次，可选 reload。
- revoke：按 public ID 禁用，不接受 secret 作为定位参数。
- list：只显示 ID、principal、expiry 和 enabled。
- 修改 TOML 使用 toml_edit 保留注释；JSON 使用结构化 parse/serialize。

### install

1. 解析并验证 config。
2. 展示 dry-run plan。
3. 检查当前用户权限；不偷偷调用 sudo。
4. 创建 system user、目录和权限。
5. 原子安装当前已签名 binary。
6. 安装 hardening 后的 systemd unit 或 launchd plist。
7. daemon-reload/bootstrap，并验证 service definition。
8. 由用户选择是否立即 start。

重复执行 install 必须幂等。覆盖不同来源 binary 或已有非 Maskman service 时必须停止并要求确认。提供 --dry-run 和 --yes。

### start / stop / status / reload

- start：启动已安装 service；未安装时明确建议 install 或 serve。
- stop：通过 service manager 请求优雅停止，支持 --timeout。
- status：合并 installed/running PID、version、uptime、config hash、connections、UDP/IP sessions、packet drops 和最近错误。
- status --json：稳定、无颜色、可供监控读取。
- reload：先本地 validate，再通过 control socket 原子 reload。

### serve

仅用于前台运行和开发。不会 fork，不安装 service。缺少所需网络权限时给出具体 capability/root 指引。

## 6. 终端体验

- Clap 负责解析和 usage，anstyle/console 负责颜色，dialoguer 负责 prompt，indicatif 负责下载进度。
- 遵守 NO_COLOR、TERM=dumb 和非 TTY；--color auto|always|never 可覆盖。
- prompt 文案必须说明将修改的路径和是否需要特权。
- spinner/progress 不进入 JSON 或重定向输出。
- 普通成功输出简短；详细诊断放 --verbose。
- 所有破坏性操作有 --yes，非交互时缺少 --yes 则失败。

建议退出码：

| code | 含义 |
| --- | --- |
| 0 | 成功 |
| 2 | CLI usage |
| 3 | 配置无效 |
| 4 | 权限不足 |
| 5 | service 不可用或状态失败 |
| 6 | network/protocol 运行失败 |
| 7 | update 检查、验证或回滚失败 |

## 7. Service definition

systemd unit 至少包含：

- Type=notify 或明确 readiness 机制；
- Restart=on-failure 和受限 restart burst；
- LimitNOFILE 与 capacity 配置一致；
- RuntimeDirectory、StateDirectory、ConfigurationDirectory；
- CapabilityBoundingSet、NoNewPrivileges、PrivateTmp、ProtectSystem；
- 明确允许网络与 TUN 所需的例外；
- ExecStart 使用绝对 binary/config path。

launchd plist：

- ProgramArguments 每个参数独立；
- KeepAlive 只在异常退出时重启；
- RunAtLoad；
- root supervisor，不使用 shell；
- stdout/stderr 进入受控日志或 unified logging adapter；
- Soft/HardResourceLimits 与 fd 容量一致。

service template 不拼接未经验证的用户字符串。

## 8. Update 命令

用法：

- maskman update --check：只检查，输出当前与最新版本。
- maskman update：交互确认后安装最新 stable。
- maskman update --version X.Y.Z：安装指定、仍受签名信任的版本。
- maskman update --yes：非交互。

流程：

1. 取得 release manifest，严格 semver 和 channel 过滤。
2. 按编译期 target 常量选择唯一 artifact。
3. 下载到安装目录同一 filesystem 的临时目录。
4. 同时验证 SHA-256 和内嵌 public key 对 archive 的 Ed25519/zipsign 签名。
5. 解包后运行 staged binary version 与 config validate。
6. 若为 service install，停止 daemon。
7. old binary 移到 versioned backup，new binary 原子 rename 到位。
8. 启动 service，等待 readiness 和 control health。
9. 健康失败则恢复 old binary 并重启；保留诊断。
10. 成功后删除过期 backup，保留最近一个可回滚版本。

GitHub 自己发布的 digest 只证明下载完整性，不能代替独立签名，因为有 release 写权限的人也能替换 asset。update 不自动提升权限；system install 无写权限时提示使用明确的特权调用。

## 9. 兼容与迁移

- schema_version 改变时提供 maskman config migrate --dry-run。
- minor version 只能新增有默认值的字段，不能悄悄改变安全默认。
- 删除字段至少经历一个 minor version 的 deprecated warning。
- daemon 启动时拒绝来自未来 schema 的配置。
- setup 生成的配置必须通过当前版本 round-trip 与 snapshot test。
