use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigDocument {
    pub schema_version: u32,
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub policy: PolicyConfig,
    #[serde(default)]
    pub proxy: ProxyConfig,
    #[serde(default)]
    pub observability: ObservabilityConfig,
    #[serde(default)]
    pub update: UpdateConfig,
}

impl Default for ConfigDocument {
    fn default() -> Self {
        Self {
            schema_version: 1,
            server: ServerConfig::default(),
            tls: TlsConfig::default(),
            auth: AuthConfig::default(),
            policy: PolicyConfig::default(),
            proxy: ProxyConfig::default(),
            observability: ObservabilityConfig::default(),
            update: UpdateConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    #[serde(default = "default_listen")]
    pub listen: Vec<String>,
    #[serde(default = "default_base_path")]
    pub base_path: String,
    #[serde(default)]
    pub worker_threads: usize,
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout: String,
    #[serde(default = "default_drain_timeout")]
    pub drain_timeout: String,
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
    #[serde(default = "default_max_requests_per_connection")]
    pub max_requests_per_connection: u32,
    #[serde(default = "default_max_header_bytes")]
    pub max_header_bytes: u32,
    #[serde(default = "default_state_dir")]
    pub state_dir: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            base_path: default_base_path(),
            worker_threads: 0,
            idle_timeout: default_idle_timeout(),
            drain_timeout: default_drain_timeout(),
            max_connections: default_max_connections(),
            max_requests_per_connection: default_max_requests_per_connection(),
            max_header_bytes: default_max_header_bytes(),
            state_dir: default_state_dir(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    #[serde(default = "default_certificate_file")]
    pub certificate_file: String,
    #[serde(default = "default_private_key_file")]
    pub private_key_file: String,
    #[serde(default)]
    pub client_ca_file: Option<String>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            certificate_file: default_certificate_file(),
            private_key_file: default_private_key_file(),
            client_ca_file: None,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthMode {
    #[default]
    Bearer,
    Mtls,
    BearerOrMtls,
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    #[serde(default = "default_auth_required")]
    pub required: bool,
    #[serde(default)]
    pub mode: AuthMode,
    #[serde(default)]
    pub principals: Vec<PrincipalConfig>,
    #[serde(default)]
    pub bearer_tokens: Vec<BearerTokenConfig>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            required: default_auth_required(),
            mode: AuthMode::default(),
            principals: Vec::new(),
            bearer_tokens: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalConfig {
    pub id: String,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub certificate_sha256: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BearerTokenConfig {
    pub id: String,
    pub principal: String,
    pub secret_sha256: String,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    #[serde(default)]
    pub roles: Vec<RoleConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleConfig {
    pub name: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub allow_destinations: Vec<String>,
    #[serde(default)]
    pub deny_destinations: Vec<String>,
    #[serde(default = "default_deny_private")]
    pub deny_private: bool,
    #[serde(default)]
    pub allowed_ip_protocols: Vec<String>,
    #[serde(default)]
    pub limits: LimitsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsConfig {
    #[serde(default = "default_active_tunnels")]
    pub active_tunnels: u32,
    #[serde(default = "default_new_tunnels_per_minute")]
    pub new_tunnels_per_minute: u32,
    #[serde(default = "default_rate")]
    pub ingress_bytes_per_second: u64,
    #[serde(default = "default_rate")]
    pub egress_bytes_per_second: u64,
    #[serde(default = "default_burst")]
    pub burst_bytes: u64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            active_tunnels: default_active_tunnels(),
            new_tunnels_per_minute: default_new_tunnels_per_minute(),
            ingress_bytes_per_second: default_rate(),
            egress_bytes_per_second: default_rate(),
            burst_bytes: default_burst(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyConfig {
    #[serde(default)]
    pub udp: UdpConfig,
    #[serde(default)]
    pub ip: IpConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UdpConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_udp_idle_timeout")]
    pub socket_idle_timeout: String,
    #[serde(default = "default_max_udp_payload")]
    pub max_payload_bytes: u32,
    #[serde(default)]
    pub prefer_ipv6: bool,
}

impl Default for UdpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            socket_idle_timeout: default_udp_idle_timeout(),
            max_payload_bytes: default_max_udp_payload(),
            prefer_ipv6: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IpConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_interface_name")]
    pub interface_name: String,
    #[serde(default = "default_mtu")]
    pub mtu: u32,
    #[serde(default)]
    pub client_ipv4_pool: Option<String>,
    #[serde(default)]
    pub client_ipv6_pool: Option<String>,
    #[serde(default)]
    pub advertise_routes: Vec<String>,
    #[serde(default)]
    pub nat: NatConfig,
}

impl Default for IpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interface_name: default_interface_name(),
            mtu: default_mtu(),
            client_ipv4_pool: None,
            client_ipv6_pool: None,
            advertise_routes: Vec::new(),
            nat: NatConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NatMode {
    #[default]
    Disabled,
    Managed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NatConfig {
    #[serde(default)]
    pub mode: NatMode,
    #[serde(default = "default_egress_interface")]
    pub egress_interface: String,
}

impl Default for NatConfig {
    fn default() -> Self {
        Self { mode: NatMode::default(), egress_interface: default_egress_interface() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservabilityConfig {
    #[serde(default = "default_log_format")]
    pub log_format: String,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default = "default_metrics_listen")]
    pub metrics_listen: String,
    #[serde(default)]
    pub include_principal_in_logs: bool,
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            log_format: default_log_format(),
            log_level: default_log_level(),
            metrics_listen: default_metrics_listen(),
            include_principal_in_logs: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateConfig {
    #[serde(default = "default_update_channel")]
    pub channel: String,
    #[serde(default = "default_repository")]
    pub repository: String,
    #[serde(default = "default_update_interval")]
    pub check_interval: String,
}

impl Default for UpdateConfig {
    fn default() -> Self {
        Self {
            channel: default_update_channel(),
            repository: default_repository(),
            check_interval: default_update_interval(),
        }
    }
}

fn default_listen() -> Vec<String> {
    vec!["0.0.0.0:443".into(), "[::]:443".into()]
}
fn default_base_path() -> String {
    "/.well-known/masque".into()
}
fn default_idle_timeout() -> String {
    "5m".into()
}
fn default_drain_timeout() -> String {
    "20s".into()
}
fn default_max_connections() -> u32 {
    20_000
}
fn default_max_requests_per_connection() -> u32 {
    64
}
fn default_max_header_bytes() -> u32 {
    16_384
}
fn default_state_dir() -> String {
    if cfg!(target_os = "macos") {
        "/Library/Application Support/Maskman/state".into()
    } else {
        "/var/lib/maskman".into()
    }
}
fn default_certificate_file() -> String {
    "tls/fullchain.pem".into()
}
fn default_private_key_file() -> String {
    "tls/private-key.pem".into()
}
fn default_auth_required() -> bool {
    true
}
fn default_enabled() -> bool {
    true
}
fn default_deny_private() -> bool {
    true
}
fn default_active_tunnels() -> u32 {
    32
}
fn default_new_tunnels_per_minute() -> u32 {
    120
}
fn default_rate() -> u64 {
    100 * 1024 * 1024
}
fn default_burst() -> u64 {
    4 * 1024 * 1024
}
fn default_udp_idle_timeout() -> String {
    "5m".into()
}
fn default_max_udp_payload() -> u32 {
    65_527
}
fn default_interface_name() -> String {
    #[cfg(target_os = "macos")]
    {
        // Let utun allocate the next free unit instead of colliding on a fixed
        // index when a second daemon is started.
        String::new()
    }
    #[cfg(not(target_os = "macos"))]
    "maskman0".into()
}
fn default_mtu() -> u32 {
    1_280
}
fn default_egress_interface() -> String {
    "auto".into()
}
fn default_log_format() -> String {
    "json".into()
}
fn default_log_level() -> String {
    "info".into()
}
fn default_metrics_listen() -> String {
    "127.0.0.1:9464".into()
}
fn default_update_channel() -> String {
    "stable".into()
}
fn default_repository() -> String {
    "backrunner/maskman".into()
}
fn default_update_interval() -> String {
    "24h".into()
}
