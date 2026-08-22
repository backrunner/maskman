#![forbid(unsafe_code)]

mod compile;
mod error;
mod load;
pub mod model;
mod validate;

use std::{
    path::{Path, PathBuf},
    str::FromStr,
};

pub use compile::{
    CompiledConfig, CompiledIp, CompiledLimits, CompiledRole, CompiledToken, CompiledUdp,
};
pub use error::ConfigError;
pub use load::{render, write_atomic};
pub use model::{AuthMode, ConfigDocument};
pub use validate::{parse_duration, resolve_path, validate, ValidationError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigFormat {
    Toml,
    Json,
}

impl ConfigFormat {
    pub fn from_path(path: &Path) -> Result<Self, ConfigError> {
        match path.extension().and_then(|extension| extension.to_str()) {
            Some("toml") => Ok(Self::Toml),
            Some("json") => Ok(Self::Json),
            _ => Err(ConfigError::UnsupportedFormat(path.to_path_buf())),
        }
    }
}

impl FromStr for ConfigFormat {
    type Err = ConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "toml" => Ok(Self::Toml),
            "json" => Ok(Self::Json),
            _ => Err(ConfigError::UnsupportedFormat(PathBuf::from(value))),
        }
    }
}

pub fn load(path: &Path) -> Result<ConfigDocument, ConfigError> {
    load::load(path)
}

pub fn compile(path: &Path) -> Result<CompiledConfig, ConfigError> {
    let document = load(path)?;
    let base_dir = path.parent().unwrap_or_else(|| Path::new("."));
    compile_document(&document, base_dir)
}

pub fn compile_document(
    document: &ConfigDocument,
    base_dir: &Path,
) -> Result<CompiledConfig, ConfigError> {
    let absolute_base = if base_dir.is_absolute() {
        base_dir.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|source| ConfigError::Read { path: base_dir.to_path_buf(), source })?
            .join(base_dir)
    };
    compile::compile(document, &absolute_base)
}

#[cfg(test)]
mod tests {
    use super::{
        load, model::ConfigDocument, render, validate, write_atomic, AuthMode, ConfigFormat,
    };

    #[test]
    fn default_config_round_trips_as_toml() {
        let document = ConfigDocument::default();
        let rendered = match render(&document, ConfigFormat::Toml) {
            Ok(rendered) => rendered,
            Err(error) => panic!("render: {error}"),
        };
        let parsed: ConfigDocument = match toml::from_str(&rendered) {
            Ok(parsed) => parsed,
            Err(error) => panic!("parse: {error}"),
        };
        if let Err(error) = validate(&parsed) {
            panic!("defaults validate: {error}");
        }
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let result = toml::from_str::<ConfigDocument>("schema_version = 1\nunknown = true\n");
        assert!(result.is_err());
    }

    #[test]
    fn atomic_writer_round_trips_toml_and_json() {
        let root = std::env::temp_dir().join(format!("maskman-config-{}", std::process::id()));
        let toml_path = root.join("config.toml");
        let json_path = root.join("config.json");
        let document = ConfigDocument::default();
        let _ = std::fs::remove_dir_all(&root);
        if let Err(error) = write_atomic(&toml_path, &document) {
            panic!("write TOML: {error}");
        }
        if let Err(error) = write_atomic(&json_path, &document) {
            panic!("write JSON: {error}");
        }
        let toml_loaded = match load(&toml_path) {
            Ok(value) => value,
            Err(error) => panic!("load TOML: {error}"),
        };
        let json_loaded = match load(&json_path) {
            Ok(value) => value,
            Err(error) => panic!("load JSON: {error}"),
        };
        assert_eq!(toml_loaded.schema_version, 1);
        assert_eq!(json_loaded.schema_version, 1);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&toml_path)
                    .unwrap_or_else(|error| panic!("stat TOML: {error}"))
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn atomic_writer_rejects_a_broken_symlink() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!(
            "maskman-config-symlink-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let path = root.join("config.toml");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap_or_else(|error| panic!("create test root: {error}"));
        symlink(root.join("missing.toml"), &path)
            .unwrap_or_else(|error| panic!("create broken config symlink: {error}"));
        assert!(write_atomic(&path, &ConfigDocument::default()).is_err());
        assert!(std::fs::symlink_metadata(&path)
            .unwrap_or_else(|error| panic!("inspect config symlink: {error}"))
            .file_type()
            .is_symlink());
        std::fs::remove_dir_all(root).unwrap_or_else(|error| panic!("remove test root: {error}"));
    }

    #[test]
    fn mtls_requires_a_ca_and_certificate_principal() {
        for mode in [AuthMode::Mtls, AuthMode::BearerOrMtls] {
            let mut document = ConfigDocument::default();
            document.auth.mode = mode;
            assert!(matches!(validate(&document), Err(validate::ValidationError::MissingClientCa)));
            document.tls.client_ca_file = Some("client-ca.pem".into());
            assert!(matches!(
                validate(&document),
                Err(validate::ValidationError::MissingCertificatePrincipal)
            ));
        }
    }

    #[test]
    fn enabled_udp_rejects_idle_timeouts_below_rfc_9298_guidance() {
        let mut document = ConfigDocument::default();
        document.proxy.udp.enabled = true;
        document.proxy.udp.socket_idle_timeout = "119s".into();
        assert!(matches!(validate(&document), Err(validate::ValidationError::UdpIdleTimeout)));
        document.proxy.udp.socket_idle_timeout = "2m".into();
        assert!(validate(&document).is_ok());
    }

    #[test]
    fn metrics_listener_cannot_collide_with_quic_listener() {
        let mut document = ConfigDocument::default();
        document.server.listen[0] = "127.0.0.1:4433".into();
        document.observability.metrics_listen = document.server.listen[0].clone();
        assert!(matches!(
            validate(&document),
            Err(crate::ValidationError::MetricsListenConflict(_))
        ));
    }

    #[test]
    fn metrics_listener_must_remain_on_loopback() {
        for address in ["0.0.0.0:9090", "[::]:9090", "192.0.2.1:9090"] {
            let mut document = ConfigDocument::default();
            document.observability.metrics_listen = address.into();
            assert!(matches!(
                validate(&document),
                Err(crate::ValidationError::MetricsListenNonLoopback(_))
            ));
        }
    }

    #[test]
    fn managed_nat_requires_ip_and_owned_interface_shape() {
        let mut document = ConfigDocument::default();
        document.proxy.ip.nat.mode = crate::model::NatMode::Managed;
        assert!(matches!(validate(&document), Err(crate::ValidationError::NatRequiresIp)));
        document.proxy.ip.enabled = true;
        document.proxy.ip.client_ipv4_pool = Some("100.64.0.0/10".into());
        document.proxy.ip.interface_name = "unsafe;name".into();
        assert!(matches!(validate(&document), Err(crate::ValidationError::InterfaceName(_))));
    }

    #[test]
    fn client_address_pools_must_match_their_declared_family() {
        let mut document = ConfigDocument::default();
        document.proxy.ip.enabled = true;
        document.proxy.ip.client_ipv4_pool = Some("fd42::/64".into());
        assert!(matches!(
            validate(&document),
            Err(crate::ValidationError::IpPool { field: "proxy.ip.client_ipv4_pool", .. })
        ));

        document.proxy.ip.client_ipv4_pool = None;
        document.proxy.ip.client_ipv6_pool = Some("100.64.0.0/10".into());
        assert!(matches!(
            validate(&document),
            Err(crate::ValidationError::IpPool { field: "proxy.ip.client_ipv6_pool", .. })
        ));
    }
}
