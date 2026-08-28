use super::{
    inspect_service_path, install, render_launchd, render_systemd, status, systemd_path, uninstall,
    ServicePathState, ServiceSpec,
};
use std::path::{Path, PathBuf};

fn spec() -> ServiceSpec {
    ServiceSpec {
        binary: PathBuf::from("/usr/local/bin/maskman"),
        config: PathBuf::from("/etc/maskman/config.toml"),
        state_dir: PathBuf::from("/var/lib/maskman"),
        service_path: PathBuf::from("/tmp/maskman.service"),
    }
}

#[test]
fn systemd_template_has_hardening_and_absolute_exec() {
    let output = render_systemd(&spec());
    assert!(output.contains("NoNewPrivileges=true"));
    assert!(output.contains("Environment=MASKMAN_ROLE=supervisor"));
    assert!(output.contains("Group=maskman"));
    assert!(output.contains("StateDirectoryMode=0770"));
    assert!(output.contains("KillMode=control-group"));
    assert!(output.contains("DeviceAllow=/dev/net/tun rw"));
    assert!(output.contains("RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK"));
    assert!(output.contains("ExecStart=\"/usr/local/bin/maskman\""));
    assert!(!output.contains("sh -c"));
}

#[test]
fn systemd_template_keeps_routine_paths_unquoted_and_start_limits_in_unit() {
    let output = render_systemd(&spec());
    // Old systemd releases do not strip quotes from path settings; routine
    // absolute paths must reach the unit file without any quote characters.
    assert!(output.contains("WorkingDirectory=/var/lib/maskman\n"));
    assert!(output.contains("ReadWritePaths=/var/lib/maskman\n"));
    assert!(output.contains("ReadOnlyPaths=/etc/maskman\n"));
    // StartLimit* belongs to [Unit] since systemd v230.
    assert!(output.starts_with(
        "[Unit]\nDescription=Maskman MASQUE proxy\nAfter=network-online.target\nWants=network-online.target\nStartLimitIntervalSec=60s\nStartLimitBurst=5\n"
    ));
}

#[test]
fn systemd_path_quotes_only_when_needed_and_escapes_specifiers() {
    assert_eq!(systemd_path(Path::new("/var/lib/maskman")), "/var/lib/maskman");
    assert_eq!(systemd_path(Path::new("/var/lib/100%")), "/var/lib/100%%");
    assert_eq!(systemd_path(Path::new("/var/lib/my maskman")), "\"/var/lib/my maskman\"");
}

#[cfg(target_os = "linux")]
#[test]
fn systemd_major_version_parses_distribution_strings() {
    use super::systemd_major_version;
    assert_eq!(systemd_major_version("systemd 249 (249.11-0ubuntu3.12)"), Some(249));
    assert_eq!(systemd_major_version("systemd 235 (235)"), Some(235));
    assert_eq!(systemd_major_version("garbage"), None);
}

#[test]
fn launchd_template_keeps_arguments_separate_and_escapes_xml() {
    let mut spec = spec();
    spec.config = PathBuf::from("/etc/maskman/a&b.toml");
    let output = render_launchd(&spec);
    assert!(
        output.contains("<array><string>/usr/local/bin/maskman</string><string>--config</string>")
    );
    assert!(output.contains("a&amp;b.toml"));
    assert!(output.contains("<key>EnvironmentVariables</key>"));
    assert!(output.contains("<key>RunAtLoad</key><true/>"));
}

#[cfg(unix)]
#[test]
fn service_operations_reject_a_broken_symlink_path() {
    use std::os::unix::fs::symlink;

    let root = std::env::temp_dir().join(format!(
        "maskman-service-symlink-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    ));
    let path = root.join("maskman.service");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap_or_else(|error| panic!("create test root: {error}"));
    symlink(root.join("missing.service"), &path)
        .unwrap_or_else(|error| panic!("create broken service symlink: {error}"));
    assert_eq!(
        inspect_service_path(&path).unwrap_or_else(|error| panic!("inspect path: {error}")),
        ServicePathState::Symlink
    );
    let service =
        spec().with_service_path(path).unwrap_or_else(|error| panic!("service path: {error}"));
    assert!(install(&service, true).is_err());
    assert!(status(&service).is_err());
    assert!(uninstall(&service, true).is_err());
    std::fs::remove_dir_all(root).unwrap_or_else(|error| panic!("remove test root: {error}"));
}
