use super::{
    inspect_service_path, install, render_launchd, status, uninstall, ServicePathState, ServiceSpec,
};
use std::path::PathBuf;

fn spec() -> ServiceSpec {
    ServiceSpec {
        binary: PathBuf::from("/usr/local/bin/maskman"),
        config: PathBuf::from("/etc/maskman/config.toml"),
        state_dir: PathBuf::from("/var/lib/maskman"),
        service_path: PathBuf::from("/tmp/maskman.service"),
    }
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
