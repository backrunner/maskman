use super::*;
use crate::service::ServiceSpec;
use std::path::PathBuf;

fn spec() -> ServiceSpec {
    ServiceSpec {
        binary: PathBuf::from("/usr/local/bin/maskman"),
        config: PathBuf::from("/etc/maskman/config.toml"),
        state_dir: PathBuf::from("/var/lib/maskman"),
        service_path: PathBuf::from("/tmp/maskman"),
    }
}

#[test]
fn openrc_script_supervises_and_prepares_state_directories() {
    let output = render(&spec()).unwrap_or_else(|error| panic!("render openrc script: {error}"));
    assert!(output.starts_with("#!/sbin/openrc-run\n"));
    assert!(output.contains("supervisor=\"supervise-daemon\""));
    assert!(output.contains("command=/usr/local/bin/maskman"));
    assert!(output.contains("command_args=\"--config /etc/maskman/config.toml serve\""));
    assert!(output.contains("directory=/var/lib/maskman"));
    assert!(output.contains("checkpath --directory --mode 0750 --owner root:maskman"));
    assert!(output.contains("start-stop-daemon --signal HUP"));
    assert!(!output.contains("sh -c"));
}

#[test]
fn openrc_render_rejects_paths_the_script_cannot_safely_represent() {
    // openrc-run evaluates the start line through the shell more than once, so
    // spaces and shell metacharacters cannot be escaped reliably; render must
    // fail closed instead.
    for bad in ["/var/lib/my maskman", "/var/lib/a$b", "/var/lib/a\"b", "/var/lib/a`b`"] {
        let mut spec = spec();
        spec.state_dir = PathBuf::from(bad);
        assert!(render(&spec).is_err(), "state dir {bad:?} must be rejected");
    }
    let mut spec = spec();
    spec.config = PathBuf::from("/etc/maskman/my config.toml");
    assert!(render(&spec).is_err(), "spaced config path must be rejected");
}
