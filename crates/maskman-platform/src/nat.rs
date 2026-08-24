use std::{
    io::Write,
    path::Path,
    process::{Command, Stdio},
};

use ipnet::IpNet;

use crate::{JournalEntry, NetworkJournal, PlatformError};

#[cfg(target_os = "linux")]
const LINUX_TABLE: &str = "inet maskman";
#[cfg(target_os = "macos")]
const MACOS_ANCHOR: &str = "com.backrunner.maskman";
const OWNERSHIP_MARKER: &str = "maskman-owned-v1";

#[derive(Debug, Clone, Copy)]
pub struct ManagedNatConfig<'a> {
    pub egress_interface: &'a str,
    pub ipv4_pool: Option<IpNet>,
    pub ipv6_pool: Option<IpNet>,
}

pub fn managed_nat_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        Command::new("nft").arg("--version").output().is_ok_and(|output| output.status.success())
    }
    #[cfg(target_os = "macos")]
    {
        Command::new("pfctl").args(["-s", "info"]).output().is_ok()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    false
}

pub fn managed_nat_resource_id() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        LINUX_TABLE
    }
    #[cfg(target_os = "macos")]
    {
        MACOS_ANCHOR
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    "unsupported"
}

pub fn apply_managed_nat(
    config: ManagedNatConfig<'_>,
    journal: &mut NetworkJournal,
) -> Result<(), PlatformError> {
    apply_managed_nat_inner(config, journal, None)
}

pub fn apply_managed_nat_persisted(
    config: ManagedNatConfig<'_>,
    journal: &mut NetworkJournal,
    journal_path: &Path,
) -> Result<(), PlatformError> {
    apply_managed_nat_inner(config, journal, Some(journal_path))
}

fn apply_managed_nat_inner(
    config: ManagedNatConfig<'_>,
    journal: &mut NetworkJournal,
    journal_path: Option<&Path>,
) -> Result<(), PlatformError> {
    validate_config(&config)?;
    if journal.entries().iter().any(|entry| matches!(entry, JournalEntry::Nat { .. })) {
        return Err(PlatformError::InvalidService(
            "managed NAT is already recorded in the resource journal".into(),
        ));
    }
    #[cfg(target_os = "linux")]
    {
        let interface = resolve_egress_interface(config.egress_interface)?;
        let rules = render_nft_rules(&interface, config.ipv4_pool, config.ipv6_pool);
        let pending = JournalEntry::NatPending { table: LINUX_TABLE.into() };
        prepare_nat(journal, pending.clone(), journal_path)?;
        apply_linux_rules(&rules)?;
        promote_nat(
            journal,
            pending,
            JournalEntry::Nat { table: LINUX_TABLE.into() },
            journal_path,
        )?;
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        let interface = resolve_egress_interface(config.egress_interface)?;
        let rules = render_pf_rules(&interface, config.ipv4_pool, config.ipv6_pool);
        let pending = JournalEntry::NatPending { table: MACOS_ANCHOR.into() };
        prepare_nat(journal, pending.clone(), journal_path)?;
        apply_pf_rules(&rules)?;
        promote_nat(
            journal,
            pending,
            JournalEntry::Nat { table: MACOS_ANCHOR.into() },
            journal_path,
        )?;
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = config;
        Err(PlatformError::Network("managed NAT is unavailable on this platform".into()))
    }
}

fn prepare_nat(
    journal: &mut NetworkJournal,
    entry: JournalEntry,
    journal_path: Option<&Path>,
) -> Result<(), PlatformError> {
    if let Some(path) = journal_path {
        journal.prepare(entry, path)
    } else {
        let _ = entry;
        Ok(())
    }
}

fn promote_nat(
    journal: &mut NetworkJournal,
    pending: JournalEntry,
    active: JournalEntry,
    journal_path: Option<&Path>,
) -> Result<(), PlatformError> {
    if let Some(path) = journal_path {
        journal.promote_last(pending, active, path)
    } else {
        journal.record(active);
        Ok(())
    }
}

pub async fn cleanup_managed_nat(table: &str) -> Result<(), PlatformError> {
    #[cfg(target_os = "linux")]
    {
        if table != LINUX_TABLE {
            return Err(PlatformError::UnsupportedCleanup(format!("nat table {table}")));
        }
        cleanup_linux_rules()
    }
    #[cfg(target_os = "macos")]
    {
        if table != MACOS_ANCHOR {
            return Err(PlatformError::UnsupportedCleanup(format!("nat anchor {table}")));
        }
        cleanup_pf_rules()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    Err(PlatformError::UnsupportedCleanup(format!("nat table {table}")))
}

fn validate_config(config: &ManagedNatConfig<'_>) -> Result<(), PlatformError> {
    if config.ipv4_pool.is_none() && config.ipv6_pool.is_none() {
        return Err(PlatformError::InvalidService(
            "managed NAT requires at least one client address pool".into(),
        ));
    }
    if config.egress_interface != "auto"
        && !config
            .egress_interface
            .chars()
            .all(|value| value.is_ascii_alphanumeric() || matches!(value, '.' | '_' | '-' | ':'))
    {
        return Err(PlatformError::InvalidService(
            "egress interface contains unsupported characters".into(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn resolve_egress_interface(value: &str) -> Result<String, PlatformError> {
    if value != "auto" {
        return Ok(value.to_owned());
    }
    if let Ok(contents) = std::fs::read_to_string("/proc/net/route") {
        for line in contents.lines().skip(1) {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.len() >= 4 && fields[1] == "00000000" && fields[3].contains('1') {
                return Ok(fields[0].to_owned());
            }
        }
    }
    let output = Command::new("ip")
        .args(["-o", "route", "show", "default"])
        .output()
        .map_err(|error| PlatformError::Network(format!("resolve default route: {error}")))?;
    if !output.status.success() {
        return Err(PlatformError::Network("no default egress interface was found".into()));
    }
    parse_interface_from_ip_output(&output.stdout)
}

#[cfg(target_os = "macos")]
fn resolve_egress_interface(value: &str) -> Result<String, PlatformError> {
    if value != "auto" {
        return Ok(value.to_owned());
    }
    let output = Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .map_err(|error| PlatformError::Network(format!("resolve default route: {error}")))?;
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines()
        .find_map(|line| line.trim().strip_prefix("interface:").map(str::trim))
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| PlatformError::Network("no default egress interface was found".into()))
}

#[cfg(target_os = "linux")]
fn parse_interface_from_ip_output(output: &[u8]) -> Result<String, PlatformError> {
    let binding = String::from_utf8_lossy(output);
    let fields = binding.split_whitespace().collect::<Vec<_>>();
    fields
        .windows(2)
        .find(|pair| pair[0] == "dev")
        .map(|pair| pair[1].to_owned())
        .filter(|value| {
            value.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-' | ':')
            })
        })
        .ok_or_else(|| PlatformError::Network("default route has no valid egress interface".into()))
}

#[cfg(target_os = "linux")]
fn render_nft_rules(interface: &str, ipv4: Option<IpNet>, ipv6: Option<IpNet>) -> String {
    let mut rules = format!(
        "table inet maskman {{\n  comment \"{OWNERSHIP_MARKER}\"\n  chain postrouting {{\n    type nat hook postrouting priority srcnat; policy accept;\n"
    );
    if let Some(IpNet::V4(network)) = ipv4 {
        rules.push_str(&format!("    ip saddr {network} oifname \"{interface}\" masquerade\n"));
    }
    if let Some(IpNet::V6(network)) = ipv6 {
        rules.push_str(&format!("    ip6 saddr {network} oifname \"{interface}\" masquerade\n"));
    }
    rules.push_str("  }\n}\n");
    rules
}

#[cfg(target_os = "linux")]
fn apply_linux_rules(rules: &str) -> Result<(), PlatformError> {
    let existing = Command::new("nft").args(["list", "table", "inet", "maskman"]).output();
    if let Ok(output) = existing {
        if output.status.success()
            && !String::from_utf8_lossy(&output.stdout).contains(OWNERSHIP_MARKER)
        {
            return Err(PlatformError::Network(
                "nft table inet maskman exists but is not owned by Maskman".into(),
            ));
        }
        if output.status.success() {
            run_command("nft", &["delete", "table", "inet", "maskman"], None)?;
        }
    }
    run_command("nft", &["-f", "-"], Some(rules.as_bytes()))
}

#[cfg(target_os = "linux")]
fn cleanup_linux_rules() -> Result<(), PlatformError> {
    let output = Command::new("nft")
        .args(["list", "table", "inet", "maskman"])
        .output()
        .map_err(|error| PlatformError::Network(format!("inspect nft table: {error}")))?;
    if !output.status.success() {
        return Ok(());
    }
    if !String::from_utf8_lossy(&output.stdout).contains(OWNERSHIP_MARKER) {
        return Err(PlatformError::UnsupportedCleanup(
            "nft table inet maskman is not owned by Maskman".into(),
        ));
    }
    run_command("nft", &["delete", "table", "inet", "maskman"], None)
}

#[cfg(target_os = "macos")]
fn render_pf_rules(interface: &str, ipv4: Option<IpNet>, ipv6: Option<IpNet>) -> String {
    let mut rules = format!("# {OWNERSHIP_MARKER}\n");
    if let Some(IpNet::V4(network)) = ipv4 {
        rules
            .push_str(&format!("nat on {interface} inet from {network} to any -> ({interface})\n"));
    }
    if let Some(IpNet::V6(network)) = ipv6 {
        rules.push_str(&format!(
            "nat on {interface} inet6 from {network} to any -> ({interface})\n"
        ));
    }
    rules
}

#[cfg(target_os = "macos")]
fn apply_pf_rules(rules: &str) -> Result<(), PlatformError> {
    match inspect_pf_anchor()? {
        PfAnchorState::Missing | PfAnchorState::Owned => {}
        PfAnchorState::Foreign => {
            return Err(PlatformError::Network(
                "pf anchor com.backrunner.maskman exists but is not owned by Maskman".into(),
            ))
        }
    }
    run_command("pfctl", &["-a", MACOS_ANCHOR, "-f", "-"], Some(rules.as_bytes()))
}

#[cfg(target_os = "macos")]
fn cleanup_pf_rules() -> Result<(), PlatformError> {
    match inspect_pf_anchor()? {
        PfAnchorState::Missing => return Ok(()),
        PfAnchorState::Foreign => {
            return Err(PlatformError::UnsupportedCleanup(
                "pf anchor com.backrunner.maskman is not owned by Maskman".into(),
            ))
        }
        PfAnchorState::Owned => {}
    }
    run_command("pfctl", &["-a", MACOS_ANCHOR, "-F", "all"], None)
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PfAnchorState {
    Missing,
    Owned,
    Foreign,
}

#[cfg(target_os = "macos")]
fn inspect_pf_anchor() -> Result<PfAnchorState, PlatformError> {
    let output = Command::new("pfctl")
        .args(["-a", MACOS_ANCHOR, "-sr"])
        .output()
        .map_err(|error| PlatformError::Network(format!("inspect pf anchor: {error}")))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if output.status.success() {
        if stdout.contains(OWNERSHIP_MARKER) || stderr.contains(OWNERSHIP_MARKER) {
            Ok(PfAnchorState::Owned)
        } else {
            Ok(PfAnchorState::Foreign)
        }
    } else if stderr.to_ascii_lowercase().contains("anchor")
        && (stderr.to_ascii_lowercase().contains("does not exist")
            || stderr.to_ascii_lowercase().contains("no such file"))
    {
        Ok(PfAnchorState::Missing)
    } else {
        Err(PlatformError::Network(format!(
            "inspect pf anchor failed: {}",
            truncate(stderr.trim())
        )))
    }
}

fn run_command(program: &str, args: &[&str], input: Option<&[u8]>) -> Result<(), PlatformError> {
    let mut command = Command::new(program);
    command.args(args).stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() });
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| PlatformError::Network(format!("{program}: {error}")))?;
    if let Some(input) = input {
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(input)
                .map_err(|error| PlatformError::Network(format!("{program} input: {error}")))?;
        }
    }
    let output = child
        .wait_with_output()
        .map_err(|error| PlatformError::Network(format!("{program}: {error}")))?;
    if output.status.success() {
        Ok(())
    } else {
        let detail = String::from_utf8_lossy(&output.stderr);
        Err(PlatformError::Network(format!("{program} failed: {}", truncate(detail.as_ref()))))
    }
}

fn truncate(value: &str) -> &str {
    value.get(..value.len().min(512)).unwrap_or("network command failed")
}

#[cfg(test)]
mod tests {
    use super::{validate_config, ManagedNatConfig};
    use ipnet::IpNet;

    #[cfg(target_os = "linux")]
    #[test]
    fn nft_rules_are_scoped_and_marked_owned() {
        use super::{render_nft_rules, OWNERSHIP_MARKER};
        let rules = render_nft_rules(
            "eth0",
            Some("100.64.0.0/10".parse().unwrap_or_else(|error| panic!("net: {error}"))),
            Some("fd42::/64".parse().unwrap_or_else(|error| panic!("net: {error}"))),
        );
        assert!(rules.contains(OWNERSHIP_MARKER));
        assert!(rules.contains("oifname \"eth0\" masquerade"));
        assert!(!rules.contains("0.0.0.0/0"));
    }

    #[test]
    fn managed_nat_requires_a_pool_and_rejects_shell_syntax() {
        let empty = ManagedNatConfig { egress_interface: "eth0", ipv4_pool: None, ipv6_pool: None };
        assert!(validate_config(&empty).is_err());
        let unsafe_interface = ManagedNatConfig {
            egress_interface: "eth0; rm -rf /",
            ipv4_pool: Some(
                "100.64.0.0/10".parse::<IpNet>().unwrap_or_else(|error| panic!("net: {error}")),
            ),
            ipv6_pool: None,
        };
        assert!(validate_config(&unsafe_interface).is_err());
    }
}
