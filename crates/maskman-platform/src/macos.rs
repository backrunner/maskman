#![cfg(target_os = "macos")]

use std::{
    path::Path,
    process::{Command, Stdio},
};

use ipnet::IpNet;

use crate::{JournalEntry, NetworkJournal, PlatformError};

pub struct MacRouteManager;

impl MacRouteManager {
    pub fn connect() -> Result<Self, PlatformError> {
        Ok(Self)
    }

    pub fn add_route(
        &self,
        route: IpNet,
        interface: &str,
        journal: &mut NetworkJournal,
    ) -> Result<(), PlatformError> {
        self.add_route_inner(route, interface, journal, None)
    }

    pub fn add_route_persisted(
        &self,
        route: IpNet,
        interface: &str,
        journal: &mut NetworkJournal,
        journal_path: &Path,
    ) -> Result<(), PlatformError> {
        self.add_route_inner(route, interface, journal, Some(journal_path))
    }

    fn add_route_inner(
        &self,
        route: IpNet,
        interface: &str,
        journal: &mut NetworkJournal,
        journal_path: Option<&Path>,
    ) -> Result<(), PlatformError> {
        validate_interface(interface)?;
        let pending = JournalEntry::RouteNamedPending {
            destination: route.to_string(),
            interface_name: interface.to_owned(),
        };
        if let Some(path) = journal_path {
            journal.prepare(pending.clone(), path)?;
        }
        let args = route_add_args(route, interface);
        run_route(&args)?;
        let active = JournalEntry::RouteNamed {
            destination: route.to_string(),
            interface_name: interface.to_owned(),
        };
        if let Some(path) = journal_path {
            journal.promote_last(pending, active, path)?;
        } else {
            journal.record(active);
        }
        Ok(())
    }

    pub async fn remove_route(route: IpNet) -> Result<(), PlatformError> {
        Self::remove_route_owned(route, None).await
    }

    pub async fn remove_route_owned(
        route: IpNet,
        expected_interface: Option<&str>,
    ) -> Result<(), PlatformError> {
        let destination = route.network().to_string();
        let inspect = Command::new("route")
            .args(["-n", "get", &destination])
            .output()
            .map_err(|error| PlatformError::Network(format!("inspect route: {error}")))?;
        if !inspect.status.success() {
            let detail = String::from_utf8_lossy(&inspect.stderr).to_ascii_lowercase();
            if detail.contains("not in table") || detail.contains("not found") {
                return Ok(());
            }
            return Err(PlatformError::Network(format!(
                "inspect route failed: {}",
                detail.trim().chars().take(512).collect::<String>()
            )));
        }
        let interface = String::from_utf8_lossy(&inspect.stdout)
            .lines()
            .find_map(|line| line.trim().strip_prefix("interface:").map(str::trim))
            .unwrap_or_default()
            .to_owned();
        if expected_interface.is_some_and(|expected| expected != interface)
            || !interface.starts_with("utun")
        {
            return Err(PlatformError::UnsupportedCleanup(format!(
                "route {route} is not owned by a utun interface"
            )));
        }
        let args = route_delete_args(route);
        match run_route(&args) {
            Ok(()) => Ok(()),
            Err(PlatformError::Network(message)) if message.contains("not in table") => Ok(()),
            Err(error) => Err(error),
        }
    }
}

fn route_add_args(route: IpNet, interface: &str) -> Vec<String> {
    match route {
        IpNet::V4(network) => vec![
            "-n".into(),
            "add".into(),
            "-net".into(),
            network.network().to_string(),
            "-netmask".into(),
            network.netmask().to_string(),
            "-interface".into(),
            interface.into(),
        ],
        IpNet::V6(network) => vec![
            "-n".into(),
            "add".into(),
            "-inet6".into(),
            network.network().to_string(),
            "-prefixlen".into(),
            network.prefix_len().to_string(),
            "-interface".into(),
            interface.into(),
        ],
    }
}

fn route_delete_args(route: IpNet) -> Vec<String> {
    match route {
        IpNet::V4(network) => vec![
            "-n".into(),
            "delete".into(),
            "-net".into(),
            network.network().to_string(),
            "-netmask".into(),
            network.netmask().to_string(),
        ],
        IpNet::V6(network) => vec![
            "-n".into(),
            "delete".into(),
            "-inet6".into(),
            network.network().to_string(),
            "-prefixlen".into(),
            network.prefix_len().to_string(),
        ],
    }
}

fn validate_interface(interface: &str) -> Result<(), PlatformError> {
    if interface.is_empty()
        || !interface
            .chars()
            .all(|value| value.is_ascii_alphanumeric() || matches!(value, '.' | '_' | '-' | ':'))
    {
        return Err(PlatformError::InvalidService("invalid macOS interface name".into()));
    }
    Ok(())
}

fn run_route(args: &[String]) -> Result<(), PlatformError> {
    let output = Command::new("route")
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| PlatformError::Network(format!("route: {error}")))?;
    if output.status.success() {
        Ok(())
    } else {
        let detail = String::from_utf8_lossy(&output.stderr);
        Err(PlatformError::Network(format!(
            "route command failed: {}",
            detail.trim().chars().take(512).collect::<String>()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::{route_add_args, route_delete_args, validate_interface};

    #[test]
    fn route_arguments_are_structured_for_both_families() {
        let v4 = route_add_args(
            "100.64.0.0/10".parse().unwrap_or_else(|error| panic!("net: {error}")),
            "utun9",
        );
        assert!(v4.windows(2).any(|pair| pair == ["-interface", "utun9"]));
        let v6 =
            route_delete_args("fd42::/64".parse().unwrap_or_else(|error| panic!("net: {error}")));
        assert!(v6.contains(&"-inet6".to_owned()));
    }

    #[test]
    fn interface_validation_rejects_command_injection() {
        assert!(validate_interface("utun9;touch /tmp/x").is_err());
        assert!(validate_interface("utun9").is_ok());
    }
}
