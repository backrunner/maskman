#[cfg(target_os = "linux")]
use std::fs;
use std::path::Path;
#[cfg(target_os = "macos")]
use std::process::{Command, Stdio};

use crate::{JournalEntry, NetworkJournal, PlatformError};

#[cfg(target_os = "linux")]
const LINUX_FORWARDING: &[&str] =
    &["/proc/sys/net/ipv4/ip_forward", "/proc/sys/net/ipv6/conf/all/forwarding"];
#[cfg(target_os = "macos")]
const MACOS_FORWARDING: &[&str] = &["net.inet.ip.forwarding", "net.inet6.ip6.forwarding"];

pub fn enable_forwarding(journal: &mut NetworkJournal) -> Result<(), PlatformError> {
    enable_forwarding_inner(journal, None)
}

pub fn enable_forwarding_persisted(
    journal: &mut NetworkJournal,
    journal_path: &Path,
) -> Result<(), PlatformError> {
    enable_forwarding_inner(journal, Some(journal_path))
}

fn enable_forwarding_inner(
    journal: &mut NetworkJournal,
    journal_path: Option<&Path>,
) -> Result<(), PlatformError> {
    #[cfg(target_os = "linux")]
    {
        for path in LINUX_FORWARDING {
            let previous = fs::read_to_string(path).map_err(|error| {
                PlatformError::Network(format!("read forwarding sysctl {path}: {error}"))
            })?;
            let previous = parse_forwarding_value(path, &previous)?;
            if previous != "1" {
                let pending =
                    JournalEntry::SysctlPending { key: (*path).into(), previous: previous.clone() };
                prepare_entry(journal, pending.clone(), journal_path)?;
                fs::write(path, b"1\n").map_err(|error| {
                    PlatformError::Network(format!("enable forwarding {path}: {error}"))
                })?;
                let active = JournalEntry::Sysctl { key: (*path).into(), previous };
                promote_entry(journal, pending, active, journal_path)?;
            }
        }
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        for key in MACOS_FORWARDING {
            let previous = read_macos_sysctl(key)?;
            if previous != "1" {
                let pending =
                    JournalEntry::SysctlPending { key: (*key).into(), previous: previous.clone() };
                prepare_entry(journal, pending.clone(), journal_path)?;
                write_macos_sysctl(key, "1")?;
                let active = JournalEntry::Sysctl { key: (*key).into(), previous };
                promote_entry(journal, pending, active, journal_path)?;
            }
        }
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = journal;
        Err(PlatformError::Network("IP forwarding is unavailable on this platform".into()))
    }
}

fn prepare_entry(
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

fn promote_entry(
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

pub fn restore_forwarding(entry: &JournalEntry) -> Result<(), PlatformError> {
    let JournalEntry::Sysctl { key, previous } = entry else {
        return Err(PlatformError::UnsupportedCleanup("not a sysctl journal entry".into()));
    };
    #[cfg(target_os = "linux")]
    {
        if !LINUX_FORWARDING.contains(&key.as_str()) {
            return Err(PlatformError::UnsupportedCleanup(format!("sysctl {key}")));
        }
        fs::write(Path::new(key), format!("{previous}\n")).map_err(|error| {
            PlatformError::Network(format!("restore forwarding {key}: {error}"))
        })?;
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        #[cfg(target_os = "macos")]
        {
            if !MACOS_FORWARDING.contains(&key.as_str()) {
                return Err(PlatformError::UnsupportedCleanup(format!("sysctl {key}")));
            }
            write_macos_sysctl(key, previous)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (key, previous);
            Err(PlatformError::UnsupportedCleanup("sysctl forwarding".into()))
        }
    }
}

fn parse_forwarding_value(key: &str, output: &str) -> Result<String, PlatformError> {
    let value = output.trim();
    if matches!(value, "0" | "1") {
        Ok(value.to_owned())
    } else {
        Err(PlatformError::Network(format!("forwarding sysctl {key} returned an invalid value")))
    }
}

#[cfg(target_os = "macos")]
fn read_macos_sysctl(key: &str) -> Result<String, PlatformError> {
    let output = Command::new("sysctl").args(["-n", key]).stdin(Stdio::null()).output().map_err(
        |error| PlatformError::Network(format!("read forwarding sysctl {key}: {error}")),
    )?;
    if !output.status.success() {
        return Err(command_error("read", key, &output.stderr));
    }
    let value = String::from_utf8(output.stdout)
        .map_err(|_| PlatformError::Network(format!("forwarding sysctl {key} was not UTF-8")))?;
    parse_forwarding_value(key, &value)
}

#[cfg(target_os = "macos")]
fn write_macos_sysctl(key: &str, value: &str) -> Result<(), PlatformError> {
    if !MACOS_FORWARDING.contains(&key) || !matches!(value, "0" | "1") {
        return Err(PlatformError::UnsupportedCleanup(format!("sysctl {key}")));
    }
    let assignment = format!("{key}={value}");
    let output = Command::new("sysctl")
        .args(["-w", assignment.as_str()])
        .stdin(Stdio::null())
        .output()
        .map_err(|error| {
            PlatformError::Network(format!("write forwarding sysctl {key}: {error}"))
        })?;
    if output.status.success() {
        Ok(())
    } else {
        Err(command_error("write", key, &output.stderr))
    }
}

#[cfg(target_os = "macos")]
fn command_error(operation: &str, key: &str, stderr: &[u8]) -> PlatformError {
    let detail = String::from_utf8_lossy(stderr);
    let detail = detail.trim().chars().take(512).collect::<String>();
    PlatformError::Network(format!("{operation} forwarding sysctl {key}: {detail}"))
}

#[cfg(test)]
mod tests {
    use super::{parse_forwarding_value, restore_forwarding};
    use crate::{JournalEntry, PlatformError};

    #[test]
    fn restore_rejects_foreign_sysctl_keys() {
        let result = restore_forwarding(&JournalEntry::Sysctl {
            key: "/proc/sys/kernel/randomize_va_space".into(),
            previous: "2".into(),
        });
        assert!(matches!(result, Err(PlatformError::UnsupportedCleanup(_))));
    }

    #[test]
    fn forwarding_values_are_strictly_boolean() {
        let enabled = parse_forwarding_value("test", " 1\n")
            .unwrap_or_else(|error| panic!("parse forwarding value: {error}"));
        assert_eq!(enabled, "1");
        assert!(parse_forwarding_value("test", "2").is_err());
        assert!(parse_forwarding_value("test", "1 extra").is_err());
    }
}
