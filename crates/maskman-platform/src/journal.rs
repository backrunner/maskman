use std::{fs, io::Write, path::Path};

use serde::{Deserialize, Serialize};

use crate::PlatformError;

#[cfg(target_os = "linux")]
use ipnet::IpNet;

const JOURNAL_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum JournalEntry {
    Tun { name: String },
    Route { destination: String, interface_index: u32 },
    Nat { table: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkJournal {
    #[serde(default = "journal_version")]
    version: u32,
    #[serde(default)]
    entries: Vec<JournalEntry>,
}

impl NetworkJournal {
    pub fn load(path: &Path) -> Result<Self, PlatformError> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let bytes = fs::read(path).map_err(PlatformError::Journal)?;
        let journal: Self = serde_json::from_slice(&bytes).map_err(|error| {
            PlatformError::Journal(std::io::Error::new(std::io::ErrorKind::InvalidData, error))
        })?;
        if journal.version != JOURNAL_VERSION {
            return Err(PlatformError::InvalidService(format!(
                "unsupported resource journal version {}",
                journal.version
            )));
        }
        Ok(journal)
    }

    pub fn persist(&self, path: &Path) -> Result<(), PlatformError> {
        let parent = path.parent().ok_or_else(|| {
            PlatformError::Journal(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "journal path has no parent",
            ))
        })?;
        fs::create_dir_all(parent).map_err(PlatformError::Journal)?;
        let file_name = path.file_name().and_then(|name| name.to_str()).ok_or_else(|| {
            PlatformError::Journal(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "journal path has no valid file name",
            ))
        })?;
        let temporary = parent.join(format!(".{file_name}.tmp-{}", std::process::id()));
        let mut file = fs::File::create(&temporary).map_err(PlatformError::Journal)?;
        let encoded = serde_json::to_vec_pretty(self).map_err(|error| {
            PlatformError::Journal(std::io::Error::new(std::io::ErrorKind::InvalidData, error))
        })?;
        file.write_all(&encoded).map_err(PlatformError::Journal)?;
        file.sync_all().map_err(PlatformError::Journal)?;
        fs::rename(&temporary, path).map_err(PlatformError::Journal)?;
        set_private_permissions(path)
    }

    pub fn remove(path: &Path) -> Result<(), PlatformError> {
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(PlatformError::Journal(error)),
        }
    }

    pub fn record(&mut self, entry: JournalEntry) {
        self.entries.push(entry);
    }

    pub fn entries(&self) -> &[JournalEntry] {
        &self.entries
    }

    pub fn drain_reverse(&mut self) -> impl DoubleEndedIterator<Item = JournalEntry> + '_ {
        self.entries.drain(..).rev()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for NetworkJournal {
    fn default() -> Self {
        Self { version: JOURNAL_VERSION, entries: Vec::new() }
    }
}

fn journal_version() -> u32 {
    JOURNAL_VERSION
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CleanupReport {
    pub inspected: usize,
    pub removed: usize,
}

pub async fn cleanup(path: &Path, dry_run: bool) -> Result<CleanupReport, PlatformError> {
    let mut journal = NetworkJournal::load(path)?;
    let report = CleanupReport { inspected: journal.entries.len(), removed: 0 };
    if dry_run {
        return Ok(report);
    }
    let mut removed = 0;
    for entry in journal.drain_reverse() {
        match entry {
            JournalEntry::Tun { name } => cleanup_tun(&name)?,
            JournalEntry::Route { destination, interface_index } => {
                #[cfg(target_os = "linux")]
                {
                    let route = destination.parse::<IpNet>().map_err(|error| {
                        PlatformError::InvalidService(format!(
                            "journal route {destination}: {error}"
                        ))
                    })?;
                    let manager = crate::LinuxRouteManager::connect()?;
                    manager.remove_route(route, interface_index).await?;
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let _ = (destination, interface_index);
                    return Err(PlatformError::UnsupportedCleanup("route".into()));
                }
            }
            JournalEntry::Nat { table } => {
                return Err(PlatformError::UnsupportedCleanup(format!("nat table {table}")));
            }
        }
        removed += 1;
    }
    NetworkJournal::remove(path)?;
    Ok(CleanupReport { inspected: report.inspected, removed })
}

fn cleanup_tun(name: &str) -> Result<(), PlatformError> {
    let interface = tappers::Interface::new(name).map_err(PlatformError::TunIo)?;
    if !interface.exists().map_err(PlatformError::TunIo)? {
        return Ok(());
    }
    let device = tappers::Tun::new_named(interface).map_err(PlatformError::TunIo)?;
    drop(device);
    Ok(())
}

#[cfg(unix)]
fn set_private_permissions(path: &Path) -> Result<(), PlatformError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(PlatformError::Journal)
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &Path) -> Result<(), PlatformError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{JournalEntry, NetworkJournal};

    #[test]
    fn journal_drains_owned_resources_in_reverse_order() {
        let mut journal = NetworkJournal::default();
        journal.record(JournalEntry::Tun { name: "maskman0".into() });
        journal.record(JournalEntry::Route { destination: "0.0.0.0/0".into(), interface_index: 7 });
        let entries = journal.drain_reverse().collect::<Vec<_>>();
        assert!(matches!(entries[0], JournalEntry::Route { .. }));
        assert!(matches!(entries[1], JournalEntry::Tun { .. }));
        assert!(journal.is_empty());
    }

    #[test]
    fn journal_round_trips_with_private_file_permissions() {
        let path = std::env::temp_dir().join(format!("maskman-journal-{}", std::process::id()));
        let mut journal = NetworkJournal::default();
        journal.record(JournalEntry::Tun { name: "maskman0".into() });
        journal.persist(&path).unwrap_or_else(|error| panic!("persist journal: {error}"));
        let loaded =
            NetworkJournal::load(&path).unwrap_or_else(|error| panic!("load journal: {error}"));
        assert_eq!(loaded.entries(), journal.entries());
        NetworkJournal::remove(&path).unwrap_or_else(|error| panic!("remove journal: {error}"));
        assert!(!PathBuf::from(&path).exists());
    }
}
