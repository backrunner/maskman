use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use serde::{Deserialize, Serialize};

use crate::PlatformError;

use ipnet::IpNet;

const JOURNAL_VERSION: u32 = 1;
const TEMP_FILE_ATTEMPTS: u64 = 32;
static NEXT_TEMP_FILE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum JournalEntry {
    TunPending { name: String },
    Tun { name: String },
    RoutePending { destination: String, interface_index: u32 },
    Route { destination: String, interface_index: u32 },
    RouteNamedPending { destination: String, interface_name: String },
    RouteNamed { destination: String, interface_name: String },
    NatPending { table: String },
    Nat { table: String },
    SysctlPending { key: String, previous: String },
    Sysctl { key: String, previous: String },
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
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default())
            }
            Err(error) => return Err(PlatformError::Journal(error)),
        };
        if metadata.file_type().is_symlink() {
            return Err(PlatformError::InvalidService(
                "resource journal must not be a symlink".into(),
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(PlatformError::InvalidService(
                    "resource journal permissions must be 0600".into(),
                ));
            }
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
        if journal.entries.len() > 1024 {
            return Err(PlatformError::InvalidService(
                "resource journal contains too many entries".into(),
            ));
        }
        journal.validate_entries()?;
        Ok(journal)
    }

    fn validate_entries(&self) -> Result<(), PlatformError> {
        for entry in &self.entries {
            match entry {
                JournalEntry::TunPending { name } => {
                    let valid = if cfg!(target_os = "linux") {
                        name.starts_with("maskman")
                    } else if cfg!(target_os = "macos") {
                        name.is_empty() || name.starts_with("utun")
                    } else {
                        false
                    };
                    if !valid || name.len() > 15 {
                        return Err(PlatformError::InvalidService(format!(
                            "journal contains an unowned TUN name {name}"
                        )));
                    }
                }
                JournalEntry::Tun { name } => {
                    let valid = if cfg!(target_os = "linux") {
                        name.starts_with("maskman")
                    } else if cfg!(target_os = "macos") {
                        name.starts_with("utun")
                    } else {
                        false
                    };
                    if !valid || name.len() > 15 {
                        return Err(PlatformError::InvalidService(format!(
                            "journal contains an unowned TUN name {name}"
                        )));
                    }
                }
                JournalEntry::RoutePending { destination, interface_index }
                | JournalEntry::Route { destination, interface_index } => {
                    if !cfg!(target_os = "linux") {
                        return Err(PlatformError::InvalidService(
                            "numeric-interface routes are only valid on Linux".into(),
                        ));
                    }
                    destination.parse::<IpNet>().map_err(|error| {
                        PlatformError::InvalidService(format!(
                            "journal route {destination}: {error}"
                        ))
                    })?;
                    if cfg!(target_os = "linux") && *interface_index == 0 {
                        return Err(PlatformError::InvalidService(
                            "journal Linux route has no interface index".into(),
                        ));
                    }
                }
                JournalEntry::RouteNamedPending { destination, interface_name }
                | JournalEntry::RouteNamed { destination, interface_name } => {
                    destination.parse::<IpNet>().map_err(|error| {
                        PlatformError::InvalidService(format!(
                            "journal route {destination}: {error}"
                        ))
                    })?;
                    if !cfg!(target_os = "macos")
                        || interface_name.is_empty()
                        || !interface_name.starts_with("utun")
                        || interface_name.len() > 15
                    {
                        return Err(PlatformError::InvalidService(
                            "journal contains an invalid named route".into(),
                        ));
                    }
                }
                JournalEntry::NatPending { table } | JournalEntry::Nat { table } => {
                    if table != crate::managed_nat_resource_id() {
                        return Err(PlatformError::InvalidService(format!(
                            "journal contains an unowned NAT resource {table}"
                        )));
                    }
                }
                JournalEntry::SysctlPending { key, previous }
                | JournalEntry::Sysctl { key, previous } => {
                    let allowed = match key.as_str() {
                        #[cfg(target_os = "linux")]
                        "/proc/sys/net/ipv4/ip_forward"
                        | "/proc/sys/net/ipv6/conf/all/forwarding" => true,
                        #[cfg(target_os = "macos")]
                        "net.inet.ip.forwarding" | "net.inet6.ip6.forwarding" => true,
                        _ => false,
                    };
                    if !allowed || !matches!(previous.as_str(), "0" | "1") {
                        return Err(PlatformError::InvalidService(format!(
                            "journal contains an unowned sysctl {key}"
                        )));
                    }
                }
            }
        }
        Ok(())
    }

    pub fn persist(&self, path: &Path) -> Result<(), PlatformError> {
        reject_existing_symlink(path)?;
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
        let encoded = serde_json::to_vec_pretty(self).map_err(|error| {
            PlatformError::Journal(std::io::Error::new(std::io::ErrorKind::InvalidData, error))
        })?;
        let (temporary, mut file) = create_temporary(parent, file_name)?;
        let result = (|| {
            set_private_permissions(&temporary)?;
            file.write_all(&encoded).map_err(PlatformError::Journal)?;
            file.sync_all().map_err(PlatformError::Journal)?;
            drop(file);
            reject_existing_symlink(path)?;
            fs::rename(&temporary, path).map_err(PlatformError::Journal)?;
            set_private_permissions(path)?;
            sync_directory(parent)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
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

    /// Persist ownership before a platform mutation. If persistence fails the
    /// in-memory entry is removed and the caller must not perform the
    /// mutation. A pending entry is intentionally non-destructive during
    /// cleanup because the mutation result may be unknown after a crash.
    pub fn prepare(&mut self, entry: JournalEntry, path: &Path) -> Result<(), PlatformError> {
        self.entries.push(entry);
        if let Err(error) = self.persist(path) {
            self.entries.pop();
            return Err(error);
        }
        Ok(())
    }

    pub fn replace_last_tun_pending(
        &mut self,
        name: String,
        path: &Path,
    ) -> Result<(), PlatformError> {
        let Some(pending) = self.entries.last().cloned() else {
            return Err(PlatformError::InvalidService("TUN journal has no pending entry".into()));
        };
        if !matches!(pending, JournalEntry::TunPending { .. }) {
            return Err(PlatformError::InvalidService("TUN journal entry order is invalid".into()));
        }
        self.promote_last(pending, JournalEntry::Tun { name }, path)
    }

    pub fn promote_last(
        &mut self,
        pending: JournalEntry,
        active: JournalEntry,
        path: &Path,
    ) -> Result<(), PlatformError> {
        if self.entries.last() != Some(&pending) {
            return Err(PlatformError::InvalidService(
                "resource journal pending entry order is invalid".into(),
            ));
        }
        *self.entries.last_mut().ok_or_else(|| {
            PlatformError::InvalidService("resource journal has no pending entry".into())
        })? = active;
        if let Err(error) = self.persist(path) {
            *self.entries.last_mut().ok_or_else(|| {
                PlatformError::InvalidService("resource journal has no pending entry".into())
            })? = pending;
            return Err(error);
        }
        Ok(())
    }

    pub(crate) fn replace_last_tun_pending_without_persist(
        &mut self,
        name: String,
    ) -> Result<(), PlatformError> {
        let Some(entry) = self.entries.last_mut() else {
            return Err(PlatformError::InvalidService("TUN journal has no pending entry".into()));
        };
        if !matches!(entry, JournalEntry::TunPending { .. }) {
            return Err(PlatformError::InvalidService("TUN journal entry order is invalid".into()));
        }
        *entry = JournalEntry::Tun { name };
        Ok(())
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

fn reject_existing_symlink(path: &Path) -> Result<(), PlatformError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(PlatformError::InvalidService("resource journal must not be a symlink".into()))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(PlatformError::Journal(error)),
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

fn create_temporary(parent: &Path, file_name: &str) -> Result<(PathBuf, fs::File), PlatformError> {
    for _ in 0..TEMP_FILE_ATTEMPTS {
        let sequence = NEXT_TEMP_FILE.fetch_add(1, Ordering::Relaxed);
        let path = parent.join(format!(".{file_name}.tmp-{}-{sequence}", std::process::id()));
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(PlatformError::Journal(error)),
        }
    }
    Err(PlatformError::Journal(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not reserve a unique journal temporary file",
    )))
}

fn sync_directory(path: &Path) -> Result<(), PlatformError> {
    fs::File::open(path).and_then(|directory| directory.sync_all()).map_err(PlatformError::Journal)
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
            JournalEntry::TunPending { .. }
            | JournalEntry::RoutePending { .. }
            | JournalEntry::RouteNamedPending { .. }
            | JournalEntry::NatPending { .. }
            | JournalEntry::SysctlPending { .. } => {}
            JournalEntry::Tun { name } => cleanup_tun(&name).await?,
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
                #[cfg(target_os = "macos")]
                {
                    let _ = interface_index;
                    let route = destination.parse::<IpNet>().map_err(|error| {
                        PlatformError::InvalidService(format!(
                            "journal route {destination}: {error}"
                        ))
                    })?;
                    crate::MacRouteManager::remove_route_owned(route, None).await?;
                }
                #[cfg(not(any(target_os = "linux", target_os = "macos")))]
                {
                    let _ = (destination, interface_index);
                    return Err(PlatformError::UnsupportedCleanup("route".into()));
                }
            }
            JournalEntry::RouteNamed { destination, interface_name } => {
                #[cfg(target_os = "macos")]
                {
                    let route = destination.parse::<IpNet>().map_err(|error| {
                        PlatformError::InvalidService(format!(
                            "journal route {destination}: {error}"
                        ))
                    })?;
                    crate::MacRouteManager::remove_route_owned(route, Some(&interface_name))
                        .await?;
                }
                #[cfg(not(target_os = "macos"))]
                {
                    let _ = (destination, interface_name);
                    return Err(PlatformError::UnsupportedCleanup("named route".into()));
                }
            }
            JournalEntry::Nat { table } => {
                crate::cleanup_managed_nat(&table).await?;
            }
            JournalEntry::Sysctl { key, previous } => {
                crate::restore_forwarding(&JournalEntry::Sysctl { key, previous })?;
            }
        }
        removed += 1;
    }
    NetworkJournal::remove(path)?;
    Ok(CleanupReport { inspected: report.inspected, removed })
}

async fn cleanup_tun(name: &str) -> Result<(), PlatformError> {
    #[cfg(target_os = "linux")]
    {
        crate::LinuxRouteManager::remove_tun(name).await
    }

    #[cfg(target_os = "macos")]
    {
        // utun devices are bound to the owning file descriptor and disappear
        // when that descriptor closes. Re-opening a name here could attach to
        // an unrelated device, so cleanup is deliberately non-creating.
        let _ = name;
        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Err(PlatformError::UnsupportedCleanup(format!("tun device {name}")))
    }
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
#[path = "journal_tests.rs"]
mod tests;
