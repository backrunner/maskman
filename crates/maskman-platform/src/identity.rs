use std::{
    io,
    process::{Command, Output, Stdio},
};

use crate::privilege::{WORKER_GROUP, WORKER_USER};
use crate::{current_uid, worker_identity_available, PlatformError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerIdentityProvision {
    Existing,
    Created,
    WouldCreate,
}

impl WorkerIdentityProvision {
    pub fn created(self) -> bool {
        matches!(self, Self::Created)
    }
}

/// Ensure the fixed service account exists. The command lines are deliberately
/// platform-specific and contain no user-controlled arguments or shell syntax.
pub fn ensure_worker_identity(dry_run: bool) -> Result<WorkerIdentityProvision, PlatformError> {
    if worker_identity_available() {
        return Ok(WorkerIdentityProvision::Existing);
    }
    if dry_run {
        return Ok(WorkerIdentityProvision::WouldCreate);
    }
    if current_uid() != 0 {
        return Err(PlatformError::InvalidService(format!(
            "dedicated worker identity {WORKER_USER} is missing; install must run as root"
        )));
    }

    #[cfg(target_os = "linux")]
    {
        create_linux_identity()?;
    }
    #[cfg(target_os = "macos")]
    {
        create_macos_identity()?;
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        return Err(PlatformError::ServiceManagementUnavailable);
    }

    if worker_identity_available() {
        Ok(WorkerIdentityProvision::Created)
    } else {
        Err(PlatformError::InvalidService(format!(
            "system account creation completed without a visible {WORKER_USER} identity"
        )))
    }
}

#[cfg(target_os = "linux")]
fn create_linux_identity() -> Result<(), PlatformError> {
    let useradd = ["/usr/sbin/useradd", "/usr/bin/useradd"]
        .into_iter()
        .find(|path| std::path::Path::new(path).is_file())
        .ok_or_else(|| {
            PlatformError::InvalidService(
                "useradd is unavailable; install the maskman system account manually".into(),
            )
        })?;
    let shell = ["/usr/sbin/nologin", "/sbin/nologin", "/bin/false"]
        .into_iter()
        .find(|path| std::path::Path::new(path).is_file())
        .unwrap_or("/bin/false");
    let group = nix::unistd::Group::from_name(WORKER_GROUP)
        .map_err(|error| PlatformError::Network(format!("lookup worker group: {error}")))?;
    let mut command = Command::new(useradd);
    command.args(["--system", "--no-create-home", "--home-dir", "/var/empty", "--shell", shell]);
    if group.is_some() {
        command.args(["--gid", WORKER_GROUP]);
    } else {
        command.arg("--user-group");
    }
    command.arg(WORKER_USER).stdin(Stdio::null());
    run_checked(&mut command, "create Linux worker identity")?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn create_macos_identity() -> Result<(), PlatformError> {
    let dscl = "/usr/bin/dscl";
    if !std::path::Path::new(dscl).is_file() {
        return Err(PlatformError::InvalidService(
            "dscl is unavailable; install the maskman system account manually".into(),
        ));
    }
    let uid = next_directory_id(dscl, "/Users")?;
    let group = nix::unistd::Group::from_name(WORKER_GROUP)
        .map_err(|error| PlatformError::Network(format!("lookup worker group: {error}")))?;
    let gid = group
        .as_ref()
        .map(|value| value.gid.as_raw())
        .unwrap_or(next_directory_id(dscl, "/Groups")?);
    let mut group_created = false;
    let mut user_created = false;
    let result = (|| {
        if group.is_none() {
            // Keep the group creation inside the transaction. A successful
            // `-create` followed by a failed attribute update must not leave
            // a partially initialized account behind.
            run_dscl(dscl, vec!["-create".into(), "/Groups/".to_owned() + WORKER_GROUP])?;
            group_created = true;
            run_dscl(
                dscl,
                vec![
                    "-create".into(),
                    "/Groups/".to_owned() + WORKER_GROUP,
                    "PrimaryGroupID".into(),
                    gid.to_string(),
                ],
            )?;
        }
        let user_path = "/Users/".to_owned() + WORKER_USER;
        run_dscl(dscl, vec!["-create".into(), user_path.clone()])?;
        user_created = true;
        for (key, value) in [
            ("UniqueID", uid.to_string()),
            ("PrimaryGroupID", gid.to_string()),
            ("UserShell", "/usr/bin/false".into()),
            ("NFSHomeDirectory", "/var/empty".into()),
            ("IsHidden", "1".into()),
        ] {
            run_dscl(dscl, vec!["-create".into(), user_path.clone(), key.into(), value])?;
        }
        run_dscl(
            dscl,
            vec![
                "-append".into(),
                "/Groups/".to_owned() + WORKER_GROUP,
                "GroupMembership".into(),
                WORKER_USER.into(),
            ],
        )?;
        Ok::<(), PlatformError>(())
    })();
    if let Err(error) = result {
        if user_created {
            let _ = run_dscl(dscl, vec!["-delete".into(), "/Users/".to_owned() + WORKER_USER]);
        }
        if group_created {
            let _ = run_dscl(dscl, vec!["-delete".into(), "/Groups/".to_owned() + WORKER_GROUP]);
        }
        return Err(error);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn next_directory_id(dscl: &str, record_type: &str) -> Result<u32, PlatformError> {
    let property = match record_type {
        "/Users" => "UniqueID",
        "/Groups" => "PrimaryGroupID",
        _ => {
            return Err(PlatformError::InvalidService(
                "unsupported macOS directory record type".into(),
            ))
        }
    };
    let output = run_output(
        Command::new(dscl).args([".", "-list", record_type, property]).stdin(Stdio::null()),
        "inspect directory service ids",
    )?;
    if !output.status.success() {
        return Err(PlatformError::ServiceCommand(io::Error::other(format!(
            "inspect directory service ids: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))));
    }
    let mut used = std::collections::HashSet::<u32>::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        if let Some(value) = line.split_whitespace().last().and_then(|value| value.parse().ok()) {
            used.insert(value);
        }
    }
    (400..500).find(|candidate| !used.contains(candidate)).ok_or_else(|| {
        PlatformError::InvalidService("no free macOS system uid is available".into())
    })
}

#[cfg(target_os = "macos")]
fn run_dscl<I>(dscl: &str, args: I) -> Result<(), PlatformError>
where
    I: IntoIterator<Item = String>,
{
    let mut command = Command::new(dscl);
    command.arg(".").args(args).stdin(Stdio::null());
    run_checked(&mut command, "update macOS worker identity")
}

fn run_checked(command: &mut Command, action: &str) -> Result<(), PlatformError> {
    let output = run_output(command, action)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(PlatformError::ServiceCommand(io::Error::other(format!(
            "{action}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))))
    }
}

fn run_output(command: &mut Command, action: &str) -> Result<Output, PlatformError> {
    command.output().map_err(|error| {
        PlatformError::ServiceCommand(io::Error::new(error.kind(), format!("{action}: {error}")))
    })
}

#[cfg(test)]
mod tests {
    use super::WorkerIdentityProvision;

    #[test]
    fn provision_state_reports_only_real_creation() {
        assert!(!WorkerIdentityProvision::Existing.created());
        assert!(WorkerIdentityProvision::Created.created());
        assert!(!WorkerIdentityProvision::WouldCreate.created());
    }
}
