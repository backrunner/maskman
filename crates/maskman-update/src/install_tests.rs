use std::{
    fs,
    path::{Path, PathBuf},
    sync::Mutex,
};

use flate2::{write::GzEncoder, Compression};
use semver::Version;
use tar::Builder;

use super::{install_verified, validate_archive_path};
use crate::{ServiceController, UpdateError, VerifiedArtifact};

const SCRIPT: &[u8] = b"#!/bin/sh\nprintf 'maskman 9.9.9\\n'\n";

#[test]
fn archive_path_rejects_traversal_and_absolute_names() {
    assert!(validate_archive_path(Path::new("../maskman")).is_err());
    assert!(validate_archive_path(Path::new("/tmp/maskman")).is_err());
    assert!(validate_archive_path(Path::new("bin/maskman")).is_ok());
}

#[cfg(unix)]
#[test]
fn install_rejects_a_broken_symlink_binary_path() {
    use std::os::unix::fs::symlink;

    let root = test_root("symlink");
    fs::create_dir_all(&root).unwrap_or_else(|error| panic!("create test root: {error}"));
    let binary = root.join("maskman");
    symlink(root.join("missing-maskman"), &binary)
        .unwrap_or_else(|error| panic!("create broken binary symlink: {error}"));
    let artifact = VerifiedArtifact { version: test_version(), archive: Vec::new() };
    assert!(install_verified(&artifact, &binary, None, None).is_err());
    remove_test_root(root);
}

#[cfg(unix)]
#[test]
fn install_runs_staged_version_check_and_keeps_one_backup() {
    let (root, binary) = installed_binary("success");
    let artifact = test_artifact();

    let outcome = install_verified(&artifact, &binary, None, None)
        .unwrap_or_else(|error| panic!("install archive: {error}"));

    assert_eq!(outcome.version, test_version());
    assert_eq!(fs::read(&binary).unwrap_or_default(), SCRIPT);
    assert_eq!(fs::read(root.join("maskman.previous")).unwrap_or_default(), b"old binary");
    remove_test_root(root);
}

#[cfg(unix)]
#[test]
fn failed_health_check_stops_new_service_before_restoring_old_binary() {
    let (root, binary) = installed_binary("rollback");
    let service = MockService::new(false);

    let error = match install_verified(&test_artifact(), &binary, None, Some(&service)) {
        Ok(_) => panic!("health failure must roll back"),
        Err(error) => error,
    };

    assert!(matches!(error, UpdateError::Health(_)));
    assert_eq!(fs::read(&binary).unwrap_or_default(), b"old binary");
    assert_eq!(service.calls(), ["stop", "start", "healthy", "stop", "start"]);
    remove_test_root(root);
}

#[cfg(unix)]
#[test]
fn rollback_does_not_replace_binary_when_failed_service_cannot_stop() {
    let (root, binary) = installed_binary("rollback-stop-failure");
    let service = MockService::new(true);

    let error = match install_verified(&test_artifact(), &binary, None, Some(&service)) {
        Ok(_) => panic!("rollback stop failure must be reported"),
        Err(error) => error,
    };

    assert!(matches!(error, UpdateError::Rollback(_)));
    assert_eq!(fs::read(&binary).unwrap_or_default(), SCRIPT);
    assert_eq!(service.calls(), ["stop", "start", "healthy", "stop"]);
    remove_test_root(root);
}

struct MockService {
    calls: Mutex<Vec<&'static str>>,
    fail_rollback_stop: bool,
}

impl MockService {
    fn new(fail_rollback_stop: bool) -> Self {
        Self { calls: Mutex::new(Vec::new()), fail_rollback_stop }
    }

    fn record(&self, action: &'static str) -> usize {
        let mut calls = self.calls.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        calls.push(action);
        calls.iter().filter(|call| **call == action).count()
    }

    fn calls(&self) -> Vec<&'static str> {
        self.calls.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone()
    }
}

impl ServiceController for MockService {
    fn stop(&self) -> Result<(), UpdateError> {
        let count = self.record("stop");
        if self.fail_rollback_stop && count == 2 {
            return Err(UpdateError::Health("test stop failure".into()));
        }
        Ok(())
    }

    fn start(&self) -> Result<(), UpdateError> {
        self.record("start");
        Ok(())
    }

    fn healthy(&self) -> Result<bool, UpdateError> {
        self.record("healthy");
        Err(UpdateError::Health("test health failure".into()))
    }
}

fn installed_binary(name: &str) -> (PathBuf, PathBuf) {
    let root = test_root(name);
    fs::create_dir_all(&root).unwrap_or_else(|error| panic!("create test directory: {error}"));
    let binary = root.join("maskman");
    fs::write(&binary, b"old binary").unwrap_or_else(|error| panic!("write old binary: {error}"));
    (root, binary)
}

fn test_artifact() -> VerifiedArtifact {
    let mut compressed = GzEncoder::new(Vec::new(), Compression::fast());
    {
        let mut builder = Builder::new(&mut compressed);
        let mut header = tar::Header::new_gnu();
        header.set_size(SCRIPT.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        builder
            .append_data(&mut header, "maskman", SCRIPT)
            .unwrap_or_else(|error| panic!("append archive entry: {error}"));
        builder.finish().unwrap_or_else(|error| panic!("finish archive: {error}"));
    }
    let archive = compressed.finish().unwrap_or_else(|error| panic!("compress archive: {error}"));
    VerifiedArtifact { version: test_version(), archive }
}

fn test_version() -> Version {
    Version::parse("9.9.9").unwrap_or_else(|error| panic!("version: {error}"))
}

fn test_root(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("maskman-update-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    root
}

fn remove_test_root(root: PathBuf) {
    fs::remove_dir_all(root).unwrap_or_else(|error| panic!("remove test root: {error}"));
}
