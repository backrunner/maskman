use std::{fs, io, path::Path};

use crate::UpdateError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExistingPath {
    Missing,
    File,
    Directory,
    Symlink,
    Other,
}

pub(crate) fn inspect_path(path: &Path) -> Result<ExistingPath, UpdateError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Ok(ExistingPath::Symlink),
        Ok(metadata) if metadata.is_file() => Ok(ExistingPath::File),
        Ok(metadata) if metadata.is_dir() => Ok(ExistingPath::Directory),
        Ok(_) => Ok(ExistingPath::Other),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(ExistingPath::Missing),
        Err(error) => Err(UpdateError::Io(error)),
    }
}

pub(crate) fn current_binary_state(path: &Path) -> Result<bool, UpdateError> {
    match inspect_path(path)? {
        ExistingPath::Missing => Ok(false),
        ExistingPath::File => Ok(true),
        ExistingPath::Symlink => Err(UpdateError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "refusing to replace a symbolic-link binary path",
        ))),
        ExistingPath::Directory | ExistingPath::Other => Err(UpdateError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "update binary path is not a regular file",
        ))),
    }
}

pub(crate) fn validate_backup_path(path: &Path) -> Result<(), UpdateError> {
    match inspect_path(path)? {
        ExistingPath::Missing | ExistingPath::File => Ok(()),
        ExistingPath::Symlink | ExistingPath::Directory | ExistingPath::Other => {
            Err(UpdateError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "update backup path is not a regular file",
            )))
        }
    }
}
