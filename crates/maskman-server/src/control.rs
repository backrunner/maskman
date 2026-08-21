use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::{watch, Semaphore},
    task::JoinHandle,
};

use crate::{stats::RuntimeSnapshot, TransportContext};

pub const CONTROL_PROTOCOL_VERSION: u32 = 1;
const MAX_CONTROL_MESSAGE_BYTES: usize = 16 * 1024;
const MAX_CONTROL_CLIENTS: usize = 16;
const MAX_CONTROL_PATH_BYTES: usize = 100;
const CONTROL_CLIENT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ControlCommand {
    Status,
    Reload,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ControlRequest {
    pub version: u32,
    pub request_id: u64,
    pub command: ControlCommand,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DaemonStatus {
    pub version: String,
    pub pid: u32,
    pub ready: bool,
    pub config_generation: u64,
    pub config_hash_sha256: Option<String>,
    pub listen: Vec<String>,
    pub metrics_listen: String,
    pub runtime: RuntimeSnapshot,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ControlResponse {
    pub version: u32,
    pub request_id: u64,
    pub ok: bool,
    pub status: Option<DaemonStatus>,
    pub error: Option<String>,
}

#[derive(Debug, Error)]
pub enum ControlError {
    #[error("control socket I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("control message is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("control message exceeds {MAX_CONTROL_MESSAGE_BYTES} bytes")]
    TooLarge,
    #[error("control protocol version {received} is unsupported; expected {expected}")]
    Version { received: u32, expected: u32 },
    #[error("another maskman daemon is listening on {0}")]
    AlreadyRunning(PathBuf),
    #[error("refusing to replace non-socket path {0}")]
    UnsafeSocketPath(PathBuf),
    #[error("control socket path is too long (maximum {MAX_CONTROL_PATH_BYTES} bytes): {0}")]
    PathTooLong(PathBuf),
    #[error("control task failed: {0}")]
    Task(String),
}

pub struct ControlHandle {
    path: PathBuf,
    shutdown: watch::Sender<bool>,
    task: JoinHandle<Result<(), ControlError>>,
}

pub fn socket_path(config: &maskman_config::CompiledConfig) -> PathBuf {
    config.state_dir.join("control.sock")
}

pub async fn request(
    path: &Path,
    command: ControlCommand,
) -> Result<ControlResponse, ControlError> {
    let mut stream = UnixStream::connect(path).await?;
    let request = ControlRequest {
        version: CONTROL_PROTOCOL_VERSION,
        request_id: NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed),
        command,
    };
    write_frame(&mut stream, &request).await?;
    stream.shutdown().await?;
    read_frame(&mut stream).await
}

pub(crate) async fn start(
    path: PathBuf,
    config_path: Option<PathBuf>,
    context: Arc<TransportContext>,
) -> Result<ControlHandle, ControlError> {
    validate_socket_path(&path)?;
    prepare_socket(&path).await?;
    let listener = UnixListener::bind(&path)?;
    set_socket_permissions(&path)?;
    let (shutdown, shutdown_rx) = watch::channel(false);
    let task_path = path.clone();
    let task = tokio::spawn(async move {
        let result = run(listener, shutdown_rx, config_path, context).await;
        let _ = std::fs::remove_file(&task_path);
        result
    });
    Ok(ControlHandle { path, shutdown, task })
}

impl ControlHandle {
    pub(crate) async fn stop(self) -> Result<(), ControlError> {
        self.shutdown.send_replace(true);
        self.task.await.map_err(|error| ControlError::Task(error.to_string()))??;
        let _ = std::fs::remove_file(&self.path);
        Ok(())
    }
}

async fn run(
    listener: UnixListener,
    mut shutdown: watch::Receiver<bool>,
    config_path: Option<PathBuf>,
    context: Arc<TransportContext>,
) -> Result<(), ControlError> {
    let permits = Arc::new(Semaphore::new(MAX_CONTROL_CLIENTS));
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
            }
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    continue;
                };
                let config_path = config_path.clone();
                let context = context.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let _ = tokio::time::timeout(
                        CONTROL_CLIENT_TIMEOUT,
                        serve_client(stream, config_path.as_deref(), &context),
                    )
                    .await;
                });
            }
        }
    }
}

async fn serve_client(
    mut stream: UnixStream,
    config_path: Option<&Path>,
    context: &Arc<TransportContext>,
) -> Result<(), ControlError> {
    let peer_uid = stream.peer_cred().ok().map(|credentials| credentials.uid());
    let response = match read_frame::<ControlRequest>(&mut stream).await {
        Ok(request) => {
            if matches!(request.command, ControlCommand::Reload)
                && !peer_uid.is_some_and(maskman_platform::control_peer_allowed)
            {
                failure(request.request_id, "reload requires the daemon owner or root".into())
            } else {
                dispatch(request, config_path, context).await
            }
        }
        Err(error) => failure(0, error.to_string()),
    };
    write_frame(&mut stream, &response).await
}

async fn dispatch(
    request: ControlRequest,
    config_path: Option<&Path>,
    context: &Arc<TransportContext>,
) -> ControlResponse {
    if request.request_id == 0 {
        return failure(request.request_id, "control request_id must be non-zero".into());
    }
    if request.version != CONTROL_PROTOCOL_VERSION {
        return failure(
            request.request_id,
            ControlError::Version { received: request.version, expected: CONTROL_PROTOCOL_VERSION }
                .to_string(),
        );
    }
    match request.command {
        ControlCommand::Status => success(request.request_id, status(config_path, context).await),
        ControlCommand::Reload => match reload(config_path, context).await {
            Ok(()) => success(request.request_id, status(config_path, context).await),
            Err(error) => failure(request.request_id, error),
        },
    }
}

async fn reload(config_path: Option<&Path>, context: &TransportContext) -> Result<(), String> {
    let path = config_path
        .ok_or_else(|| "daemon was started without a reloadable config path".to_owned())?;
    let config = maskman_config::compile(path).map_err(|error| error.to_string())?;
    context.reload(config)
}

async fn status(config_path: Option<&Path>, context: &TransportContext) -> DaemonStatus {
    let config = context.config_snapshot();
    DaemonStatus {
        version: env!("CARGO_PKG_VERSION").to_owned(),
        pid: std::process::id(),
        ready: true,
        config_generation: context.config_generation(),
        config_hash_sha256: config_hash(config_path).await,
        listen: config.listen.iter().map(ToString::to_string).collect(),
        metrics_listen: config.metrics_listen.to_string(),
        runtime: context.runtime_snapshot(),
    }
}

async fn config_hash(path: Option<&Path>) -> Option<String> {
    let bytes = tokio::fs::read(path?).await.ok()?;
    Some(Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect())
}

fn success(request_id: u64, status: DaemonStatus) -> ControlResponse {
    ControlResponse {
        version: CONTROL_PROTOCOL_VERSION,
        request_id,
        ok: true,
        status: Some(status),
        error: None,
    }
}

fn failure(request_id: u64, error: String) -> ControlResponse {
    ControlResponse {
        version: CONTROL_PROTOCOL_VERSION,
        request_id,
        ok: false,
        status: None,
        error: Some(error),
    }
}

async fn prepare_socket(path: &Path) -> Result<(), ControlError> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
        let metadata = tokio::fs::symlink_metadata(parent).await?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(ControlError::UnsafeSocketPath(parent.to_path_buf()));
        }
        set_directory_permissions(parent)?;
    }
    let metadata = match tokio::fs::symlink_metadata(path).await {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if !is_socket_type(&metadata) {
        return Err(ControlError::UnsafeSocketPath(path.to_path_buf()));
    }
    if !socket_permissions_are_private(&metadata) {
        return Err(ControlError::UnsafeSocketPath(path.to_path_buf()));
    }
    if tokio::time::timeout(std::time::Duration::from_millis(250), UnixStream::connect(path))
        .await
        .is_ok_and(|result| result.is_ok())
    {
        return Err(ControlError::AlreadyRunning(path.to_path_buf()));
    }
    std::fs::remove_file(path)?;
    Ok(())
}

fn validate_socket_path(path: &Path) -> Result<(), ControlError> {
    if !path.is_absolute() {
        return Err(ControlError::UnsafeSocketPath(path.to_path_buf()));
    }
    if path.as_os_str().as_encoded_bytes().len() > MAX_CONTROL_PATH_BYTES {
        return Err(ControlError::PathTooLong(path.to_path_buf()));
    }
    Ok(())
}

#[cfg(unix)]
fn socket_permissions_are_private(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o077 == 0
}

#[cfg(unix)]
fn set_directory_permissions(path: &Path) -> Result<(), ControlError> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.permissions().mode() & 0o077 != 0 {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn set_directory_permissions(_path: &Path) -> Result<(), ControlError> {
    Ok(())
}

#[cfg(unix)]
fn is_socket_type(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::FileTypeExt;
    metadata.file_type().is_socket()
}

#[cfg(not(unix))]
fn is_socket_type(_metadata: &std::fs::Metadata) -> bool {
    false
}

#[cfg(not(unix))]
fn socket_permissions_are_private(_metadata: &std::fs::Metadata) -> bool {
    true
}

async fn read_frame<T: DeserializeOwned>(stream: &mut UnixStream) -> Result<T, ControlError> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    let length = u32::from_be_bytes(header) as usize;
    if length > MAX_CONTROL_MESSAGE_BYTES {
        return Err(ControlError::TooLarge);
    }
    let mut data = vec![0u8; length];
    stream.read_exact(&mut data).await?;
    Ok(serde_json::from_slice(&data)?)
}

async fn write_frame<T: Serialize>(stream: &mut UnixStream, value: &T) -> Result<(), ControlError> {
    let encoded = serde_json::to_vec(value)?;
    if encoded.len() > MAX_CONTROL_MESSAGE_BYTES {
        return Err(ControlError::TooLarge);
    }
    let length = u32::try_from(encoded.len()).map_err(|_| ControlError::TooLarge)?.to_be_bytes();
    stream.write_all(&length).await?;
    stream.write_all(&encoded).await?;
    Ok(())
}

#[cfg(unix)]
fn set_socket_permissions(path: &Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(test)]
#[path = "control_tests.rs"]
mod tests;
