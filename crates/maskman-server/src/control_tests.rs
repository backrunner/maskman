use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use tokio::io::AsyncWriteExt;

use super::{
    read_frame, request, socket_path, start, validate_socket_path, ControlCommand, ControlError,
    ControlRequest, MAX_CONTROL_MESSAGE_BYTES,
};
use crate::TransportContext;

static NEXT_TEST_ROOT: AtomicU64 = AtomicU64::new(0);

fn short_test_root() -> PathBuf {
    // macOS limits sockaddr_un paths to a little over one hundred bytes;
    // temp_dir() can already consume most of that budget on CI runners.
    let sequence = NEXT_TEST_ROOT.fetch_add(1, Ordering::Relaxed);
    let root = PathBuf::from("/tmp").join(format!("mm-{}-{sequence}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    root
}

fn test_context(root: &std::path::Path) -> (PathBuf, Arc<TransportContext>) {
    let config_path = root.join("config.toml");
    let mut document = maskman_config::ConfigDocument::default();
    document.server.state_dir = root.to_string_lossy().into_owned();
    maskman_config::write_atomic(&config_path, &document)
        .unwrap_or_else(|error| panic!("write config: {error}"));
    let config = maskman_config::compile(&config_path)
        .unwrap_or_else(|error| panic!("compile config: {error}"));
    (config_path, Arc::new(TransportContext::new(Arc::new(config))))
}

#[tokio::test]
async fn status_and_reload_use_versioned_local_protocol() {
    let root = short_test_root();
    std::fs::create_dir_all(&root).unwrap_or_else(|error| panic!("create root: {error}"));
    let (config_path, context) = test_context(&root);
    let path = socket_path(&context.config_snapshot());
    let handle = start(path.clone(), Some(config_path), context.clone())
        .await
        .unwrap_or_else(|error| panic!("start control: {error}"));

    let first = request(&path, ControlCommand::Status)
        .await
        .unwrap_or_else(|error| panic!("status: {error}"));
    assert!(first.ok);
    assert!(first.request_id > 0);
    assert_eq!(first.status.as_ref().map(|status| status.config_generation), Some(1));
    let second = request(&path, ControlCommand::Reload)
        .await
        .unwrap_or_else(|error| panic!("reload: {error}"));
    assert!(second.ok);
    assert_eq!(second.status.as_ref().map(|status| status.config_generation), Some(2));
    handle.stop().await.unwrap_or_else(|error| panic!("stop control: {error}"));
    std::fs::remove_dir_all(root).unwrap_or_else(|error| panic!("remove root: {error}"));
}

#[tokio::test]
async fn reload_rejects_restart_required_fields_atomically() {
    let root = short_test_root();
    std::fs::create_dir_all(&root).unwrap_or_else(|error| panic!("create root: {error}"));
    let (config_path, context) = test_context(&root);
    let path = socket_path(&context.config_snapshot());
    let handle = start(path.clone(), Some(config_path.clone()), context.clone())
        .await
        .unwrap_or_else(|error| panic!("start control: {error}"));

    let mut document =
        maskman_config::load(&config_path).unwrap_or_else(|error| panic!("load config: {error}"));
    document.server.listen = vec!["127.0.0.1:8443".into()];
    maskman_config::write_atomic(&config_path, &document)
        .unwrap_or_else(|error| panic!("write config: {error}"));
    let response = request(&path, ControlCommand::Reload)
        .await
        .unwrap_or_else(|error| panic!("reload: {error}"));
    assert!(!response.ok);
    assert_eq!(context.config_generation(), 1);
    assert!(response.error.as_deref().is_some_and(|error| error.contains("server.listen")));

    handle.stop().await.unwrap_or_else(|error| panic!("stop control: {error}"));
    std::fs::remove_dir_all(root).unwrap_or_else(|error| panic!("remove root: {error}"));
}

#[test]
fn socket_path_is_bounded_and_absolute() {
    assert!(matches!(
        validate_socket_path(std::path::Path::new("relative/control.sock")),
        Err(ControlError::UnsafeSocketPath(_))
    ));
    let long = std::path::PathBuf::from("/").join("x".repeat(120));
    assert!(matches!(validate_socket_path(&long), Err(ControlError::PathTooLong(_))));
}

#[tokio::test]
async fn control_frames_reject_unknown_fields_and_unbounded_payloads() {
    let (mut client, mut server) =
        tokio::net::UnixStream::pair().unwrap_or_else(|error| panic!("unix pair: {error}"));
    let unknown = br#"{"version":1,"command":"status","extra":true}"#;
    client
        .write_all(&(unknown.len() as u32).to_be_bytes())
        .await
        .unwrap_or_else(|error| panic!("write unknown length: {error}"));
    client.write_all(unknown).await.unwrap_or_else(|error| panic!("write unknown frame: {error}"));
    assert!(read_frame::<ControlRequest>(&mut server).await.is_err());

    let (mut client, mut server) =
        tokio::net::UnixStream::pair().unwrap_or_else(|error| panic!("unix pair: {error}"));
    let oversized = (MAX_CONTROL_MESSAGE_BYTES as u32 + 1).to_be_bytes();
    let (write_result, read_result) =
        tokio::join!(client.write_all(&oversized), read_frame::<ControlRequest>(&mut server));
    write_result.unwrap_or_else(|error| panic!("write oversized frame: {error}"));
    assert!(matches!(read_result, Err(ControlError::TooLarge)));
}

#[cfg(unix)]
#[tokio::test]
async fn control_socket_is_private_and_non_socket_paths_are_preserved() {
    use std::os::unix::fs::PermissionsExt;

    let root = short_test_root();
    std::fs::create_dir_all(&root).unwrap_or_else(|error| panic!("create root: {error}"));
    let (config_path, context) = test_context(&root);
    let path = socket_path(&context.config_snapshot());
    std::fs::write(&path, b"operator file")
        .unwrap_or_else(|error| panic!("write sentinel: {error}"));
    let error = match start(path.clone(), Some(config_path), context).await {
        Ok(_) => panic!("regular file must not be replaced"),
        Err(error) => error,
    };
    assert!(matches!(error, ControlError::UnsafeSocketPath(_)));
    assert_eq!(std::fs::read(&path).unwrap_or_default(), b"operator file");
    std::fs::remove_file(&path).unwrap_or_else(|error| panic!("remove sentinel: {error}"));

    let context = test_context(&root).1;
    let path = socket_path(&context.config_snapshot());
    let handle = start(path.clone(), None, context)
        .await
        .unwrap_or_else(|error| panic!("start control: {error}"));
    let mode = std::fs::metadata(&path)
        .unwrap_or_else(|error| panic!("stat socket: {error}"))
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    handle.stop().await.unwrap_or_else(|error| panic!("stop control: {error}"));
    std::fs::remove_dir_all(root).unwrap_or_else(|error| panic!("remove root: {error}"));
}
