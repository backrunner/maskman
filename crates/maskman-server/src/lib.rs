#![forbid(unsafe_code)]

use std::{
    net::{SocketAddr, UdpSocket},
    path::{Path, PathBuf},
};

use maskman_config::CompiledConfig;
use thiserror::Error;
use tokio::task::JoinSet;

mod auth;
pub mod control;
mod datagram;
mod metrics;
mod policy;
mod proxy;
mod request;
mod request_ip;
mod resources;
mod session;
mod stats;
mod supervisor;
mod tls;
mod transport;
mod tun_bridge;

pub use stats::RuntimeSnapshot;
pub use transport::{
    server_config, TransportContext, TransportError, TransportLimits, TransportMode,
    TransportServer, TransportShutdown,
};

pub use resources::PreparedResources;

/// Resources transferred from the root supervisor to the unprivileged worker.
pub struct WorkerResources {
    pub(crate) listeners: Vec<UdpSocket>,
    pub(crate) tun: Option<maskman_platform::TunDevice>,
}

pub fn validate_tls(config: &CompiledConfig) -> Result<(), TransportError> {
    transport::server_config_with_client_ca(
        &config.certificate_file,
        &config.private_key_file,
        config.client_ca_file.as_deref(),
        matches!(&config.auth_mode, maskman_config::AuthMode::Mtls),
    )
    .map(|_| ())
}

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("server configuration has no listener")]
    MissingListener,
    #[error("server transport failed: {0}")]
    Transport(String),
    #[error("server transport task failed: {0}")]
    Task(String),
    #[error("failed to install shutdown signal handler: {0}")]
    Signal(String),
}

#[derive(Debug, Clone)]
pub struct ServerStatus {
    pub listen: Vec<SocketAddr>,
    pub connections: u64,
    pub udp_sessions: u64,
    pub ip_sessions: u64,
}

pub fn status(config: &CompiledConfig) -> ServerStatus {
    ServerStatus { listen: config.listen.clone(), connections: 0, udp_sessions: 0, ip_sessions: 0 }
}

pub async fn serve(config: CompiledConfig) -> Result<(), ServerError> {
    serve_inner(config, None, None).await
}

pub async fn serve_with_config_path(
    config: CompiledConfig,
    config_path: PathBuf,
) -> Result<(), ServerError> {
    if std::env::var("MASKMAN_ROLE").as_deref() == Ok("supervisor") {
        supervisor::run(config, config_path).await
    } else {
        serve_inner(config, Some(config_path), None).await
    }
}

pub async fn serve_worker_with_resources(
    config: CompiledConfig,
    config_path: PathBuf,
    resources: WorkerResources,
) -> Result<(), ServerError> {
    serve_inner(config, Some(config_path), Some(resources)).await
}

/// Decode the descriptor hand-off prepared by the platform supervisor.
pub fn worker_resources_from_environment(
    config: &CompiledConfig,
) -> Result<WorkerResources, ServerError> {
    let raw = std::env::var("MASKMAN_LISTENER_FDS")
        .map_err(|_| ServerError::Transport("worker listener descriptors are missing".into()))?;
    if raw.len() > 2048 {
        return Err(ServerError::Transport("worker listener descriptor list is too long".into()));
    }
    let mut seen = std::collections::HashSet::new();
    let mut listeners = Vec::new();
    for value in raw.split(',') {
        let fd = value
            .parse::<i32>()
            .map_err(|_| ServerError::Transport("worker listener descriptor is invalid".into()))?;
        if fd < 0 || !seen.insert(fd) {
            return Err(ServerError::Transport("worker listener descriptors are invalid".into()));
        }
        listeners.push(
            maskman_platform::inherited_udp(fd)
                .map_err(|error| ServerError::Transport(error.to_string()))?,
        );
    }
    if listeners.is_empty() || listeners.len() != config.listen.len() {
        return Err(ServerError::Transport(
            "worker listener descriptor count does not match configuration".into(),
        ));
    }
    let tun = if config.ip.enabled {
        let raw = std::env::var("MASKMAN_TUN_FD")
            .map_err(|_| ServerError::Transport("worker TUN descriptor is missing".into()))?;
        let fd = raw
            .parse::<i32>()
            .map_err(|_| ServerError::Transport("worker TUN descriptor is invalid".into()))?;
        if fd < 0 || !seen.insert(fd) {
            return Err(ServerError::Transport("worker TUN descriptor is invalid".into()));
        }
        Some(
            maskman_platform::inherited_tun(
                fd,
                config.ip.interface_name.clone(),
                config.ip.mtu as u16,
            )
            .map_err(|error| ServerError::Transport(error.to_string()))?,
        )
    } else {
        if std::env::var_os("MASKMAN_TUN_FD").is_some() {
            return Err(ServerError::Transport(
                "worker received a TUN descriptor while IP proxy is disabled".into(),
            ));
        }
        None
    };
    Ok(WorkerResources { listeners, tun })
}

async fn serve_inner(
    config: CompiledConfig,
    config_path: Option<PathBuf>,
    worker_resources: Option<WorkerResources>,
) -> Result<(), ServerError> {
    if config.listen.is_empty() {
        return Err(ServerError::MissingListener);
    }
    maskman_platform::apply_worker_hardening()
        .map_err(|error| ServerError::Transport(error.to_string()))?;
    let quic_config = transport::server_config_with_client_ca(
        &config.certificate_file,
        &config.private_key_file,
        config.client_ca_file.as_deref(),
        matches!(&config.auth_mode, maskman_config::AuthMode::Mtls),
    )
    .map_err(|error| ServerError::Transport(error.to_string()))?;
    let limits = TransportLimits {
        max_connections: config.max_connections,
        max_requests_per_connection: config.max_requests_per_connection,
        max_header_bytes: config.max_header_bytes,
        idle_timeout: config.idle_timeout,
        drain_timeout: config.drain_timeout,
    };
    let mut servers = Vec::with_capacity(config.listen.len());
    let config = std::sync::Arc::new(config);
    let context = std::sync::Arc::new(TransportContext::new(config.clone()));
    let mut owned_resources =
        if worker_resources.is_none() { Some(resources::prepare(&config).await?) } else { None };
    let (mut listeners, tun, journal_path) = match worker_resources {
        Some(resources) => (resources.listeners, resources.tun, None),
        None => {
            let resources = owned_resources
                .take()
                .ok_or_else(|| ServerError::Transport("resource preparation was lost".into()))?;
            let (listeners, tun, journal_path) = resources.into_worker_parts();
            (listeners, tun, journal_path)
        }
    };
    // `pop` below keeps the configured listener order without repeatedly
    // shifting the vector.
    listeners.reverse();
    let mut tun_task = if config.ip.enabled {
        let device = tun.ok_or_else(|| {
            ServerError::Transport("IP worker started without a prepared TUN device".into())
        })?;
        let receiver = context
            .take_tun_receiver()
            .ok_or_else(|| ServerError::Transport("TUN queue was already claimed".into()))?;
        Some(tokio::spawn(tun_bridge::run(device, context.clone(), receiver)))
    } else {
        None
    };
    let metrics = match metrics::start(config.metrics_listen, context.stats_handle()).await {
        Ok(metrics) => metrics,
        Err(error) => {
            if let Some(task) = tun_task.take() {
                task.abort();
                let _ = task.await;
            }
            if let Some(path) = journal_path.as_deref() {
                let _ = resources::cleanup(Some(path)).await;
            }
            return Err(ServerError::Transport(format!(
                "failed to bind metrics listener {}: {error}",
                config.metrics_listen
            )));
        }
    };
    for _ in 0..config.listen.len() {
        let socket = listeners.pop().ok_or_else(|| {
            ServerError::Transport("worker listener descriptor count is too small".into())
        })?;
        let server = match TransportServer::bind_with_socket(
            socket,
            quic_config.clone(),
            limits,
            transport::default_server_mode(),
            context.clone(),
        ) {
            Ok(server) => server,
            Err(error) => {
                if let Some(task) = tun_task.take() {
                    task.abort();
                    let _ = task.await;
                }
                if let Some(path) = journal_path.as_deref() {
                    let _ = resources::cleanup(Some(path)).await;
                }
                metrics.stop().await;
                return Err(ServerError::Transport(error.to_string()));
            }
        };
        servers.push(server);
    }
    let control = if config_path.is_some() {
        match control::start(control::socket_path(&config), config_path.clone(), context.clone())
            .await
        {
            Ok(control) => Some(control),
            Err(error) => {
                metrics.stop().await;
                if let Some(task) = tun_task.take() {
                    task.abort();
                    let _ = task.await;
                }
                if let Some(path) = journal_path.as_deref() {
                    let _ = resources::cleanup(Some(path)).await;
                }
                return Err(ServerError::Transport(error.to_string()));
            }
        }
    } else {
        None
    };
    let result = run_servers(servers, config_path.as_deref(), &context).await;
    let control_result = match control {
        Some(control) => {
            control.stop().await.map_err(|error| ServerError::Transport(error.to_string()))
        }
        None => Ok(()),
    };
    if let Some(task) = tun_task {
        task.abort();
        let _ = task.await;
    }
    metrics.stop().await;
    let cleanup = resources::cleanup(journal_path.as_deref()).await;
    match (result, cleanup, control_result) {
        (Ok(()), Ok(()), Ok(())) => Ok(()),
        (Ok(()), Ok(()), Err(error)) => Err(error),
        (Ok(()), Err(error), _) => Err(error),
        (Err(error), _, _) => Err(error),
    }
}

async fn run_servers(
    servers: Vec<TransportServer>,
    config_path: Option<&Path>,
    context: &std::sync::Arc<TransportContext>,
) -> Result<(), ServerError> {
    let shutdown = servers.iter().map(TransportServer::shutdown_handle).collect::<Vec<_>>();
    let mut tasks = JoinSet::new();
    for server in servers {
        tasks.spawn(server.run());
    }
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .map_err(|error| ServerError::Signal(error.to_string()))?;
        let mut reload = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
            .map_err(|error| ServerError::Signal(error.to_string()))?;
        let ctrl_c = tokio::signal::ctrl_c();
        tokio::pin!(ctrl_c);
        loop {
            tokio::select! {
                result = tasks.join_next() => {
                    tasks.abort_all();
                    return map_server_result(result.ok_or(ServerError::MissingListener)?);
                }
                result = &mut ctrl_c => {
                    result.map_err(|error| ServerError::Signal(error.to_string()))?;
                    break;
                }
                _ = terminate.recv() => break,
                _ = reload.recv() => reload_config(config_path, context),
            }
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await.map_err(|error| ServerError::Signal(error.to_string()))?;

    for handle in shutdown {
        handle.shutdown();
    }
    while let Some(result) = tasks.join_next().await {
        map_server_result(result)?;
    }
    Ok(())
}

fn reload_config(config_path: Option<&Path>, context: &TransportContext) {
    let result = config_path
        .ok_or_else(|| "daemon was started without a reloadable config path".to_owned())
        .and_then(|path| maskman_config::compile(path).map_err(|error| error.to_string()))
        .and_then(|config| context.reload(config));
    if let Err(error) = result {
        context.record_runtime_error(error);
    }
}

fn map_server_result(
    result: Result<Result<(), TransportError>, tokio::task::JoinError>,
) -> Result<(), ServerError> {
    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(ServerError::Transport(error.to_string())),
        Err(error) => Err(ServerError::Task(error.to_string())),
    }
}
