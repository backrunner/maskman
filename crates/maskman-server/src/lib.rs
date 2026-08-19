#![forbid(unsafe_code)]

use std::{net::SocketAddr, path::Path};

use maskman_config::CompiledConfig;
use thiserror::Error;
use tokio::task::JoinSet;

mod auth;
mod datagram;
mod policy;
mod proxy;
mod request;
mod request_ip;
mod session;
mod tls;
mod transport;
mod tun_bridge;

pub use transport::{
    server_config, TransportContext, TransportError, TransportLimits, TransportMode,
    TransportServer, TransportShutdown,
};

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("server configuration has no listener")]
    MissingListener,
    #[error("server transport failed: {0}")]
    Transport(String),
    #[error("server transport task failed: {0}")]
    Task(String),
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
    if config.listen.is_empty() {
        return Err(ServerError::MissingListener);
    }
    if config.ip.nat_managed {
        return Err(ServerError::Transport(
            "managed NAT is not available until a platform firewall backend is configured"
                .to_owned(),
        ));
    }
    let quic_config = transport::server_config_with_client_ca(
        &config.certificate_file,
        &config.private_key_file,
        config.client_ca_file.as_deref(),
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
    let journal_path = config.state_dir.join("resource-journal.json");
    let mut journal = if config.ip.enabled {
        let journal = maskman_platform::NetworkJournal::load(&journal_path)
            .map_err(|error| ServerError::Transport(error.to_string()))?;
        if !journal.is_empty() {
            return Err(ServerError::Transport(format!(
                "owned platform resources remain in {}; run maskman cleanup before starting",
                journal_path.display()
            )));
        }
        Some(journal)
    } else {
        None
    };
    let mut tun_task = if config.ip.enabled {
        let receiver = context
            .take_tun_receiver()
            .ok_or_else(|| ServerError::Transport("TUN queue was already claimed".to_owned()))?;
        let device = maskman_platform::TunDevice::create(
            maskman_platform::TunConfig {
                name: config.ip.interface_name.clone(),
                mtu: config.ip.mtu as u16,
            },
            journal.as_mut().ok_or_else(|| {
                ServerError::Transport("TUN journal was not initialized".to_owned())
            })?,
        )
        .map_err(|error| ServerError::Transport(error.to_string()))?;
        journal
            .as_ref()
            .ok_or_else(|| ServerError::Transport("TUN journal was not initialized".to_owned()))?
            .persist(&journal_path)
            .map_err(|error| ServerError::Transport(error.to_string()))?;
        if let Err(error) = provision_routes(
            &config,
            &device,
            journal.as_mut().ok_or_else(|| {
                ServerError::Transport("TUN journal was not initialized".to_owned())
            })?,
            &journal_path,
        )
        .await
        {
            drop(device);
            let cleanup = cleanup_owned_resources(&journal_path).await;
            return match cleanup {
                Ok(()) => Err(error),
                Err(cleanup_error) => Err(ServerError::Transport(format!(
                    "{error}; resource cleanup failed: {cleanup_error}"
                ))),
            };
        }
        Some(tokio::spawn(tun_bridge::run(device, context.clone(), receiver)))
    } else {
        None
    };
    for address in config.listen.iter().copied() {
        let server = match TransportServer::bind_with_context(
            address,
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
                if config.ip.enabled {
                    let _ = cleanup_owned_resources(&journal_path).await;
                }
                return Err(ServerError::Transport(error.to_string()));
            }
        };
        servers.push(server);
    }
    let result = run_servers(servers).await;
    if let Some(task) = tun_task {
        task.abort();
        let _ = task.await;
    }
    let cleanup =
        if config.ip.enabled { cleanup_owned_resources(&journal_path).await } else { Ok(()) };
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(cleanup_error)) => Err(ServerError::Transport(format!(
            "{error}; resource cleanup failed: {cleanup_error}"
        ))),
    }
}

async fn cleanup_owned_resources(path: &Path) -> Result<(), ServerError> {
    maskman_platform::cleanup_journal(path, false)
        .await
        .map(|_| ())
        .map_err(|error| ServerError::Transport(format!("resource cleanup failed: {error}")))
}

#[cfg(target_os = "linux")]
async fn provision_routes(
    config: &CompiledConfig,
    device: &maskman_platform::TunDevice,
    journal: &mut maskman_platform::NetworkJournal,
    journal_path: &Path,
) -> Result<(), ServerError> {
    let interface_index =
        device.interface_index().map_err(|error| ServerError::Transport(error.to_string()))?;
    let manager = maskman_platform::LinuxRouteManager::connect()
        .map_err(|error| ServerError::Transport(error.to_string()))?;
    for route in [config.ip.ipv4_pool, config.ip.ipv6_pool].into_iter().flatten() {
        manager
            .add_route(route, interface_index, journal)
            .await
            .map_err(|error| ServerError::Transport(error.to_string()))?;
        journal.persist(journal_path).map_err(|error| ServerError::Transport(error.to_string()))?;
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
async fn provision_routes(
    _config: &CompiledConfig,
    _device: &maskman_platform::TunDevice,
    _journal: &mut maskman_platform::NetworkJournal,
    _journal_path: &Path,
) -> Result<(), ServerError> {
    Ok(())
}

async fn run_servers(servers: Vec<TransportServer>) -> Result<(), ServerError> {
    let mut tasks = JoinSet::new();
    for server in servers {
        tasks.spawn(server.run());
    }
    let result = tasks.join_next().await.ok_or(ServerError::MissingListener)?;
    tasks.abort_all();
    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(ServerError::Transport(error.to_string())),
        Err(error) => Err(ServerError::Task(error.to_string())),
    }
}
