#![forbid(unsafe_code)]

use std::net::SocketAddr;

use maskman_config::CompiledConfig;
use thiserror::Error;
use tokio::task::JoinSet;

mod datagram;
mod request;
mod tls;
mod transport;

pub use transport::{
    server_config, TransportError, TransportLimits, TransportMode, TransportServer,
    TransportShutdown,
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
    let quic_config = server_config(&config.certificate_file, &config.private_key_file)
        .map_err(|error| ServerError::Transport(error.to_string()))?;
    let limits = TransportLimits {
        max_connections: config.max_connections,
        max_requests_per_connection: config.max_requests_per_connection,
        max_header_bytes: config.max_header_bytes,
        idle_timeout: config.idle_timeout,
        drain_timeout: config.drain_timeout,
    };
    let mut servers = Vec::with_capacity(config.listen.len());
    for address in config.listen {
        servers.push(
            TransportServer::bind(
                address,
                quic_config.clone(),
                limits,
                transport::default_server_mode(),
            )
            .map_err(|error| ServerError::Transport(error.to_string()))?,
        );
    }
    run_servers(servers).await
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
