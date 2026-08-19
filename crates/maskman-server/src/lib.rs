#![forbid(unsafe_code)]

use std::net::SocketAddr;

use maskman_config::CompiledConfig;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("server transport is not implemented yet; complete the HTTP/3 transport spike first")]
    TransportSpikeRequired,
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

pub fn serve(_config: CompiledConfig) -> Result<(), ServerError> {
    Err(ServerError::TransportSpikeRequired)
}
