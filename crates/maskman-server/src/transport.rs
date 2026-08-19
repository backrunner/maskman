use std::{net::SocketAddr, sync::Arc, time::Duration};

use bytes::Bytes;
use maskman_config::CompiledConfig;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::{sync::watch, task::JoinSet};

use crate::{
    datagram, request,
    session::{QuotaState, SessionRegistry},
    tls,
};

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("failed to bind QUIC endpoint: {0}")]
    Bind(#[from] std::io::Error),
    #[error("QUIC connection failed: {0}")]
    Connection(#[from] quinn::ConnectionError),
    #[error("HTTP/3 connection failed: {0}")]
    Http3(#[from] h3::error::ConnectionError),
    #[error("HTTP/3 datagram failed: {0}")]
    Datagram(String),
    #[error("invalid QUIC transport configuration: {0}")]
    Configuration(String),
    #[error(transparent)]
    Tls(#[from] tls::TlsError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportMode {
    RejectUntilAuthentication,
    EchoDatagrams,
}

#[derive(Debug, Clone, Copy)]
pub struct TransportLimits {
    pub max_connections: u32,
    pub max_requests_per_connection: u32,
    pub max_header_bytes: u32,
    pub idle_timeout: Duration,
    pub drain_timeout: Duration,
}

pub struct TransportServer {
    endpoint: quinn::Endpoint,
    max_connections: u32,
    max_header_bytes: u32,
    mode: TransportMode,
    drain_timeout: Duration,
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
    context: Option<Arc<TransportContext>>,
}

pub struct TransportContext {
    pub(crate) config: Arc<CompiledConfig>,
    pub(crate) quotas: Arc<QuotaState>,
}

impl TransportContext {
    pub fn new(config: Arc<CompiledConfig>) -> Self {
        Self { config, quotas: Arc::new(QuotaState::default()) }
    }
}

#[derive(Clone)]
pub struct TransportShutdown {
    shutdown_tx: watch::Sender<bool>,
}

impl TransportShutdown {
    pub fn shutdown(&self) {
        self.shutdown_tx.send_replace(true);
    }
}

impl TransportServer {
    pub fn bind(
        address: SocketAddr,
        mut server_config: quinn::ServerConfig,
        limits: TransportLimits,
        mode: TransportMode,
    ) -> Result<Self, TransportError> {
        configure_transport(&mut server_config, limits)?;
        let endpoint = quinn::Endpoint::server(server_config, address)?;
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        Ok(Self {
            endpoint,
            max_connections: limits.max_connections,
            max_header_bytes: limits.max_header_bytes,
            mode,
            drain_timeout: limits.drain_timeout,
            shutdown_tx,
            shutdown_rx,
            context: None,
        })
    }

    pub fn bind_with_context(
        address: SocketAddr,
        server_config: quinn::ServerConfig,
        limits: TransportLimits,
        mode: TransportMode,
        context: Arc<TransportContext>,
    ) -> Result<Self, TransportError> {
        let mut server = Self::bind(address, server_config, limits, mode)?;
        server.context = Some(context);
        Ok(server)
    }

    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        self.endpoint.local_addr().map_err(TransportError::Bind)
    }

    pub fn shutdown_handle(&self) -> TransportShutdown {
        TransportShutdown { shutdown_tx: self.shutdown_tx.clone() }
    }

    pub async fn run(mut self) -> Result<(), TransportError> {
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                changed = self.shutdown_rx.changed() => {
                    if changed.is_err() || *self.shutdown_rx.borrow() {
                        break;
                    }
                }
                incoming = self.endpoint.accept() => {
                    let Some(incoming) = incoming else {
                        break;
                    };
                    if self.endpoint.open_connections() >= self.max_connections as usize {
                        incoming.refuse();
                        continue;
                    }
                    let max_header_bytes = self.max_header_bytes;
                    let mode = self.mode;
                    let shutdown = self.shutdown_rx.clone();
                    let context = self.context.clone();
                    connections.spawn(async move {
                        handle_connection(incoming, max_header_bytes, mode, shutdown, context).await
                    });
                }
                completed = connections.join_next(), if !connections.is_empty() => {
                    observe_connection_result(completed);
                }
            }
        }

        self.shutdown_tx.send_replace(true);
        drain_connections(&mut connections, self.drain_timeout).await;
        self.endpoint.close(0u32.into(), b"maskman shutdown");
        self.endpoint.wait_idle().await;
        Ok(())
    }
}

fn observe_connection_result(
    _result: Option<Result<Result<(), TransportError>, tokio::task::JoinError>>,
) {
    // Metrics and structured logging are attached here when observability lands.
}

async fn drain_connections(
    connections: &mut JoinSet<Result<(), TransportError>>,
    drain_timeout: Duration,
) {
    let drain = async {
        while let Some(result) = connections.join_next().await {
            observe_connection_result(Some(result));
        }
    };
    if tokio::time::timeout(drain_timeout, drain).await.is_err() {
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    }
}

fn configure_transport(
    server_config: &mut quinn::ServerConfig,
    limits: TransportLimits,
) -> Result<(), TransportError> {
    let idle_timeout =
        limits.idle_timeout.try_into().map_err(|error: quinn::VarIntBoundsExceeded| {
            TransportError::Configuration(error.to_string())
        })?;
    let mut transport = quinn::TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(limits.max_requests_per_connection.into())
        .max_concurrent_uni_streams(16u32.into())
        .max_idle_timeout(Some(idle_timeout))
        .datagram_receive_buffer_size(Some(4 * 1024 * 1024))
        .datagram_send_buffer_size(4 * 1024 * 1024);
    server_config.transport_config(Arc::new(transport));
    Ok(())
}

pub fn server_config(
    certificate_file: &std::path::Path,
    private_key_file: &std::path::Path,
) -> Result<quinn::ServerConfig, TransportError> {
    Ok(tls::load_server_config(certificate_file, private_key_file)?)
}

pub fn server_config_with_client_ca(
    certificate_file: &std::path::Path,
    private_key_file: &std::path::Path,
    client_ca_file: Option<&std::path::Path>,
) -> Result<quinn::ServerConfig, TransportError> {
    Ok(tls::load_server_config_with_client_ca(certificate_file, private_key_file, client_ca_file)?)
}

async fn handle_connection(
    incoming: quinn::Incoming,
    max_header_bytes: u32,
    mode: TransportMode,
    shutdown: watch::Receiver<bool>,
    context: Option<Arc<TransportContext>>,
) -> Result<(), TransportError> {
    let connection = incoming.await?;
    let peer_certificate_sha256 = peer_certificate_sha256(&connection);
    let datagram_connection = connection.clone();
    let quic = h3_quinn::Connection::new(connection);
    let mut builder = h3::server::builder();
    builder
        .max_field_section_size(u64::from(max_header_bytes))
        .enable_extended_connect(true)
        .enable_datagram(true);
    let mut http3 = builder.build(quic).await?;
    drive_connection(
        &mut http3,
        &datagram_connection,
        mode,
        shutdown,
        context,
        peer_certificate_sha256,
    )
    .await
}

async fn drive_connection(
    http3: &mut h3::server::Connection<h3_quinn::Connection, Bytes>,
    datagram_connection: &quinn::Connection,
    mode: TransportMode,
    mut shutdown: watch::Receiver<bool>,
    context: Option<Arc<TransportContext>>,
    peer_certificate_sha256: Option<[u8; 32]>,
) -> Result<(), TransportError> {
    let registry = Arc::new(SessionRegistry::default());
    let mut draining = *shutdown.borrow();
    if draining {
        http3.shutdown(0).await?;
    }
    loop {
        tokio::select! {
            changed = shutdown.changed(), if !draining => {
                if changed.is_err() || *shutdown.borrow() {
                    draining = true;
                    http3.shutdown(0).await?;
                }
            },
            request = http3.accept() => match request? {
                Some(resolver) => {
                    let request_context = context.as_ref().map(|context| request::RequestContext {
                        config: context.config.clone(),
                        registry: registry.clone(),
                        quotas: context.quotas.clone(),
                        connection: datagram_connection.clone(),
                        peer_certificate_sha256,
                    });
                    tokio::spawn(async move {
                        let _ = request::handle(resolver, request_mode(mode), request_context).await;
                    });
                }
                None => return Ok(()),
            },
            raw = datagram_connection.read_datagram(), if !draining => {
                let raw = raw.map_err(|error| TransportError::Datagram(error.to_string()))?;
                let Ok(datagram) = datagram::decode(raw) else {
                    continue;
                };
                if context.is_some() {
                    forward_datagram(&registry, datagram.stream_id, datagram.payload, 65_527);
                } else if mode == TransportMode::EchoDatagrams {
                    let encoded = datagram::encode(datagram.stream_id, datagram.payload)
                        .map_err(|error| TransportError::Datagram(error.to_string()))?;
                    datagram_connection
                        .send_datagram(encoded)
                        .map_err(|error| TransportError::Datagram(error.to_string()))?;
                }
            },
        }
    }
}

fn forward_datagram(
    registry: &SessionRegistry,
    stream_id: u64,
    payload: Bytes,
    max_payload: usize,
) {
    let Ok(datagram) = maskman_protocol::capsule::decode_datagram(&payload) else {
        return;
    };
    if datagram.context_id != 0 || datagram.payload.len() > max_payload {
        return;
    }
    let _ = registry.try_send(stream_id, Bytes::copy_from_slice(datagram.payload));
}

fn peer_certificate_sha256(connection: &quinn::Connection) -> Option<[u8; 32]> {
    let identity = connection.peer_identity()?;
    let certificates =
        identity.downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>().ok()?;
    let certificate = certificates.first()?;
    let digest = Sha256::digest(certificate.as_ref());
    Some(digest.into())
}

fn request_mode(mode: TransportMode) -> request::RequestMode {
    match mode {
        TransportMode::RejectUntilAuthentication => request::RequestMode::RejectUntilAuthentication,
        TransportMode::EchoDatagrams => request::RequestMode::EchoDatagrams,
    }
}

pub fn default_server_mode() -> TransportMode {
    TransportMode::RejectUntilAuthentication
}

#[cfg(test)]
#[path = "transport_tests.rs"]
mod tests;
