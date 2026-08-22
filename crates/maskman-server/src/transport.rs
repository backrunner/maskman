use std::{
    net::{SocketAddr, UdpSocket},
    sync::Arc,
    time::Duration,
};

use bytes::Bytes;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::{sync::watch, task::JoinSet};

use crate::{datagram, request, session::SessionRegistry, stats::ActivityKind, tls};

#[path = "transport_context.rs"]
mod context;
pub use context::TransportContext;

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

struct ConnectionRuntime {
    mode: TransportMode,
    context: Option<Arc<TransportContext>>,
    connection_id: Option<u64>,
    peer_certificate_sha256: Option<[u8; 32]>,
    drain_timeout: Duration,
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

    /// Bind an endpoint around a socket opened by the supervisor. Keeping the
    /// socket creation outside this adapter is what lets the worker run after
    /// it has been reduced to the dedicated service identity.
    pub fn bind_with_socket(
        socket: UdpSocket,
        mut server_config: quinn::ServerConfig,
        limits: TransportLimits,
        mode: TransportMode,
        context: Arc<TransportContext>,
    ) -> Result<Self, TransportError> {
        configure_transport(&mut server_config, limits)?;
        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(server_config),
            socket,
            Arc::new(quinn::TokioRuntime),
        )?;
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        Ok(Self {
            endpoint,
            max_connections: limits.max_connections,
            max_header_bytes: limits.max_header_bytes,
            mode,
            drain_timeout: limits.drain_timeout,
            shutdown_tx,
            shutdown_rx,
            context: Some(context),
        })
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
                    let drain_timeout = self.drain_timeout;
                    connections.spawn(async move {
                        handle_connection(
                            incoming,
                            max_header_bytes,
                            mode,
                            shutdown,
                            context,
                            drain_timeout,
                        )
                        .await
                    });
                }
                completed = connections.join_next(), if !connections.is_empty() => {
                    observe_connection_result(completed, self.context.as_deref());
                }
            }
        }

        self.shutdown_tx.send_replace(true);
        drain_connections(&mut connections, self.drain_timeout, self.context.as_deref()).await;
        self.endpoint.close(0u32.into(), b"maskman shutdown");
        self.endpoint.wait_idle().await;
        Ok(())
    }
}

fn observe_connection_result(
    _result: Option<Result<Result<(), TransportError>, tokio::task::JoinError>>,
    context: Option<&TransportContext>,
) {
    let Some(context) = context else { return };
    match _result {
        Some(Ok(Err(error))) => context.record_runtime_error(error.to_string()),
        Some(Err(error)) => context.record_runtime_error(error.to_string()),
        _ => {}
    }
}

async fn drain_connections(
    connections: &mut JoinSet<Result<(), TransportError>>,
    drain_timeout: Duration,
    context: Option<&TransportContext>,
) {
    let drain = async {
        while let Some(result) = connections.join_next().await {
            observe_connection_result(Some(result), context);
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
    require_client_certificate: bool,
) -> Result<quinn::ServerConfig, TransportError> {
    Ok(tls::load_server_config_with_client_ca(
        certificate_file,
        private_key_file,
        client_ca_file,
        require_client_certificate,
    )?)
}

async fn handle_connection(
    incoming: quinn::Incoming,
    max_header_bytes: u32,
    mode: TransportMode,
    shutdown: watch::Receiver<bool>,
    context: Option<Arc<TransportContext>>,
    drain_timeout: Duration,
) -> Result<(), TransportError> {
    let connection = incoming.await?;
    let _activity = context.as_ref().map(|context| context.stats.begin(ActivityKind::Connection));
    let peer_certificate_sha256 = peer_certificate_sha256(&connection);
    let datagram_connection = connection.clone();
    let connection_id = context.as_ref().map(|context| context.next_connection_id());
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
        shutdown,
        ConnectionRuntime { mode, context, connection_id, peer_certificate_sha256, drain_timeout },
    )
    .await
}

async fn drive_connection(
    http3: &mut h3::server::Connection<h3_quinn::Connection, Bytes>,
    datagram_connection: &quinn::Connection,
    mut shutdown: watch::Receiver<bool>,
    runtime: ConnectionRuntime,
) -> Result<(), TransportError> {
    let ConnectionRuntime { mode, context, connection_id, peer_certificate_sha256, drain_timeout } =
        runtime;
    let registry = Arc::new(SessionRegistry::default());
    let mut requests = JoinSet::new();
    if *shutdown.borrow() {
        http3.shutdown(0).await?;
        return Ok(());
    }
    let result = loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    if let Err(error) = http3.shutdown(0).await {
                        break Err(error.into());
                    }
                    break Ok(());
                }
            },
            request = http3.accept() => match request {
                Ok(Some(resolver)) => {
                    let request_context = context.as_ref().map(|context| request::RequestContext {
                        config: context.config_snapshot(),
                        registry: registry.clone(),
                        quotas: context.quotas.clone(),
                        ip_registry: context.ip_registry.clone(),
                        address_pools: context.address_pools.clone(),
                        tun_sender: context.tun_tx.clone(),
                        dns_permits: context.dns_permits.clone(),
                        connection: datagram_connection.clone(),
                        connection_id: connection_id.unwrap_or_default(),
                        peer_certificate_sha256,
                        stats: context.stats.clone(),
                    });
                    requests.spawn(request::handle(resolver, request_mode(mode), request_context));
                }
                Ok(None) => break Ok(()),
                Err(error) => break Err(error.into()),
            },
            raw = datagram_connection.read_datagram() => {
                let raw = match raw {
                    Ok(raw) => raw,
                    Err(error) => break Err(TransportError::Datagram(error.to_string())),
                };
                let Ok(datagram) = datagram::decode(raw) else {
                    continue;
                };
                if context.is_some() {
                    forward_datagram(
                        &registry,
                        context.as_deref(),
                        connection_id.unwrap_or_default(),
                        datagram.stream_id,
                        datagram.payload,
                    );
                } else if mode == TransportMode::EchoDatagrams {
                    let encoded = match datagram::encode(datagram.stream_id, datagram.payload) {
                        Ok(encoded) => encoded,
                        Err(error) => break Err(TransportError::Datagram(error.to_string())),
                    };
                    if let Err(error) = datagram_connection.send_datagram(encoded) {
                        break Err(TransportError::Datagram(error.to_string()));
                    }
                }
            },
            completed = requests.join_next(), if !requests.is_empty() => {
                observe_request_result(completed, context.as_deref());
            }
        }
    };
    drain_request_tasks(&mut requests, drain_timeout, context.as_deref()).await;
    result
}

fn observe_request_result(
    result: Option<Result<Result<(), request::RequestError>, tokio::task::JoinError>>,
    context: Option<&TransportContext>,
) {
    let Some(context) = context else { return };
    match result {
        Some(Ok(Err(error))) => context.record_runtime_error(error.to_string()),
        Some(Err(error)) => context.record_runtime_error(error.to_string()),
        _ => {}
    }
}

async fn drain_request_tasks(
    requests: &mut JoinSet<Result<(), request::RequestError>>,
    drain_timeout: Duration,
    context: Option<&TransportContext>,
) {
    let drain = async {
        while let Some(result) = requests.join_next().await {
            observe_request_result(Some(result), context);
        }
    };
    if tokio::time::timeout(drain_timeout, drain).await.is_err() {
        requests.abort_all();
        while requests.join_next().await.is_some() {}
    }
}

fn forward_datagram(
    registry: &SessionRegistry,
    context: Option<&TransportContext>,
    connection_id: u64,
    stream_id: u64,
    payload: Bytes,
) {
    let Ok(datagram) = maskman_protocol::capsule::decode_datagram(&payload) else {
        return;
    };
    if datagram.context_id != 0 {
        return;
    }
    let payload = Bytes::copy_from_slice(datagram.payload);
    match registry.try_send(stream_id, payload.clone()) {
        Some(forwarded) => {
            if let Some(context) = context {
                context.stats.packet_result(forwarded);
            }
        }
        None => {
            if let Some(context) = context {
                if let Err(reason) = context.ip_registry.try_send(connection_id, stream_id, payload)
                {
                    if matches!(reason, crate::proxy::ip::IpDropReason::Destination) {
                        context.stats.packet_result(false);
                    }
                }
            }
        }
    }
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
