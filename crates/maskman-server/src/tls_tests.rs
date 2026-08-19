use std::{
    fs,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use quinn::{ClientConfig, Endpoint};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

use super::load_server_config_with_client_ca;
use crate::{TransportLimits, TransportMode, TransportServer};

#[tokio::test]
async fn required_mtls_rejects_anonymous_and_accepts_trusted_clients() {
    assert!(!handshake(true, false).await);
    assert!(handshake(true, true).await);
}

#[tokio::test]
async fn optional_mtls_allows_anonymous_tls_handshakes() {
    assert!(handshake(false, false).await);
}

async fn handshake(require_client_certificate: bool, send_client_certificate: bool) -> bool {
    let fixture = TlsFixture::new();
    let files = fixture.write_pem_files();
    let server_config = load_server_config_with_client_ca(
        &files.server_certificate,
        &files.server_key,
        Some(&files.ca_certificate),
        require_client_certificate,
    )
    .unwrap_or_else(|error| panic!("load mTLS server config: {error}"));
    let server = TransportServer::bind(
        SocketAddr::from(([127, 0, 0, 1], 0)),
        server_config,
        test_limits(),
        TransportMode::EchoDatagrams,
    )
    .unwrap_or_else(|error| panic!("bind mTLS test server: {error}"));
    let address = server
        .local_addr()
        .unwrap_or_else(|error| panic!("read mTLS test server address: {error}"));
    let shutdown = server.shutdown_handle();
    let task = tokio::spawn(server.run());

    let mut endpoint = Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0)))
        .unwrap_or_else(|error| panic!("bind mTLS test client: {error}"));
    endpoint.set_default_client_config(fixture.client_config(send_client_certificate));
    let result = endpoint
        .connect(address, "localhost")
        .unwrap_or_else(|error| panic!("start mTLS test connection: {error}"))
        .await;
    let accepted = match &result {
        Ok(connection) => {
            tokio::time::timeout(Duration::from_millis(200), connection.closed()).await.is_err()
        }
        Err(_) => false,
    };
    if accepted {
        let connection = result.as_ref().unwrap_or_else(|error| {
            panic!("accepted mTLS connection unexpectedly failed: {error}")
        });
        connection.close(0u32.into(), b"mTLS test complete");
    }
    endpoint.close(0u32.into(), b"mTLS test complete");
    shutdown.shutdown();
    task.await
        .unwrap_or_else(|error| panic!("join mTLS test server: {error}"))
        .unwrap_or_else(|error| panic!("run mTLS test server: {error}"));
    accepted
}

struct TlsFixture {
    ca: Certificate,
    server: Certificate,
    server_key: KeyPair,
    client: Certificate,
    client_key: KeyPair,
}

impl TlsFixture {
    fn new() -> Self {
        let ca_key =
            KeyPair::generate().unwrap_or_else(|error| panic!("generate test CA key: {error}"));
        let mut ca_params = CertificateParams::new(Vec::<String>::new())
            .unwrap_or_else(|error| panic!("build test CA parameters: {error}"));
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca = ca_params
            .self_signed(&ca_key)
            .unwrap_or_else(|error| panic!("generate test CA: {error}"));

        let server_key =
            KeyPair::generate().unwrap_or_else(|error| panic!("generate server key: {error}"));
        let mut server_params = CertificateParams::new(vec!["localhost".to_owned()])
            .unwrap_or_else(|error| panic!("build server certificate parameters: {error}"));
        server_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server = server_params
            .signed_by(&server_key, &ca, &ca_key)
            .unwrap_or_else(|error| panic!("sign server certificate: {error}"));

        let client_key =
            KeyPair::generate().unwrap_or_else(|error| panic!("generate client key: {error}"));
        let mut client_params = CertificateParams::new(vec!["maskman-client".to_owned()])
            .unwrap_or_else(|error| panic!("build client certificate parameters: {error}"));
        client_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let client = client_params
            .signed_by(&client_key, &ca, &ca_key)
            .unwrap_or_else(|error| panic!("sign client certificate: {error}"));

        Self { ca, server, server_key, client, client_key }
    }

    fn write_pem_files(&self) -> PemFiles {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
        let root =
            std::env::temp_dir().join(format!("maskman-mtls-{}-{nonce}", std::process::id()));
        fs::create_dir(&root).unwrap_or_else(|error| {
            panic!("create mTLS test directory {}: {error}", root.display())
        });
        let files = PemFiles {
            server_certificate: root.join("server.pem"),
            server_key: root.join("server-key.pem"),
            ca_certificate: root.join("ca.pem"),
            root,
        };
        fs::write(&files.server_certificate, self.server.pem())
            .unwrap_or_else(|error| panic!("write server certificate: {error}"));
        fs::write(&files.server_key, self.server_key.serialize_pem())
            .unwrap_or_else(|error| panic!("write server key: {error}"));
        fs::write(&files.ca_certificate, self.ca.pem())
            .unwrap_or_else(|error| panic!("write CA certificate: {error}"));
        files
    }

    fn client_config(&self, send_client_certificate: bool) -> ClientConfig {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from(self.ca.der().to_vec()))
            .unwrap_or_else(|error| panic!("add mTLS test CA: {error}"));
        let builder = rustls::ClientConfig::builder().with_root_certificates(roots);
        let mut crypto = if send_client_certificate {
            builder
                .with_client_auth_cert(
                    vec![CertificateDer::from(self.client.der().to_vec())],
                    PrivatePkcs8KeyDer::from(self.client_key.serialize_der()).into(),
                )
                .unwrap_or_else(|error| panic!("build authenticated client TLS config: {error}"))
        } else {
            builder.with_no_client_auth()
        };
        crypto.alpn_protocols = vec![b"h3".to_vec()];
        let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
            .unwrap_or_else(|error| panic!("build mTLS test QUIC config: {error}"));
        ClientConfig::new(Arc::new(quic_crypto))
    }
}

struct PemFiles {
    root: PathBuf,
    server_certificate: PathBuf,
    server_key: PathBuf,
    ca_certificate: PathBuf,
}

impl Drop for PemFiles {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn test_limits() -> TransportLimits {
    TransportLimits {
        max_connections: 4,
        max_requests_per_connection: 4,
        max_header_bytes: 16_384,
        idle_timeout: Duration::from_secs(2),
        drain_timeout: Duration::from_secs(1),
    }
}
