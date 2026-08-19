use std::{path::Path, sync::Arc};

use rustls::{
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
    server::WebPkiClientVerifier,
    RootCertStore,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TlsError {
    #[error("TLS certificate file contains no certificates: {0}")]
    EmptyCertificateChain(String),
    #[error("TLS private key file contains no private key: {0}")]
    MissingPrivateKey(String),
    #[error("failed to read TLS PEM {path}: {source}")]
    Pem { path: String, source: rustls::pki_types::pem::Error },
    #[error("invalid TLS certificate or key: {0}")]
    Certificate(#[from] rustls::Error),
    #[error("failed to adapt TLS configuration to Quinn: {0}")]
    Quinn(String),
    #[error("failed to build client certificate verifier: {0}")]
    ClientVerifier(String),
}

pub fn load_server_config(
    certificate_file: &Path,
    private_key_file: &Path,
) -> Result<quinn::ServerConfig, TlsError> {
    load_server_config_with_client_ca(certificate_file, private_key_file, None)
}

pub fn load_server_config_with_client_ca(
    certificate_file: &Path,
    private_key_file: &Path,
    client_ca_file: Option<&Path>,
) -> Result<quinn::ServerConfig, TlsError> {
    let certificates = load_certificates(certificate_file)?;
    let private_key = load_private_key(private_key_file)?;
    let builder = rustls::ServerConfig::builder();
    let mut crypto = match client_ca_file {
        Some(path) => {
            let roots = load_roots(path)?;
            let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
                .allow_unauthenticated()
                .build()
                .map_err(|error| TlsError::ClientVerifier(error.to_string()))?;
            builder
                .with_client_cert_verifier(verifier)
                .with_single_cert(certificates, private_key)?
        }
        None => builder.with_no_client_auth().with_single_cert(certificates, private_key)?,
    };
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(crypto)
        .map_err(|error| TlsError::Quinn(error.to_string()))?;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(quic_crypto)))
}

fn load_roots(path: &Path) -> Result<RootCertStore, TlsError> {
    let certificates = load_certificates(path)?;
    let mut roots = RootCertStore::empty();
    for certificate in certificates {
        roots.add(certificate).map_err(TlsError::Certificate)?;
    }
    Ok(roots)
}

fn load_certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let certificates = CertificateDer::pem_file_iter(path)
        .map_err(|source| TlsError::Pem { path: path.display().to_string(), source })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| TlsError::Pem { path: path.display().to_string(), source })?;
    if certificates.is_empty() {
        return Err(TlsError::EmptyCertificateChain(path.display().to_string()));
    }
    Ok(certificates)
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, TlsError> {
    PrivateKeyDer::from_pem_file(path).map_err(|source| match source {
        rustls::pki_types::pem::Error::NoItemsFound => {
            TlsError::MissingPrivateKey(path.display().to_string())
        }
        source => TlsError::Pem { path: path.display().to_string(), source },
    })
}
