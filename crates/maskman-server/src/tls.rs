use std::{path::Path, sync::Arc};

use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
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
}

pub fn load_server_config(
    certificate_file: &Path,
    private_key_file: &Path,
) -> Result<quinn::ServerConfig, TlsError> {
    let certificates = load_certificates(certificate_file)?;
    let private_key = load_private_key(private_key_file)?;
    let mut crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)?;
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(crypto)
        .map_err(|error| TlsError::Quinn(error.to_string()))?;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(quic_crypto)))
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
