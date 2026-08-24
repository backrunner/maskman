use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use http::HeaderMap;
use maskman_config::{AuthMode, CompiledConfig};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub id: String,
    pub roles: Vec<String>,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    #[error("authentication credentials are required")]
    Missing,
    #[error("authentication credentials are invalid")]
    Invalid,
    #[error("authentication credentials have expired")]
    Expired,
    #[error("authenticated principal is not configured")]
    UnknownPrincipal,
}

#[derive(Clone)]
pub struct Authenticator {
    config: Arc<CompiledConfig>,
}

impl Authenticator {
    pub fn new(config: Arc<CompiledConfig>) -> Self {
        Self { config }
    }

    pub fn authenticate(
        &self,
        headers: &HeaderMap,
        peer_certificate_sha256: Option<[u8; 32]>,
    ) -> Result<Principal, AuthError> {
        if matches!(self.config.auth_mode, AuthMode::None) && !self.config.auth_required {
            return Ok(Principal {
                id: "anonymous".to_owned(),
                roles: self.config.roles.keys().cloned().collect(),
            });
        }
        let bearer = self.bearer(headers);
        let credentials =
            bearer.or_else(|bearer_error| self.basic(headers).map_err(|_| bearer_error));
        let certificate = peer_certificate_sha256.and_then(|digest| self.certificate(digest));
        match self.config.auth_mode {
            AuthMode::Bearer => credentials,
            AuthMode::Mtls => certificate.ok_or(AuthError::Missing),
            AuthMode::BearerOrMtls => match credentials {
                Ok(principal) => Ok(principal),
                Err(error) => certificate.ok_or(error),
            },
            AuthMode::None => Err(AuthError::Missing),
        }
    }

    fn bearer(&self, headers: &HeaderMap) -> Result<Principal, AuthError> {
        let value = headers
            .get(http::header::AUTHORIZATION)
            .ok_or(AuthError::Missing)?
            .to_str()
            .map_err(|_| AuthError::Invalid)?;
        let Some(encoded) = value.strip_prefix("Bearer ") else {
            return Err(AuthError::Invalid);
        };
        let Some(encoded) = encoded.strip_prefix("mm_") else {
            return Err(AuthError::Invalid);
        };
        // The ID may contain underscores and the base64url secret may contain
        // underscores too. Match a configured ID prefix instead of splitting
        // at an attacker-controlled delimiter; longest wins for nested IDs.
        let (_token_id, secret, token) = self
            .config
            .token_principals
            .iter()
            .filter_map(|(token_id, token)| {
                encoded
                    .strip_prefix(token_id.as_str())
                    .and_then(|suffix| suffix.strip_prefix('_'))
                    .filter(|secret| !secret.is_empty() && secret.len() <= 512)
                    .map(|secret| (token_id.as_str(), secret, token))
            })
            .max_by_key(|(token_id, _, _)| token_id.len())
            .ok_or(AuthError::Invalid)?;
        let digest = Sha256::digest(secret.as_bytes());
        if digest.as_slice().ct_eq(&token.secret_sha256).unwrap_u8() != 1 {
            return Err(AuthError::Invalid);
        }
        if token.expires_at.is_some_and(|expiry| expiry <= time::OffsetDateTime::now_utc()) {
            return Err(AuthError::Expired);
        }
        self.principal(&token.principal)
    }

    fn basic(&self, headers: &HeaderMap) -> Result<Principal, AuthError> {
        let value = headers
            .get(http::header::AUTHORIZATION)
            .ok_or(AuthError::Missing)?
            .to_str()
            .map_err(|_| AuthError::Invalid)?;
        let encoded = value.strip_prefix("Basic ").ok_or(AuthError::Invalid)?;
        let decoded = BASE64.decode(encoded).map_err(|_| AuthError::Invalid)?;
        let credentials = std::str::from_utf8(&decoded).map_err(|_| AuthError::Invalid)?;
        let (token_id, secret) = credentials.split_once(':').ok_or(AuthError::Invalid)?;
        if token_id.is_empty() || secret.is_empty() || secret.len() > 512 {
            return Err(AuthError::Invalid);
        }
        let token = self
            .config
            .token_principals
            .iter()
            .find(|(configured_id, _)| configured_id.as_str() == token_id)
            .map(|(_, token)| token)
            .ok_or(AuthError::Invalid)?;
        let digest = Sha256::digest(secret.as_bytes());
        if digest.as_slice().ct_eq(&token.secret_sha256).unwrap_u8() != 1 {
            return Err(AuthError::Invalid);
        }
        if token.expires_at.is_some_and(|expiry| expiry <= time::OffsetDateTime::now_utc()) {
            return Err(AuthError::Expired);
        }
        self.principal(&token.principal)
    }

    fn certificate(&self, digest: [u8; 32]) -> Option<Principal> {
        let key = digest.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
        let principal = self.config.certificate_principals.get(&key)?;
        self.principal(principal).ok()
    }

    fn principal(&self, id: &str) -> Result<Principal, AuthError> {
        let roles = self.config.principals.get(id).ok_or(AuthError::UnknownPrincipal)?;
        Ok(Principal { id: id.to_owned(), roles: roles.clone() })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use http::HeaderMap;
    use maskman_config::model::ConfigDocument;
    use sha2::{Digest, Sha256};

    use super::{AuthError, Authenticator};

    fn auth_with_token(
        token_id: &str,
        secret_value: &str,
        expires_at: Option<&str>,
    ) -> Authenticator {
        let secret = Sha256::digest(secret_value.as_bytes());
        let digest = secret.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
        let mut document = ConfigDocument::default();
        document.auth.principals.push(maskman_config::model::PrincipalConfig {
            id: "client".into(),
            roles: vec!["role".into()],
            certificate_sha256: Vec::new(),
        });
        document.auth.bearer_tokens.push(maskman_config::model::BearerTokenConfig {
            id: token_id.into(),
            principal: "client".into(),
            secret_sha256: digest,
            expires_at: expires_at.map(str::to_owned),
            enabled: true,
        });
        document.policy.roles.push(maskman_config::model::RoleConfig {
            name: "role".into(),
            capabilities: vec!["connect-udp".into()],
            allow_destinations: vec!["8.8.8.8/32".into()],
            deny_destinations: Vec::new(),
            deny_private: true,
            allowed_ip_protocols: Vec::new(),
            limits: Default::default(),
        });
        let config = maskman_config::compile_document(&document, std::path::Path::new("."))
            .unwrap_or_else(|error| panic!("compile auth test config: {error}"));
        Authenticator::new(Arc::new(config))
    }

    fn auth(expires_at: Option<&str>) -> Authenticator {
        auth_with_token("token", "secret", expires_at)
    }

    #[test]
    fn bearer_secret_is_verified_without_logging_or_plaintext_config() {
        let authenticator = auth(None);
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            "Bearer mm_token_secret".parse().unwrap_or_else(|error| panic!("header: {error}")),
        );
        let principal = authenticator
            .authenticate(&headers, None)
            .unwrap_or_else(|error| panic!("authenticate: {error}"));
        assert_eq!(principal.id, "client");
        headers.insert(
            "authorization",
            "Bearer mm_token_wrong".parse().unwrap_or_else(|error| panic!("header: {error}")),
        );
        assert_eq!(authenticator.authenticate(&headers, None), Err(AuthError::Invalid));
    }

    #[test]
    fn basic_username_and_password_are_verified_for_masque_clients() {
        let authenticator = auth(None);
        let encoded = BASE64.encode("token:secret");
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            format!("Basic {encoded}").parse().unwrap_or_else(|error| panic!("header: {error}")),
        );
        let principal = authenticator
            .authenticate(&headers, None)
            .unwrap_or_else(|error| panic!("authenticate: {error}"));
        assert_eq!(principal.id, "client");
    }

    #[test]
    fn expired_bearer_is_rejected() {
        let authenticator = auth(Some("2000-01-01T00:00:00Z"));
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            "Bearer mm_token_secret".parse().unwrap_or_else(|error| panic!("header: {error}")),
        );
        assert_eq!(authenticator.authenticate(&headers, None), Err(AuthError::Expired));
    }

    #[test]
    fn token_ids_and_secrets_may_contain_underscores() {
        let authenticator = auth_with_token("token_with", "secret_under_score", None);
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            "Bearer mm_token_with_secret_under_score"
                .parse()
                .unwrap_or_else(|error| panic!("header: {error}")),
        );
        assert_eq!(
            authenticator
                .authenticate(&headers, None)
                .unwrap_or_else(|error| panic!("authenticate: {error}"))
                .id,
            "client"
        );
    }
}
