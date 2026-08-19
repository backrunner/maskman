use semver::Version;
use serde::Deserialize;

use crate::{
    target_triple,
    verify::{decode_public_key, download_limited, verify_checksum, verify_signature},
    UpdateClientState, UpdateError, VerifiedArtifact, API_BASE,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseInfo {
    pub version: Version,
    pub tag: String,
    pub target: String,
    pub archive_url: String,
    pub checksum_url: String,
    pub signature_url: String,
}

pub struct UpdateClient {
    pub(crate) state: UpdateClientState,
}

impl UpdateClient {
    pub fn new(repository: &str, current_version: &str) -> Result<Self, UpdateError> {
        let repository = validate_repository(repository)?;
        let current_version = Version::parse(current_version)
            .map_err(|_| UpdateError::InvalidVersion(current_version.into()))?;
        let key = decode_public_key(crate::RELEASE_PUBLIC_KEY_HEX)?;
        let http = reqwest::blocking::Client::builder()
            .user_agent(format!("maskman/{current_version}"))
            .timeout(std::time::Duration::from_secs(20))
            .build()
            .map_err(|error| UpdateError::Http(error.to_string()))?;
        Ok(Self {
            state: UpdateClientState {
                repository,
                current_version,
                target: target_triple()?.into(),
                api_base: API_BASE.into(),
                public_key: key,
                http,
            },
        })
    }

    pub fn with_api_base(mut self, api_base: impl Into<String>) -> Self {
        self.state.api_base = api_base.into();
        self
    }

    pub fn with_public_key(mut self, public_key: ed25519_dalek::VerifyingKey) -> Self {
        self.state.public_key = public_key;
        self
    }

    pub fn current_version(&self) -> &Version {
        &self.state.current_version
    }

    pub fn target(&self) -> &str {
        &self.state.target
    }

    pub fn latest(&self, requested: Option<&str>) -> Result<ReleaseInfo, UpdateError> {
        let requested = requested
            .map(|value| {
                Version::parse(value).map_err(|_| UpdateError::InvalidVersion(value.into()))
            })
            .transpose()?;
        let url = format!(
            "{}/repos/{}/releases",
            self.state.api_base.trim_end_matches('/'),
            self.state.repository
        );
        let releases = self
            .state
            .http
            .get(url)
            .send()
            .map_err(|error| UpdateError::Http(error.to_string()))?
            .error_for_status()
            .map_err(|error| UpdateError::Http(error.to_string()))?
            .json::<Vec<GithubRelease>>()
            .map_err(|error| UpdateError::Http(error.to_string()))?;
        let mut candidates = releases
            .iter()
            .filter_map(|release| release_info(release, &self.state.target, requested.as_ref()))
            .collect::<Vec<_>>();
        candidates.sort_by(|left, right| left.version.cmp(&right.version));
        candidates.pop().ok_or_else(|| {
            UpdateError::ReleaseNotFound(
                requested.map_or_else(|| "latest".into(), |value| value.to_string()),
                self.state.target.clone(),
            )
        })
    }

    pub fn download_verified(
        &self,
        release: &ReleaseInfo,
    ) -> Result<VerifiedArtifact, UpdateError> {
        let archive =
            download_limited(&self.state.http, &release.archive_url, crate::MAX_DOWNLOAD_BYTES)?;
        let checksum = download_limited(&self.state.http, &release.checksum_url, 8 * 1024)?;
        verify_checksum(&archive, &checksum)?;
        let signature = download_limited(&self.state.http, &release.signature_url, 8 * 1024)?;
        verify_signature(&archive, &signature, &self.state.public_key)?;
        Ok(VerifiedArtifact { version: release.version.clone(), archive })
    }
}

fn release_info(
    release: &GithubRelease,
    target: &str,
    requested: Option<&Version>,
) -> Option<ReleaseInfo> {
    if release.draft || (requested.is_none() && release.prerelease) {
        return None;
    }
    let version = Version::parse(release.tag_name.trim_start_matches('v')).ok()?;
    if requested.is_some_and(|value| value != &version) {
        return None;
    }
    let archive_name = format!("maskman-{version}-{target}.tar.gz");
    let checksum_name = format!("{archive_name}.sha256");
    let signature_name = format!("{archive_name}.sig");
    let asset = |name: &str| {
        release
            .assets
            .iter()
            .find(|asset| asset.name == name)
            .map(|asset| asset.browser_download_url.clone())
    };
    Some(ReleaseInfo {
        version,
        tag: release.tag_name.clone(),
        target: target.into(),
        archive_url: asset(&archive_name)?,
        checksum_url: asset(&checksum_name)?,
        signature_url: asset(&signature_name)?,
    })
}

fn validate_repository(repository: &str) -> Result<String, UpdateError> {
    let mut parts = repository.split('/');
    let owner = parts.next().unwrap_or_default();
    let name = parts.next().unwrap_or_default();
    if parts.next().is_some()
        || owner.is_empty()
        || name.is_empty()
        || !owner.chars().all(|value| value.is_ascii_alphanumeric() || "-_.".contains(value))
        || !name.chars().all(|value| value.is_ascii_alphanumeric() || "-_.".contains(value))
    {
        return Err(UpdateError::InvalidRepository(repository.into()));
    }
    Ok(repository.into())
}

#[derive(Debug, Deserialize)]
struct GithubRelease {
    tag_name: String,
    draft: bool,
    prerelease: bool,
    assets: Vec<GithubAsset>,
}

#[derive(Debug, Deserialize)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
}
