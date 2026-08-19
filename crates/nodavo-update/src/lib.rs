//! Signed release verification and effect-isolated update orchestration.
//!
//! The crate deliberately has no concrete HTTP client, filesystem writer,
//! process launcher, installer, or signing-key API. Network, staging,
//! persistence, and platform installation remain behind contracts so policy
//! and crash recovery can be tested without executing downloaded content.

mod runtime;
mod supervision;

pub use runtime::*;
pub use supervision::*;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, VerifyingKey};
use semver::Version;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Current signed-manifest schema.
pub const MANIFEST_SCHEMA_VERSION: u16 = 1;
/// Maximum JSON envelope accepted before parsing or allocation.
pub const MAX_MANIFEST_BYTES: usize = 16 * 1024;
/// Maximum artifact size described by a manifest (16 GiB).
pub const MAX_ARTIFACT_BYTES: u64 = 16 * 1024 * 1024 * 1024;
/// Maximum encoded HTTPS artifact URL length.
pub const MAX_ARTIFACT_URL_BYTES: usize = 2_048;

const MAX_PRODUCT_BYTES: usize = 64;
const MAX_TARGET_COMPONENT_BYTES: usize = 32;
const MAX_VERSION_BYTES: usize = 128;
const MAX_INSTALL_IDENTIFIER_BYTES: usize = 255;
const MAX_SIGNATURE_TEXT_BYTES: usize = 96;
const SHA256_HEX_BYTES: usize = 64;
const CANONICAL_DOMAIN: &[u8] = b"NODAVO RELEASE MANIFEST\0";

/// Authenticated release metadata.
///
/// Fields remain private so callers cannot accidentally mutate the data after
/// signature and policy verification.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ReleaseManifest {
    schema: u16,
    product: String,
    channel: String,
    platform: String,
    arch: String,
    version: Version,
    minimum_version: Version,
    artifact_url: String,
    artifact_size: u64,
    artifact_sha256: String,
    rollback_epoch: u64,
}

impl ReleaseManifest {
    #[must_use]
    pub const fn schema(&self) -> u16 {
        self.schema
    }

    #[must_use]
    pub fn product(&self) -> &str {
        &self.product
    }

    #[must_use]
    pub fn channel(&self) -> &str {
        &self.channel
    }

    #[must_use]
    pub fn platform(&self) -> &str {
        &self.platform
    }

    #[must_use]
    pub fn arch(&self) -> &str {
        &self.arch
    }

    #[must_use]
    pub const fn version(&self) -> &Version {
        &self.version
    }

    /// Oldest installed version allowed to consume this update directly.
    #[must_use]
    pub const fn minimum_version(&self) -> &Version {
        &self.minimum_version
    }

    #[must_use]
    pub fn artifact_url(&self) -> &str {
        &self.artifact_url
    }

    #[must_use]
    pub const fn artifact_size(&self) -> u64 {
        self.artifact_size
    }

    #[must_use]
    pub const fn rollback_epoch(&self) -> u64 {
        self.rollback_epoch
    }

    /// Returns the signed SHA-256 digest as bytes after validating all fields.
    ///
    /// # Errors
    ///
    /// Returns an error when any manifest field is invalid or outside its hard
    /// bound.
    pub fn artifact_sha256(&self) -> Result<[u8; 32], UpdateError> {
        self.validate()
    }

    /// Produces the deterministic, domain-separated signature payload.
    ///
    /// This representation is independent of JSON whitespace and field order.
    ///
    /// # Errors
    ///
    /// Returns an error when any field is invalid or outside its hard bound.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, UpdateError> {
        let digest = self.validate()?;
        let version = self.version.to_string();
        let minimum_version = self.minimum_version.to_string();
        let mut canonical = Vec::with_capacity(512);
        canonical.extend_from_slice(CANONICAL_DOMAIN);
        canonical.extend_from_slice(&self.schema.to_be_bytes());
        append_string(&mut canonical, &self.product)?;
        append_string(&mut canonical, &self.channel)?;
        append_string(&mut canonical, &self.platform)?;
        append_string(&mut canonical, &self.arch)?;
        append_string(&mut canonical, &version)?;
        append_string(&mut canonical, &minimum_version)?;
        append_string(&mut canonical, &self.artifact_url)?;
        canonical.extend_from_slice(&self.artifact_size.to_be_bytes());
        canonical.extend_from_slice(&digest);
        canonical.extend_from_slice(&self.rollback_epoch.to_be_bytes());
        Ok(canonical)
    }

    fn validate(&self) -> Result<[u8; 32], UpdateError> {
        if self.schema != MANIFEST_SCHEMA_VERSION {
            return Err(UpdateError::UnsupportedSchema);
        }
        validate_token(&self.product, MAX_PRODUCT_BYTES)?;
        validate_token(&self.channel, MAX_TARGET_COMPONENT_BYTES)?;
        validate_token(&self.platform, MAX_TARGET_COMPONENT_BYTES)?;
        validate_token(&self.arch, MAX_TARGET_COMPONENT_BYTES)?;

        let version = self.version.to_string();
        let minimum_version = self.minimum_version.to_string();
        if version.len() > MAX_VERSION_BYTES
            || minimum_version.len() > MAX_VERSION_BYTES
            || self.version < self.minimum_version
        {
            return Err(UpdateError::InvalidVersionBounds);
        }
        validate_https_url(&self.artifact_url)?;
        if self.artifact_size == 0 || self.artifact_size > MAX_ARTIFACT_BYTES {
            return Err(UpdateError::ArtifactSizeOutOfBounds);
        }
        parse_sha256(&self.artifact_sha256)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedManifest {
    manifest: ReleaseManifest,
    signature: String,
}

/// Local target and installed-version policy for an update check.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationPolicy {
    product: String,
    channel: String,
    platform: String,
    arch: String,
    install_identity: String,
    installed_version: Version,
}

impl VerificationPolicy {
    /// Creates a strict policy for exactly one product, channel, target, and
    /// platform bundle/package identity.
    ///
    /// # Errors
    ///
    /// Returns [`UpdateError::InvalidMetadata`] for invalid identifiers.
    pub fn new(
        product: impl Into<String>,
        channel: impl Into<String>,
        platform: impl Into<String>,
        arch: impl Into<String>,
        install_identity: impl Into<String>,
        installed_version: Version,
    ) -> Result<Self, UpdateError> {
        let policy = Self {
            product: product.into(),
            channel: channel.into(),
            platform: platform.into(),
            arch: arch.into(),
            install_identity: install_identity.into(),
            installed_version,
        };
        validate_token(&policy.product, MAX_PRODUCT_BYTES)?;
        validate_token(&policy.channel, MAX_TARGET_COMPONENT_BYTES)?;
        validate_token(&policy.platform, MAX_TARGET_COMPONENT_BYTES)?;
        validate_token(&policy.arch, MAX_TARGET_COMPONENT_BYTES)?;
        validate_install_identifier(&policy.install_identity)?;
        if policy.installed_version.to_string().len() > MAX_VERSION_BYTES {
            return Err(UpdateError::InvalidVersionBounds);
        }
        Ok(policy)
    }

    #[must_use]
    pub const fn installed_version(&self) -> &Version {
        &self.installed_version
    }

    /// Locally pinned bundle or package identity allowed for this target.
    #[must_use]
    pub fn install_identity(&self) -> &str {
        &self.install_identity
    }
}

/// Persisted rollback floor supplied by the host application.
///
/// This crate does not write persistence. The host should advance this state
/// only after a verified artifact is successfully installed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RollbackState {
    minimum_epoch: u64,
    minimum_version: Version,
}

impl RollbackState {
    #[must_use]
    pub const fn new(minimum_epoch: u64, minimum_version: Version) -> Self {
        Self {
            minimum_epoch,
            minimum_version,
        }
    }

    #[must_use]
    pub const fn minimum_epoch(&self) -> u64 {
        self.minimum_epoch
    }

    #[must_use]
    pub const fn minimum_version(&self) -> &Version {
        &self.minimum_version
    }
}

/// Offline verifier pinned to a release public key and one target policy.
#[derive(Clone, Debug)]
pub struct ReleaseVerifier {
    release_key: VerifyingKey,
    policy: VerificationPolicy,
}

impl ReleaseVerifier {
    #[must_use]
    pub const fn new(release_key: VerifyingKey, policy: VerificationPolicy) -> Self {
        Self {
            release_key,
            policy,
        }
    }

    /// Parses and verifies one bounded JSON envelope without network access.
    ///
    /// # Errors
    ///
    /// Rejects malformed, oversized, incorrectly signed, mismatched, stale, or
    /// rollback release metadata.
    pub fn verify_json(
        &self,
        envelope_json: &[u8],
        rollback: &RollbackState,
    ) -> Result<VerifiedRelease, UpdateError> {
        if envelope_json.is_empty() || envelope_json.len() > MAX_MANIFEST_BYTES {
            return Err(UpdateError::ManifestTooLarge);
        }
        let signed: SignedManifest =
            serde_json::from_slice(envelope_json).map_err(|_| UpdateError::MalformedManifest)?;
        let digest = signed.manifest.validate()?;
        let canonical = signed.manifest.canonical_bytes()?;
        let signature = parse_signature(&signed.signature)?;
        self.release_key
            .verify_strict(&canonical, &signature)
            .map_err(|_| UpdateError::InvalidSignature)?;
        self.verify_policy(&signed.manifest, rollback)?;

        Ok(VerifiedRelease {
            manifest: signed.manifest,
            artifact_sha256: digest,
            install_identity: self.policy.install_identity.clone(),
            installed_version: self.policy.installed_version.clone(),
        })
    }

    fn verify_policy(
        &self,
        manifest: &ReleaseManifest,
        rollback: &RollbackState,
    ) -> Result<(), UpdateError> {
        if manifest.product != self.policy.product
            || manifest.channel != self.policy.channel
            || manifest.platform != self.policy.platform
            || manifest.arch != self.policy.arch
        {
            return Err(UpdateError::TargetMismatch);
        }
        if manifest.version <= self.policy.installed_version {
            return Err(UpdateError::TargetNotNewer);
        }
        if self.policy.installed_version < manifest.minimum_version {
            return Err(UpdateError::CurrentVersionUnsupported);
        }
        if manifest.rollback_epoch < rollback.minimum_epoch
            || manifest.version < rollback.minimum_version
        {
            return Err(UpdateError::RollbackRejected);
        }
        Ok(())
    }
}

/// Authenticated release metadata returned by [`ReleaseVerifier`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedRelease {
    manifest: ReleaseManifest,
    artifact_sha256: [u8; 32],
    install_identity: String,
    installed_version: Version,
}

impl VerifiedRelease {
    #[must_use]
    pub const fn manifest(&self) -> &ReleaseManifest {
        &self.manifest
    }

    #[must_use]
    pub const fn artifact_sha256(&self) -> &[u8; 32] {
        &self.artifact_sha256
    }

    /// Locally pinned install identity carried from the verification policy.
    #[must_use]
    pub fn install_identity(&self) -> &str {
        &self.install_identity
    }

    /// Locally authenticated version that consumed the signed manifest.
    #[must_use]
    pub const fn installed_version(&self) -> &Version {
        &self.installed_version
    }

    /// Creates a bounded streaming verifier for bytes downloaded by the host.
    #[must_use]
    pub fn artifact_verifier(&self) -> ArtifactVerifier {
        ArtifactVerifier {
            expected_size: self.manifest.artifact_size,
            expected_digest: self.artifact_sha256,
            observed_size: 0,
            hasher: Sha256::new(),
            rejected: false,
        }
    }

    /// Computes the rollback floor to persist after a successful installation.
    ///
    /// Merely verifying or downloading a release must not advance this state.
    #[must_use]
    pub fn rollback_state_after_install(&self, previous: &RollbackState) -> RollbackState {
        RollbackState {
            minimum_epoch: previous.minimum_epoch.max(self.manifest.rollback_epoch),
            minimum_version: previous
                .minimum_version
                .clone()
                .max(self.manifest.version.clone()),
        }
    }
}

/// Incremental size and SHA-256 verifier for an externally downloaded artifact.
#[derive(Clone, Debug)]
pub struct ArtifactVerifier {
    expected_size: u64,
    expected_digest: [u8; 32],
    observed_size: u64,
    hasher: Sha256,
    rejected: bool,
}

impl ArtifactVerifier {
    /// Number of bytes incorporated so far.
    #[must_use]
    pub const fn observed_size(&self) -> u64 {
        self.observed_size
    }

    /// Adds one downloaded chunk without retaining artifact contents.
    ///
    /// # Errors
    ///
    /// Returns an error if the signed artifact length would be exceeded.
    pub fn update(&mut self, chunk: &[u8]) -> Result<(), UpdateError> {
        if self.rejected {
            return Err(UpdateError::ArtifactSizeMismatch);
        }
        let chunk_len =
            u64::try_from(chunk.len()).map_err(|_| UpdateError::ArtifactSizeMismatch)?;
        let Some(next_size) = self.observed_size.checked_add(chunk_len) else {
            self.rejected = true;
            return Err(UpdateError::ArtifactSizeMismatch);
        };
        if next_size > self.expected_size {
            self.rejected = true;
            return Err(UpdateError::ArtifactSizeMismatch);
        }
        self.hasher.update(chunk);
        self.observed_size = next_size;
        Ok(())
    }

    /// Finishes verification after the host reaches end-of-stream.
    ///
    /// # Errors
    ///
    /// Returns an error unless both the exact signed size and SHA-256 digest
    /// match.
    pub fn finish(self) -> Result<(), UpdateError> {
        if self.rejected || self.observed_size != self.expected_size {
            return Err(UpdateError::ArtifactSizeMismatch);
        }
        let observed: [u8; 32] = self.hasher.finalize().into();
        if observed != self.expected_digest {
            return Err(UpdateError::ArtifactDigestMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum UpdateError {
    #[error("the manifest envelope is empty or exceeds its hard size limit")]
    ManifestTooLarge,
    #[error("the manifest envelope is malformed or contains unknown fields")]
    MalformedManifest,
    #[error("the manifest schema is unsupported")]
    UnsupportedSchema,
    #[error("manifest target metadata is invalid")]
    InvalidMetadata,
    #[error("manifest version bounds are invalid")]
    InvalidVersionBounds,
    #[error("the artifact URL is not an acceptable absolute HTTPS URL")]
    InsecureArtifactUrl,
    #[error("the artifact size is outside the supported range")]
    ArtifactSizeOutOfBounds,
    #[error("the artifact SHA-256 digest is not canonical lowercase hexadecimal")]
    InvalidArtifactDigest,
    #[error("the manifest signature encoding is invalid")]
    InvalidSignatureEncoding,
    #[error("the manifest signature is invalid")]
    InvalidSignature,
    #[error("the manifest product, channel, platform, or architecture does not match")]
    TargetMismatch,
    #[error("the signed release is not newer than the installed version")]
    TargetNotNewer,
    #[error("the installed version cannot safely consume this update")]
    CurrentVersionUnsupported,
    #[error("the signed release is below the persisted rollback floor")]
    RollbackRejected,
    #[error("the downloaded artifact size does not match the signed size")]
    ArtifactSizeMismatch,
    #[error("the downloaded artifact SHA-256 does not match the signed digest")]
    ArtifactDigestMismatch,
}

fn validate_token(value: &str, max_bytes: usize) -> Result<(), UpdateError> {
    if value.is_empty()
        || value.len() > max_bytes
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"-._".contains(&byte)
        })
    {
        return Err(UpdateError::InvalidMetadata);
    }
    Ok(())
}

fn validate_install_identifier(value: &str) -> Result<(), UpdateError> {
    if value.is_empty()
        || value.len() > MAX_INSTALL_IDENTIFIER_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_'))
    {
        return Err(UpdateError::InvalidMetadata);
    }
    Ok(())
}

fn validate_https_url(value: &str) -> Result<(), UpdateError> {
    if value.len() > MAX_ARTIFACT_URL_BYTES
        || !value.is_ascii()
        || !value.starts_with("https://")
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ' || byte == b'\\')
        || value.contains('#')
    {
        return Err(UpdateError::InsecureArtifactUrl);
    }

    let remainder = &value["https://".len()..];
    let authority_end = remainder.find(['/', '?']).unwrap_or(remainder.len());
    let authority = &remainder[..authority_end];
    if authority.is_empty() || authority.contains('@') || !valid_authority(authority) {
        return Err(UpdateError::InsecureArtifactUrl);
    }
    Ok(())
}

fn valid_authority(authority: &str) -> bool {
    if let Some(bracketed) = authority.strip_prefix('[') {
        let Some(closing) = bracketed.find(']') else {
            return false;
        };
        let address = &bracketed[..closing];
        let suffix = &bracketed[closing + 1..];
        return !address.is_empty()
            && address
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() || byte == b':' || byte == b'.')
            && valid_optional_port(suffix);
    }

    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    !host.is_empty()
        && !host.starts_with('.')
        && !host.ends_with('.')
        && host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'.')
        && port
            .is_none_or(|port| !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()))
}

fn valid_optional_port(suffix: &str) -> bool {
    suffix.is_empty()
        || suffix
            .strip_prefix(':')
            .is_some_and(|port| !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()))
}

fn parse_sha256(value: &str) -> Result<[u8; 32], UpdateError> {
    if value.len() != SHA256_HEX_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(UpdateError::InvalidArtifactDigest);
    }
    let mut digest = [0_u8; 32];
    for (destination, pair) in digest.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        *destination = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
    }
    Ok(digest)
}

const fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => 0,
    }
}

fn parse_signature(value: &str) -> Result<Signature, UpdateError> {
    if value.is_empty() || value.len() > MAX_SIGNATURE_TEXT_BYTES {
        return Err(UpdateError::InvalidSignatureEncoding);
    }
    let decoded = STANDARD
        .decode(value)
        .map_err(|_| UpdateError::InvalidSignatureEncoding)?;
    let bytes: [u8; 64] = decoded
        .try_into()
        .map_err(|_| UpdateError::InvalidSignatureEncoding)?;
    Ok(Signature::from_bytes(&bytes))
}

fn append_string(destination: &mut Vec<u8>, value: &str) -> Result<(), UpdateError> {
    let length = u32::try_from(value.len()).map_err(|_| UpdateError::InvalidMetadata)?;
    destination.extend_from_slice(&length.to_be_bytes());
    destination.extend_from_slice(value.as_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest_json(signature: &str, artifact_size: u64) -> String {
        format!(
            r#"{{"manifest":{{"schema":1,"product":"nodavo","channel":"stable","platform":"macos","arch":"aarch64","version":"2.0.0","minimum_version":"1.0.0","artifact_url":"https://updates.example.test/nodavo.pkg","artifact_size":{artifact_size},"artifact_sha256":"785b0751fc2c53dc14a4ce3d800e69ef9ce1009eb327ccf458afe09c242c26c9","rollback_epoch":7}},"signature":"{signature}"}}"#
        )
    }

    #[test]
    fn canonical_form_ignores_json_field_order() {
        let first = manifest_json("invalid", 1_024);
        let second = r#"{"signature":"invalid","manifest":{"rollback_epoch":7,"artifact_sha256":"785b0751fc2c53dc14a4ce3d800e69ef9ce1009eb327ccf458afe09c242c26c9","artifact_size":1024,"artifact_url":"https://updates.example.test/nodavo.pkg","minimum_version":"1.0.0","version":"2.0.0","arch":"aarch64","platform":"macos","channel":"stable","product":"nodavo","schema":1}}"#;
        let first: SignedManifest = serde_json::from_str(&first).unwrap();
        let second: SignedManifest = serde_json::from_str(second).unwrap();

        assert_eq!(
            first.manifest.canonical_bytes().unwrap(),
            second.manifest.canonical_bytes().unwrap()
        );
    }

    #[test]
    fn signed_manifest_rejects_tampering_and_rollback() {
        // This fixture contains only a public verification key and signature;
        // the ephemeral signing key used to produce it is not retained.
        const PUBLIC_KEY: [u8; 32] = [
            144, 23, 104, 79, 80, 228, 113, 121, 75, 64, 212, 118, 181, 66, 104, 119, 204, 209, 47,
            37, 158, 74, 3, 241, 167, 101, 16, 168, 71, 18, 62, 104,
        ];
        const SIGNATURE: &str = "6guPkoFGJJ9Mh8CKc2tdfeC5+J+okxgxlQ3hPyQQW2PPkOHZzXg1S9JWCodhrkLUuHvwv4JyH4ZVp+cruJi6Ag==";

        let key = VerifyingKey::from_bytes(&PUBLIC_KEY).unwrap();
        let policy = VerificationPolicy::new(
            "nodavo",
            "stable",
            "macos",
            "aarch64",
            "dev.nodavo.macos",
            Version::parse("1.5.0").unwrap(),
        )
        .unwrap();
        let verifier = ReleaseVerifier::new(key, policy);
        let state = RollbackState::new(7, Version::parse("1.5.0").unwrap());

        let accepted = verifier.verify_json(manifest_json(SIGNATURE, 1_024).as_bytes(), &state);
        assert!(accepted.is_ok());
        assert_eq!(
            verifier.verify_json(manifest_json(SIGNATURE, 1_025).as_bytes(), &state),
            Err(UpdateError::InvalidSignature)
        );

        let future_floor = RollbackState::new(8, Version::parse("2.1.0").unwrap());
        assert_eq!(
            verifier.verify_json(manifest_json(SIGNATURE, 1_024).as_bytes(), &future_floor),
            Err(UpdateError::RollbackRejected)
        );

        let mut wrong_target: SignedManifest =
            serde_json::from_str(&manifest_json(SIGNATURE, 1_024)).unwrap();
        wrong_target.manifest.channel = "beta".to_owned();
        assert_eq!(
            verifier.verify_policy(&wrong_target.manifest, &state),
            Err(UpdateError::TargetMismatch)
        );
    }
}
