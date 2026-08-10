//! Effect-isolated download, staging, installation, and crash recovery.

use std::fmt;

use semver::Version;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    ArtifactVerifier, MAX_ARTIFACT_BYTES, MAX_VERSION_BYTES, RollbackState, UpdateError,
    VerifiedRelease, validate_https_url,
};

/// Largest chunk requested from a downloader or staging adapter (256 KiB).
pub const MAX_DOWNLOAD_CHUNK_BYTES: usize = 256 * 1024;
/// Maximum encoded rollback-floor record.
pub const MAX_ROLLBACK_STATE_BYTES: usize = 4 * 1024;
/// Maximum encoded crash-recovery journal.
pub const MAX_RECOVERY_JOURNAL_BYTES: usize = 16 * 1024;

const ROLLBACK_STATE_SCHEMA: u16 = 1;
const RECOVERY_JOURNAL_SCHEMA: u16 = 1;
const MAX_INSTALL_IDENTIFIER_BYTES: usize = 255;

/// Opaque content-addressed key used by staging adapters.
///
/// Adapters must derive local paths from this value rather than from a URL or
/// remote filename.
#[derive(Clone, Copy, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactId {
    sha256: [u8; 32],
    size: u64,
}

impl ArtifactId {
    #[must_use]
    pub const fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }

    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }
}

impl fmt::Debug for ArtifactId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactId")
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

/// Coarse external-effect failure without paths, URLs, or downloaded content.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("an external updater effect failed")]
pub struct ExternalEffectError;

/// Strict request created only from authenticated release metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DownloadRequest {
    url: String,
    resume_from: u64,
    expected_size: u64,
}

impl DownloadRequest {
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    #[must_use]
    pub const fn resume_from(&self) -> u64 {
        self.resume_from
    }

    #[must_use]
    pub const fn expected_size(&self) -> u64 {
        self.expected_size
    }
}

/// Validated response metadata for an HTTPS download stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DownloadMetadata {
    effective_url: String,
    start_offset: u64,
    total_size: u64,
}

impl DownloadMetadata {
    /// Creates response metadata after validating the effective URL.
    ///
    /// # Errors
    ///
    /// Rejects non-HTTPS, malformed, or unbounded effective URLs and invalid
    /// byte ranges.
    pub fn new(
        effective_url: impl Into<String>,
        start_offset: u64,
        total_size: u64,
    ) -> Result<Self, UpdateRuntimeError> {
        let effective_url = effective_url.into();
        validate_https_url(&effective_url).map_err(UpdateRuntimeError::Manifest)?;
        if total_size == 0 || total_size > MAX_ARTIFACT_BYTES || start_offset > total_size {
            return Err(UpdateRuntimeError::DownloadResponseRejected);
        }
        Ok(Self {
            effective_url,
            start_offset,
            total_size,
        })
    }

    #[must_use]
    pub fn effective_url(&self) -> &str {
        &self.effective_url
    }

    #[must_use]
    pub const fn start_offset(&self) -> u64 {
        self.start_offset
    }

    #[must_use]
    pub const fn total_size(&self) -> u64 {
        self.total_size
    }
}

/// Pull-based bounded response body.
///
/// Implementations must enforce TLS validation, reject redirects to non-HTTPS
/// URLs, bound redirect count, apply finite connection/read timeouts, reject
/// content transformation/encoding, and never return more bytes than fit in
/// `buffer`. A resumed response must validate exact `Content-Range` semantics;
/// a fresh response must validate a successful full-body status. Returning zero
/// means authenticated end-of-stream.
pub trait DownloadStream {
    fn metadata(&self) -> &DownloadMetadata;

    /// Reads at most `buffer.len()` bytes.
    ///
    /// # Errors
    ///
    /// Returns a coarse effect error for transport, TLS, timeout, or response
    /// failures.
    fn read_chunk(&mut self, buffer: &mut [u8]) -> Result<usize, ExternalEffectError>;
}

/// HTTPS-only downloader boundary.
///
/// Implementations must not attach ambient credentials and must interpret
/// `resume_from` as an exact byte-range request.
pub trait HttpsDownloader {
    type Stream: DownloadStream;

    /// Opens one bounded response stream.
    ///
    /// # Errors
    ///
    /// Returns an error when HTTPS/TLS policy, redirect policy, or transport
    /// setup fails.
    fn open(&mut self, request: &DownloadRequest) -> Result<Self::Stream, ExternalEffectError>;
}

/// Current durable state of a content-addressed staging entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StagedArtifactState {
    Missing,
    Partial(u64),
    Sealed(u64),
}

/// Durable, resumable temporary-artifact boundary.
///
/// Implementations must use private storage, reject symbolic-link/reparse
/// traversal, make `append` conditional on the exact offset, durably flush in
/// `seal`, and never expose an unsealed entry to an installer.
pub trait ArtifactStaging {
    /// Inspects the durable entry without following attacker-controlled links.
    ///
    /// # Errors
    ///
    /// Returns an error when the private staging location cannot be validated.
    fn inspect(&mut self, artifact: ArtifactId)
    -> Result<StagedArtifactState, ExternalEffectError>;

    /// Reads staged bytes at an exact offset.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid offsets or staging I/O failures.
    fn read_at(
        &mut self,
        artifact: ArtifactId,
        offset: u64,
        buffer: &mut [u8],
    ) -> Result<usize, ExternalEffectError>;

    /// Appends bytes only when the durable length equals `expected_offset`.
    ///
    /// # Errors
    ///
    /// Returns an error on offset mismatch, sealed state, or staging failure.
    fn append(
        &mut self,
        artifact: ArtifactId,
        expected_offset: u64,
        bytes: &[u8],
    ) -> Result<(), ExternalEffectError>;

    /// Atomically resets an entry to an empty unsealed state.
    ///
    /// # Errors
    ///
    /// Returns an error when the reset cannot be made durable.
    fn reset(&mut self, artifact: ArtifactId) -> Result<(), ExternalEffectError>;

    /// Durably marks a complete entry immutable and installer-visible.
    ///
    /// # Errors
    ///
    /// Returns an error when durability or immutability cannot be guaranteed.
    fn seal(&mut self, artifact: ArtifactId) -> Result<(), ExternalEffectError>;

    /// Removes a rejected or abandoned entry.
    ///
    /// # Errors
    ///
    /// Returns an error when removal cannot be completed safely.
    fn discard(&mut self, artifact: ArtifactId) -> Result<(), ExternalEffectError>;
}

/// Explicit user decision for the offered release.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserConsent {
    ApproveDownloadAndInstall,
    Decline,
}

/// Observable updater status. It contains no URL, path, or artifact content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpdateStatus {
    AwaitingConsent,
    Declined,
    ReadyToDownload,
    Downloading { received: u64, total: u64 },
    DownloadPaused { received: u64, total: u64 },
    Staged,
    PreparingInstall,
    AwaitingRestart,
    AwaitingHealthCheck,
    RollingBack,
    Installed,
    RolledBack,
    Failed(UpdateRuntimeError),
}

/// Supported platform installation transaction kinds.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum InstallTarget {
    MacOsAppBundle { bundle_identifier: String },
    WindowsPackage { package_identity: String },
}

impl InstallTarget {
    /// Creates a macOS application-bundle target.
    ///
    /// # Errors
    ///
    /// Rejects an invalid or unbounded bundle identifier.
    pub fn macos_app_bundle(
        bundle_identifier: impl Into<String>,
    ) -> Result<Self, UpdateRuntimeError> {
        let bundle_identifier = bundle_identifier.into();
        validate_install_identifier(&bundle_identifier)?;
        Ok(Self::MacOsAppBundle { bundle_identifier })
    }

    /// Creates a Windows package target.
    ///
    /// # Errors
    ///
    /// Rejects an invalid or unbounded package identity.
    pub fn windows_package(
        package_identity: impl Into<String>,
    ) -> Result<Self, UpdateRuntimeError> {
        let package_identity = package_identity.into();
        validate_install_identifier(&package_identity)?;
        Ok(Self::WindowsPackage { package_identity })
    }

    #[must_use]
    pub const fn platform(&self) -> &'static str {
        match self {
            Self::MacOsAppBundle { .. } => "macos",
            Self::WindowsPackage { .. } => "windows",
        }
    }

    #[must_use]
    pub fn identifier(&self) -> &str {
        match self {
            Self::MacOsAppBundle { bundle_identifier } => bundle_identifier,
            Self::WindowsPackage { package_identity } => package_identity,
        }
    }
}

/// Immutable transaction plan passed to platform installers.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallPlan {
    artifact: ArtifactId,
    target: InstallTarget,
    version: Version,
    rollback_epoch: u64,
    rollback_floor_after_install: RollbackStateDisk,
}

impl InstallPlan {
    #[must_use]
    pub const fn artifact(&self) -> ArtifactId {
        self.artifact
    }

    #[must_use]
    pub const fn target(&self) -> &InstallTarget {
        &self.target
    }

    #[must_use]
    pub const fn version(&self) -> &Version {
        &self.version
    }

    #[must_use]
    pub const fn rollback_epoch(&self) -> u64 {
        self.rollback_epoch
    }

    #[must_use]
    pub fn rollback_floor_after_install(&self) -> RollbackState {
        self.rollback_floor_after_install.clone().into_state()
    }

    fn validate(&self) -> Result<(), UpdateRuntimeError> {
        if self.artifact.size == 0 || self.artifact.size > MAX_ARTIFACT_BYTES {
            return Err(UpdateRuntimeError::CorruptPersistentState);
        }
        validate_install_identifier(match &self.target {
            InstallTarget::MacOsAppBundle { bundle_identifier } => bundle_identifier,
            InstallTarget::WindowsPackage { package_identity } => package_identity,
        })?;
        if self.version.to_string().len() > MAX_VERSION_BYTES
            || self
                .rollback_floor_after_install
                .minimum_version
                .to_string()
                .len()
                > MAX_VERSION_BYTES
            || self.rollback_floor_after_install.minimum_version < self.version
            || self.rollback_floor_after_install.minimum_epoch < self.rollback_epoch
        {
            return Err(UpdateRuntimeError::CorruptPersistentState);
        }
        Ok(())
    }
}

/// Durable phase used to resolve crashes around external install effects.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallPhase {
    Preparing,
    Prepared,
    Activated,
    CandidateStarted,
    Healthy,
    RollingBack,
}

/// Bounded, versioned recovery record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstallJournal {
    phase: InstallPhase,
    plan: InstallPlan,
}

impl InstallJournal {
    #[must_use]
    pub const fn phase(&self) -> InstallPhase {
        self.phase
    }

    #[must_use]
    pub const fn plan(&self) -> &InstallPlan {
        &self.plan
    }

    /// Encodes the journal for atomic durable replacement.
    ///
    /// # Errors
    ///
    /// Rejects invalid fields or an encoded record above its hard bound.
    pub fn encode(&self) -> Result<Vec<u8>, UpdateRuntimeError> {
        self.plan.validate()?;
        let encoded = serde_json::to_vec(&InstallJournalDisk {
            schema: RECOVERY_JOURNAL_SCHEMA,
            phase: self.phase,
            plan: self.plan.clone(),
        })
        .map_err(|_| UpdateRuntimeError::CorruptPersistentState)?;
        if encoded.len() > MAX_RECOVERY_JOURNAL_BYTES {
            return Err(UpdateRuntimeError::CorruptPersistentState);
        }
        Ok(encoded)
    }

    /// Decodes one bounded journal record.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, malformed, unknown-version, or invalid state.
    pub fn decode(bytes: &[u8]) -> Result<Self, UpdateRuntimeError> {
        if bytes.is_empty() || bytes.len() > MAX_RECOVERY_JOURNAL_BYTES {
            return Err(UpdateRuntimeError::CorruptPersistentState);
        }
        let disk: InstallJournalDisk = serde_json::from_slice(bytes)
            .map_err(|_| UpdateRuntimeError::CorruptPersistentState)?;
        if disk.schema != RECOVERY_JOURNAL_SCHEMA {
            return Err(UpdateRuntimeError::CorruptPersistentState);
        }
        disk.plan.validate()?;
        Ok(Self {
            phase: disk.phase,
            plan: disk.plan,
        })
    }

    fn with_phase(&self, phase: InstallPhase) -> Self {
        Self {
            phase,
            plan: self.plan.clone(),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallJournalDisk {
    schema: u16,
    phase: InstallPhase,
    plan: InstallPlan,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RollbackStateDisk {
    minimum_epoch: u64,
    minimum_version: Version,
}

impl RollbackStateDisk {
    fn into_state(self) -> RollbackState {
        RollbackState::new(self.minimum_epoch, self.minimum_version)
    }
}

impl From<&RollbackState> for RollbackStateDisk {
    fn from(value: &RollbackState) -> Self {
        Self {
            minimum_epoch: value.minimum_epoch(),
            minimum_version: value.minimum_version().clone(),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RollbackEnvelope {
    schema: u16,
    state: RollbackStateDisk,
}

impl RollbackState {
    /// Encodes a bounded, versioned anti-rollback floor.
    ///
    /// # Errors
    ///
    /// Rejects an invalid or oversized version string or record.
    pub fn encode(&self) -> Result<Vec<u8>, UpdateRuntimeError> {
        if self.minimum_version().to_string().len() > MAX_VERSION_BYTES {
            return Err(UpdateRuntimeError::CorruptPersistentState);
        }
        let encoded = serde_json::to_vec(&RollbackEnvelope {
            schema: ROLLBACK_STATE_SCHEMA,
            state: self.into(),
        })
        .map_err(|_| UpdateRuntimeError::CorruptPersistentState)?;
        if encoded.len() > MAX_ROLLBACK_STATE_BYTES {
            return Err(UpdateRuntimeError::CorruptPersistentState);
        }
        Ok(encoded)
    }

    /// Decodes a bounded, versioned anti-rollback floor.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, malformed, or unknown-version records.
    pub fn decode(bytes: &[u8]) -> Result<Self, UpdateRuntimeError> {
        if bytes.is_empty() || bytes.len() > MAX_ROLLBACK_STATE_BYTES {
            return Err(UpdateRuntimeError::CorruptPersistentState);
        }
        let envelope: RollbackEnvelope = serde_json::from_slice(bytes)
            .map_err(|_| UpdateRuntimeError::CorruptPersistentState)?;
        if envelope.schema != ROLLBACK_STATE_SCHEMA
            || envelope.state.minimum_version.to_string().len() > MAX_VERSION_BYTES
        {
            return Err(UpdateRuntimeError::CorruptPersistentState);
        }
        Ok(envelope.state.into_state())
    }
}

/// Atomic recovery-journal persistence boundary.
///
/// `replace` must durably replace the previous record, and `clear` must be
/// durable. Implementations must reject links/reparse points and private data
/// must remain readable only by the current user. The storage must also detect
/// unauthorized same-user mutation (for example with an OS-protected MAC),
/// because a forged `Healthy` phase would bypass explicit consent.
pub trait RecoveryJournalStore {
    /// Loads the current encoded journal, if any.
    ///
    /// # Errors
    ///
    /// Returns an error when private durable storage cannot be read safely.
    fn load(&mut self) -> Result<Option<Vec<u8>>, ExternalEffectError>;
    /// Atomically and durably replaces the current journal.
    ///
    /// # Errors
    ///
    /// Returns an error when replacement durability cannot be guaranteed.
    fn replace(&mut self, encoded: &[u8]) -> Result<(), ExternalEffectError>;
    /// Durably removes the current journal.
    ///
    /// # Errors
    ///
    /// Returns an error when removal cannot be guaranteed.
    fn clear(&mut self) -> Result<(), ExternalEffectError>;
}

/// Monotonic anti-rollback persistence boundary.
///
/// `advance` must atomically persist the component-wise maximum of its current
/// record and `minimum`; it must never lower either floor. Deletion, replacement
/// by an older record, and unauthorized same-user mutation must fail closed via
/// OS-protected integrity storage.
pub trait RollbackStateStore {
    /// Loads the current anti-rollback floor.
    ///
    /// # Errors
    ///
    /// Returns an error when durable state is missing, corrupt, or unreadable.
    fn load(&mut self) -> Result<RollbackState, ExternalEffectError>;
    /// Atomically advances both floors using component-wise maximum semantics.
    ///
    /// # Errors
    ///
    /// Returns an error when the monotonic durable update cannot be guaranteed.
    fn advance(&mut self, minimum: &RollbackState) -> Result<(), ExternalEffectError>;
}

/// Platform executor observation used for idempotent crash recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstallObservation {
    Absent,
    Prepared,
    Activated,
    Committed,
    RolledBack,
}

/// Atomic platform installation transaction boundary.
///
/// Every adapter must reopen only the sealed content-addressed stage and verify
/// its exact signed size and SHA-256. A macOS adapter must additionally verify
/// the expected bundle identifier, semantic version, Developer ID,
/// notarization, and sealed code before an atomic same-volume bundle swap. A
/// Windows adapter must verify package identity, version, and Authenticode
/// before using the platform package transaction. All methods must be
/// idempotent. No method may execute artifact content; restart remains an
/// explicit host action. The host must serialize updater transactions with an
/// exclusive per-installation lock.
pub trait AtomicInstaller {
    /// Observes a transaction without executing installed content.
    ///
    /// # Errors
    ///
    /// Returns an error when the platform transaction cannot be inspected.
    fn inspect(&mut self, plan: &InstallPlan) -> Result<InstallObservation, ExternalEffectError>;
    /// Verifies and prepares a sealed artifact without activating it.
    ///
    /// # Errors
    ///
    /// Returns an error on any identity, signature, digest, or staging failure.
    fn prepare(&mut self, plan: &InstallPlan) -> Result<(), ExternalEffectError>;
    /// Atomically activates prepared content without launching it.
    ///
    /// # Errors
    ///
    /// Returns an error when atomic activation cannot be guaranteed.
    fn activate(&mut self, plan: &InstallPlan) -> Result<(), ExternalEffectError>;
    /// Commits a healthy transaction and retires its rollback backup.
    ///
    /// # Errors
    ///
    /// Returns an error when the idempotent commit cannot complete.
    fn commit(&mut self, plan: &InstallPlan) -> Result<(), ExternalEffectError>;
    /// Restores the previous installation and removes prepared content.
    ///
    /// # Errors
    ///
    /// Returns an error when the idempotent rollback cannot complete.
    fn rollback(&mut self, plan: &InstallPlan) -> Result<(), ExternalEffectError>;
}

/// Result of reconciling a persisted install journal at startup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryStatus {
    NoRecoveryNeeded,
    RolledBack(InstallPlan),
    AwaitingRestart(InstallPlan),
    AwaitingHealthCheck(InstallPlan),
    Installed(InstallPlan),
}

/// Errors returned by the effect-isolated updater runtime.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum UpdateRuntimeError {
    #[error("signed release metadata was rejected: {0}")]
    Manifest(UpdateError),
    #[error("explicit user consent is required for this operation")]
    ConsentRequired,
    #[error("the updater state transition is invalid")]
    InvalidTransition,
    #[error("the download effect failed")]
    DownloadFailed,
    #[error("download response metadata is inconsistent with the signed release")]
    DownloadResponseRejected,
    #[error("the staging effect failed")]
    StagingFailed,
    #[error("the staged artifact failed size or digest verification")]
    ArtifactVerificationFailed,
    #[error("the install target does not match the signed platform")]
    InstallTargetMismatch,
    #[error("the recovery journal effect failed")]
    JournalFailed,
    #[error("the anti-rollback persistence effect failed")]
    RollbackStateFailed,
    #[error("the platform installer effect failed")]
    InstallerFailed,
    #[error("persistent updater state is malformed or outside its hard bound")]
    CorruptPersistentState,
}

impl From<UpdateError> for UpdateRuntimeError {
    fn from(value: UpdateError) -> Self {
        Self::Manifest(value)
    }
}

/// One explicitly consented update attempt.
pub struct UpdateSession {
    release: VerifiedRelease,
    rollback_before: RollbackState,
    status: UpdateStatus,
    plan: Option<InstallPlan>,
}

impl fmt::Debug for UpdateSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UpdateSession")
            .field("version", self.release.manifest().version())
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

impl UpdateSession {
    #[must_use]
    pub const fn new(release: VerifiedRelease, rollback_before: RollbackState) -> Self {
        Self {
            release,
            rollback_before,
            status: UpdateStatus::AwaitingConsent,
            plan: None,
        }
    }

    #[must_use]
    pub const fn status(&self) -> UpdateStatus {
        self.status
    }

    #[must_use]
    pub const fn release(&self) -> &VerifiedRelease {
        &self.release
    }

    /// Records the explicit user decision. Approval covers download and the
    /// later platform install transaction for this exact signed release.
    ///
    /// # Errors
    ///
    /// Returns an error when a decision has already been recorded.
    pub fn decide(&mut self, decision: UserConsent) -> Result<(), UpdateRuntimeError> {
        if self.status != UpdateStatus::AwaitingConsent {
            return Err(UpdateRuntimeError::InvalidTransition);
        }
        self.status = match decision {
            UserConsent::ApproveDownloadAndInstall => UpdateStatus::ReadyToDownload,
            UserConsent::Decline => UpdateStatus::Declined,
        };
        Ok(())
    }

    /// Resumes or starts a bounded artifact download, verifies the complete
    /// staged bytes, then seals the staging entry.
    ///
    /// # Errors
    ///
    /// Rejects missing consent, invalid transitions, inconsistent byte-range
    /// responses, external-effect failures, and size/digest mismatches.
    pub fn stage_download<D, S>(
        &mut self,
        downloader: &mut D,
        staging: &mut S,
    ) -> Result<ArtifactId, UpdateRuntimeError>
    where
        D: HttpsDownloader,
        S: ArtifactStaging,
    {
        if !matches!(
            self.status,
            UpdateStatus::ReadyToDownload | UpdateStatus::DownloadPaused { .. }
        ) {
            return Err(if self.status == UpdateStatus::AwaitingConsent {
                UpdateRuntimeError::ConsentRequired
            } else {
                UpdateRuntimeError::InvalidTransition
            });
        }

        let artifact = self.artifact_id();
        let staged_state = staging
            .inspect(artifact)
            .map_err(|_| self.fail(UpdateRuntimeError::StagingFailed))?;
        let (mut verifier, mut offset) = self.replay_staged(staging, artifact, staged_state)?;

        if matches!(staged_state, StagedArtifactState::Sealed(_)) {
            return if verifier.finish().is_ok() {
                self.status = UpdateStatus::Staged;
                Ok(artifact)
            } else {
                let _ = staging.discard(artifact);
                Err(self.fail(UpdateRuntimeError::ArtifactVerificationFailed))
            };
        }

        if offset == artifact.size {
            return self.finish_staging(staging, artifact, verifier);
        }

        self.status = UpdateStatus::Downloading {
            received: offset,
            total: artifact.size,
        };
        let request = DownloadRequest {
            url: self.release.manifest().artifact_url().to_owned(),
            resume_from: offset,
            expected_size: artifact.size,
        };
        let mut stream = downloader.open(&request).map_err(|_| {
            self.status = UpdateStatus::DownloadPaused {
                received: offset,
                total: artifact.size,
            };
            UpdateRuntimeError::DownloadFailed
        })?;
        let metadata = stream.metadata();
        if metadata.total_size != artifact.size {
            return Err(self.fail(UpdateRuntimeError::DownloadResponseRejected));
        }
        if metadata.start_offset != offset {
            if offset > 0 && metadata.start_offset == 0 {
                staging
                    .reset(artifact)
                    .map_err(|_| self.fail(UpdateRuntimeError::StagingFailed))?;
                verifier = self.release.artifact_verifier();
                offset = 0;
            } else {
                return Err(self.fail(UpdateRuntimeError::DownloadResponseRejected));
            }
        }

        let mut buffer = vec![0_u8; MAX_DOWNLOAD_CHUNK_BYTES];
        loop {
            let read = stream.read_chunk(&mut buffer).map_err(|_| {
                self.status = UpdateStatus::DownloadPaused {
                    received: offset,
                    total: artifact.size,
                };
                UpdateRuntimeError::DownloadFailed
            })?;
            if read == 0 {
                break;
            }
            if read > buffer.len() {
                return Err(self.fail(UpdateRuntimeError::DownloadResponseRejected));
            }
            let chunk = &buffer[..read];
            verifier.update(chunk).map_err(|_| {
                let _ = staging.discard(artifact);
                self.fail(UpdateRuntimeError::ArtifactVerificationFailed)
            })?;
            staging
                .append(artifact, offset, chunk)
                .map_err(|_| self.fail(UpdateRuntimeError::StagingFailed))?;
            offset = verifier.observed_size();
            self.status = UpdateStatus::Downloading {
                received: offset,
                total: artifact.size,
            };
        }

        self.finish_staging(staging, artifact, verifier)
    }

    /// Begins and atomically activates an installation transaction. The method
    /// never launches installed content; successful return requires an explicit
    /// host restart before health acknowledgement.
    ///
    /// # Errors
    ///
    /// Rejects unstaged content, target mismatch, or any journal/installer
    /// effect failure.
    pub fn begin_install<I, J, R>(
        &mut self,
        target: InstallTarget,
        installer: &mut I,
        journal_store: &mut J,
        rollback_store: &mut R,
    ) -> Result<(), UpdateRuntimeError>
    where
        I: AtomicInstaller,
        J: RecoveryJournalStore,
        R: RollbackStateStore,
    {
        if self.status != UpdateStatus::Staged {
            return Err(if self.status == UpdateStatus::AwaitingConsent {
                UpdateRuntimeError::ConsentRequired
            } else {
                UpdateRuntimeError::InvalidTransition
            });
        }
        if target.platform() != self.release.manifest().platform()
            || target.identifier() != self.release.install_identity()
        {
            return Err(self.fail(UpdateRuntimeError::InstallTargetMismatch));
        }
        let current_floor = rollback_store
            .load()
            .map_err(|_| self.fail(UpdateRuntimeError::RollbackStateFailed))?;
        if release_is_below_floor(&self.release, &current_floor) {
            return Err(self.fail(UpdateRuntimeError::Manifest(UpdateError::RollbackRejected)));
        }
        let effective_floor = RollbackState::new(
            self.rollback_before
                .minimum_epoch()
                .max(current_floor.minimum_epoch()),
            self.rollback_before
                .minimum_version()
                .clone()
                .max(current_floor.minimum_version().clone()),
        );
        let plan = InstallPlan {
            artifact: self.artifact_id(),
            target,
            version: self.release.manifest().version().clone(),
            rollback_epoch: self.release.manifest().rollback_epoch(),
            rollback_floor_after_install: RollbackStateDisk::from(
                &self.release.rollback_state_after_install(&effective_floor),
            ),
        };
        plan.validate()?;
        self.status = UpdateStatus::PreparingInstall;
        let mut journal = InstallJournal {
            phase: InstallPhase::Preparing,
            plan: plan.clone(),
        };
        persist_journal(journal_store, &journal).map_err(|error| self.fail(error))?;
        installer
            .prepare(&plan)
            .map_err(|_| self.fail(UpdateRuntimeError::InstallerFailed))?;
        journal = journal.with_phase(InstallPhase::Prepared);
        persist_journal(journal_store, &journal).map_err(|error| self.fail(error))?;
        installer
            .activate(&plan)
            .map_err(|_| self.fail(UpdateRuntimeError::InstallerFailed))?;
        journal = journal.with_phase(InstallPhase::Activated);
        persist_journal(journal_store, &journal).map_err(|error| self.fail(error))?;
        self.plan = Some(plan);
        self.status = UpdateStatus::AwaitingRestart;
        Ok(())
    }

    /// Durably records that the newly activated candidate reached its startup
    /// self-check. This must be called by the candidate, not by the old process
    /// before requesting restart.
    ///
    /// # Errors
    ///
    /// Returns an error outside [`UpdateStatus::AwaitingRestart`] or unless the
    /// journal and platform executor both still report the expected activated
    /// transaction.
    pub fn acknowledge_restart<I, J>(
        &mut self,
        installer: &mut I,
        journal_store: &mut J,
    ) -> Result<(), UpdateRuntimeError>
    where
        I: AtomicInstaller,
        J: RecoveryJournalStore,
    {
        if self.status != UpdateStatus::AwaitingRestart {
            return Err(UpdateRuntimeError::InvalidTransition);
        }
        let expected = self
            .plan
            .clone()
            .ok_or(UpdateRuntimeError::InvalidTransition)?;
        persist_candidate_started(installer, journal_store, Some(&expected))?;
        self.status = UpdateStatus::AwaitingHealthCheck;
        Ok(())
    }

    /// Commits a healthy activated installation and then advances the durable
    /// anti-rollback floor.
    ///
    /// # Errors
    ///
    /// Returns an error outside the health-check phase or when any durable
    /// effect fails.
    pub fn confirm_healthy<I, J, R>(
        &mut self,
        installer: &mut I,
        journal_store: &mut J,
        rollback_store: &mut R,
    ) -> Result<(), UpdateRuntimeError>
    where
        I: AtomicInstaller,
        J: RecoveryJournalStore,
        R: RollbackStateStore,
    {
        if self.status != UpdateStatus::AwaitingHealthCheck {
            return Err(UpdateRuntimeError::InvalidTransition);
        }
        let plan = self
            .plan
            .clone()
            .ok_or(UpdateRuntimeError::InvalidTransition)?;
        let encoded = journal_store
            .load()
            .map_err(|_| self.fail(UpdateRuntimeError::JournalFailed))?
            .ok_or_else(|| self.fail(UpdateRuntimeError::InvalidTransition))?;
        let started = InstallJournal::decode(&encoded).map_err(|error| self.fail(error))?;
        if started.phase != InstallPhase::CandidateStarted || started.plan != plan {
            return Err(self.fail(UpdateRuntimeError::CorruptPersistentState));
        }
        if installer
            .inspect(&plan)
            .map_err(|_| self.fail(UpdateRuntimeError::InstallerFailed))?
            != InstallObservation::Activated
        {
            return Err(self.fail(UpdateRuntimeError::CorruptPersistentState));
        }
        let current_floor = rollback_store
            .load()
            .map_err(|_| self.fail(UpdateRuntimeError::RollbackStateFailed))?;
        if plan_is_below_floor(&plan, &current_floor) {
            return Err(self.fail(UpdateRuntimeError::Manifest(UpdateError::RollbackRejected)));
        }
        let journal = started.with_phase(InstallPhase::Healthy);
        persist_journal(journal_store, &journal).map_err(|error| self.fail(error))?;
        installer
            .commit(&plan)
            .map_err(|_| self.fail(UpdateRuntimeError::InstallerFailed))?;
        rollback_store
            .advance(&plan.rollback_floor_after_install())
            .map_err(|_| self.fail(UpdateRuntimeError::RollbackStateFailed))?;
        journal_store
            .clear()
            .map_err(|_| self.fail(UpdateRuntimeError::JournalFailed))?;
        self.status = UpdateStatus::Installed;
        Ok(())
    }

    /// Rolls back an activated candidate without advancing the rollback floor.
    ///
    /// # Errors
    ///
    /// Returns an error outside the restart/health phases or when recovery
    /// persistence or the platform rollback fails.
    pub fn rollback<I, J>(
        &mut self,
        installer: &mut I,
        journal_store: &mut J,
    ) -> Result<(), UpdateRuntimeError>
    where
        I: AtomicInstaller,
        J: RecoveryJournalStore,
    {
        if !matches!(
            self.status,
            UpdateStatus::AwaitingRestart | UpdateStatus::AwaitingHealthCheck
        ) {
            return Err(UpdateRuntimeError::InvalidTransition);
        }
        let plan = self
            .plan
            .clone()
            .ok_or(UpdateRuntimeError::InvalidTransition)?;
        if installer
            .inspect(&plan)
            .map_err(|_| self.fail(UpdateRuntimeError::InstallerFailed))?
            != InstallObservation::Activated
        {
            return Err(self.fail(UpdateRuntimeError::CorruptPersistentState));
        }
        self.status = UpdateStatus::RollingBack;
        persist_journal(
            journal_store,
            &InstallJournal {
                phase: InstallPhase::RollingBack,
                plan: plan.clone(),
            },
        )
        .map_err(|error| self.fail(error))?;
        installer
            .rollback(&plan)
            .map_err(|_| self.fail(UpdateRuntimeError::InstallerFailed))?;
        journal_store
            .clear()
            .map_err(|_| self.fail(UpdateRuntimeError::JournalFailed))?;
        self.status = UpdateStatus::RolledBack;
        Ok(())
    }

    fn artifact_id(&self) -> ArtifactId {
        ArtifactId {
            sha256: *self.release.artifact_sha256(),
            size: self.release.manifest().artifact_size(),
        }
    }

    fn replay_staged<S: ArtifactStaging>(
        &mut self,
        staging: &mut S,
        artifact: ArtifactId,
        state: StagedArtifactState,
    ) -> Result<(ArtifactVerifier, u64), UpdateRuntimeError> {
        let length = match state {
            StagedArtifactState::Missing => 0,
            StagedArtifactState::Partial(length) | StagedArtifactState::Sealed(length) => length,
        };
        if length > artifact.size {
            let _ = staging.discard(artifact);
            return Err(self.fail(UpdateRuntimeError::ArtifactVerificationFailed));
        }
        let mut verifier = self.release.artifact_verifier();
        let mut offset = 0_u64;
        let mut buffer = vec![0_u8; MAX_DOWNLOAD_CHUNK_BYTES];
        while offset < length {
            let remaining = usize::try_from((length - offset).min(MAX_DOWNLOAD_CHUNK_BYTES as u64))
                .map_err(|_| self.fail(UpdateRuntimeError::StagingFailed))?;
            let read = staging
                .read_at(artifact, offset, &mut buffer[..remaining])
                .map_err(|_| self.fail(UpdateRuntimeError::StagingFailed))?;
            if read == 0 || read > remaining {
                return Err(self.fail(UpdateRuntimeError::StagingFailed));
            }
            verifier.update(&buffer[..read]).map_err(|_| {
                let _ = staging.discard(artifact);
                self.fail(UpdateRuntimeError::ArtifactVerificationFailed)
            })?;
            offset = verifier.observed_size();
        }
        Ok((verifier, offset))
    }

    fn finish_staging<S: ArtifactStaging>(
        &mut self,
        staging: &mut S,
        artifact: ArtifactId,
        verifier: ArtifactVerifier,
    ) -> Result<ArtifactId, UpdateRuntimeError> {
        if verifier.finish().is_err() {
            let _ = staging.discard(artifact);
            return Err(self.fail(UpdateRuntimeError::ArtifactVerificationFailed));
        }
        staging
            .seal(artifact)
            .map_err(|_| self.fail(UpdateRuntimeError::StagingFailed))?;
        self.status = UpdateStatus::Staged;
        Ok(artifact)
    }

    fn fail(&mut self, error: UpdateRuntimeError) -> UpdateRuntimeError {
        self.status = UpdateStatus::Failed(error);
        error
    }
}

/// Reconciles a durable journal after process or machine failure.
///
/// Pre-activation ambiguity is resolved by idempotent rollback. Activated
/// content always waits for an explicit health decision. A previously recorded
/// healthy decision resumes commit and monotonic rollback-floor persistence.
///
/// # Errors
///
/// Returns an error for corrupt persistence or journal/installer/rollback
/// effect failures.
pub fn recover_installation<I, J, R>(
    installer: &mut I,
    journal_store: &mut J,
    rollback_store: &mut R,
) -> Result<RecoveryStatus, UpdateRuntimeError>
where
    I: AtomicInstaller,
    J: RecoveryJournalStore,
    R: RollbackStateStore,
{
    let Some(encoded) = journal_store
        .load()
        .map_err(|_| UpdateRuntimeError::JournalFailed)?
    else {
        return Ok(RecoveryStatus::NoRecoveryNeeded);
    };
    let journal = InstallJournal::decode(&encoded)?;
    match journal.phase {
        InstallPhase::Preparing | InstallPhase::Prepared => {
            installer
                .rollback(journal.plan())
                .map_err(|_| UpdateRuntimeError::InstallerFailed)?;
            journal_store
                .clear()
                .map_err(|_| UpdateRuntimeError::JournalFailed)?;
            Ok(RecoveryStatus::RolledBack(journal.plan))
        }
        InstallPhase::Activated | InstallPhase::CandidateStarted => {
            let observation = installer
                .inspect(journal.plan())
                .map_err(|_| UpdateRuntimeError::InstallerFailed)?;
            if observation == InstallObservation::Committed {
                return Err(UpdateRuntimeError::CorruptPersistentState);
            }
            let current_floor = rollback_store
                .load()
                .map_err(|_| UpdateRuntimeError::RollbackStateFailed)?;
            if plan_is_below_floor(journal.plan(), &current_floor) {
                installer
                    .rollback(journal.plan())
                    .map_err(|_| UpdateRuntimeError::InstallerFailed)?;
                journal_store
                    .clear()
                    .map_err(|_| UpdateRuntimeError::JournalFailed)?;
                return Ok(RecoveryStatus::RolledBack(journal.plan));
            }
            match observation {
                InstallObservation::Activated if journal.phase == InstallPhase::Activated => {
                    Ok(RecoveryStatus::AwaitingRestart(journal.plan))
                }
                InstallObservation::Activated => {
                    Ok(RecoveryStatus::AwaitingHealthCheck(journal.plan))
                }
                InstallObservation::Committed => Err(UpdateRuntimeError::CorruptPersistentState),
                InstallObservation::Absent
                | InstallObservation::Prepared
                | InstallObservation::RolledBack => {
                    installer
                        .rollback(journal.plan())
                        .map_err(|_| UpdateRuntimeError::InstallerFailed)?;
                    journal_store
                        .clear()
                        .map_err(|_| UpdateRuntimeError::JournalFailed)?;
                    Ok(RecoveryStatus::RolledBack(journal.plan))
                }
            }
        }
        InstallPhase::Healthy => {
            let observation = installer
                .inspect(journal.plan())
                .map_err(|_| UpdateRuntimeError::InstallerFailed)?;
            let current_floor = rollback_store
                .load()
                .map_err(|_| UpdateRuntimeError::RollbackStateFailed)?;
            if plan_is_below_floor(journal.plan(), &current_floor) {
                return Err(UpdateRuntimeError::Manifest(UpdateError::RollbackRejected));
            }
            if !matches!(
                observation,
                InstallObservation::Activated | InstallObservation::Committed
            ) {
                return Err(UpdateRuntimeError::CorruptPersistentState);
            }
            installer
                .commit(journal.plan())
                .map_err(|_| UpdateRuntimeError::InstallerFailed)?;
            rollback_store
                .advance(&journal.plan.rollback_floor_after_install())
                .map_err(|_| UpdateRuntimeError::RollbackStateFailed)?;
            journal_store
                .clear()
                .map_err(|_| UpdateRuntimeError::JournalFailed)?;
            Ok(RecoveryStatus::Installed(journal.plan))
        }
        InstallPhase::RollingBack => {
            installer
                .rollback(journal.plan())
                .map_err(|_| UpdateRuntimeError::InstallerFailed)?;
            journal_store
                .clear()
                .map_err(|_| UpdateRuntimeError::JournalFailed)?;
            Ok(RecoveryStatus::RolledBack(journal.plan))
        }
    }
}

/// Durably records that the recovered activated candidate reached startup.
///
/// This call must originate from the newly activated candidate after its own
/// startup self-check. It never marks the candidate healthy.
///
/// # Errors
///
/// Rejects a missing/non-activated journal, inconsistent platform observation,
/// or journal/installer effect failure.
pub fn record_recovered_candidate_started<I, J>(
    installer: &mut I,
    journal_store: &mut J,
) -> Result<InstallPlan, UpdateRuntimeError>
where
    I: AtomicInstaller,
    J: RecoveryJournalStore,
{
    persist_candidate_started(installer, journal_store, None)
}

fn persist_candidate_started<I, J>(
    installer: &mut I,
    journal_store: &mut J,
    expected: Option<&InstallPlan>,
) -> Result<InstallPlan, UpdateRuntimeError>
where
    I: AtomicInstaller,
    J: RecoveryJournalStore,
{
    let encoded = journal_store
        .load()
        .map_err(|_| UpdateRuntimeError::JournalFailed)?
        .ok_or(UpdateRuntimeError::InvalidTransition)?;
    let journal = InstallJournal::decode(&encoded)?;
    if journal.phase != InstallPhase::Activated {
        return Err(UpdateRuntimeError::InvalidTransition);
    }
    if expected.is_some_and(|expected| journal.plan() != expected) {
        return Err(UpdateRuntimeError::CorruptPersistentState);
    }
    if installer
        .inspect(journal.plan())
        .map_err(|_| UpdateRuntimeError::InstallerFailed)?
        != InstallObservation::Activated
    {
        return Err(UpdateRuntimeError::CorruptPersistentState);
    }
    let started = journal.with_phase(InstallPhase::CandidateStarted);
    persist_journal(journal_store, &started)?;
    Ok(started.plan)
}

/// Commits a recovered started candidate after an explicit healthy decision.
///
/// # Errors
///
/// Rejects a missing/non-started journal, inconsistent platform observation,
/// stale rollback floor, or any durable effect failure.
pub fn confirm_recovered_healthy<I, J, R>(
    installer: &mut I,
    journal_store: &mut J,
    rollback_store: &mut R,
) -> Result<InstallPlan, UpdateRuntimeError>
where
    I: AtomicInstaller,
    J: RecoveryJournalStore,
    R: RollbackStateStore,
{
    let encoded = journal_store
        .load()
        .map_err(|_| UpdateRuntimeError::JournalFailed)?
        .ok_or(UpdateRuntimeError::InvalidTransition)?;
    let journal = InstallJournal::decode(&encoded)?;
    if journal.phase != InstallPhase::CandidateStarted {
        return Err(UpdateRuntimeError::InvalidTransition);
    }
    let current_floor = rollback_store
        .load()
        .map_err(|_| UpdateRuntimeError::RollbackStateFailed)?;
    if plan_is_below_floor(journal.plan(), &current_floor) {
        return Err(UpdateRuntimeError::Manifest(UpdateError::RollbackRejected));
    }
    if installer
        .inspect(journal.plan())
        .map_err(|_| UpdateRuntimeError::InstallerFailed)?
        != InstallObservation::Activated
    {
        return Err(UpdateRuntimeError::CorruptPersistentState);
    }
    let healthy = journal.with_phase(InstallPhase::Healthy);
    persist_journal(journal_store, &healthy)?;
    installer
        .commit(healthy.plan())
        .map_err(|_| UpdateRuntimeError::InstallerFailed)?;
    rollback_store
        .advance(&healthy.plan.rollback_floor_after_install())
        .map_err(|_| UpdateRuntimeError::RollbackStateFailed)?;
    journal_store
        .clear()
        .map_err(|_| UpdateRuntimeError::JournalFailed)?;
    Ok(healthy.plan)
}

/// Rolls back a recovered activated candidate after an explicit unhealthy or
/// cancel decision.
///
/// # Errors
///
/// Rejects a missing/non-activated journal or any durable effect failure.
pub fn rollback_recovered<I, J>(
    installer: &mut I,
    journal_store: &mut J,
) -> Result<InstallPlan, UpdateRuntimeError>
where
    I: AtomicInstaller,
    J: RecoveryJournalStore,
{
    let encoded = journal_store
        .load()
        .map_err(|_| UpdateRuntimeError::JournalFailed)?
        .ok_or(UpdateRuntimeError::InvalidTransition)?;
    let journal = InstallJournal::decode(&encoded)?;
    if !matches!(
        journal.phase,
        InstallPhase::Activated | InstallPhase::CandidateStarted
    ) {
        return Err(UpdateRuntimeError::InvalidTransition);
    }
    if installer
        .inspect(journal.plan())
        .map_err(|_| UpdateRuntimeError::InstallerFailed)?
        != InstallObservation::Activated
    {
        return Err(UpdateRuntimeError::CorruptPersistentState);
    }
    let rolling_back = journal.with_phase(InstallPhase::RollingBack);
    persist_journal(journal_store, &rolling_back)?;
    installer
        .rollback(rolling_back.plan())
        .map_err(|_| UpdateRuntimeError::InstallerFailed)?;
    journal_store
        .clear()
        .map_err(|_| UpdateRuntimeError::JournalFailed)?;
    Ok(rolling_back.plan)
}

fn persist_journal<J: RecoveryJournalStore>(
    store: &mut J,
    journal: &InstallJournal,
) -> Result<(), UpdateRuntimeError> {
    let encoded = journal.encode()?;
    store
        .replace(&encoded)
        .map_err(|_| UpdateRuntimeError::JournalFailed)
}

fn release_is_below_floor(release: &VerifiedRelease, floor: &RollbackState) -> bool {
    release.manifest().rollback_epoch() < floor.minimum_epoch()
        || release.manifest().version() < floor.minimum_version()
}

fn plan_is_below_floor(plan: &InstallPlan, floor: &RollbackState) -> bool {
    plan.rollback_epoch < floor.minimum_epoch() || plan.version < *floor.minimum_version()
}

fn validate_install_identifier(value: &str) -> Result<(), UpdateRuntimeError> {
    if value.is_empty()
        || value.len() > MAX_INSTALL_IDENTIFIER_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_'))
    {
        return Err(UpdateRuntimeError::CorruptPersistentState);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ReleaseManifest;
    use sha2::{Digest as _, Sha256};
    use std::fmt::Write as _;

    fn verified_release(bytes: &[u8], platform: &str) -> VerifiedRelease {
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        let artifact_sha256 = digest
            .iter()
            .fold(String::with_capacity(64), |mut encoded, byte| {
                write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
                encoded
            });
        VerifiedRelease {
            manifest: ReleaseManifest {
                schema: 1,
                product: "nodavo".to_owned(),
                channel: "stable".to_owned(),
                platform: platform.to_owned(),
                arch: if platform == "macos" {
                    "aarch64".to_owned()
                } else {
                    "x86_64".to_owned()
                },
                version: Version::parse("2.0.0").unwrap(),
                minimum_version: Version::parse("1.0.0").unwrap(),
                artifact_url: "https://updates.example.test/nodavo.pkg".to_owned(),
                artifact_size: u64::try_from(bytes.len()).unwrap(),
                artifact_sha256,
                rollback_epoch: 7,
            },
            artifact_sha256: digest,
            install_identity: if platform == "macos" {
                "dev.nodavo.macos".to_owned()
            } else {
                "Nodavo.Package".to_owned()
            },
        }
    }

    fn rollback_floor() -> RollbackState {
        RollbackState::new(6, Version::parse("1.5.0").unwrap())
    }

    struct FakeStream {
        metadata: DownloadMetadata,
        bytes: Vec<u8>,
        cursor: usize,
        maximum_chunk: usize,
        fail_at: Option<usize>,
    }

    impl DownloadStream for FakeStream {
        fn metadata(&self) -> &DownloadMetadata {
            &self.metadata
        }

        fn read_chunk(&mut self, buffer: &mut [u8]) -> Result<usize, ExternalEffectError> {
            if self.fail_at.is_some_and(|offset| self.cursor >= offset) {
                return Err(ExternalEffectError);
            }
            if self.cursor == self.bytes.len() {
                return Ok(0);
            }
            let count = buffer
                .len()
                .min(self.maximum_chunk)
                .min(self.bytes.len() - self.cursor);
            buffer[..count].copy_from_slice(&self.bytes[self.cursor..self.cursor + count]);
            self.cursor += count;
            Ok(count)
        }
    }

    struct FakeDownloader {
        bytes: Vec<u8>,
        honor_range: bool,
        maximum_chunk: usize,
        fail_at: Option<usize>,
        requested_offsets: Vec<u64>,
    }

    impl FakeDownloader {
        fn new(bytes: &[u8]) -> Self {
            Self {
                bytes: bytes.to_vec(),
                honor_range: true,
                maximum_chunk: 3,
                fail_at: None,
                requested_offsets: Vec::new(),
            }
        }
    }

    impl HttpsDownloader for FakeDownloader {
        type Stream = FakeStream;

        fn open(&mut self, request: &DownloadRequest) -> Result<Self::Stream, ExternalEffectError> {
            self.requested_offsets.push(request.resume_from());
            let start = if self.honor_range {
                request.resume_from()
            } else {
                0
            };
            Ok(FakeStream {
                metadata: DownloadMetadata::new(
                    request.url(),
                    start,
                    u64::try_from(self.bytes.len()).unwrap(),
                )
                .unwrap(),
                bytes: self.bytes.clone(),
                cursor: usize::try_from(start).unwrap(),
                maximum_chunk: self.maximum_chunk,
                fail_at: self.fail_at,
            })
        }
    }

    #[derive(Default)]
    struct FakeStage {
        bytes: Vec<u8>,
        sealed: bool,
        resets: usize,
        discards: usize,
    }

    impl ArtifactStaging for FakeStage {
        fn inspect(
            &mut self,
            _artifact: ArtifactId,
        ) -> Result<StagedArtifactState, ExternalEffectError> {
            if self.bytes.is_empty() {
                Ok(StagedArtifactState::Missing)
            } else if self.sealed {
                Ok(StagedArtifactState::Sealed(
                    u64::try_from(self.bytes.len()).unwrap(),
                ))
            } else {
                Ok(StagedArtifactState::Partial(
                    u64::try_from(self.bytes.len()).unwrap(),
                ))
            }
        }

        fn read_at(
            &mut self,
            _artifact: ArtifactId,
            offset: u64,
            buffer: &mut [u8],
        ) -> Result<usize, ExternalEffectError> {
            let offset = usize::try_from(offset).map_err(|_| ExternalEffectError)?;
            if offset > self.bytes.len() {
                return Err(ExternalEffectError);
            }
            let count = buffer.len().min(self.bytes.len() - offset);
            buffer[..count].copy_from_slice(&self.bytes[offset..offset + count]);
            Ok(count)
        }

        fn append(
            &mut self,
            _artifact: ArtifactId,
            expected_offset: u64,
            bytes: &[u8],
        ) -> Result<(), ExternalEffectError> {
            if expected_offset != u64::try_from(self.bytes.len()).unwrap() || self.sealed {
                return Err(ExternalEffectError);
            }
            self.bytes.extend_from_slice(bytes);
            Ok(())
        }

        fn reset(&mut self, _artifact: ArtifactId) -> Result<(), ExternalEffectError> {
            self.bytes.clear();
            self.sealed = false;
            self.resets += 1;
            Ok(())
        }

        fn seal(&mut self, _artifact: ArtifactId) -> Result<(), ExternalEffectError> {
            self.sealed = true;
            Ok(())
        }

        fn discard(&mut self, _artifact: ArtifactId) -> Result<(), ExternalEffectError> {
            self.bytes.clear();
            self.sealed = false;
            self.discards += 1;
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeJournal {
        encoded: Option<Vec<u8>>,
    }

    impl RecoveryJournalStore for FakeJournal {
        fn load(&mut self) -> Result<Option<Vec<u8>>, ExternalEffectError> {
            Ok(self.encoded.clone())
        }

        fn replace(&mut self, encoded: &[u8]) -> Result<(), ExternalEffectError> {
            self.encoded = Some(encoded.to_vec());
            Ok(())
        }

        fn clear(&mut self) -> Result<(), ExternalEffectError> {
            self.encoded = None;
            Ok(())
        }
    }

    struct FakeRollbackStore {
        state: RollbackState,
        advances: usize,
    }

    impl FakeRollbackStore {
        fn new() -> Self {
            Self {
                state: rollback_floor(),
                advances: 0,
            }
        }
    }

    impl RollbackStateStore for FakeRollbackStore {
        fn load(&mut self) -> Result<RollbackState, ExternalEffectError> {
            Ok(self.state.clone())
        }

        fn advance(&mut self, minimum: &RollbackState) -> Result<(), ExternalEffectError> {
            self.state = RollbackState::new(
                self.state.minimum_epoch().max(minimum.minimum_epoch()),
                self.state
                    .minimum_version()
                    .clone()
                    .max(minimum.minimum_version().clone()),
            );
            self.advances += 1;
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeInstaller {
        observation: Option<InstallObservation>,
        prepares: usize,
        activates: usize,
        commits: usize,
        rollbacks: usize,
    }

    impl AtomicInstaller for FakeInstaller {
        fn inspect(
            &mut self,
            _plan: &InstallPlan,
        ) -> Result<InstallObservation, ExternalEffectError> {
            Ok(self.observation.unwrap_or(InstallObservation::Absent))
        }

        fn prepare(&mut self, _plan: &InstallPlan) -> Result<(), ExternalEffectError> {
            self.prepares += 1;
            self.observation = Some(InstallObservation::Prepared);
            Ok(())
        }

        fn activate(&mut self, _plan: &InstallPlan) -> Result<(), ExternalEffectError> {
            self.activates += 1;
            self.observation = Some(InstallObservation::Activated);
            Ok(())
        }

        fn commit(&mut self, _plan: &InstallPlan) -> Result<(), ExternalEffectError> {
            self.commits += 1;
            self.observation = Some(InstallObservation::Committed);
            Ok(())
        }

        fn rollback(&mut self, _plan: &InstallPlan) -> Result<(), ExternalEffectError> {
            self.rollbacks += 1;
            self.observation = Some(InstallObservation::RolledBack);
            Ok(())
        }
    }

    #[test]
    fn explicit_consent_precedes_every_effect() {
        let bytes = b"verified artifact";
        let mut session = UpdateSession::new(verified_release(bytes, "macos"), rollback_floor());
        let mut downloader = FakeDownloader::new(bytes);
        let mut staging = FakeStage::default();

        assert_eq!(
            session.stage_download(&mut downloader, &mut staging),
            Err(UpdateRuntimeError::ConsentRequired)
        );
        assert!(downloader.requested_offsets.is_empty());
        assert!(staging.bytes.is_empty());

        session.decide(UserConsent::Decline).unwrap();
        assert_eq!(session.status(), UpdateStatus::Declined);
        assert_eq!(
            session.stage_download(&mut downloader, &mut staging),
            Err(UpdateRuntimeError::InvalidTransition)
        );
    }

    #[test]
    fn partial_stage_resumes_and_is_stream_verified_before_sealing() {
        let bytes = b"verified artifact bytes";
        let mut session = UpdateSession::new(verified_release(bytes, "macos"), rollback_floor());
        session
            .decide(UserConsent::ApproveDownloadAndInstall)
            .unwrap();
        let mut staging = FakeStage {
            bytes: bytes[..8].to_vec(),
            ..FakeStage::default()
        };
        let mut downloader = FakeDownloader::new(bytes);

        let artifact = session
            .stage_download(&mut downloader, &mut staging)
            .unwrap();

        assert_eq!(downloader.requested_offsets, vec![8]);
        assert_eq!(staging.bytes, bytes);
        assert!(staging.sealed);
        assert_eq!(artifact.size(), u64::try_from(bytes.len()).unwrap());
        assert_eq!(session.status(), UpdateStatus::Staged);
    }

    #[test]
    fn ignored_range_resets_partial_stage_before_accepting_full_body() {
        let bytes = b"complete replacement body";
        let mut session = UpdateSession::new(verified_release(bytes, "macos"), rollback_floor());
        session
            .decide(UserConsent::ApproveDownloadAndInstall)
            .unwrap();
        let mut staging = FakeStage {
            bytes: bytes[..5].to_vec(),
            ..FakeStage::default()
        };
        let mut downloader = FakeDownloader::new(bytes);
        downloader.honor_range = false;

        session
            .stage_download(&mut downloader, &mut staging)
            .unwrap();

        assert_eq!(staging.resets, 1);
        assert_eq!(staging.bytes, bytes);
        assert!(staging.sealed);
    }

    #[test]
    fn interrupted_download_resumes_without_replaying_network_bytes() {
        let bytes = b"resumable verified artifact";
        let mut session = UpdateSession::new(verified_release(bytes, "macos"), rollback_floor());
        session
            .decide(UserConsent::ApproveDownloadAndInstall)
            .unwrap();
        let mut staging = FakeStage::default();
        let mut interrupted = FakeDownloader::new(bytes);
        interrupted.fail_at = Some(6);

        assert_eq!(
            session.stage_download(&mut interrupted, &mut staging),
            Err(UpdateRuntimeError::DownloadFailed)
        );
        assert_eq!(
            session.status(),
            UpdateStatus::DownloadPaused {
                received: 6,
                total: u64::try_from(bytes.len()).unwrap()
            }
        );

        let mut resumed = FakeDownloader::new(bytes);
        session.stage_download(&mut resumed, &mut staging).unwrap();
        assert_eq!(resumed.requested_offsets, vec![6]);
        assert_eq!(staging.bytes, bytes);
        assert!(staging.sealed);
    }

    #[test]
    fn digest_mismatch_discards_staged_content() {
        let expected = b"expected artifact";
        let delivered = b"tampered artifact";
        assert_eq!(expected.len(), delivered.len());
        let mut session = UpdateSession::new(verified_release(expected, "macos"), rollback_floor());
        session
            .decide(UserConsent::ApproveDownloadAndInstall)
            .unwrap();
        let mut staging = FakeStage::default();
        let mut downloader = FakeDownloader::new(delivered);

        assert_eq!(
            session.stage_download(&mut downloader, &mut staging),
            Err(UpdateRuntimeError::ArtifactVerificationFailed)
        );
        assert!(staging.bytes.is_empty());
        assert_eq!(staging.discards, 1);
    }

    #[test]
    fn install_waits_for_restart_and_health_before_rollback_floor_advances() {
        let bytes = b"verified artifact";
        let mut session = UpdateSession::new(verified_release(bytes, "macos"), rollback_floor());
        session
            .decide(UserConsent::ApproveDownloadAndInstall)
            .unwrap();
        session
            .stage_download(&mut FakeDownloader::new(bytes), &mut FakeStage::default())
            .unwrap();
        let mut installer = FakeInstaller::default();
        let mut journal = FakeJournal::default();
        let mut rollback = FakeRollbackStore::new();

        session
            .begin_install(
                InstallTarget::macos_app_bundle("dev.nodavo.macos").unwrap(),
                &mut installer,
                &mut journal,
                &mut rollback,
            )
            .unwrap();
        assert_eq!(session.status(), UpdateStatus::AwaitingRestart);
        assert_eq!(rollback.advances, 0);
        assert_eq!(
            InstallJournal::decode(journal.encoded.as_deref().unwrap())
                .unwrap()
                .phase(),
            InstallPhase::Activated
        );

        session
            .acknowledge_restart(&mut installer, &mut journal)
            .unwrap();
        session
            .confirm_healthy(&mut installer, &mut journal, &mut rollback)
            .unwrap();

        assert_eq!(session.status(), UpdateStatus::Installed);
        assert_eq!(installer.commits, 1);
        assert_eq!(rollback.state.minimum_epoch(), 7);
        assert_eq!(
            rollback.state.minimum_version(),
            &Version::parse("2.0.0").unwrap()
        );
        assert!(journal.encoded.is_none());
    }

    #[test]
    fn install_target_must_match_authenticated_platform() {
        let bytes = b"verified artifact";
        let mut session = UpdateSession::new(verified_release(bytes, "macos"), rollback_floor());
        session
            .decide(UserConsent::ApproveDownloadAndInstall)
            .unwrap();
        session
            .stage_download(&mut FakeDownloader::new(bytes), &mut FakeStage::default())
            .unwrap();

        assert_eq!(
            session.begin_install(
                InstallTarget::windows_package("Nodavo.Package").unwrap(),
                &mut FakeInstaller::default(),
                &mut FakeJournal::default(),
                &mut FakeRollbackStore::new(),
            ),
            Err(UpdateRuntimeError::InstallTargetMismatch)
        );

        let mut same_platform =
            UpdateSession::new(verified_release(bytes, "macos"), rollback_floor());
        same_platform
            .decide(UserConsent::ApproveDownloadAndInstall)
            .unwrap();
        same_platform
            .stage_download(&mut FakeDownloader::new(bytes), &mut FakeStage::default())
            .unwrap();
        assert_eq!(
            same_platform.begin_install(
                InstallTarget::macos_app_bundle("dev.attacker.other").unwrap(),
                &mut FakeInstaller::default(),
                &mut FakeJournal::default(),
                &mut FakeRollbackStore::new(),
            ),
            Err(UpdateRuntimeError::InstallTargetMismatch)
        );
    }

    #[test]
    fn rollback_floor_is_reloaded_immediately_before_install() {
        let bytes = b"verified artifact";
        let mut session = UpdateSession::new(verified_release(bytes, "macos"), rollback_floor());
        session
            .decide(UserConsent::ApproveDownloadAndInstall)
            .unwrap();
        session
            .stage_download(&mut FakeDownloader::new(bytes), &mut FakeStage::default())
            .unwrap();
        let mut installer = FakeInstaller::default();
        let mut journal = FakeJournal::default();
        let mut rollback = FakeRollbackStore {
            state: RollbackState::new(8, Version::parse("2.1.0").unwrap()),
            advances: 0,
        };

        assert_eq!(
            session.begin_install(
                InstallTarget::macos_app_bundle("dev.nodavo.macos").unwrap(),
                &mut installer,
                &mut journal,
                &mut rollback,
            ),
            Err(UpdateRuntimeError::Manifest(UpdateError::RollbackRejected))
        );
        assert_eq!(installer.prepares, 0);
        assert!(journal.encoded.is_none());
    }

    #[test]
    fn recovery_never_commits_activated_candidate_without_health_consent() {
        let bytes = b"verified artifact";
        let mut session = UpdateSession::new(verified_release(bytes, "macos"), rollback_floor());
        session
            .decide(UserConsent::ApproveDownloadAndInstall)
            .unwrap();
        session
            .stage_download(&mut FakeDownloader::new(bytes), &mut FakeStage::default())
            .unwrap();
        let mut installer = FakeInstaller::default();
        let mut journal = FakeJournal::default();
        let mut rollback = FakeRollbackStore::new();
        session
            .begin_install(
                InstallTarget::macos_app_bundle("dev.nodavo.macos").unwrap(),
                &mut installer,
                &mut journal,
                &mut rollback,
            )
            .unwrap();

        let recovered = recover_installation(&mut installer, &mut journal, &mut rollback).unwrap();
        assert!(matches!(recovered, RecoveryStatus::AwaitingRestart(_)));
        assert_eq!(installer.commits, 0);
        assert_eq!(rollback.advances, 0);

        record_recovered_candidate_started(&mut installer, &mut journal).unwrap();
        let recovered = recover_installation(&mut installer, &mut journal, &mut rollback).unwrap();
        assert!(matches!(recovered, RecoveryStatus::AwaitingHealthCheck(_)));

        let committed =
            confirm_recovered_healthy(&mut installer, &mut journal, &mut rollback).unwrap();
        assert_eq!(committed.version(), &Version::parse("2.0.0").unwrap());
        assert_eq!(installer.commits, 1);
        assert_eq!(rollback.advances, 1);
        assert!(journal.encoded.is_none());
    }

    #[test]
    fn preactivation_crash_is_resolved_by_idempotent_rollback() {
        let release = verified_release(b"artifact", "macos");
        let plan = InstallPlan {
            artifact: ArtifactId {
                sha256: *release.artifact_sha256(),
                size: release.manifest().artifact_size(),
            },
            target: InstallTarget::macos_app_bundle("dev.nodavo.macos").unwrap(),
            version: release.manifest().version().clone(),
            rollback_epoch: release.manifest().rollback_epoch(),
            rollback_floor_after_install: RollbackStateDisk::from(
                &release.rollback_state_after_install(&rollback_floor()),
            ),
        };
        let mut journal = FakeJournal {
            encoded: Some(
                InstallJournal {
                    phase: InstallPhase::Prepared,
                    plan: plan.clone(),
                }
                .encode()
                .unwrap(),
            ),
        };
        let mut installer = FakeInstaller {
            observation: Some(InstallObservation::Activated),
            ..FakeInstaller::default()
        };

        assert_eq!(
            recover_installation(&mut installer, &mut journal, &mut FakeRollbackStore::new())
                .unwrap(),
            RecoveryStatus::RolledBack(plan)
        );
        assert_eq!(installer.rollbacks, 1);
        assert!(journal.encoded.is_none());
    }

    #[test]
    fn explicit_unhealthy_decision_rolls_back_without_advancing_floor() {
        let bytes = b"verified artifact";
        let mut session = UpdateSession::new(verified_release(bytes, "macos"), rollback_floor());
        session
            .decide(UserConsent::ApproveDownloadAndInstall)
            .unwrap();
        session
            .stage_download(&mut FakeDownloader::new(bytes), &mut FakeStage::default())
            .unwrap();
        let mut installer = FakeInstaller::default();
        let mut journal = FakeJournal::default();
        let mut rollback = FakeRollbackStore::new();
        session
            .begin_install(
                InstallTarget::macos_app_bundle("dev.nodavo.macos").unwrap(),
                &mut installer,
                &mut journal,
                &mut rollback,
            )
            .unwrap();

        session.rollback(&mut installer, &mut journal).unwrap();

        assert_eq!(session.status(), UpdateStatus::RolledBack);
        assert_eq!(installer.rollbacks, 1);
        assert_eq!(rollback.advances, 0);
        assert!(journal.encoded.is_none());
    }

    #[test]
    fn recovery_rolls_back_activated_candidate_below_current_floor() {
        let release = verified_release(b"artifact", "macos");
        let plan = InstallPlan {
            artifact: ArtifactId {
                sha256: *release.artifact_sha256(),
                size: release.manifest().artifact_size(),
            },
            target: InstallTarget::macos_app_bundle("dev.nodavo.macos").unwrap(),
            version: release.manifest().version().clone(),
            rollback_epoch: release.manifest().rollback_epoch(),
            rollback_floor_after_install: RollbackStateDisk::from(
                &release.rollback_state_after_install(&rollback_floor()),
            ),
        };
        let mut journal = FakeJournal {
            encoded: Some(
                InstallJournal {
                    phase: InstallPhase::Activated,
                    plan: plan.clone(),
                }
                .encode()
                .unwrap(),
            ),
        };
        let mut installer = FakeInstaller {
            observation: Some(InstallObservation::Activated),
            ..FakeInstaller::default()
        };
        let mut rollback = FakeRollbackStore {
            state: RollbackState::new(8, Version::parse("2.1.0").unwrap()),
            advances: 0,
        };

        assert_eq!(
            recover_installation(&mut installer, &mut journal, &mut rollback).unwrap(),
            RecoveryStatus::RolledBack(plan)
        );
        assert_eq!(installer.rollbacks, 1);
        assert!(journal.encoded.is_none());
    }

    #[test]
    fn impossible_committed_state_does_not_bypass_health_gate() {
        let release = verified_release(b"artifact", "macos");
        let plan = InstallPlan {
            artifact: ArtifactId {
                sha256: *release.artifact_sha256(),
                size: release.manifest().artifact_size(),
            },
            target: InstallTarget::macos_app_bundle("dev.nodavo.macos").unwrap(),
            version: release.manifest().version().clone(),
            rollback_epoch: release.manifest().rollback_epoch(),
            rollback_floor_after_install: RollbackStateDisk::from(
                &release.rollback_state_after_install(&rollback_floor()),
            ),
        };
        let mut journal = FakeJournal {
            encoded: Some(
                InstallJournal {
                    phase: InstallPhase::Activated,
                    plan,
                }
                .encode()
                .unwrap(),
            ),
        };
        let mut installer = FakeInstaller {
            observation: Some(InstallObservation::Committed),
            ..FakeInstaller::default()
        };
        let mut rollback = FakeRollbackStore {
            state: RollbackState::new(8, Version::parse("2.1.0").unwrap()),
            advances: 0,
        };

        assert_eq!(
            recover_installation(&mut installer, &mut journal, &mut rollback),
            Err(UpdateRuntimeError::CorruptPersistentState)
        );
        assert_eq!(rollback.advances, 0);
        assert!(journal.encoded.is_some());
        assert_eq!(
            rollback_recovered(&mut installer, &mut journal),
            Err(UpdateRuntimeError::CorruptPersistentState)
        );
        assert!(journal.encoded.is_some());
    }

    #[test]
    fn recovered_health_confirmation_rechecks_platform_state() {
        let bytes = b"verified artifact";
        let mut session = UpdateSession::new(verified_release(bytes, "macos"), rollback_floor());
        session
            .decide(UserConsent::ApproveDownloadAndInstall)
            .unwrap();
        session
            .stage_download(&mut FakeDownloader::new(bytes), &mut FakeStage::default())
            .unwrap();
        let mut installer = FakeInstaller::default();
        let mut journal = FakeJournal::default();
        let mut rollback = FakeRollbackStore::new();
        session
            .begin_install(
                InstallTarget::macos_app_bundle("dev.nodavo.macos").unwrap(),
                &mut installer,
                &mut journal,
                &mut rollback,
            )
            .unwrap();
        record_recovered_candidate_started(&mut installer, &mut journal).unwrap();
        installer.observation = Some(InstallObservation::RolledBack);

        assert_eq!(
            confirm_recovered_healthy(&mut installer, &mut journal, &mut rollback),
            Err(UpdateRuntimeError::CorruptPersistentState)
        );
        assert_eq!(installer.commits, 0);
        assert_eq!(rollback.advances, 0);
        assert!(journal.encoded.is_some());
    }

    #[test]
    fn persistent_codecs_are_versioned_bounded_and_deny_unknown_fields() {
        let state = rollback_floor();
        assert_eq!(
            RollbackState::decode(&state.encode().unwrap()).unwrap(),
            state
        );
        assert_eq!(
            RollbackState::decode(br#"{"schema":1,"state":{"minimum_epoch":6,"minimum_version":"1.5.0"},"extra":true}"#),
            Err(UpdateRuntimeError::CorruptPersistentState)
        );
        assert_eq!(
            InstallJournal::decode(&vec![b'x'; MAX_RECOVERY_JOURNAL_BYTES + 1]),
            Err(UpdateRuntimeError::CorruptPersistentState)
        );
    }

    #[test]
    fn effective_download_url_must_remain_https() {
        assert_eq!(
            DownloadMetadata::new("http://updates.example.test/file", 0, 10),
            Err(UpdateRuntimeError::Manifest(
                UpdateError::InsecureArtifactUrl
            ))
        );
        assert!(DownloadMetadata::new("https://updates.example.test/file", 0, 10).is_ok());
    }
}
