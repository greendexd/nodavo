mod network;
mod staging;

use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock, TryLockError};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::VerifyingKey;
use nodavo_local_ipc::{UpdateFailureCode, UpdatePhase, UpdateSnapshot};
use nodavo_update::{
    ArtifactId, ArtifactStaging, ExternalEffectError, ReleaseVerifier, RollbackState,
    StagedArtifactState, UpdateError, UpdateRuntimeError, UpdateSession, UpdateStatus, UserConsent,
    VerificationPolicy,
};
use semver::Version;
use thiserror::Error;
use url::Url;
use uuid::Uuid;

use self::network::{ManifestFetcher, NativeHttpsClient};
use self::staging::PrivateFileStaging;

const UPDATE_MANIFEST_URL: Option<&str> = option_env!("NODAVO_UPDATE_MANIFEST_URL");
const UPDATE_PUBLIC_KEY_BASE64: Option<&str> = option_env!("NODAVO_UPDATE_PUBLIC_KEY_BASE64");

static COORDINATOR: OnceLock<Arc<UpdateCoordinator>> = OnceLock::new();

pub(crate) fn coordinator() -> Arc<UpdateCoordinator> {
    Arc::clone(COORDINATOR.get_or_init(|| Arc::new(UpdateCoordinator::configured())))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HttpsOrigin {
    host: String,
    port: u16,
}

impl HttpsOrigin {
    fn parse(value: &str) -> Result<Self, CoordinatorError> {
        let parsed = Url::parse(value).map_err(|_| CoordinatorError::NotConfigured)?;
        if parsed.scheme() != "https"
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.fragment().is_some()
        {
            return Err(CoordinatorError::NotConfigured);
        }
        let host = parsed
            .host_str()
            .filter(|host| !host.is_empty())
            .ok_or(CoordinatorError::NotConfigured)?
            .to_ascii_lowercase();
        let port = parsed
            .port_or_known_default()
            .ok_or(CoordinatorError::NotConfigured)?;
        Ok(Self { host, port })
    }

    fn permits(&self, value: &str) -> bool {
        Self::parse(value).is_ok_and(|candidate| candidate == *self)
    }
}

trait CoordinatorEffects: Send {
    fn fetch_manifest(&mut self) -> Result<Vec<u8>, ExternalEffectError>;

    fn stage_download(
        &mut self,
        session: &mut UpdateSession,
        progress: &mut dyn FnMut(u64, u64),
    ) -> Result<ArtifactId, UpdateRuntimeError>;
}

struct ProductionEffects {
    network: NativeHttpsClient,
    staging: PrivateFileStaging,
}

impl CoordinatorEffects for ProductionEffects {
    fn fetch_manifest(&mut self) -> Result<Vec<u8>, ExternalEffectError> {
        self.network.fetch_manifest()
    }

    fn stage_download(
        &mut self,
        session: &mut UpdateSession,
        progress: &mut dyn FnMut(u64, u64),
    ) -> Result<ArtifactId, UpdateRuntimeError> {
        let total = session.release().manifest().artifact_size();
        let mut reporting = ReportingStaging {
            inner: &mut self.staging,
            total,
            progress,
        };
        session.stage_download(&mut self.network, &mut reporting)
    }
}

struct ReportingStaging<'a, S> {
    inner: &'a mut S,
    total: u64,
    progress: &'a mut dyn FnMut(u64, u64),
}

impl<S: ArtifactStaging> ArtifactStaging for ReportingStaging<'_, S> {
    fn inspect(
        &mut self,
        artifact: ArtifactId,
    ) -> Result<StagedArtifactState, ExternalEffectError> {
        let state = self.inner.inspect(artifact)?;
        let received = match state {
            StagedArtifactState::Missing => 0,
            StagedArtifactState::Partial(length) | StagedArtifactState::Sealed(length) => length,
        };
        (self.progress)(received, self.total);
        Ok(state)
    }

    fn read_at(
        &mut self,
        artifact: ArtifactId,
        offset: u64,
        buffer: &mut [u8],
    ) -> Result<usize, ExternalEffectError> {
        self.inner.read_at(artifact, offset, buffer)
    }

    fn append(
        &mut self,
        artifact: ArtifactId,
        expected_offset: u64,
        bytes: &[u8],
    ) -> Result<(), ExternalEffectError> {
        self.inner
            .append(artifact, expected_offset, bytes)
            .inspect(|()| {
                let received =
                    expected_offset.saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
                (self.progress)(received, self.total);
            })
    }

    fn reset(&mut self, artifact: ArtifactId) -> Result<(), ExternalEffectError> {
        self.inner.reset(artifact).inspect(|()| {
            (self.progress)(0, self.total);
        })
    }

    fn seal(&mut self, artifact: ArtifactId) -> Result<(), ExternalEffectError> {
        self.inner.seal(artifact)
    }

    fn discard(&mut self, artifact: ArtifactId) -> Result<(), ExternalEffectError> {
        self.inner.discard(artifact)
    }
}

struct Offer {
    id: Uuid,
    version: String,
    total: u64,
    session: UpdateSession,
}

struct OperationState {
    verifier: Option<ReleaseVerifier>,
    rollback: RollbackState,
    origin: Option<HttpsOrigin>,
    effects: Option<Box<dyn CoordinatorEffects>>,
    offer: Option<Offer>,
    active_download: Option<DownloadToken>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DownloadToken(Uuid);

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DecisionOutcome {
    Complete(UpdateSnapshot),
    StartDownload {
        snapshot: UpdateSnapshot,
        token: DownloadToken,
    },
}

/// Process-wide exclusive coordinator for manual, non-activating updates.
pub(crate) struct UpdateCoordinator {
    snapshot: Mutex<UpdateSnapshot>,
    operation: Mutex<OperationState>,
}

impl UpdateCoordinator {
    fn configured() -> Self {
        Self::try_configured().unwrap_or_else(|_| Self::unavailable())
    }

    fn try_configured() -> Result<Self, CoordinatorError> {
        let endpoint = UPDATE_MANIFEST_URL.ok_or(CoordinatorError::NotConfigured)?;
        let encoded_key = UPDATE_PUBLIC_KEY_BASE64.ok_or(CoordinatorError::NotConfigured)?;
        let origin = HttpsOrigin::parse(endpoint)?;
        let decoded_key = STANDARD
            .decode(encoded_key)
            .map_err(|_| CoordinatorError::NotConfigured)?;
        let key_bytes: [u8; 32] = decoded_key
            .try_into()
            .map_err(|_| CoordinatorError::NotConfigured)?;
        let release_key =
            VerifyingKey::from_bytes(&key_bytes).map_err(|_| CoordinatorError::NotConfigured)?;
        let installed =
            Version::parse(env!("CARGO_PKG_VERSION")).map_err(|_| CoordinatorError::Internal)?;
        let policy = VerificationPolicy::new(
            "nodavo",
            "stable",
            target_platform()?,
            target_architecture()?,
            install_identity()?,
            installed.clone(),
        )
        .map_err(|_| CoordinatorError::Internal)?;
        let root = update_state_directory()?.join("update-staging-v1");
        let effects = ProductionEffects {
            network: NativeHttpsClient::new(endpoint.to_owned())
                .map_err(|_| CoordinatorError::Internal)?,
            staging: PrivateFileStaging::new(&root).map_err(|_| CoordinatorError::Internal)?,
        };
        Ok(Self::new(
            ReleaseVerifier::new(release_key, policy),
            RollbackState::new(0, installed),
            origin,
            Box::new(effects),
        ))
    }

    fn unavailable() -> Self {
        Self {
            snapshot: Mutex::new(failure_snapshot(
                UpdatePhase::Unavailable,
                UpdateFailureCode::NotConfigured,
            )),
            operation: Mutex::new(OperationState {
                verifier: None,
                rollback: RollbackState::new(
                    0,
                    Version::parse(env!("CARGO_PKG_VERSION"))
                        .unwrap_or_else(|_| Version::new(0, 0, 0)),
                ),
                origin: None,
                effects: None,
                offer: None,
                active_download: None,
            }),
        }
    }

    fn new(
        verifier: ReleaseVerifier,
        rollback: RollbackState,
        origin: HttpsOrigin,
        effects: Box<dyn CoordinatorEffects>,
    ) -> Self {
        Self {
            snapshot: Mutex::new(empty_snapshot(UpdatePhase::Idle)),
            operation: Mutex::new(OperationState {
                verifier: Some(verifier),
                rollback,
                origin: Some(origin),
                effects: Some(effects),
                offer: None,
                active_download: None,
            }),
        }
    }

    pub(crate) fn snapshot(&self) -> UpdateSnapshot {
        self.snapshot
            .lock()
            .map_or_else(|_| internal_failure_snapshot(), |snapshot| snapshot.clone())
    }

    pub(crate) fn check_for_update(&self) -> Result<UpdateSnapshot, CoordinatorError> {
        let mut operation = self.try_operation()?;
        if operation.active_download.is_some() {
            return Err(CoordinatorError::Busy);
        }
        if operation.verifier.is_none() || operation.effects.is_none() {
            return Ok(self.snapshot());
        }
        operation.offer = None;
        self.publish(empty_snapshot(UpdatePhase::Checking))?;

        let Ok(envelope) = operation
            .effects
            .as_mut()
            .ok_or(CoordinatorError::Internal)?
            .fetch_manifest()
        else {
            let snapshot = failure_snapshot(UpdatePhase::Failed, UpdateFailureCode::Network);
            self.publish(snapshot.clone())?;
            return Ok(snapshot);
        };
        let release = match operation
            .verifier
            .as_ref()
            .ok_or(CoordinatorError::Internal)?
            .verify_json(&envelope, &operation.rollback)
        {
            Ok(release) => release,
            Err(UpdateError::TargetNotNewer) => {
                let snapshot = empty_snapshot(UpdatePhase::UpToDate);
                self.publish(snapshot.clone())?;
                return Ok(snapshot);
            }
            Err(_) => {
                let snapshot =
                    failure_snapshot(UpdatePhase::Failed, UpdateFailureCode::ManifestRejected);
                self.publish(snapshot.clone())?;
                return Ok(snapshot);
            }
        };
        if !operation
            .origin
            .as_ref()
            .ok_or(CoordinatorError::Internal)?
            .permits(release.manifest().artifact_url())
        {
            let snapshot =
                failure_snapshot(UpdatePhase::Failed, UpdateFailureCode::ManifestRejected);
            self.publish(snapshot.clone())?;
            return Ok(snapshot);
        }

        let id = Uuid::new_v4();
        let version = release.manifest().version().to_string();
        let total = release.manifest().artifact_size();
        operation.offer = Some(Offer {
            id,
            version: version.clone(),
            total,
            session: UpdateSession::new(release, operation.rollback.clone()),
        });
        let snapshot = offered_snapshot(UpdatePhase::OfferAvailable, id, version, total);
        self.publish(snapshot.clone())?;
        Ok(snapshot)
    }

    pub(crate) fn record_decision(
        &self,
        offer_id: &str,
        accepted: bool,
    ) -> Result<DecisionOutcome, CoordinatorError> {
        let parsed = Uuid::parse_str(offer_id).map_err(|_| CoordinatorError::OfferMismatch)?;
        if parsed.hyphenated().to_string() != offer_id {
            return Err(CoordinatorError::OfferMismatch);
        }
        let mut operation = self.try_operation()?;
        if operation.active_download.is_some() {
            return Err(CoordinatorError::Busy);
        }
        let mut offer = operation
            .offer
            .take()
            .ok_or(CoordinatorError::OfferMismatch)?;
        if offer.id != parsed {
            operation.offer = Some(offer);
            return Err(CoordinatorError::OfferMismatch);
        }

        if !accepted {
            if offer.session.status() != UpdateStatus::AwaitingConsent {
                operation.offer = Some(offer);
                return Err(CoordinatorError::InvalidTransition);
            }
            offer
                .session
                .decide(UserConsent::Decline)
                .map_err(|_| CoordinatorError::InvalidTransition)?;
            let snapshot = empty_snapshot(UpdatePhase::Declined);
            self.publish(snapshot.clone())?;
            return Ok(DecisionOutcome::Complete(snapshot));
        }

        match offer.session.status() {
            UpdateStatus::AwaitingConsent => offer
                .session
                .decide(UserConsent::ApproveDownloadAndInstall)
                .map_err(|_| CoordinatorError::InvalidTransition)?,
            UpdateStatus::DownloadPaused { .. } => {}
            _ => {
                operation.offer = Some(offer);
                return Err(CoordinatorError::InvalidTransition);
            }
        }
        let snapshot = offered_snapshot(
            UpdatePhase::ConsentRecorded,
            offer.id,
            offer.version.clone(),
            offer.total,
        );
        self.publish(snapshot.clone())?;
        let token = DownloadToken(Uuid::new_v4());
        operation.offer = Some(offer);
        operation.active_download = Some(token);
        Ok(DecisionOutcome::StartDownload { snapshot, token })
    }

    pub(crate) fn download_offer(
        &self,
        token: DownloadToken,
    ) -> Result<UpdateSnapshot, CoordinatorError> {
        let mut operation = self
            .operation
            .lock()
            .map_err(|_| CoordinatorError::Internal)?;
        if operation.active_download != Some(token) {
            return Err(CoordinatorError::InvalidTransition);
        }
        let mut offer = operation.offer.take().ok_or(CoordinatorError::Internal)?;

        let latest = Arc::new(Mutex::new(0_u64));
        let latest_for_progress = Arc::clone(&latest);
        let snapshot_state = &self.snapshot;
        let id = offer.id;
        let version = offer.version.clone();
        let total = offer.total;
        let mut progress = move |received: u64, reported_total: u64| {
            if reported_total != total || received > total {
                return;
            }
            if let Ok(mut latest) = latest_for_progress.lock() {
                *latest = received;
            }
            if let Ok(snapshot) = progress_snapshot(id, version.clone(), received, total)
                && let Ok(mut current) = snapshot_state.lock()
            {
                *current = snapshot;
            }
        };
        progress(0, total);
        let result = operation
            .effects
            .as_mut()
            .ok_or(CoordinatorError::Internal)?
            .stage_download(&mut offer.session, &mut progress);
        drop(progress);
        let received = latest.lock().map_or(0, |value| *value);
        operation.active_download = None;

        match result {
            Ok(_) => {
                let snapshot = complete_snapshot(offer.id, offer.version.clone(), offer.total);
                operation.offer = Some(offer);
                self.publish(snapshot.clone())?;
                Ok(snapshot)
            }
            Err(UpdateRuntimeError::DownloadFailed)
                if matches!(offer.session.status(), UpdateStatus::DownloadPaused { .. }) =>
            {
                let snapshot =
                    paused_snapshot(offer.id, offer.version.clone(), received, offer.total);
                operation.offer = Some(offer);
                self.publish(snapshot.clone())?;
                Ok(snapshot)
            }
            Err(UpdateRuntimeError::ArtifactVerificationFailed) => {
                let snapshot =
                    failure_snapshot(UpdatePhase::Failed, UpdateFailureCode::Verification);
                self.publish(snapshot.clone())?;
                Ok(snapshot)
            }
            Err(UpdateRuntimeError::StagingFailed) => {
                let snapshot = failure_snapshot(UpdatePhase::Failed, UpdateFailureCode::Staging);
                self.publish(snapshot.clone())?;
                Ok(snapshot)
            }
            Err(_) => {
                let snapshot = failure_snapshot(UpdatePhase::Failed, UpdateFailureCode::Internal);
                self.publish(snapshot.clone())?;
                Ok(snapshot)
            }
        }
    }

    pub(crate) fn publish_internal_failure(&self) {
        let _ = self.publish(internal_failure_snapshot());
    }

    fn try_operation(&self) -> Result<std::sync::MutexGuard<'_, OperationState>, CoordinatorError> {
        match self.operation.try_lock() {
            Ok(operation) => Ok(operation),
            Err(TryLockError::WouldBlock) => Err(CoordinatorError::Busy),
            Err(TryLockError::Poisoned(_)) => Err(CoordinatorError::Internal),
        }
    }

    fn publish(&self, snapshot: UpdateSnapshot) -> Result<(), CoordinatorError> {
        *self
            .snapshot
            .lock()
            .map_err(|_| CoordinatorError::Internal)? = snapshot;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum CoordinatorError {
    #[error("updater configuration is unavailable")]
    NotConfigured,
    #[error("another updater operation is already active")]
    Busy,
    #[error("the update offer identifier does not match")]
    OfferMismatch,
    #[error("the updater state transition is invalid")]
    InvalidTransition,
    #[error("the updater failed internally")]
    Internal,
}

fn empty_snapshot(phase: UpdatePhase) -> UpdateSnapshot {
    UpdateSnapshot::new(phase, None, None, None, None, None)
        .expect("constant empty updater snapshot must be valid")
}

fn offered_snapshot(phase: UpdatePhase, id: Uuid, version: String, total: u64) -> UpdateSnapshot {
    UpdateSnapshot::new(
        phase,
        Some(id.hyphenated().to_string()),
        Some(version),
        None,
        Some(total),
        None,
    )
    .expect("verified update offer must fit the public snapshot")
}

fn progress_snapshot(
    id: Uuid,
    version: String,
    received: u64,
    total: u64,
) -> Result<UpdateSnapshot, nodavo_local_ipc::UpdateSnapshotError> {
    UpdateSnapshot::new(
        UpdatePhase::Downloading,
        Some(id.hyphenated().to_string()),
        Some(version),
        Some(received),
        Some(total),
        None,
    )
}

fn paused_snapshot(id: Uuid, version: String, received: u64, total: u64) -> UpdateSnapshot {
    UpdateSnapshot::new(
        UpdatePhase::DownloadPaused,
        Some(id.hyphenated().to_string()),
        Some(version),
        Some(received.min(total)),
        Some(total),
        None,
    )
    .expect("bounded paused progress must be valid")
}

fn complete_snapshot(id: Uuid, version: String, total: u64) -> UpdateSnapshot {
    UpdateSnapshot::new(
        UpdatePhase::VerifiedStaged,
        Some(id.hyphenated().to_string()),
        Some(version),
        Some(total),
        Some(total),
        None,
    )
    .expect("verified staged progress must be valid")
}

fn failure_snapshot(phase: UpdatePhase, failure: UpdateFailureCode) -> UpdateSnapshot {
    UpdateSnapshot::new(phase, None, None, None, None, Some(failure))
        .expect("constant updater failure snapshot must be valid")
}

fn internal_failure_snapshot() -> UpdateSnapshot {
    failure_snapshot(UpdatePhase::Failed, UpdateFailureCode::Internal)
}

fn target_platform() -> Result<&'static str, CoordinatorError> {
    if cfg!(target_os = "macos") {
        Ok("macos")
    } else if cfg!(target_os = "windows") {
        Ok("windows")
    } else {
        Err(CoordinatorError::NotConfigured)
    }
}

fn target_architecture() -> Result<&'static str, CoordinatorError> {
    match std::env::consts::ARCH {
        "aarch64" => Ok("aarch64"),
        "x86_64" => Ok("x86_64"),
        _ => Err(CoordinatorError::NotConfigured),
    }
}

fn install_identity() -> Result<&'static str, CoordinatorError> {
    if cfg!(target_os = "macos") {
        Ok("dev.nodavo.macos")
    } else if cfg!(target_os = "windows") {
        Ok("dev.nodavo.Nodavo")
    } else {
        Err(CoordinatorError::NotConfigured)
    }
}

fn update_state_directory() -> Result<PathBuf, CoordinatorError> {
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var_os("HOME").ok_or(CoordinatorError::NotConfigured)?;
        Ok(PathBuf::from(home)
            .join("Library")
            .join("Application Support")
            .join("Nodavo"))
    }
    #[cfg(target_os = "windows")]
    {
        let local = std::env::var_os("LOCALAPPDATA").ok_or(CoordinatorError::NotConfigured)?;
        return Ok(PathBuf::from(local).join("Nodavo"));
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let home = std::env::var_os("HOME").ok_or(CoordinatorError::NotConfigured)?;
        Ok(PathBuf::from(home)
            .join(".local")
            .join("state")
            .join("nodavo"))
    }
    #[cfg(not(any(unix, target_os = "windows")))]
    Err(CoordinatorError::NotConfigured)
}

#[cfg(test)]
mod tests;
