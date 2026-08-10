use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signer as _, SigningKey};
use nodavo_local_ipc::{UpdateFailureCode, UpdatePhase};
use nodavo_update::{
    ArtifactId, ArtifactStaging, DownloadMetadata, DownloadRequest, DownloadStream,
    ExternalEffectError, HttpsDownloader, ReleaseManifest, RollbackState, StagedArtifactState,
    UpdateRuntimeError, UpdateSession, VerificationPolicy,
};
use semver::Version;
use serde_json::json;
use sha2::{Digest as _, Sha256};

use super::*;

#[derive(Default)]
struct FakeStage {
    bytes: Vec<u8>,
    sealed: bool,
}

impl ArtifactStaging for FakeStage {
    fn inspect(
        &mut self,
        _artifact: ArtifactId,
    ) -> Result<StagedArtifactState, ExternalEffectError> {
        if self.sealed {
            Ok(StagedArtifactState::Sealed(self.bytes.len() as u64))
        } else if self.bytes.is_empty() {
            Ok(StagedArtifactState::Missing)
        } else {
            Ok(StagedArtifactState::Partial(self.bytes.len() as u64))
        }
    }

    fn read_at(
        &mut self,
        _artifact: ArtifactId,
        offset: u64,
        buffer: &mut [u8],
    ) -> Result<usize, ExternalEffectError> {
        let offset = usize::try_from(offset).map_err(|_| ExternalEffectError)?;
        let available = self.bytes.get(offset..).ok_or(ExternalEffectError)?;
        let count = available.len().min(buffer.len());
        buffer[..count].copy_from_slice(&available[..count]);
        Ok(count)
    }

    fn append(
        &mut self,
        _artifact: ArtifactId,
        expected_offset: u64,
        bytes: &[u8],
    ) -> Result<(), ExternalEffectError> {
        if self.sealed || self.bytes.len() as u64 != expected_offset {
            return Err(ExternalEffectError);
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    fn reset(&mut self, _artifact: ArtifactId) -> Result<(), ExternalEffectError> {
        if self.sealed {
            return Err(ExternalEffectError);
        }
        self.bytes.clear();
        Ok(())
    }

    fn seal(&mut self, artifact: ArtifactId) -> Result<(), ExternalEffectError> {
        if self.bytes.len() as u64 != artifact.size() {
            return Err(ExternalEffectError);
        }
        self.sealed = true;
        Ok(())
    }

    fn discard(&mut self, _artifact: ArtifactId) -> Result<(), ExternalEffectError> {
        self.bytes.clear();
        self.sealed = false;
        Ok(())
    }
}

struct GateState {
    entered: bool,
    released: bool,
}

struct FakeStream {
    metadata: DownloadMetadata,
    bytes: Arc<Vec<u8>>,
    cursor: usize,
    fail_after: Option<usize>,
    fail_once: Arc<AtomicBool>,
    gate: Option<Arc<(Mutex<GateState>, Condvar)>>,
}

impl DownloadStream for FakeStream {
    fn metadata(&self) -> &DownloadMetadata {
        &self.metadata
    }

    fn read_chunk(&mut self, buffer: &mut [u8]) -> Result<usize, ExternalEffectError> {
        if let Some(gate) = self.gate.take() {
            let (state, wake) = &*gate;
            let mut state = state.lock().map_err(|_| ExternalEffectError)?;
            state.entered = true;
            wake.notify_all();
            while !state.released {
                state = wake.wait(state).map_err(|_| ExternalEffectError)?;
            }
        }
        if self.fail_after.is_some_and(|limit| self.cursor >= limit)
            && self.fail_once.swap(false, Ordering::SeqCst)
        {
            return Err(ExternalEffectError);
        }
        if self.cursor == self.bytes.len() {
            return Ok(0);
        }
        let mut count = (self.bytes.len() - self.cursor).min(buffer.len());
        if self.fail_once.load(Ordering::SeqCst)
            && let Some(limit) = self.fail_after
        {
            count = count.min(limit.saturating_sub(self.cursor));
        }
        if count == 0 {
            return Err(ExternalEffectError);
        }
        buffer[..count].copy_from_slice(&self.bytes[self.cursor..self.cursor + count]);
        self.cursor += count;
        Ok(count)
    }
}

struct FakeDownloader {
    bytes: Arc<Vec<u8>>,
    requested_offsets: Arc<Mutex<Vec<u64>>>,
    fail_after: Option<usize>,
    fail_once: Arc<AtomicBool>,
    gate: Option<Arc<(Mutex<GateState>, Condvar)>>,
}

impl HttpsDownloader for FakeDownloader {
    type Stream = FakeStream;

    fn open(&mut self, request: &DownloadRequest) -> Result<Self::Stream, ExternalEffectError> {
        self.requested_offsets
            .lock()
            .map_err(|_| ExternalEffectError)?
            .push(request.resume_from());
        Ok(FakeStream {
            metadata: DownloadMetadata::new(
                request.url(),
                request.resume_from(),
                request.expected_size(),
            )
            .map_err(|_| ExternalEffectError)?,
            bytes: Arc::clone(&self.bytes),
            cursor: usize::try_from(request.resume_from()).map_err(|_| ExternalEffectError)?,
            fail_after: self.fail_after,
            fail_once: Arc::clone(&self.fail_once),
            gate: self.gate.take(),
        })
    }
}

struct TestEffects {
    manifest: Vec<u8>,
    downloader: FakeDownloader,
    staging: FakeStage,
}

impl CoordinatorEffects for TestEffects {
    fn fetch_manifest(&mut self) -> Result<Vec<u8>, ExternalEffectError> {
        Ok(self.manifest.clone())
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
        session.stage_download(&mut self.downloader, &mut reporting)
    }
}

fn test_coordinator(
    artifact: &[u8],
    artifact_url: &str,
    release_version: &str,
    staging: FakeStage,
    fail_after: Option<usize>,
    gate: Option<Arc<(Mutex<GateState>, Condvar)>>,
) -> (UpdateCoordinator, Arc<Mutex<Vec<u64>>>) {
    let key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let digest = Sha256::digest(artifact);
    let manifest_value = json!({
        "schema": 1,
        "product": "nodavo",
        "channel": "stable",
        "platform": "macos",
        "arch": "aarch64",
        "version": release_version,
        "minimum_version": "1.0.0",
        "artifact_url": artifact_url,
        "artifact_size": artifact.len(),
        "artifact_sha256": format!("{digest:x}"),
        "rollback_epoch": 1
    });
    let manifest: ReleaseManifest = serde_json::from_value(manifest_value.clone()).unwrap();
    let signature = key.sign(&manifest.canonical_bytes().unwrap());
    let envelope = serde_json::to_vec(&json!({
        "manifest": manifest_value,
        "signature": STANDARD.encode(signature.to_bytes())
    }))
    .unwrap();
    let installed = Version::parse("1.0.0").unwrap();
    let policy = VerificationPolicy::new(
        "nodavo",
        "stable",
        "macos",
        "aarch64",
        "dev.nodavo.macos",
        installed.clone(),
    )
    .unwrap();
    let offsets = Arc::new(Mutex::new(Vec::new()));
    let effects = TestEffects {
        manifest: envelope,
        downloader: FakeDownloader {
            bytes: Arc::new(artifact.to_vec()),
            requested_offsets: Arc::clone(&offsets),
            fail_after,
            fail_once: Arc::new(AtomicBool::new(fail_after.is_some())),
            gate,
        },
        staging,
    };
    (
        UpdateCoordinator::new(
            ReleaseVerifier::new(key.verifying_key(), policy),
            RollbackState::new(0, installed),
            HttpsOrigin::parse("https://updates.example.test/manifest.json").unwrap(),
            Box::new(effects),
        ),
        offsets,
    )
}

fn offer_id(coordinator: &UpdateCoordinator) -> String {
    coordinator
        .check_for_update()
        .unwrap()
        .offer_id()
        .unwrap()
        .to_owned()
}

fn accept(coordinator: &UpdateCoordinator, id: &str) -> DownloadToken {
    match coordinator.record_decision(id, true).unwrap() {
        DecisionOutcome::StartDownload { snapshot, token } => {
            assert_eq!(snapshot.phase(), UpdatePhase::ConsentRecorded);
            token
        }
        DecisionOutcome::Complete(_) => panic!("approval must schedule a download"),
    }
}

#[test]
fn exact_canonical_offer_consent_stages_without_activation() {
    let artifact = b"verified update bytes";
    let (coordinator, offsets) = test_coordinator(
        artifact,
        "https://updates.example.test/artifact.pkg",
        "2.0.0",
        FakeStage::default(),
        None,
        None,
    );
    let id = offer_id(&coordinator);
    assert_eq!(
        coordinator.record_decision(&id.to_uppercase(), true),
        Err(CoordinatorError::OfferMismatch)
    );
    assert_eq!(
        coordinator.record_decision(&Uuid::new_v4().hyphenated().to_string(), true),
        Err(CoordinatorError::OfferMismatch)
    );

    let token = accept(&coordinator, &id);
    let staged = coordinator.download_offer(token).unwrap();
    assert_eq!(staged.phase(), UpdatePhase::VerifiedStaged);
    assert_eq!(staged.received_bytes(), staged.total_bytes());
    assert_eq!(*offsets.lock().unwrap(), vec![0]);
}

#[test]
fn paused_exact_offer_is_idempotently_resumed_without_redeciding_core_consent() {
    let artifact = b"resume this update";
    let (coordinator, offsets) = test_coordinator(
        artifact,
        "https://updates.example.test/artifact.pkg",
        "2.0.0",
        FakeStage::default(),
        Some(4),
        None,
    );
    let id = offer_id(&coordinator);
    let first = accept(&coordinator, &id);
    let paused = coordinator.download_offer(first).unwrap();
    assert_eq!(paused.phase(), UpdatePhase::DownloadPaused);
    assert_eq!(paused.received_bytes(), Some(4));
    assert_eq!(
        coordinator.record_decision(&id, false),
        Err(CoordinatorError::InvalidTransition)
    );

    let resumed = accept(&coordinator, &id);
    assert_eq!(
        coordinator.download_offer(resumed).unwrap().phase(),
        UpdatePhase::VerifiedStaged
    );
    assert_eq!(*offsets.lock().unwrap(), vec![0, 4]);
}

#[test]
fn fixed_origin_and_up_to_date_are_distinguished_from_valid_offer() {
    let (mismatch, _) = test_coordinator(
        b"bytes",
        "https://cdn.example.test/artifact.pkg",
        "2.0.0",
        FakeStage::default(),
        None,
        None,
    );
    let rejected = mismatch.check_for_update().unwrap();
    assert_eq!(rejected.phase(), UpdatePhase::Failed);
    assert_eq!(
        rejected.failure(),
        Some(UpdateFailureCode::ManifestRejected)
    );

    let (current, _) = test_coordinator(
        b"bytes",
        "https://updates.example.test/artifact.pkg",
        "1.0.0",
        FakeStage::default(),
        None,
        None,
    );
    assert_eq!(
        current.check_for_update().unwrap().phase(),
        UpdatePhase::UpToDate
    );
}

#[test]
fn accepted_decision_returns_before_blocking_download_and_status_remains_pollable() {
    let gate = Arc::new((
        Mutex::new(GateState {
            entered: false,
            released: false,
        }),
        Condvar::new(),
    ));
    let (coordinator, _) = test_coordinator(
        b"blocking artifact",
        "https://updates.example.test/artifact.pkg",
        "2.0.0",
        FakeStage::default(),
        None,
        Some(Arc::clone(&gate)),
    );
    let coordinator = Arc::new(coordinator);
    let id = offer_id(&coordinator);
    let token = accept(&coordinator, &id);
    let worker_coordinator = Arc::clone(&coordinator);
    let worker = std::thread::spawn(move || worker_coordinator.download_offer(token));

    let (state, wake) = &*gate;
    let mut state = state.lock().unwrap();
    while !state.entered {
        state = wake.wait(state).unwrap();
    }
    assert_eq!(coordinator.snapshot().phase(), UpdatePhase::Downloading);
    assert_eq!(coordinator.check_for_update(), Err(CoordinatorError::Busy));
    assert_eq!(
        coordinator.record_decision(&id, true),
        Err(CoordinatorError::Busy)
    );
    state.released = true;
    wake.notify_all();
    drop(state);

    assert_eq!(
        worker.join().unwrap().unwrap().phase(),
        UpdatePhase::VerifiedStaged
    );
}
