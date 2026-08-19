//! Bounded one-shot handoff into a stable update supervisor.
//!
//! The handoff carries only the original signed manifest envelope and a
//! replay identifier. It deliberately cannot represent a filesystem path,
//! installation plan, reducer action, transaction, or process attempt. The
//! receiving supervisor must re-verify the envelope and sealed artifact while
//! it owns the protected update transaction.

use std::fmt;

use serde::{Deserialize, Serialize};

#[cfg(any(feature = "supervisor-host", test))]
use crate::{
    ArtifactId, AttemptId, ExternalEffectError, InstallTarget, MAX_VERSION_BYTES, ReleaseVerifier,
    RollbackState, SupervisionJournal, SupervisionPolicy, TransactionId, plan_supervisor_install,
};
use crate::{MAX_MANIFEST_BYTES, UpdateRuntimeError};
#[cfg(any(feature = "supervisor-host", test))]
use semver::Version;

/// Current binary install-handoff schema.
pub const INSTALL_HANDOFF_SCHEMA: u16 = 1;
/// Exact fixed header size of an install handoff.
pub const INSTALL_HANDOFF_HEADER_BYTES: usize = 48;
/// Largest accepted install handoff, including its fixed header.
pub const MAX_INSTALL_HANDOFF_BYTES: usize = MAX_MANIFEST_BYTES + INSTALL_HANDOFF_HEADER_BYTES;

const INSTALL_HANDOFF_MAGIC: &[u8; 8] = b"NDVHOF01";
const INSTALL_AND_RESTART_KIND: u8 = 1;
const RESERVED_BYTE: u8 = 0;

/// One-shot replay identifier minted for an explicit install/restart request.
///
/// This value is not authentication. The stable supervisor authenticates the
/// peer process separately and durably reserves this value under its protected
/// transaction. Its debug form is redacted to keep it out of diagnostics.
#[derive(Clone, Copy, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct InstallRequestId([u8; 32]);

impl InstallRequestId {
    /// Creates a nonzero one-shot request identifier.
    ///
    /// # Errors
    ///
    /// Rejects the all-zero sentinel.
    pub fn new(bytes: [u8; 32]) -> Result<Self, UpdateRuntimeError> {
        if bytes == [0; 32] {
            return Err(UpdateRuntimeError::CorruptPersistentState);
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl<'de> Deserialize<'de> for InstallRequestId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = <[u8; 32]>::deserialize(deserializer)?;
        Self::new(bytes).map_err(serde::de::Error::custom)
    }
}

impl fmt::Debug for InstallRequestId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InstallRequestId([REDACTED])")
    }
}

/// Exact explicit install/restart request delivered to the stable supervisor.
///
/// The original signed envelope is intentionally retained as raw bytes so the
/// supervisor, rather than the old agent, performs authoritative verification.
#[derive(Eq, PartialEq)]
pub struct InstallAndRestartHandoff {
    request_id: InstallRequestId,
    signed_manifest_envelope: Vec<u8>,
}

impl InstallAndRestartHandoff {
    /// Creates a bounded one-shot request for the exact signed envelope.
    ///
    /// # Errors
    ///
    /// Rejects an empty or oversized envelope.
    pub(crate) fn new(
        request_id: InstallRequestId,
        signed_manifest_envelope: Vec<u8>,
    ) -> Result<Self, UpdateRuntimeError> {
        InstallRequestId::new(*request_id.as_bytes())?;
        if signed_manifest_envelope.is_empty()
            || signed_manifest_envelope.len() > MAX_MANIFEST_BYTES
        {
            return Err(UpdateRuntimeError::CorruptPersistentState);
        }
        Ok(Self {
            request_id,
            signed_manifest_envelope,
        })
    }

    #[must_use]
    pub const fn request_id(&self) -> InstallRequestId {
        self.request_id
    }

    #[cfg(any(feature = "supervisor-host", test))]
    #[must_use]
    pub fn signed_manifest_envelope(&self) -> &[u8] {
        &self.signed_manifest_envelope
    }

    /// Encodes the fixed-header, raw-envelope handoff.
    ///
    /// # Errors
    ///
    /// Rejects an internally invalid request or a length that cannot be
    /// represented by the fixed codec.
    pub fn encode(&self) -> Result<Vec<u8>, UpdateRuntimeError> {
        InstallRequestId::new(*self.request_id.as_bytes())?;
        let envelope_len = self.signed_manifest_envelope.len();
        if envelope_len == 0 || envelope_len > MAX_MANIFEST_BYTES {
            return Err(UpdateRuntimeError::CorruptPersistentState);
        }
        let envelope_len =
            u32::try_from(envelope_len).map_err(|_| UpdateRuntimeError::CorruptPersistentState)?;
        let mut encoded =
            Vec::with_capacity(INSTALL_HANDOFF_HEADER_BYTES + self.signed_manifest_envelope.len());
        encoded.extend_from_slice(INSTALL_HANDOFF_MAGIC);
        encoded.extend_from_slice(&INSTALL_HANDOFF_SCHEMA.to_be_bytes());
        encoded.push(INSTALL_AND_RESTART_KIND);
        encoded.push(RESERVED_BYTE);
        encoded.extend_from_slice(self.request_id.as_bytes());
        encoded.extend_from_slice(&envelope_len.to_be_bytes());
        encoded.extend_from_slice(&self.signed_manifest_envelope);
        Ok(encoded)
    }

    /// Decodes one strictly bounded canonical handoff.
    ///
    /// # Errors
    ///
    /// Rejects truncated, oversized, unknown-version, unknown-kind,
    /// noncanonical, empty, or trailing input before allocating the envelope.
    #[cfg(any(feature = "supervisor-host", test))]
    pub fn decode(encoded: &[u8]) -> Result<Self, UpdateRuntimeError> {
        if encoded.len() <= INSTALL_HANDOFF_HEADER_BYTES
            || encoded.len() > MAX_INSTALL_HANDOFF_BYTES
            || &encoded[..8] != INSTALL_HANDOFF_MAGIC
            || u16::from_be_bytes([encoded[8], encoded[9]]) != INSTALL_HANDOFF_SCHEMA
            || encoded[10] != INSTALL_AND_RESTART_KIND
            || encoded[11] != RESERVED_BYTE
        {
            return Err(UpdateRuntimeError::CorruptPersistentState);
        }

        let mut request_id = [0_u8; 32];
        request_id.copy_from_slice(&encoded[12..44]);
        let request_id = InstallRequestId::new(request_id)?;
        let envelope_len = u32::from_be_bytes(
            encoded[44..48]
                .try_into()
                .map_err(|_| UpdateRuntimeError::CorruptPersistentState)?,
        );
        let envelope_len = usize::try_from(envelope_len)
            .map_err(|_| UpdateRuntimeError::CorruptPersistentState)?;
        if envelope_len == 0
            || envelope_len > MAX_MANIFEST_BYTES
            || encoded.len() != INSTALL_HANDOFF_HEADER_BYTES + envelope_len
        {
            return Err(UpdateRuntimeError::CorruptPersistentState);
        }
        Self::new(request_id, encoded[INSTALL_HANDOFF_HEADER_BYTES..].to_vec())
    }
}

impl fmt::Debug for InstallAndRestartHandoff {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InstallAndRestartHandoff")
            .field(
                "signed_manifest_envelope_bytes",
                &self.signed_manifest_envelope.len(),
            )
            .finish_non_exhaustive()
    }
}

/// Exact installed target authenticated through the bound old process and
/// current platform installation while the stable supervisor lock is held.
///
/// This and the reducer host APIs are compiled only with `supervisor-host`.
/// That non-default feature is a packaging/build trust boundary preventing the
/// ordinary agent from linking admission/action APIs; it does not replace
/// mutual process authentication, protected storage, or exclusive locking.
#[cfg(any(feature = "supervisor-host", test))]
#[derive(Clone, Eq, PartialEq)]
pub struct AuthenticatedInstalledTarget {
    target: InstallTarget,
    version: Version,
}

#[cfg(any(feature = "supervisor-host", test))]
impl AuthenticatedInstalledTarget {
    /// Creates exact locally authenticated installed-target evidence.
    ///
    /// The platform host must construct this only after binding the current
    /// connection to the exact old process and inspecting the fixed installed
    /// target. This constructor validates bounds but is not authentication.
    ///
    /// # Errors
    ///
    /// Rejects an unbounded semantic-version representation.
    pub fn new(target: InstallTarget, version: Version) -> Result<Self, UpdateRuntimeError> {
        target.validate()?;
        if version.to_string().len() > MAX_VERSION_BYTES {
            return Err(UpdateRuntimeError::CorruptPersistentState);
        }
        Ok(Self { target, version })
    }

    #[must_use]
    pub const fn target(&self) -> &InstallTarget {
        &self.target
    }

    #[must_use]
    pub const fn version(&self) -> &Version {
        &self.version
    }
}

#[cfg(any(feature = "supervisor-host", test))]
impl fmt::Debug for AuthenticatedInstalledTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedInstalledTarget")
            .field("platform", &self.target.platform())
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

/// Stable-supervisor boundary that begins one protected initial transaction.
///
/// Implementations live only in the separately authenticated supervisor. A
/// successful call provisionally reserves the request under the held lock,
/// proves that no active journal exists, binds the exact authenticated old
/// process, and holds the exclusive installation lock for the returned
/// transaction. It must not durably consume or tombstone the request before
/// `persist_initial_and_reload` commits the request and journal together.
#[cfg(any(feature = "supervisor-host", test))]
pub trait InitialSupervisionHost {
    type Transaction<'a>: InitialSupervisionTransaction
    where
        Self: 'a;

    /// Provisionally reserves one request and starts an expected-absent
    /// transaction without writing a durable request tombstone.
    ///
    /// # Errors
    ///
    /// Returns an error for replay, an existing journal, failed peer binding,
    /// or unavailable protected storage/lock ownership.
    fn begin_initial(
        &mut self,
        request_id: InstallRequestId,
    ) -> Result<Self::Transaction<'_>, ExternalEffectError>;
}

/// Supervisor-owned protected state held across initial verification.
#[cfg(any(feature = "supervisor-host", test))]
pub trait InitialSupervisionTransaction {
    /// Authenticates the exact current process/install target before release
    /// verification policy or rollback state is trusted.
    ///
    /// # Errors
    ///
    /// Returns an error unless the bound old process and fixed current install
    /// can both be authenticated without accepting caller-supplied identity.
    fn authenticate_current_install(
        &mut self,
    ) -> Result<AuthenticatedInstalledTarget, ExternalEffectError>;

    /// Loads the fresh authenticated rollback floor while exclusivity is held.
    ///
    /// # Errors
    ///
    /// Returns an error if protected rollback state cannot be authenticated.
    fn rollback_floor(&mut self) -> Result<RollbackState, ExternalEffectError>;

    /// Reopens the fixed content-addressed sealed artifact and verifies its
    /// exact size and SHA-256 without executing or activating it.
    ///
    /// # Errors
    ///
    /// Returns an error for missing, mutable, unreadable, or mismatched bytes.
    fn verify_sealed_artifact(&mut self, artifact: ArtifactId) -> Result<(), ExternalEffectError>;

    /// Supervisor-generated identity for the new durable transaction.
    fn transaction_id(&mut self) -> TransactionId;

    /// Supervisor-generated identity bound to the exact old agent process.
    fn old_process_exit_attempt(&mut self) -> AttemptId;

    /// Atomically persists the expected-absent initial journal and reloads it
    /// through the authenticated store.
    ///
    /// The protected replacement must atomically commit the request replay
    /// tombstone, exact old-process binding, and journal together. It must fail
    /// if an active journal exists or the request was consumed. The returned
    /// bytes must be the authenticated durable record just reloaded from the
    /// store. No activation or process launch is permitted by this operation.
    /// Once called, either success or error is commit-ambiguous to the caller:
    /// the lock and admission must remain closed until authenticated store
    /// recovery proves the durable outcome. No retry, action, or new request is
    /// authorized from the immediate return value alone.
    ///
    /// # Errors
    ///
    /// Returns an error unless atomic replacement, durability, authentication,
    /// and exact reload all succeed while the exclusive lock remains held.
    fn persist_initial_and_reload(
        &mut self,
        encoded_journal: &[u8],
    ) -> Result<Vec<u8>, ExternalEffectError>;
}

/// Re-verifies and durably hands one install/restart request to a stable
/// supervisor without returning an installation plan, journal, or action.
///
/// The caller supplies supervisor-local fixed policy, never agent-provided
/// target or plan data. Failures before the persistence call authorize no
/// action. A persistence error or non-exact reload is commit-ambiguous and
/// requires authenticated store recovery before retry or reducer execution.
///
/// # Errors
///
/// Rejects replay/busy state, invalid signed metadata, stale rollback state,
/// target mismatch, rejected staged bytes, invalid generated evidence, or a
/// failed/non-exact authenticated journal replacement.
#[cfg(any(feature = "supervisor-host", test))]
pub fn accept_install_and_restart<H>(
    verifier: &ReleaseVerifier,
    policy: SupervisionPolicy,
    request: &InstallAndRestartHandoff,
    host: &mut H,
) -> Result<(), UpdateRuntimeError>
where
    H: InitialSupervisionHost,
{
    let mut transaction = host
        .begin_initial(request.request_id())
        .map_err(|_| UpdateRuntimeError::JournalFailed)?;
    let installed = transaction
        .authenticate_current_install()
        .map_err(|_| UpdateRuntimeError::AuthenticatedInstalledTargetMismatch)?;
    let floor = transaction
        .rollback_floor()
        .map_err(|_| UpdateRuntimeError::RollbackStateFailed)?;
    let release = verifier
        .verify_json(request.signed_manifest_envelope(), &floor)
        .map_err(UpdateRuntimeError::Manifest)?;
    if release.installed_version() != installed.version()
        || release.install_identity() != installed.target().identifier()
        || release.manifest().platform() != installed.target().platform()
    {
        return Err(UpdateRuntimeError::AuthenticatedInstalledTargetMismatch);
    }
    let plan = plan_supervisor_install(&release, installed.target().clone(), &floor)?;
    transaction
        .verify_sealed_artifact(plan.artifact())
        .map_err(|_| UpdateRuntimeError::ArtifactVerificationFailed)?;
    let transaction_id = transaction.transaction_id();
    let old_process_exit_attempt = transaction.old_process_exit_attempt();
    let journal = SupervisionJournal::from_authorized_plan(
        request.request_id(),
        transaction_id,
        old_process_exit_attempt,
        plan,
        release.installed_version().clone(),
        policy,
    )?;
    let encoded = journal.encode()?;
    let reloaded = transaction
        .persist_initial_and_reload(&encoded)
        .map_err(|_| UpdateRuntimeError::SupervisionCommitOutcomeUnknown)?;
    let reloaded_journal = SupervisionJournal::decode(&reloaded)
        .map_err(|_| UpdateRuntimeError::SupervisionCommitOutcomeUnknown)?;
    if reloaded != encoded || reloaded_journal != journal {
        return Err(UpdateRuntimeError::SupervisionCommitOutcomeUnknown);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use ed25519_dalek::{Signer as _, SigningKey};
    use semver::Version;
    use serde_json::json;
    use sha2::{Digest as _, Sha256};

    use super::*;
    use crate::{
        ReleaseManifest, SupervisionAction, SupervisionPhase, UpdateError, VerificationPolicy,
    };

    const ARTIFACT: &[u8] = b"exact sealed supervisor artifact";

    #[derive(Clone, Copy, Eq, PartialEq)]
    enum FailurePoint {
        Begin,
        CurrentInstall,
        Floor,
        SealedArtifact,
        Persist,
    }

    #[derive(Clone, Copy, Default, Eq, PartialEq)]
    enum PersistBehavior {
        #[default]
        ExactReload,
        CorruptReload,
        CommitThenError,
    }

    struct FakeHost {
        calls: Vec<&'static str>,
        floor: RollbackState,
        installed: AuthenticatedInstalledTarget,
        sealed_bytes: Vec<u8>,
        sealed: bool,
        transaction: TransactionId,
        old_process_attempt: AttemptId,
        failure: Option<FailurePoint>,
        consumed: HashSet<InstallRequestId>,
        active: bool,
        persisted: Option<Vec<u8>>,
        persist_behavior: PersistBehavior,
    }

    impl FakeHost {
        fn new() -> Self {
            Self {
                calls: Vec::new(),
                floor: RollbackState::new(6, Version::new(1, 5, 0)),
                installed: AuthenticatedInstalledTarget::new(
                    InstallTarget::macos_app_bundle("dev.nodavo.macos").unwrap(),
                    Version::new(1, 5, 0),
                )
                .unwrap(),
                sealed_bytes: ARTIFACT.to_vec(),
                sealed: true,
                transaction: TransactionId::new([2; 32]).unwrap(),
                old_process_attempt: AttemptId::new([3; 32]).unwrap(),
                failure: None,
                consumed: HashSet::new(),
                active: false,
                persisted: None,
                persist_behavior: PersistBehavior::default(),
            }
        }
    }

    struct FakeInitialTransaction<'a> {
        host: &'a mut FakeHost,
        request_id: InstallRequestId,
    }

    impl InitialSupervisionHost for FakeHost {
        type Transaction<'a> = FakeInitialTransaction<'a>;

        fn begin_initial(
            &mut self,
            request_id: InstallRequestId,
        ) -> Result<Self::Transaction<'_>, ExternalEffectError> {
            self.calls.push("begin");
            if self.failure == Some(FailurePoint::Begin)
                || self.active
                || self.consumed.contains(&request_id)
            {
                return Err(ExternalEffectError);
            }
            Ok(FakeInitialTransaction {
                host: self,
                request_id,
            })
        }
    }

    impl InitialSupervisionTransaction for FakeInitialTransaction<'_> {
        fn authenticate_current_install(
            &mut self,
        ) -> Result<AuthenticatedInstalledTarget, ExternalEffectError> {
            self.host.calls.push("current_install");
            if self.host.failure == Some(FailurePoint::CurrentInstall) {
                return Err(ExternalEffectError);
            }
            Ok(self.host.installed.clone())
        }

        fn rollback_floor(&mut self) -> Result<RollbackState, ExternalEffectError> {
            self.host.calls.push("floor");
            if self.host.failure == Some(FailurePoint::Floor) {
                return Err(ExternalEffectError);
            }
            Ok(self.host.floor.clone())
        }

        fn verify_sealed_artifact(
            &mut self,
            artifact: ArtifactId,
        ) -> Result<(), ExternalEffectError> {
            self.host.calls.push("sealed_artifact");
            if self.host.failure == Some(FailurePoint::SealedArtifact) || !self.host.sealed {
                return Err(ExternalEffectError);
            }
            let observed: [u8; 32] = Sha256::digest(&self.host.sealed_bytes).into();
            if artifact.size()
                != u64::try_from(self.host.sealed_bytes.len()).map_err(|_| ExternalEffectError)?
                || artifact.sha256() != &observed
            {
                return Err(ExternalEffectError);
            }
            Ok(())
        }

        fn transaction_id(&mut self) -> TransactionId {
            self.host.calls.push("transaction_id");
            self.host.transaction
        }

        fn old_process_exit_attempt(&mut self) -> AttemptId {
            self.host.calls.push("old_process_attempt");
            self.host.old_process_attempt
        }

        fn persist_initial_and_reload(
            &mut self,
            encoded_journal: &[u8],
        ) -> Result<Vec<u8>, ExternalEffectError> {
            self.host.calls.push("persist");
            if self.host.failure == Some(FailurePoint::Persist)
                || self.host.active
                || self.host.consumed.contains(&self.request_id)
            {
                return Err(ExternalEffectError);
            }
            let journal =
                SupervisionJournal::decode(encoded_journal).map_err(|_| ExternalEffectError)?;
            if journal.install_request_id() != self.request_id
                || journal.transaction() != self.host.transaction
                || journal.old_process_exit_attempt() != self.host.old_process_attempt
                || journal.phase() != SupervisionPhase::Preparing
            {
                return Err(ExternalEffectError);
            }
            self.host.consumed.insert(self.request_id);
            self.host.active = true;
            self.host.persisted = Some(encoded_journal.to_vec());
            if self.host.persist_behavior == PersistBehavior::CommitThenError {
                return Err(ExternalEffectError);
            }
            let mut reloaded = encoded_journal.to_vec();
            if self.host.persist_behavior == PersistBehavior::CorruptReload {
                reloaded.push(0);
            }
            Ok(reloaded)
        }
    }

    fn request_id() -> InstallRequestId {
        InstallRequestId::new([0x41; 32]).unwrap()
    }

    fn supervision_policy() -> SupervisionPolicy {
        SupervisionPolicy::new(2, 2, 30_000, 90_000, 60_000, 90_000, 30_000).unwrap()
    }

    fn signed_request(
        artifact: &[u8],
        version: &str,
        rollback_epoch: u64,
    ) -> (ReleaseVerifier, InstallAndRestartHandoff) {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let digest = Sha256::digest(artifact);
        let manifest_value = json!({
            "schema": 1,
            "product": "nodavo",
            "channel": "stable",
            "platform": "macos",
            "arch": "aarch64",
            "version": version,
            "minimum_version": "1.0.0",
            "artifact_url": "https://updates.example.test/nodavo.zip",
            "artifact_size": artifact.len(),
            "artifact_sha256": format!("{digest:x}"),
            "rollback_epoch": rollback_epoch,
        });
        let manifest: ReleaseManifest = serde_json::from_value(manifest_value.clone()).unwrap();
        let signature = signing_key.sign(&manifest.canonical_bytes().unwrap());
        let envelope = serde_json::to_vec(&json!({
            "manifest": manifest_value,
            "signature": STANDARD.encode(signature.to_bytes()),
        }))
        .unwrap();
        let verifier = ReleaseVerifier::new(
            signing_key.verifying_key(),
            VerificationPolicy::new(
                "nodavo",
                "stable",
                "macos",
                "aarch64",
                "dev.nodavo.macos",
                Version::new(1, 5, 0),
            )
            .unwrap(),
        );
        (
            verifier,
            InstallAndRestartHandoff::new(request_id(), envelope).unwrap(),
        )
    }

    #[test]
    fn fixed_binary_codec_round_trips_and_rejects_noncanonical_input() {
        let handoff = InstallAndRestartHandoff::new(request_id(), b"signed".to_vec()).unwrap();
        let encoded = handoff.encode().unwrap();
        assert_eq!(encoded.len(), INSTALL_HANDOFF_HEADER_BYTES + 6);
        assert_eq!(InstallAndRestartHandoff::decode(&encoded).unwrap(), handoff);
        assert_eq!(
            InstallAndRestartHandoff::decode(&encoded)
                .unwrap()
                .encode()
                .unwrap(),
            encoded
        );
        assert_eq!(MAX_INSTALL_HANDOFF_BYTES, 16_432);

        for offset in [0, 8, 10, 11] {
            let mut invalid = encoded.clone();
            invalid[offset] ^= 1;
            assert_eq!(
                InstallAndRestartHandoff::decode(&invalid),
                Err(UpdateRuntimeError::CorruptPersistentState)
            );
        }
        let mut zero_id = encoded.clone();
        zero_id[12..44].fill(0);
        assert_eq!(
            InstallAndRestartHandoff::decode(&zero_id),
            Err(UpdateRuntimeError::CorruptPersistentState)
        );
        assert!(
            serde_json::from_value::<InstallRequestId>(serde_json::Value::Array(vec![
                serde_json::Value::from(0);
                32
            ]))
            .is_err()
        );
        let mut wrong_length = encoded.clone();
        wrong_length[44..48].copy_from_slice(&7_u32.to_be_bytes());
        assert_eq!(
            InstallAndRestartHandoff::decode(&wrong_length),
            Err(UpdateRuntimeError::CorruptPersistentState)
        );
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            InstallAndRestartHandoff::decode(&trailing),
            Err(UpdateRuntimeError::CorruptPersistentState)
        );
        assert_eq!(
            InstallAndRestartHandoff::decode(&encoded[..INSTALL_HANDOFF_HEADER_BYTES]),
            Err(UpdateRuntimeError::CorruptPersistentState)
        );
        assert_eq!(
            InstallAndRestartHandoff::decode(&vec![0; MAX_INSTALL_HANDOFF_BYTES + 1]),
            Err(UpdateRuntimeError::CorruptPersistentState)
        );
    }

    #[test]
    fn request_and_handoff_debug_omit_ids_and_manifest_content() {
        assert_eq!(
            format!("{:?}", request_id()),
            "InstallRequestId([REDACTED])"
        );
        let handoff =
            InstallAndRestartHandoff::new(request_id(), b"private-envelope".to_vec()).unwrap();
        let debug = format!("{handoff:?}");
        assert!(!debug.contains("private-envelope"));
        assert!(!debug.contains("InstallRequestId"));
        assert!(!debug.contains("65"));
    }

    #[test]
    fn authenticated_installed_target_revalidates_deserialized_identity() {
        let malformed: InstallTarget = serde_json::from_value(json!({
            "kind": "mac_os_app_bundle",
            "bundle_identifier": ""
        }))
        .unwrap();
        assert_eq!(
            AuthenticatedInstalledTarget::new(malformed, Version::new(1, 5, 0)),
            Err(UpdateRuntimeError::CorruptPersistentState)
        );
    }

    #[test]
    fn supervisor_reverifies_then_persists_exact_request_and_evidence() {
        let (verifier, request) = signed_request(ARTIFACT, "2.0.0", 7);
        let mut host = FakeHost::new();
        let accepted: () =
            accept_install_and_restart(&verifier, supervision_policy(), &request, &mut host)
                .unwrap();
        assert_eq!(accepted, ());
        assert_eq!(
            host.calls,
            [
                "begin",
                "current_install",
                "floor",
                "sealed_artifact",
                "transaction_id",
                "old_process_attempt",
                "persist",
            ]
        );
        let persisted = host.persisted.as_ref().unwrap();
        let journal = SupervisionJournal::decode(persisted).unwrap();
        assert_eq!(journal.install_request_id(), request_id());
        assert_eq!(journal.transaction(), host.transaction);
        assert_eq!(journal.old_process_exit_attempt(), host.old_process_attempt);
        assert_eq!(journal.phase(), SupervisionPhase::Preparing);
        assert!(matches!(
            journal.next_action().unwrap(),
            SupervisionAction::Prepare { .. }
        ));
        let debug = format!("{journal:?}");
        assert!(!debug.contains("InstallRequestId"));
        assert!(!debug.contains("65"));
    }

    #[test]
    fn precommit_failures_stop_and_persist_errors_are_commit_ambiguous() {
        let expected = [
            (
                FailurePoint::Begin,
                vec!["begin"],
                UpdateRuntimeError::JournalFailed,
            ),
            (
                FailurePoint::CurrentInstall,
                vec!["begin", "current_install"],
                UpdateRuntimeError::AuthenticatedInstalledTargetMismatch,
            ),
            (
                FailurePoint::Floor,
                vec!["begin", "current_install", "floor"],
                UpdateRuntimeError::RollbackStateFailed,
            ),
            (
                FailurePoint::SealedArtifact,
                vec!["begin", "current_install", "floor", "sealed_artifact"],
                UpdateRuntimeError::ArtifactVerificationFailed,
            ),
            (
                FailurePoint::Persist,
                vec![
                    "begin",
                    "current_install",
                    "floor",
                    "sealed_artifact",
                    "transaction_id",
                    "old_process_attempt",
                    "persist",
                ],
                UpdateRuntimeError::SupervisionCommitOutcomeUnknown,
            ),
        ];
        for (failure, calls, error) in expected {
            let (verifier, request) = signed_request(ARTIFACT, "2.0.0", 7);
            let mut host = FakeHost::new();
            host.failure = Some(failure);
            assert_eq!(
                accept_install_and_restart(&verifier, supervision_policy(), &request, &mut host,),
                Err(error)
            );
            assert_eq!(host.calls, calls);
            assert!(host.persisted.is_none());
            assert!(!host.active);
            assert!(host.consumed.is_empty());
        }
    }

    #[test]
    fn manifest_floor_target_and_sealed_bytes_fail_before_persistence() {
        let (verifier, mut request) = signed_request(ARTIFACT, "2.0.0", 7);
        request.signed_manifest_envelope[0] ^= 1;
        let mut host = FakeHost::new();
        assert!(matches!(
            accept_install_and_restart(&verifier, supervision_policy(), &request, &mut host,),
            Err(UpdateRuntimeError::Manifest(_))
        ));
        assert_eq!(host.calls, ["begin", "current_install", "floor"]);

        let (verifier, request) = signed_request(ARTIFACT, "2.0.0", 7);
        let mut stale = FakeHost::new();
        stale.floor = RollbackState::new(8, Version::new(2, 1, 0));
        assert_eq!(
            accept_install_and_restart(&verifier, supervision_policy(), &request, &mut stale,),
            Err(UpdateRuntimeError::Manifest(UpdateError::RollbackRejected))
        );
        assert_eq!(stale.calls, ["begin", "current_install", "floor"]);

        let mut wrong_version = FakeHost::new();
        wrong_version.installed = AuthenticatedInstalledTarget::new(
            InstallTarget::macos_app_bundle("dev.nodavo.macos").unwrap(),
            Version::new(1, 4, 0),
        )
        .unwrap();
        assert_eq!(
            accept_install_and_restart(
                &verifier,
                supervision_policy(),
                &request,
                &mut wrong_version,
            ),
            Err(UpdateRuntimeError::AuthenticatedInstalledTargetMismatch)
        );
        assert_eq!(wrong_version.calls, ["begin", "current_install", "floor"]);

        let mut wrong_target = FakeHost::new();
        wrong_target.installed = AuthenticatedInstalledTarget::new(
            InstallTarget::macos_app_bundle("dev.nodavo.other").unwrap(),
            Version::new(1, 5, 0),
        )
        .unwrap();
        assert_eq!(
            accept_install_and_restart(
                &verifier,
                supervision_policy(),
                &request,
                &mut wrong_target,
            ),
            Err(UpdateRuntimeError::AuthenticatedInstalledTargetMismatch)
        );
        assert_eq!(wrong_target.calls, ["begin", "current_install", "floor"]);

        let mut wrong_bytes = FakeHost::new();
        wrong_bytes.sealed_bytes.push(0);
        assert_eq!(
            accept_install_and_restart(&verifier, supervision_policy(), &request, &mut wrong_bytes,),
            Err(UpdateRuntimeError::ArtifactVerificationFailed)
        );
        assert_eq!(
            wrong_bytes.calls,
            ["begin", "current_install", "floor", "sealed_artifact"]
        );
    }

    #[test]
    fn replay_and_nonexact_authenticated_reload_fail_closed() {
        let (verifier, request) = signed_request(ARTIFACT, "2.0.0", 7);
        let mut host = FakeHost::new();
        accept_install_and_restart(&verifier, supervision_policy(), &request, &mut host).unwrap();
        host.active = false;
        host.persisted = None;
        host.calls.clear();
        assert_eq!(
            accept_install_and_restart(&verifier, supervision_policy(), &request, &mut host,),
            Err(UpdateRuntimeError::JournalFailed)
        );
        assert_eq!(host.calls, ["begin"]);

        let mut corrupt_reload = FakeHost::new();
        corrupt_reload.persist_behavior = PersistBehavior::CorruptReload;
        assert_eq!(
            accept_install_and_restart(
                &verifier,
                supervision_policy(),
                &request,
                &mut corrupt_reload,
            ),
            Err(UpdateRuntimeError::SupervisionCommitOutcomeUnknown)
        );
        assert!(corrupt_reload.active);

        let mut ambiguous_commit = FakeHost::new();
        ambiguous_commit.persist_behavior = PersistBehavior::CommitThenError;
        assert_eq!(
            accept_install_and_restart(
                &verifier,
                supervision_policy(),
                &request,
                &mut ambiguous_commit,
            ),
            Err(UpdateRuntimeError::SupervisionCommitOutcomeUnknown)
        );
        assert!(ambiguous_commit.active);
        assert!(ambiguous_commit.persisted.is_some());
        assert!(ambiguous_commit.consumed.contains(&request_id()));
    }
}
