//! Pure, write-ahead supervision policy for update activation and rollback.
//!
//! This module deliberately performs no persistence, process launch, waiting,
//! installation, or health probing. A stable host outside the installation
//! being replaced must authenticate and durably store each returned journal
//! before asking for its next action. Repeating an action after a crash is safe
//! only when the host adapters honor their documented idempotency contracts.

use std::fmt;

use semver::Version;
use serde::{Deserialize, Serialize};

use crate::{
    ArtifactId, ExternalEffectError, InstallPlan, InstallTarget, MAX_RECOVERY_JOURNAL_BYTES,
    MAX_VERSION_BYTES, RollbackState, UpdateRuntimeError,
};

/// Maximum encoded supervision journal.
pub const MAX_SUPERVISION_JOURNAL_BYTES: usize = MAX_RECOVERY_JOURNAL_BYTES;
/// Largest durable launch-attempt budget accepted from a host policy.
pub const MAX_SUPERVISION_ATTEMPTS: u8 = 8;
/// Smallest persisted supervision timeout (one second).
pub const MIN_SUPERVISION_TIMEOUT_MS: u64 = 1_000;
/// Largest persisted supervision timeout (ten minutes).
pub const MAX_SUPERVISION_TIMEOUT_MS: u64 = 10 * 60 * 1_000;

const SUPERVISION_JOURNAL_SCHEMA: u16 = 2;

/// Host boundary proving that creation consumed authorization while the stable
/// supervisor held its exclusive per-installation transaction lock.
pub trait SupervisionTransactionLock {
    /// Verifies that the caller currently owns the exclusive transaction.
    ///
    /// # Errors
    ///
    /// Returns an error if exclusivity cannot be proved without acquiring a
    /// second or weaker lock.
    fn ensure_exclusive(&mut self) -> Result<(), ExternalEffectError>;
}

/// Random transaction identity used to reject stale candidate signals.
///
/// The value is not a secret, but its `Debug` representation is redacted so it
/// cannot accidentally become a stable diagnostic identifier.
#[derive(Clone, Copy, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TransactionId([u8; 32]);

impl TransactionId {
    /// Creates a transaction identity from host-generated random bytes.
    ///
    /// # Errors
    ///
    /// Rejects the all-zero sentinel. The pure update crate never obtains
    /// randomness itself.
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

impl fmt::Debug for TransactionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TransactionId([REDACTED])")
    }
}

/// Host-generated identity for exactly one asynchronous supervision attempt.
///
/// A fresh random value is required for each candidate launch, previous-version
/// launch, and old-process exit wait. Delayed events from another attempt are
/// rejected even when they cite the same public transaction and version.
#[derive(Clone, Copy, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AttemptId([u8; 32]);

impl AttemptId {
    /// Creates an attempt identity from host-generated random bytes.
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

impl fmt::Debug for AttemptId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AttemptId([REDACTED])")
    }
}

/// Exact retained predecessor evidence required for rollback.
///
/// `artifact` binds the digest and size of the predecessor release artifact,
/// `target` binds its platform installation identity, and `installer_evidence`
/// binds opaque platform-owned evidence for the retained backup/transaction.
/// A platform adapter creates this descriptor while preparing the transaction;
/// the reducer will not authorize activation or rollback until it is durable.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryArtifactDescriptor {
    artifact: ArtifactId,
    target: InstallTarget,
    version: Version,
    installer_evidence: [u8; 32],
}

impl RecoveryArtifactDescriptor {
    /// Creates bounded cryptographic predecessor evidence.
    ///
    /// # Errors
    ///
    /// Rejects an oversized version or the all-zero evidence sentinel.
    pub fn new(
        artifact: ArtifactId,
        target: InstallTarget,
        version: Version,
        installer_evidence: [u8; 32],
    ) -> Result<Self, UpdateRuntimeError> {
        let descriptor = Self {
            artifact,
            target,
            version,
            installer_evidence,
        };
        descriptor.validate()?;
        Ok(descriptor)
    }

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
    pub const fn installer_evidence(&self) -> &[u8; 32] {
        &self.installer_evidence
    }

    fn validate(&self) -> Result<(), UpdateRuntimeError> {
        ArtifactId::new(*self.artifact.sha256(), self.artifact.size())?;
        if self.version.to_string().len() > MAX_VERSION_BYTES || self.installer_evidence == [0; 32]
        {
            return Err(UpdateRuntimeError::CorruptPersistentState);
        }
        Ok(())
    }
}

impl fmt::Debug for RecoveryArtifactDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryArtifactDescriptor")
            .field("artifact", &self.artifact)
            .field("target", &self.target)
            .field("version", &self.version)
            .field("installer_evidence", &"[REDACTED]")
            .finish()
    }
}

/// Exact activated-candidate evidence returned by the platform installer.
///
/// The descriptor must match the authenticated plan's artifact digest, size,
/// version, and target. The opaque evidence additionally binds the concrete
/// activated platform transaction inspected by the stable supervisor.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CandidateArtifactDescriptor(RecoveryArtifactDescriptor);

impl CandidateArtifactDescriptor {
    /// Creates bounded exact candidate evidence.
    ///
    /// # Errors
    ///
    /// Rejects malformed artifact or installer evidence.
    pub fn new(
        artifact: ArtifactId,
        target: InstallTarget,
        version: Version,
        installer_evidence: [u8; 32],
    ) -> Result<Self, UpdateRuntimeError> {
        RecoveryArtifactDescriptor::new(artifact, target, version, installer_evidence).map(Self)
    }

    #[must_use]
    pub const fn artifact(&self) -> ArtifactId {
        self.0.artifact()
    }

    #[must_use]
    pub const fn target(&self) -> &InstallTarget {
        self.0.target()
    }

    #[must_use]
    pub const fn version(&self) -> &Version {
        self.0.version()
    }

    #[must_use]
    pub const fn installer_evidence(&self) -> &[u8; 32] {
        self.0.installer_evidence()
    }

    fn validate(&self) -> Result<(), UpdateRuntimeError> {
        self.0.validate()
    }
}

impl fmt::Debug for CandidateArtifactDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("CandidateArtifactDescriptor")
            .field(&self.0)
            .finish()
    }
}

/// Durable retry and monotonic-deadline budgets selected before activation.
///
/// Timeout values are durations, not wall-clock timestamps. A stable host
/// starts a fresh monotonic timer for the current persisted attempt. The
/// attempt number is written before launch, so a process or machine restart
/// cannot reset the durable retry budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisionPolicy {
    maximum_candidate_start_attempts: u8,
    maximum_previous_start_attempts: u8,
    old_process_exit_timeout_ms: u64,
    candidate_start_timeout_ms: u64,
    candidate_health_timeout_ms: u64,
    previous_start_timeout_ms: u64,
    exact_process_exit_timeout_ms: u64,
}

impl SupervisionPolicy {
    /// Creates bounded durable supervision policy.
    ///
    /// # Errors
    ///
    /// Rejects zero or excessive attempt budgets and deadlines outside the
    /// fixed one-second to ten-minute range.
    pub fn new(
        maximum_candidate_start_attempts: u8,
        maximum_previous_start_attempts: u8,
        old_process_exit_timeout_ms: u64,
        candidate_start_timeout_ms: u64,
        candidate_health_timeout_ms: u64,
        previous_start_timeout_ms: u64,
        exact_process_exit_timeout_ms: u64,
    ) -> Result<Self, UpdateRuntimeError> {
        let policy = Self {
            maximum_candidate_start_attempts,
            maximum_previous_start_attempts,
            old_process_exit_timeout_ms,
            candidate_start_timeout_ms,
            candidate_health_timeout_ms,
            previous_start_timeout_ms,
            exact_process_exit_timeout_ms,
        };
        policy.validate()?;
        Ok(policy)
    }

    #[must_use]
    pub const fn maximum_candidate_start_attempts(&self) -> u8 {
        self.maximum_candidate_start_attempts
    }

    #[must_use]
    pub const fn maximum_previous_start_attempts(&self) -> u8 {
        self.maximum_previous_start_attempts
    }

    #[must_use]
    pub const fn old_process_exit_timeout_ms(&self) -> u64 {
        self.old_process_exit_timeout_ms
    }

    #[must_use]
    pub const fn candidate_start_timeout_ms(&self) -> u64 {
        self.candidate_start_timeout_ms
    }

    #[must_use]
    pub const fn candidate_health_timeout_ms(&self) -> u64 {
        self.candidate_health_timeout_ms
    }

    #[must_use]
    pub const fn previous_start_timeout_ms(&self) -> u64 {
        self.previous_start_timeout_ms
    }

    /// Deadline for proving that one exact attempted process has exited after
    /// an idempotent stop request.
    #[must_use]
    pub const fn exact_process_exit_timeout_ms(&self) -> u64 {
        self.exact_process_exit_timeout_ms
    }

    fn validate(&self) -> Result<(), UpdateRuntimeError> {
        if self.maximum_candidate_start_attempts == 0
            || self.maximum_candidate_start_attempts > MAX_SUPERVISION_ATTEMPTS
            || self.maximum_previous_start_attempts == 0
            || self.maximum_previous_start_attempts > MAX_SUPERVISION_ATTEMPTS
            || !valid_timeout(self.old_process_exit_timeout_ms)
            || !valid_timeout(self.candidate_start_timeout_ms)
            || !valid_timeout(self.candidate_health_timeout_ms)
            || !valid_timeout(self.previous_start_timeout_ms)
            || !valid_timeout(self.exact_process_exit_timeout_ms)
        {
            return Err(UpdateRuntimeError::CorruptPersistentState);
        }
        Ok(())
    }
}

/// Safe continuation after an exact candidate process has been quiesced.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateExitDisposition {
    Retry,
    RollBack,
}

/// Safe continuation after an exact predecessor process has been quiesced.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreviousExitDisposition {
    Retry,
    ManualRecoveryRequired,
}

/// Exact process image/transaction evidence carried across stop and exit
/// observations. The stable supervisor, not the launched process, constructs
/// and authenticates this value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SupervisedProcessDescriptor {
    Candidate(CandidateArtifactDescriptor),
    Previous(RecoveryArtifactDescriptor),
}

#[derive(Clone, Copy)]
enum SupervisedProcessKind {
    Candidate,
    Previous,
}

/// Durable activation state. Every effect-bearing phase is a write-ahead
/// intent: the phase must already be authenticated and durable before the host
/// executes the action returned by [`SupervisionJournal::next_action`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
pub enum SupervisionPhase {
    Preparing,
    Prepared,
    Activating,
    Activated {
        candidate_attempts: u8,
    },
    CandidateStartRequested {
        attempt: u8,
        attempt_id: AttemptId,
    },
    CandidateStarted {
        attempt: u8,
        attempt_id: AttemptId,
    },
    CandidateStopRequested {
        attempt: u8,
        attempt_id: AttemptId,
        after_exit: CandidateExitDisposition,
    },
    CandidateExitPending {
        attempt: u8,
        attempt_id: AttemptId,
        after_exit: CandidateExitDisposition,
    },
    Healthy,
    FloorAdvanced,
    CandidateCommitted,
    RollingBack,
    RollbackRestored {
        previous_attempts: u8,
    },
    PreviousStartRequested {
        attempt: u8,
        attempt_id: AttemptId,
    },
    PreviousStopRequested {
        attempt: u8,
        attempt_id: AttemptId,
        after_exit: PreviousExitDisposition,
    },
    PreviousExitPending {
        attempt: u8,
        attempt_id: AttemptId,
        after_exit: PreviousExitDisposition,
    },
    Aborted,
    PreviousRestored,
    ManualRecoveryRequired,
}

/// One authenticated observation of the action selected from a durable phase.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SupervisionObservation {
    Prepared {
        transaction: TransactionId,
        recovery: RecoveryArtifactDescriptor,
    },
    OldProcessExited {
        transaction: TransactionId,
        attempt_id: AttemptId,
    },
    OldProcessExitTimedOut {
        transaction: TransactionId,
        attempt_id: AttemptId,
    },
    Activated {
        transaction: TransactionId,
        candidate: CandidateArtifactDescriptor,
    },
    CandidateAttemptCreated {
        transaction: TransactionId,
        attempt: u8,
        attempt_id: AttemptId,
    },
    CandidateStarted {
        transaction: TransactionId,
        attempt: u8,
        attempt_id: AttemptId,
        candidate: CandidateArtifactDescriptor,
    },
    CandidateStartTimedOut {
        transaction: TransactionId,
        attempt: u8,
        attempt_id: AttemptId,
    },
    CandidateExited {
        transaction: TransactionId,
        attempt: u8,
        attempt_id: AttemptId,
    },
    CandidateStopIssued {
        transaction: TransactionId,
        attempt: u8,
        attempt_id: AttemptId,
        candidate: CandidateArtifactDescriptor,
    },
    CandidateHealthy {
        transaction: TransactionId,
        attempt: u8,
        attempt_id: AttemptId,
        candidate: CandidateArtifactDescriptor,
    },
    CandidateHealthTimedOut {
        transaction: TransactionId,
        attempt: u8,
        attempt_id: AttemptId,
    },
    RollbackFloorAdvanced {
        transaction: TransactionId,
        candidate: CandidateArtifactDescriptor,
        floor: RollbackState,
    },
    RollbackBackupRetired {
        transaction: TransactionId,
        candidate: CandidateArtifactDescriptor,
        recovery: RecoveryArtifactDescriptor,
    },
    RollbackRestored {
        transaction: TransactionId,
        recovery: RecoveryArtifactDescriptor,
    },
    PreviousAttemptCreated {
        transaction: TransactionId,
        attempt: u8,
        attempt_id: AttemptId,
    },
    PreviousStarted {
        transaction: TransactionId,
        attempt: u8,
        attempt_id: AttemptId,
        recovery: RecoveryArtifactDescriptor,
    },
    PreviousStartTimedOut {
        transaction: TransactionId,
        attempt: u8,
        attempt_id: AttemptId,
    },
    PreviousStopIssued {
        transaction: TransactionId,
        attempt: u8,
        attempt_id: AttemptId,
        recovery: RecoveryArtifactDescriptor,
    },
    ExactProcessExited {
        transaction: TransactionId,
        attempt: u8,
        attempt_id: AttemptId,
        process: SupervisedProcessDescriptor,
    },
    ExactProcessExitTimedOut {
        transaction: TransactionId,
        attempt: u8,
        attempt_id: AttemptId,
        process: SupervisedProcessDescriptor,
    },
}

/// Exactly one next host operation selected from durable state.
///
/// `Persist` is deliberately an action of its own. The host must complete and
/// authenticate that replacement before calling `next_action` on the returned
/// journal. Every other variant is idempotent and is selected only from an
/// already-persisted write-ahead phase.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SupervisionAction {
    Persist(Box<SupervisionJournal>),
    Prepare {
        transaction: TransactionId,
        plan: InstallPlan,
        expected_previous_version: Version,
    },
    WaitForOldProcessExit {
        transaction: TransactionId,
        attempt_id: AttemptId,
        timeout_ms: u64,
    },
    Activate {
        transaction: TransactionId,
        plan: InstallPlan,
        recovery: RecoveryArtifactDescriptor,
    },
    CreateCandidateAttempt {
        transaction: TransactionId,
        attempt: u8,
    },
    StartCandidate {
        transaction: TransactionId,
        attempt: u8,
        attempt_id: AttemptId,
        candidate: CandidateArtifactDescriptor,
        timeout_ms: u64,
    },
    WaitForCandidateHealth {
        transaction: TransactionId,
        attempt: u8,
        attempt_id: AttemptId,
        candidate: CandidateArtifactDescriptor,
        timeout_ms: u64,
    },
    StopCandidate {
        transaction: TransactionId,
        attempt: u8,
        attempt_id: AttemptId,
        candidate: CandidateArtifactDescriptor,
    },
    StopPrevious {
        transaction: TransactionId,
        attempt: u8,
        attempt_id: AttemptId,
        recovery: RecoveryArtifactDescriptor,
    },
    WaitForExactExit {
        transaction: TransactionId,
        attempt: u8,
        attempt_id: AttemptId,
        process: SupervisedProcessDescriptor,
        timeout_ms: u64,
    },
    AdvanceRollbackFloor {
        transaction: TransactionId,
        candidate: CandidateArtifactDescriptor,
        floor: RollbackState,
    },
    RetireRollbackBackup {
        transaction: TransactionId,
        candidate: CandidateArtifactDescriptor,
        recovery: RecoveryArtifactDescriptor,
    },
    RollBack {
        transaction: TransactionId,
        candidate: Option<CandidateArtifactDescriptor>,
        recovery: RecoveryArtifactDescriptor,
    },
    CreatePreviousAttempt {
        transaction: TransactionId,
        attempt: u8,
        recovery: RecoveryArtifactDescriptor,
    },
    StartPrevious {
        transaction: TransactionId,
        attempt: u8,
        attempt_id: AttemptId,
        recovery: RecoveryArtifactDescriptor,
        timeout_ms: u64,
    },
    ClearJournal,
    ManualRecoveryRequired,
}

/// Bounded versioned journal owned by a stable external supervisor.
///
/// Encoded bytes do not authenticate themselves. Production storage must
/// provide OS-protected integrity, atomic replacement, deletion protection,
/// and exclusive single-writer ownership outside the target being replaced.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupervisionJournal {
    transaction: TransactionId,
    old_process_exit_attempt: AttemptId,
    plan: InstallPlan,
    previous_version: Version,
    recovery: Option<RecoveryArtifactDescriptor>,
    candidate: Option<CandidateArtifactDescriptor>,
    policy: SupervisionPolicy,
    phase: SupervisionPhase,
}

impl SupervisionJournal {
    /// Creates the first write-ahead journal after distinct install/restart
    /// consent has already been recorded by the authenticated host.
    ///
    /// # Errors
    ///
    /// Rejects an invalid plan, policy, transaction, or previous version.
    pub(crate) fn from_authorized_plan(
        transaction: TransactionId,
        old_process_exit_attempt: AttemptId,
        plan: InstallPlan,
        previous_version: Version,
        policy: SupervisionPolicy,
    ) -> Result<Self, UpdateRuntimeError> {
        let journal = Self {
            transaction,
            old_process_exit_attempt,
            plan,
            previous_version,
            recovery: None,
            candidate: None,
            policy,
            phase: SupervisionPhase::Preparing,
        };
        journal.validate()?;
        Ok(journal)
    }

    #[must_use]
    pub const fn transaction(&self) -> TransactionId {
        self.transaction
    }

    #[must_use]
    pub const fn old_process_exit_attempt(&self) -> AttemptId {
        self.old_process_exit_attempt
    }

    #[must_use]
    pub const fn plan(&self) -> &InstallPlan {
        &self.plan
    }

    #[must_use]
    pub const fn previous_version(&self) -> &Version {
        &self.previous_version
    }

    #[must_use]
    pub const fn recovery(&self) -> Option<&RecoveryArtifactDescriptor> {
        self.recovery.as_ref()
    }

    #[must_use]
    pub const fn candidate(&self) -> Option<&CandidateArtifactDescriptor> {
        self.candidate.as_ref()
    }

    #[must_use]
    pub const fn policy(&self) -> SupervisionPolicy {
        self.policy
    }

    #[must_use]
    pub const fn phase(&self) -> SupervisionPhase {
        self.phase
    }

    /// Returns exactly one operation authorized by the current durable phase.
    ///
    /// A returned `Persist` is an ordering barrier, not a suggestion: none of
    /// the subsequent external effects are authorized until that exact journal
    /// has been atomically stored and authenticated.
    ///
    /// # Errors
    ///
    /// Rejects corrupt decoded or host-constructed state.
    #[allow(
        clippy::too_many_lines,
        reason = "the exhaustive durable-phase reducer is kept in one auditable match"
    )]
    pub fn next_action(&self) -> Result<SupervisionAction, UpdateRuntimeError> {
        self.validate()?;
        let action = match self.phase {
            SupervisionPhase::Preparing => SupervisionAction::Prepare {
                transaction: self.transaction,
                plan: self.plan.clone(),
                expected_previous_version: self.previous_version.clone(),
            },
            SupervisionPhase::Prepared => SupervisionAction::WaitForOldProcessExit {
                transaction: self.transaction,
                attempt_id: self.old_process_exit_attempt,
                timeout_ms: self.policy.old_process_exit_timeout_ms,
            },
            SupervisionPhase::Activating => SupervisionAction::Activate {
                transaction: self.transaction,
                plan: self.plan.clone(),
                recovery: self.required_recovery()?.clone(),
            },
            SupervisionPhase::Activated { candidate_attempts } => {
                let Some(attempt) = candidate_attempts.checked_add(1) else {
                    return Err(UpdateRuntimeError::CorruptPersistentState);
                };
                if attempt > self.policy.maximum_candidate_start_attempts {
                    SupervisionAction::Persist(Box::new(
                        self.with_phase(SupervisionPhase::RollingBack),
                    ))
                } else {
                    SupervisionAction::CreateCandidateAttempt {
                        transaction: self.transaction,
                        attempt,
                    }
                }
            }
            SupervisionPhase::CandidateStartRequested {
                attempt,
                attempt_id,
            } => SupervisionAction::StartCandidate {
                transaction: self.transaction,
                attempt,
                attempt_id,
                candidate: self.required_candidate()?.clone(),
                timeout_ms: self.policy.candidate_start_timeout_ms,
            },
            SupervisionPhase::CandidateStarted {
                attempt,
                attempt_id,
            } => SupervisionAction::WaitForCandidateHealth {
                transaction: self.transaction,
                attempt,
                attempt_id,
                candidate: self.required_candidate()?.clone(),
                timeout_ms: self.policy.candidate_health_timeout_ms,
            },
            SupervisionPhase::CandidateStopRequested {
                attempt,
                attempt_id,
                ..
            } => SupervisionAction::StopCandidate {
                transaction: self.transaction,
                attempt,
                attempt_id,
                candidate: self.required_candidate()?.clone(),
            },
            SupervisionPhase::CandidateExitPending {
                attempt,
                attempt_id,
                ..
            } => SupervisionAction::WaitForExactExit {
                transaction: self.transaction,
                attempt,
                attempt_id,
                process: SupervisedProcessDescriptor::Candidate(self.required_candidate()?.clone()),
                timeout_ms: self.policy.exact_process_exit_timeout_ms,
            },
            SupervisionPhase::Healthy => SupervisionAction::AdvanceRollbackFloor {
                transaction: self.transaction,
                candidate: self.required_candidate()?.clone(),
                floor: self.plan.rollback_floor_after_install(),
            },
            SupervisionPhase::FloorAdvanced => SupervisionAction::RetireRollbackBackup {
                transaction: self.transaction,
                candidate: self.required_candidate()?.clone(),
                recovery: self.required_recovery()?.clone(),
            },
            SupervisionPhase::CandidateCommitted
            | SupervisionPhase::PreviousRestored
            | SupervisionPhase::Aborted => SupervisionAction::ClearJournal,
            SupervisionPhase::RollingBack => SupervisionAction::RollBack {
                transaction: self.transaction,
                candidate: self.candidate.clone(),
                recovery: self.required_recovery()?.clone(),
            },
            SupervisionPhase::RollbackRestored { previous_attempts } => {
                let Some(attempt) = previous_attempts.checked_add(1) else {
                    return Err(UpdateRuntimeError::CorruptPersistentState);
                };
                if attempt > self.policy.maximum_previous_start_attempts {
                    SupervisionAction::Persist(Box::new(
                        self.with_phase(SupervisionPhase::ManualRecoveryRequired),
                    ))
                } else {
                    SupervisionAction::CreatePreviousAttempt {
                        transaction: self.transaction,
                        attempt,
                        recovery: self.required_recovery()?.clone(),
                    }
                }
            }
            SupervisionPhase::PreviousStartRequested {
                attempt,
                attempt_id,
            } => SupervisionAction::StartPrevious {
                transaction: self.transaction,
                attempt,
                attempt_id,
                recovery: self.required_recovery()?.clone(),
                timeout_ms: self.policy.previous_start_timeout_ms,
            },
            SupervisionPhase::PreviousStopRequested {
                attempt,
                attempt_id,
                ..
            } => SupervisionAction::StopPrevious {
                transaction: self.transaction,
                attempt,
                attempt_id,
                recovery: self.required_recovery()?.clone(),
            },
            SupervisionPhase::PreviousExitPending {
                attempt,
                attempt_id,
                ..
            } => SupervisionAction::WaitForExactExit {
                transaction: self.transaction,
                attempt,
                attempt_id,
                process: SupervisedProcessDescriptor::Previous(self.required_recovery()?.clone()),
                timeout_ms: self.policy.exact_process_exit_timeout_ms,
            },
            SupervisionPhase::ManualRecoveryRequired => SupervisionAction::ManualRecoveryRequired,
        };
        Ok(action)
    }

    /// Applies one authenticated observation to the current durable phase.
    ///
    /// The returned journal must be persisted before asking it for an action.
    /// If the caller crashes before persistence, recovery repeats the previous
    /// idempotent action instead of assuming its effect completed.
    ///
    /// # Errors
    ///
    /// Rejects observations for another phase or signals whose transaction,
    /// attempt identity, artifact, target, version, or installer evidence does
    /// not exactly match the current durable state.
    #[allow(
        clippy::too_many_lines,
        reason = "one exhaustive transition table keeps write-ahead ordering reviewable"
    )]
    pub fn observe(&self, observation: SupervisionObservation) -> Result<Self, UpdateRuntimeError> {
        self.validate()?;
        let phase = match (self.phase, observation) {
            (
                SupervisionPhase::Preparing,
                SupervisionObservation::Prepared {
                    transaction,
                    recovery,
                },
            ) => {
                self.validate_transaction(transaction)?;
                self.validate_recovery_descriptor(&recovery)?;
                let mut next = self.with_phase(SupervisionPhase::Prepared);
                next.recovery = Some(recovery);
                next.validate()?;
                return Ok(next);
            }
            (
                SupervisionPhase::Prepared,
                SupervisionObservation::OldProcessExited {
                    transaction,
                    attempt_id,
                },
            ) => {
                self.validate_old_process_attempt(transaction, attempt_id)?;
                SupervisionPhase::Activating
            }
            (
                SupervisionPhase::Prepared,
                SupervisionObservation::OldProcessExitTimedOut {
                    transaction,
                    attempt_id,
                },
            ) => {
                self.validate_old_process_attempt(transaction, attempt_id)?;
                SupervisionPhase::Aborted
            }
            (
                SupervisionPhase::Activating,
                SupervisionObservation::Activated {
                    transaction,
                    candidate,
                },
            ) => {
                self.validate_transaction(transaction)?;
                self.validate_candidate_descriptor(&candidate)?;
                let mut next = self.with_phase(SupervisionPhase::Activated {
                    candidate_attempts: 0,
                });
                next.candidate = Some(candidate);
                next.validate()?;
                return Ok(next);
            }
            (
                SupervisionPhase::Activated { candidate_attempts },
                SupervisionObservation::CandidateAttemptCreated {
                    transaction,
                    attempt,
                    attempt_id,
                },
            ) => {
                self.validate_transaction(transaction)?;
                AttemptId::new(*attempt_id.as_bytes())?;
                let expected = candidate_attempts
                    .checked_add(1)
                    .ok_or(UpdateRuntimeError::CorruptPersistentState)?;
                if attempt != expected || attempt > self.policy.maximum_candidate_start_attempts {
                    return Err(UpdateRuntimeError::InvalidTransition);
                }
                SupervisionPhase::CandidateStartRequested {
                    attempt,
                    attempt_id,
                }
            }
            (
                SupervisionPhase::CandidateStartRequested {
                    attempt,
                    attempt_id,
                },
                SupervisionObservation::CandidateStarted {
                    transaction,
                    attempt: observed_attempt,
                    attempt_id: observed_attempt_id,
                    candidate,
                },
            ) => {
                self.validate_candidate_event(
                    transaction,
                    observed_attempt,
                    observed_attempt_id,
                    &candidate,
                    attempt,
                    attempt_id,
                )?;
                SupervisionPhase::CandidateStarted {
                    attempt,
                    attempt_id,
                }
            }
            (
                SupervisionPhase::CandidateStartRequested {
                    attempt,
                    attempt_id,
                },
                SupervisionObservation::CandidateStartTimedOut {
                    transaction,
                    attempt: observed_attempt,
                    attempt_id: observed_attempt_id,
                }
                | SupervisionObservation::CandidateExited {
                    transaction,
                    attempt: observed_attempt,
                    attempt_id: observed_attempt_id,
                },
            ) => {
                self.validate_attempt_event(
                    transaction,
                    observed_attempt,
                    observed_attempt_id,
                    attempt,
                    attempt_id,
                )?;
                SupervisionPhase::CandidateStopRequested {
                    attempt,
                    attempt_id,
                    after_exit: candidate_exit_disposition(
                        attempt,
                        self.policy.maximum_candidate_start_attempts,
                    ),
                }
            }
            (
                SupervisionPhase::CandidateStarted {
                    attempt,
                    attempt_id,
                },
                SupervisionObservation::CandidateHealthy {
                    transaction,
                    attempt: observed_attempt,
                    attempt_id: observed_attempt_id,
                    candidate,
                },
            ) => {
                self.validate_candidate_event(
                    transaction,
                    observed_attempt,
                    observed_attempt_id,
                    &candidate,
                    attempt,
                    attempt_id,
                )?;
                SupervisionPhase::Healthy
            }
            (
                SupervisionPhase::CandidateStarted {
                    attempt,
                    attempt_id,
                },
                SupervisionObservation::CandidateHealthTimedOut {
                    transaction,
                    attempt: observed_attempt,
                    attempt_id: observed_attempt_id,
                }
                | SupervisionObservation::CandidateExited {
                    transaction,
                    attempt: observed_attempt,
                    attempt_id: observed_attempt_id,
                },
            ) => {
                self.validate_attempt_event(
                    transaction,
                    observed_attempt,
                    observed_attempt_id,
                    attempt,
                    attempt_id,
                )?;
                SupervisionPhase::CandidateStopRequested {
                    attempt,
                    attempt_id,
                    after_exit: CandidateExitDisposition::RollBack,
                }
            }
            (
                SupervisionPhase::CandidateStopRequested {
                    attempt,
                    attempt_id,
                    after_exit,
                },
                SupervisionObservation::CandidateStopIssued {
                    transaction,
                    attempt: observed_attempt,
                    attempt_id: observed_attempt_id,
                    candidate,
                },
            ) => {
                self.validate_candidate_event(
                    transaction,
                    observed_attempt,
                    observed_attempt_id,
                    &candidate,
                    attempt,
                    attempt_id,
                )?;
                SupervisionPhase::CandidateExitPending {
                    attempt,
                    attempt_id,
                    after_exit,
                }
            }
            (
                SupervisionPhase::CandidateExitPending {
                    attempt,
                    attempt_id,
                    after_exit,
                },
                SupervisionObservation::ExactProcessExited {
                    transaction,
                    attempt: observed_attempt,
                    attempt_id: observed_attempt_id,
                    process,
                },
            ) => {
                self.validate_supervised_process_event(
                    transaction,
                    observed_attempt,
                    observed_attempt_id,
                    &process,
                    attempt,
                    attempt_id,
                    SupervisedProcessKind::Candidate,
                )?;
                candidate_phase_after_exact_exit(attempt, after_exit)
            }
            (
                SupervisionPhase::CandidateExitPending {
                    attempt,
                    attempt_id,
                    ..
                },
                SupervisionObservation::ExactProcessExitTimedOut {
                    transaction,
                    attempt: observed_attempt,
                    attempt_id: observed_attempt_id,
                    process,
                },
            ) => {
                self.validate_supervised_process_event(
                    transaction,
                    observed_attempt,
                    observed_attempt_id,
                    &process,
                    attempt,
                    attempt_id,
                    SupervisedProcessKind::Candidate,
                )?;
                SupervisionPhase::ManualRecoveryRequired
            }
            (
                SupervisionPhase::Healthy,
                SupervisionObservation::RollbackFloorAdvanced {
                    transaction,
                    candidate,
                    floor,
                },
            ) => {
                self.validate_transaction(transaction)?;
                self.validate_exact_candidate_descriptor(&candidate)?;
                if floor != self.plan.rollback_floor_after_install() {
                    return Err(UpdateRuntimeError::CorruptPersistentState);
                }
                SupervisionPhase::FloorAdvanced
            }
            (
                SupervisionPhase::FloorAdvanced,
                SupervisionObservation::RollbackBackupRetired {
                    transaction,
                    candidate,
                    recovery,
                },
            ) => {
                self.validate_transaction(transaction)?;
                self.validate_exact_candidate_descriptor(&candidate)?;
                self.validate_recovery_event(&recovery)?;
                SupervisionPhase::CandidateCommitted
            }
            (
                SupervisionPhase::RollingBack,
                SupervisionObservation::RollbackRestored {
                    transaction,
                    recovery,
                },
            ) => {
                self.validate_transaction(transaction)?;
                self.validate_recovery_event(&recovery)?;
                SupervisionPhase::RollbackRestored {
                    previous_attempts: 0,
                }
            }
            (
                SupervisionPhase::RollbackRestored { previous_attempts },
                SupervisionObservation::PreviousAttemptCreated {
                    transaction,
                    attempt,
                    attempt_id,
                },
            ) => {
                self.validate_transaction(transaction)?;
                AttemptId::new(*attempt_id.as_bytes())?;
                let expected = previous_attempts
                    .checked_add(1)
                    .ok_or(UpdateRuntimeError::CorruptPersistentState)?;
                if attempt != expected || attempt > self.policy.maximum_previous_start_attempts {
                    return Err(UpdateRuntimeError::InvalidTransition);
                }
                SupervisionPhase::PreviousStartRequested {
                    attempt,
                    attempt_id,
                }
            }
            (
                SupervisionPhase::PreviousStartRequested {
                    attempt,
                    attempt_id,
                },
                SupervisionObservation::PreviousStarted {
                    transaction,
                    attempt: observed_attempt,
                    attempt_id: observed_attempt_id,
                    recovery,
                },
            ) => {
                self.validate_attempt_event(
                    transaction,
                    observed_attempt,
                    observed_attempt_id,
                    attempt,
                    attempt_id,
                )?;
                self.validate_recovery_event(&recovery)?;
                SupervisionPhase::PreviousRestored
            }
            (
                SupervisionPhase::PreviousStartRequested {
                    attempt,
                    attempt_id,
                },
                SupervisionObservation::PreviousStartTimedOut {
                    transaction,
                    attempt: observed_attempt,
                    attempt_id: observed_attempt_id,
                },
            ) => {
                self.validate_attempt_event(
                    transaction,
                    observed_attempt,
                    observed_attempt_id,
                    attempt,
                    attempt_id,
                )?;
                SupervisionPhase::PreviousStopRequested {
                    attempt,
                    attempt_id,
                    after_exit: previous_exit_disposition(
                        attempt,
                        self.policy.maximum_previous_start_attempts,
                    ),
                }
            }
            (
                SupervisionPhase::PreviousStopRequested {
                    attempt,
                    attempt_id,
                    after_exit,
                },
                SupervisionObservation::PreviousStopIssued {
                    transaction,
                    attempt: observed_attempt,
                    attempt_id: observed_attempt_id,
                    recovery,
                },
            ) => {
                self.validate_attempt_event(
                    transaction,
                    observed_attempt,
                    observed_attempt_id,
                    attempt,
                    attempt_id,
                )?;
                self.validate_recovery_event(&recovery)?;
                SupervisionPhase::PreviousExitPending {
                    attempt,
                    attempt_id,
                    after_exit,
                }
            }
            (
                SupervisionPhase::PreviousExitPending {
                    attempt,
                    attempt_id,
                    after_exit,
                },
                SupervisionObservation::ExactProcessExited {
                    transaction,
                    attempt: observed_attempt,
                    attempt_id: observed_attempt_id,
                    process,
                },
            ) => {
                self.validate_supervised_process_event(
                    transaction,
                    observed_attempt,
                    observed_attempt_id,
                    &process,
                    attempt,
                    attempt_id,
                    SupervisedProcessKind::Previous,
                )?;
                previous_phase_after_exact_exit(attempt, after_exit)
            }
            (
                SupervisionPhase::PreviousExitPending {
                    attempt,
                    attempt_id,
                    ..
                },
                SupervisionObservation::ExactProcessExitTimedOut {
                    transaction,
                    attempt: observed_attempt,
                    attempt_id: observed_attempt_id,
                    process,
                },
            ) => {
                self.validate_supervised_process_event(
                    transaction,
                    observed_attempt,
                    observed_attempt_id,
                    &process,
                    attempt,
                    attempt_id,
                    SupervisedProcessKind::Previous,
                )?;
                SupervisionPhase::ManualRecoveryRequired
            }
            _ => return Err(UpdateRuntimeError::InvalidTransition),
        };
        let next = self.with_phase(phase);
        next.validate()?;
        Ok(next)
    }

    /// Encodes the bounded journal for an authenticated atomic store.
    ///
    /// # Errors
    ///
    /// Rejects invalid state or an encoded journal above its hard bound.
    pub fn encode(&self) -> Result<Vec<u8>, UpdateRuntimeError> {
        self.validate()?;
        let encoded = serde_json::to_vec(&SupervisionJournalDisk {
            schema: SUPERVISION_JOURNAL_SCHEMA,
            transaction: self.transaction,
            old_process_exit_attempt: self.old_process_exit_attempt,
            plan: self.plan.clone(),
            previous_version: self.previous_version.clone(),
            recovery: self.recovery.clone(),
            candidate: self.candidate.clone(),
            policy: self.policy,
            phase: self.phase,
        })
        .map_err(|_| UpdateRuntimeError::CorruptPersistentState)?;
        if encoded.len() > MAX_SUPERVISION_JOURNAL_BYTES {
            return Err(UpdateRuntimeError::CorruptPersistentState);
        }
        Ok(encoded)
    }

    /// Decodes one bounded journal from an already authenticated store.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, malformed, unknown-version, or inconsistent
    /// records. Authentication must be completed by the store before decoding.
    pub fn decode(bytes: &[u8]) -> Result<Self, UpdateRuntimeError> {
        if bytes.is_empty() || bytes.len() > MAX_SUPERVISION_JOURNAL_BYTES {
            return Err(UpdateRuntimeError::CorruptPersistentState);
        }
        let disk: SupervisionJournalDisk = serde_json::from_slice(bytes)
            .map_err(|_| UpdateRuntimeError::CorruptPersistentState)?;
        if disk.schema != SUPERVISION_JOURNAL_SCHEMA {
            return Err(UpdateRuntimeError::CorruptPersistentState);
        }
        let journal = Self {
            transaction: disk.transaction,
            old_process_exit_attempt: disk.old_process_exit_attempt,
            plan: disk.plan,
            previous_version: disk.previous_version,
            recovery: disk.recovery,
            candidate: disk.candidate,
            policy: disk.policy,
            phase: disk.phase,
        };
        journal.validate()?;
        Ok(journal)
    }

    fn validate(&self) -> Result<(), UpdateRuntimeError> {
        TransactionId::new(*self.transaction.as_bytes())?;
        AttemptId::new(*self.old_process_exit_attempt.as_bytes())?;
        self.plan.validate()?;
        self.policy.validate()?;
        if self.previous_version.to_string().len() > MAX_VERSION_BYTES
            || self.previous_version >= *self.plan.version()
        {
            return Err(UpdateRuntimeError::CorruptPersistentState);
        }
        self.validate_descriptors()?;
        self.validate_phase_attempts()?;
        self.validate_exit_disposition()?;
        Ok(())
    }

    fn validate_descriptors(&self) -> Result<(), UpdateRuntimeError> {
        let recovery_required = !matches!(self.phase, SupervisionPhase::Preparing);
        if recovery_required {
            self.validate_recovery_descriptor(self.required_recovery()?)?;
        } else if self.recovery.is_some() {
            return Err(UpdateRuntimeError::CorruptPersistentState);
        }
        let candidate_required = matches!(
            self.phase,
            SupervisionPhase::Activated { .. }
                | SupervisionPhase::CandidateStartRequested { .. }
                | SupervisionPhase::CandidateStarted { .. }
                | SupervisionPhase::CandidateStopRequested { .. }
                | SupervisionPhase::CandidateExitPending { .. }
                | SupervisionPhase::Healthy
                | SupervisionPhase::FloorAdvanced
                | SupervisionPhase::CandidateCommitted
        );
        if candidate_required {
            self.validate_candidate_descriptor(self.required_candidate()?)?;
        } else if matches!(
            self.phase,
            SupervisionPhase::Preparing | SupervisionPhase::Prepared | SupervisionPhase::Activating
        ) && self.candidate.is_some()
        {
            return Err(UpdateRuntimeError::CorruptPersistentState);
        } else if let Some(candidate) = &self.candidate {
            self.validate_candidate_descriptor(candidate)?;
        }
        Ok(())
    }

    fn validate_phase_attempts(&self) -> Result<(), UpdateRuntimeError> {
        match self.phase {
            SupervisionPhase::Activated { candidate_attempts } => {
                if candidate_attempts > self.policy.maximum_candidate_start_attempts {
                    return Err(UpdateRuntimeError::CorruptPersistentState);
                }
            }
            SupervisionPhase::CandidateStartRequested {
                attempt,
                attempt_id,
            }
            | SupervisionPhase::CandidateStarted {
                attempt,
                attempt_id,
            }
            | SupervisionPhase::CandidateStopRequested {
                attempt,
                attempt_id,
                ..
            }
            | SupervisionPhase::CandidateExitPending {
                attempt,
                attempt_id,
                ..
            } => {
                if attempt == 0 || attempt > self.policy.maximum_candidate_start_attempts {
                    return Err(UpdateRuntimeError::CorruptPersistentState);
                }
                AttemptId::new(*attempt_id.as_bytes())?;
            }
            SupervisionPhase::RollbackRestored { previous_attempts } => {
                if previous_attempts > self.policy.maximum_previous_start_attempts {
                    return Err(UpdateRuntimeError::CorruptPersistentState);
                }
            }
            SupervisionPhase::PreviousStartRequested {
                attempt,
                attempt_id,
            }
            | SupervisionPhase::PreviousStopRequested {
                attempt,
                attempt_id,
                ..
            }
            | SupervisionPhase::PreviousExitPending {
                attempt,
                attempt_id,
                ..
            } => {
                if attempt == 0 || attempt > self.policy.maximum_previous_start_attempts {
                    return Err(UpdateRuntimeError::CorruptPersistentState);
                }
                AttemptId::new(*attempt_id.as_bytes())?;
            }
            SupervisionPhase::Preparing
            | SupervisionPhase::Prepared
            | SupervisionPhase::Activating
            | SupervisionPhase::Healthy
            | SupervisionPhase::FloorAdvanced
            | SupervisionPhase::CandidateCommitted
            | SupervisionPhase::RollingBack
            | SupervisionPhase::PreviousRestored
            | SupervisionPhase::Aborted
            | SupervisionPhase::ManualRecoveryRequired => {}
        }
        Ok(())
    }

    fn validate_exit_disposition(&self) -> Result<(), UpdateRuntimeError> {
        match self.phase {
            SupervisionPhase::CandidateStopRequested {
                attempt,
                after_exit,
                ..
            }
            | SupervisionPhase::CandidateExitPending {
                attempt,
                after_exit,
                ..
            } if after_exit == CandidateExitDisposition::Retry
                && attempt >= self.policy.maximum_candidate_start_attempts =>
            {
                return Err(UpdateRuntimeError::CorruptPersistentState);
            }
            SupervisionPhase::PreviousStopRequested {
                attempt,
                after_exit,
                ..
            }
            | SupervisionPhase::PreviousExitPending {
                attempt,
                after_exit,
                ..
            } if after_exit == PreviousExitDisposition::Retry
                && attempt >= self.policy.maximum_previous_start_attempts =>
            {
                return Err(UpdateRuntimeError::CorruptPersistentState);
            }
            _ => {}
        }
        Ok(())
    }

    fn validate_transaction(&self, transaction: TransactionId) -> Result<(), UpdateRuntimeError> {
        if transaction != self.transaction {
            return Err(UpdateRuntimeError::CandidateMismatch);
        }
        Ok(())
    }

    fn validate_old_process_attempt(
        &self,
        transaction: TransactionId,
        attempt_id: AttemptId,
    ) -> Result<(), UpdateRuntimeError> {
        if transaction != self.transaction || attempt_id != self.old_process_exit_attempt {
            return Err(UpdateRuntimeError::CandidateMismatch);
        }
        Ok(())
    }

    fn validate_attempt_event(
        &self,
        transaction: TransactionId,
        observed_attempt: u8,
        observed_attempt_id: AttemptId,
        expected_attempt: u8,
        expected_attempt_id: AttemptId,
    ) -> Result<(), UpdateRuntimeError> {
        if transaction != self.transaction
            || observed_attempt != expected_attempt
            || observed_attempt_id != expected_attempt_id
        {
            return Err(UpdateRuntimeError::CandidateMismatch);
        }
        Ok(())
    }

    fn validate_candidate_event(
        &self,
        transaction: TransactionId,
        observed_attempt: u8,
        observed_attempt_id: AttemptId,
        candidate: &CandidateArtifactDescriptor,
        expected_attempt: u8,
        expected_attempt_id: AttemptId,
    ) -> Result<(), UpdateRuntimeError> {
        self.validate_attempt_event(
            transaction,
            observed_attempt,
            observed_attempt_id,
            expected_attempt,
            expected_attempt_id,
        )?;
        self.validate_exact_candidate_descriptor(candidate)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "all exact process signal components are compared at one trust boundary"
    )]
    fn validate_supervised_process_event(
        &self,
        transaction: TransactionId,
        observed_attempt: u8,
        observed_attempt_id: AttemptId,
        process: &SupervisedProcessDescriptor,
        expected_attempt: u8,
        expected_attempt_id: AttemptId,
        expected_kind: SupervisedProcessKind,
    ) -> Result<(), UpdateRuntimeError> {
        self.validate_attempt_event(
            transaction,
            observed_attempt,
            observed_attempt_id,
            expected_attempt,
            expected_attempt_id,
        )?;
        match (expected_kind, process) {
            (
                SupervisedProcessKind::Candidate,
                SupervisedProcessDescriptor::Candidate(candidate),
            ) => {
                self.validate_exact_candidate_descriptor(candidate)?;
            }
            (SupervisedProcessKind::Previous, SupervisedProcessDescriptor::Previous(recovery)) => {
                self.validate_recovery_event(recovery)?;
            }
            _ => return Err(UpdateRuntimeError::CandidateMismatch),
        }
        Ok(())
    }

    fn validate_candidate_descriptor(
        &self,
        candidate: &CandidateArtifactDescriptor,
    ) -> Result<(), UpdateRuntimeError> {
        candidate.validate()?;
        if candidate.artifact() != self.plan.artifact()
            || candidate.target() != self.plan.target()
            || candidate.version() != self.plan.version()
        {
            return Err(UpdateRuntimeError::CorruptPersistentState);
        }
        Ok(())
    }

    fn validate_exact_candidate_descriptor(
        &self,
        candidate: &CandidateArtifactDescriptor,
    ) -> Result<(), UpdateRuntimeError> {
        self.validate_candidate_descriptor(candidate)?;
        if candidate != self.required_candidate()? {
            return Err(UpdateRuntimeError::CandidateMismatch);
        }
        Ok(())
    }

    fn required_recovery(&self) -> Result<&RecoveryArtifactDescriptor, UpdateRuntimeError> {
        self.recovery
            .as_ref()
            .ok_or(UpdateRuntimeError::CorruptPersistentState)
    }

    fn required_candidate(&self) -> Result<&CandidateArtifactDescriptor, UpdateRuntimeError> {
        self.candidate
            .as_ref()
            .ok_or(UpdateRuntimeError::CorruptPersistentState)
    }

    fn validate_recovery_descriptor(
        &self,
        recovery: &RecoveryArtifactDescriptor,
    ) -> Result<(), UpdateRuntimeError> {
        recovery.validate()?;
        if recovery.version() != &self.previous_version || recovery.target() != self.plan.target() {
            return Err(UpdateRuntimeError::CorruptPersistentState);
        }
        Ok(())
    }

    fn validate_recovery_event(
        &self,
        recovery: &RecoveryArtifactDescriptor,
    ) -> Result<(), UpdateRuntimeError> {
        self.validate_recovery_descriptor(recovery)?;
        if recovery != self.required_recovery()? {
            return Err(UpdateRuntimeError::CandidateMismatch);
        }
        Ok(())
    }

    fn with_phase(&self, phase: SupervisionPhase) -> Self {
        Self {
            transaction: self.transaction,
            old_process_exit_attempt: self.old_process_exit_attempt,
            plan: self.plan.clone(),
            previous_version: self.previous_version.clone(),
            recovery: self.recovery.clone(),
            candidate: self.candidate.clone(),
            policy: self.policy,
            phase,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SupervisionJournalDisk {
    schema: u16,
    transaction: TransactionId,
    old_process_exit_attempt: AttemptId,
    plan: InstallPlan,
    previous_version: Version,
    recovery: Option<RecoveryArtifactDescriptor>,
    candidate: Option<CandidateArtifactDescriptor>,
    policy: SupervisionPolicy,
    phase: SupervisionPhase,
}

const fn valid_timeout(timeout_ms: u64) -> bool {
    timeout_ms >= MIN_SUPERVISION_TIMEOUT_MS && timeout_ms <= MAX_SUPERVISION_TIMEOUT_MS
}

const fn candidate_exit_disposition(attempt: u8, maximum: u8) -> CandidateExitDisposition {
    if attempt < maximum {
        CandidateExitDisposition::Retry
    } else {
        CandidateExitDisposition::RollBack
    }
}

const fn candidate_phase_after_exact_exit(
    attempt: u8,
    disposition: CandidateExitDisposition,
) -> SupervisionPhase {
    match disposition {
        CandidateExitDisposition::Retry => SupervisionPhase::Activated {
            candidate_attempts: attempt,
        },
        CandidateExitDisposition::RollBack => SupervisionPhase::RollingBack,
    }
}

const fn previous_exit_disposition(attempt: u8, maximum: u8) -> PreviousExitDisposition {
    if attempt < maximum {
        PreviousExitDisposition::Retry
    } else {
        PreviousExitDisposition::ManualRecoveryRequired
    }
}

const fn previous_phase_after_exact_exit(
    attempt: u8,
    disposition: PreviousExitDisposition,
) -> SupervisionPhase {
    match disposition {
        PreviousExitDisposition::Retry => SupervisionPhase::RollbackRestored {
            previous_attempts: attempt,
        },
        PreviousExitDisposition::ManualRecoveryRequired => SupervisionPhase::ManualRecoveryRequired,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transaction(byte: u8) -> TransactionId {
        TransactionId::new([byte; 32]).unwrap()
    }

    fn attempt(byte: u8) -> AttemptId {
        AttemptId::new([byte; 32]).unwrap()
    }

    fn policy(candidate_attempts: u8, previous_attempts: u8) -> SupervisionPolicy {
        SupervisionPolicy::new(
            candidate_attempts,
            previous_attempts,
            30_000,
            90_000,
            60_000,
            90_000,
            30_000,
        )
        .unwrap()
    }

    fn journal_with_policy(policy: SupervisionPolicy) -> SupervisionJournal {
        SupervisionJournal::from_authorized_plan(
            transaction(1),
            attempt(10),
            InstallPlan::test_macos(Version::new(2, 0, 0), 7),
            Version::new(1, 5, 0),
            policy,
        )
        .unwrap()
    }

    fn journal() -> SupervisionJournal {
        journal_with_policy(policy(2, 2))
    }

    fn recovery() -> RecoveryArtifactDescriptor {
        RecoveryArtifactDescriptor::new(
            ArtifactId::new([9; 32], 96).unwrap(),
            InstallTarget::macos_app_bundle("dev.nodavo.macos").unwrap(),
            Version::new(1, 5, 0),
            [3; 32],
        )
        .unwrap()
    }

    fn candidate() -> CandidateArtifactDescriptor {
        CandidateArtifactDescriptor::new(
            ArtifactId::new([7; 32], 128).unwrap(),
            InstallTarget::macos_app_bundle("dev.nodavo.macos").unwrap(),
            Version::new(2, 0, 0),
            [4; 32],
        )
        .unwrap()
    }

    fn prepared(journal: &SupervisionJournal) -> SupervisionJournal {
        journal
            .observe(SupervisionObservation::Prepared {
                transaction: journal.transaction(),
                recovery: recovery(),
            })
            .unwrap()
    }

    fn activated() -> SupervisionJournal {
        prepared(&journal())
            .observe(SupervisionObservation::OldProcessExited {
                transaction: transaction(1),
                attempt_id: attempt(10),
            })
            .unwrap()
            .observe(SupervisionObservation::Activated {
                transaction: transaction(1),
                candidate: candidate(),
            })
            .unwrap()
    }

    fn candidate_start_requested() -> SupervisionJournal {
        activated()
            .observe(SupervisionObservation::CandidateAttemptCreated {
                transaction: transaction(1),
                attempt: 1,
                attempt_id: attempt(11),
            })
            .unwrap()
    }

    fn candidate_started() -> SupervisionJournal {
        let journal = candidate_start_requested();
        journal
            .observe(SupervisionObservation::CandidateStarted {
                transaction: journal.transaction(),
                attempt: 1,
                attempt_id: attempt(11),
                candidate: candidate(),
            })
            .unwrap()
    }

    fn candidate_process() -> SupervisedProcessDescriptor {
        SupervisedProcessDescriptor::Candidate(candidate())
    }

    fn previous_process() -> SupervisedProcessDescriptor {
        SupervisedProcessDescriptor::Previous(recovery())
    }

    fn stop_candidate_and_confirm_exact_exit(mut state: SupervisionJournal) -> SupervisionJournal {
        let (attempt_number, attempt_id) = match state.phase() {
            SupervisionPhase::CandidateStopRequested {
                attempt,
                attempt_id,
                ..
            } => (attempt, attempt_id),
            phase => panic!("expected candidate stop request, got {phase:?}"),
        };
        assert_eq!(
            state.next_action().unwrap(),
            SupervisionAction::StopCandidate {
                transaction: transaction(1),
                attempt: attempt_number,
                attempt_id,
                candidate: candidate(),
            }
        );
        state = state
            .observe(SupervisionObservation::CandidateStopIssued {
                transaction: transaction(1),
                attempt: attempt_number,
                attempt_id,
                candidate: candidate(),
            })
            .unwrap();
        assert_eq!(
            state.next_action().unwrap(),
            SupervisionAction::WaitForExactExit {
                transaction: transaction(1),
                attempt: attempt_number,
                attempt_id,
                process: candidate_process(),
                timeout_ms: 30_000,
            }
        );
        state
            .observe(SupervisionObservation::ExactProcessExited {
                transaction: transaction(1),
                attempt: attempt_number,
                attempt_id,
                process: candidate_process(),
            })
            .unwrap()
    }

    fn stop_previous_and_confirm_exact_exit(mut state: SupervisionJournal) -> SupervisionJournal {
        let (attempt_number, attempt_id) = match state.phase() {
            SupervisionPhase::PreviousStopRequested {
                attempt,
                attempt_id,
                ..
            } => (attempt, attempt_id),
            phase => panic!("expected previous stop request, got {phase:?}"),
        };
        assert_eq!(
            state.next_action().unwrap(),
            SupervisionAction::StopPrevious {
                transaction: transaction(1),
                attempt: attempt_number,
                attempt_id,
                recovery: recovery(),
            }
        );
        state = state
            .observe(SupervisionObservation::PreviousStopIssued {
                transaction: transaction(1),
                attempt: attempt_number,
                attempt_id,
                recovery: recovery(),
            })
            .unwrap();
        assert_eq!(
            state.next_action().unwrap(),
            SupervisionAction::WaitForExactExit {
                transaction: transaction(1),
                attempt: attempt_number,
                attempt_id,
                process: previous_process(),
                timeout_ms: 30_000,
            }
        );
        state
            .observe(SupervisionObservation::ExactProcessExited {
                transaction: transaction(1),
                attempt: attempt_number,
                attempt_id,
                process: previous_process(),
            })
            .unwrap()
    }

    fn rollback_after_candidate_timeout() -> SupervisionJournal {
        let stopping = candidate_started()
            .observe(SupervisionObservation::CandidateHealthTimedOut {
                transaction: transaction(1),
                attempt: 1,
                attempt_id: attempt(11),
            })
            .unwrap();
        stop_candidate_and_confirm_exact_exit(stopping)
    }

    fn rollback_restored() -> SupervisionJournal {
        rollback_after_candidate_timeout()
            .observe(SupervisionObservation::RollbackRestored {
                transaction: transaction(1),
                recovery: recovery(),
            })
            .unwrap()
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the full happy path asserts every externally visible durable barrier"
    )]
    fn happy_path_is_one_durable_action_at_a_time_and_advances_floor_before_retirement() {
        let mut journal = journal();
        assert_eq!(
            journal.next_action().unwrap(),
            SupervisionAction::Prepare {
                transaction: transaction(1),
                plan: InstallPlan::test_macos(Version::new(2, 0, 0), 7),
                expected_previous_version: Version::new(1, 5, 0),
            }
        );

        journal = prepared(&journal);
        assert_eq!(journal.phase(), SupervisionPhase::Prepared);
        assert_eq!(
            journal.next_action().unwrap(),
            SupervisionAction::WaitForOldProcessExit {
                transaction: transaction(1),
                attempt_id: attempt(10),
                timeout_ms: 30_000,
            }
        );

        journal = journal
            .observe(SupervisionObservation::OldProcessExited {
                transaction: transaction(1),
                attempt_id: attempt(10),
            })
            .unwrap();
        assert_eq!(
            journal.next_action().unwrap(),
            SupervisionAction::Activate {
                transaction: transaction(1),
                plan: InstallPlan::test_macos(Version::new(2, 0, 0), 7),
                recovery: recovery(),
            }
        );
        journal = journal
            .observe(SupervisionObservation::Activated {
                transaction: transaction(1),
                candidate: candidate(),
            })
            .unwrap();

        assert_eq!(
            journal.next_action().unwrap(),
            SupervisionAction::CreateCandidateAttempt {
                transaction: transaction(1),
                attempt: 1,
            }
        );
        journal = journal
            .observe(SupervisionObservation::CandidateAttemptCreated {
                transaction: transaction(1),
                attempt: 1,
                attempt_id: attempt(11),
            })
            .unwrap();
        assert_eq!(
            journal.next_action().unwrap(),
            SupervisionAction::StartCandidate {
                transaction: transaction(1),
                attempt: 1,
                attempt_id: attempt(11),
                candidate: candidate(),
                timeout_ms: 90_000,
            }
        );

        journal = journal
            .observe(SupervisionObservation::CandidateStarted {
                transaction: transaction(1),
                attempt: 1,
                attempt_id: attempt(11),
                candidate: candidate(),
            })
            .unwrap();
        assert_eq!(
            journal.next_action().unwrap(),
            SupervisionAction::WaitForCandidateHealth {
                transaction: transaction(1),
                attempt: 1,
                attempt_id: attempt(11),
                candidate: candidate(),
                timeout_ms: 60_000,
            }
        );

        journal = journal
            .observe(SupervisionObservation::CandidateHealthy {
                transaction: transaction(1),
                attempt: 1,
                attempt_id: attempt(11),
                candidate: candidate(),
            })
            .unwrap();
        assert_eq!(
            journal.next_action().unwrap(),
            SupervisionAction::AdvanceRollbackFloor {
                transaction: transaction(1),
                candidate: candidate(),
                floor: RollbackState::new(7, Version::new(2, 0, 0)),
            }
        );

        journal = journal
            .observe(SupervisionObservation::RollbackFloorAdvanced {
                transaction: transaction(1),
                candidate: candidate(),
                floor: RollbackState::new(7, Version::new(2, 0, 0)),
            })
            .unwrap();
        assert_eq!(journal.phase(), SupervisionPhase::FloorAdvanced);
        assert_eq!(
            journal.next_action().unwrap(),
            SupervisionAction::RetireRollbackBackup {
                transaction: transaction(1),
                candidate: candidate(),
                recovery: recovery(),
            }
        );

        journal = journal
            .observe(SupervisionObservation::RollbackBackupRetired {
                transaction: transaction(1),
                candidate: candidate(),
                recovery: recovery(),
            })
            .unwrap();
        assert_eq!(journal.phase(), SupervisionPhase::CandidateCommitted);
        assert_eq!(
            journal.next_action().unwrap(),
            SupervisionAction::ClearJournal
        );
    }

    #[test]
    fn exact_transaction_attempt_and_candidate_evidence_gate_start_and_health() {
        let requested = candidate_start_requested();
        assert_eq!(
            requested.observe(SupervisionObservation::CandidateStarted {
                transaction: transaction(2),
                attempt: 1,
                attempt_id: attempt(11),
                candidate: candidate(),
            }),
            Err(UpdateRuntimeError::CandidateMismatch)
        );
        assert_eq!(
            requested.observe(SupervisionObservation::CandidateStarted {
                transaction: transaction(1),
                attempt: 1,
                attempt_id: attempt(12),
                candidate: candidate(),
            }),
            Err(UpdateRuntimeError::CandidateMismatch)
        );
        let substituted = CandidateArtifactDescriptor::new(
            ArtifactId::new([7; 32], 128).unwrap(),
            InstallTarget::macos_app_bundle("dev.nodavo.macos").unwrap(),
            Version::new(2, 0, 0),
            [8; 32],
        )
        .unwrap();
        assert_eq!(
            requested.observe(SupervisionObservation::CandidateStarted {
                transaction: transaction(1),
                attempt: 1,
                attempt_id: attempt(11),
                candidate: substituted.clone(),
            }),
            Err(UpdateRuntimeError::CandidateMismatch)
        );

        let started = candidate_started();
        assert_eq!(
            started.observe(SupervisionObservation::CandidateHealthy {
                transaction: transaction(2),
                attempt: 1,
                attempt_id: attempt(11),
                candidate: candidate(),
            }),
            Err(UpdateRuntimeError::CandidateMismatch)
        );
        assert_eq!(
            started.observe(SupervisionObservation::CandidateHealthy {
                transaction: transaction(1),
                attempt: 1,
                attempt_id: attempt(11),
                candidate: substituted,
            }),
            Err(UpdateRuntimeError::CandidateMismatch)
        );
    }

    #[test]
    fn candidate_start_attempts_survive_codec_round_trip_and_end_in_rollback() {
        let first = candidate_start_requested();
        let stopping = first
            .observe(SupervisionObservation::CandidateStartTimedOut {
                transaction: transaction(1),
                attempt: 1,
                attempt_id: attempt(11),
            })
            .unwrap();
        assert_eq!(
            stopping.phase(),
            SupervisionPhase::CandidateStopRequested {
                attempt: 1,
                attempt_id: attempt(11),
                after_exit: CandidateExitDisposition::Retry,
            }
        );
        let after_timeout = stop_candidate_and_confirm_exact_exit(stopping);
        assert_eq!(
            after_timeout.phase(),
            SupervisionPhase::Activated {
                candidate_attempts: 1
            }
        );

        let recovered = SupervisionJournal::decode(&after_timeout.encode().unwrap()).unwrap();
        assert_eq!(
            recovered.next_action().unwrap(),
            SupervisionAction::CreateCandidateAttempt {
                transaction: transaction(1),
                attempt: 2,
            }
        );
        let second = recovered
            .observe(SupervisionObservation::CandidateAttemptCreated {
                transaction: transaction(1),
                attempt: 2,
                attempt_id: attempt(12),
            })
            .unwrap();
        assert_eq!(
            second.phase(),
            SupervisionPhase::CandidateStartRequested {
                attempt: 2,
                attempt_id: attempt(12),
            }
        );
        let stopping = second
            .observe(SupervisionObservation::CandidateStartTimedOut {
                transaction: transaction(1),
                attempt: 2,
                attempt_id: attempt(12),
            })
            .unwrap();
        assert_eq!(
            stopping.phase(),
            SupervisionPhase::CandidateStopRequested {
                attempt: 2,
                attempt_id: attempt(12),
                after_exit: CandidateExitDisposition::RollBack,
            }
        );
        let rollback = stop_candidate_and_confirm_exact_exit(stopping);
        assert_eq!(rollback.phase(), SupervisionPhase::RollingBack);
        assert_eq!(
            rollback.next_action().unwrap(),
            SupervisionAction::RollBack {
                transaction: transaction(1),
                candidate: Some(candidate()),
                recovery: recovery(),
            }
        );
    }

    #[test]
    fn timed_out_candidate_cannot_retry_or_rollback_before_exact_exit() {
        let stopping = candidate_start_requested()
            .observe(SupervisionObservation::CandidateStartTimedOut {
                transaction: transaction(1),
                attempt: 1,
                attempt_id: attempt(11),
            })
            .unwrap();
        assert!(matches!(
            stopping.next_action().unwrap(),
            SupervisionAction::StopCandidate { .. }
        ));
        assert_eq!(
            stopping.observe(SupervisionObservation::CandidateStarted {
                transaction: transaction(1),
                attempt: 1,
                attempt_id: attempt(11),
                candidate: candidate(),
            }),
            Err(UpdateRuntimeError::InvalidTransition)
        );
        assert_eq!(
            stopping.observe(SupervisionObservation::CandidateAttemptCreated {
                transaction: transaction(1),
                attempt: 2,
                attempt_id: attempt(12),
            }),
            Err(UpdateRuntimeError::InvalidTransition)
        );

        let pending = stopping
            .observe(SupervisionObservation::CandidateStopIssued {
                transaction: transaction(1),
                attempt: 1,
                attempt_id: attempt(11),
                candidate: candidate(),
            })
            .unwrap();
        let pending = SupervisionJournal::decode(&pending.encode().unwrap()).unwrap();
        assert!(matches!(
            pending.next_action().unwrap(),
            SupervisionAction::WaitForExactExit { .. }
        ));
        assert_eq!(
            pending.observe(SupervisionObservation::ExactProcessExited {
                transaction: transaction(1),
                attempt: 1,
                attempt_id: attempt(12),
                process: candidate_process(),
            }),
            Err(UpdateRuntimeError::CandidateMismatch)
        );
        let manual = pending
            .observe(SupervisionObservation::ExactProcessExitTimedOut {
                transaction: transaction(1),
                attempt: 1,
                attempt_id: attempt(11),
                process: candidate_process(),
            })
            .unwrap();
        assert_eq!(manual.phase(), SupervisionPhase::ManualRecoveryRequired);
        assert_eq!(
            manual.next_action().unwrap(),
            SupervisionAction::ManualRecoveryRequired
        );
    }

    #[test]
    fn timed_out_predecessor_cannot_retry_before_exact_exit() {
        let requested = rollback_restored()
            .observe(SupervisionObservation::PreviousAttemptCreated {
                transaction: transaction(1),
                attempt: 1,
                attempt_id: attempt(20),
            })
            .unwrap();
        let stopping = requested
            .observe(SupervisionObservation::PreviousStartTimedOut {
                transaction: transaction(1),
                attempt: 1,
                attempt_id: attempt(20),
            })
            .unwrap();
        assert!(matches!(
            stopping.next_action().unwrap(),
            SupervisionAction::StopPrevious { .. }
        ));
        assert_eq!(
            stopping.observe(SupervisionObservation::PreviousAttemptCreated {
                transaction: transaction(1),
                attempt: 2,
                attempt_id: attempt(21),
            }),
            Err(UpdateRuntimeError::InvalidTransition)
        );
        let pending = stopping
            .observe(SupervisionObservation::PreviousStopIssued {
                transaction: transaction(1),
                attempt: 1,
                attempt_id: attempt(20),
                recovery: recovery(),
            })
            .unwrap();
        assert_eq!(
            pending.observe(SupervisionObservation::ExactProcessExited {
                transaction: transaction(1),
                attempt: 1,
                attempt_id: attempt(20),
                process: candidate_process(),
            }),
            Err(UpdateRuntimeError::CandidateMismatch)
        );
        let retry = pending
            .observe(SupervisionObservation::ExactProcessExited {
                transaction: transaction(1),
                attempt: 1,
                attempt_id: attempt(20),
                process: previous_process(),
            })
            .unwrap();
        assert_eq!(
            retry.phase(),
            SupervisionPhase::RollbackRestored {
                previous_attempts: 1
            }
        );
    }

    #[test]
    fn candidate_exit_before_health_rolls_back_without_floor_or_commit_action() {
        let stopping = candidate_started()
            .observe(SupervisionObservation::CandidateExited {
                transaction: transaction(1),
                attempt: 1,
                attempt_id: attempt(11),
            })
            .unwrap();
        assert_eq!(
            stopping.phase(),
            SupervisionPhase::CandidateStopRequested {
                attempt: 1,
                attempt_id: attempt(11),
                after_exit: CandidateExitDisposition::RollBack,
            }
        );
        let rollback = stop_candidate_and_confirm_exact_exit(stopping);
        assert_eq!(rollback.phase(), SupervisionPhase::RollingBack);
        assert_eq!(
            rollback.next_action().unwrap(),
            SupervisionAction::RollBack {
                transaction: transaction(1),
                candidate: Some(candidate()),
                recovery: recovery(),
            }
        );
    }

    #[test]
    fn rollback_is_impossible_without_exact_durable_predecessor_evidence() {
        let mut rollback = candidate_started()
            .observe(SupervisionObservation::CandidateHealthTimedOut {
                transaction: transaction(1),
                attempt: 1,
                attempt_id: attempt(11),
            })
            .unwrap();
        rollback.recovery = None;
        assert_eq!(
            rollback.next_action(),
            Err(UpdateRuntimeError::CorruptPersistentState)
        );
        assert_eq!(
            rollback.encode(),
            Err(UpdateRuntimeError::CorruptPersistentState)
        );
    }

    #[test]
    fn prepared_observation_binds_artifact_target_version_and_installer_evidence() {
        let descriptor = recovery();
        assert_eq!(descriptor.artifact().sha256(), &[9; 32]);
        assert_eq!(descriptor.artifact().size(), 96);
        assert_eq!(descriptor.target(), journal().plan().target());
        assert_eq!(descriptor.version(), &Version::new(1, 5, 0));
        assert_eq!(descriptor.installer_evidence(), &[3; 32]);

        let wrong_target = RecoveryArtifactDescriptor::new(
            descriptor.artifact(),
            InstallTarget::macos_app_bundle("dev.attacker.other").unwrap(),
            descriptor.version().clone(),
            [3; 32],
        )
        .unwrap();
        assert_eq!(
            journal().observe(SupervisionObservation::Prepared {
                transaction: transaction(1),
                recovery: wrong_target,
            }),
            Err(UpdateRuntimeError::CorruptPersistentState)
        );
        let wrong_version = RecoveryArtifactDescriptor::new(
            descriptor.artifact(),
            descriptor.target().clone(),
            Version::new(1, 4, 0),
            [3; 32],
        )
        .unwrap();
        assert_eq!(
            journal().observe(SupervisionObservation::Prepared {
                transaction: transaction(1),
                recovery: wrong_version,
            }),
            Err(UpdateRuntimeError::CorruptPersistentState)
        );
        assert_eq!(
            RecoveryArtifactDescriptor::new(
                descriptor.artifact(),
                descriptor.target().clone(),
                descriptor.version().clone(),
                [0; 32],
            ),
            Err(UpdateRuntimeError::CorruptPersistentState)
        );
    }

    #[test]
    fn rollback_recovery_repeats_the_same_exact_predecessor_action() {
        let rollback = rollback_after_candidate_timeout();
        let encoded = rollback.encode().unwrap();
        let expected = SupervisionAction::RollBack {
            transaction: transaction(1),
            candidate: Some(candidate()),
            recovery: recovery(),
        };
        assert_eq!(rollback.next_action().unwrap(), expected);
        assert_eq!(rollback.next_action().unwrap(), expected);

        let recovered = SupervisionJournal::decode(&encoded).unwrap();
        assert_eq!(recovered.next_action().unwrap(), expected);
        assert_eq!(recovered.encode().unwrap(), encoded);
    }

    #[test]
    fn corrupt_durable_installer_evidence_is_rejected_on_decode() {
        let state = prepared(&journal());
        let mut value: serde_json::Value =
            serde_json::from_slice(&state.encode().unwrap()).unwrap();
        value["recovery"]["installer_evidence"] = serde_json::to_value([0_u8; 32]).unwrap();
        assert_eq!(
            SupervisionJournal::decode(&serde_json::to_vec(&value).unwrap()),
            Err(UpdateRuntimeError::CorruptPersistentState)
        );
    }

    #[test]
    fn old_process_timeout_aborts_without_rollback_or_predecessor_launch() {
        let aborted = prepared(&journal())
            .observe(SupervisionObservation::OldProcessExitTimedOut {
                transaction: transaction(1),
                attempt_id: attempt(10),
            })
            .unwrap();
        assert_eq!(aborted.phase(), SupervisionPhase::Aborted);
        assert!(aborted.candidate().is_none());
        assert_eq!(
            aborted.next_action().unwrap(),
            SupervisionAction::ClearJournal
        );
        assert_eq!(
            aborted.observe(SupervisionObservation::RollbackRestored {
                transaction: transaction(1),
                recovery: recovery(),
            }),
            Err(UpdateRuntimeError::InvalidTransition)
        );
    }

    #[test]
    fn predecessor_start_signal_authenticates_exact_recovery_descriptor() {
        let rollback = rollback_restored()
            .observe(SupervisionObservation::PreviousAttemptCreated {
                transaction: transaction(1),
                attempt: 1,
                attempt_id: attempt(20),
            })
            .unwrap();
        assert_eq!(
            rollback.next_action().unwrap(),
            SupervisionAction::StartPrevious {
                transaction: transaction(1),
                attempt: 1,
                attempt_id: attempt(20),
                recovery: recovery(),
                timeout_ms: 90_000,
            }
        );
        let wrong_recovery = RecoveryArtifactDescriptor::new(
            ArtifactId::new([8; 32], 96).unwrap(),
            InstallTarget::macos_app_bundle("dev.nodavo.macos").unwrap(),
            Version::new(1, 5, 0),
            [3; 32],
        )
        .unwrap();
        assert_eq!(
            rollback.observe(SupervisionObservation::PreviousStarted {
                transaction: transaction(1),
                attempt: 1,
                attempt_id: attempt(20),
                recovery: wrong_recovery,
            }),
            Err(UpdateRuntimeError::CandidateMismatch)
        );
        let complete = rollback
            .observe(SupervisionObservation::PreviousStarted {
                transaction: transaction(1),
                attempt: 1,
                attempt_id: attempt(20),
                recovery: recovery(),
            })
            .unwrap();
        assert_eq!(
            complete.next_action().unwrap(),
            SupervisionAction::ClearJournal
        );
    }

    #[test]
    fn previous_start_attempts_are_bounded_and_latch_manual_recovery() {
        let mut state = rollback_restored();

        state = state
            .observe(SupervisionObservation::PreviousAttemptCreated {
                transaction: transaction(1),
                attempt: 1,
                attempt_id: attempt(20),
            })
            .unwrap();
        state = state
            .observe(SupervisionObservation::PreviousStartTimedOut {
                transaction: transaction(1),
                attempt: 1,
                attempt_id: attempt(20),
            })
            .unwrap();
        assert_eq!(
            state.phase(),
            SupervisionPhase::PreviousStopRequested {
                attempt: 1,
                attempt_id: attempt(20),
                after_exit: PreviousExitDisposition::Retry,
            }
        );
        state = stop_previous_and_confirm_exact_exit(state);
        state = SupervisionJournal::decode(&state.encode().unwrap()).unwrap();
        state = state
            .observe(SupervisionObservation::PreviousAttemptCreated {
                transaction: transaction(1),
                attempt: 2,
                attempt_id: attempt(21),
            })
            .unwrap();
        state = state
            .observe(SupervisionObservation::PreviousStartTimedOut {
                transaction: transaction(1),
                attempt: 2,
                attempt_id: attempt(21),
            })
            .unwrap();
        assert_eq!(
            state.phase(),
            SupervisionPhase::PreviousStopRequested {
                attempt: 2,
                attempt_id: attempt(21),
                after_exit: PreviousExitDisposition::ManualRecoveryRequired,
            }
        );
        state = stop_previous_and_confirm_exact_exit(state);

        assert_eq!(state.phase(), SupervisionPhase::ManualRecoveryRequired);
        assert_eq!(
            state.next_action().unwrap(),
            SupervisionAction::ManualRecoveryRequired
        );
    }

    #[test]
    fn repeated_action_queries_do_not_advance_durable_state() {
        let phases = [
            journal(),
            prepared(&journal()),
            candidate_start_requested(),
            candidate_started(),
        ];
        for state in phases {
            let encoded_before = state.encode().unwrap();
            let first = state.next_action().unwrap();
            let second = state.next_action().unwrap();
            assert_eq!(first, second);
            assert_eq!(state.encode().unwrap(), encoded_before);
        }
    }

    #[test]
    fn every_allowed_attempt_budget_is_exactly_enforced() {
        for maximum in 1..=MAX_SUPERVISION_ATTEMPTS {
            let initial = journal_with_policy(policy(maximum, maximum));
            let mut state = prepared(&initial)
                .observe(SupervisionObservation::OldProcessExited {
                    transaction: transaction(1),
                    attempt_id: attempt(10),
                })
                .unwrap()
                .observe(SupervisionObservation::Activated {
                    transaction: transaction(1),
                    candidate: candidate(),
                })
                .unwrap();
            for attempt_number in 1..=maximum {
                let attempt_id = attempt(30_u8.saturating_add(attempt_number));
                state = state
                    .observe(SupervisionObservation::CandidateAttemptCreated {
                        transaction: transaction(1),
                        attempt: attempt_number,
                        attempt_id,
                    })
                    .unwrap();
                assert_eq!(
                    state.phase(),
                    SupervisionPhase::CandidateStartRequested {
                        attempt: attempt_number,
                        attempt_id,
                    }
                );
                state = state
                    .observe(SupervisionObservation::CandidateStartTimedOut {
                        transaction: transaction(1),
                        attempt: attempt_number,
                        attempt_id,
                    })
                    .unwrap();
                state = stop_candidate_and_confirm_exact_exit(state);
            }
            assert_eq!(state.phase(), SupervisionPhase::RollingBack);
        }
    }

    #[test]
    fn invalid_observations_never_skip_health_or_floor_barriers() {
        let requested = candidate_start_requested();
        assert_eq!(
            requested.observe(SupervisionObservation::CandidateHealthy {
                transaction: transaction(1),
                attempt: 1,
                attempt_id: attempt(11),
                candidate: candidate(),
            }),
            Err(UpdateRuntimeError::InvalidTransition)
        );
        let started = candidate_started();
        assert_eq!(
            started.observe(SupervisionObservation::RollbackFloorAdvanced {
                transaction: transaction(1),
                candidate: candidate(),
                floor: RollbackState::new(7, Version::new(2, 0, 0)),
            }),
            Err(UpdateRuntimeError::InvalidTransition)
        );
        let healthy = started
            .observe(SupervisionObservation::CandidateHealthy {
                transaction: transaction(1),
                attempt: 1,
                attempt_id: attempt(11),
                candidate: candidate(),
            })
            .unwrap();
        assert_eq!(
            healthy.observe(SupervisionObservation::RollbackBackupRetired {
                transaction: transaction(1),
                candidate: candidate(),
                recovery: recovery(),
            }),
            Err(UpdateRuntimeError::InvalidTransition)
        );
    }

    #[test]
    fn floor_and_backup_retirement_require_exact_candidate_installer_evidence() {
        let substituted = CandidateArtifactDescriptor::new(
            candidate().artifact(),
            candidate().target().clone(),
            candidate().version().clone(),
            [8; 32],
        )
        .unwrap();
        let healthy = candidate_started()
            .observe(SupervisionObservation::CandidateHealthy {
                transaction: transaction(1),
                attempt: 1,
                attempt_id: attempt(11),
                candidate: candidate(),
            })
            .unwrap();
        let floor = RollbackState::new(7, Version::new(2, 0, 0));
        assert_eq!(
            healthy.observe(SupervisionObservation::RollbackFloorAdvanced {
                transaction: transaction(1),
                candidate: substituted.clone(),
                floor: floor.clone(),
            }),
            Err(UpdateRuntimeError::CandidateMismatch)
        );

        let floor_advanced = healthy
            .observe(SupervisionObservation::RollbackFloorAdvanced {
                transaction: transaction(1),
                candidate: candidate(),
                floor,
            })
            .unwrap();
        assert_eq!(
            floor_advanced.observe(SupervisionObservation::RollbackBackupRetired {
                transaction: transaction(1),
                candidate: substituted,
                recovery: recovery(),
            }),
            Err(UpdateRuntimeError::CandidateMismatch)
        );
    }

    #[test]
    fn policy_and_transaction_bounds_fail_closed() {
        assert_eq!(
            TransactionId::new([0; 32]),
            Err(UpdateRuntimeError::CorruptPersistentState)
        );
        assert_eq!(
            AttemptId::new([0; 32]),
            Err(UpdateRuntimeError::CorruptPersistentState)
        );
        for attempts in [0, MAX_SUPERVISION_ATTEMPTS + 1] {
            assert_eq!(
                SupervisionPolicy::new(attempts, 1, 30_000, 90_000, 60_000, 90_000, 30_000),
                Err(UpdateRuntimeError::CorruptPersistentState)
            );
        }
        for timeout in [
            0,
            MIN_SUPERVISION_TIMEOUT_MS - 1,
            MAX_SUPERVISION_TIMEOUT_MS + 1,
        ] {
            assert_eq!(
                SupervisionPolicy::new(1, 1, timeout, 90_000, 60_000, 90_000, 30_000),
                Err(UpdateRuntimeError::CorruptPersistentState)
            );
        }
    }

    #[test]
    fn codec_is_bounded_versioned_and_denies_unknown_or_inconsistent_fields() {
        let original = journal();
        let encoded = original.encode().unwrap();
        assert_eq!(SupervisionJournal::decode(&encoded).unwrap(), original);
        assert_eq!(
            SupervisionJournal::decode(&vec![b'x'; MAX_SUPERVISION_JOURNAL_BYTES + 1]),
            Err(UpdateRuntimeError::CorruptPersistentState)
        );

        let mut value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unknown".to_owned(), serde_json::Value::Bool(true));
        assert_eq!(
            SupervisionJournal::decode(&serde_json::to_vec(&value).unwrap()),
            Err(UpdateRuntimeError::CorruptPersistentState)
        );

        let mut value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        value["schema"] = serde_json::Value::from(1);
        assert_eq!(
            SupervisionJournal::decode(&serde_json::to_vec(&value).unwrap()),
            Err(UpdateRuntimeError::CorruptPersistentState)
        );
    }

    #[test]
    fn journal_rejects_non_previous_version_and_redacts_transaction_debug() {
        assert_eq!(
            SupervisionJournal::from_authorized_plan(
                transaction(1),
                attempt(10),
                InstallPlan::test_macos(Version::new(2, 0, 0), 7),
                Version::new(2, 0, 0),
                policy(1, 1),
            ),
            Err(UpdateRuntimeError::CorruptPersistentState)
        );
        let debug = format!("{:?}", transaction(0x41));
        assert_eq!(debug, "TransactionId([REDACTED])");
        assert!(!debug.contains("65"));
    }
}
