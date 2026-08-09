use std::fmt;

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;

use crate::crypto::{DeviceSignature, DeviceSigner, SigningError};
use crate::trust::{CommittedTrust, PendingTrust, TrustRecord};

pub const PAIRING_NONCE_BYTES: usize = 32;
pub const MIN_TLS_EXPORTER_BYTES: usize = 32;
pub const MAX_TLS_EXPORTER_BYTES: usize = 256;

const TRANSCRIPT_DOMAIN: &[u8] = b"nodavo/pairing-transcript/v2\0";
const BINDING_DOMAIN: &[u8] = b"nodavo/pairing-channel-binding/v1\0";
const SAS_DOMAIN: &[u8] = b"nodavo/pairing-sas/v1\0";
const ACCEPTANCE_DOMAIN: &[u8] = b"nodavo/pairing-acceptance/v1\0";
const SAS_MODULUS: u32 = 1_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingRole {
    Initiator,
    Responder,
}

impl PairingRole {
    const fn tag(self) -> u8 {
        match self {
            Self::Initiator => 1,
            Self::Responder => 2,
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::Initiator => 0,
            Self::Responder => 1,
        }
    }

    const fn peer(self) -> Self {
        match self {
            Self::Initiator => Self::Responder,
            Self::Responder => Self::Initiator,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PairingNonce([u8; PAIRING_NONCE_BYTES]);

impl PairingNonce {
    #[must_use]
    pub fn generate() -> Self {
        Self(rand::random::<[u8; PAIRING_NONCE_BYTES]>())
    }

    #[must_use]
    pub const fn from_bytes(bytes: [u8; PAIRING_NONCE_BYTES]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; PAIRING_NONCE_BYTES] {
        &self.0
    }
}

/// Canonical, role-ordered public transcript for one pairing attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairingTranscript {
    protocol_version: u16,
    initiator: PendingTrust,
    responder: PendingTrust,
    initiator_nonce: PairingNonce,
    responder_nonce: PairingNonce,
}

impl PairingTranscript {
    fn new(
        protocol_version: u16,
        initiator: PendingTrust,
        responder: PendingTrust,
        initiator_nonce: PairingNonce,
        responder_nonce: PairingNonce,
    ) -> Result<Self, PairingError> {
        if protocol_version == 0 {
            return Err(PairingError::InvalidProtocolVersion);
        }
        if initiator.identity() == responder.identity() {
            return Err(PairingError::SamePersistentIdentity);
        }
        if initiator.transport_certificate() == responder.transport_certificate() {
            return Err(PairingError::SameTransportCertificate);
        }
        if initiator_nonce == responder_nonce {
            return Err(PairingError::RepeatedNonce);
        }
        Ok(Self {
            protocol_version,
            initiator,
            responder,
            initiator_nonce,
            responder_nonce,
        })
    }

    #[must_use]
    pub const fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    #[must_use]
    pub const fn participant(&self, role: PairingRole) -> &PendingTrust {
        match role {
            PairingRole::Initiator => &self.initiator,
            PairingRole::Responder => &self.responder,
        }
    }

    /// Returns the exact role-ordered transcript bytes used by the reducer.
    ///
    /// Each field is fixed-width and roles have distinct tags, so there is no
    /// concatenation ambiguity. The TLS exporter is deliberately not returned;
    /// it is mixed into the private channel binding separately.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(
            TRANSCRIPT_DOMAIN.len() + 2 + 2 * (1 + PAIRING_NONCE_BYTES + 32 + 32 + 1),
        );
        bytes.extend_from_slice(TRANSCRIPT_DOMAIN);
        bytes.extend_from_slice(&self.protocol_version.to_be_bytes());
        self.append_participant(PairingRole::Initiator, &mut bytes);
        self.append_participant(PairingRole::Responder, &mut bytes);
        bytes
    }

    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.canonical_bytes()).into()
    }

    fn append_participant(&self, role: PairingRole, bytes: &mut Vec<u8>) {
        let participant = self.participant(role);
        let nonce = match role {
            PairingRole::Initiator => self.initiator_nonce,
            PairingRole::Responder => self.responder_nonce,
        };
        bytes.push(role.tag());
        bytes.extend_from_slice(nonce.as_bytes());
        bytes.extend_from_slice(participant.identity().public_key_bytes());
        bytes.extend_from_slice(participant.transport_certificate().sha256());
        bytes.push(participant.grants_to_peer().bits());
    }
}

/// Six decimal digits shown to the user on both devices.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct SasCode(u32);

impl SasCode {
    #[must_use]
    pub const fn value(self) -> u32 {
        self.0
    }

    #[must_use]
    pub fn matches(self, other: Self) -> bool {
        self.0.to_be_bytes().ct_eq(&other.0.to_be_bytes()).into()
    }
}

impl fmt::Display for SasCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:06}", self.0)
    }
}

impl fmt::Debug for SasCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SasCode([redacted])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PairingAcceptance {
    role: PairingRole,
    signature: DeviceSignature,
}

impl PairingAcceptance {
    #[must_use]
    pub const fn from_parts(role: PairingRole, signature: DeviceSignature) -> Self {
        Self { role, signature }
    }

    #[must_use]
    pub const fn role(self) -> PairingRole {
        self.role
    }

    #[must_use]
    pub const fn signature(self) -> DeviceSignature {
        self.signature
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingPhase {
    AwaitingConfirmations,
    AwaitingAcceptances,
    ReadyToCommit,
    Committed,
    Aborted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingAction {
    ConfirmSas { role: PairingRole, sas: SasCode },
    SubmitAcceptance(PairingAcceptance),
    Commit { established_at_unix_ms: u64 },
    Abort,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[non_exhaustive]
pub enum PairingError {
    #[error("the protocol version must be non-zero")]
    InvalidProtocolVersion,
    #[error("the TLS exporter is outside the accepted bounds")]
    InvalidTlsExporter,
    #[error("both pairing roles cannot use the same persistent identity")]
    SamePersistentIdentity,
    #[error("both pairing roles cannot use the same persistent TLS certificate")]
    SameTransportCertificate,
    #[error("pairing roles must contribute distinct nonces")]
    RepeatedNonce,
    #[error("the supplied SAS does not match this pairing transaction")]
    SasMismatch,
    #[error("the pairing action is not valid in the current phase")]
    InvalidTransition,
    #[error("this pairing role has already confirmed or accepted")]
    DuplicateAction,
    #[error("the signer does not own the persistent identity for this role")]
    SignerIdentityMismatch,
    #[error("the signed pairing acceptance is invalid")]
    InvalidAcceptance,
    #[error("the pairing transaction has not committed")]
    NotCommitted,
    #[error("the signing provider failed")]
    Signing,
}

impl From<SigningError> for PairingError {
    fn from(_: SigningError) -> Self {
        Self::Signing
    }
}

/// Explicit reducer for a single two-party pairing attempt.
pub struct PairingTxn {
    transcript: PairingTranscript,
    binding_digest: [u8; 32],
    sas: SasCode,
    confirmations: [bool; 2],
    acceptances: [Option<DeviceSignature>; 2],
    phase: PairingPhase,
    established_at_unix_ms: Option<u64>,
}

impl PairingTxn {
    pub fn new(
        protocol_version: u16,
        tls_exporter: &[u8],
        initiator: PendingTrust,
        initiator_nonce: PairingNonce,
        responder: PendingTrust,
        responder_nonce: PairingNonce,
    ) -> Result<Self, PairingError> {
        if !(MIN_TLS_EXPORTER_BYTES..=MAX_TLS_EXPORTER_BYTES).contains(&tls_exporter.len()) {
            return Err(PairingError::InvalidTlsExporter);
        }
        let transcript = PairingTranscript::new(
            protocol_version,
            initiator,
            responder,
            initiator_nonce,
            responder_nonce,
        )?;
        let transcript_digest = transcript.digest();
        let mut binding = Sha256::new();
        binding.update(BINDING_DOMAIN);
        binding.update(
            u16::try_from(tls_exporter.len())
                .map_err(|_| PairingError::InvalidTlsExporter)?
                .to_be_bytes(),
        );
        binding.update(tls_exporter);
        binding.update(transcript_digest);
        let binding_digest: [u8; 32] = binding.finalize().into();

        let mut sas_digest = Sha256::new();
        sas_digest.update(SAS_DOMAIN);
        sas_digest.update(binding_digest);
        let sas_digest: [u8; 32] = sas_digest.finalize().into();
        let sas = SasCode(
            u32::from_be_bytes(sas_digest[..4].try_into().expect("fixed slice")) % SAS_MODULUS,
        );

        Ok(Self {
            transcript,
            binding_digest,
            sas,
            confirmations: [false; 2],
            acceptances: [None, None],
            phase: PairingPhase::AwaitingConfirmations,
            established_at_unix_ms: None,
        })
    }

    #[must_use]
    pub const fn transcript(&self) -> &PairingTranscript {
        &self.transcript
    }

    #[must_use]
    pub const fn sas(&self) -> SasCode {
        self.sas
    }

    #[must_use]
    pub const fn phase(&self) -> PairingPhase {
        self.phase
    }

    pub fn create_acceptance(
        &self,
        role: PairingRole,
        signer: &dyn DeviceSigner,
    ) -> Result<PairingAcceptance, PairingError> {
        if signer.public_identity() != self.transcript.participant(role).identity() {
            return Err(PairingError::SignerIdentityMismatch);
        }
        let signature = signer.sign(&self.acceptance_message(role))?;
        Ok(PairingAcceptance { role, signature })
    }

    /// Applies exactly one state-machine action.
    pub fn reduce(&mut self, action: PairingAction) -> Result<PairingPhase, PairingError> {
        if matches!(self.phase, PairingPhase::Committed | PairingPhase::Aborted) {
            return Err(PairingError::InvalidTransition);
        }
        match action {
            PairingAction::ConfirmSas { role, sas } => self.confirm_sas(role, sas)?,
            PairingAction::SubmitAcceptance(acceptance) => {
                self.submit_acceptance(acceptance)?;
            }
            PairingAction::Commit {
                established_at_unix_ms,
            } => self.commit(established_at_unix_ms)?,
            PairingAction::Abort => self.phase = PairingPhase::Aborted,
        }
        Ok(self.phase)
    }

    /// Returns the peer trust record visible from `local_role` after commit.
    pub fn committed_trust_for(
        &self,
        local_role: PairingRole,
    ) -> Result<CommittedTrust, PairingError> {
        let established_at_unix_ms = self
            .established_at_unix_ms
            .ok_or(PairingError::NotCommitted)?;
        if self.phase != PairingPhase::Committed {
            return Err(PairingError::NotCommitted);
        }
        let local = self.transcript.participant(local_role);
        let peer = self.transcript.participant(local_role.peer());
        Ok(CommittedTrust(TrustRecord::paired(
            peer.identity(),
            peer.transport_certificate().clone(),
            local.grants_to_peer(),
            established_at_unix_ms,
        )))
    }

    fn confirm_sas(&mut self, role: PairingRole, sas: SasCode) -> Result<(), PairingError> {
        if self.phase != PairingPhase::AwaitingConfirmations {
            return Err(PairingError::InvalidTransition);
        }
        if !self.sas.matches(sas) {
            return Err(PairingError::SasMismatch);
        }
        let confirmation = &mut self.confirmations[role.index()];
        if *confirmation {
            return Err(PairingError::DuplicateAction);
        }
        *confirmation = true;
        if self.confirmations.iter().all(|confirmed| *confirmed) {
            self.phase = PairingPhase::AwaitingAcceptances;
        }
        Ok(())
    }

    fn submit_acceptance(&mut self, acceptance: PairingAcceptance) -> Result<(), PairingError> {
        if !matches!(
            self.phase,
            PairingPhase::AwaitingAcceptances | PairingPhase::ReadyToCommit
        ) {
            return Err(PairingError::InvalidTransition);
        }
        let index = acceptance.role.index();
        if self.acceptances[index].is_some() {
            return Err(PairingError::DuplicateAction);
        }
        self.transcript
            .participant(acceptance.role)
            .identity()
            .verify(
                &self.acceptance_message(acceptance.role),
                &acceptance.signature,
            )
            .map_err(|_| PairingError::InvalidAcceptance)?;
        self.acceptances[index] = Some(acceptance.signature);
        if self.acceptances.iter().all(Option::is_some) {
            self.phase = PairingPhase::ReadyToCommit;
        }
        Ok(())
    }

    fn commit(&mut self, established_at_unix_ms: u64) -> Result<(), PairingError> {
        if self.phase != PairingPhase::ReadyToCommit {
            return Err(PairingError::InvalidTransition);
        }
        self.established_at_unix_ms = Some(established_at_unix_ms);
        self.phase = PairingPhase::Committed;
        Ok(())
    }

    fn acceptance_message(&self, role: PairingRole) -> Vec<u8> {
        let mut message = Vec::with_capacity(ACCEPTANCE_DOMAIN.len() + 32 + 2 + 1);
        message.extend_from_slice(ACCEPTANCE_DOMAIN);
        message.extend_from_slice(&self.binding_digest);
        message.extend_from_slice(&self.transcript.protocol_version.to_be_bytes());
        message.push(role.tag());
        message
    }
}

impl fmt::Debug for PairingTxn {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairingTxn")
            .field("phase", &self.phase)
            .field("sensitive_fields", &"[redacted]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use super::*;
    use crate::{
        Capability, CapabilityGrants, MemoryTrustStore, Revocation, RevocationReason,
        SoftwareSigner, TransportCertificate, TrustStore,
    };

    fn certificates() -> &'static (TransportCertificate, TransportCertificate) {
        static CERTIFICATES: OnceLock<(TransportCertificate, TransportCertificate)> =
            OnceLock::new();
        CERTIFICATES.get_or_init(|| {
            let initiator =
                rcgen::generate_simple_self_signed(vec!["initiator.nodavo.invalid".into()])
                    .unwrap();
            let responder =
                rcgen::generate_simple_self_signed(vec!["responder.nodavo.invalid".into()])
                    .unwrap();
            (
                TransportCertificate::from_der(initiator.cert.der().to_vec()).unwrap(),
                TransportCertificate::from_der(responder.cert.der().to_vec()).unwrap(),
            )
        })
    }

    fn fixture() -> (PairingTxn, SoftwareSigner, SoftwareSigner) {
        let initiator_signer = SoftwareSigner::from_secret_seed([7; 32]);
        let responder_signer = SoftwareSigner::from_secret_seed([9; 32]);
        let initiator = PendingTrust::new(
            initiator_signer.public_identity(),
            CapabilityGrants::NONE.with(Capability::RemoteInput),
            certificates().0.clone(),
        );
        let responder = PendingTrust::new(
            responder_signer.public_identity(),
            CapabilityGrants::NONE.with(Capability::ClipboardRead),
            certificates().1.clone(),
        );
        let transaction = PairingTxn::new(
            1,
            &[0x42; MIN_TLS_EXPORTER_BYTES],
            initiator,
            PairingNonce::from_bytes([1; PAIRING_NONCE_BYTES]),
            responder,
            PairingNonce::from_bytes([2; PAIRING_NONCE_BYTES]),
        )
        .unwrap();
        (transaction, initiator_signer, responder_signer)
    }

    #[test]
    fn sas_is_deterministic_and_roles_are_bound() {
        let (first, _, _) = fixture();
        let (second, _, _) = fixture();
        assert_eq!(first.sas(), second.sas());
        assert_eq!(first.transcript().digest(), second.transcript().digest());

        let swapped = PairingTxn::new(
            first.transcript().protocol_version(),
            &[0x42; MIN_TLS_EXPORTER_BYTES],
            first
                .transcript()
                .participant(PairingRole::Responder)
                .clone(),
            PairingNonce::from_bytes([2; PAIRING_NONCE_BYTES]),
            first
                .transcript()
                .participant(PairingRole::Initiator)
                .clone(),
            PairingNonce::from_bytes([1; PAIRING_NONCE_BYTES]),
        )
        .unwrap();
        assert_ne!(first.sas(), swapped.sas());
    }

    #[test]
    fn persistent_certificate_substitution_changes_sas() {
        let (original, initiator_signer, responder_signer) = fixture();
        let replacement =
            rcgen::generate_simple_self_signed(vec!["replacement.nodavo.invalid".into()]).unwrap();
        let substituted_responder = PendingTrust::new(
            responder_signer.public_identity(),
            CapabilityGrants::NONE.with(Capability::ClipboardRead),
            TransportCertificate::from_der(replacement.cert.der().to_vec()).unwrap(),
        );
        let substituted = PairingTxn::new(
            1,
            &[0x42; MIN_TLS_EXPORTER_BYTES],
            PendingTrust::new(
                initiator_signer.public_identity(),
                CapabilityGrants::NONE.with(Capability::RemoteInput),
                certificates().0.clone(),
            ),
            PairingNonce::from_bytes([1; PAIRING_NONCE_BYTES]),
            substituted_responder,
            PairingNonce::from_bytes([2; PAIRING_NONCE_BYTES]),
        )
        .unwrap();

        assert_ne!(
            original.transcript().digest(),
            substituted.transcript().digest()
        );
        assert_ne!(original.sas(), substituted.sas());
    }

    #[test]
    fn uncommitted_pairing_does_not_expose_transport_binding() {
        let (pairing, _, _) = fixture();
        assert!(matches!(
            pairing.committed_trust_for(PairingRole::Initiator),
            Err(PairingError::NotCommitted)
        ));
    }

    #[test]
    fn acceptance_signature_cannot_be_relabelled() {
        let (mut transaction, initiator, _) = fixture();
        let sas = transaction.sas();
        transaction
            .reduce(PairingAction::ConfirmSas {
                role: PairingRole::Initiator,
                sas,
            })
            .unwrap();
        transaction
            .reduce(PairingAction::ConfirmSas {
                role: PairingRole::Responder,
                sas,
            })
            .unwrap();
        let initiator_acceptance = transaction
            .create_acceptance(PairingRole::Initiator, &initiator)
            .unwrap();
        let relabelled =
            PairingAcceptance::from_parts(PairingRole::Responder, initiator_acceptance.signature());

        assert_eq!(
            transaction.reduce(PairingAction::SubmitAcceptance(relabelled)),
            Err(PairingError::InvalidAcceptance)
        );
    }

    #[test]
    fn revocation_disables_grants_transactionally() {
        let (mut pairing, initiator, responder) = fixture();
        let sas = pairing.sas();
        for role in [PairingRole::Initiator, PairingRole::Responder] {
            pairing
                .reduce(PairingAction::ConfirmSas { role, sas })
                .unwrap();
        }
        let initiator_acceptance = pairing
            .create_acceptance(PairingRole::Initiator, &initiator)
            .unwrap();
        let responder_acceptance = pairing
            .create_acceptance(PairingRole::Responder, &responder)
            .unwrap();
        pairing
            .reduce(PairingAction::SubmitAcceptance(initiator_acceptance))
            .unwrap();
        pairing
            .reduce(PairingAction::SubmitAcceptance(responder_acceptance))
            .unwrap();
        pairing
            .reduce(PairingAction::Commit {
                established_at_unix_ms: 100,
            })
            .unwrap();

        let trust = pairing.committed_trust_for(PairingRole::Initiator).unwrap();
        let peer_id = trust.record().peer().device_id();
        let store = MemoryTrustStore::default();
        let mut write = store.begin().unwrap();
        write.stage_trust(trust).unwrap();
        write.commit().unwrap();

        let mut revoke = store.begin().unwrap();
        revoke
            .stage_revocation(
                peer_id,
                Revocation::new(101, RevocationReason::UserRequested),
            )
            .unwrap();
        revoke.commit().unwrap();

        let read = store.begin().unwrap();
        let record = read.get(peer_id).unwrap().unwrap();
        assert!(!record.is_active());
        assert!(!record.allows(Capability::RemoteInput));
    }
}
