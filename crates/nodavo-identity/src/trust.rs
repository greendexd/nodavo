use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{DeviceId, PublicIdentity};

const KNOWN_CAPABILITY_BITS: u8 = 0b0000_1111;
pub const MAX_TRANSPORT_CERTIFICATE_DER_BYTES: usize = 64 * 1024;

/// Bounded persistent TLS certificate contributed during pairing.
///
/// The full DER is retained because future TLS sessions pin this exact
/// certificate. Debug formatting never reveals the certificate or its hash.
#[derive(Clone, Eq, PartialEq)]
pub struct TransportCertificate {
    der: Arc<[u8]>,
    sha256: [u8; 32],
}

impl TransportCertificate {
    /// Validates and retains a DER-encoded X.509 certificate.
    ///
    /// # Errors
    ///
    /// Returns an error when the input is empty, exceeds 64 KiB, or cannot be
    /// parsed as a certificate trust anchor by rustls.
    pub fn from_der(der: Vec<u8>) -> Result<Self, TransportCertificateError> {
        if der.is_empty() {
            return Err(TransportCertificateError::Empty);
        }
        if der.len() > MAX_TRANSPORT_CERTIFICATE_DER_BYTES {
            return Err(TransportCertificateError::TooLarge);
        }
        let mut validation_store = rustls::RootCertStore::empty();
        validation_store
            .add(rustls::pki_types::CertificateDer::from(der.clone()))
            .map_err(|_| TransportCertificateError::InvalidDer)?;
        let sha256 = Sha256::digest(&der).into();
        Ok(Self {
            der: Arc::from(der),
            sha256,
        })
    }

    #[must_use]
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    #[must_use]
    pub const fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }

    #[must_use]
    pub fn matches_der(&self, candidate: &[u8]) -> bool {
        self.der.as_ref() == candidate
    }
}

impl fmt::Debug for TransportCertificate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TransportCertificate([redacted])")
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[non_exhaustive]
pub enum TransportCertificateError {
    #[error("the persistent TLS certificate is empty")]
    Empty,
    #[error("the persistent TLS certificate exceeds 64 KiB")]
    TooLarge,
    #[error("the persistent TLS certificate is not valid DER")]
    InvalidDer,
}

/// Identity and exact TLS certificate authenticated by a completed pairing.
///
/// Its fields and constructor are private. A value can only be obtained from a
/// committed pairing or a trust record that already contains such a binding.
#[derive(Clone, Eq, PartialEq)]
pub struct VerifiedPeerTransportBinding {
    peer: PublicIdentity,
    certificate: TransportCertificate,
}

impl VerifiedPeerTransportBinding {
    const fn new(peer: PublicIdentity, certificate: TransportCertificate) -> Self {
        Self { peer, certificate }
    }

    #[must_use]
    pub const fn peer_identity(&self) -> PublicIdentity {
        self.peer
    }

    #[must_use]
    pub const fn certificate(&self) -> &TransportCertificate {
        &self.certificate
    }

    #[must_use]
    pub fn certificate_der(&self) -> &[u8] {
        self.certificate.der()
    }

    #[must_use]
    pub fn matches_certificate_der(&self, candidate: &[u8]) -> bool {
        self.certificate.matches_der(candidate)
    }
}

impl fmt::Debug for VerifiedPeerTransportBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedPeerTransportBinding([redacted])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Capability {
    RemoteInput = 0b0000_0001,
    ClipboardRead = 0b0000_0010,
    ClipboardWrite = 0b0000_0100,
    FileTransfer = 0b0000_1000,
}

/// Explicit per-peer capabilities. An empty set is valid and grants no access.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CapabilityGrants(u8);

impl CapabilityGrants {
    pub const NONE: Self = Self(0);

    /// Creates a capability set from its serialized bit representation.
    ///
    /// # Errors
    ///
    /// Returns [`TrustStoreError::InvalidCapabilities`] when `bits` contains
    /// values not assigned to a known capability.
    pub fn from_bits(bits: u8) -> Result<Self, TrustStoreError> {
        if bits & !KNOWN_CAPABILITY_BITS == 0 {
            Ok(Self(bits))
        } else {
            Err(TrustStoreError::InvalidCapabilities)
        }
    }

    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    #[must_use]
    pub const fn with(self, capability: Capability) -> Self {
        Self(self.0 | capability as u8)
    }

    #[must_use]
    pub const fn contains(self, capability: Capability) -> bool {
        self.0 & capability as u8 != 0
    }
}

/// One side's persistent identity and the capabilities it explicitly grants to
/// the other side if pairing completes.
#[derive(Clone, Eq, PartialEq)]
pub struct PendingTrust {
    identity: PublicIdentity,
    grants_to_peer: CapabilityGrants,
    transport_certificate: TransportCertificate,
}

impl PendingTrust {
    #[must_use]
    pub const fn new(
        identity: PublicIdentity,
        grants_to_peer: CapabilityGrants,
        transport_certificate: TransportCertificate,
    ) -> Self {
        Self {
            identity,
            grants_to_peer,
            transport_certificate,
        }
    }

    #[must_use]
    pub const fn identity(&self) -> PublicIdentity {
        self.identity
    }

    #[must_use]
    pub const fn grants_to_peer(&self) -> CapabilityGrants {
        self.grants_to_peer
    }

    #[must_use]
    pub const fn transport_certificate(&self) -> &TransportCertificate {
        &self.transport_certificate
    }
}

impl fmt::Debug for PendingTrust {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingTrust")
            .field("identity", &self.identity)
            .field("grants_to_peer", &self.grants_to_peer)
            .field("transport_certificate", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevocationReason {
    UserRequested,
    DeviceLost,
    IdentityReset,
    SuspectedCompromise,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Revocation {
    revoked_at_unix_ms: u64,
    reason: RevocationReason,
}

impl Revocation {
    #[must_use]
    pub const fn new(revoked_at_unix_ms: u64, reason: RevocationReason) -> Self {
        Self {
            revoked_at_unix_ms,
            reason,
        }
    }

    #[must_use]
    pub const fn revoked_at_unix_ms(self) -> u64 {
        self.revoked_at_unix_ms
    }

    #[must_use]
    pub const fn reason(self) -> RevocationReason {
        self.reason
    }
}

/// Persisted trust for a peer. A revoked record never authorizes capabilities.
#[derive(Clone, Eq, PartialEq)]
pub struct TrustRecord {
    transport_binding: VerifiedPeerTransportBinding,
    grants: CapabilityGrants,
    established_at_unix_ms: u64,
    revocation: Option<Revocation>,
}

impl TrustRecord {
    pub(crate) const fn paired(
        peer: PublicIdentity,
        transport_certificate: TransportCertificate,
        grants: CapabilityGrants,
        established_at_unix_ms: u64,
    ) -> Self {
        Self {
            transport_binding: VerifiedPeerTransportBinding::new(peer, transport_certificate),
            grants,
            established_at_unix_ms,
            revocation: None,
        }
    }

    /// Reconstructs a record read from an implementation's authenticated,
    /// protected backing store.
    ///
    /// This is the only restart boundary that can recreate the otherwise
    /// private transport binding. The caller is responsible for establishing
    /// that the record came from its OS-protected trust store; mDNS, manual
    /// endpoints, network messages, or unconfirmed pairing state are never
    /// valid inputs.
    ///
    /// # Errors
    ///
    /// Rejects a revocation timestamp older than trust establishment.
    pub fn restore_persisted(
        peer: PublicIdentity,
        transport_certificate: TransportCertificate,
        grants: CapabilityGrants,
        established_at_unix_ms: u64,
        revocation: Option<Revocation>,
    ) -> Result<Self, TrustStoreError> {
        if revocation.is_some_and(|value| value.revoked_at_unix_ms < established_at_unix_ms) {
            return Err(TrustStoreError::InvalidRevocationTime);
        }
        Ok(Self {
            transport_binding: VerifiedPeerTransportBinding::new(peer, transport_certificate),
            grants,
            established_at_unix_ms,
            revocation,
        })
    }

    #[must_use]
    pub const fn peer(&self) -> PublicIdentity {
        self.transport_binding.peer_identity()
    }

    #[must_use]
    pub const fn grants(&self) -> CapabilityGrants {
        self.grants
    }

    #[must_use]
    pub const fn established_at_unix_ms(&self) -> u64 {
        self.established_at_unix_ms
    }

    #[must_use]
    pub const fn revocation(&self) -> Option<Revocation> {
        self.revocation
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.revocation.is_none()
    }

    #[must_use]
    pub const fn allows(&self, capability: Capability) -> bool {
        self.is_active() && self.grants.contains(capability)
    }

    /// Returns the authenticated transport binding only while trust is active.
    #[must_use]
    pub const fn transport_binding(&self) -> Option<&VerifiedPeerTransportBinding> {
        if self.is_active() {
            Some(&self.transport_binding)
        } else {
            None
        }
    }

    fn revoke(&mut self, revocation: Revocation) -> Result<(), TrustStoreError> {
        if self.revocation.is_some() {
            return Err(TrustStoreError::AlreadyRevoked);
        }
        if revocation.revoked_at_unix_ms < self.established_at_unix_ms {
            return Err(TrustStoreError::InvalidRevocationTime);
        }
        self.revocation = Some(revocation);
        Ok(())
    }
}

impl fmt::Debug for TrustRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrustRecord")
            .field("peer", &self.peer())
            .field("grants", &self.grants)
            .field("established_at_unix_ms", &self.established_at_unix_ms)
            .field("revocation", &self.revocation)
            .field("transport_binding", &"[redacted]")
            .finish()
    }
}

/// Proof that an active record came from a fully committed pairing reducer.
///
/// The inner record is intentionally not publicly constructible.
#[derive(Debug)]
pub struct CommittedTrust(pub(crate) TrustRecord);

impl CommittedTrust {
    #[must_use]
    pub const fn record(&self) -> &TrustRecord {
        &self.0
    }

    #[must_use]
    pub fn into_record(self) -> TrustRecord {
        self.0
    }

    /// Exact peer certificate binding authenticated by the completed pairing.
    #[must_use]
    pub const fn transport_binding(&self) -> &VerifiedPeerTransportBinding {
        &self.0.transport_binding
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[non_exhaustive]
pub enum TrustStoreError {
    #[error("the capability bitset contains unknown capabilities")]
    InvalidCapabilities,
    #[error("the trust record does not exist")]
    NotFound,
    #[error("the trust record is already revoked")]
    AlreadyRevoked,
    #[error("the revocation predates trust establishment")]
    InvalidRevocationTime,
    #[error("the trust transaction conflicted with another commit")]
    Conflict,
    #[error("the trust store is unavailable")]
    Unavailable,
    #[error("the trust store rejected the operation")]
    Backend,
}

/// Atomic trust-store update. Dropping without `commit` rolls changes back.
pub trait TrustStoreTransaction: Send {
    /// Looks up the record for `peer` in this transaction's view.
    ///
    /// # Errors
    ///
    /// Returns an error when the trust-store backend cannot complete the read.
    fn get(&self, peer: DeviceId) -> Result<Option<TrustRecord>, TrustStoreError>;

    /// Stages only a record issued by a completed pairing transaction.
    ///
    /// # Errors
    ///
    /// Returns an error when the trust-store backend cannot stage the update.
    fn stage_trust(&mut self, trust: CommittedTrust) -> Result<(), TrustStoreError>;

    /// Stages a revocation for the record identified by `peer`.
    ///
    /// # Errors
    ///
    /// Returns an error when the record is missing or already revoked, the
    /// revocation predates trust establishment, or the backend rejects it.
    fn stage_revocation(
        &mut self,
        peer: DeviceId,
        revocation: Revocation,
    ) -> Result<(), TrustStoreError>;

    /// Atomically commits all staged changes.
    ///
    /// # Errors
    ///
    /// Returns an error when the transaction conflicts with another commit or
    /// the trust-store backend cannot persist the changes.
    fn commit(self: Box<Self>) -> Result<(), TrustStoreError>;

    fn rollback(self: Box<Self>);
}

/// Transactional persistence boundary for an OS-protected trust database.
pub trait TrustStore: Send + Sync {
    /// Begins an atomic trust-store update.
    ///
    /// # Errors
    ///
    /// Returns an error when the trust-store backend is unavailable or cannot
    /// create a transaction.
    fn begin(&self) -> Result<Box<dyn TrustStoreTransaction + '_>, TrustStoreError>;
}

#[derive(Clone, Default)]
pub struct MemoryTrustStore {
    state: Arc<Mutex<MemoryState>>,
}

#[derive(Clone, Default)]
struct MemoryState {
    generation: u64,
    records: HashMap<DeviceId, TrustRecord>,
}

impl TrustStore for MemoryTrustStore {
    fn begin(&self) -> Result<Box<dyn TrustStoreTransaction + '_>, TrustStoreError> {
        let state = self
            .state
            .lock()
            .map_err(|_| TrustStoreError::Unavailable)?;
        Ok(Box::new(MemoryTransaction {
            store: Arc::clone(&self.state),
            base_generation: state.generation,
            records: state.records.clone(),
        }))
    }
}

struct MemoryTransaction {
    store: Arc<Mutex<MemoryState>>,
    base_generation: u64,
    records: HashMap<DeviceId, TrustRecord>,
}

impl TrustStoreTransaction for MemoryTransaction {
    fn get(&self, peer: DeviceId) -> Result<Option<TrustRecord>, TrustStoreError> {
        Ok(self.records.get(&peer).cloned())
    }

    fn stage_trust(&mut self, trust: CommittedTrust) -> Result<(), TrustStoreError> {
        let record = trust.into_record();
        self.records.insert(record.peer().device_id(), record);
        Ok(())
    }

    fn stage_revocation(
        &mut self,
        peer: DeviceId,
        revocation: Revocation,
    ) -> Result<(), TrustStoreError> {
        self.records
            .get_mut(&peer)
            .ok_or(TrustStoreError::NotFound)?
            .revoke(revocation)
    }

    fn commit(self: Box<Self>) -> Result<(), TrustStoreError> {
        let mut state = self
            .store
            .lock()
            .map_err(|_| TrustStoreError::Unavailable)?;
        if state.generation != self.base_generation {
            return Err(TrustStoreError::Conflict);
        }
        state.records = self.records;
        state.generation = state.generation.wrapping_add(1);
        Ok(())
    }

    fn rollback(self: Box<Self>) {}
}
