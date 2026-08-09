//! Device identity, explicit pairing, and transactional trust primitives.
//!
//! Discovery metadata is never accepted as identity proof. New trust records
//! can be staged only from a completed pairing transaction, after both users
//! confirmed the same SAS and both persistent identities signed acceptance.
//! Production keychain/keystore implementations belong behind [`DeviceSigner`]
//! and [`TrustStore`]; this crate includes only a development software signer
//! and an in-memory trust store.

mod crypto;
mod pairing;
mod trust;

pub use crypto::{
    DEVICE_ID_BYTES, DeviceId, DeviceSignature, DeviceSigner, PublicIdentity, SIGNATURE_BYTES,
    SigningError, SoftwareSigner,
};
pub use pairing::{
    MAX_TLS_EXPORTER_BYTES, MIN_TLS_EXPORTER_BYTES, PAIRING_NONCE_BYTES, PairingAcceptance,
    PairingAction, PairingError, PairingNonce, PairingPhase, PairingRole, PairingTranscript,
    PairingTxn, SasCode,
};
pub use trust::{
    Capability, CapabilityGrants, CommittedTrust, MAX_TRANSPORT_CERTIFICATE_DER_BYTES,
    MemoryTrustStore, PendingTrust, Revocation, RevocationReason, TransportCertificate,
    TransportCertificateError, TrustRecord, TrustStore, TrustStoreError, TrustStoreTransaction,
    VerifiedPeerTransportBinding,
};
