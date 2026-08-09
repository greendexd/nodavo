use std::fmt;

use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use subtle::{Choice, ConstantTimeEq};
use thiserror::Error;
use zeroize::Zeroizing;

pub const DEVICE_ID_BYTES: usize = 32;
pub const SIGNATURE_BYTES: usize = 64;
const DEVICE_ID_DOMAIN: &[u8] = b"nodavo/device-id/v1\0";

/// Stable identifier derived from a persistent public key.
///
/// Stable identifiers must not be written to routine logs or telemetry.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DeviceId([u8; DEVICE_ID_BYTES]);

impl DeviceId {
    #[must_use]
    pub fn from_public_key(public_key: &[u8; 32]) -> Self {
        let mut digest = Sha256::new();
        digest.update(DEVICE_ID_DOMAIN);
        digest.update(public_key);
        Self(digest.finalize().into())
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; DEVICE_ID_BYTES] {
        &self.0
    }

    /// Constant-time comparison for callers that need to avoid data-dependent
    /// comparison behavior at an authentication boundary.
    #[must_use]
    pub fn constant_time_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl fmt::Debug for DeviceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DeviceId([redacted])")
    }
}

/// A persistent public device identity.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PublicIdentity {
    device_id: DeviceId,
    public_key: [u8; 32],
}

impl PublicIdentity {
    #[must_use]
    pub fn from_public_key(public_key: [u8; 32]) -> Self {
        Self {
            device_id: DeviceId::from_public_key(&public_key),
            public_key,
        }
    }

    pub fn from_parts(device_id: DeviceId, public_key: [u8; 32]) -> Result<Self, SigningError> {
        if device_id == DeviceId::from_public_key(&public_key) {
            Ok(Self {
                device_id,
                public_key,
            })
        } else {
            Err(SigningError::IdentityMismatch)
        }
    }

    #[must_use]
    pub const fn device_id(&self) -> DeviceId {
        self.device_id
    }

    #[must_use]
    pub const fn public_key_bytes(&self) -> &[u8; 32] {
        &self.public_key
    }

    pub fn verify(&self, message: &[u8], signature: &DeviceSignature) -> Result<(), SigningError> {
        let key = VerifyingKey::from_bytes(&self.public_key)
            .map_err(|_| SigningError::InvalidPublicKey)?;
        let signature = ed25519_dalek::Signature::from_bytes(signature.as_bytes());
        key.verify_strict(message, &signature)
            .map_err(|_| SigningError::InvalidSignature)
    }
}

impl fmt::Debug for PublicIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PublicIdentity([redacted])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DeviceSignature([u8; SIGNATURE_BYTES]);

impl DeviceSignature {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; SIGNATURE_BYTES]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SIGNATURE_BYTES] {
        &self.0
    }
}

impl fmt::Debug for DeviceSignature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DeviceSignature([redacted])")
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[non_exhaustive]
pub enum SigningError {
    #[error("the public key is not a valid Ed25519 key")]
    InvalidPublicKey,
    #[error("the device identifier does not match the public key")]
    IdentityMismatch,
    #[error("the Ed25519 signature is invalid")]
    InvalidSignature,
    #[error("the signing backend rejected the operation")]
    Backend,
}

/// Persistent signing boundary implemented by an OS-backed key provider.
pub trait DeviceSigner: Send + Sync {
    fn public_identity(&self) -> PublicIdentity;

    fn sign(&self, message: &[u8]) -> Result<DeviceSignature, SigningError>;
}

/// Development-only Ed25519 signer backed by process memory.
///
/// The stored seed is zeroized on drop, and the temporary `SigningKey` is
/// zeroized by `ed25519-dalek` with its enabled `zeroize` feature. Production
/// builds should inject a non-exportable OS-keychain implementation instead.
pub struct SoftwareSigner {
    secret_seed: Zeroizing<[u8; 32]>,
    public_identity: PublicIdentity,
}

impl SoftwareSigner {
    #[must_use]
    pub fn generate() -> Self {
        let secret_seed = Zeroizing::new(rand::random::<[u8; 32]>());
        Self::from_zeroizing_seed(secret_seed)
    }

    #[must_use]
    pub fn from_secret_seed(secret_seed: [u8; 32]) -> Self {
        Self::from_zeroizing_seed(Zeroizing::new(secret_seed))
    }

    fn from_zeroizing_seed(secret_seed: Zeroizing<[u8; 32]>) -> Self {
        let signing_key = SigningKey::from_bytes(&secret_seed);
        let public_identity =
            PublicIdentity::from_public_key(signing_key.verifying_key().to_bytes());
        Self {
            secret_seed,
            public_identity,
        }
    }
}

impl DeviceSigner for SoftwareSigner {
    fn public_identity(&self) -> PublicIdentity {
        self.public_identity
    }

    fn sign(&self, message: &[u8]) -> Result<DeviceSignature, SigningError> {
        let signing_key = SigningKey::from_bytes(&self.secret_seed);
        Ok(DeviceSignature(signing_key.sign(message).to_bytes()))
    }
}

impl fmt::Debug for SoftwareSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SoftwareSigner([secret redacted])")
    }
}
