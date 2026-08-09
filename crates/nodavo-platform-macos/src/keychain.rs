//! Bounded persistence for Nodavo secrets in the current user's Keychain.

use std::fmt;

use thiserror::Error;
use zeroize::Zeroize;

/// Generic-password service used by the Nodavo session agent.
pub const NODAVO_AGENT_KEYCHAIN_SERVICE: &str = "dev.nodavo.agent";
/// Account containing the Ed25519 device signing seed.
pub const DEVICE_SIGNING_SEED_ACCOUNT: &str = "dev.nodavo.device-signing-seed.v1";
/// Account containing the TLS private key in its application-defined encoding.
pub const TLS_PRIVATE_KEY_ACCOUNT: &str = "dev.nodavo.tls-private-key.v1";
/// Account containing the bounded, application-encoded trust database.
pub const TRUST_DATABASE_ACCOUNT: &str = "dev.nodavo.trust-database.v1";

const NODAVO_NAMESPACE: &str = "dev.nodavo.";
const MAX_SERVICE_BYTES: usize = 128;
const MAX_ACCOUNT_BYTES: usize = 192;
/// Maximum number of bytes stored in any one Nodavo Keychain item.
pub const MAX_KEYCHAIN_SECRET_BYTES: usize = 512 * 1024;

/// A Keychain-loaded value whose contents are redacted from `Debug` and wiped
/// from its Rust-owned allocation on drop.
pub struct KeychainSecret(Vec<u8>);

impl KeychainSecret {
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Borrow the secret for immediate parsing or key construction.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        &self.0
    }

    /// Length of the secret without exposing its contents.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl AsRef<[u8]> for KeychainSecret {
    fn as_ref(&self) -> &[u8] {
        self.expose_secret()
    }
}

impl fmt::Debug for KeychainSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KeychainSecret([REDACTED])")
    }
}

impl Drop for KeychainSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Whether a successful store created an item or atomically replaced its data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreDisposition {
    Created,
    Updated,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[non_exhaustive]
pub enum KeychainError {
    #[error("the Keychain service is not a valid Nodavo namespace")]
    InvalidService,
    #[error("the Keychain account is not a valid Nodavo namespace")]
    InvalidAccount,
    #[error("the Keychain value is empty")]
    EmptySecret,
    #[error("the Keychain value exceeds the 512 KiB limit")]
    SecretTooLarge,
    #[error("the Keychain item does not exist")]
    NotFound,
    #[error("the Keychain item is malformed or exceeds the 512 KiB limit")]
    MalformedItem,
    #[error("Keychain access requires an unlocked user session")]
    InteractionNotAllowed,
    #[error("Keychain authentication failed")]
    AuthenticationFailed,
    #[error("the current user's Keychain is unavailable")]
    Unavailable,
    #[error("the process lacks the signed Keychain access entitlement")]
    MissingEntitlement,
    #[error("Security.framework rejected the Keychain operation (OSStatus {0})")]
    SecurityFramework(i32),
}

/// A service-scoped boundary around current-user, non-synchronizable Keychain
/// generic-password items.
///
/// The service and every account must live under `dev.nodavo.`. The native
/// adapter selects the Data Protection Keychain and
/// `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`; it never falls back to a
/// file or another keychain.
#[derive(Clone, Eq, PartialEq)]
pub struct MacKeychain {
    service: String,
}

impl MacKeychain {
    /// Creates a boundary for a service in the `dev.nodavo.` namespace.
    ///
    /// # Errors
    ///
    /// Returns [`KeychainError::InvalidService`] if the service is malformed,
    /// outside the namespace, or longer than the configured bound.
    pub fn new(service: &str) -> Result<Self, KeychainError> {
        validate_name(service, MAX_SERVICE_BYTES).map_err(|()| KeychainError::InvalidService)?;
        Ok(Self {
            service: service.to_owned(),
        })
    }

    #[must_use]
    pub fn service(&self) -> &str {
        &self.service
    }

    /// Creates or atomically updates a bounded Keychain value.
    ///
    /// # Errors
    ///
    /// Returns a validation error before native access, or a semantic
    /// Keychain error if Security.framework rejects the operation.
    pub fn store(&self, account: &str, secret: &[u8]) -> Result<StoreDisposition, KeychainError> {
        Self::validate_account(account)?;
        validate_secret(secret)?;

        #[cfg(target_os = "macos")]
        {
            super::macos::keychain_store(&self.service, account, secret)
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(KeychainError::Unavailable)
        }
    }

    /// Loads a bounded Keychain value into a redacted, zeroizing container.
    ///
    /// # Errors
    ///
    /// Returns [`KeychainError::NotFound`] for a missing item, a validation
    /// error for a malformed account, or another semantic Keychain error.
    pub fn load(&self, account: &str) -> Result<KeychainSecret, KeychainError> {
        Self::validate_account(account)?;

        #[cfg(target_os = "macos")]
        {
            let bytes = super::macos::keychain_load(&self.service, account)?;
            Ok(KeychainSecret::new(bytes))
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(KeychainError::Unavailable)
        }
    }

    /// Deletes one Keychain value without affecting any other account.
    ///
    /// # Errors
    ///
    /// Returns [`KeychainError::NotFound`] for a missing item, a validation
    /// error for a malformed account, or another semantic Keychain error.
    pub fn delete(&self, account: &str) -> Result<(), KeychainError> {
        Self::validate_account(account)?;

        #[cfg(target_os = "macos")]
        {
            super::macos::keychain_delete(&self.service, account)
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(KeychainError::Unavailable)
        }
    }

    fn validate_account(account: &str) -> Result<(), KeychainError> {
        validate_name(account, MAX_ACCOUNT_BYTES).map_err(|()| KeychainError::InvalidAccount)
    }
}

impl Default for MacKeychain {
    fn default() -> Self {
        Self {
            service: NODAVO_AGENT_KEYCHAIN_SERVICE.to_owned(),
        }
    }
}

impl fmt::Debug for MacKeychain {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacKeychain")
            .field("service", &self.service)
            .finish_non_exhaustive()
    }
}

fn validate_name(value: &str, maximum: usize) -> Result<(), ()> {
    if value.len() > maximum || !value.starts_with(NODAVO_NAMESPACE) {
        return Err(());
    }
    let suffix = &value[NODAVO_NAMESPACE.len()..];
    if suffix.is_empty()
        || suffix.starts_with('.')
        || suffix.ends_with('.')
        || suffix.contains("..")
        || !suffix.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
    {
        return Err(());
    }
    Ok(())
}

fn validate_secret(secret: &[u8]) -> Result<(), KeychainError> {
    if secret.is_empty() {
        return Err(KeychainError::EmptySecret);
    }
    if secret.len() > MAX_KEYCHAIN_SECRET_BYTES {
        return Err(KeychainError::SecretTooLarge);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_service_and_account_namespaces() {
        assert!(MacKeychain::new(NODAVO_AGENT_KEYCHAIN_SERVICE).is_ok());
        assert_eq!(
            MacKeychain::new("example.invalid.agent"),
            Err(KeychainError::InvalidService)
        );

        let store = MacKeychain::default();
        assert!(matches!(
            store.load("device-key"),
            Err(KeychainError::InvalidAccount)
        ));
        assert!(matches!(
            store.load("dev.nodavo.bad/account"),
            Err(KeychainError::InvalidAccount)
        ));
    }

    #[test]
    fn rejects_secret_bounds_before_platform_access() {
        let store = MacKeychain::default();
        assert_eq!(
            store.store(DEVICE_SIGNING_SEED_ACCOUNT, &[]),
            Err(KeychainError::EmptySecret)
        );
        let oversized = vec![0_u8; MAX_KEYCHAIN_SECRET_BYTES + 1];
        assert_eq!(
            store.store(DEVICE_SIGNING_SEED_ACCOUNT, &oversized),
            Err(KeychainError::SecretTooLarge)
        );
    }

    #[test]
    fn debug_output_redacts_secret_contents() {
        let secret = KeychainSecret::new(b"must-not-appear".to_vec());
        let rendered = format!("{secret:?}");
        assert!(!rendered.contains("must-not-appear"));
        assert_eq!(rendered, "KeychainSecret([REDACTED])");
    }
}
