//! Production identity and trust persistence in the current user's Keychain.

use zeroize::Zeroizing;

use nodavo_platform_macos::{
    DEVICE_SIGNING_SEED_ACCOUNT, KeychainError, MacKeychain, StoreDisposition,
    TLS_PRIVATE_KEY_ACCOUNT, TRUST_DATABASE_ACCOUNT,
};

use crate::storage::{
    DevelopmentStorage, DeviceMaterial, PeerRecord, StorageError, create_split_identity,
    decode_peers, decode_split_identity, encode_peers,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SecretStoreDisposition {
    Created,
    Updated,
}

trait SecretStore: Send + Sync {
    fn load(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, StorageError>;
    fn store(&self, account: &str, value: &[u8]) -> Result<SecretStoreDisposition, StorageError>;
    fn delete(&self, account: &str) -> Result<(), StorageError>;
}

struct SystemSecretStore {
    keychain: MacKeychain,
}

impl SystemSecretStore {
    fn new() -> Self {
        Self {
            keychain: MacKeychain::default(),
        }
    }
}

impl SecretStore for SystemSecretStore {
    fn load(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, StorageError> {
        match self.keychain.load(account) {
            Ok(secret) => Ok(Some(Zeroizing::new(secret.expose_secret().to_vec()))),
            Err(KeychainError::NotFound) => Ok(None),
            Err(error) => Err(map_keychain_error(&error)),
        }
    }

    fn store(&self, account: &str, value: &[u8]) -> Result<SecretStoreDisposition, StorageError> {
        self.keychain
            .store(account, value)
            .map(|disposition| match disposition {
                StoreDisposition::Created => SecretStoreDisposition::Created,
                StoreDisposition::Updated => SecretStoreDisposition::Updated,
            })
            .map_err(|error| map_keychain_error(&error))
    }

    fn delete(&self, account: &str) -> Result<(), StorageError> {
        match self.keychain.delete(account) {
            Ok(()) | Err(KeychainError::NotFound) => Ok(()),
            Err(error) => Err(map_keychain_error(&error)),
        }
    }
}

fn map_keychain_error(error: &KeychainError) -> StorageError {
    match error {
        KeychainError::MissingEntitlement => StorageError::MissingEntitlement,
        _ => StorageError::Keychain,
    }
}

/// Production macOS storage. It never consults the development file backend.
pub(crate) struct MacKeychainStorage {
    store: Box<dyn SecretStore>,
}

impl MacKeychainStorage {
    /// Opens the production Keychain boundary and verifies entitlement access.
    pub(crate) fn new() -> Result<Self, StorageError> {
        Self::with_store(Box::new(SystemSecretStore::new()))
    }

    fn with_store(store: Box<dyn SecretStore>) -> Result<Self, StorageError> {
        let storage = Self { store };
        // A missing item proves the query was authorized. Any entitlement,
        // locked-session, malformed-item, or Keychain failure remains fatal.
        drop(storage.store.load(TRUST_DATABASE_ACCOUNT)?);
        Ok(storage)
    }
}

impl DevelopmentStorage for MacKeychainStorage {
    fn load_or_create_identity(&self) -> Result<DeviceMaterial, StorageError> {
        let signing = self.store.load(DEVICE_SIGNING_SEED_ACCOUNT)?;
        let tls = self.store.load(TLS_PRIVATE_KEY_ACCOUNT)?;
        match (signing, tls) {
            (Some(signing), Some(tls)) => decode_split_identity(&signing, &tls),
            (None, None) => {
                let (material, signing, tls) = create_split_identity()?;
                let signing_disposition =
                    self.store.store(DEVICE_SIGNING_SEED_ACCOUNT, &signing)?;
                if let Err(error) = self.store.store(TLS_PRIVATE_KEY_ACCOUNT, &tls) {
                    if signing_disposition == SecretStoreDisposition::Created {
                        let _ = self.store.delete(DEVICE_SIGNING_SEED_ACCOUNT);
                    }
                    return Err(error);
                }
                Ok(material)
            }
            (Some(_), None) | (None, Some(_)) => Err(StorageError::InvalidData),
        }
    }

    fn load_peers(&self) -> Result<Vec<PeerRecord>, StorageError> {
        let Some(encoded) = self.store.load(TRUST_DATABASE_ACCOUNT)? else {
            return Ok(Vec::new());
        };
        decode_peers(&encoded)
    }

    fn store_peers(&self, peers: &[PeerRecord]) -> Result<(), StorageError> {
        let encoded = encode_peers(peers)?;
        let _ = self.store.store(TRUST_DATABASE_ACCOUNT, &encoded)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use nodavo_identity::{CapabilityGrants, DeviceSigner as _};

    use super::*;

    #[derive(Clone, Copy)]
    enum FakeFailure {
        MissingEntitlement,
        Keychain,
    }

    #[derive(Default)]
    struct FakeState {
        values: HashMap<String, Vec<u8>>,
        fail_all: Option<FakeFailure>,
        fail_store_account: Option<String>,
    }

    #[derive(Clone, Default)]
    struct FakeSecretStore {
        state: Arc<Mutex<FakeState>>,
    }

    impl FakeSecretStore {
        fn with_failure(failure: FakeFailure) -> Self {
            let store = Self::default();
            store.state.lock().unwrap().fail_all = Some(failure);
            store
        }

        fn fail_store(&self, account: &str) {
            self.state.lock().unwrap().fail_store_account = Some(account.to_owned());
        }

        fn contains(&self, account: &str) -> bool {
            self.state.lock().unwrap().values.contains_key(account)
        }

        fn insert(&self, account: &str, value: &[u8]) {
            self.state
                .lock()
                .unwrap()
                .values
                .insert(account.to_owned(), value.to_vec());
        }

        fn failure(state: &FakeState) -> Result<(), StorageError> {
            match state.fail_all {
                Some(FakeFailure::MissingEntitlement) => Err(StorageError::MissingEntitlement),
                Some(FakeFailure::Keychain) => Err(StorageError::Keychain),
                None => Ok(()),
            }
        }
    }

    impl SecretStore for FakeSecretStore {
        fn load(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, StorageError> {
            let state = self.state.lock().unwrap();
            Self::failure(&state)?;
            Ok(state.values.get(account).cloned().map(Zeroizing::new))
        }

        fn store(
            &self,
            account: &str,
            value: &[u8],
        ) -> Result<SecretStoreDisposition, StorageError> {
            let mut state = self.state.lock().unwrap();
            Self::failure(&state)?;
            if state.fail_store_account.as_deref() == Some(account) {
                return Err(StorageError::Keychain);
            }
            let disposition = if state
                .values
                .insert(account.to_owned(), value.to_vec())
                .is_some()
            {
                SecretStoreDisposition::Updated
            } else {
                SecretStoreDisposition::Created
            };
            Ok(disposition)
        }

        fn delete(&self, account: &str) -> Result<(), StorageError> {
            let mut state = self.state.lock().unwrap();
            Self::failure(&state)?;
            state.values.remove(account);
            Ok(())
        }
    }

    fn peer_record() -> PeerRecord {
        let generated =
            rcgen::generate_simple_self_signed(vec!["peer.nodavo.invalid".to_owned()]).unwrap();
        PeerRecord {
            public_key: [7; 32],
            certificate_der: generated.cert.der().to_vec(),
            grants: CapabilityGrants::NONE,
            established_at_unix_ms: 10,
            revoked_at_unix_ms: None,
            server_name: "peer.nodavo.invalid".to_owned(),
            last_endpoint: Some("127.0.0.1:4431".parse().unwrap()),
        }
    }

    #[test]
    fn identity_and_trust_round_trip_through_separate_accounts() {
        let backend = FakeSecretStore::default();
        let storage = MacKeychainStorage::with_store(Box::new(backend.clone())).unwrap();
        let first = storage.load_or_create_identity().unwrap();
        let peers = vec![peer_record()];
        storage.store_peers(&peers).unwrap();

        let reopened = MacKeychainStorage::with_store(Box::new(backend.clone())).unwrap();
        let second = reopened.load_or_create_identity().unwrap();
        assert_eq!(
            first.signer.public_identity(),
            second.signer.public_identity()
        );
        assert_eq!(first.certificate_der, second.certificate_der);
        assert_eq!(reopened.load_peers().unwrap(), peers);
        assert!(backend.contains(DEVICE_SIGNING_SEED_ACCOUNT));
        assert!(backend.contains(TLS_PRIVATE_KEY_ACCOUNT));
        assert!(backend.contains(TRUST_DATABASE_ACCOUNT));
    }

    #[test]
    fn partial_identity_fails_closed_without_regeneration() {
        let backend = FakeSecretStore::default();
        let (_, signing, _) = create_split_identity().unwrap();
        backend.insert(DEVICE_SIGNING_SEED_ACCOUNT, &signing);
        let storage = MacKeychainStorage::with_store(Box::new(backend.clone())).unwrap();

        assert!(matches!(
            storage.load_or_create_identity(),
            Err(StorageError::InvalidData)
        ));
        assert!(backend.contains(DEVICE_SIGNING_SEED_ACCOUNT));
        assert!(!backend.contains(TLS_PRIVATE_KEY_ACCOUNT));
    }

    #[test]
    fn failed_tls_store_rolls_back_new_signing_seed() {
        let backend = FakeSecretStore::default();
        backend.fail_store(TLS_PRIVATE_KEY_ACCOUNT);
        let storage = MacKeychainStorage::with_store(Box::new(backend.clone())).unwrap();

        assert!(matches!(
            storage.load_or_create_identity(),
            Err(StorageError::Keychain)
        ));
        assert!(!backend.contains(DEVICE_SIGNING_SEED_ACCOUNT));
        assert!(!backend.contains(TLS_PRIVATE_KEY_ACCOUNT));
    }

    #[test]
    fn missing_entitlement_is_not_replaced_with_another_backend() {
        let backend = FakeSecretStore::with_failure(FakeFailure::MissingEntitlement);
        assert!(matches!(
            MacKeychainStorage::with_store(Box::new(backend)),
            Err(StorageError::MissingEntitlement)
        ));

        let backend = FakeSecretStore::with_failure(FakeFailure::Keychain);
        assert!(matches!(
            MacKeychainStorage::with_store(Box::new(backend)),
            Err(StorageError::Keychain)
        ));
    }
}
