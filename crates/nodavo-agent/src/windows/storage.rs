//! Current-user DPAPI persistence for the Windows agent.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

use nodavo_platform_windows::{
    MAX_PROTECTED_SECRET_BLOB_BYTES, ProtectedSecretBlob, protect_current_user_secret,
    replace_file_atomic, unprotect_current_user_secret,
};

use crate::storage::{
    DevelopmentStorage, DeviceMaterial, MAX_STORAGE_FILE_BYTES, PeerRecord, StorageError,
    create_identity, decode_identity, decode_peers, encode_peers,
};

const IDENTITY_FILE: &str = "identity-v1.dpapi";
const TRUST_FILE: &str = "trust-v1.dpapi";
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

pub(super) struct WindowsDpapiStorage {
    directory: PathBuf,
}

impl WindowsDpapiStorage {
    pub(super) fn new(directory: PathBuf) -> Self {
        Self { directory }
    }

    fn prepare_directory(&self) -> Result<(), StorageError> {
        match fs::symlink_metadata(&self.directory) {
            Ok(metadata) => validate_directory_metadata(&metadata),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir_all(&self.directory)?;
                let metadata = fs::symlink_metadata(&self.directory)?;
                validate_directory_metadata(&metadata)
            }
            Err(error) => Err(error.into()),
        }
    }

    fn identity_path(&self) -> PathBuf {
        self.directory.join(IDENTITY_FILE)
    }

    fn trust_path(&self) -> PathBuf {
        self.directory.join(TRUST_FILE)
    }
}

impl DevelopmentStorage for WindowsDpapiStorage {
    fn load_or_create_identity(&self) -> Result<DeviceMaterial, StorageError> {
        self.prepare_directory()?;
        let path = self.identity_path();
        if let Some(protected) = read_protected(&path)? {
            let plaintext =
                unprotect_current_user_secret(&protected).map_err(|_| StorageError::Protection)?;
            if plaintext.len() as u64 > MAX_STORAGE_FILE_BYTES {
                return Err(StorageError::InvalidData);
            }
            return decode_identity(&plaintext);
        }

        let (material, plaintext) = create_identity()?;
        protect_and_write(&path, &plaintext)?;
        Ok(material)
    }

    fn load_peers(&self) -> Result<Vec<PeerRecord>, StorageError> {
        self.prepare_directory()?;
        let Some(protected) = read_protected(&self.trust_path())? else {
            return Ok(Vec::new());
        };
        let plaintext =
            unprotect_current_user_secret(&protected).map_err(|_| StorageError::Protection)?;
        decode_peers(&plaintext)
    }

    fn store_peers(&self, peers: &[PeerRecord]) -> Result<(), StorageError> {
        self.prepare_directory()?;
        let plaintext = encode_peers(peers)?;
        protect_and_write(&self.trust_path(), &plaintext)
    }
}

fn validate_directory_metadata(metadata: &fs::Metadata) -> Result<(), StorageError> {
    if !metadata.file_type().is_dir()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        Err(StorageError::UnsafePath)
    } else {
        Ok(())
    }
}

fn validate_file_metadata(metadata: &fs::Metadata) -> Result<(), StorageError> {
    if !metadata.file_type().is_file()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || metadata.len() > MAX_PROTECTED_SECRET_BLOB_BYTES as u64
    {
        Err(StorageError::UnsafePath)
    } else {
        Ok(())
    }
}

fn read_protected(path: &Path) -> Result<Option<ProtectedSecretBlob>, StorageError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .share_mode(0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let metadata = file.metadata()?;
    validate_file_metadata(&metadata)?;
    let capacity = usize::try_from(metadata.len()).map_err(|_| StorageError::InvalidData)?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(MAX_PROTECTED_SECRET_BLOB_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_PROTECTED_SECRET_BLOB_BYTES {
        return Err(StorageError::InvalidData);
    }
    ProtectedSecretBlob::from_bytes(bytes)
        .map(Some)
        .map_err(|_| StorageError::InvalidData)
}

fn protect_and_write(path: &Path, plaintext: &[u8]) -> Result<(), StorageError> {
    if plaintext.is_empty() || plaintext.len() as u64 > MAX_STORAGE_FILE_BYTES {
        return Err(StorageError::InvalidData);
    }
    let protected = protect_current_user_secret(plaintext).map_err(|_| StorageError::Protection)?;
    write_protected_atomic(path, protected.as_bytes())
}

fn write_protected_atomic(path: &Path, bytes: &[u8]) -> Result<(), StorageError> {
    if bytes.is_empty() || bytes.len() > MAX_PROTECTED_SECRET_BLOB_BYTES {
        return Err(StorageError::InvalidData);
    }
    if let Ok(metadata) = fs::symlink_metadata(path) {
        validate_file_metadata(&metadata)?;
    }
    let parent = path.parent().ok_or(StorageError::UnsafePath)?;
    let temporary = parent.join(format!(
        ".nodavo-protected-{}-{:016x}.tmp",
        std::process::id(),
        rand::random::<u64>()
    ));
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .share_mode(0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let mut file = options.open(&temporary)?;
    let write_result = file.write_all(bytes).and_then(|()| file.sync_all());
    drop(file);
    let result = write_result.map_err(StorageError::Io).and_then(|()| {
        replace_file_atomic(&temporary, path).map_err(|_| StorageError::AtomicReplace)
    });
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use nodavo_identity::{Capability, CapabilityGrants, DeviceSigner as _};

    use super::*;

    fn temporary_directory() -> PathBuf {
        std::env::temp_dir().join(format!(
            "nodavo-agent-dpapi-test-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ))
    }

    #[test]
    fn identity_is_persistent_without_plaintext_secret_fields() {
        let directory = temporary_directory();
        let storage = WindowsDpapiStorage::new(directory.clone());
        let first = storage.load_or_create_identity().unwrap();
        let second = storage.load_or_create_identity().unwrap();
        assert_eq!(
            first.signer.public_identity(),
            second.signer.public_identity()
        );
        assert_eq!(first.certificate_der, second.certificate_der);

        let protected = fs::read(directory.join(IDENTITY_FILE)).unwrap();
        assert!(
            !protected
                .windows(b"ed25519_seed".len())
                .any(|window| window == b"ed25519_seed")
        );
        assert!(serde_json::from_slice::<serde_json::Value>(&protected).is_err());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn trust_replacement_is_persistent_and_dpapi_protected() {
        let directory = temporary_directory();
        let storage = WindowsDpapiStorage::new(directory.clone());
        let generated =
            rcgen::generate_simple_self_signed(vec!["peer.nodavo.invalid".to_owned()]).unwrap();
        let mut peer = PeerRecord {
            public_key: [7_u8; 32],
            certificate_der: generated.cert.der().to_vec(),
            grants: CapabilityGrants::NONE.with(Capability::RemoteInput),
            established_at_unix_ms: 10,
            revoked_at_unix_ms: None,
            server_name: "peer.nodavo.invalid".to_owned(),
            last_endpoint: None,
        };

        storage.store_peers(std::slice::from_ref(&peer)).unwrap();
        peer.last_endpoint = Some("127.0.0.1:44310".parse().unwrap());
        storage.store_peers(std::slice::from_ref(&peer)).unwrap();
        assert_eq!(storage.load_peers().unwrap(), vec![peer]);

        let protected = fs::read(directory.join(TRUST_FILE)).unwrap();
        assert!(
            !protected
                .windows(b"public_key".len())
                .any(|window| window == b"public_key")
        );
        assert!(serde_json::from_slice::<serde_json::Value>(&protected).is_err());
        fs::remove_dir_all(directory).unwrap();
    }
}
