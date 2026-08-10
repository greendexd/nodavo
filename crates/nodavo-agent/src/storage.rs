//! Persistent identity and trust serialization behind an explicit storage boundary.
//!
//! The private-file backend is development-only. Production platform adapters
//! persist the same bounded semantic records through OS-protected storage.
//! No backend logs identity, trust, or private-key contents.

use std::collections::HashSet;
#[cfg(unix)]
use std::fs::{self, File, OpenOptions};
#[cfg(unix)]
use std::io::{Read, Write};
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
#[cfg(unix)]
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use nodavo_identity::{
    CapabilityGrants, DeviceId, PublicIdentity, Revocation, RevocationReason, SoftwareSigner,
    TransportCertificate, TrustRecord,
};
use nodavo_local_ipc::MAX_TRUSTED_PEERS;
use nodavo_protocol::GrantEpoch;
use nodavo_transport::quinn_backend::CertificateCredentials;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const IDENTITY_FORMAT_VERSION: u16 = 1;
const LEGACY_TRUST_FORMAT_VERSION: u16 = 1;
const TRUST_FORMAT_VERSION: u16 = 2;
#[cfg(unix)]
const IDENTITY_FILE: &str = "development-identity-v1.json";
#[cfg(unix)]
const TRUST_FILE: &str = "development-trust-v1.json";
pub(crate) const MAX_STORAGE_FILE_BYTES: u64 = 512 * 1024;
const MAX_PEERS: usize = MAX_TRUSTED_PEERS;
const MAX_DISPLAY_NAME_BYTES: usize = 63;
const MIGRATED_DISPLAY_NAME: &str = "Previously trusted device";
pub(crate) const MAX_PRIVATE_KEY_BYTES: usize = 16 * 1024;
pub(crate) const MAX_CERTIFICATE_BYTES: usize = 64 * 1024;
pub(crate) const MAX_SERVER_NAME_BYTES: usize = 253;

pub(crate) struct DeviceMaterial {
    pub(crate) signer: SoftwareSigner,
    pub(crate) certificate_der: Vec<u8>,
    pub(crate) private_key_pkcs8_der: Zeroizing<Vec<u8>>,
    pub(crate) server_name: String,
}

#[cfg(any(target_os = "macos", all(test, unix)))]
pub(crate) type SplitIdentityPayloads = (DeviceMaterial, Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>);

impl DeviceMaterial {
    pub(crate) fn credentials(&self) -> Result<CertificateCredentials, StorageError> {
        CertificateCredentials::from_der(
            vec![self.certificate_der.clone()],
            self.private_key_pkcs8_der.to_vec(),
        )
        .map_err(|_| StorageError::InvalidData)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PeerRecord {
    pub(crate) public_key: [u8; 32],
    pub(crate) certificate_der: Vec<u8>,
    pub(crate) grants: CapabilityGrants,
    pub(crate) grant_epoch: GrantEpoch,
    pub(crate) display_name: String,
    pub(crate) established_at_unix_ms: u64,
    pub(crate) revoked_at_unix_ms: Option<u64>,
    pub(crate) server_name: String,
    pub(crate) last_endpoint: Option<SocketAddr>,
}

impl PeerRecord {
    pub(crate) fn device_id(&self) -> DeviceId {
        PublicIdentity::from_public_key(self.public_key).device_id()
    }

    pub(crate) const fn is_active(&self) -> bool {
        self.revoked_at_unix_ms.is_none()
    }

    /// Restores the binding only from the already validated private trust file.
    pub(crate) fn restored_trust(&self) -> Result<TrustRecord, StorageError> {
        let identity = PublicIdentity::from_public_key(self.public_key);
        let certificate = TransportCertificate::from_der(self.certificate_der.clone())
            .map_err(|_| StorageError::InvalidData)?;
        let revocation = self
            .revoked_at_unix_ms
            .map(|timestamp| Revocation::new(timestamp, RevocationReason::UserRequested));
        TrustRecord::restore_persisted(
            identity,
            certificate,
            self.grants,
            self.established_at_unix_ms,
            revocation,
        )
        .map_err(|_| StorageError::InvalidData)
    }
}

#[derive(Debug, Error)]
pub(crate) enum StorageError {
    #[error("persistent storage I/O failed")]
    Io(#[from] std::io::Error),
    #[error("persistent storage data is invalid or unsupported")]
    InvalidData,
    #[error("persistent storage path is unsafe")]
    UnsafePath,
    #[cfg(target_os = "windows")]
    #[error("operating-system storage protection failed")]
    Protection,
    #[cfg(target_os = "windows")]
    #[error("atomic persistent storage replacement failed")]
    AtomicReplace,
    #[cfg(target_os = "macos")]
    #[error("macOS Keychain access requires a signed Keychain entitlement")]
    MissingEntitlement,
    #[cfg(target_os = "macos")]
    #[error("macOS Keychain storage failed")]
    Keychain,
}

pub(crate) trait DevelopmentStorage: Send + Sync {
    fn load_or_create_identity(&self) -> Result<DeviceMaterial, StorageError>;
    fn load_peers(&self) -> Result<Vec<PeerRecord>, StorageError>;
    fn store_peers(&self, peers: &[PeerRecord]) -> Result<(), StorageError>;
}

#[cfg(unix)]
pub(crate) struct FileDevelopmentStorage {
    directory: PathBuf,
}

#[cfg(unix)]
impl FileDevelopmentStorage {
    pub(crate) fn new(directory: PathBuf) -> Self {
        Self { directory }
    }

    fn prepare_directory(&self) -> Result<(), StorageError> {
        if let Ok(metadata) = fs::symlink_metadata(&self.directory) {
            if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
                return Err(StorageError::UnsafePath);
            }
        } else {
            fs::create_dir_all(&self.directory)?;
        }
        #[cfg(unix)]
        fs::set_permissions(&self.directory, fs::Permissions::from_mode(0o700))?;
        Ok(())
    }

    fn identity_path(&self) -> PathBuf {
        self.directory.join(IDENTITY_FILE)
    }

    fn trust_path(&self) -> PathBuf {
        self.directory.join(TRUST_FILE)
    }
}

#[cfg(unix)]
impl DevelopmentStorage for FileDevelopmentStorage {
    fn load_or_create_identity(&self) -> Result<DeviceMaterial, StorageError> {
        self.prepare_directory()?;
        let path = self.identity_path();
        if let Some(bytes) = read_bounded(&path)? {
            return decode_identity(&bytes);
        }
        let (material, encoded) = create_identity()?;
        write_private_atomic(&path, &encoded)?;
        Ok(material)
    }

    fn load_peers(&self) -> Result<Vec<PeerRecord>, StorageError> {
        self.prepare_directory()?;
        let Some(bytes) = read_bounded(&self.trust_path())? else {
            return Ok(Vec::new());
        };
        decode_peers(&bytes)
    }

    fn store_peers(&self, peers: &[PeerRecord]) -> Result<(), StorageError> {
        self.prepare_directory()?;
        let encoded = encode_peers(peers)?;
        write_private_atomic(&self.trust_path(), &encoded)
    }
}

#[derive(Deserialize, Serialize, Zeroize)]
#[serde(deny_unknown_fields)]
struct IdentityDisk {
    format_version: u16,
    ed25519_seed: String,
    certificate_der: String,
    private_key_pkcs8_der: String,
    server_name: String,
}

#[derive(Deserialize, Serialize, Zeroize)]
#[serde(deny_unknown_fields)]
#[cfg(any(target_os = "macos", all(test, unix)))]
struct SigningSeedDisk {
    format_version: u16,
    ed25519_seed: String,
}

#[derive(Deserialize, Serialize, Zeroize)]
#[serde(deny_unknown_fields)]
#[cfg(any(target_os = "macos", all(test, unix)))]
struct TlsIdentityDisk {
    format_version: u16,
    certificate_der: String,
    private_key_pkcs8_der: String,
    server_name: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TrustDisk {
    format_version: u16,
    peers: Vec<PeerDisk>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PeerDisk {
    public_key: String,
    certificate_der: String,
    grants: u8,
    #[serde(default)]
    grant_epoch: Option<u64>,
    #[serde(default)]
    display_name: Option<String>,
    established_at_unix_ms: u64,
    revoked_at_unix_ms: Option<u64>,
    server_name: String,
    last_endpoint: Option<String>,
}

impl PeerDisk {
    fn from_record(record: &PeerRecord) -> Self {
        Self {
            public_key: STANDARD.encode(record.public_key),
            certificate_der: STANDARD.encode(&record.certificate_der),
            grants: record.grants.bits(),
            grant_epoch: Some(record.grant_epoch.get()),
            display_name: Some(record.display_name.clone()),
            established_at_unix_ms: record.established_at_unix_ms,
            revoked_at_unix_ms: record.revoked_at_unix_ms,
            server_name: record.server_name.clone(),
            last_endpoint: record.last_endpoint.map(|value| value.to_string()),
        }
    }

    fn into_record(self, format_version: u16) -> Result<PeerRecord, StorageError> {
        let public_key = decode_array::<32>(&self.public_key)?;
        let certificate_der = decode_bounded(&self.certificate_der, MAX_CERTIFICATE_BYTES)?;
        TransportCertificate::from_der(certificate_der.clone())
            .map_err(|_| StorageError::InvalidData)?;
        let grants =
            CapabilityGrants::from_bits(self.grants).map_err(|_| StorageError::InvalidData)?;
        let (grant_epoch, display_name) = match format_version {
            LEGACY_TRUST_FORMAT_VERSION
                if self.grant_epoch.is_none() && self.display_name.is_none() =>
            {
                (GrantEpoch::new(1), MIGRATED_DISPLAY_NAME.to_owned())
            }
            TRUST_FORMAT_VERSION => {
                let epoch = GrantEpoch::new(self.grant_epoch.ok_or(StorageError::InvalidData)?);
                let display_name = self.display_name.ok_or(StorageError::InvalidData)?;
                (epoch, display_name)
            }
            _ => return Err(StorageError::InvalidData),
        };
        if grant_epoch.is_zero() {
            return Err(StorageError::InvalidData);
        }
        validate_display_name(&display_name)?;
        validate_server_name(&self.server_name)?;
        if self
            .revoked_at_unix_ms
            .is_some_and(|revoked| revoked < self.established_at_unix_ms)
        {
            return Err(StorageError::InvalidData);
        }
        let last_endpoint = self
            .last_endpoint
            .map(|value| value.parse().map_err(|_| StorageError::InvalidData))
            .transpose()?;
        Ok(PeerRecord {
            public_key,
            certificate_der,
            grants,
            grant_epoch,
            display_name,
            established_at_unix_ms: self.established_at_unix_ms,
            revoked_at_unix_ms: self.revoked_at_unix_ms,
            server_name: self.server_name,
            last_endpoint,
        })
    }
}

pub(crate) fn create_identity() -> Result<(DeviceMaterial, Zeroizing<Vec<u8>>), StorageError> {
    let (material, secret_seed) = generate_identity_material()?;
    let disk = Zeroizing::new(IdentityDisk {
        format_version: IDENTITY_FORMAT_VERSION,
        ed25519_seed: STANDARD.encode(*secret_seed),
        certificate_der: STANDARD.encode(&material.certificate_der),
        private_key_pkcs8_der: STANDARD.encode(&*material.private_key_pkcs8_der),
        server_name: material.server_name.clone(),
    });
    let encoded = encode_sensitive(&*disk)?;
    Ok((material, encoded))
}

#[cfg(any(target_os = "macos", all(test, unix)))]
pub(crate) fn create_split_identity() -> Result<SplitIdentityPayloads, StorageError> {
    let (material, secret_seed) = generate_identity_material()?;
    let signing = Zeroizing::new(SigningSeedDisk {
        format_version: IDENTITY_FORMAT_VERSION,
        ed25519_seed: STANDARD.encode(*secret_seed),
    });
    let tls = Zeroizing::new(TlsIdentityDisk {
        format_version: IDENTITY_FORMAT_VERSION,
        certificate_der: STANDARD.encode(&material.certificate_der),
        private_key_pkcs8_der: STANDARD.encode(&*material.private_key_pkcs8_der),
        server_name: material.server_name.clone(),
    });
    Ok((
        material,
        encode_sensitive(&*signing)?,
        encode_sensitive(&*tls)?,
    ))
}

fn generate_identity_material() -> Result<(DeviceMaterial, Zeroizing<[u8; 32]>), StorageError> {
    let secret_seed = Zeroizing::new(rand::random::<[u8; 32]>());
    let signer = SoftwareSigner::from_secret_seed(*secret_seed);
    let server_name = "agent.nodavo.invalid".to_owned();
    let generated = rcgen::generate_simple_self_signed(vec![server_name.clone()])
        .map_err(|_| StorageError::InvalidData)?;
    let certificate_der = generated.cert.der().to_vec();
    let private_key_pkcs8_der = Zeroizing::new(generated.signing_key.serialize_der());
    Ok((
        DeviceMaterial {
            signer,
            certificate_der,
            private_key_pkcs8_der,
            server_name,
        },
        secret_seed,
    ))
}

pub(crate) fn decode_identity(bytes: &[u8]) -> Result<DeviceMaterial, StorageError> {
    validate_payload_size(bytes)?;
    let disk = Zeroizing::new(
        serde_json::from_slice::<IdentityDisk>(bytes).map_err(|_| StorageError::InvalidData)?,
    );
    if disk.format_version != IDENTITY_FORMAT_VERSION {
        return Err(StorageError::InvalidData);
    }
    let secret_seed = Zeroizing::new(decode_array::<32>(&disk.ed25519_seed)?);
    let certificate_der = decode_bounded(&disk.certificate_der, MAX_CERTIFICATE_BYTES)?;
    let private_key_pkcs8_der = Zeroizing::new(decode_bounded(
        &disk.private_key_pkcs8_der,
        MAX_PRIVATE_KEY_BYTES,
    )?);
    restore_identity_material(
        &secret_seed,
        certificate_der,
        private_key_pkcs8_der,
        disk.server_name.clone(),
    )
}

#[cfg(any(target_os = "macos", all(test, unix)))]
pub(crate) fn decode_split_identity(
    signing_bytes: &[u8],
    tls_bytes: &[u8],
) -> Result<DeviceMaterial, StorageError> {
    validate_payload_size(signing_bytes)?;
    validate_payload_size(tls_bytes)?;
    let signing = Zeroizing::new(
        serde_json::from_slice::<SigningSeedDisk>(signing_bytes)
            .map_err(|_| StorageError::InvalidData)?,
    );
    let tls = Zeroizing::new(
        serde_json::from_slice::<TlsIdentityDisk>(tls_bytes)
            .map_err(|_| StorageError::InvalidData)?,
    );
    if signing.format_version != IDENTITY_FORMAT_VERSION
        || tls.format_version != IDENTITY_FORMAT_VERSION
    {
        return Err(StorageError::InvalidData);
    }
    let secret_seed = Zeroizing::new(decode_array::<32>(&signing.ed25519_seed)?);
    let certificate_der = decode_bounded(&tls.certificate_der, MAX_CERTIFICATE_BYTES)?;
    let private_key_pkcs8_der = Zeroizing::new(decode_bounded(
        &tls.private_key_pkcs8_der,
        MAX_PRIVATE_KEY_BYTES,
    )?);
    restore_identity_material(
        &secret_seed,
        certificate_der,
        private_key_pkcs8_der,
        tls.server_name.clone(),
    )
}

fn restore_identity_material(
    secret_seed: &[u8; 32],
    certificate_der: Vec<u8>,
    private_key_pkcs8_der: Zeroizing<Vec<u8>>,
    server_name: String,
) -> Result<DeviceMaterial, StorageError> {
    validate_server_name(&server_name)?;
    TransportCertificate::from_der(certificate_der.clone())
        .map_err(|_| StorageError::InvalidData)?;
    CertificateCredentials::from_der(
        vec![certificate_der.clone()],
        private_key_pkcs8_der.to_vec(),
    )
    .map_err(|_| StorageError::InvalidData)?;
    Ok(DeviceMaterial {
        signer: SoftwareSigner::from_secret_seed(*secret_seed),
        certificate_der,
        private_key_pkcs8_der,
        server_name,
    })
}

fn encode_sensitive<T>(value: &T) -> Result<Zeroizing<Vec<u8>>, StorageError>
where
    T: Serialize,
{
    let encoded = Zeroizing::new(serde_json::to_vec(value).map_err(|_| StorageError::InvalidData)?);
    validate_payload_size(&encoded)?;
    Ok(encoded)
}

fn validate_payload_size(bytes: &[u8]) -> Result<(), StorageError> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_STORAGE_FILE_BYTES {
        Err(StorageError::InvalidData)
    } else {
        Ok(())
    }
}

pub(crate) fn encode_peers(peers: &[PeerRecord]) -> Result<Vec<u8>, StorageError> {
    if peers.len() > MAX_PEERS {
        return Err(StorageError::InvalidData);
    }
    let disk = TrustDisk {
        format_version: TRUST_FORMAT_VERSION,
        peers: peers.iter().map(PeerDisk::from_record).collect(),
    };
    let encoded = serde_json::to_vec(&disk).map_err(|_| StorageError::InvalidData)?;
    if encoded.len() as u64 > MAX_STORAGE_FILE_BYTES {
        return Err(StorageError::InvalidData);
    }
    Ok(encoded)
}

pub(crate) fn decode_peers(bytes: &[u8]) -> Result<Vec<PeerRecord>, StorageError> {
    if bytes.len() as u64 > MAX_STORAGE_FILE_BYTES {
        return Err(StorageError::InvalidData);
    }
    let disk: TrustDisk = serde_json::from_slice(bytes).map_err(|_| StorageError::InvalidData)?;
    if !matches!(
        disk.format_version,
        LEGACY_TRUST_FORMAT_VERSION | TRUST_FORMAT_VERSION
    ) || disk.peers.len() > MAX_PEERS
    {
        return Err(StorageError::InvalidData);
    }
    let format_version = disk.format_version;
    let mut ids = HashSet::with_capacity(disk.peers.len());
    disk.peers
        .into_iter()
        .map(|peer| {
            let record = peer.into_record(format_version)?;
            if !ids.insert(record.device_id()) {
                return Err(StorageError::InvalidData);
            }
            Ok(record)
        })
        .collect()
}

fn decode_array<const N: usize>(encoded: &str) -> Result<[u8; N], StorageError> {
    let decoded = Zeroizing::new(
        STANDARD
            .decode(encoded)
            .map_err(|_| StorageError::InvalidData)?,
    );
    decoded
        .as_slice()
        .try_into()
        .map_err(|_| StorageError::InvalidData)
}

fn decode_bounded(encoded: &str, maximum: usize) -> Result<Vec<u8>, StorageError> {
    if encoded.len() > maximum.saturating_mul(2) {
        return Err(StorageError::InvalidData);
    }
    let decoded = STANDARD
        .decode(encoded)
        .map_err(|_| StorageError::InvalidData)?;
    if decoded.is_empty() || decoded.len() > maximum {
        return Err(StorageError::InvalidData);
    }
    Ok(decoded)
}

fn validate_server_name(name: &str) -> Result<(), StorageError> {
    if name.is_empty() || name.len() > MAX_SERVER_NAME_BYTES || !name.is_ascii() {
        Err(StorageError::InvalidData)
    } else {
        Ok(())
    }
}

fn validate_display_name(name: &str) -> Result<(), StorageError> {
    if name.is_empty()
        || name.len() > MAX_DISPLAY_NAME_BYTES
        || name.trim() != name
        || name.chars().any(char::is_control)
    {
        Err(StorageError::InvalidData)
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn read_bounded(path: &Path) -> Result<Option<Vec<u8>>, StorageError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_STORAGE_FILE_BYTES
    {
        return Err(StorageError::UnsafePath);
    }
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    let file = File::open(path)?;
    let capacity = usize::try_from(metadata.len()).map_err(|_| StorageError::InvalidData)?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(MAX_STORAGE_FILE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_STORAGE_FILE_BYTES {
        return Err(StorageError::InvalidData);
    }
    Ok(Some(bytes))
}

#[cfg(unix)]
fn write_private_atomic(path: &Path, bytes: &[u8]) -> Result<(), StorageError> {
    if bytes.len() as u64 > MAX_STORAGE_FILE_BYTES {
        return Err(StorageError::InvalidData);
    }
    if let Ok(metadata) = fs::symlink_metadata(path)
        && (!metadata.file_type().is_file() || metadata.file_type().is_symlink())
    {
        return Err(StorageError::UnsafePath);
    }
    let parent = path.parent().ok_or(StorageError::UnsafePath)?;
    let temporary = parent.join(format!(
        ".nodavo-storage-{}-{:016x}.tmp",
        std::process::id(),
        rand::random::<u64>()
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(&temporary)?;
    let result = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        #[cfg(unix)]
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        Ok::<(), std::io::Error>(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(StorageError::Io)
}

pub(crate) fn device_id_text(device_id: DeviceId) -> String {
    let mut encoded = String::with_capacity(64);
    for byte in device_id.as_bytes() {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

#[cfg(all(test, unix))]
mod tests {
    use nodavo_identity::DeviceSigner as _;

    use super::*;

    fn temporary_directory() -> PathBuf {
        std::env::temp_dir().join(format!(
            "nodavo-agent-storage-test-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ))
    }

    #[test]
    fn identity_is_persistent_and_private() {
        let directory = temporary_directory();
        let storage = FileDevelopmentStorage::new(directory.clone());
        let first = storage.load_or_create_identity().unwrap();
        let second = storage.load_or_create_identity().unwrap();
        assert_eq!(
            first.signer.public_identity(),
            second.signer.public_identity()
        );
        assert_eq!(first.certificate_der, second.certificate_der);
        #[cfg(unix)]
        {
            let mode = fs::metadata(directory.join(IDENTITY_FILE))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn rejects_unknown_identity_format() {
        let directory = temporary_directory();
        fs::create_dir_all(&directory).unwrap();
        write_private_atomic(
            &directory.join(IDENTITY_FILE),
            br#"{"format_version":99,"ed25519_seed":"x","certificate_der":"x","private_key_pkcs8_der":"x","server_name":"x"}"#,
        )
        .unwrap();
        let storage = FileDevelopmentStorage::new(directory.clone());
        assert!(matches!(
            storage.load_or_create_identity(),
            Err(StorageError::InvalidData)
        ));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn split_identity_codec_is_versioned_and_bounded() {
        let (_, mut signing, tls) = create_split_identity().unwrap();
        let marker = br#""format_version":1"#;
        let version = signing
            .windows(marker.len())
            .position(|window| window == marker)
            .unwrap()
            + marker.len()
            - 1;
        signing[version] = b'9';
        assert!(matches!(
            decode_split_identity(&signing, &tls),
            Err(StorageError::InvalidData)
        ));

        let oversized = vec![0_u8; usize::try_from(MAX_STORAGE_FILE_BYTES).unwrap() + 1];
        assert!(matches!(
            decode_split_identity(&oversized, &tls),
            Err(StorageError::InvalidData)
        ));
    }

    #[test]
    fn restored_revoked_peer_cannot_expose_transport_binding() {
        let generated =
            rcgen::generate_simple_self_signed(vec!["peer.nodavo.invalid".to_owned()]).unwrap();
        let record = PeerRecord {
            public_key: [7_u8; 32],
            certificate_der: generated.cert.der().to_vec(),
            grants: CapabilityGrants::NONE,
            grant_epoch: GrantEpoch::new(1),
            display_name: "Test peer".to_owned(),
            established_at_unix_ms: 10,
            revoked_at_unix_ms: Some(11),
            server_name: "peer.nodavo.invalid".to_owned(),
            last_endpoint: Some("127.0.0.1:4431".parse().unwrap()),
        };
        let trust = record.restored_trust().unwrap();
        assert!(!trust.is_active());
        assert!(trust.transport_binding().is_none());
    }

    #[test]
    fn legacy_trust_migrates_to_named_epoch_records_without_losing_grants() {
        let generated =
            rcgen::generate_simple_self_signed(vec!["peer.nodavo.invalid".to_owned()]).unwrap();
        let record = PeerRecord {
            public_key: [8_u8; 32],
            certificate_der: generated.cert.der().to_vec(),
            grants: CapabilityGrants::NONE.with(nodavo_identity::Capability::RemoteInput),
            grant_epoch: GrantEpoch::new(7),
            display_name: "Current peer name".to_owned(),
            established_at_unix_ms: 10,
            revoked_at_unix_ms: None,
            server_name: "peer.nodavo.invalid".to_owned(),
            last_endpoint: Some("127.0.0.1:4431".parse().unwrap()),
        };
        let mut legacy: serde_json::Value =
            serde_json::from_slice(&encode_peers(std::slice::from_ref(&record)).unwrap()).unwrap();
        legacy["format_version"] = 1.into();
        legacy["peers"][0]
            .as_object_mut()
            .unwrap()
            .remove("grant_epoch");
        legacy["peers"][0]
            .as_object_mut()
            .unwrap()
            .remove("display_name");

        let migrated = decode_peers(&serde_json::to_vec(&legacy).unwrap()).unwrap();
        assert_eq!(migrated[0].grants, record.grants);
        assert_eq!(migrated[0].grant_epoch, GrantEpoch::new(1));
        assert_eq!(migrated[0].display_name, MIGRATED_DISPLAY_NAME);

        let persisted = encode_peers(&migrated).unwrap();
        let round_trip = decode_peers(&persisted).unwrap();
        assert_eq!(round_trip, migrated);
        let encoded: serde_json::Value = serde_json::from_slice(&persisted).unwrap();
        assert_eq!(encoded["format_version"], TRUST_FORMAT_VERSION);
        assert_eq!(encoded["peers"][0]["grant_epoch"], 1);
        assert_eq!(encoded["peers"][0]["display_name"], MIGRATED_DISPLAY_NAME);
    }
}
