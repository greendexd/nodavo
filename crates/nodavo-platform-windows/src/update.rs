//! Fail-closed Windows update policy, package inspection, and private staging.
//!
//! This module deliberately does not register, activate, launch, or remove a
//! package. Package deployment remains a separate, explicitly supervised trust
//! boundary. The staging backend protects its directory and files at creation,
//! retains a deny-delete handle chain to the root, and rejects reparse points.
//! Windows exposes write-through namespace mutations but no generally supported
//! directory `fsync`; callers can inspect [`WindowsDirectoryDurability`] rather
//! than assuming Unix directory durability.

use std::fmt;

#[cfg(target_os = "windows")]
use nodavo_update::{ArtifactId, ArtifactStaging, ExternalEffectError, StagedArtifactState};
use thiserror::Error;

const MAX_PACKAGE_NAME_BYTES: usize = 50;
const MAX_PUBLISHER_BYTES: usize = 8 * 1024;
const MAX_PACKAGE_FAMILY_NAME_BYTES: usize = 64;
const MAX_APPLICATION_ID_BYTES: usize = 64;
const MAX_AUMID_BYTES: usize = 130;
const MAX_PACKAGE_FULL_NAME_BYTES: usize = 255;
#[cfg(target_os = "windows")]
const MAX_BUNDLE_PACKAGES: usize = 4;

#[cfg(target_os = "windows")]
const STAGING_LEASE_NAME: &str = ".coordinator.lock";
#[cfg(any(target_os = "windows", test))]
const MAX_STAGE_ENTRIES: usize = 6;
#[cfg(target_os = "windows")]
const MAX_RETAINED_SEALED: usize = 2;
#[cfg(any(target_os = "windows", test))]
const MAX_STAGE_TOTAL_BYTES: u64 = nodavo_update::MAX_ARTIFACT_BYTES * 2;

#[cfg(any(target_os = "windows", test))]
fn append_fits_staging_quota(
    entry_count: usize,
    used_bytes: u64,
    appended_bytes: u64,
    creates_entry: bool,
) -> bool {
    entry_count
        .checked_add(usize::from(creates_entry))
        .is_some_and(|count| count <= MAX_STAGE_ENTRIES)
        && used_bytes
            .checked_add(appended_bytes)
            .is_some_and(|total| total <= MAX_STAGE_TOTAL_BYTES)
}

/// Exact four-component version used by an MSIX package identity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WindowsPackageVersion {
    major: u16,
    minor: u16,
    build: u16,
    revision: u16,
}

impl WindowsPackageVersion {
    #[must_use]
    pub const fn new(major: u16, minor: u16, build: u16, revision: u16) -> Self {
        Self {
            major,
            minor,
            build,
            revision,
        }
    }

    /// Decodes the `PACKAGE_VERSION` integer returned by official Appx APIs.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub const fn from_package_u64(value: u64) -> Self {
        Self {
            major: (value >> 48) as u16,
            minor: (value >> 32) as u16,
            build: (value >> 16) as u16,
            revision: value as u16,
        }
    }

    #[must_use]
    pub const fn components(self) -> [u16; 4] {
        [self.major, self.minor, self.build, self.revision]
    }
}

impl fmt::Display for WindowsPackageVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}.{}.{}.{}",
            self.major, self.minor, self.build, self.revision
        )
    }
}

/// Distribution authority selected at build time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsDistribution {
    /// A vendor-signed package handled by the Nodavo direct-update channel.
    DirectSigned,
    /// A package whose deployment and rollback authority remains Microsoft Store.
    MicrosoftStore,
}

/// Architectures accepted by the current x64/ARM64 bundle contract.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum WindowsPackageArchitecture {
    X64,
    Arm64,
}

/// Explicitly reported durability available from the Windows staging adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsDirectoryDurability {
    /// File bytes are flushed and namespace replacement uses
    /// `MOVEFILE_WRITE_THROUGH`. Windows has no portable directory `fsync`.
    FileAndWriteThroughNamespace,
}

/// Coarse package/update rejection without paths or native error text.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum WindowsUpdateError {
    #[error("the Windows package identity policy is invalid")]
    InvalidPolicy,
    #[error("the Windows package bundle was rejected")]
    PackageRejected,
    #[error("private Windows update staging is unavailable")]
    StagingUnavailable,
}

/// One application payload observed through the official Appx packaging APIs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InspectedWindowsPackage {
    package_full_name: String,
    architecture: WindowsPackageArchitecture,
    resource_id: String,
    application_user_model_id: String,
}

impl InspectedWindowsPackage {
    #[must_use]
    pub fn package_full_name(&self) -> &str {
        &self.package_full_name
    }

    #[must_use]
    pub const fn architecture(&self) -> WindowsPackageArchitecture {
        self.architecture
    }

    #[must_use]
    pub fn resource_id(&self) -> &str {
        &self.resource_id
    }

    #[must_use]
    pub fn application_user_model_id(&self) -> &str {
        &self.application_user_model_id
    }
}

/// Bounded identity evidence read from an `MSIXBundle` without deployment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InspectedWindowsBundle {
    package_name: String,
    publisher: String,
    package_family_name: String,
    version: WindowsPackageVersion,
    packages: Vec<InspectedWindowsPackage>,
}

impl InspectedWindowsBundle {
    #[must_use]
    pub fn package_name(&self) -> &str {
        &self.package_name
    }

    #[must_use]
    pub fn publisher(&self) -> &str {
        &self.publisher
    }

    #[must_use]
    pub fn package_family_name(&self) -> &str {
        &self.package_family_name
    }

    #[must_use]
    pub const fn version(&self) -> WindowsPackageVersion {
        self.version
    }

    #[must_use]
    pub fn packages(&self) -> &[InspectedWindowsPackage] {
        &self.packages
    }
}

/// Exact package identity policy independent of package deployment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsPackageIdentityPolicy {
    distribution: WindowsDistribution,
    package_name: String,
    publisher: String,
    package_family_name: String,
    application_id: String,
    application_user_model_id: String,
    version: WindowsPackageVersion,
    direct_signer_certificate_sha256: Option<[u8; 32]>,
}

impl WindowsPackageIdentityPolicy {
    /// Creates a policy for the exact two-architecture Nodavo package bundle.
    ///
    /// Direct distribution requires a nonzero pinned signer certificate digest.
    /// Store distribution forbids that field because Store remains the package
    /// deployment authority; it must not silently enter the direct-update path.
    ///
    /// # Errors
    ///
    /// Rejects malformed or unbounded identifiers, inconsistent AUMIDs, and a
    /// signer-pin policy that does not match the selected distribution.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        distribution: WindowsDistribution,
        package_name: impl Into<String>,
        publisher: impl Into<String>,
        package_family_name: impl Into<String>,
        application_id: impl Into<String>,
        application_user_model_id: impl Into<String>,
        version: WindowsPackageVersion,
        direct_signer_certificate_sha256: Option<[u8; 32]>,
    ) -> Result<Self, WindowsUpdateError> {
        let policy = Self {
            distribution,
            package_name: package_name.into(),
            publisher: publisher.into(),
            package_family_name: package_family_name.into(),
            application_id: application_id.into(),
            application_user_model_id: application_user_model_id.into(),
            version,
            direct_signer_certificate_sha256,
        };
        policy.validate()?;
        Ok(policy)
    }

    #[must_use]
    pub const fn distribution(&self) -> WindowsDistribution {
        self.distribution
    }

    #[must_use]
    pub const fn version(&self) -> WindowsPackageVersion {
        self.version
    }

    #[must_use]
    pub fn direct_signer_certificate_sha256(&self) -> Option<&[u8; 32]> {
        self.direct_signer_certificate_sha256.as_ref()
    }

    /// Requires the exact identity, version, AUMID, empty resource IDs, and one
    /// x64 plus one ARM64 application payload.
    ///
    /// This is only manifest-identity authorization. Direct distribution must
    /// separately verify package trust and the pinned signer certificate before
    /// any deployment effect; a `true` result is never signature evidence.
    #[must_use]
    pub fn authorizes(&self, bundle: &InspectedWindowsBundle) -> bool {
        if self.validate().is_err()
            || bundle.package_name != self.package_name
            || bundle.publisher != self.publisher
            || bundle.package_family_name != self.package_family_name
            || bundle.version != self.version
            || bundle.packages.len() != 2
        {
            return false;
        }
        let mut architectures = bundle
            .packages
            .iter()
            .map(InspectedWindowsPackage::architecture)
            .collect::<Vec<_>>();
        architectures.sort_unstable();
        architectures.dedup();
        architectures
            == [
                WindowsPackageArchitecture::X64,
                WindowsPackageArchitecture::Arm64,
            ]
            && bundle.packages.iter().all(|package| {
                package.resource_id.is_empty()
                    && package.application_user_model_id == self.application_user_model_id
                    && valid_bounded_text(&package.package_full_name, MAX_PACKAGE_FULL_NAME_BYTES)
            })
    }

    fn validate(&self) -> Result<(), WindowsUpdateError> {
        if !valid_package_name(&self.package_name)
            || !valid_bounded_text(&self.publisher, MAX_PUBLISHER_BYTES)
            || !self.publisher.starts_with("CN=")
            || !valid_package_family_name(&self.package_family_name)
            || !valid_token(&self.application_id, MAX_APPLICATION_ID_BYTES)
            || !valid_bounded_text(&self.application_user_model_id, MAX_AUMID_BYTES)
            || self.application_user_model_id
                != format!("{}!{}", self.package_family_name, self.application_id)
        {
            return Err(WindowsUpdateError::InvalidPolicy);
        }
        match (self.distribution, self.direct_signer_certificate_sha256) {
            (WindowsDistribution::DirectSigned, Some(digest)) if digest != [0; 32] => Ok(()),
            (WindowsDistribution::MicrosoftStore, None) => Ok(()),
            _ => Err(WindowsUpdateError::InvalidPolicy),
        }
    }
}

fn valid_package_name(value: &str) -> bool {
    value.len() >= 3
        && value.len() <= MAX_PACKAGE_NAME_BYTES
        && !value.ends_with('.')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
}

fn valid_package_family_name(value: &str) -> bool {
    value.len() >= 3
        && value.len() <= MAX_PACKAGE_FAMILY_NAME_BYTES
        && value.bytes().filter(|byte| *byte == b'_').count() == 1
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

fn valid_token(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

fn valid_bounded_text(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && !value.chars().any(char::is_control)
}

#[cfg(target_os = "windows")]
mod windows_backend {
    use std::collections::HashSet;
    use std::ffi::OsString;
    use std::fs::{self, File};
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::windows::fs::MetadataExt as _;
    use std::path::{Component, Path, PathBuf, Prefix};
    use std::time::SystemTime;

    use super::{
        ArtifactId, ArtifactStaging, ExternalEffectError, InspectedWindowsBundle,
        InspectedWindowsPackage, MAX_APPLICATION_ID_BYTES, MAX_AUMID_BYTES, MAX_BUNDLE_PACKAGES,
        MAX_PACKAGE_FULL_NAME_BYTES, MAX_PUBLISHER_BYTES, MAX_RETAINED_SEALED, MAX_STAGE_ENTRIES,
        MAX_STAGE_TOTAL_BYTES, STAGING_LEASE_NAME, StagedArtifactState, WindowsDirectoryDurability,
        WindowsPackageArchitecture, WindowsPackageVersion, WindowsUpdateError,
        append_fits_staging_quota, fmt, valid_bounded_text, valid_package_family_name,
        valid_package_name,
    };
    use crate::windows::ffi;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

    /// Private, current-user, content-addressed Windows artifact staging.
    ///
    /// This is not an anti-rollback journal store. The protected DACL, retained
    /// fixed-volume deny-delete handle chain, and lease reject accidental
    /// sharing and ordinary namespace substitution, but Windows grants the
    /// owning user authority to delete or replay its own files. Consequently
    /// this type intentionally implements
    /// only [`ArtifactStaging`], never `RecoveryJournalStore` or
    /// `RollbackStateStore`, whose stronger same-user mutation contract would
    /// require a separately isolated principal or OS monotonic facility.
    pub struct WindowsArtifactStaging {
        root: PathBuf,
        root_handle: File,
        _namespace_handles: Vec<File>,
        _lease: File,
        poisoned: bool,
    }

    impl fmt::Debug for WindowsArtifactStaging {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("WindowsArtifactStaging")
                .field("durability", &self.directory_durability())
                .finish_non_exhaustive()
        }
    }

    impl WindowsArtifactStaging {
        /// Creates or opens an exact staging root. The parent must already exist;
        /// this prevents ambient recursive creation with inherited permissions.
        ///
        /// # Errors
        ///
        /// Fails closed when the root or lease cannot be created with the
        /// private policy, another process owns the lease, or retained staging
        /// state is malformed, unsafe, or over quota.
        pub fn new(root: &Path) -> Result<Self, WindowsUpdateError> {
            let RetainedStagingRoot {
                canonical_path,
                root_handle,
                namespace_handles,
            } = retain_staging_root(root).map_err(|_| WindowsUpdateError::StagingUnavailable)?;
            validate_directory(&root_handle).map_err(|_| WindowsUpdateError::StagingUnavailable)?;
            let lease_path = canonical_path.join(STAGING_LEASE_NAME);
            let lease = ffi::open_or_create_private_update_lease(&lease_path)
                .map_err(|_| WindowsUpdateError::StagingUnavailable)?;
            validate_regular(&lease, 0, None)
                .map_err(|_| WindowsUpdateError::StagingUnavailable)?;
            let mut staging = Self {
                root: canonical_path,
                root_handle,
                _namespace_handles: namespace_handles,
                _lease: lease,
                poisoned: false,
            };
            staging
                .cleanup_and_bound(None)
                .map_err(|_| WindowsUpdateError::StagingUnavailable)?;
            Ok(staging)
        }

        #[must_use]
        pub const fn directory_durability(&self) -> WindowsDirectoryDurability {
            WindowsDirectoryDurability::FileAndWriteThroughNamespace
        }

        fn require_usable(&self) -> Result<(), ExternalEffectError> {
            if self.poisoned {
                return Err(ExternalEffectError);
            }
            validate_directory(&self.root_handle)
        }

        fn partial_path(&self, artifact: ArtifactId) -> PathBuf {
            self.root.join(stage_name(artifact, StageKind::Partial))
        }

        fn sealed_path(&self, artifact: ArtifactId) -> PathBuf {
            self.root.join(stage_name(artifact, StageKind::Sealed))
        }

        fn poison<T>(&mut self) -> Result<T, ExternalEffectError> {
            self.poisoned = true;
            Err(ExternalEffectError)
        }

        fn inspect_path(
            path: &Path,
            artifact: ArtifactId,
            kind: StageKind,
        ) -> Result<Option<u64>, ExternalEffectError> {
            match ffi::open_existing_update_file(path, false) {
                Ok(file) => {
                    let length = file.metadata().map_err(|_| ExternalEffectError)?.len();
                    validate_stage_file(&file, length, ParsedStageName { artifact, kind })?;
                    Ok(Some(length))
                }
                Err(error) if error.is_not_found() => Ok(None),
                Err(_) => Err(ExternalEffectError),
            }
        }

        fn cleanup_and_bound(&mut self, retain: Option<&Path>) -> Result<(), ExternalEffectError> {
            self.require_usable()?;
            let mut entries = Vec::new();
            let mut artifacts = HashSet::new();
            for entry in fs::read_dir(&self.root).map_err(|_| ExternalEffectError)? {
                let entry = entry.map_err(|_| ExternalEffectError)?;
                let name = entry.file_name().to_string_lossy().into_owned();
                if name == STAGING_LEASE_NAME {
                    continue;
                }
                if parse_reset_name(&name) {
                    let path = entry.path();
                    let file = ffi::open_existing_update_file(&path, false)
                        .map_err(|_| ExternalEffectError)?;
                    let metadata = file.metadata().map_err(|_| ExternalEffectError)?;
                    validate_regular(&file, metadata.len(), Some(0))?;
                    drop(file);
                    fs::remove_file(path).map_err(|_| ExternalEffectError)?;
                    continue;
                }
                let Some(stage) = parse_stage_name(&name) else {
                    return self.poison();
                };
                if !artifacts.insert(stage.artifact) {
                    return self.poison();
                }
                let path = entry.path();
                let file = ffi::open_existing_update_file(&path, false)
                    .map_err(|_| ExternalEffectError)?;
                let metadata = file.metadata().map_err(|_| ExternalEffectError)?;
                validate_stage_file(&file, metadata.len(), stage)?;
                entries.push(StageEntry {
                    path,
                    kind: stage.kind,
                    length: metadata.len(),
                    modified: metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
                });
            }

            let total = entries.iter().try_fold(0_u64, |sum, entry| {
                sum.checked_add(entry.length).ok_or(ExternalEffectError)
            })?;
            if entries.len() > MAX_STAGE_ENTRIES || total > MAX_STAGE_TOTAL_BYTES {
                entries.sort_by_key(|entry| entry.modified);
                for entry in entries.iter().filter(|entry| {
                    entry.kind == StageKind::Partial
                        && retain.is_none_or(|retain| entry.path != retain)
                }) {
                    fs::remove_file(&entry.path).map_err(|_| ExternalEffectError)?;
                }
            }

            let mut sealed = entries
                .iter()
                .filter(|entry| entry.kind == StageKind::Sealed)
                .collect::<Vec<_>>();
            sealed.sort_by_key(|entry| entry.modified);
            let removable = sealed.len().saturating_sub(MAX_RETAINED_SEALED);
            for entry in sealed
                .into_iter()
                .filter(|entry| retain.is_none_or(|retain| entry.path != retain))
                .take(removable)
            {
                fs::remove_file(&entry.path).map_err(|_| ExternalEffectError)?;
            }

            let (count, bounded_total) = scan_usage(&self.root)?;
            if count > MAX_STAGE_ENTRIES || bounded_total > MAX_STAGE_TOTAL_BYTES {
                return self.poison();
            }
            Ok(())
        }
    }

    impl ArtifactStaging for WindowsArtifactStaging {
        fn inspect(
            &mut self,
            artifact: ArtifactId,
        ) -> Result<StagedArtifactState, ExternalEffectError> {
            self.require_usable()?;
            match (
                Self::inspect_path(&self.partial_path(artifact), artifact, StageKind::Partial)?,
                Self::inspect_path(&self.sealed_path(artifact), artifact, StageKind::Sealed)?,
            ) {
                (None, None) => Ok(StagedArtifactState::Missing),
                (Some(length), None) => Ok(StagedArtifactState::Partial(length)),
                (None, Some(length)) => Ok(StagedArtifactState::Sealed(length)),
                (Some(_), Some(_)) => self.poison(),
            }
        }

        fn read_at(
            &mut self,
            artifact: ArtifactId,
            offset: u64,
            buffer: &mut [u8],
        ) -> Result<usize, ExternalEffectError> {
            self.require_usable()?;
            let (path, kind) = match (
                Self::inspect_path(&self.partial_path(artifact), artifact, StageKind::Partial)?,
                Self::inspect_path(&self.sealed_path(artifact), artifact, StageKind::Sealed)?,
            ) {
                (Some(_), None) => (self.partial_path(artifact), StageKind::Partial),
                (None, Some(_)) => (self.sealed_path(artifact), StageKind::Sealed),
                _ => return self.poison(),
            };
            let mut file =
                ffi::open_existing_update_file(&path, false).map_err(|_| ExternalEffectError)?;
            let length = file.metadata().map_err(|_| ExternalEffectError)?.len();
            validate_stage_file(&file, length, ParsedStageName { artifact, kind })?;
            if offset > length {
                return self.poison();
            }
            file.seek(SeekFrom::Start(offset))
                .map_err(|_| ExternalEffectError)?;
            file.read(buffer).map_err(|_| ExternalEffectError)
        }

        fn append(
            &mut self,
            artifact: ArtifactId,
            expected_offset: u64,
            bytes: &[u8],
        ) -> Result<(), ExternalEffectError> {
            self.require_usable()?;
            if bytes.is_empty()
                || Self::inspect_path(&self.sealed_path(artifact), artifact, StageKind::Sealed)?
                    .is_some()
                || expected_offset
                    .checked_add(u64::try_from(bytes.len()).map_err(|_| ExternalEffectError)?)
                    .is_none_or(|end| end > artifact.size())
            {
                return self.poison();
            }
            let partial = self.partial_path(artifact);
            let creates_entry = match Self::inspect_path(&partial, artifact, StageKind::Partial)? {
                Some(_) => false,
                None if expected_offset == 0 => {
                    self.cleanup_and_bound(None)?;
                    true
                }
                None => return self.poison(),
            };
            // Every scan finishes before the append handle is opened. Update
            // files deliberately deny sharing while their exact length is
            // checked and changed, so reopening the same file during a scan
            // would fail even within this process.
            let (count, used) = scan_usage(&self.root)?;
            let additional = u64::try_from(bytes.len()).map_err(|_| ExternalEffectError)?;
            if !append_fits_staging_quota(count, used, additional, creates_entry) {
                return self.poison();
            }
            let mut file = if creates_entry {
                ffi::create_private_update_file(&partial).map_err(|_| ExternalEffectError)?
            } else {
                ffi::open_existing_update_file(&partial, true).map_err(|_| ExternalEffectError)?
            };
            let metadata = file.metadata().map_err(|_| ExternalEffectError)?;
            validate_regular(&file, metadata.len(), Some(artifact.size()))?;
            if metadata.len() != expected_offset {
                return self.poison();
            }
            file.seek(SeekFrom::End(0))
                .map_err(|_| ExternalEffectError)?;
            file.write_all(bytes).map_err(|_| ExternalEffectError)?;
            file.sync_all().map_err(|_| ExternalEffectError)
        }

        fn reset(&mut self, artifact: ArtifactId) -> Result<(), ExternalEffectError> {
            self.require_usable()?;
            if Self::inspect_path(&self.sealed_path(artifact), artifact, StageKind::Sealed)?
                .is_some()
            {
                return self.poison();
            }
            let partial = self.partial_path(artifact);
            if Self::inspect_path(&partial, artifact, StageKind::Partial)?.is_none() {
                self.cleanup_and_bound(None)?;
                let (count, used) = scan_usage(&self.root)?;
                if !append_fits_staging_quota(count, used, 0, true) {
                    return self.poison();
                }
            }
            let temporary = self.root.join(format!(
                ".reset-{}-{}.tmp",
                stage_digest_hex(artifact),
                artifact.size()
            ));
            match ffi::open_existing_update_file(&temporary, false) {
                Ok(file) => {
                    validate_regular(&file, 0, Some(0))?;
                    drop(file);
                    fs::remove_file(&temporary).map_err(|_| ExternalEffectError)?;
                }
                Err(error) if error.is_not_found() => {}
                Err(_) => return self.poison(),
            }
            let temporary_file =
                ffi::create_private_update_file(&temporary).map_err(|_| ExternalEffectError)?;
            let temporary_length = temporary_file
                .metadata()
                .map_err(|_| ExternalEffectError)?
                .len();
            validate_regular(&temporary_file, temporary_length, Some(0))?;
            temporary_file.sync_all().map_err(|_| ExternalEffectError)?;
            drop(temporary_file);
            if ffi::move_update_file_write_through(&temporary, &partial, true).is_err() {
                let _ = fs::remove_file(&temporary);
                return self.poison();
            }
            Ok(())
        }

        fn seal(&mut self, artifact: ArtifactId) -> Result<(), ExternalEffectError> {
            self.require_usable()?;
            let partial = self.partial_path(artifact);
            let sealed = self.sealed_path(artifact);
            if Self::inspect_path(&sealed, artifact, StageKind::Sealed)?.is_some() {
                return self.poison();
            }
            // FlushFileBuffers, used by File::sync_all on Windows, requires a
            // handle opened for writing even though sealing writes no bytes.
            let file =
                ffi::open_existing_update_file(&partial, true).map_err(|_| ExternalEffectError)?;
            let length = file.metadata().map_err(|_| ExternalEffectError)?.len();
            validate_regular(&file, length, Some(artifact.size()))?;
            if length != artifact.size() {
                return self.poison();
            }
            file.sync_all().map_err(|_| ExternalEffectError)?;
            drop(file);
            ffi::move_update_file_write_through(&partial, &sealed, false)
                .map_err(|_| ExternalEffectError)?;
            self.cleanup_and_bound(Some(&sealed))
        }

        fn discard(&mut self, artifact: ArtifactId) -> Result<(), ExternalEffectError> {
            self.require_usable()?;
            for (path, kind) in [
                (self.partial_path(artifact), StageKind::Partial),
                (self.sealed_path(artifact), StageKind::Sealed),
            ] {
                if Self::inspect_path(&path, artifact, kind)?.is_some() {
                    fs::remove_file(path).map_err(|_| ExternalEffectError)?;
                }
            }
            Ok(())
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum StageKind {
        Partial,
        Sealed,
    }

    struct StageEntry {
        path: PathBuf,
        kind: StageKind,
        length: u64,
        modified: SystemTime,
    }

    struct RetainedStagingRoot {
        canonical_path: PathBuf,
        root_handle: File,
        namespace_handles: Vec<File>,
    }

    fn retain_staging_root(root: &Path) -> Result<RetainedStagingRoot, ExternalEffectError> {
        let (drive_root, components) = local_drive_path(root).ok_or(ExternalEffectError)?;
        if components.is_empty() {
            return Err(ExternalEffectError);
        }
        let drive_handle =
            ffi::open_retained_update_directory(&drive_root).map_err(|_| ExternalEffectError)?;
        validate_namespace_directory(&drive_handle)?;
        let volume_root =
            ffi::canonical_fixed_volume_root(&drive_handle).map_err(|_| ExternalEffectError)?;
        if volume_root.components().any(|component| {
            matches!(
                component,
                Component::Normal(_) | Component::ParentDir | Component::CurDir
            )
        }) {
            // A drive alias rooted in a subdirectory (for example SUBST) is not
            // a stable volume root and must not seed the saved namespace.
            return Err(ExternalEffectError);
        }

        let mut namespace_handles = vec![drive_handle];
        let mut lookup_path = volume_root.clone();
        for (index, component) in components.iter().enumerate() {
            lookup_path.push(component);
            let final_component = index + 1 == components.len();
            let handle = match ffi::open_retained_update_directory(&lookup_path) {
                Ok(handle) => handle,
                Err(_) if final_component => {
                    ffi::create_private_update_directory(&lookup_path)
                        .map_err(|_| ExternalEffectError)?;
                    ffi::open_retained_update_directory(&lookup_path)
                        .map_err(|_| ExternalEffectError)?
                }
                Err(_) => return Err(ExternalEffectError),
            };
            validate_namespace_directory(&handle)?;
            namespace_handles.push(handle);
        }
        let root_handle = namespace_handles.pop().ok_or(ExternalEffectError)?;
        let canonical_path =
            ffi::canonical_volume_path(&root_handle).map_err(|_| ExternalEffectError)?;
        if !canonical_path.starts_with(&volume_root) {
            return Err(ExternalEffectError);
        }
        Ok(RetainedStagingRoot {
            canonical_path,
            root_handle,
            namespace_handles,
        })
    }

    fn open_bound_private_file(path: &Path) -> Result<File, ExternalEffectError> {
        let (drive_root, mut components) = local_drive_path(path).ok_or(ExternalEffectError)?;
        let file_name = components.pop().ok_or(ExternalEffectError)?;
        let drive_handle =
            ffi::open_retained_update_directory(&drive_root).map_err(|_| ExternalEffectError)?;
        validate_namespace_directory(&drive_handle)?;
        let mut canonical =
            ffi::canonical_fixed_volume_root(&drive_handle).map_err(|_| ExternalEffectError)?;
        if canonical.components().any(|component| {
            matches!(
                component,
                Component::Normal(_) | Component::ParentDir | Component::CurDir
            )
        }) {
            return Err(ExternalEffectError);
        }

        let mut namespace_handles = vec![drive_handle];
        for component in components {
            canonical.push(component);
            let handle =
                ffi::open_retained_update_directory(&canonical).map_err(|_| ExternalEffectError)?;
            validate_namespace_directory(&handle)?;
            namespace_handles.push(handle);
        }
        canonical.push(file_name);
        // The retained directory chain stays alive until after the final file
        // has been opened by handle, closing every intermediate pivot window.
        let file = ffi::open_update_bundle_guard(&canonical).map_err(|_| ExternalEffectError)?;
        drop(namespace_handles);
        Ok(file)
    }

    fn local_drive_path(path: &Path) -> Option<(PathBuf, Vec<OsString>)> {
        let mut components = path.components();
        let Component::Prefix(prefix) = components.next()? else {
            return None;
        };
        let drive_root = match prefix.kind() {
            Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) => {
                let drive = char::from(drive).to_ascii_uppercase();
                PathBuf::from(format!(r"{drive}:\"))
            }
            Prefix::Verbatim(volume) if valid_volume_guid_prefix(volume) => {
                PathBuf::from(format!(r"\\?\{}\", volume.to_string_lossy()))
            }
            _ => return None,
        };
        if components.next()? != Component::RootDir {
            return None;
        }
        let mut normal = Vec::new();
        for component in components {
            let Component::Normal(component) = component else {
                return None;
            };
            if !valid_namespace_component(component) {
                return None;
            }
            normal.push(component.to_os_string());
        }
        Some((drive_root, normal))
    }

    fn valid_namespace_component(value: &std::ffi::OsStr) -> bool {
        let Some(value) = value.to_str() else {
            return false;
        };
        if value.is_empty()
            || value == "."
            || value == ".."
            || value.ends_with('.')
            || value.ends_with(' ')
            || value.chars().any(|character| {
                character.is_control()
                    || matches!(
                        character,
                        '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*'
                    )
            })
        {
            return false;
        }
        let base = value
            .split('.')
            .next()
            .unwrap_or_default()
            .to_ascii_uppercase();
        !matches!(base.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$")
            && !(base.len() == 4
                && (base.starts_with("COM") || base.starts_with("LPT"))
                && matches!(base.as_bytes()[3], b'1'..=b'9'))
    }

    fn valid_volume_guid_prefix(value: &std::ffi::OsStr) -> bool {
        let Some(value) = value.to_str() else {
            return false;
        };
        let Some(guid) = value
            .strip_prefix("Volume{")
            .and_then(|value| value.strip_suffix('}'))
        else {
            return false;
        };
        guid.len() == 36
            && guid.bytes().enumerate().all(|(index, byte)| {
                if matches!(index, 8 | 13 | 18 | 23) {
                    byte == b'-'
                } else {
                    byte.is_ascii_hexdigit()
                }
            })
    }

    fn validate_directory(file: &File) -> Result<(), ExternalEffectError> {
        ffi::validate_private_update_handle(file).map_err(|_| ExternalEffectError)?;
        validate_namespace_directory(file)
    }

    fn validate_namespace_directory(file: &File) -> Result<(), ExternalEffectError> {
        let metadata = file.metadata().map_err(|_| ExternalEffectError)?;
        if !metadata.file_type().is_dir()
            || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            Err(ExternalEffectError)
        } else {
            Ok(())
        }
    }

    fn validate_regular(
        file: &File,
        length: u64,
        maximum: Option<u64>,
    ) -> Result<(), ExternalEffectError> {
        ffi::validate_private_update_handle(file).map_err(|_| ExternalEffectError)?;
        let metadata = file.metadata().map_err(|_| ExternalEffectError)?;
        if !metadata.file_type().is_file()
            || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || metadata.len() != length
            || maximum.is_some_and(|maximum| length > maximum)
        {
            Err(ExternalEffectError)
        } else {
            Ok(())
        }
    }

    fn validate_stage_file(
        file: &File,
        length: u64,
        stage: ParsedStageName,
    ) -> Result<(), ExternalEffectError> {
        validate_regular(file, length, Some(stage.artifact.size()))?;
        if stage.kind == StageKind::Sealed && length != stage.artifact.size() {
            return Err(ExternalEffectError);
        }
        Ok(())
    }

    fn scan_usage(root: &Path) -> Result<(usize, u64), ExternalEffectError> {
        let mut count = 0_usize;
        let mut total = 0_u64;
        let mut artifacts = HashSet::new();
        for entry in fs::read_dir(root).map_err(|_| ExternalEffectError)? {
            let entry = entry.map_err(|_| ExternalEffectError)?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name == STAGING_LEASE_NAME {
                continue;
            }
            let stage = parse_stage_name(&name).ok_or(ExternalEffectError)?;
            if !artifacts.insert(stage.artifact) {
                return Err(ExternalEffectError);
            }
            let file = ffi::open_existing_update_file(&entry.path(), false)
                .map_err(|_| ExternalEffectError)?;
            let metadata = file.metadata().map_err(|_| ExternalEffectError)?;
            validate_stage_file(&file, metadata.len(), stage)?;
            count = count.checked_add(1).ok_or(ExternalEffectError)?;
            total = total
                .checked_add(metadata.len())
                .ok_or(ExternalEffectError)?;
        }
        Ok((count, total))
    }

    fn stage_name(artifact: ArtifactId, kind: StageKind) -> String {
        let suffix = match kind {
            StageKind::Partial => "partial",
            StageKind::Sealed => "sealed",
        };
        format!(
            "{}-{}.{}",
            stage_digest_hex(artifact),
            artifact.size(),
            suffix
        )
    }

    fn stage_digest_hex(artifact: ArtifactId) -> String {
        let mut output = String::with_capacity(64);
        for byte in artifact.sha256() {
            use fmt::Write as _;
            let _ = write!(output, "{byte:02x}");
        }
        output
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct ParsedStageName {
        artifact: ArtifactId,
        kind: StageKind,
    }

    fn parse_stage_name(name: &str) -> Option<ParsedStageName> {
        let (stem, kind) = if let Some(stem) = name.strip_suffix(".partial") {
            (stem, StageKind::Partial)
        } else {
            (name.strip_suffix(".sealed")?, StageKind::Sealed)
        };
        let (digest, size) = stem.split_once('-')?;
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return None;
        }
        let mut sha256 = [0_u8; 32];
        for (output, pair) in sha256.iter_mut().zip(digest.as_bytes().chunks_exact(2)) {
            *output = hex_nibble(pair[0])?
                .checked_mul(16)?
                .checked_add(hex_nibble(pair[1])?)?;
        }
        let parsed_size = size.parse::<u64>().ok()?;
        if parsed_size.to_string() != size {
            return None;
        }
        let artifact = ArtifactId::new(sha256, parsed_size).ok()?;
        Some(ParsedStageName { artifact, kind })
    }

    fn hex_nibble(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        }
    }

    fn parse_reset_name(name: &str) -> bool {
        let Some(stem) = name
            .strip_prefix(".reset-")
            .and_then(|name| name.strip_suffix(".tmp"))
        else {
            return false;
        };
        let Some((digest, size)) = stem.split_once('-') else {
            return false;
        };
        let Ok(parsed_size) = size.parse::<u64>() else {
            return false;
        };
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            && parsed_size.to_string() == size
            && parsed_size > 0
            && parsed_size <= nodavo_update::MAX_ARTIFACT_BYTES
    }

    /// Reads identity metadata through `IAppxBundleReader`/`IAppxPackageReader`.
    /// This is inspection only: Windows deployment must still validate package
    /// trust and signature before registration or any other deployment effect.
    ///
    /// # Errors
    ///
    /// Rejects an unreadable or malformed bundle, unsupported payloads,
    /// unbounded identity text, resource packages, or multiple applications.
    pub fn inspect_windows_package_bundle(
        path: &Path,
    ) -> Result<InspectedWindowsBundle, WindowsUpdateError> {
        let bundle =
            open_bound_private_file(path).map_err(|_| WindowsUpdateError::PackageRejected)?;
        let native =
            ffi::inspect_update_bundle(bundle).map_err(|_| WindowsUpdateError::PackageRejected)?;
        if native.packages.is_empty() || native.packages.len() > MAX_BUNDLE_PACKAGES {
            return Err(WindowsUpdateError::PackageRejected);
        }
        let packages = native
            .packages
            .into_iter()
            .map(|package| {
                let architecture = match package.architecture {
                    ffi::NativeUpdateArchitecture::X64 => WindowsPackageArchitecture::X64,
                    ffi::NativeUpdateArchitecture::Arm64 => WindowsPackageArchitecture::Arm64,
                };
                if !valid_bounded_text(&package.package_full_name, MAX_PACKAGE_FULL_NAME_BYTES)
                    || package.resource_id.len() > MAX_APPLICATION_ID_BYTES
                    || !valid_bounded_text(&package.application_user_model_id, MAX_AUMID_BYTES)
                {
                    return Err(WindowsUpdateError::PackageRejected);
                }
                Ok(InspectedWindowsPackage {
                    package_full_name: package.package_full_name,
                    architecture,
                    resource_id: package.resource_id,
                    application_user_model_id: package.application_user_model_id,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let bundle = InspectedWindowsBundle {
            package_name: native.package_name,
            publisher: native.publisher,
            package_family_name: native.package_family_name,
            version: WindowsPackageVersion::from_package_u64(native.version),
            packages,
        };
        if !valid_package_name(&bundle.package_name)
            || !valid_bounded_text(&bundle.publisher, MAX_PUBLISHER_BYTES)
            || !valid_package_family_name(&bundle.package_family_name)
        {
            return Err(WindowsUpdateError::PackageRejected);
        }
        Ok(bundle)
    }

    #[cfg(test)]
    mod tests {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::time::{SystemTime, UNIX_EPOCH};

        use super::*;

        static NEXT_TEMPORARY_ROOT: AtomicU64 = AtomicU64::new(0);

        fn temporary_root() -> PathBuf {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            std::env::temp_dir().join(format!(
                "nodavo-windows-update-stage-{}-{nonce}-{}",
                std::process::id(),
                NEXT_TEMPORARY_ROOT.fetch_add(1, Ordering::Relaxed)
            ))
        }

        #[test]
        fn retained_root_handle_can_validate_security_and_enumerate() {
            let root = temporary_root();
            ffi::create_private_update_directory(&root).unwrap();
            let handle = ffi::open_retained_update_directory(&root).unwrap();
            ffi::validate_private_update_handle(&handle).unwrap();
            assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
            drop(handle);
            fs::remove_dir(root).unwrap();
        }

        #[test]
        fn staging_root_must_be_absolute_and_lexically_normal() {
            assert!(WindowsArtifactStaging::new(Path::new("relative-stage")).is_err());
            let root = temporary_root();
            let parent = root.parent().unwrap();
            let traversing = parent
                .join("unused")
                .join("..")
                .join(root.file_name().unwrap());
            assert!(WindowsArtifactStaging::new(&traversing).is_err());
            assert!(!root.exists());
        }

        #[test]
        fn retained_intermediate_handle_blocks_namespace_pivot() {
            let base = temporary_root();
            ffi::create_private_update_directory(&base).unwrap();
            let retained = ffi::open_retained_update_directory(&base).unwrap();
            validate_namespace_directory(&retained).unwrap();
            let moved = base.with_extension("moved");
            assert!(fs::rename(&base, &moved).is_err());
            drop(retained);
            fs::rename(&base, &moved).unwrap();
            fs::remove_dir_all(moved).unwrap();
        }

        #[test]
        fn append_scans_quota_before_holding_exclusive_file_handle() {
            let root = temporary_root();
            let mut staging = WindowsArtifactStaging::new(&root).unwrap();
            let artifact = ArtifactId::new([9; 32], 4).unwrap();
            staging.append(artifact, 0, b"ab").unwrap();
            staging.append(artifact, 2, b"cd").unwrap();
            assert_eq!(
                staging.inspect(artifact).unwrap(),
                StagedArtifactState::Partial(4)
            );
            drop(staging);
            fs::remove_dir_all(root).unwrap();
        }

        #[test]
        fn seal_opens_complete_partial_with_flush_capable_access() {
            let root = temporary_root();
            let mut staging = WindowsArtifactStaging::new(&root).unwrap();
            let artifact = ArtifactId::new([7; 32], 4).unwrap();
            staging.append(artifact, 0, b"data").unwrap();
            staging.seal(artifact).unwrap();
            assert_eq!(
                staging.inspect(artifact).unwrap(),
                StagedArtifactState::Sealed(4)
            );
            drop(staging);
            fs::remove_dir_all(root).unwrap();
        }

        #[test]
        fn private_staging_round_trip_and_exclusive_lease() {
            let root = temporary_root();
            let mut staging = WindowsArtifactStaging::new(&root).unwrap();
            assert!(matches!(
                staging.root.components().next(),
                Some(Component::Prefix(prefix))
                    if matches!(prefix.kind(), Prefix::Verbatim(value) if value.to_string_lossy().starts_with("Volume{"))
            ));
            assert_eq!(
                staging.directory_durability(),
                WindowsDirectoryDurability::FileAndWriteThroughNamespace
            );
            assert!(WindowsArtifactStaging::new(&root).is_err());
            assert!(WindowsArtifactStaging::new(&staging.root).is_err());

            let artifact = ArtifactId::new([5; 32], 4).unwrap();
            staging.append(artifact, 0, b"data").unwrap();
            let mut bytes = [0_u8; 4];
            assert_eq!(staging.read_at(artifact, 0, &mut bytes).unwrap(), 4);
            assert_eq!(&bytes, b"data");
            staging.seal(artifact).unwrap();
            assert_eq!(
                staging.inspect(artifact).unwrap(),
                StagedArtifactState::Sealed(4)
            );
            staging.discard(artifact).unwrap();
            assert_eq!(
                staging.inspect(artifact).unwrap(),
                StagedArtifactState::Missing
            );

            drop(staging);
            fs::remove_dir_all(root).unwrap();
        }

        #[test]
        fn stage_names_round_trip_exact_content_identity() {
            let artifact = ArtifactId::new([0xab; 32], 19).unwrap();
            let name = stage_name(artifact, StageKind::Sealed);
            assert_eq!(
                parse_stage_name(&name),
                Some(ParsedStageName {
                    artifact,
                    kind: StageKind::Sealed,
                })
            );
            assert!(parse_stage_name(&name.to_ascii_uppercase()).is_none());
            assert!(parse_stage_name(&format!("{name}.partial")).is_none());
            let digest = stage_digest_hex(artifact);
            assert!(parse_stage_name(&format!("{digest}-019.sealed")).is_none());
            assert!(parse_stage_name(&format!("{digest}-+19.sealed")).is_none());
            assert!(!parse_reset_name(&format!(".reset-{digest}-019.tmp")));
            assert!(!parse_reset_name(&format!(".reset-{digest}-+19.tmp")));
        }

        #[test]
        fn constructor_rejects_sealed_length_that_disagrees_with_name() {
            let root = temporary_root();
            let staging = WindowsArtifactStaging::new(&root).unwrap();
            drop(staging);

            let artifact = ArtifactId::new([0x31; 32], 4).unwrap();
            let path = root.join(stage_name(artifact, StageKind::Sealed));
            let mut file = ffi::create_private_update_file(&path).unwrap();
            file.write_all(b"bad").unwrap();
            file.sync_all().unwrap();
            drop(file);

            assert!(WindowsArtifactStaging::new(&root).is_err());
            fs::remove_dir_all(root).unwrap();
        }

        #[test]
        fn constructor_rejects_partial_and_sealed_aliases_for_one_artifact() {
            let root = temporary_root();
            let staging = WindowsArtifactStaging::new(&root).unwrap();
            drop(staging);

            let artifact = ArtifactId::new([0x42; 32], 1).unwrap();
            for kind in [StageKind::Partial, StageKind::Sealed] {
                let path = root.join(stage_name(artifact, kind));
                let mut file = ffi::create_private_update_file(&path).unwrap();
                file.write_all(b"x").unwrap();
                file.sync_all().unwrap();
            }

            assert!(WindowsArtifactStaging::new(&root).is_err());
            fs::remove_dir_all(root).unwrap();
        }

        #[test]
        fn bundle_inspector_api_is_read_only_and_bounded() {
            let missing = temporary_root().join("missing.msixbundle");
            assert_eq!(
                inspect_windows_package_bundle(&missing),
                Err(WindowsUpdateError::PackageRejected)
            );
            assert_eq!(
                inspect_windows_package_bundle(Path::new("relative.msixbundle")),
                Err(WindowsUpdateError::PackageRejected)
            );
        }

        #[test]
        fn namespace_planner_rejects_unc_and_noncanonical_aliases() {
            assert!(local_drive_path(Path::new(r"\\server\share\stage")).is_none());
            assert!(local_drive_path(Path::new(r"C:\safe\..\stage")).is_none());
            assert!(local_drive_path(Path::new(r"C:relative\stage")).is_none());
            assert!(local_drive_path(Path::new(r"C:\safe\stage.")).is_none());
            assert!(local_drive_path(Path::new(r"C:\safe\stage:stream")).is_none());
            assert!(local_drive_path(Path::new(r"C:\safe\CON")).is_none());
            let (root, components) = local_drive_path(Path::new(r"c:\safe\stage")).unwrap();
            assert_eq!(root, Path::new(r"C:\"));
            assert_eq!(
                components,
                [OsString::from("safe"), OsString::from("stage")]
            );
            let (volume, components) = local_drive_path(Path::new(
                r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\safe\stage",
            ))
            .unwrap();
            assert_eq!(
                volume,
                Path::new(r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\")
            );
            assert_eq!(
                components,
                [OsString::from("safe"), OsString::from("stage")]
            );
        }
    }
}

#[cfg(target_os = "windows")]
pub use windows_backend::{WindowsArtifactStaging, inspect_windows_package_bundle};

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(distribution: WindowsDistribution) -> WindowsPackageIdentityPolicy {
        WindowsPackageIdentityPolicy::new(
            distribution,
            "dev.nodavo.Nodavo",
            "CN=Nodavo Release Publisher",
            "dev.nodavo.Nodavo_ab12cd34ef56g",
            "App",
            "dev.nodavo.Nodavo_ab12cd34ef56g!App",
            WindowsPackageVersion::new(1, 2, 3, 4),
            (distribution == WindowsDistribution::DirectSigned).then_some([7; 32]),
        )
        .unwrap()
    }

    fn package(
        architecture: WindowsPackageArchitecture,
        resource_id: &str,
    ) -> InspectedWindowsPackage {
        InspectedWindowsPackage {
            package_full_name: format!(
                "dev.nodavo.Nodavo_1.2.3.4_{}_{}__ab12cd34ef56g",
                match architecture {
                    WindowsPackageArchitecture::X64 => "x64",
                    WindowsPackageArchitecture::Arm64 => "arm64",
                },
                resource_id
            ),
            architecture,
            resource_id: resource_id.to_owned(),
            application_user_model_id: "dev.nodavo.Nodavo_ab12cd34ef56g!App".to_owned(),
        }
    }

    #[test]
    fn append_quota_plan_counts_new_entries_and_rejects_overflow() {
        assert!(append_fits_staging_quota(0, 0, 1, true));
        assert!(append_fits_staging_quota(
            MAX_STAGE_ENTRIES,
            MAX_STAGE_TOTAL_BYTES - 1,
            1,
            false
        ));
        assert!(!append_fits_staging_quota(MAX_STAGE_ENTRIES, 0, 1, true));
        assert!(!append_fits_staging_quota(
            0,
            MAX_STAGE_TOTAL_BYTES,
            1,
            true
        ));
        assert!(!append_fits_staging_quota(usize::MAX, 0, 1, true));
        assert!(!append_fits_staging_quota(0, u64::MAX, 1, false));
    }

    fn bundle() -> InspectedWindowsBundle {
        InspectedWindowsBundle {
            package_name: "dev.nodavo.Nodavo".to_owned(),
            publisher: "CN=Nodavo Release Publisher".to_owned(),
            package_family_name: "dev.nodavo.Nodavo_ab12cd34ef56g".to_owned(),
            version: WindowsPackageVersion::new(1, 2, 3, 4),
            packages: vec![
                package(WindowsPackageArchitecture::X64, ""),
                package(WindowsPackageArchitecture::Arm64, ""),
            ],
        }
    }

    #[test]
    fn package_version_uses_all_four_windows_components() {
        let encoded = (1_u64 << 48) | (2_u64 << 32) | (3_u64 << 16) | 4;
        let version = WindowsPackageVersion::from_package_u64(encoded);
        assert_eq!(version.components(), [1, 2, 3, 4]);
        assert_eq!(version.to_string(), "1.2.3.4");
        assert!(version > WindowsPackageVersion::new(1, 2, 3, 3));
    }

    #[test]
    fn direct_and_store_policies_are_distinct_and_fail_closed() {
        assert_eq!(
            policy(WindowsDistribution::DirectSigned).distribution(),
            WindowsDistribution::DirectSigned
        );
        assert_eq!(
            policy(WindowsDistribution::MicrosoftStore).distribution(),
            WindowsDistribution::MicrosoftStore
        );
        assert!(
            WindowsPackageIdentityPolicy::new(
                WindowsDistribution::DirectSigned,
                "dev.nodavo.Nodavo",
                "CN=Nodavo Release Publisher",
                "dev.nodavo.Nodavo_ab12cd34ef56g",
                "App",
                "dev.nodavo.Nodavo_ab12cd34ef56g!App",
                WindowsPackageVersion::new(1, 2, 3, 4),
                None,
            )
            .is_err()
        );
    }

    #[test]
    fn identity_policy_requires_exact_two_architecture_bundle() {
        let policy = policy(WindowsDistribution::DirectSigned);
        assert!(policy.authorizes(&bundle()));

        let mut wrong = bundle();
        wrong.version = WindowsPackageVersion::new(1, 2, 3, 5);
        assert!(!policy.authorizes(&wrong));

        let mut duplicate = bundle();
        duplicate.packages[1].architecture = WindowsPackageArchitecture::X64;
        assert!(!policy.authorizes(&duplicate));

        let mut resource = bundle();
        resource.packages[0].resource_id = "language".to_owned();
        assert!(!policy.authorizes(&resource));
    }

    #[test]
    fn malformed_identity_policy_is_rejected() {
        assert!(
            WindowsPackageIdentityPolicy::new(
                WindowsDistribution::MicrosoftStore,
                "bad_name",
                "publisher",
                "bad-family",
                "App!",
                "mismatch!App",
                WindowsPackageVersion::new(1, 0, 0, 0),
                None,
            )
            .is_err()
        );
    }
}
