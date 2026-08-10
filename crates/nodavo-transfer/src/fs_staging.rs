//! Filesystem-backed private staging with content verification and no-overwrite finalization.

#[cfg(windows)]
#[path = "fs_staging_windows.rs"]
mod windows_acl;

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
#[cfg(any(unix, test))]
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
#[cfg(test)]
use std::path::PathBuf;
use std::path::{Component, Path};

use cap_fs_ext::{DirExt as _, FollowSymlinks, MetadataExt as _, OpenOptionsFollowExt as _};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, File, Metadata, OpenOptions};

use crate::{
    ContentHash, EntryKind, ResumableStagingArea, ResumeState, StagingArea, TransferChunk,
    TransferError, TransferFuture, TransferId, TransferManifest,
};

const STAGING_DIRECTORY_NAME: &str = ".nodavo-staging";
const HASH_BUFFER_BYTES: usize = 256 * 1024;
const PROGRESS_MAGIC: &[u8; 8] = b"NODAVO\0\x01";
const PROGRESS_HEADER_BYTES: usize = 8 + 32 + 4;
const PROGRESS_RECORD_BYTES: usize = 4 + 8 + 8;
const MAX_PROGRESS_RECORDS: usize = 1_000_000;
const MAX_PROGRESS_BYTES: u64 =
    (PROGRESS_HEADER_BYTES + PROGRESS_RECORD_BYTES * MAX_PROGRESS_RECORDS) as u64;
const MANIFEST_HASH_DOMAIN: &[u8] = b"Nodavo transfer manifest v1\0";
const PROGRESS_RECORD_DOMAIN: &[u8] = b"Nodavo transfer progress v1\0";
const OPERATION_LEASE_NAME: &str = ".operation.lease";

/// A single-transfer filesystem staging area rooted inside the destination filesystem.
///
/// Placing the private staging directory below the destination keeps final hard links
/// on one filesystem. Each destination file is created with no-overwrite semantics;
/// received content is never executed or opened automatically.
pub struct FileSystemStagingArea {
    destination: Dir,
    staging: Dir,
    active: Option<ActiveTransfer>,
    cleanup_failed: bool,
}

struct ActiveTransfer {
    id: TransferId,
    _lease: TransferLease,
    directory: Dir,
    progress_name: OsString,
    progress: File,
    progress_records: usize,
    manifest: TransferManifest,
    written: HashMap<usize, u64>,
}

struct TransferLease {
    _file: std::fs::File,
}

impl FileSystemStagingArea {
    /// Whether directory-entry publication is known to survive immediate
    /// power loss after a successful finalization acknowledgement.
    ///
    /// File contents and progress records are flushed on every platform.
    /// Windows has no supported directory-entry flush primitive in the
    /// filesystem APIs used here, so strict callers must fail closed there.
    #[must_use]
    pub const fn directory_entry_crash_durability_supported() -> bool {
        !cfg!(windows)
    }

    /// Opens an existing, non-symlink destination directory and prepares a private
    /// staging directory below it.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::Platform`] if the destination is missing, is a
    /// symlink, is not a directory, or cannot host a private staging directory.
    pub fn new(destination_root: impl AsRef<Path>) -> Result<Self, TransferError> {
        Self::new_inner(destination_root.as_ref(), None)
    }

    /// Opens peer-scoped staging below the shared destination.
    ///
    /// Persisted state from another authenticated peer is unreachable through
    /// this instance even when that peer chose the same wire transfer UUID.
    /// Legacy unscoped state is deliberately not migrated in pre-alpha builds.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::Platform`] when either the destination, shared
    /// staging root, or private peer namespace cannot be opened safely.
    pub fn new_scoped(
        destination_root: impl AsRef<Path>,
        authenticated_owner: [u8; 32],
    ) -> Result<Self, TransferError> {
        Self::new_inner(destination_root.as_ref(), Some(authenticated_owner))
    }

    fn new_inner(
        destination_root: &Path,
        authenticated_owner: Option<[u8; 32]>,
    ) -> Result<Self, TransferError> {
        let destination = open_ambient_directory_no_follow(destination_root)?;
        let (staging, created) = match destination.symlink_metadata(STAGING_DIRECTORY_NAME) {
            Ok(metadata) if metadata_is_reparse(&metadata) || !metadata.is_dir() => {
                return Err(TransferError::Platform);
            }
            Ok(_) => {
                let staging = open_private_dir_component_no_follow(
                    &destination,
                    Path::new(STAGING_DIRECTORY_NAME),
                )?;
                require_private_directory(&staging)?;
                (staging, false)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match create_private_directory_component(
                    &destination,
                    Path::new(STAGING_DIRECTORY_NAME),
                ) {
                    Ok(staging) => (staging, true),
                    Err(TransferError::DestinationExists) => {
                        let staging = open_private_dir_component_no_follow(
                            &destination,
                            Path::new(STAGING_DIRECTORY_NAME),
                        )?;
                        require_private_directory(&staging)?;
                        (staging, false)
                    }
                    Err(error) => return Err(error),
                }
            }
            Err(_) => return Err(TransferError::Platform),
        };
        if let Err(error) = sync_directory(&staging) {
            if created {
                staging
                    .remove_open_dir_all()
                    .map_err(|_| TransferError::Platform)?;
                sync_directory(&destination)?;
            }
            return Err(error);
        }
        if created && let Err(error) = sync_directory(&destination) {
            return match staging.remove_open_dir_all() {
                Ok(()) => match sync_directory(&destination) {
                    Ok(()) => Err(error),
                    Err(cleanup) => Err(cleanup),
                },
                Err(_) => Err(TransferError::Platform),
            };
        }
        let staging = if let Some(owner) = authenticated_owner {
            let owner_name = staging_owner_name(owner);
            let (owner_staging, owner_created) = match staging
                .symlink_metadata(Path::new(&owner_name))
            {
                Ok(metadata) if metadata_is_reparse(&metadata) || !metadata.is_dir() => {
                    return Err(TransferError::Platform);
                }
                Ok(_) => (
                    open_private_dir_component_no_follow(&staging, Path::new(&owner_name))?,
                    false,
                ),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    match create_private_directory_component(&staging, Path::new(&owner_name)) {
                        Ok(directory) => (directory, true),
                        Err(TransferError::DestinationExists) => (
                            open_private_dir_component_no_follow(&staging, Path::new(&owner_name))?,
                            false,
                        ),
                        Err(error) => return Err(error),
                    }
                }
                Err(_) => return Err(TransferError::Platform),
            };
            require_private_directory(&owner_staging)?;
            sync_directory(&owner_staging)?;
            if owner_created {
                sync_directory(&staging)?;
            }
            owner_staging
        } else {
            staging
        };
        Ok(Self {
            destination,
            staging,
            active: None,
            cleanup_failed: false,
        })
    }

    fn active_mut(&mut self, transfer: TransferId) -> Result<&mut ActiveTransfer, TransferError> {
        if self.cleanup_failed {
            return Err(TransferError::Platform);
        }
        self.active
            .as_mut()
            .filter(|active| active.id == transfer)
            .ok_or(TransferError::TransferNotActive)
    }

    /// Reopens durable staging after an interrupted process and returns the
    /// exact next contiguous offset for every manifest entry.
    ///
    /// The sender must present the same authenticated transfer identifier and
    /// manifest again. Any mismatch, reparse/symlink substitution, malformed
    /// progress record, or staged file shorter than the durable offset fails
    /// closed. Bytes written after the last durable record are truncated.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::InvalidResumeState`] for mismatched or malformed
    /// progress and [`TransferError::TransferNotActive`] if another transfer is
    /// already open in this staging area.
    pub fn resume(
        &mut self,
        transfer: TransferId,
        manifest: &TransferManifest,
    ) -> Result<ResumeState, TransferError> {
        if self.cleanup_failed {
            return Err(TransferError::Platform);
        }
        if self.active.is_some() {
            return Err(TransferError::TransferNotActive);
        }
        require_directory_handle(&self.destination)?;
        require_private_directory(&self.staging)?;
        let lease = acquire_transfer_lease(&self.staging)?;

        let directory_name = transfer_directory_name(transfer);
        let progress_name = transfer_progress_name(transfer);
        let directory = open_dir_component_no_follow(&self.staging, Path::new(&directory_name))
            .map_err(|_| TransferError::InvalidResumeState)?;
        require_private_directory(&directory).map_err(|_| TransferError::InvalidResumeState)?;
        let (mut progress, written, progress_records) = load_progress(
            &self.staging,
            Path::new(&progress_name),
            manifest,
            &directory,
        )?;
        progress
            .seek(SeekFrom::End(0))
            .map_err(|_| TransferError::Platform)?;
        let next_offsets = manifest
            .entries()
            .iter()
            .enumerate()
            .map(|(index, _)| written.get(&index).copied().unwrap_or(0))
            .collect();
        self.active = Some(ActiveTransfer {
            id: transfer,
            _lease: lease,
            directory,
            progress_name,
            progress,
            progress_records,
            manifest: manifest.clone(),
            written,
        });
        Ok(ResumeState {
            transfer,
            next_offsets,
        })
    }

    /// Deletes one interrupted transfer without following links or touching
    /// destination files. An unrelated active transfer is never disturbed.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::TransferNotActive`] while another transfer is
    /// open in this staging instance.
    pub fn discard_persisted(&mut self, transfer: TransferId) -> Result<(), TransferError> {
        if let Some(active) = self.active.as_ref() {
            if active.id == transfer {
                return self.try_abort(transfer);
            }
            return Err(TransferError::TransferNotActive);
        }
        self.discard_unopened_persisted(transfer)
    }

    /// Deletes safe persisted staging that has not been reopened.
    ///
    /// The caller must obtain `transfer` from the authenticated peer scope used
    /// to construct this staging instance. Scoped instances resolve only below
    /// that peer's private namespace. This method never follows substituted
    /// links and never affects an active transfer.
    ///
    /// # Errors
    ///
    /// Rejects active staging, unsafe substitutions, identity mismatches, and
    /// any cleanup or durability failure.
    pub fn discard_unopened_persisted(
        &mut self,
        transfer: TransferId,
    ) -> Result<(), TransferError> {
        if self.active.is_some() {
            return Err(TransferError::TransferNotActive);
        }
        if self.cleanup_failed {
            return Err(TransferError::Platform);
        }
        let _lease = acquire_transfer_lease(&self.staging)?;
        remove_persisted_transfer(&self.staging, transfer)
    }

    /// Aborts active staging and reports cleanup failures.
    ///
    /// The trait-level [`StagingArea::abort`] cannot return an error, so callers
    /// that need immediate cleanup confirmation should use this method.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::TransferNotActive`] for another transfer and
    /// [`TransferError::Platform`] when cleanup could not be completed.
    pub fn try_abort(&mut self, transfer: TransferId) -> Result<(), TransferError> {
        if self.cleanup_failed {
            return Err(TransferError::Platform);
        }
        let Some(active) = self.active.take() else {
            return Ok(());
        };
        if active.id != transfer {
            self.active = Some(active);
            return Err(TransferError::TransferNotActive);
        }
        let result = remove_active_transfer(&self.staging, active);
        if result.is_err() {
            self.cleanup_failed = true;
        }
        result
    }

    fn finalize_with_hook(
        &mut self,
        transfer: TransferId,
        before_publish: impl FnMut(&crate::ManifestEntry),
    ) -> Result<(), TransferError> {
        if self.cleanup_failed {
            return Err(TransferError::Platform);
        }
        let active = self
            .active
            .as_ref()
            .filter(|active| active.id == transfer)
            .ok_or(TransferError::TransferNotActive)?;
        verify_complete(active)?;
        preflight_destination(&self.destination, &active.manifest)?;
        if let Err(error) = publish_entries_with_hook(&self.destination, active, before_publish) {
            // Publication may have reached the destination before this error.
            // Reject all later writes/finalization until explicit cleanup.
            self.cleanup_failed = true;
            return Err(error);
        }

        let active = self.active.take().ok_or(TransferError::TransferNotActive)?;
        let result = remove_active_transfer(&self.staging, active);
        if result.is_err() {
            self.cleanup_failed = true;
        }
        result
    }
}

impl StagingArea for FileSystemStagingArea {
    fn begin<'a>(
        &'a mut self,
        transfer: TransferId,
        manifest: &'a TransferManifest,
    ) -> TransferFuture<'a, Result<(), TransferError>> {
        Box::pin(async move {
            if self.cleanup_failed {
                return Err(TransferError::Platform);
            }
            if self.active.is_some() {
                return Err(TransferError::TransferNotActive);
            }
            require_directory_handle(&self.destination)?;
            require_private_directory(&self.staging)?;
            let lease = acquire_transfer_lease(&self.staging)?;

            let directory_name = transfer_directory_name(transfer);
            let progress_name = transfer_progress_name(transfer);
            match self.staging.symlink_metadata(Path::new(&progress_name)) {
                Ok(_) => return Err(TransferError::DestinationExists),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(TransferError::Platform),
            }
            let directory =
                match create_private_directory_component(&self.staging, Path::new(&directory_name))
                {
                    Ok(directory) => directory,
                    Err(error) => return Err(error),
                };
            let result = prepare_entries(&directory, manifest);
            if let Err(error) = result {
                return match remove_transfer_directory(&self.staging, directory) {
                    Ok(()) => Err(error),
                    Err(cleanup) => {
                        self.cleanup_failed = true;
                        Err(cleanup)
                    }
                };
            }

            let progress = match create_progress(&self.staging, Path::new(&progress_name), manifest)
            {
                Ok(progress) => progress,
                Err(error) => {
                    return match remove_transfer_directory(&self.staging, directory) {
                        Ok(()) => Err(error),
                        Err(cleanup) => {
                            self.cleanup_failed = true;
                            Err(cleanup)
                        }
                    };
                }
            };
            if let Err(error) = sync_directory(&self.staging) {
                return match cleanup_unopened_transfer(
                    &self.staging,
                    directory,
                    &progress_name,
                    progress,
                ) {
                    Ok(()) => Err(error),
                    Err(cleanup) => {
                        self.cleanup_failed = true;
                        Err(cleanup)
                    }
                };
            }

            let written = manifest
                .entries()
                .iter()
                .enumerate()
                .filter_map(|(index, entry)| (entry.kind == EntryKind::File).then_some((index, 0)))
                .collect();
            self.active = Some(ActiveTransfer {
                id: transfer,
                _lease: lease,
                directory,
                progress_name,
                progress,
                progress_records: 0,
                manifest: manifest.clone(),
                written,
            });
            Ok(())
        })
    }

    fn write(&mut self, chunk: TransferChunk) -> TransferFuture<'_, Result<(), TransferError>> {
        Box::pin(async move {
            let active = self.active_mut(chunk.transfer)?;
            chunk.validate(&active.manifest)?;
            let index =
                usize::try_from(chunk.entry_index).map_err(|_| TransferError::InvalidChunk)?;
            let written = active
                .written
                .get(&index)
                .copied()
                .ok_or(TransferError::InvalidChunk)?;
            if chunk.offset != written {
                return Err(TransferError::NonSequentialChunk);
            }
            let entry = active
                .manifest
                .entries()
                .get(index)
                .ok_or(TransferError::InvalidChunk)?;
            let mut file = open_relative_file_no_follow(
                &active.directory,
                Path::new(entry.path.as_str()),
                true,
            )?;
            require_private_file(&file)?;
            file.seek(SeekFrom::Start(chunk.offset))
                .map_err(|_| TransferError::Platform)?;
            file.write_all(&chunk.bytes)
                .map_err(|_| TransferError::Platform)?;
            file.sync_all().map_err(|_| TransferError::Platform)?;
            let next_offset = written
                .checked_add(
                    u64::try_from(chunk.bytes.len()).map_err(|_| TransferError::InvalidChunk)?,
                )
                .ok_or(TransferError::InvalidChunk)?;
            append_progress(
                &mut active.progress,
                index,
                next_offset,
                active.progress_records,
            )?;
            active.progress_records += 1;
            active.written.insert(index, next_offset);
            Ok(())
        })
    }

    fn finalize(&mut self, transfer: TransferId) -> TransferFuture<'_, Result<(), TransferError>> {
        Box::pin(async move { self.finalize_with_hook(transfer, |_| {}) })
    }

    fn abort(&mut self, transfer: TransferId) {
        let _ = self.try_abort(transfer);
    }

    fn abort_confirmed(&mut self, transfer: TransferId) -> Result<(), TransferError> {
        self.try_abort(transfer)
    }
}

impl ResumableStagingArea for FileSystemStagingArea {
    fn has_persisted(&self, transfer: TransferId) -> Result<bool, TransferError> {
        if self.cleanup_failed {
            return Err(TransferError::Platform);
        }
        require_private_directory(&self.staging)?;
        let directory = transfer_directory_name(transfer);
        let progress = transfer_progress_name(transfer);
        match (
            self.staging.symlink_metadata(Path::new(&directory)),
            self.staging.symlink_metadata(Path::new(&progress)),
        ) {
            (Err(left), Err(right))
                if left.kind() == std::io::ErrorKind::NotFound
                    && right.kind() == std::io::ErrorKind::NotFound =>
            {
                Ok(false)
            }
            (Ok(directory_meta), Ok(progress_meta))
                if directory_meta.is_dir()
                    && !metadata_is_reparse(&directory_meta)
                    && progress_meta.is_file()
                    && !metadata_is_reparse(&progress_meta) =>
            {
                let directory = open_dir_component_no_follow(&self.staging, Path::new(&directory))
                    .map_err(|_| TransferError::InvalidResumeState)?;
                let progress = open_private_file_component_no_follow(
                    &self.staging,
                    Path::new(&progress),
                    false,
                )
                .map_err(|_| TransferError::InvalidResumeState)?;
                require_private_directory(&directory)
                    .and_then(|()| require_private_file(&progress))
                    .map_err(|_| TransferError::InvalidResumeState)?;
                Ok(true)
            }
            _ => Err(TransferError::InvalidResumeState),
        }
    }

    fn resume(
        &mut self,
        transfer: TransferId,
        manifest: &TransferManifest,
    ) -> Result<ResumeState, TransferError> {
        Self::resume(self, transfer, manifest)
    }
}

#[cfg(test)]
fn transfer_directory(root: &Path, transfer: TransferId) -> PathBuf {
    root.join(transfer_directory_name(transfer))
}

#[cfg(test)]
fn transfer_progress_path(root: &Path, transfer: TransferId) -> PathBuf {
    root.join(transfer_progress_name(transfer))
}

fn transfer_directory_name(transfer: TransferId) -> OsString {
    format!("{}.data", transfer.as_uuid()).into()
}

fn staging_owner_name(owner: [u8; 32]) -> OsString {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut name = String::with_capacity(5 + owner.len() * 2);
    name.push_str("peer-");
    for byte in owner {
        name.push(char::from(HEX[usize::from(byte >> 4)]));
        name.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    OsString::from(name)
}

fn transfer_progress_name(transfer: TransferId) -> OsString {
    format!("{}.progress", transfer.as_uuid()).into()
}

fn acquire_transfer_lease(staging: &Dir) -> Result<TransferLease, TransferError> {
    let name = Path::new(OPERATION_LEASE_NAME);
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create_new(true)
        .follow(FollowSymlinks::No);
    configure_private_file_options(&mut options);
    let (file, created) = match staging.open_with(name, &options) {
        Ok(file) => (file, true),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let file = open_private_file_component_no_follow(staging, name, true)?;
            (file, false)
        }
        Err(_) => return Err(TransferError::Platform),
    };
    let metadata = file.metadata().map_err(|_| TransferError::Platform)?;
    if metadata_is_reparse(&metadata) || !metadata.is_file() {
        return Err(TransferError::Platform);
    }
    if created {
        make_private_file(&file)?;
        file.sync_all().map_err(|_| TransferError::Platform)?;
        sync_directory(staging)?;
    } else {
        require_private_file(&file)?;
    }
    let file = file.into_std();
    file.try_lock().map_err(|error| match error {
        std::fs::TryLockError::WouldBlock => TransferError::TransferNotActive,
        std::fs::TryLockError::Error(_) => TransferError::Platform,
    })?;
    Ok(TransferLease { _file: file })
}

fn manifest_fingerprint(manifest: &TransferManifest) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(MANIFEST_HASH_DOMAIN);
    hasher.update(
        &u32::try_from(manifest.entries().len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    for entry in manifest.entries() {
        let path = entry.path.as_str().as_bytes();
        hasher.update(&u32::try_from(path.len()).unwrap_or(u32::MAX).to_be_bytes());
        hasher.update(path);
        hasher.update(&[match entry.kind {
            EntryKind::File => 1,
            EntryKind::Directory => 2,
        }]);
        hasher.update(&entry.size.to_be_bytes());
        match entry.hash {
            Some(hash) => {
                hasher.update(&[1]);
                hasher.update(hash.as_bytes());
            }
            None => {
                hasher.update(&[0]);
            }
        }
    }
    *hasher.finalize().as_bytes()
}

fn create_progress(
    staging: &Dir,
    name: &Path,
    manifest: &TransferManifest,
) -> Result<File, TransferError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create_new(true)
        .follow(FollowSymlinks::No);
    configure_private_file_options(&mut options);
    let mut file = staging
        .open_with(name, &options)
        .map_err(|error| map_create_error(&error))?;
    if let Err(error) = make_private_file(&file) {
        return match cleanup_created_file(staging, name, file) {
            Ok(()) => Err(error),
            Err(cleanup) => Err(cleanup),
        };
    }
    let entry_count =
        u32::try_from(manifest.entries().len()).map_err(|_| TransferError::InvalidManifest)?;
    let mut header = Vec::with_capacity(PROGRESS_HEADER_BYTES);
    header.extend_from_slice(PROGRESS_MAGIC);
    header.extend_from_slice(&manifest_fingerprint(manifest));
    header.extend_from_slice(&entry_count.to_be_bytes());
    let result = file.write_all(&header).and_then(|()| file.sync_all());
    if result.is_err() {
        return match cleanup_created_file(staging, name, file) {
            Ok(()) => Err(TransferError::Platform),
            Err(cleanup) => Err(cleanup),
        };
    }
    Ok(file)
}

fn append_progress(
    progress: &mut File,
    entry_index: usize,
    next_offset: u64,
    record_count: usize,
) -> Result<(), TransferError> {
    if record_count >= MAX_PROGRESS_RECORDS {
        return Err(TransferError::ProgressLimitExceeded);
    }
    let entry_index = u32::try_from(entry_index).map_err(|_| TransferError::InvalidResumeState)?;
    let mut record = [0_u8; PROGRESS_RECORD_BYTES];
    record[..4].copy_from_slice(&entry_index.to_be_bytes());
    record[4..12].copy_from_slice(&next_offset.to_be_bytes());
    record[12..].copy_from_slice(&progress_record_checksum(entry_index, next_offset));
    progress
        .write_all(&record)
        .and_then(|()| progress.sync_all())
        .map_err(|_| TransferError::Platform)
}

fn progress_record_checksum(entry_index: u32, next_offset: u64) -> [u8; 8] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(PROGRESS_RECORD_DOMAIN);
    hasher.update(&entry_index.to_be_bytes());
    hasher.update(&next_offset.to_be_bytes());
    let digest = hasher.finalize();
    let mut checksum = [0_u8; 8];
    checksum.copy_from_slice(&digest.as_bytes()[..8]);
    checksum
}

fn load_progress(
    staging: &Dir,
    name: &Path,
    manifest: &TransferManifest,
    directory: &Dir,
) -> Result<(File, HashMap<usize, u64>, usize), TransferError> {
    let mut progress = open_relative_file_no_follow(staging, name, true)
        .map_err(|_| TransferError::InvalidResumeState)?;
    require_private_file(&progress).map_err(|_| TransferError::InvalidResumeState)?;
    let metadata = progress
        .metadata()
        .map_err(|_| TransferError::InvalidResumeState)?;
    if metadata_is_reparse(&metadata)
        || !metadata.is_file()
        || metadata.len() < PROGRESS_HEADER_BYTES as u64
        || metadata.len() > MAX_PROGRESS_BYTES
    {
        return Err(TransferError::InvalidResumeState);
    }
    let capacity =
        usize::try_from(metadata.len()).map_err(|_| TransferError::InvalidResumeState)?;
    let mut encoded = Vec::with_capacity(capacity);
    Read::by_ref(&mut progress)
        .take(MAX_PROGRESS_BYTES + 1)
        .read_to_end(&mut encoded)
        .map_err(|_| TransferError::InvalidResumeState)?;
    if encoded.len() as u64 != metadata.len() || encoded.len() < PROGRESS_HEADER_BYTES {
        return Err(TransferError::InvalidResumeState);
    }
    if encoded.get(..8) != Some(PROGRESS_MAGIC.as_slice())
        || encoded.get(8..40) != Some(manifest_fingerprint(manifest).as_slice())
    {
        return Err(TransferError::InvalidResumeState);
    }
    let entry_count = encoded
        .get(40..44)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .map(u32::from_be_bytes)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or(TransferError::InvalidResumeState)?;
    if entry_count != manifest.entries().len() {
        return Err(TransferError::InvalidResumeState);
    }

    let payload = &encoded[PROGRESS_HEADER_BYTES..];
    let complete_bytes = payload.len() / PROGRESS_RECORD_BYTES * PROGRESS_RECORD_BYTES;
    let record_count = complete_bytes / PROGRESS_RECORD_BYTES;
    if record_count > MAX_PROGRESS_RECORDS {
        return Err(TransferError::InvalidResumeState);
    }
    let mut written = manifest
        .entries()
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| (entry.kind == EntryKind::File).then_some((index, 0)))
        .collect::<HashMap<_, _>>();
    for record in payload[..complete_bytes].chunks_exact(PROGRESS_RECORD_BYTES) {
        let entry_index = u32::from_be_bytes(
            record[..4]
                .try_into()
                .map_err(|_| TransferError::InvalidResumeState)?,
        );
        let next_offset = u64::from_be_bytes(
            record[4..12]
                .try_into()
                .map_err(|_| TransferError::InvalidResumeState)?,
        );
        let checksum: [u8; 8] = record[12..]
            .try_into()
            .map_err(|_| TransferError::InvalidResumeState)?;
        if checksum != progress_record_checksum(entry_index, next_offset) {
            return Err(TransferError::InvalidResumeState);
        }
        let index = usize::try_from(entry_index).map_err(|_| TransferError::InvalidResumeState)?;
        let entry = manifest
            .entries()
            .get(index)
            .filter(|entry| entry.kind == EntryKind::File)
            .ok_or(TransferError::InvalidResumeState)?;
        let previous = written
            .get(&index)
            .copied()
            .ok_or(TransferError::InvalidResumeState)?;
        if next_offset <= previous || next_offset > entry.size {
            return Err(TransferError::InvalidResumeState);
        }
        written.insert(index, next_offset);
    }

    if complete_bytes != payload.len() {
        let durable_length = u64::try_from(PROGRESS_HEADER_BYTES + complete_bytes)
            .map_err(|_| TransferError::InvalidResumeState)?;
        progress
            .set_len(durable_length)
            .and_then(|()| progress.sync_all())
            .map_err(|_| TransferError::Platform)?;
    }
    validate_resumed_entries(directory, manifest, &written)?;
    Ok((progress, written, record_count))
}

fn validate_resumed_entries(
    directory: &Dir,
    manifest: &TransferManifest,
    written: &HashMap<usize, u64>,
) -> Result<(), TransferError> {
    for (index, entry) in manifest.entries().iter().enumerate() {
        let path = Path::new(entry.path.as_str());
        match entry.kind {
            EntryKind::Directory => {
                let child = open_relative_directory_no_follow(directory, path)
                    .map_err(|_| TransferError::InvalidResumeState)?;
                require_private_directory(&child).map_err(|_| TransferError::InvalidResumeState)?;
            }
            EntryKind::File => {
                let expected = written
                    .get(&index)
                    .copied()
                    .ok_or(TransferError::InvalidResumeState)?;
                let file = open_relative_file_no_follow(directory, path, true)
                    .map_err(|_| TransferError::InvalidResumeState)?;
                require_private_file(&file).map_err(|_| TransferError::InvalidResumeState)?;
                let actual = file
                    .metadata()
                    .map_err(|_| TransferError::InvalidResumeState)?
                    .len();
                if actual < expected {
                    return Err(TransferError::InvalidResumeState);
                }
                if actual > expected {
                    file.set_len(expected)
                        .and_then(|()| file.sync_all())
                        .map_err(|_| TransferError::Platform)?;
                }
            }
        }
    }
    Ok(())
}

fn prepare_entries(root: &Dir, manifest: &TransferManifest) -> Result<(), TransferError> {
    for entry in manifest.entries() {
        let path = Path::new(entry.path.as_str());
        let (parent, name) = create_private_parents(root, path)?;
        match entry.kind {
            EntryKind::Directory => {
                match create_private_directory_component(&parent, Path::new(&name)) {
                    Ok(directory) => {
                        sync_directory(&directory)?;
                        sync_directory(&parent)?;
                    }
                    Err(TransferError::DestinationExists) => {
                        let directory =
                            open_private_dir_component_no_follow(&parent, Path::new(&name))?;
                        require_private_directory(&directory)?;
                    }
                    Err(error) => return Err(error),
                }
            }
            EntryKind::File => {
                let mut options = OpenOptions::new();
                options
                    .write(true)
                    .create_new(true)
                    .follow(FollowSymlinks::No);
                configure_private_file_options(&mut options);
                let file = parent
                    .open_with(Path::new(&name), &options)
                    .map_err(|error| map_create_error(&error))?;
                make_private_file(&file)?;
                file.sync_all().map_err(|_| TransferError::Platform)?;
                sync_directory(&parent)?;
            }
        }
    }
    sync_directory(root)?;
    Ok(())
}

fn create_private_parents(root: &Dir, path: &Path) -> Result<(Dir, OsString), TransferError> {
    let (components, name) = split_relative_path(path)?;
    let mut current = root.try_clone().map_err(|_| TransferError::Platform)?;
    for component in components {
        match create_private_directory_component(&current, Path::new(&component)) {
            Ok(child) => {
                sync_directory(&child)?;
                sync_directory(&current)?;
                current = child;
            }
            Err(TransferError::DestinationExists) => {
                current = open_private_dir_component_no_follow(&current, Path::new(&component))?;
                require_private_directory(&current)?;
            }
            Err(error) => return Err(error),
        }
    }
    Ok((current, name))
}

fn verify_complete(active: &ActiveTransfer) -> Result<(), TransferError> {
    for (index, entry) in active.manifest.entries().iter().enumerate() {
        let path = Path::new(entry.path.as_str());
        match entry.kind {
            EntryKind::Directory => {
                let directory = open_relative_directory_no_follow(&active.directory, path)?;
                require_private_directory(&directory)?;
            }
            EntryKind::File => {
                if active.written.get(&index).copied() != Some(entry.size) {
                    return Err(TransferError::IntegrityMismatch);
                }
                let file = open_relative_file_no_follow(&active.directory, path, false)?;
                require_private_file(&file)?;
                let expected = entry.hash.ok_or(TransferError::InvalidManifest)?;
                if hash_file(file)? != expected {
                    return Err(TransferError::IntegrityMismatch);
                }
            }
        }
    }
    Ok(())
}

fn preflight_destination(root: &Dir, manifest: &TransferManifest) -> Result<(), TransferError> {
    require_directory_handle(root)?;
    for entry in manifest.entries() {
        if destination_path_exists(root, Path::new(entry.path.as_str()))? {
            return Err(TransferError::DestinationExists);
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct ObjectIdentity {
    device: u64,
    inode: u64,
}

#[derive(Clone, Copy)]
enum PublishedKind {
    File,
    Directory,
}

struct PublishedEntry {
    parent: Dir,
    name: OsString,
    identity: ObjectIdentity,
    kind: PublishedKind,
    depth: usize,
}

fn publish_entries_with_hook(
    root: &Dir,
    active: &ActiveTransfer,
    mut before_publish: impl FnMut(&crate::ManifestEntry),
) -> Result<(), TransferError> {
    let mut published = Vec::new();
    let result = publish_entries_inner(root, active, &mut published, &mut before_publish)
        .and_then(|()| sync_published_directories(root, &published));
    if let Err(error) = result {
        return match rollback_published(&mut published) {
            Ok(()) => Err(error),
            Err(cleanup) => Err(cleanup),
        };
    }
    Ok(())
}

fn publish_entries_inner(
    root: &Dir,
    active: &ActiveTransfer,
    published: &mut Vec<PublishedEntry>,
    before_publish: &mut impl FnMut(&crate::ManifestEntry),
) -> Result<(), TransferError> {
    let mut directories = active
        .manifest
        .entries()
        .iter()
        .filter(|entry| entry.kind == EntryKind::Directory)
        .collect::<Vec<_>>();
    directories.sort_by_key(|entry| entry.path.as_str().matches('/').count());
    for entry in directories {
        let path = Path::new(entry.path.as_str());
        let (parent, name) = create_destination_parents(root, path, published)?;
        before_publish(entry);
        parent
            .create_dir(Path::new(&name))
            .map_err(|error| map_create_error(&error))?;
        track_created_directory(parent, name, path.components().count(), published)?;
        let published_directory = open_relative_directory_no_follow(root, path)?;
        if directory_identity(&published_directory)?
            != published.last().ok_or(TransferError::Platform)?.identity
        {
            return Err(TransferError::Platform);
        }
    }

    for entry in active
        .manifest
        .entries()
        .iter()
        .filter(|entry| entry.kind == EntryKind::File)
    {
        let path = Path::new(entry.path.as_str());
        let (source_parent, source_name) = open_parent_no_follow(&active.directory, path)?;
        let source = open_file_component_no_follow(&source_parent, Path::new(&source_name), false)?;
        require_private_file(&source)?;
        let source_metadata = source.metadata().map_err(|_| TransferError::Platform)?;
        if source_metadata.len() != entry.size
            || hash_file(source.try_clone().map_err(|_| TransferError::Platform)?)?
                != entry.hash.ok_or(TransferError::InvalidManifest)?
        {
            return Err(TransferError::IntegrityMismatch);
        }
        let expected_identity = file_identity(&source)?;
        let (destination_parent, destination_name) =
            create_destination_parents(root, path, published)?;
        before_publish(entry);
        source_parent
            .hard_link(
                Path::new(&source_name),
                &destination_parent,
                Path::new(&destination_name),
            )
            .map_err(|error| map_create_error(&error))?;
        published.push(PublishedEntry {
            parent: destination_parent,
            name: destination_name,
            identity: expected_identity,
            kind: PublishedKind::File,
            depth: path.components().count(),
        });
        let destination = open_relative_file_no_follow(root, path, false)?;
        if file_identity(&destination)? != expected_identity {
            return Err(TransferError::Platform);
        }
    }
    Ok(())
}

fn sync_published_directories(
    root: &Dir,
    published: &[PublishedEntry],
) -> Result<(), TransferError> {
    sync_published_directories_with(root, published, sync_directory)
}

fn sync_published_directories_with(
    root: &Dir,
    published: &[PublishedEntry],
    mut sync: impl FnMut(&Dir) -> Result<(), TransferError>,
) -> Result<(), TransferError> {
    let root_identity = directory_identity(root)?;
    let mut directories = Vec::new();
    let mut seen = HashSet::new();
    for entry in published {
        let parent_identity = directory_identity(&entry.parent)?;
        if parent_identity != root_identity && seen.insert(parent_identity) {
            directories.push((
                entry.depth.saturating_sub(1),
                entry
                    .parent
                    .try_clone()
                    .map_err(|_| TransferError::Platform)?,
            ));
        }
        if matches!(entry.kind, PublishedKind::Directory) {
            let directory = open_dir_component_no_follow(&entry.parent, Path::new(&entry.name))?;
            let identity = directory_identity(&directory)?;
            if identity != entry.identity {
                return Err(TransferError::Platform);
            }
            if identity != root_identity && seen.insert(identity) {
                directories.push((entry.depth, directory));
            }
        }
    }
    directories.sort_by_key(|entry| std::cmp::Reverse(entry.0));
    for (_, directory) in directories {
        sync(&directory)?;
    }
    sync(root)
}

fn create_destination_parents(
    root: &Dir,
    destination: &Path,
    published: &mut Vec<PublishedEntry>,
) -> Result<(Dir, OsString), TransferError> {
    let (components, name) = split_relative_path(destination)?;
    let mut current = root.try_clone().map_err(|_| TransferError::Platform)?;
    for (index, component) in components.into_iter().enumerate() {
        match current.symlink_metadata(Path::new(&component)) {
            Ok(metadata) if metadata_is_reparse(&metadata) || !metadata.is_dir() => {
                return Err(TransferError::DestinationExists);
            }
            Ok(_) => {
                current = open_dir_component_no_follow(&current, Path::new(&component))?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                current
                    .create_dir(Path::new(&component))
                    .map_err(|error| map_create_error(&error))?;
                track_created_directory(current, component, index + 1, published)?;
                let created = published.last().ok_or(TransferError::Platform)?;
                current = open_dir_component_no_follow(&created.parent, Path::new(&created.name))?;
            }
            Err(_) => return Err(TransferError::Platform),
        }
    }
    Ok((current, name))
}

fn track_created_directory(
    parent: Dir,
    name: OsString,
    depth: usize,
    published: &mut Vec<PublishedEntry>,
) -> Result<(), TransferError> {
    // Destination parents are not an enforceable exclusive trust boundary.
    // On an open/identity failure, retain the new name and fail closed instead
    // of risking deletion of a same-user replacement through a pathname race.
    let directory = open_dir_component_no_follow(&parent, Path::new(&name))?;
    let identity = directory_identity(&directory)?;
    published.push(PublishedEntry {
        parent,
        name,
        identity,
        kind: PublishedKind::Directory,
        depth,
    });
    Ok(())
}

fn hash_file(mut file: File) -> Result<ContentHash, TransferError> {
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0_u8; HASH_BUFFER_BYTES];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| TransferError::Platform)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(ContentHash::from_bytes(*hasher.finalize().as_bytes()))
}

fn open_ambient_directory_no_follow(path: &Path) -> Result<Dir, TransferError> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| TransferError::Platform)?
            .join(path)
    };
    let name = absolute.file_name().ok_or(TransferError::Platform)?;
    let parent = absolute.parent().ok_or(TransferError::Platform)?;
    let parent =
        Dir::open_ambient_dir(parent, ambient_authority()).map_err(|_| TransferError::Platform)?;
    open_dir_component_no_follow(&parent, Path::new(name))
}

fn require_directory_handle(directory: &Dir) -> Result<(), TransferError> {
    let metadata = directory
        .dir_metadata()
        .map_err(|_| TransferError::Platform)?;
    if metadata_is_reparse(&metadata) || !metadata.is_dir() {
        return Err(TransferError::Platform);
    }
    Ok(())
}

fn require_private_directory(directory: &Dir) -> Result<(), TransferError> {
    require_directory_handle(directory)?;
    verify_private_directory(directory)
}

#[cfg(unix)]
fn verify_private_directory(directory: &Dir) -> Result<(), TransferError> {
    use cap_std::fs::MetadataExt as _;

    let metadata = directory
        .dir_metadata()
        .map_err(|_| TransferError::Platform)?;
    if metadata.mode() & 0o777 != 0o700 {
        return Err(TransferError::Platform);
    }
    Ok(())
}

#[cfg(windows)]
fn verify_private_directory(directory: &Dir) -> Result<(), TransferError> {
    let handle = directory
        .try_clone()
        .map_err(|_| TransferError::Platform)?
        .into_std_file();
    windows_acl::verify_owner_only_directory(&handle).map_err(|_| TransferError::Platform)
}

#[cfg(all(not(unix), not(windows)))]
#[allow(clippy::unnecessary_wraps)]
fn verify_private_directory(_directory: &Dir) -> Result<(), TransferError> {
    Ok(())
}

#[cfg(unix)]
fn require_private_file(file: &File) -> Result<(), TransferError> {
    use cap_std::fs::MetadataExt as _;

    let metadata = file.metadata().map_err(|_| TransferError::Platform)?;
    if metadata.mode() & 0o777 != 0o600 {
        return Err(TransferError::Platform);
    }
    Ok(())
}

#[cfg(all(not(unix), not(windows)))]
#[allow(clippy::unnecessary_wraps)]
fn require_private_file(_file: &File) -> Result<(), TransferError> {
    Ok(())
}

#[cfg(windows)]
fn require_private_file(file: &File) -> Result<(), TransferError> {
    let handle = file
        .try_clone()
        .map_err(|_| TransferError::Platform)?
        .into_std();
    windows_acl::verify_owner_only_file(&handle).map_err(|_| TransferError::Platform)
}

fn split_relative_path(path: &Path) -> Result<(Vec<OsString>, OsString), TransferError> {
    let mut components = path
        .components()
        .map(|component| match component {
            Component::Normal(value) => Ok(value.to_os_string()),
            _ => Err(TransferError::InvalidPath),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let name = components.pop().ok_or(TransferError::InvalidPath)?;
    Ok((components, name))
}

fn open_parent_no_follow(root: &Dir, path: &Path) -> Result<(Dir, OsString), TransferError> {
    let (components, name) = split_relative_path(path)?;
    let mut parent = root.try_clone().map_err(|_| TransferError::Platform)?;
    for component in components {
        parent = open_dir_component_no_follow(&parent, Path::new(&component))?;
    }
    Ok((parent, name))
}

fn open_relative_directory_no_follow(root: &Dir, path: &Path) -> Result<Dir, TransferError> {
    let components = path
        .components()
        .map(|component| match component {
            Component::Normal(value) => Ok(value.to_os_string()),
            _ => Err(TransferError::InvalidPath),
        })
        .collect::<Result<Vec<_>, _>>()?;
    if components.is_empty() {
        return Err(TransferError::InvalidPath);
    }
    let mut directory = root.try_clone().map_err(|_| TransferError::Platform)?;
    for component in components {
        directory = open_dir_component_no_follow(&directory, Path::new(&component))?;
    }
    Ok(directory)
}

fn open_relative_file_no_follow(
    root: &Dir,
    path: &Path,
    writable: bool,
) -> Result<File, TransferError> {
    let (parent, name) = open_parent_no_follow(root, path)?;
    open_private_file_component_no_follow(&parent, Path::new(&name), writable)
}

fn open_private_file_component_no_follow(
    parent: &Dir,
    name: &Path,
    writable: bool,
) -> Result<File, TransferError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(writable)
        .follow(FollowSymlinks::No);
    configure_private_existing_file_options(&mut options, writable);
    let file = parent
        .open_with(name, &options)
        .map_err(|_| TransferError::Platform)?;
    let metadata = file.metadata().map_err(|_| TransferError::Platform)?;
    if metadata_is_reparse(&metadata) || !metadata.is_file() {
        return Err(TransferError::Platform);
    }
    Ok(file)
}

fn open_file_component_no_follow(
    parent: &Dir,
    name: &Path,
    writable: bool,
) -> Result<File, TransferError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(writable)
        .follow(FollowSymlinks::No);
    let file = parent
        .open_with(name, &options)
        .map_err(|_| TransferError::Platform)?;
    let metadata = file.metadata().map_err(|_| TransferError::Platform)?;
    if metadata_is_reparse(&metadata) || !metadata.is_file() {
        return Err(TransferError::Platform);
    }
    Ok(file)
}

fn open_dir_component_no_follow(parent: &Dir, name: &Path) -> Result<Dir, TransferError> {
    let directory = parent
        .open_dir_nofollow(name)
        .map_err(|_| TransferError::Platform)?;
    let metadata = directory
        .dir_metadata()
        .map_err(|_| TransferError::Platform)?;
    if metadata_is_reparse(&metadata) || !metadata.is_dir() {
        return Err(TransferError::Platform);
    }
    Ok(directory)
}

#[cfg(unix)]
fn create_private_directory_component(parent: &Dir, name: &Path) -> Result<Dir, TransferError> {
    use cap_std::fs::{DirBuilder, DirBuilderExt as _};

    let mut builder = DirBuilder::new();
    builder.mode(0o700);
    parent
        .create_dir_with(name, &builder)
        .map_err(|error| map_create_error(&error))?;
    let directory = open_private_dir_component_no_follow(parent, name)?;
    make_private_directory(&directory)?;
    Ok(directory)
}

#[cfg(all(not(unix), not(windows)))]
fn create_private_directory_component(parent: &Dir, name: &Path) -> Result<Dir, TransferError> {
    parent
        .create_dir(name)
        .map_err(|error| map_create_error(&error))?;
    let directory = open_private_dir_component_no_follow(parent, name)?;
    make_private_directory(&directory)?;
    Ok(directory)
}

#[cfg(windows)]
fn create_private_directory_component(parent: &Dir, name: &Path) -> Result<Dir, TransferError> {
    let component = name
        .file_name()
        .filter(|_| name.components().count() == 1)
        .ok_or(TransferError::InvalidPath)?;
    let parent_handle = parent
        .try_clone()
        .map_err(|_| TransferError::Platform)?
        .into_std_file();
    let directory = windows_acl::create_owner_only_directory(&parent_handle, component)
        .map_err(|error| map_create_error(&error))?;
    Ok(Dir::from_std_file(directory))
}

#[cfg(not(windows))]
fn open_private_dir_component_no_follow(parent: &Dir, name: &Path) -> Result<Dir, TransferError> {
    open_dir_component_no_follow(parent, name)
}

#[cfg(windows)]
fn open_private_dir_component_no_follow(parent: &Dir, name: &Path) -> Result<Dir, TransferError> {
    use cap_fs_ext::OpenOptionsMaybeDirExt as _;
    use cap_std::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_GENERIC_READ, FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL, WRITE_DAC,
    };

    let mut options = OpenOptions::new();
    options
        .read(true)
        .follow(FollowSymlinks::No)
        .maybe_dir(true)
        .access_mode(FILE_GENERIC_READ | READ_CONTROL | WRITE_DAC)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
    let file = parent
        .open_with(name, &options)
        .map_err(|_| TransferError::Platform)?;
    let metadata = file.metadata().map_err(|_| TransferError::Platform)?;
    if metadata_is_reparse(&metadata) || !metadata.is_dir() {
        return Err(TransferError::Platform);
    }
    Ok(Dir::from_std_file(file.into_std()))
}

#[cfg(unix)]
fn configure_private_file_options(options: &mut OpenOptions) {
    use cap_std::fs::OpenOptionsExt as _;

    options.mode(0o600);
}

#[cfg(all(not(unix), not(windows)))]
fn configure_private_file_options(_options: &mut OpenOptions) {}

#[cfg(not(windows))]
fn configure_private_existing_file_options(_options: &mut OpenOptions, _writable: bool) {}

#[cfg(windows)]
fn configure_private_file_options(options: &mut OpenOptions) {
    use cap_std::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL,
        WRITE_DAC,
    };

    options
        .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE | READ_CONTROL | WRITE_DAC)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
}

#[cfg(windows)]
fn configure_private_existing_file_options(options: &mut OpenOptions, writable: bool) {
    use cap_std::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL,
    };

    let access = if writable {
        FILE_GENERIC_READ | FILE_GENERIC_WRITE | READ_CONTROL
    } else {
        FILE_GENERIC_READ | READ_CONTROL
    };
    options
        .access_mode(access)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
}

fn destination_path_exists(root: &Dir, path: &Path) -> Result<bool, TransferError> {
    let (components, name) = split_relative_path(path)?;
    let mut parent = root.try_clone().map_err(|_| TransferError::Platform)?;
    for component in components {
        match parent.symlink_metadata(Path::new(&component)) {
            Ok(metadata) if metadata_is_reparse(&metadata) || !metadata.is_dir() => {
                return Err(TransferError::DestinationExists);
            }
            Ok(_) => {
                parent = open_dir_component_no_follow(&parent, Path::new(&component))?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(_) => return Err(TransferError::Platform),
        }
    }
    match parent.symlink_metadata(Path::new(&name)) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(TransferError::Platform),
    }
}

fn identity(metadata: &Metadata) -> ObjectIdentity {
    ObjectIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

fn file_identity(file: &File) -> Result<ObjectIdentity, TransferError> {
    let metadata = file.metadata().map_err(|_| TransferError::Platform)?;
    if metadata_is_reparse(&metadata) || !metadata.is_file() {
        return Err(TransferError::Platform);
    }
    Ok(identity(&metadata))
}

fn directory_identity(directory: &Dir) -> Result<ObjectIdentity, TransferError> {
    let metadata = directory
        .dir_metadata()
        .map_err(|_| TransferError::Platform)?;
    if metadata_is_reparse(&metadata) || !metadata.is_dir() {
        return Err(TransferError::Platform);
    }
    Ok(identity(&metadata))
}

fn rollback_published(published: &mut Vec<PublishedEntry>) -> Result<(), TransferError> {
    if published.is_empty() {
        return Ok(());
    }
    // std/cap-std has no portable conditional-unlink primitive bound to an
    // opened `(device, inode)`. Destination parents are user-controlled, so a
    // verify-then-unlink rollback could delete a replacement installed in the
    // gap. Retain every published name and force the caller to poison the
    // operation for authenticated/manual cleanup.
    published.clear();
    Err(TransferError::Platform)
}

#[cfg(not(windows))]
fn sync_directory(directory: &Dir) -> Result<(), TransferError> {
    directory
        .try_clone()
        .and_then(|clone| clone.into_std_file().sync_all())
        .map_err(|_| TransferError::Platform)
}

#[cfg(windows)]
#[allow(clippy::unnecessary_wraps)]
fn sync_directory(_directory: &Dir) -> Result<(), TransferError> {
    // Windows does not provide a supported FlushFileBuffers equivalent for
    // directory handles through std/cap-std. File data is still flushed; the
    // directory-entry durability limitation is reported by the platform API.
    Ok(())
}

fn map_create_error(error: &std::io::Error) -> TransferError {
    if error.kind() == std::io::ErrorKind::AlreadyExists {
        TransferError::DestinationExists
    } else {
        TransferError::Platform
    }
}

fn remove_active_transfer(staging: &Dir, active: ActiveTransfer) -> Result<(), TransferError> {
    let ActiveTransfer {
        _lease: lease,
        directory,
        progress_name,
        progress,
        ..
    } = active;
    require_private_directory(&directory)?;
    require_private_file(&progress)?;
    let progress_identity = file_identity(&progress)?;
    drop(progress);
    remove_transfer_directory(staging, directory)?;
    remove_named_file_if_identity(staging, Path::new(&progress_name), progress_identity)?;
    sync_directory(staging)?;
    drop(lease);
    Ok(())
}

fn cleanup_unopened_transfer(
    staging: &Dir,
    directory: Dir,
    progress_name: &OsString,
    progress: File,
) -> Result<(), TransferError> {
    let progress_identity = file_identity(&progress)?;
    drop(progress);
    remove_transfer_directory(staging, directory)?;
    remove_named_file_if_identity(staging, Path::new(&progress_name), progress_identity)?;
    sync_directory(staging)
}

fn remove_transfer_directory(staging: &Dir, directory: Dir) -> Result<(), TransferError> {
    directory
        .remove_open_dir_all()
        .map_err(|_| TransferError::Platform)?;
    sync_directory(staging)
}

fn remove_persisted_transfer(staging: &Dir, transfer: TransferId) -> Result<(), TransferError> {
    require_private_directory(staging)?;
    let directory_name = transfer_directory_name(transfer);
    let progress_name = transfer_progress_name(transfer);
    let directory = match staging.symlink_metadata(Path::new(&directory_name)) {
        Ok(metadata) if metadata_is_reparse(&metadata) || !metadata.is_dir() => {
            return Err(TransferError::InvalidResumeState);
        }
        Ok(_) => Some(open_dir_component_no_follow(
            staging,
            Path::new(&directory_name),
        )?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => return Err(TransferError::Platform),
    };
    let progress = match staging.symlink_metadata(Path::new(&progress_name)) {
        Ok(metadata) if metadata_is_reparse(&metadata) || !metadata.is_file() => {
            return Err(TransferError::InvalidResumeState);
        }
        Ok(_) => Some(open_private_file_component_no_follow(
            staging,
            Path::new(&progress_name),
            true,
        )?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => return Err(TransferError::Platform),
    };
    let progress_identity = progress.as_ref().map(file_identity).transpose()?;

    if let Some(directory) = directory.as_ref() {
        require_private_directory(directory).map_err(|_| TransferError::InvalidResumeState)?;
    }
    if let Some(progress) = progress.as_ref() {
        require_private_file(progress).map_err(|_| TransferError::InvalidResumeState)?;
    }

    if let Some(directory) = directory {
        remove_transfer_directory(staging, directory)?;
    }
    if let (Some(progress), Some(expected)) = (progress, progress_identity) {
        drop(progress);
        remove_named_file_if_identity(staging, Path::new(&progress_name), expected)?;
    }
    sync_directory(staging)
}

fn cleanup_created_file(parent: &Dir, name: &Path, file: File) -> Result<(), TransferError> {
    let identity = file_identity(&file)?;
    drop(file);
    remove_named_file_if_identity(parent, name, identity)
}

fn remove_named_file_if_identity(
    parent: &Dir,
    name: &Path,
    expected: ObjectIdentity,
) -> Result<(), TransferError> {
    // This helper is restricted to the private staging root, protected by the
    // process-wide operation lease plus mode 0700 or an exact owner-only DACL.
    // Portable filesystems still cannot defend the final name unlink against a
    // malicious process running as the same OS user; identity mismatch always
    // fails without deletion.
    match parent.symlink_metadata(name) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(TransferError::Platform),
        Ok(metadata) if metadata_is_reparse(&metadata) || !metadata.is_file() => {
            return Err(TransferError::Platform);
        }
        Ok(_) => {}
    }
    let current = open_private_file_component_no_follow(parent, name, false)?;
    if file_identity(&current)? != expected {
        return Err(TransferError::Platform);
    }
    drop(current);
    parent
        .remove_file(name)
        .map_err(|_| TransferError::Platform)?;
    sync_directory(parent)
}

#[cfg(windows)]
fn metadata_is_reparse(metadata: &Metadata) -> bool {
    use cap_fs_ext::OsMetadataExt as _;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn metadata_is_reparse(metadata: &Metadata) -> bool {
    metadata.file_type().is_symlink()
}

#[cfg(unix)]
fn make_private_directory(directory: &Dir) -> Result<(), TransferError> {
    use std::os::unix::fs::PermissionsExt as _;

    directory
        .try_clone()
        .and_then(|clone| {
            clone
                .into_std_file()
                .set_permissions(fs::Permissions::from_mode(0o700))
        })
        .map_err(|_| TransferError::Platform)
}

#[cfg(unix)]
fn make_private_file(file: &File) -> Result<(), TransferError> {
    use cap_std::fs::PermissionsExt as _;

    file.set_permissions(cap_std::fs::Permissions::from_mode(0o600))
        .map_err(|_| TransferError::Platform)
}

#[cfg(windows)]
fn make_private_file(file: &File) -> Result<(), TransferError> {
    let handle = file
        .try_clone()
        .map_err(|_| TransferError::Platform)?
        .into_std();
    windows_acl::protect_owner_only_file(&handle).map_err(|_| TransferError::Platform)
}

#[cfg(not(any(unix, windows)))]
#[allow(clippy::unnecessary_wraps)]
fn make_private_directory(_directory: &Dir) -> Result<(), TransferError> {
    Ok(())
}

#[cfg(not(any(unix, windows)))]
#[allow(clippy::unnecessary_wraps)]
fn make_private_file(_file: &File) -> Result<(), TransferError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;
    use crate::{ManifestEntry, RelativePath};

    fn temporary_directory() -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("nodavo-transfer-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&path).unwrap();
        path
    }

    #[tokio::test]
    async fn stages_verifies_and_publishes_without_overwrite() {
        let root = temporary_directory();
        let payload = b"bounded transfer";
        let manifest = TransferManifest::new(vec![ManifestEntry {
            path: RelativePath::parse("received.txt").unwrap(),
            kind: EntryKind::File,
            size: payload.len() as u64,
            hash: Some(ContentHash::digest(payload)),
        }])
        .unwrap();
        let transfer = TransferId::new();
        let mut staging = FileSystemStagingArea::new(&root).unwrap();
        staging.begin(transfer, &manifest).await.unwrap();
        staging
            .write(TransferChunk {
                transfer,
                entry_index: 0,
                offset: 0,
                bytes: Bytes::copy_from_slice(payload),
            })
            .await
            .unwrap();
        staging.finalize(transfer).await.unwrap();
        assert_eq!(fs::read(root.join("received.txt")).unwrap(), payload);
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn refuses_an_existing_destination() {
        let root = temporary_directory();
        fs::write(root.join("received.txt"), b"keep me").unwrap();
        let manifest = TransferManifest::new(vec![ManifestEntry {
            path: RelativePath::parse("received.txt").unwrap(),
            kind: EntryKind::File,
            size: 0,
            hash: Some(ContentHash::digest(b"")),
        }])
        .unwrap();
        let transfer = TransferId::new();
        let mut staging = FileSystemStagingArea::new(&root).unwrap();
        staging.begin(transfer, &manifest).await.unwrap();
        assert_eq!(
            staging.finalize(transfer).await,
            Err(TransferError::DestinationExists)
        );
        assert_eq!(fs::read(root.join("received.txt")).unwrap(), b"keep me");
        staging.abort(transfer);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn destination_root_symlink_is_rejected_without_following_it() {
        use std::os::unix::fs::symlink;

        let root = temporary_directory();
        let alias = root.with_extension("alias");
        symlink(&root, &alias).unwrap();
        assert!(matches!(
            FileSystemStagingArea::new(&alias),
            Err(TransferError::Platform)
        ));
        fs::remove_file(alias).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn existing_permissive_staging_root_is_rejected_without_repair() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let root = temporary_directory();
        let staging = root.join(STAGING_DIRECTORY_NAME);
        fs::create_dir(&staging).unwrap();
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o755)).unwrap();

        assert!(matches!(
            FileSystemStagingArea::new(&root),
            Err(TransferError::Platform)
        ));
        assert_eq!(fs::metadata(&staging).unwrap().mode() & 0o777, 0o755);
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn later_publish_conflict_retains_earlier_identity_without_overwrite() {
        let root = temporary_directory();
        let first = b"first";
        let second = b"second";
        let manifest = TransferManifest::new(vec![
            ManifestEntry {
                path: RelativePath::parse("a.txt").unwrap(),
                kind: EntryKind::File,
                size: first.len() as u64,
                hash: Some(ContentHash::digest(first)),
            },
            ManifestEntry {
                path: RelativePath::parse("b.txt").unwrap(),
                kind: EntryKind::File,
                size: second.len() as u64,
                hash: Some(ContentHash::digest(second)),
            },
        ])
        .unwrap();
        let transfer = TransferId::new();
        let mut staging = FileSystemStagingArea::new(&root).unwrap();
        staging.begin(transfer, &manifest).await.unwrap();
        for (entry_index, payload) in [first.as_slice(), second.as_slice()]
            .into_iter()
            .enumerate()
        {
            staging
                .write(TransferChunk {
                    transfer,
                    entry_index: u32::try_from(entry_index).unwrap(),
                    offset: 0,
                    bytes: Bytes::copy_from_slice(payload),
                })
                .await
                .unwrap();
        }

        let active = staging.active.as_ref().unwrap();
        preflight_destination(&staging.destination, &active.manifest).unwrap();
        let conflict = root.join("b.txt");
        let result = publish_entries_with_hook(&staging.destination, active, |entry| {
            if entry.path.as_str() == "b.txt" {
                fs::write(&conflict, b"do not overwrite").unwrap();
            }
        });

        assert_eq!(result, Err(TransferError::Platform));
        assert_eq!(fs::read(root.join("a.txt")).unwrap(), first);
        assert_eq!(fs::read(&conflict).unwrap(), b"do not overwrite");
        staging.abort(transfer);
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn publication_syncs_each_directory_after_mutation_and_root_last() {
        let root = temporary_directory();
        let payload = b"payload";
        let manifest = TransferManifest::new(vec![
            ManifestEntry {
                path: RelativePath::parse("nested").unwrap(),
                kind: EntryKind::Directory,
                size: 0,
                hash: None,
            },
            ManifestEntry {
                path: RelativePath::parse("nested/file.txt").unwrap(),
                kind: EntryKind::File,
                size: payload.len() as u64,
                hash: Some(ContentHash::digest(payload)),
            },
        ])
        .unwrap();
        let transfer = TransferId::new();
        let mut staging = FileSystemStagingArea::new(&root).unwrap();
        staging.begin(transfer, &manifest).await.unwrap();
        staging
            .write(TransferChunk {
                transfer,
                entry_index: 1,
                offset: 0,
                bytes: Bytes::copy_from_slice(payload),
            })
            .await
            .unwrap();

        let active = staging.active.as_ref().unwrap();
        let mut published = Vec::new();
        publish_entries_inner(&staging.destination, active, &mut published, &mut |_| {}).unwrap();
        let root_identity = directory_identity(&staging.destination).unwrap();
        let mut order = Vec::new();
        sync_published_directories_with(&staging.destination, &published, |directory| {
            order.push(directory_identity(directory)?);
            Ok(())
        })
        .unwrap();
        assert_eq!(order.last(), Some(&root_identity));
        assert_eq!(
            order.iter().copied().collect::<HashSet<_>>().len(),
            order.len()
        );
        assert!(order.len() >= 2);

        assert_eq!(
            rollback_published(&mut published),
            Err(TransferError::Platform)
        );
        fs::remove_file(root.join("nested/file.txt")).unwrap();
        fs::remove_dir(root.join("nested")).unwrap();
        staging.try_abort(transfer).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn rollback_failure_poisoning_retains_a_substituted_destination() {
        let root = temporary_directory();
        let first = b"first";
        let second = b"second";
        let manifest = TransferManifest::new(vec![
            ManifestEntry {
                path: RelativePath::parse("a.txt").unwrap(),
                kind: EntryKind::File,
                size: first.len() as u64,
                hash: Some(ContentHash::digest(first)),
            },
            ManifestEntry {
                path: RelativePath::parse("b.txt").unwrap(),
                kind: EntryKind::File,
                size: second.len() as u64,
                hash: Some(ContentHash::digest(second)),
            },
        ])
        .unwrap();
        let transfer = TransferId::new();
        let mut staging = FileSystemStagingArea::new(&root).unwrap();
        staging.begin(transfer, &manifest).await.unwrap();
        for (entry_index, payload) in [first.as_slice(), second.as_slice()]
            .into_iter()
            .enumerate()
        {
            staging
                .write(TransferChunk {
                    transfer,
                    entry_index: u32::try_from(entry_index).unwrap(),
                    offset: 0,
                    bytes: Bytes::copy_from_slice(payload),
                })
                .await
                .unwrap();
        }

        let first_destination = root.join("a.txt");
        let second_destination = root.join("b.txt");
        let result = staging.finalize_with_hook(transfer, |entry| {
            if entry.path.as_str() == "b.txt" {
                fs::remove_file(&first_destination).unwrap();
                fs::write(&first_destination, b"replacement").unwrap();
                fs::write(&second_destination, b"conflict").unwrap();
            }
        });
        assert_eq!(result, Err(TransferError::Platform));
        assert_eq!(fs::read(&first_destination).unwrap(), b"replacement");
        assert_eq!(fs::read(&second_destination).unwrap(), b"conflict");
        assert!(staging.cleanup_failed);
        assert_eq!(
            staging.finalize(transfer).await,
            Err(TransferError::Platform)
        );
        assert_eq!(staging.try_abort(transfer), Err(TransferError::Platform));
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn staged_intermediate_symlink_substitution_cannot_redirect_writes() {
        use std::os::unix::fs::symlink;

        let root = temporary_directory();
        let outside = temporary_directory();
        fs::write(outside.join("received.txt"), b"outside").unwrap();
        let payload = b"bounded";
        let manifest = TransferManifest::new(vec![ManifestEntry {
            path: RelativePath::parse("nested/received.txt").unwrap(),
            kind: EntryKind::File,
            size: payload.len() as u64,
            hash: Some(ContentHash::digest(payload)),
        }])
        .unwrap();
        let transfer = TransferId::new();
        let mut staging = FileSystemStagingArea::new(&root).unwrap();
        staging.begin(transfer, &manifest).await.unwrap();

        let transfer_root = transfer_directory(&root.join(STAGING_DIRECTORY_NAME), transfer);
        fs::remove_file(transfer_root.join("nested/received.txt")).unwrap();
        fs::remove_dir(transfer_root.join("nested")).unwrap();
        symlink(&outside, transfer_root.join("nested")).unwrap();

        assert_eq!(
            staging
                .write(TransferChunk {
                    transfer,
                    entry_index: 0,
                    offset: 0,
                    bytes: Bytes::copy_from_slice(payload),
                })
                .await,
            Err(TransferError::Platform)
        );
        assert_eq!(fs::read(outside.join("received.txt")).unwrap(), b"outside");
        staging.abort(transfer);
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(outside).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn destination_symlink_substitution_cannot_redirect_finalize() {
        use std::os::unix::fs::symlink;

        let root = temporary_directory();
        let outside = temporary_directory();
        let payload = b"bounded";
        let manifest = TransferManifest::new(vec![ManifestEntry {
            path: RelativePath::parse("nested/received.txt").unwrap(),
            kind: EntryKind::File,
            size: payload.len() as u64,
            hash: Some(ContentHash::digest(payload)),
        }])
        .unwrap();
        let transfer = TransferId::new();
        let mut staging = FileSystemStagingArea::new(&root).unwrap();
        staging.begin(transfer, &manifest).await.unwrap();
        staging
            .write(TransferChunk {
                transfer,
                entry_index: 0,
                offset: 0,
                bytes: Bytes::copy_from_slice(payload),
            })
            .await
            .unwrap();
        symlink(&outside, root.join("nested")).unwrap();

        assert_eq!(
            staging.finalize(transfer).await,
            Err(TransferError::DestinationExists)
        );
        assert!(!outside.join("received.txt").exists());
        staging.abort(transfer);
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(outside).unwrap();
    }

    #[tokio::test]
    async fn resumes_from_durable_offset_and_discards_torn_tail() {
        let root = temporary_directory();
        let payload = b"resumable bounded transfer";
        let manifest = TransferManifest::new(vec![ManifestEntry {
            path: RelativePath::parse("resume/received.txt").unwrap(),
            kind: EntryKind::File,
            size: payload.len() as u64,
            hash: Some(ContentHash::digest(payload)),
        }])
        .unwrap();
        let transfer = TransferId::new();
        let split = 9_usize;
        {
            let mut staging = FileSystemStagingArea::new(&root).unwrap();
            staging.begin(transfer, &manifest).await.unwrap();
            staging
                .write(TransferChunk {
                    transfer,
                    entry_index: 0,
                    offset: 0,
                    bytes: Bytes::copy_from_slice(&payload[..split]),
                })
                .await
                .unwrap();
        }

        let staging_root = root.join(STAGING_DIRECTORY_NAME);
        let data_path = transfer_directory(&staging_root, transfer).join("resume/received.txt");
        fs::OpenOptions::new()
            .append(true)
            .open(&data_path)
            .unwrap()
            .write_all(b"uncommitted-tail")
            .unwrap();
        fs::OpenOptions::new()
            .append(true)
            .open(transfer_progress_path(&staging_root, transfer))
            .unwrap()
            .write_all(&[1, 2, 3])
            .unwrap();

        let mut resumed = FileSystemStagingArea::new(&root).unwrap();
        let state = resumed.resume(transfer, &manifest).unwrap();
        assert_eq!(state.transfer(), transfer);
        assert_eq!(state.next_offset(0), Some(split as u64));
        assert_eq!(fs::metadata(&data_path).unwrap().len(), split as u64);
        resumed
            .write(TransferChunk {
                transfer,
                entry_index: 0,
                offset: split as u64,
                bytes: Bytes::copy_from_slice(&payload[split..]),
            })
            .await
            .unwrap();
        resumed.finalize(transfer).await.unwrap();
        assert_eq!(fs::read(root.join("resume/received.txt")).unwrap(), payload);
        assert!(!transfer_progress_path(&staging_root, transfer).exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn resume_rejects_a_different_manifest() {
        let root = temporary_directory();
        let manifest = TransferManifest::new(vec![ManifestEntry {
            path: RelativePath::parse("received.txt").unwrap(),
            kind: EntryKind::File,
            size: 1,
            hash: Some(ContentHash::digest(b"a")),
        }])
        .unwrap();
        let different = TransferManifest::new(vec![ManifestEntry {
            path: RelativePath::parse("received.txt").unwrap(),
            kind: EntryKind::File,
            size: 1,
            hash: Some(ContentHash::digest(b"b")),
        }])
        .unwrap();
        let transfer = TransferId::new();
        {
            let mut staging = FileSystemStagingArea::new(&root).unwrap();
            staging.begin(transfer, &manifest).await.unwrap();
        }
        let mut resumed = FileSystemStagingArea::new(&root).unwrap();
        assert_eq!(
            resumed.resume(transfer, &different),
            Err(TransferError::InvalidResumeState)
        );
        resumed.discard_persisted(transfer).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn unopened_discard_is_transfer_scoped_and_refuses_active_state() {
        let root = temporary_directory();
        let manifest = TransferManifest::new(vec![ManifestEntry {
            path: RelativePath::parse("received.txt").unwrap(),
            kind: EntryKind::File,
            size: 1,
            hash: Some(ContentHash::digest(b"a")),
        }])
        .unwrap();
        let first = TransferId::new();
        let second = TransferId::new();
        {
            let mut staging = FileSystemStagingArea::new(&root).unwrap();
            staging.begin(first, &manifest).await.unwrap();
            assert_eq!(
                staging.discard_unopened_persisted(first),
                Err(TransferError::TransferNotActive)
            );
        }
        {
            let mut staging = FileSystemStagingArea::new(&root).unwrap();
            staging.begin(second, &manifest).await.unwrap();
        }

        let mut staging = FileSystemStagingArea::new(&root).unwrap();
        assert!(staging.has_persisted(first).unwrap());
        assert!(staging.has_persisted(second).unwrap());
        staging.discard_unopened_persisted(first).unwrap();
        assert!(!staging.has_persisted(first).unwrap());
        assert!(staging.has_persisted(second).unwrap());
        staging.discard_unopened_persisted(second).unwrap();
        let retained = fs::read_dir(root.join(STAGING_DIRECTORY_NAME))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].file_name(), OPERATION_LEASE_NAME);
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn transfer_lease_blocks_resume_and_discard_from_another_instance() {
        let root = temporary_directory();
        let manifest = TransferManifest::new(vec![ManifestEntry {
            path: RelativePath::parse("received.txt").unwrap(),
            kind: EntryKind::File,
            size: 1,
            hash: Some(ContentHash::digest(b"a")),
        }])
        .unwrap();
        let transfer = TransferId::new();
        let mut first = FileSystemStagingArea::new(&root).unwrap();
        first.begin(transfer, &manifest).await.unwrap();

        let mut second = FileSystemStagingArea::new(&root).unwrap();
        assert_eq!(
            second.discard_unopened_persisted(transfer),
            Err(TransferError::TransferNotActive)
        );
        assert_eq!(
            second.resume(transfer, &manifest),
            Err(TransferError::TransferNotActive)
        );

        drop(first);
        second.discard_unopened_persisted(transfer).unwrap();
        assert!(!second.has_persisted(transfer).unwrap());
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn peer_scopes_isolate_the_same_wire_transfer_id() {
        let root = temporary_directory();
        let manifest = TransferManifest::new(vec![ManifestEntry {
            path: RelativePath::parse("received.txt").unwrap(),
            kind: EntryKind::File,
            size: 1,
            hash: Some(ContentHash::digest(b"a")),
        }])
        .unwrap();
        let transfer = TransferId::from_bytes([71; 16]);
        {
            let mut first = FileSystemStagingArea::new_scoped(&root, [1; 32]).unwrap();
            first.begin(transfer, &manifest).await.unwrap();
            first
                .write(TransferChunk {
                    transfer,
                    entry_index: 0,
                    offset: 0,
                    bytes: bytes::Bytes::from_static(b"a"),
                })
                .await
                .unwrap();
        }

        let mut second = FileSystemStagingArea::new_scoped(&root, [2; 32]).unwrap();
        assert!(!second.has_persisted(transfer).unwrap());
        assert!(second.resume(transfer, &manifest).is_err());
        second.discard_unopened_persisted(transfer).unwrap();

        let mut first = FileSystemStagingArea::new_scoped(&root, [1; 32]).unwrap();
        assert!(first.has_persisted(transfer).unwrap());
        first.discard_unopened_persisted(transfer).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn abort_surfaces_substituted_cleanup_and_poisoned_instance() {
        use std::os::unix::fs::symlink;

        let root = temporary_directory();
        let outside = root.join("outside.txt");
        fs::write(&outside, b"outside").unwrap();
        let manifest = TransferManifest::new(vec![ManifestEntry {
            path: RelativePath::parse("received.txt").unwrap(),
            kind: EntryKind::File,
            size: 1,
            hash: Some(ContentHash::digest(b"a")),
        }])
        .unwrap();
        let transfer = TransferId::new();
        let mut staging = FileSystemStagingArea::new(&root).unwrap();
        staging.begin(transfer, &manifest).await.unwrap();
        let staging_root = root.join(STAGING_DIRECTORY_NAME);
        let progress = transfer_progress_path(&staging_root, transfer);
        fs::rename(&progress, progress.with_extension("saved")).unwrap();
        symlink(&outside, &progress).unwrap();

        assert_eq!(staging.try_abort(transfer), Err(TransferError::Platform));
        assert_eq!(
            staging.try_abort(transfer),
            Err(TransferError::Platform),
            "cleanup poison must be sticky and retries may never report success"
        );
        assert_eq!(fs::read(&outside).unwrap(), b"outside");
        assert_eq!(
            staging.begin(TransferId::new(), &manifest).await,
            Err(TransferError::Platform)
        );
        fs::remove_dir_all(root).unwrap();
    }
}
