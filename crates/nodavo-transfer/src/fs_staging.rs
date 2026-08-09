//! Filesystem-backed private staging with content verification and no-overwrite finalization.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::{
    ContentHash, EntryKind, ResumeState, StagingArea, TransferChunk, TransferError, TransferFuture,
    TransferId, TransferManifest,
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

/// A single-transfer filesystem staging area rooted inside the destination filesystem.
///
/// Placing the private staging directory below the destination keeps final hard links
/// on one filesystem. Each destination file is created with no-overwrite semantics;
/// received content is never executed or opened automatically.
pub struct FileSystemStagingArea {
    destination_root: PathBuf,
    staging_root: PathBuf,
    active: Option<ActiveTransfer>,
}

struct ActiveTransfer {
    id: TransferId,
    directory: PathBuf,
    progress_path: PathBuf,
    progress: File,
    progress_records: usize,
    manifest: TransferManifest,
    written: HashMap<usize, u64>,
}

impl FileSystemStagingArea {
    /// Opens an existing, non-symlink destination directory and prepares a private
    /// staging directory below it.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::Platform`] if the destination is missing, is a
    /// symlink, is not a directory, or cannot host a private staging directory.
    pub fn new(destination_root: impl AsRef<Path>) -> Result<Self, TransferError> {
        let destination_root = destination_root.as_ref();
        require_real_directory(destination_root)?;
        let destination_root = destination_root
            .canonicalize()
            .map_err(|_| TransferError::Platform)?;
        let staging_root = destination_root.join(STAGING_DIRECTORY_NAME);
        match fs::symlink_metadata(&staging_root) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(TransferError::Platform);
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&staging_root).map_err(|_| TransferError::Platform)?;
            }
            Err(_) => return Err(TransferError::Platform),
        }
        make_private(&staging_root)?;
        Ok(Self {
            destination_root,
            staging_root,
            active: None,
        })
    }

    fn active_mut(&mut self, transfer: TransferId) -> Result<&mut ActiveTransfer, TransferError> {
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
        if self.active.is_some() {
            return Err(TransferError::TransferNotActive);
        }
        require_real_directory(&self.destination_root)?;
        require_real_directory(&self.staging_root)?;

        let directory = transfer_directory(&self.staging_root, transfer);
        let progress_path = transfer_progress_path(&self.staging_root, transfer);
        require_real_directory(&directory).map_err(|_| TransferError::InvalidResumeState)?;
        let (mut progress, written, progress_records) =
            load_progress(&progress_path, manifest, &directory)?;
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
            directory,
            progress_path,
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
                self.abort(transfer);
                return Ok(());
            }
            return Err(TransferError::TransferNotActive);
        }
        remove_private_tree(&transfer_directory(&self.staging_root, transfer));
        remove_progress_file(&transfer_progress_path(&self.staging_root, transfer));
        Ok(())
    }
}

impl StagingArea for FileSystemStagingArea {
    fn begin<'a>(
        &'a mut self,
        transfer: TransferId,
        manifest: &'a TransferManifest,
    ) -> TransferFuture<'a, Result<(), TransferError>> {
        Box::pin(async move {
            if self.active.is_some() {
                return Err(TransferError::TransferNotActive);
            }
            require_real_directory(&self.destination_root)?;
            require_real_directory(&self.staging_root)?;

            let directory = transfer_directory(&self.staging_root, transfer);
            let progress_path = transfer_progress_path(&self.staging_root, transfer);
            if fs::symlink_metadata(&progress_path).is_ok() {
                return Err(TransferError::DestinationExists);
            }
            fs::create_dir(&directory).map_err(|error| map_create_error(&error))?;
            make_private(&directory)?;

            let result = prepare_entries(&directory, manifest);
            if let Err(error) = result {
                remove_private_tree(&directory);
                return Err(error);
            }

            let progress = match create_progress(&progress_path, manifest) {
                Ok(progress) => progress,
                Err(error) => {
                    remove_private_tree(&directory);
                    return Err(error);
                }
            };

            let written = manifest
                .entries()
                .iter()
                .enumerate()
                .filter_map(|(index, entry)| (entry.kind == EntryKind::File).then_some((index, 0)))
                .collect();
            self.active = Some(ActiveTransfer {
                id: transfer,
                directory,
                progress_path,
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
            let path = active.directory.join(entry.path.as_str());
            require_regular_file(&path)?;
            let mut file = OpenOptions::new()
                .write(true)
                .open(path)
                .map_err(|_| TransferError::Platform)?;
            file.seek(SeekFrom::Start(chunk.offset))
                .map_err(|_| TransferError::Platform)?;
            file.write_all(&chunk.bytes)
                .map_err(|_| TransferError::Platform)?;
            file.sync_data().map_err(|_| TransferError::Platform)?;
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
        Box::pin(async move {
            let active = self
                .active
                .as_ref()
                .filter(|active| active.id == transfer)
                .ok_or(TransferError::TransferNotActive)?;
            verify_complete(active)?;
            preflight_destination(&self.destination_root, &active.manifest)?;
            publish_entries(&self.destination_root, active)?;

            let directory = active.directory.clone();
            let progress_path = active.progress_path.clone();
            self.active = None;
            remove_private_tree(&directory);
            remove_progress_file(&progress_path);
            Ok(())
        })
    }

    fn abort(&mut self, transfer: TransferId) {
        let Some(active) = self.active.take() else {
            return;
        };
        if active.id == transfer {
            remove_private_tree(&active.directory);
            remove_progress_file(&active.progress_path);
        } else {
            self.active = Some(active);
        }
    }
}

impl Drop for FileSystemStagingArea {
    fn drop(&mut self) {
        if let Some(active) = self.active.as_mut() {
            // Leaving private staging in place is what makes process-restart
            // resume possible. Explicit cancellation must call `abort`.
            let _ = active.progress.sync_all();
        }
    }
}

fn transfer_directory(root: &Path, transfer: TransferId) -> PathBuf {
    root.join(format!("{}.data", transfer.as_uuid()))
}

fn transfer_progress_path(root: &Path, transfer: TransferId) -> PathBuf {
    root.join(format!("{}.progress", transfer.as_uuid()))
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

fn create_progress(path: &Path, manifest: &TransferManifest) -> Result<File, TransferError> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| map_create_error(&error))?;
    if let Err(error) = make_private_file(path) {
        drop(file);
        remove_progress_file(path);
        return Err(error);
    }
    let entry_count =
        u32::try_from(manifest.entries().len()).map_err(|_| TransferError::InvalidManifest)?;
    let mut header = Vec::with_capacity(PROGRESS_HEADER_BYTES);
    header.extend_from_slice(PROGRESS_MAGIC);
    header.extend_from_slice(&manifest_fingerprint(manifest));
    header.extend_from_slice(&entry_count.to_be_bytes());
    let result = file.write_all(&header).and_then(|()| file.sync_all());
    if result.is_err() {
        drop(file);
        remove_progress_file(path);
        return Err(TransferError::Platform);
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
        .and_then(|()| progress.sync_data())
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
    path: &Path,
    manifest: &TransferManifest,
    directory: &Path,
) -> Result<(File, HashMap<usize, u64>, usize), TransferError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| TransferError::InvalidResumeState)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() < PROGRESS_HEADER_BYTES as u64
        || metadata.len() > MAX_PROGRESS_BYTES
    {
        return Err(TransferError::InvalidResumeState);
    }
    let mut progress = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|_| TransferError::InvalidResumeState)?;
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
    directory: &Path,
    manifest: &TransferManifest,
    written: &HashMap<usize, u64>,
) -> Result<(), TransferError> {
    for (index, entry) in manifest.entries().iter().enumerate() {
        let path = directory.join(entry.path.as_str());
        match entry.kind {
            EntryKind::Directory => {
                require_real_directory(&path).map_err(|_| TransferError::InvalidResumeState)?;
            }
            EntryKind::File => {
                require_regular_file(&path).map_err(|_| TransferError::InvalidResumeState)?;
                let expected = written
                    .get(&index)
                    .copied()
                    .ok_or(TransferError::InvalidResumeState)?;
                let actual = fs::metadata(&path)
                    .map_err(|_| TransferError::InvalidResumeState)?
                    .len();
                if actual < expected {
                    return Err(TransferError::InvalidResumeState);
                }
                if actual > expected {
                    let file = OpenOptions::new()
                        .write(true)
                        .open(&path)
                        .map_err(|_| TransferError::InvalidResumeState)?;
                    file.set_len(expected)
                        .and_then(|()| file.sync_all())
                        .map_err(|_| TransferError::Platform)?;
                }
            }
        }
    }
    Ok(())
}

fn prepare_entries(root: &Path, manifest: &TransferManifest) -> Result<(), TransferError> {
    for entry in manifest.entries() {
        let path = root.join(entry.path.as_str());
        let parent = path.parent().ok_or(TransferError::InvalidPath)?;
        create_private_directories(root, parent)?;
        match entry.kind {
            EntryKind::Directory => match fs::create_dir(&path) {
                Ok(()) => make_private(&path)?,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    require_real_directory(&path)?;
                }
                Err(_) => return Err(TransferError::Platform),
            },
            EntryKind::File => {
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(path)
                    .map_err(|error| map_create_error(&error))?;
            }
        }
    }
    Ok(())
}

fn create_private_directories(root: &Path, target: &Path) -> Result<(), TransferError> {
    let relative = target
        .strip_prefix(root)
        .map_err(|_| TransferError::InvalidPath)?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component);
        match fs::create_dir(&current) {
            Ok(()) => make_private(&current)?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                require_real_directory(&current)?;
            }
            Err(_) => return Err(TransferError::Platform),
        }
    }
    Ok(())
}

fn verify_complete(active: &ActiveTransfer) -> Result<(), TransferError> {
    for (index, entry) in active.manifest.entries().iter().enumerate() {
        let path = active.directory.join(entry.path.as_str());
        match entry.kind {
            EntryKind::Directory => require_real_directory(&path)?,
            EntryKind::File => {
                if active.written.get(&index).copied() != Some(entry.size) {
                    return Err(TransferError::IntegrityMismatch);
                }
                require_regular_file(&path)?;
                let expected = entry.hash.ok_or(TransferError::InvalidManifest)?;
                if hash_file(&path)? != expected {
                    return Err(TransferError::IntegrityMismatch);
                }
            }
        }
    }
    Ok(())
}

fn preflight_destination(root: &Path, manifest: &TransferManifest) -> Result<(), TransferError> {
    require_real_directory(root)?;
    for entry in manifest.entries() {
        let destination = root.join(entry.path.as_str());
        match fs::symlink_metadata(destination) {
            Ok(_) => return Err(TransferError::DestinationExists),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(TransferError::Platform),
        }
    }
    Ok(())
}

fn publish_entries(root: &Path, active: &ActiveTransfer) -> Result<(), TransferError> {
    let mut directories = active
        .manifest
        .entries()
        .iter()
        .filter(|entry| entry.kind == EntryKind::Directory)
        .collect::<Vec<_>>();
    directories.sort_by_key(|entry| entry.path.as_str().matches('/').count());
    for entry in directories {
        let destination = root.join(entry.path.as_str());
        create_destination_parents(root, &destination)?;
        fs::create_dir(&destination).map_err(|error| map_create_error(&error))?;
    }

    for entry in active
        .manifest
        .entries()
        .iter()
        .filter(|entry| entry.kind == EntryKind::File)
    {
        let source = active.directory.join(entry.path.as_str());
        let destination = root.join(entry.path.as_str());
        create_destination_parents(root, &destination)?;
        fs::hard_link(source, destination).map_err(|error| map_create_error(&error))?;
    }
    Ok(())
}

fn create_destination_parents(root: &Path, destination: &Path) -> Result<(), TransferError> {
    let parent = destination.parent().ok_or(TransferError::InvalidPath)?;
    let relative = parent
        .strip_prefix(root)
        .map_err(|_| TransferError::InvalidPath)?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(TransferError::DestinationExists);
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&current).map_err(|error| map_create_error(&error))?;
            }
            Err(_) => return Err(TransferError::Platform),
        }
    }
    Ok(())
}

fn hash_file(path: &Path) -> Result<ContentHash, TransferError> {
    let mut file = File::open(path).map_err(|_| TransferError::Platform)?;
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

fn require_real_directory(path: &Path) -> Result<(), TransferError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| TransferError::Platform)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(TransferError::Platform);
    }
    Ok(())
}

fn require_regular_file(path: &Path) -> Result<(), TransferError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| TransferError::Platform)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(TransferError::Platform);
    }
    Ok(())
}

fn map_create_error(error: &std::io::Error) -> TransferError {
    if error.kind() == std::io::ErrorKind::AlreadyExists {
        TransferError::DestinationExists
    } else {
        TransferError::Platform
    }
}

fn remove_private_tree(path: &Path) {
    if fs::symlink_metadata(path)
        .is_ok_and(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
    {
        let _ = fs::remove_dir_all(path);
    }
}

fn remove_progress_file(path: &Path) {
    if fs::symlink_metadata(path)
        .is_ok_and(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
    {
        let _ = fs::remove_file(path);
    }
}

#[cfg(unix)]
fn make_private(path: &Path) -> Result<(), TransferError> {
    use std::os::unix::fs::PermissionsExt as _;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|_| TransferError::Platform)
}

#[cfg(unix)]
fn make_private_file(path: &Path) -> Result<(), TransferError> {
    use std::os::unix::fs::PermissionsExt as _;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|_| TransferError::Platform)
}

#[cfg(not(unix))]
fn make_private(_path: &Path) -> Result<(), TransferError> {
    Ok(())
}

#[cfg(not(unix))]
fn make_private_file(_path: &Path) -> Result<(), TransferError> {
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
        OpenOptions::new()
            .append(true)
            .open(&data_path)
            .unwrap()
            .write_all(b"uncommitted-tail")
            .unwrap();
        OpenOptions::new()
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
}
