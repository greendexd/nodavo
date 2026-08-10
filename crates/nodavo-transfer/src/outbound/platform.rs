//! Platform-specific, no-follow source opening and stable filesystem evidence.

use std::path::Path;
use std::time::SystemTime;

use cap_std::fs::{Dir, File, Metadata, OpenOptions};

use crate::TransferError;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) struct FileIdentity {
    #[cfg(any(unix, windows))]
    device: u64,
    #[cfg(any(unix, windows))]
    inode: u64,
    #[cfg(not(any(unix, windows)))]
    created_nanos: u128,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct StableEvidence {
    pub(super) identity: FileIdentity,
    pub(super) size: u64,
    pub(super) modified: SystemTime,
}

pub(super) fn open_file_no_follow(parent: &Dir, name: &Path) -> Result<File, TransferError> {
    let mut options = OpenOptions::new();
    options.read(true);
    configure_file_options(&mut options);
    let file = parent
        .open_with(name, &options)
        .map_err(|_| TransferError::InvalidSource)?;
    let metadata = file.metadata().map_err(|_| TransferError::InvalidSource)?;
    if !metadata.is_file() || metadata_is_unsafe(&metadata) {
        return Err(TransferError::UnsafeSourceType);
    }
    Ok(file)
}

pub(super) fn open_dir_no_follow(parent: &Dir, name: &Path) -> Result<Dir, TransferError> {
    let mut options = OpenOptions::new();
    options.read(true);
    configure_directory_options(&mut options);
    let file = parent
        .open_with(name, &options)
        .map_err(|_| TransferError::InvalidSource)?;
    let metadata = file.metadata().map_err(|_| TransferError::InvalidSource)?;
    if !metadata.is_dir() || metadata_is_unsafe(&metadata) {
        return Err(TransferError::UnsafeSourceType);
    }
    Ok(Dir::from_std_file(file.into_std()))
}

pub(super) fn file_evidence(file: &File) -> Result<StableEvidence, TransferError> {
    let metadata = file.metadata().map_err(|_| TransferError::InvalidSource)?;
    if !metadata.is_file() || metadata_is_unsafe(&metadata) {
        return Err(TransferError::UnsafeSourceType);
    }
    evidence(&metadata)
}

pub(super) fn directory_identity(directory: &Dir) -> Result<FileIdentity, TransferError> {
    let metadata = directory
        .dir_metadata()
        .map_err(|_| TransferError::InvalidSource)?;
    if !metadata.is_dir() || metadata_is_unsafe(&metadata) {
        return Err(TransferError::UnsafeSourceType);
    }
    Ok(identity(&metadata))
}

fn evidence(metadata: &Metadata) -> Result<StableEvidence, TransferError> {
    Ok(StableEvidence {
        identity: identity(metadata),
        size: metadata.len(),
        modified: metadata
            .modified()
            .map_err(|_| TransferError::InvalidSource)?
            .into_std(),
    })
}

#[cfg(any(unix, windows))]
fn identity(metadata: &Metadata) -> FileIdentity {
    use cap_fs_ext::MetadataExt as _;

    FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

#[cfg(not(any(unix, windows)))]
fn identity(metadata: &Metadata) -> FileIdentity {
    let created_nanos = metadata
        .created()
        .expect("unsupported targets require stable creation time")
        .into_std()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("creation time predates the Unix epoch")
        .as_nanos();
    FileIdentity { created_nanos }
}

#[cfg(unix)]
fn metadata_is_unsafe(metadata: &Metadata) -> bool {
    use cap_fs_ext::OsMetadataExt as _;

    metadata.is_file()
        && metadata.len() != 0
        && metadata.blocks().saturating_mul(512) < metadata.len()
}

#[cfg(windows)]
fn metadata_is_unsafe(metadata: &Metadata) -> bool {
    use cap_fs_ext::OsMetadataExt as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_SPARSE_FILE,
    };

    metadata.file_attributes() & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_SPARSE_FILE) != 0
}

#[cfg(not(any(unix, windows)))]
fn metadata_is_unsafe(_metadata: &Metadata) -> bool {
    false
}

#[cfg(unix)]
fn configure_file_options(options: &mut OpenOptions) {
    use cap_std::fs::OpenOptionsExt as _;

    options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
}

#[cfg(unix)]
fn configure_directory_options(options: &mut OpenOptions) {
    use cap_std::fs::OpenOptionsExt as _;

    options.custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY);
}

#[cfg(windows)]
fn configure_file_options(options: &mut OpenOptions) {
    use cap_std::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;

    options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
}

#[cfg(windows)]
fn configure_directory_options(options: &mut OpenOptions) {
    use cap_std::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    };

    options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS);
}

#[cfg(not(any(unix, windows)))]
fn configure_file_options(_options: &mut OpenOptions) {}

#[cfg(not(any(unix, windows)))]
fn configure_directory_options(_options: &mut OpenOptions) {}
