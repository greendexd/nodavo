//! Safe, streaming file-transfer primitives.
//!
//! Absolute destination paths and native filesystem handles deliberately never
//! enter this crate. Platform adapters receive validated relative paths only.

use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;

use bytes::Bytes;
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;
use uuid::Uuid;

mod fs_staging;
mod outbound;
mod queue;
mod receiver;

pub use fs_staging::FileSystemStagingArea;
pub use outbound::{OutboundResumePoint, OutboundTransferSource};
pub use queue::{
    MAX_ACTIVE_TRANSFERS, MAX_QUEUED_TRANSFERS, QueueEffect, QueuedTransfer, TransferQueue,
    TransferQueueState,
};
pub use receiver::{ActiveReceiveSnapshot, TransferReceiver};

pub const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
pub const MAX_MANIFEST_ENTRIES: usize = 10_000;
pub const MAX_RELATIVE_PATH_BYTES: usize = 1024;
pub const MAX_TRANSFER_BYTES: u64 = 10 * 1024 * 1024 * 1024;
pub const MAX_CHUNK_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TransferId(Uuid);

impl TransferId {
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }

    /// Restores an identifier received from an authenticated transfer manifest.
    #[must_use]
    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    /// Restores an identifier from its authenticated 16-byte wire form.
    #[must_use]
    pub const fn from_bytes(value: [u8; 16]) -> Self {
        Self(Uuid::from_bytes(value))
    }

    /// Returns the stable 16-byte wire form without formatting it for logs.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 16] {
        *self.0.as_bytes()
    }
}

impl Default for TransferId {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContentHash([u8; 32]);

impl ContentHash {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[must_use]
    pub fn digest(bytes: &[u8]) -> Self {
        Self(*blake3::hash(bytes).as_bytes())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RelativePath(String);

impl RelativePath {
    /// Parses a normalized cross-platform relative path.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::InvalidPath`] for absolute paths, traversal,
    /// invalid characters, Windows device names, or paths above the hard limit.
    pub fn parse(input: &str) -> Result<Self, TransferError> {
        if input.is_empty() || input.len() > MAX_RELATIVE_PATH_BYTES {
            return Err(TransferError::InvalidPath);
        }
        if input.starts_with('/') || input.starts_with('\\') || input.contains('\\') {
            return Err(TransferError::InvalidPath);
        }

        let normalized = input.nfc().collect::<String>();
        if normalized.len() > MAX_RELATIVE_PATH_BYTES {
            return Err(TransferError::InvalidPath);
        }

        for segment in normalized.split('/') {
            if segment.is_empty()
                || segment == "."
                || segment == ".."
                || segment.ends_with(['.', ' '])
                || segment.chars().any(is_unsafe_filename_character)
                || is_windows_reserved_name(segment)
            {
                return Err(TransferError::InvalidPath);
            }
        }

        Ok(Self(normalized))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn collision_key(&self) -> String {
        self.0.to_lowercase()
    }
}

fn is_unsafe_filename_character(character: char) -> bool {
    character.is_control() || matches!(character, '\0' | ':' | '*' | '?' | '"' | '<' | '>' | '|')
}

fn is_windows_reserved_name(segment: &str) -> bool {
    let stem = segment
        .split('.')
        .next()
        .unwrap_or(segment)
        .to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || stem
            .strip_prefix("COM")
            .or_else(|| stem.strip_prefix("LPT"))
            .is_some_and(|suffix| {
                suffix.len() == 1 && matches!(suffix.as_bytes().first(), Some(b'1'..=b'9'))
            })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Directory,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestEntry {
    pub path: RelativePath,
    pub kind: EntryKind,
    pub size: u64,
    pub hash: Option<ContentHash>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferManifest {
    entries: Vec<ManifestEntry>,
    total_bytes: u64,
}

impl TransferManifest {
    /// Validates and constructs a bounded transfer manifest.
    ///
    /// # Errors
    ///
    /// Returns an error for empty or oversized manifests, path collisions,
    /// invalid entry metadata, or aggregate content above the transfer limit.
    pub fn new(entries: Vec<ManifestEntry>) -> Result<Self, TransferError> {
        if entries.is_empty() || entries.len() > MAX_MANIFEST_ENTRIES {
            return Err(TransferError::InvalidManifest);
        }

        let mut estimated_size = 0_usize;
        let mut total_bytes = 0_u64;
        let mut collision_keys = HashSet::with_capacity(entries.len());
        for entry in &entries {
            estimated_size = estimated_size
                .checked_add(entry.path.as_str().len() + 64)
                .ok_or(TransferError::ManifestTooLarge)?;
            if estimated_size > MAX_MANIFEST_BYTES {
                return Err(TransferError::ManifestTooLarge);
            }
            if !collision_keys.insert(entry.path.collision_key()) {
                return Err(TransferError::PathCollision);
            }

            match entry.kind {
                EntryKind::File if entry.hash.is_some() => {
                    total_bytes = total_bytes
                        .checked_add(entry.size)
                        .ok_or(TransferError::TransferTooLarge)?;
                }
                EntryKind::Directory if entry.size == 0 && entry.hash.is_none() => {}
                EntryKind::File | EntryKind::Directory => {
                    return Err(TransferError::InvalidManifest);
                }
            }
            if total_bytes > MAX_TRANSFER_BYTES {
                return Err(TransferError::TransferTooLarge);
            }
        }

        Ok(Self {
            entries,
            total_bytes,
        })
    }

    #[must_use]
    pub fn entries(&self) -> &[ManifestEntry] {
        &self.entries
    }

    #[must_use]
    pub const fn total_bytes(&self) -> u64 {
        self.total_bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferChunk {
    pub transfer: TransferId,
    pub entry_index: u32,
    pub offset: u64,
    pub bytes: Bytes,
}

/// Validated receiver progress recovered from durable staging state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumeState {
    transfer: TransferId,
    next_offsets: Vec<u64>,
}

impl ResumeState {
    #[must_use]
    pub const fn transfer(&self) -> TransferId {
        self.transfer
    }

    /// Returns the next contiguous byte offset for one manifest entry.
    /// Directories always report zero.
    #[must_use]
    pub fn next_offset(&self, entry_index: usize) -> Option<u64> {
        self.next_offsets.get(entry_index).copied()
    }

    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.next_offsets.len()
    }
}

impl TransferChunk {
    /// Checks an untrusted chunk against its manifest entry and hard limits.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::InvalidChunk`] if the entry is missing, is not
    /// a file, or the chunk is empty, oversized, overflowing, or out of bounds.
    pub fn validate(&self, manifest: &TransferManifest) -> Result<(), TransferError> {
        if self.bytes.is_empty() || self.bytes.len() > MAX_CHUNK_BYTES {
            return Err(TransferError::InvalidChunk);
        }
        let entry = manifest
            .entries()
            .get(usize::try_from(self.entry_index).map_err(|_| TransferError::InvalidChunk)?)
            .ok_or(TransferError::InvalidChunk)?;
        if entry.kind != EntryKind::File {
            return Err(TransferError::InvalidChunk);
        }
        let end = self
            .offset
            .checked_add(u64::try_from(self.bytes.len()).map_err(|_| TransferError::InvalidChunk)?)
            .ok_or(TransferError::InvalidChunk)?;
        if end > entry.size {
            return Err(TransferError::InvalidChunk);
        }
        Ok(())
    }
}

pub type TransferFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Staging boundary that can reopen validated durable progress after restart.
pub trait ResumableStagingArea: StagingArea {
    /// Reports whether both pieces of safe durable state exist for a transfer.
    ///
    /// # Errors
    ///
    /// Rejects partial state, links/reparse substitutions, or inaccessible
    /// staging metadata instead of treating corruption as a fresh transfer.
    fn has_persisted(&self, transfer: TransferId) -> Result<bool, TransferError>;

    /// Reopens an interrupted transfer and returns exact contiguous offsets.
    ///
    /// # Errors
    ///
    /// Rejects a missing, malformed, mismatched, or unsafe persisted state.
    fn resume(
        &mut self,
        transfer: TransferId,
        manifest: &TransferManifest,
    ) -> Result<ResumeState, TransferError>;
}

/// Platform-owned staging area. Implementations must use create-new semantics
/// and atomically finalize without silently overwriting an existing file.
pub trait StagingArea: Send {
    fn begin<'a>(
        &'a mut self,
        transfer: TransferId,
        manifest: &'a TransferManifest,
    ) -> TransferFuture<'a, Result<(), TransferError>>;

    fn write(&mut self, chunk: TransferChunk) -> TransferFuture<'_, Result<(), TransferError>>;

    fn finalize(&mut self, transfer: TransferId) -> TransferFuture<'_, Result<(), TransferError>>;

    fn abort(&mut self, transfer: TransferId);

    /// Aborts staging and confirms that cleanup completed.
    ///
    /// In-memory implementations may rely on the default. Filesystem-backed
    /// implementations must override this method so callers never publish a
    /// cancelled terminal state after a hidden cleanup failure.
    ///
    /// # Errors
    ///
    /// Returns the staging implementation's cleanup error. Callers must treat
    /// any error as irreversible for that staging instance.
    fn abort_confirmed(&mut self, transfer: TransferId) -> Result<(), TransferError> {
        self.abort(transfer);
        Ok(())
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TransferError {
    #[error("invalid relative path")]
    InvalidPath,
    #[error("manifest is invalid")]
    InvalidManifest,
    #[error("manifest is too large")]
    ManifestTooLarge,
    #[error("transfer exceeds the configured aggregate size limit")]
    TransferTooLarge,
    #[error("manifest paths collide after cross-platform normalization")]
    PathCollision,
    #[error("file chunk is invalid")]
    InvalidChunk,
    #[error("file chunks must be written once in ascending contiguous order")]
    NonSequentialChunk,
    #[error("the transfer cannot complete before every declared file byte is present")]
    IncompleteTransfer,
    #[error("the requested transfer is not active in this staging area")]
    TransferNotActive,
    #[error("destination already exists")]
    DestinationExists,
    #[error("content integrity check failed")]
    IntegrityMismatch,
    #[error("a selected source is missing, non-Unicode, or not a regular file or directory")]
    InvalidSource,
    #[error("source links, junctions, reparse points, or sparse files are not transferable")]
    UnsafeSourceType,
    #[error("source roots overlap, alias each other, or have no safe common filesystem root")]
    UnsafeSourceRoots,
    #[error("a source directory cycle or stable-identity alias was detected")]
    SourceCycle,
    #[error("source identity, size, modification time, or content changed after manifest hashing")]
    SourceChanged,
    #[error("transfer was cancelled")]
    Cancelled,
    #[error("durable transfer progress is malformed or does not match the manifest")]
    InvalidResumeState,
    #[error("transfer uses too many chunks to persist bounded resume progress")]
    ProgressLimitExceeded,
    #[error("the transfer queue is full")]
    QueueFull,
    #[error("the transfer is already present in the queue")]
    DuplicateTransfer,
    #[error("the transfer queue transition is invalid")]
    InvalidQueueTransition,
    #[error("platform staging failed")]
    Platform,
}

#[cfg(test)]
mod tests {
    use super::{ContentHash, EntryKind, ManifestEntry, RelativePath, TransferManifest};

    #[test]
    fn rejects_traversal_and_windows_device_names() {
        for path in [
            "../secret",
            "folder/../../secret",
            "CON.txt",
            "safe\\escape",
        ] {
            assert!(RelativePath::parse(path).is_err(), "accepted {path}");
        }
    }

    #[test]
    fn rejects_case_collisions() {
        let entries = vec![
            ManifestEntry {
                path: RelativePath::parse("Folder/File.txt").unwrap(),
                kind: EntryKind::File,
                size: 1,
                hash: Some(ContentHash::digest(b"a")),
            },
            ManifestEntry {
                path: RelativePath::parse("folder/file.TXT").unwrap(),
                kind: EntryKind::File,
                size: 1,
                hash: Some(ContentHash::digest(b"b")),
            },
        ];
        assert!(TransferManifest::new(entries).is_err());
    }
}
