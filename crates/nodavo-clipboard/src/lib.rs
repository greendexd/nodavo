//! Bounded, content-addressed clipboard synchronization contracts.
//!
//! Offers contain metadata only. Content is pulled through bounded streams and
//! is never represented as one untrusted whole-content allocation here.

use std::collections::HashSet;
use std::fmt;
use std::future::Future;
use std::pin::Pin;

use bytes::Bytes;
use nodavo_protocol::DeviceId;
use thiserror::Error;

mod state;

pub use state::{
    AppliedClipboard, ClipboardEffect, ClipboardFailure, ClipboardState, LocalClipboardChange,
    MAX_ACTIVE_INCOMING_TRANSFERS, MAX_ACTIVE_OUTGOING_TRANSFERS, NativeClipboardRevision,
    PeerClipboardGrants, RepresentationKey,
};

pub const MAX_REPRESENTATIONS: usize = 8;
pub const MAX_TEXT_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_HTML_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_IMAGE_BYTES: u64 = 100 * 1024 * 1024;
pub const MAX_FILE_LIST_BYTES: u64 = 1024 * 1024;
pub const MAX_CLIPBOARD_CHUNK_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ClipboardRevision(u64);

impl ClipboardRevision {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl From<nodavo_protocol::ClipboardRevision> for ClipboardRevision {
    fn from(value: nodavo_protocol::ClipboardRevision) -> Self {
        Self::new(value.get())
    }
}

impl From<ClipboardRevision> for nodavo_protocol::ClipboardRevision {
    fn from(value: ClipboardRevision) -> Self {
        Self::new(value.get())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContentHash([u8; 32]);

impl ContentHash {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub fn digest(bytes: &[u8]) -> Self {
        Self(*blake3::hash(bytes).as_bytes())
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for ContentHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ContentHash([redacted])")
    }
}

impl From<nodavo_protocol::ContentHash> for ContentHash {
    fn from(value: nodavo_protocol::ContentHash) -> Self {
        Self::from_bytes(*value.as_bytes())
    }
}

impl From<ContentHash> for nodavo_protocol::ContentHash {
    fn from(value: ContentHash) -> Self {
        Self::new(*value.as_bytes())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RepresentationKind {
    Utf8Text,
    Html,
    Png,
    Bmp,
    FileList,
}

impl RepresentationKind {
    #[must_use]
    pub const fn max_bytes(self) -> u64 {
        match self {
            Self::Utf8Text => MAX_TEXT_BYTES,
            Self::Html => MAX_HTML_BYTES,
            Self::Png | Self::Bmp => MAX_IMAGE_BYTES,
            Self::FileList => MAX_FILE_LIST_BYTES,
        }
    }
}

impl From<nodavo_protocol::ClipboardRepresentationKind> for RepresentationKind {
    fn from(value: nodavo_protocol::ClipboardRepresentationKind) -> Self {
        match value {
            nodavo_protocol::ClipboardRepresentationKind::Utf8Text => Self::Utf8Text,
            nodavo_protocol::ClipboardRepresentationKind::Html => Self::Html,
            nodavo_protocol::ClipboardRepresentationKind::Png => Self::Png,
            nodavo_protocol::ClipboardRepresentationKind::Bmp => Self::Bmp,
            nodavo_protocol::ClipboardRepresentationKind::FileList => Self::FileList,
        }
    }
}

impl From<RepresentationKind> for nodavo_protocol::ClipboardRepresentationKind {
    fn from(value: RepresentationKind) -> Self {
        match value {
            RepresentationKind::Utf8Text => Self::Utf8Text,
            RepresentationKind::Html => Self::Html,
            RepresentationKind::Png => Self::Png,
            RepresentationKind::Bmp => Self::Bmp,
            RepresentationKind::FileList => Self::FileList,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RepresentationMeta {
    pub kind: RepresentationKind,
    pub byte_len: u64,
    pub hash: ContentHash,
}

impl RepresentationMeta {
    /// Validates the representation-specific hard byte limit.
    ///
    /// # Errors
    ///
    /// Returns [`ClipboardError::RepresentationTooLarge`] for an oversized
    /// representation or an empty image.
    pub fn validate(self) -> Result<Self, ClipboardError> {
        if self.byte_len > self.kind.max_bytes()
            || (self.byte_len == 0
                && matches!(self.kind, RepresentationKind::Png | RepresentationKind::Bmp))
        {
            return Err(ClipboardError::RepresentationTooLarge);
        }
        Ok(self)
    }
}

impl TryFrom<nodavo_protocol::ClipboardRepresentation> for RepresentationMeta {
    type Error = ClipboardError;

    fn try_from(value: nodavo_protocol::ClipboardRepresentation) -> Result<Self, Self::Error> {
        Self {
            kind: value.kind.into(),
            byte_len: value.byte_len,
            hash: value.hash.into(),
        }
        .validate()
    }
}

impl From<RepresentationMeta> for nodavo_protocol::ClipboardRepresentation {
    fn from(value: RepresentationMeta) -> Self {
        Self {
            kind: value.kind.into(),
            byte_len: value.byte_len,
            hash: value.hash.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClipboardOffer {
    Cleared {
        origin: DeviceId,
        revision: ClipboardRevision,
    },
    Content {
        origin: DeviceId,
        revision: ClipboardRevision,
        representations: Vec<RepresentationMeta>,
    },
}

impl ClipboardOffer {
    /// Builds a bounded content offer with unique representation kinds.
    ///
    /// # Errors
    ///
    /// Returns an offer or representation validation error when metadata is
    /// empty, duplicated, or outside its hard limits.
    pub fn content(
        origin: DeviceId,
        revision: ClipboardRevision,
        representations: Vec<RepresentationMeta>,
    ) -> Result<Self, ClipboardError> {
        if representations.is_empty() || representations.len() > MAX_REPRESENTATIONS {
            return Err(ClipboardError::InvalidOffer);
        }
        let mut kinds = HashSet::with_capacity(representations.len());
        for representation in &representations {
            representation.validate()?;
            if !kinds.insert(representation.kind) {
                return Err(ClipboardError::DuplicateRepresentation);
            }
        }
        Ok(Self::Content {
            origin,
            revision,
            representations,
        })
    }

    #[must_use]
    pub const fn origin(&self) -> DeviceId {
        match self {
            Self::Cleared { origin, .. } | Self::Content { origin, .. } => *origin,
        }
    }

    #[must_use]
    pub const fn revision(&self) -> ClipboardRevision {
        match self {
            Self::Cleared { revision, .. } | Self::Content { revision, .. } => *revision,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AppliedRepresentation {
    pub origin: DeviceId,
    pub revision: ClipboardRevision,
    pub hash: ContentHash,
}

/// Tracks remote content written to the local pasteboard so the next native
/// change notification is not reflected back to its origin.
#[derive(Debug, Default)]
pub struct LoopGuard {
    applied: HashSet<AppliedRepresentation>,
}

impl LoopGuard {
    /// Records one remote application marker.
    ///
    /// # Errors
    ///
    /// Returns [`ClipboardError::LoopGuardFull`] at the hard marker limit.
    pub fn record(&mut self, marker: AppliedRepresentation) -> Result<(), ClipboardError> {
        if self.applied.len() >= MAX_REPRESENTATIONS && !self.applied.contains(&marker) {
            return Err(ClipboardError::LoopGuardFull);
        }
        self.applied.insert(marker);
        Ok(())
    }

    pub fn consume_if_applied(&mut self, marker: &AppliedRepresentation) -> bool {
        self.applied.remove(marker)
    }

    pub fn clear(&mut self) {
        self.applied.clear();
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ClipboardChunk {
    pub revision: ClipboardRevision,
    pub kind: RepresentationKind,
    pub offset: u64,
    pub bytes: Bytes,
}

impl fmt::Debug for ClipboardChunk {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClipboardChunk")
            .field("revision", &self.revision)
            .field("kind", &self.kind)
            .field("offset", &self.offset)
            .field("byte_len", &self.bytes.len())
            .finish()
    }
}

impl ClipboardChunk {
    /// Checks kind, non-empty bounded bytes, and the advertised byte range.
    ///
    /// # Errors
    ///
    /// Returns [`ClipboardError::InvalidChunk`] for any mismatch or overflow.
    pub fn validate(&self, meta: RepresentationMeta) -> Result<(), ClipboardError> {
        if self.kind != meta.kind
            || self.bytes.is_empty()
            || self.bytes.len() > MAX_CLIPBOARD_CHUNK_BYTES
        {
            return Err(ClipboardError::InvalidChunk);
        }
        let end = self
            .offset
            .checked_add(u64::try_from(self.bytes.len()).map_err(|_| ClipboardError::InvalidChunk)?)
            .ok_or(ClipboardError::InvalidChunk)?;
        if end > meta.byte_len {
            return Err(ClipboardError::InvalidChunk);
        }
        Ok(())
    }
}

pub type ClipboardFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub trait ContentSource: Send {
    fn read_chunk(
        &mut self,
        max_bytes: usize,
    ) -> ClipboardFuture<'_, Result<Option<Bytes>, ClipboardError>>;
}

pub trait ContentSink: Send {
    fn write_chunk(&mut self, bytes: Bytes) -> ClipboardFuture<'_, Result<(), ClipboardError>>;

    fn commit(&mut self, expected: ContentHash) -> ClipboardFuture<'_, Result<(), ClipboardError>>;

    fn abort(&mut self);
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ClipboardError {
    #[error("clipboard offer is invalid")]
    InvalidOffer,
    #[error("clipboard representation exceeds its hard size limit")]
    RepresentationTooLarge,
    #[error("clipboard offer repeats a representation kind")]
    DuplicateRepresentation,
    #[error("clipboard chunk is invalid")]
    InvalidChunk,
    #[error("clipboard content integrity check failed")]
    IntegrityMismatch,
    #[error("clipboard loop guard reached its hard limit")]
    LoopGuardFull,
    #[error("clipboard operation was cancelled")]
    Cancelled,
    #[error("the peer is disconnected")]
    Disconnected,
    #[error("the peer does not have the required clipboard grant")]
    GrantDenied,
    #[error("the clipboard revision is stale")]
    StaleRevision,
    #[error("the clipboard transfer does not match an active representation")]
    TransferNotFound,
    #[error("the clipboard representation already has an active transfer")]
    TransferAlreadyActive,
    #[error("the clipboard transfer reached its concurrency limit")]
    TooManyActiveTransfers,
    #[error("the clipboard source ended before the advertised byte length")]
    SourceEndedEarly,
    #[error("the clipboard transfer is not ready to be applied")]
    TransferNotReady,
    #[error("platform clipboard adapter failed")]
    Platform,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offer_rejects_duplicate_and_oversized_representations() {
        let origin = DeviceId::new([7; 32]);
        let text = RepresentationMeta {
            kind: RepresentationKind::Utf8Text,
            byte_len: 3,
            hash: ContentHash::digest(b"abc"),
        };
        assert!(
            ClipboardOffer::content(origin, ClipboardRevision::new(1), vec![text, text]).is_err()
        );

        let image = RepresentationMeta {
            kind: RepresentationKind::Png,
            byte_len: MAX_IMAGE_BYTES + 1,
            hash: ContentHash::digest(b"oversized"),
        };
        assert!(ClipboardOffer::content(origin, ClipboardRevision::new(2), vec![image]).is_err());
    }

    #[test]
    fn loop_guard_consumes_remote_marker_once() {
        let marker = AppliedRepresentation {
            origin: DeviceId::new([9; 32]),
            revision: ClipboardRevision::new(4),
            hash: ContentHash::digest(b"content"),
        };
        let mut guard = LoopGuard::default();
        guard.record(marker).unwrap();
        assert!(guard.consume_if_applied(&marker));
        assert!(!guard.consume_if_applied(&marker));
    }

    #[test]
    fn chunk_debug_redacts_content() {
        let chunk = ClipboardChunk {
            revision: ClipboardRevision::new(1),
            kind: RepresentationKind::Utf8Text,
            offset: 0,
            bytes: Bytes::from_static(b"secret clipboard text"),
        };
        assert!(!format!("{chunk:?}").contains("secret clipboard text"));
    }
}
