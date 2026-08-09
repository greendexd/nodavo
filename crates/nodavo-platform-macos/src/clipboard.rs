//! Bounded semantic adapter for the macOS general pasteboard.

use std::collections::HashMap;
use std::fmt;

use bytes::Bytes;
use nodavo_clipboard::{
    ClipboardEffect, ClipboardError, ClipboardFuture, ContentHash, ContentSink, ContentSource,
    LocalClipboardChange, MAX_ACTIVE_INCOMING_TRANSFERS, MAX_CLIPBOARD_CHUNK_BYTES,
    NativeClipboardRevision, RepresentationKey, RepresentationKind, RepresentationMeta,
};
use thiserror::Error;
use zeroize::Zeroize;

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[non_exhaustive]
pub enum MacClipboardError {
    #[error("the macOS pasteboard is unavailable")]
    Unavailable,
    #[error("the macOS pasteboard returned an invalid change count")]
    InvalidRevision,
    #[error("the macOS pasteboard rejected a content read")]
    ReadRejected,
    #[error("the macOS pasteboard changed while it was being read")]
    ChangedDuringRead,
    #[error("the clipboard representation exceeds its hard size limit")]
    RepresentationTooLarge,
    #[error("the macOS pasteboard rejected a content write")]
    WriteRejected,
    #[error("the macOS pasteboard raised a native exception")]
    NativeException,
    #[error("the macOS pasteboard returned an unknown native status ({0})")]
    NativeStatus(i32),
    #[error("the clipboard representation kind is unsupported on macOS")]
    UnsupportedRepresentation,
    #[error("the text clipboard representation is not valid UTF-8")]
    InvalidUtf8,
    #[error("the PNG clipboard representation is malformed")]
    InvalidPng,
    #[error("the clipboard transfer chunk is invalid or out of order")]
    InvalidChunk,
    #[error("the clipboard transfer does not match the staged source or sink")]
    TransferNotFound,
    #[error("the clipboard transfer already has a staged sink")]
    TransferAlreadyActive,
    #[error("the clipboard sink concurrency limit was reached")]
    TooManyActiveTransfers,
    #[error("the clipboard content integrity check failed")]
    IntegrityMismatch,
    #[error("the reducer effect is not a macOS clipboard platform effect")]
    NotPlatformEffect,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) enum PasteboardTarget {
    #[default]
    General,
    #[cfg(test)]
    Named(String),
}

/// Access to the current user's general pasteboard.
///
/// The value owns no native object. Every call obtains and releases its native
/// references inside the FFI boundary, so it can safely outlive any `AppKit`
/// autorelease pool.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MacClipboard {
    target: PasteboardTarget,
}

impl MacClipboard {
    #[must_use]
    pub const fn general() -> Self {
        Self {
            target: PasteboardTarget::General,
        }
    }

    /// Returns the current native change counter without reading content.
    ///
    /// # Errors
    ///
    /// Returns a semantic native error if `AppKit` cannot access the pasteboard
    /// or reports an invalid counter.
    pub fn change_count(&self) -> Result<NativeClipboardRevision, MacClipboardError> {
        #[cfg(target_os = "macos")]
        {
            super::macos::clipboard_change_count(&self.target)
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(MacClipboardError::Unavailable)
        }
    }

    /// Captures one internally consistent, bounded snapshot of the supported
    /// exact pasteboard types.
    ///
    /// The snapshot owns copied bytes and can service later reducer read
    /// effects even after another application changes the native pasteboard.
    ///
    /// # Errors
    ///
    /// Rejects an over-limit value, invalid UTF-8 or PNG data, a missing value
    /// for a declared exact type, and a pasteboard change during the read.
    pub fn snapshot(&self) -> Result<MacClipboardSnapshot, MacClipboardError> {
        #[cfg(target_os = "macos")]
        {
            let native = super::macos::clipboard_snapshot(&self.target)?;
            MacClipboardSnapshot::from_native(native)
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(MacClipboardError::Unavailable)
        }
    }

    /// Clears the selected pasteboard and returns its new native revision.
    ///
    /// # Errors
    ///
    /// Returns a semantic native error if `AppKit` rejects the operation.
    pub fn clear(&self) -> Result<NativeClipboardRevision, MacClipboardError> {
        #[cfg(target_os = "macos")]
        {
            super::macos::clipboard_clear(&self.target)
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(MacClipboardError::Unavailable)
        }
    }

    /// Replaces the pasteboard with one exact supported representation and
    /// returns its new native revision.
    ///
    /// # Errors
    ///
    /// Rejects unsupported, malformed, or over-limit content before native
    /// access and reports any `AppKit` write failure.
    pub fn write_representation(
        &self,
        kind: RepresentationKind,
        bytes: &[u8],
    ) -> Result<NativeClipboardRevision, MacClipboardError> {
        validate_representation(kind, bytes)?;
        #[cfg(target_os = "macos")]
        {
            super::macos::clipboard_write(&self.target, kind, bytes)
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(MacClipboardError::Unavailable)
        }
    }

    /// Creates a bounded staged sink for a reducer `BeginReceive` effect.
    /// Native pasteboard contents are not changed until the sink commits.
    ///
    /// # Errors
    ///
    /// Rejects unsupported kinds and representation-specific length bounds.
    pub fn begin_receive(
        &self,
        key: RepresentationKey,
        byte_len: u64,
    ) -> Result<MacClipboardSink, MacClipboardError> {
        MacClipboardSink::new(self.clone(), key, byte_len)
    }

    #[cfg(test)]
    fn named_for_test(name: String) -> Self {
        Self {
            target: PasteboardTarget::Named(name),
        }
    }
}

#[derive(Clone)]
struct SnapshotRepresentation {
    meta: RepresentationMeta,
    bytes: Bytes,
}

/// One immutable pasteboard revision with content bytes retained in Rust-owned
/// storage for incremental source reads.
#[derive(Clone)]
pub struct MacClipboardSnapshot {
    revision: NativeClipboardRevision,
    native_types_empty: bool,
    representations: Vec<SnapshotRepresentation>,
}

impl MacClipboardSnapshot {
    fn from_native(native: NativeClipboardSnapshot) -> Result<Self, MacClipboardError> {
        let mut representations = Vec::with_capacity(native.representations.len());
        for representation in native.representations {
            validate_representation(representation.kind, &representation.bytes)?;
            let bytes = Bytes::from(representation.bytes);
            let byte_len = u64::try_from(bytes.len())
                .map_err(|_| MacClipboardError::RepresentationTooLarge)?;
            representations.push(SnapshotRepresentation {
                meta: RepresentationMeta {
                    kind: representation.kind,
                    byte_len,
                    hash: ContentHash::digest(&bytes),
                },
                bytes,
            });
        }
        Ok(Self {
            revision: native.revision,
            native_types_empty: native.native_types_empty,
            representations,
        })
    }

    #[must_use]
    pub const fn revision(&self) -> NativeClipboardRevision {
        self.revision
    }

    /// Converts this observation into a reducer input. `None` means the
    /// pasteboard has only unsupported native types and must not be reflected
    /// as a remote clear.
    #[must_use]
    pub fn local_change(&self) -> Option<LocalClipboardChange> {
        if self.representations.is_empty() {
            self.native_types_empty
                .then_some(LocalClipboardChange::Cleared)
        } else {
            Some(LocalClipboardChange::Content(
                self.representations
                    .iter()
                    .map(|representation| representation.meta)
                    .collect(),
            ))
        }
    }

    #[must_use]
    pub fn representations(&self) -> Vec<RepresentationMeta> {
        self.representations
            .iter()
            .map(|representation| representation.meta)
            .collect()
    }

    /// Opens an owned, incremental source correlated to one reducer key.
    ///
    /// # Errors
    ///
    /// Rejects a revision, kind, or content-hash mismatch.
    pub fn source(&self, key: RepresentationKey) -> Result<MacClipboardSource, MacClipboardError> {
        if key.revision.get() != self.revision.get() {
            return Err(MacClipboardError::TransferNotFound);
        }
        let representation = self
            .representations
            .iter()
            .find(|representation| {
                representation.meta.kind == key.kind && representation.meta.hash == key.hash
            })
            .ok_or(MacClipboardError::TransferNotFound)?;
        Ok(MacClipboardSource {
            kind: key.kind,
            bytes: representation.bytes.clone(),
            cursor: 0,
        })
    }

    fn read_effect_chunk(
        &self,
        key: RepresentationKey,
        offset: u64,
        max_bytes: usize,
    ) -> Result<Option<Bytes>, MacClipboardError> {
        if max_bytes == 0 || max_bytes > MAX_CLIPBOARD_CHUNK_BYTES {
            return Err(MacClipboardError::InvalidChunk);
        }
        let source = self.source(key)?;
        let offset = usize::try_from(offset).map_err(|_| MacClipboardError::InvalidChunk)?;
        if offset > source.bytes.len() {
            return Err(MacClipboardError::InvalidChunk);
        }
        if offset == source.bytes.len() {
            return Ok(None);
        }
        let end = offset.saturating_add(max_bytes).min(source.bytes.len());
        Ok(Some(source.bytes.slice(offset..end)))
    }
}

impl fmt::Debug for MacClipboardSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacClipboardSnapshot")
            .field("revision", &self.revision)
            .field("native_types_empty", &self.native_types_empty)
            .field("representations", &self.representations())
            .finish()
    }
}

/// An incremental source backed by one immutable, bounded snapshot.
pub struct MacClipboardSource {
    kind: RepresentationKind,
    bytes: Bytes,
    cursor: usize,
}

impl MacClipboardSource {
    /// Reads the next bounded source chunk synchronously.
    ///
    /// # Errors
    ///
    /// Rejects zero or over-limit chunk sizes.
    pub fn read_next(&mut self, max_bytes: usize) -> Result<Option<Bytes>, MacClipboardError> {
        if max_bytes == 0 || max_bytes > MAX_CLIPBOARD_CHUNK_BYTES {
            return Err(MacClipboardError::InvalidChunk);
        }
        if self.cursor == self.bytes.len() {
            return Ok(None);
        }
        let end = self.cursor.saturating_add(max_bytes).min(self.bytes.len());
        let bytes = self.bytes.slice(self.cursor..end);
        self.cursor = end;
        Ok(Some(bytes))
    }
}

impl fmt::Debug for MacClipboardSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacClipboardSource")
            .field("kind", &self.kind)
            .field("byte_len", &self.bytes.len())
            .field("cursor", &self.cursor)
            .finish()
    }
}

impl ContentSource for MacClipboardSource {
    fn read_chunk(
        &mut self,
        max_bytes: usize,
    ) -> ClipboardFuture<'_, Result<Option<Bytes>, ClipboardError>> {
        Box::pin(async move { self.read_next(max_bytes).map_err(clipboard_core_error) })
    }
}

/// A staged, sequential receive sink. Its allocation and each write are
/// bounded before any native pasteboard mutation occurs.
pub struct MacClipboardSink {
    clipboard: MacClipboard,
    key: RepresentationKey,
    expected_len: usize,
    bytes: Vec<u8>,
    finished: bool,
}

impl MacClipboardSink {
    fn new(
        clipboard: MacClipboard,
        key: RepresentationKey,
        byte_len: u64,
    ) -> Result<Self, MacClipboardError> {
        validate_kind_and_length(key.kind, byte_len)?;
        let expected_len =
            usize::try_from(byte_len).map_err(|_| MacClipboardError::RepresentationTooLarge)?;
        Ok(Self {
            clipboard,
            key,
            expected_len,
            bytes: Vec::new(),
            finished: false,
        })
    }

    #[must_use]
    pub const fn key(&self) -> RepresentationKey {
        self.key
    }

    /// Appends one exact next chunk.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, out-of-order, or overrun chunks.
    pub fn write_at(&mut self, offset: u64, bytes: &[u8]) -> Result<(), MacClipboardError> {
        if self.finished
            || bytes.is_empty()
            || bytes.len() > MAX_CLIPBOARD_CHUNK_BYTES
            || usize::try_from(offset).ok() != Some(self.bytes.len())
            || self
                .bytes
                .len()
                .checked_add(bytes.len())
                .is_none_or(|end| end > self.expected_len)
        {
            return Err(MacClipboardError::InvalidChunk);
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    /// Verifies length, hash, and exact representation encoding, then replaces
    /// the pasteboard contents and returns the resulting native revision.
    ///
    /// # Errors
    ///
    /// Rejects incomplete or invalid content and any native write failure.
    pub fn commit_to_pasteboard(
        &mut self,
        expected: ContentHash,
    ) -> Result<NativeClipboardRevision, MacClipboardError> {
        if self.finished || self.bytes.len() != self.expected_len {
            return Err(MacClipboardError::InvalidChunk);
        }
        if expected != self.key.hash || ContentHash::digest(&self.bytes) != expected {
            return Err(MacClipboardError::IntegrityMismatch);
        }
        validate_representation(self.key.kind, &self.bytes)?;
        let revision = self
            .clipboard
            .write_representation(self.key.kind, &self.bytes)?;
        self.bytes.zeroize();
        self.bytes.clear();
        self.finished = true;
        Ok(revision)
    }

    pub fn abort_receive(&mut self) {
        self.bytes.zeroize();
        self.bytes.clear();
        self.finished = true;
    }
}

impl fmt::Debug for MacClipboardSink {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacClipboardSink")
            .field("revision", &self.key.revision)
            .field("kind", &self.key.kind)
            .field("expected_len", &self.expected_len)
            .field("received_len", &self.bytes.len())
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

impl Drop for MacClipboardSink {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl ContentSink for MacClipboardSink {
    fn write_chunk(&mut self, bytes: Bytes) -> ClipboardFuture<'_, Result<(), ClipboardError>> {
        Box::pin(async move {
            let offset = u64::try_from(self.bytes.len()).map_err(|_| ClipboardError::Platform)?;
            self.write_at(offset, &bytes).map_err(clipboard_core_error)
        })
    }

    fn commit(&mut self, expected: ContentHash) -> ClipboardFuture<'_, Result<(), ClipboardError>> {
        Box::pin(async move {
            self.commit_to_pasteboard(expected)
                .map(|_| ())
                .map_err(clipboard_core_error)
        })
    }

    fn abort(&mut self) {
        self.abort_receive();
    }
}

/// Result of executing exactly one platform-side reducer effect.
#[derive(Clone, PartialEq, Eq)]
pub enum MacClipboardEffectOutcome {
    ReceiveBegun {
        key: RepresentationKey,
    },
    ReceiveChunkWritten {
        key: RepresentationKey,
        offset: u64,
    },
    ReceiveAborted {
        key: RepresentationKey,
    },
    LocalChunkRead {
        key: RepresentationKey,
        offset: u64,
        bytes: Option<Bytes>,
    },
    RemoteApplied {
        key: RepresentationKey,
        native_revision: NativeClipboardRevision,
    },
    RemoteCleared {
        origin: nodavo_protocol::DeviceId,
        revision: nodavo_clipboard::ClipboardRevision,
        native_revision: NativeClipboardRevision,
    },
}

impl fmt::Debug for MacClipboardEffectOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReceiveBegun { key } => formatter
                .debug_struct("ReceiveBegun")
                .field("revision", &key.revision)
                .field("kind", &key.kind)
                .finish(),
            Self::ReceiveChunkWritten { key, offset } => formatter
                .debug_struct("ReceiveChunkWritten")
                .field("revision", &key.revision)
                .field("kind", &key.kind)
                .field("offset", offset)
                .finish(),
            Self::ReceiveAborted { key } => formatter
                .debug_struct("ReceiveAborted")
                .field("revision", &key.revision)
                .field("kind", &key.kind)
                .finish(),
            Self::LocalChunkRead { key, offset, bytes } => formatter
                .debug_struct("LocalChunkRead")
                .field("revision", &key.revision)
                .field("kind", &key.kind)
                .field("offset", offset)
                .field("byte_len", &bytes.as_ref().map_or(0, Bytes::len))
                .finish(),
            Self::RemoteApplied {
                key,
                native_revision,
            } => formatter
                .debug_struct("RemoteApplied")
                .field("revision", &key.revision)
                .field("kind", &key.kind)
                .field("native_revision", native_revision)
                .finish(),
            Self::RemoteCleared {
                origin: _,
                revision,
                native_revision,
            } => formatter
                .debug_struct("RemoteCleared")
                .field("origin", &"[redacted]")
                .field("revision", revision)
                .field("native_revision", native_revision)
                .finish(),
        }
    }
}

/// Stateful executor for the platform-only effects emitted by
/// `nodavo-clipboard`.
pub struct MacClipboardEffectExecutor {
    clipboard: MacClipboard,
    local_snapshot: Option<MacClipboardSnapshot>,
    incoming: HashMap<RepresentationKey, MacClipboardSink>,
}

impl MacClipboardEffectExecutor {
    #[must_use]
    pub fn new(clipboard: MacClipboard) -> Self {
        Self {
            clipboard,
            local_snapshot: None,
            incoming: HashMap::new(),
        }
    }

    /// Captures and retains the latest source snapshot for subsequent
    /// `ReadLocalChunk` effects.
    ///
    /// # Errors
    ///
    /// Returns any bounded snapshot validation or native access failure.
    pub fn observe(&mut self) -> Result<&MacClipboardSnapshot, MacClipboardError> {
        let snapshot = self.clipboard.snapshot()?;
        Ok(self.local_snapshot.insert(snapshot))
    }

    #[must_use]
    pub fn local_snapshot(&self) -> Option<&MacClipboardSnapshot> {
        self.local_snapshot.as_ref()
    }

    /// Executes one reducer effect that belongs to the macOS clipboard
    /// boundary. Network-facing effects are rejected without side effects.
    ///
    /// # Errors
    ///
    /// Returns a correlation, validation, bound, integrity, or native error.
    pub fn execute(
        &mut self,
        effect: ClipboardEffect,
    ) -> Result<MacClipboardEffectOutcome, MacClipboardError> {
        match effect {
            ClipboardEffect::ReadLocalChunk {
                key,
                offset,
                max_bytes,
            } => {
                let snapshot = self
                    .local_snapshot
                    .as_ref()
                    .ok_or(MacClipboardError::TransferNotFound)?;
                let bytes = snapshot.read_effect_chunk(key, offset, max_bytes)?;
                Ok(MacClipboardEffectOutcome::LocalChunkRead { key, offset, bytes })
            }
            ClipboardEffect::BeginReceive { key, byte_len } => {
                if self.incoming.contains_key(&key) {
                    return Err(MacClipboardError::TransferAlreadyActive);
                }
                if self.incoming.len() >= MAX_ACTIVE_INCOMING_TRANSFERS {
                    return Err(MacClipboardError::TooManyActiveTransfers);
                }
                let sink = self.clipboard.begin_receive(key, byte_len)?;
                self.incoming.insert(key, sink);
                Ok(MacClipboardEffectOutcome::ReceiveBegun { key })
            }
            ClipboardEffect::WriteReceiveChunk { key, offset, bytes } => {
                self.incoming
                    .get_mut(&key)
                    .ok_or(MacClipboardError::TransferNotFound)?
                    .write_at(offset, &bytes)?;
                Ok(MacClipboardEffectOutcome::ReceiveChunkWritten { key, offset })
            }
            ClipboardEffect::CommitReceive { key } => {
                let mut sink = self
                    .incoming
                    .remove(&key)
                    .ok_or(MacClipboardError::TransferNotFound)?;
                // A native write may clear the pasteboard before a later
                // AppKit step fails, so no cached source remains trustworthy
                // once the commit is attempted.
                self.local_snapshot = None;
                let native_revision = sink.commit_to_pasteboard(key.hash)?;
                Ok(MacClipboardEffectOutcome::RemoteApplied {
                    key,
                    native_revision,
                })
            }
            ClipboardEffect::AbortReceive { key } => {
                let mut sink = self
                    .incoming
                    .remove(&key)
                    .ok_or(MacClipboardError::TransferNotFound)?;
                sink.abort_receive();
                Ok(MacClipboardEffectOutcome::ReceiveAborted { key })
            }
            ClipboardEffect::ClearLocal { origin, revision } => {
                // Conservatively invalidate before crossing FFI: a native
                // exception can occur after AppKit has mutated the board.
                self.local_snapshot = None;
                let native_revision = self.clipboard.clear()?;
                Ok(MacClipboardEffectOutcome::RemoteCleared {
                    origin,
                    revision,
                    native_revision,
                })
            }
            ClipboardEffect::SendOffer(_)
            | ClipboardEffect::SendRequest(_)
            | ClipboardEffect::SendChunk { .. }
            | ClipboardEffect::SendAbort { .. }
            | ClipboardEffect::RemoteOfferAvailable(_) => Err(MacClipboardError::NotPlatformEffect),
        }
    }
}

impl fmt::Debug for MacClipboardEffectExecutor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacClipboardEffectExecutor")
            .field(
                "local_revision",
                &self
                    .local_snapshot
                    .as_ref()
                    .map(MacClipboardSnapshot::revision),
            )
            .field("incoming_count", &self.incoming.len())
            .finish_non_exhaustive()
    }
}

pub(crate) struct NativeClipboardRepresentation {
    pub kind: RepresentationKind,
    pub bytes: Vec<u8>,
}

pub(crate) struct NativeClipboardSnapshot {
    pub revision: NativeClipboardRevision,
    pub native_types_empty: bool,
    pub representations: Vec<NativeClipboardRepresentation>,
}

fn validate_kind_and_length(
    kind: RepresentationKind,
    byte_len: u64,
) -> Result<(), MacClipboardError> {
    if !matches!(
        kind,
        RepresentationKind::Utf8Text | RepresentationKind::Html | RepresentationKind::Png
    ) {
        return Err(MacClipboardError::UnsupportedRepresentation);
    }
    if byte_len > kind.max_bytes() || (kind == RepresentationKind::Png && byte_len == 0) {
        return Err(MacClipboardError::RepresentationTooLarge);
    }
    Ok(())
}

fn validate_representation(
    kind: RepresentationKind,
    bytes: &[u8],
) -> Result<(), MacClipboardError> {
    let byte_len =
        u64::try_from(bytes.len()).map_err(|_| MacClipboardError::RepresentationTooLarge)?;
    validate_kind_and_length(kind, byte_len)?;
    match kind {
        RepresentationKind::Utf8Text | RepresentationKind::Html => {
            std::str::from_utf8(bytes).map_err(|_| MacClipboardError::InvalidUtf8)?;
        }
        RepresentationKind::Png => validate_png(bytes)?,
        RepresentationKind::Bmp | RepresentationKind::FileList => {
            return Err(MacClipboardError::UnsupportedRepresentation);
        }
    }
    Ok(())
}

fn validate_png(bytes: &[u8]) -> Result<(), MacClipboardError> {
    const SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
    if !bytes.starts_with(SIGNATURE) {
        return Err(MacClipboardError::InvalidPng);
    }

    let mut cursor = SIGNATURE.len();
    let mut chunk_index = 0_usize;
    let mut saw_idat = false;
    loop {
        let header_end = cursor.checked_add(8).ok_or(MacClipboardError::InvalidPng)?;
        let header = bytes
            .get(cursor..header_end)
            .ok_or(MacClipboardError::InvalidPng)?;
        let data_len = usize::try_from(u32::from_be_bytes(
            header[..4]
                .try_into()
                .map_err(|_| MacClipboardError::InvalidPng)?,
        ))
        .map_err(|_| MacClipboardError::InvalidPng)?;
        let chunk_type: [u8; 4] = header[4..]
            .try_into()
            .map_err(|_| MacClipboardError::InvalidPng)?;
        if !chunk_type.iter().all(u8::is_ascii_alphabetic) || chunk_type[2].is_ascii_lowercase() {
            return Err(MacClipboardError::InvalidPng);
        }
        let data_end = header_end
            .checked_add(data_len)
            .ok_or(MacClipboardError::InvalidPng)?;
        let chunk_end = data_end
            .checked_add(4)
            .ok_or(MacClipboardError::InvalidPng)?;
        let chunk_data = bytes
            .get(header_end..data_end)
            .ok_or(MacClipboardError::InvalidPng)?;
        let expected_crc = u32::from_be_bytes(
            bytes
                .get(data_end..chunk_end)
                .ok_or(MacClipboardError::InvalidPng)?
                .try_into()
                .map_err(|_| MacClipboardError::InvalidPng)?,
        );
        if png_crc32(&bytes[cursor + 4..data_end]) != expected_crc {
            return Err(MacClipboardError::InvalidPng);
        }
        if chunk_index == 0 && &chunk_type != b"IHDR" {
            return Err(MacClipboardError::InvalidPng);
        }

        match &chunk_type {
            b"IHDR" if chunk_index == 0 => validate_png_header(chunk_data)?,
            b"IHDR" => return Err(MacClipboardError::InvalidPng),
            b"IDAT" => saw_idat = true,
            b"IEND" => {
                if data_len != 0 || !saw_idat || chunk_end != bytes.len() {
                    return Err(MacClipboardError::InvalidPng);
                }
                return Ok(());
            }
            _ => {}
        }
        cursor = chunk_end;
        chunk_index = chunk_index
            .checked_add(1)
            .ok_or(MacClipboardError::InvalidPng)?;
    }
}

fn validate_png_header(data: &[u8]) -> Result<(), MacClipboardError> {
    if data.len() != 13 {
        return Err(MacClipboardError::InvalidPng);
    }
    let width = u32::from_be_bytes(
        data[..4]
            .try_into()
            .map_err(|_| MacClipboardError::InvalidPng)?,
    );
    let height = u32::from_be_bytes(
        data[4..8]
            .try_into()
            .map_err(|_| MacClipboardError::InvalidPng)?,
    );
    let bit_depth = data[8];
    let color_type = data[9];
    let valid_depth = match color_type {
        0 => matches!(bit_depth, 1 | 2 | 4 | 8 | 16),
        2 | 4 | 6 => matches!(bit_depth, 8 | 16),
        3 => matches!(bit_depth, 1 | 2 | 4 | 8),
        _ => false,
    };
    if width == 0
        || height == 0
        || !valid_depth
        || data[10] != 0
        || data[11] != 0
        || !matches!(data[12], 0 | 1)
    {
        return Err(MacClipboardError::InvalidPng);
    }
    Ok(())
}

fn png_crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0_u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

fn clipboard_core_error(error: MacClipboardError) -> ClipboardError {
    match error {
        MacClipboardError::RepresentationTooLarge => ClipboardError::RepresentationTooLarge,
        MacClipboardError::InvalidChunk => ClipboardError::InvalidChunk,
        MacClipboardError::IntegrityMismatch => ClipboardError::IntegrityMismatch,
        MacClipboardError::TransferNotFound => ClipboardError::TransferNotFound,
        MacClipboardError::TransferAlreadyActive => ClipboardError::TransferAlreadyActive,
        MacClipboardError::TooManyActiveTransfers => ClipboardError::TooManyActiveTransfers,
        MacClipboardError::Unavailable
        | MacClipboardError::InvalidRevision
        | MacClipboardError::ReadRejected
        | MacClipboardError::ChangedDuringRead
        | MacClipboardError::WriteRejected
        | MacClipboardError::NativeException
        | MacClipboardError::NativeStatus(_)
        | MacClipboardError::UnsupportedRepresentation
        | MacClipboardError::InvalidUtf8
        | MacClipboardError::InvalidPng
        | MacClipboardError::NotPlatformEffect => ClipboardError::Platform,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nodavo_clipboard::ClipboardRevision;
    use nodavo_protocol::DeviceId;
    use uuid::Uuid;

    const ONE_PIXEL_PNG: &[u8] = &[
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44,
        0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F,
        0x15, 0xC4, 0x89, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x44, 0x41, 0x54, 0x08, 0xD7, 0x63, 0xF8,
        0xCF, 0xC0, 0xF0, 0x1F, 0x00, 0x05, 0x00, 0x01, 0xFF, 0x72, 0x9C, 0x52, 0x67, 0x00, 0x00,
        0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
    ];

    fn key(kind: RepresentationKind, bytes: &[u8]) -> RepresentationKey {
        RepresentationKey {
            origin: DeviceId::new([7; 32]),
            revision: ClipboardRevision::new(1),
            kind,
            hash: ContentHash::digest(bytes),
        }
    }

    #[test]
    fn validates_exact_utf8_and_png_encodings() {
        assert!(validate_representation(RepresentationKind::Utf8Text, "привет".as_bytes()).is_ok());
        assert!(validate_representation(RepresentationKind::Html, b"<b>ok</b>").is_ok());
        assert_eq!(
            validate_representation(RepresentationKind::Html, &[0xFF]),
            Err(MacClipboardError::InvalidUtf8)
        );
        assert!(validate_representation(RepresentationKind::Png, ONE_PIXEL_PNG).is_ok());

        let mut corrupt = ONE_PIXEL_PNG.to_vec();
        corrupt[40] ^= 1;
        assert_eq!(
            validate_representation(RepresentationKind::Png, &corrupt),
            Err(MacClipboardError::InvalidPng)
        );
    }

    #[test]
    fn sink_enforces_offsets_integrity_and_redacts_debug() {
        let content = b"private clipboard text";
        let key = key(RepresentationKind::Utf8Text, content);
        let mut sink = MacClipboard::general()
            .begin_receive(key, u64::try_from(content.len()).unwrap())
            .unwrap();
        assert_eq!(
            sink.write_at(1, content),
            Err(MacClipboardError::InvalidChunk)
        );
        sink.write_at(0, &content[..8]).unwrap();
        sink.write_at(8, &content[8..]).unwrap();
        assert!(!format!("{sink:?}").contains("private clipboard text"));
    }

    #[test]
    fn snapshot_and_outcomes_redact_content() {
        let content = Bytes::from_static(b"do not expose this clipboard value");
        let native = NativeClipboardSnapshot {
            revision: NativeClipboardRevision::new(3),
            native_types_empty: false,
            representations: vec![NativeClipboardRepresentation {
                kind: RepresentationKind::Utf8Text,
                bytes: content.to_vec(),
            }],
        };
        let snapshot = MacClipboardSnapshot::from_native(native).unwrap();
        assert!(!format!("{snapshot:?}").contains("do not expose"));

        let key = RepresentationKey {
            origin: DeviceId::new([4; 32]),
            revision: ClipboardRevision::new(3),
            kind: RepresentationKind::Utf8Text,
            hash: ContentHash::digest(&content),
        };
        let outcome = MacClipboardEffectOutcome::LocalChunkRead {
            key,
            offset: 0,
            bytes: Some(content),
        };
        assert!(!format!("{outcome:?}").contains("do not expose"));
    }

    #[test]
    fn executor_services_bounded_source_and_staged_abort_effects() {
        let content = b"incremental source";
        let native = NativeClipboardSnapshot {
            revision: NativeClipboardRevision::new(9),
            native_types_empty: false,
            representations: vec![NativeClipboardRepresentation {
                kind: RepresentationKind::Utf8Text,
                bytes: content.to_vec(),
            }],
        };
        let key = RepresentationKey {
            origin: DeviceId::new([5; 32]),
            revision: ClipboardRevision::new(9),
            kind: RepresentationKind::Utf8Text,
            hash: ContentHash::digest(content),
        };
        let mut executor = MacClipboardEffectExecutor::new(MacClipboard::general());
        executor.local_snapshot = Some(MacClipboardSnapshot::from_native(native).unwrap());

        let first = executor
            .execute(ClipboardEffect::ReadLocalChunk {
                key,
                offset: 0,
                max_bytes: 4,
            })
            .unwrap();
        assert!(matches!(
            first,
            MacClipboardEffectOutcome::LocalChunkRead {
                offset: 0,
                bytes: Some(ref bytes),
                ..
            } if bytes == &Bytes::from_static(b"incr")
        ));

        executor
            .execute(ClipboardEffect::BeginReceive {
                key,
                byte_len: content.len() as u64,
            })
            .unwrap();
        executor
            .execute(ClipboardEffect::WriteReceiveChunk {
                key,
                offset: 0,
                bytes: Bytes::from_static(b"incr"),
            })
            .unwrap();
        assert!(matches!(
            executor
                .execute(ClipboardEffect::AbortReceive { key })
                .unwrap(),
            MacClipboardEffectOutcome::ReceiveAborted { .. }
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn isolated_native_pasteboard_round_trips_all_supported_types_and_clear() {
        let name = format!("dev.nodavo.test.{}", Uuid::new_v4().simple());
        let clipboard = MacClipboard::named_for_test(name.clone());
        let origin = DeviceId::new([8; 32]);
        let mut executor = MacClipboardEffectExecutor::new(clipboard.clone());
        for (wire_revision, (kind, bytes)) in [
            (RepresentationKind::Utf8Text, "Nodavo π".as_bytes()),
            (RepresentationKind::Html, "<p>Nodavo π</p>".as_bytes()),
            (RepresentationKind::Png, ONE_PIXEL_PNG),
        ]
        .into_iter()
        .enumerate()
        {
            let key = RepresentationKey {
                origin,
                revision: ClipboardRevision::new(wire_revision as u64 + 1),
                kind,
                hash: ContentHash::digest(bytes),
            };
            executor
                .execute(ClipboardEffect::BeginReceive {
                    key,
                    byte_len: bytes.len() as u64,
                })
                .unwrap();
            executor
                .execute(ClipboardEffect::WriteReceiveChunk {
                    key,
                    offset: 0,
                    bytes: Bytes::copy_from_slice(bytes),
                })
                .unwrap();
            let MacClipboardEffectOutcome::RemoteApplied {
                native_revision: revision,
                ..
            } = executor
                .execute(ClipboardEffect::CommitReceive { key })
                .unwrap()
            else {
                panic!("commit returned an unrelated platform outcome");
            };
            let snapshot = clipboard.snapshot().unwrap();
            assert_eq!(snapshot.revision(), revision);
            assert_eq!(snapshot.representations().len(), 1);
            assert_eq!(snapshot.representations()[0].kind, kind);
            assert_eq!(snapshot.representations()[0].byte_len, bytes.len() as u64);
            assert_eq!(
                snapshot.representations()[0].hash,
                ContentHash::digest(bytes)
            );
        }
        let clear_revision = ClipboardRevision::new(10);
        let cleared = match executor
            .execute(ClipboardEffect::ClearLocal {
                origin,
                revision: clear_revision,
            })
            .unwrap()
        {
            MacClipboardEffectOutcome::RemoteCleared {
                revision,
                native_revision,
                ..
            } if revision == clear_revision => native_revision,
            _ => panic!("clear returned an unrelated platform outcome"),
        };
        let snapshot = clipboard.snapshot().unwrap();
        assert_eq!(snapshot.revision(), cleared);
        assert_eq!(snapshot.local_change(), Some(LocalClipboardChange::Cleared));

        super::super::macos::clipboard_release_named(&PasteboardTarget::Named(name));
    }
}
