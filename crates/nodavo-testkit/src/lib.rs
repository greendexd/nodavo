//! Deterministic, runtime-neutral adapters for Nodavo integration tests.
//!
//! The virtual adapters use only standard futures and collections. They do not
//! expose Tokio, Quinn, native handles, wall-clock time, or real filesystem and
//! clipboard state to the core crates.

use std::fmt;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use bytes::Bytes;
use nodavo_clipboard::{
    ClipboardError, ClipboardFuture, ContentHash as ClipboardHash, ContentSink, ContentSource,
    MAX_CLIPBOARD_CHUNK_BYTES, MAX_IMAGE_BYTES,
};
use nodavo_input::InputEvent;
use nodavo_session::MonotonicMillis;
use nodavo_transfer::{
    EntryKind, StagingArea, TransferChunk, TransferError, TransferFuture, TransferId,
    TransferManifest,
};
use thiserror::Error;

/// A cloneable monotonic clock advanced explicitly by a test.
#[derive(Clone, Debug)]
pub struct VirtualClock {
    millis: Arc<AtomicU64>,
}

impl VirtualClock {
    #[must_use]
    pub fn new(now: MonotonicMillis) -> Self {
        Self {
            millis: Arc::new(AtomicU64::new(now.get())),
        }
    }

    #[must_use]
    pub fn now(&self) -> MonotonicMillis {
        MonotonicMillis::new(self.millis.load(Ordering::SeqCst))
    }

    /// Advances the shared clock by an exact integral number of milliseconds.
    ///
    /// # Errors
    ///
    /// Returns [`ClockError::Overflow`] instead of wrapping.
    pub fn advance_millis(&self, delta: u64) -> Result<MonotonicMillis, ClockError> {
        self.millis
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                current.checked_add(delta)
            })
            .map(|previous| MonotonicMillis::new(previous + delta))
            .map_err(|_| ClockError::Overflow)
    }

    /// Advances to an absolute monotonic value without permitting time travel.
    ///
    /// # Errors
    ///
    /// Returns [`ClockError::WouldMoveBackward`] if `target` is earlier than
    /// the current virtual time.
    pub fn advance_to(&self, target: MonotonicMillis) -> Result<(), ClockError> {
        self.millis
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                (target.get() >= current).then_some(target.get())
            })
            .map(|_| ())
            .map_err(|_| ClockError::WouldMoveBackward)
    }
}

impl Default for VirtualClock {
    fn default() -> Self {
        Self::new(MonotonicMillis::new(0))
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ClockError {
    #[error("virtual monotonic time overflowed")]
    Overflow,
    #[error("virtual monotonic clocks cannot move backward")]
    WouldMoveBackward,
}

/// Recording input adapter for runtime orchestration tests.
///
/// Its custom `Debug` output includes counts only because input payloads must
/// not enter test logs accidentally.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct VirtualInputPort {
    events: Vec<InputEvent>,
    reject_after: Option<usize>,
}

impl VirtualInputPort {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            events: Vec::new(),
            reject_after: None,
        }
    }

    /// Configures deterministic failure after `accepted_events` successful
    /// injections.
    pub fn reject_after(&mut self, accepted_events: usize) {
        self.reject_after = Some(accepted_events);
    }

    /// Records one semantic event.
    ///
    /// # Errors
    ///
    /// Returns [`VirtualInputError::Rejected`] at the configured failure point.
    pub fn inject(&mut self, event: InputEvent) -> Result<(), VirtualInputError> {
        if self
            .reject_after
            .is_some_and(|accepted| self.events.len() >= accepted)
        {
            return Err(VirtualInputError::Rejected);
        }
        self.events.push(event);
        Ok(())
    }

    #[must_use]
    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    #[must_use]
    pub fn events(&self) -> &[InputEvent] {
        &self.events
    }

    #[must_use]
    pub fn take_events(&mut self) -> Vec<InputEvent> {
        std::mem::take(&mut self.events)
    }
}

impl fmt::Debug for VirtualInputPort {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VirtualInputPort")
            .field("event_count", &self.events.len())
            .field("reject_after", &self.reject_after)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum VirtualInputError {
    #[error("the virtual input port rejected the event")]
    Rejected,
}

/// In-memory clipboard source that honors both caller and protocol chunk limits.
#[derive(Clone)]
pub struct VirtualClipboardSource {
    content: Bytes,
    offset: usize,
    source_chunk_limit: usize,
    reject_after_chunks: Option<usize>,
    chunks_read: usize,
}

impl VirtualClipboardSource {
    /// Creates a source. A zero chunk limit is normalized to one byte.
    #[must_use]
    pub fn new(content: Bytes, source_chunk_limit: usize) -> Self {
        Self {
            content,
            offset: 0,
            source_chunk_limit: source_chunk_limit.clamp(1, MAX_CLIPBOARD_CHUNK_BYTES),
            reject_after_chunks: None,
            chunks_read: 0,
        }
    }

    pub fn reject_after_chunks(&mut self, successful_chunks: usize) {
        self.reject_after_chunks = Some(successful_chunks);
    }

    #[must_use]
    pub fn remaining_bytes(&self) -> usize {
        self.content.len().saturating_sub(self.offset)
    }
}

impl fmt::Debug for VirtualClipboardSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VirtualClipboardSource")
            .field("total_bytes", &self.content.len())
            .field("offset", &self.offset)
            .field("remaining_bytes", &self.remaining_bytes())
            .field("source_chunk_limit", &self.source_chunk_limit)
            .field("reject_after_chunks", &self.reject_after_chunks)
            .field("chunks_read", &self.chunks_read)
            .finish()
    }
}

impl ContentSource for VirtualClipboardSource {
    fn read_chunk(
        &mut self,
        max_bytes: usize,
    ) -> ClipboardFuture<'_, Result<Option<Bytes>, ClipboardError>> {
        Box::pin(async move {
            if max_bytes == 0 {
                return Err(ClipboardError::InvalidChunk);
            }
            if self
                .reject_after_chunks
                .is_some_and(|successful| self.chunks_read >= successful)
            {
                return Err(ClipboardError::Platform);
            }
            if self.offset == self.content.len() {
                return Ok(None);
            }
            let chunk_len = self
                .remaining_bytes()
                .min(max_bytes)
                .min(self.source_chunk_limit)
                .min(MAX_CLIPBOARD_CHUNK_BYTES);
            let end = self.offset + chunk_len;
            let chunk = self.content.slice(self.offset..end);
            self.offset = end;
            self.chunks_read += 1;
            Ok(Some(chunk))
        })
    }
}

/// In-memory clipboard sink with bounded writes and explicit commit state.
#[derive(Clone)]
pub struct VirtualClipboardSink {
    content: Vec<u8>,
    max_bytes: u64,
    committed: bool,
    aborted: bool,
}

impl VirtualClipboardSink {
    #[must_use]
    pub const fn with_max_bytes(max_bytes: u64) -> Self {
        Self {
            content: Vec::new(),
            max_bytes,
            committed: false,
            aborted: false,
        }
    }

    #[must_use]
    pub fn committed_bytes(&self) -> Option<&[u8]> {
        self.committed.then_some(self.content.as_slice())
    }

    #[must_use]
    pub const fn was_aborted(&self) -> bool {
        self.aborted
    }
}

impl Default for VirtualClipboardSink {
    fn default() -> Self {
        Self::with_max_bytes(MAX_IMAGE_BYTES)
    }
}

impl fmt::Debug for VirtualClipboardSink {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VirtualClipboardSink")
            .field("byte_len", &self.content.len())
            .field("max_bytes", &self.max_bytes)
            .field("committed", &self.committed)
            .field("aborted", &self.aborted)
            .finish()
    }
}

impl ContentSink for VirtualClipboardSink {
    fn write_chunk(&mut self, bytes: Bytes) -> ClipboardFuture<'_, Result<(), ClipboardError>> {
        Box::pin(async move {
            if self.committed
                || self.aborted
                || bytes.is_empty()
                || bytes.len() > MAX_CLIPBOARD_CHUNK_BYTES
            {
                return Err(ClipboardError::InvalidChunk);
            }
            let next_len = self
                .content
                .len()
                .checked_add(bytes.len())
                .ok_or(ClipboardError::RepresentationTooLarge)?;
            if u64::try_from(next_len).map_err(|_| ClipboardError::RepresentationTooLarge)?
                > self.max_bytes
            {
                return Err(ClipboardError::RepresentationTooLarge);
            }
            self.content.extend_from_slice(&bytes);
            Ok(())
        })
    }

    fn commit(
        &mut self,
        expected: ClipboardHash,
    ) -> ClipboardFuture<'_, Result<(), ClipboardError>> {
        Box::pin(async move {
            if self.committed || self.aborted {
                return Err(ClipboardError::Platform);
            }
            if ClipboardHash::digest(&self.content) != expected {
                return Err(ClipboardError::IntegrityMismatch);
            }
            self.committed = true;
            Ok(())
        })
    }

    fn abort(&mut self) {
        self.content.clear();
        self.committed = false;
        self.aborted = true;
    }
}

struct ActiveTransfer {
    id: TransferId,
    manifest: TransferManifest,
    entries: Vec<Vec<u8>>,
    written_bytes: u64,
}

struct CompletedTransfer {
    id: TransferId,
    files: Vec<(String, Vec<u8>)>,
}

/// Bounded in-memory implementation of the file-transfer staging contract.
///
/// Chunks must arrive sequentially within each file. Finalization validates
/// every signed length and BLAKE3 content hash before exposing completed bytes.
pub struct VirtualStagingArea {
    max_bytes: u64,
    active: Option<ActiveTransfer>,
    completed: Option<CompletedTransfer>,
    aborted: bool,
}

impl VirtualStagingArea {
    #[must_use]
    pub const fn with_max_bytes(max_bytes: u64) -> Self {
        Self {
            max_bytes,
            active: None,
            completed: None,
            aborted: false,
        }
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.active.is_some()
    }

    #[must_use]
    pub const fn was_aborted(&self) -> bool {
        self.aborted
    }

    #[must_use]
    pub fn completed_transfer(&self) -> Option<TransferId> {
        self.completed.as_ref().map(|completed| completed.id)
    }

    /// Returns completed test data by validated relative path.
    #[must_use]
    pub fn completed_file(&self, relative_path: &str) -> Option<&[u8]> {
        self.completed.as_ref().and_then(|completed| {
            completed
                .files
                .iter()
                .find_map(|(path, bytes)| (path == relative_path).then_some(bytes.as_slice()))
        })
    }
}

impl Default for VirtualStagingArea {
    fn default() -> Self {
        Self::with_max_bytes(256 * 1024 * 1024)
    }
}

impl fmt::Debug for VirtualStagingArea {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VirtualStagingArea")
            .field("max_bytes", &self.max_bytes)
            .field("active", &self.active.is_some())
            .field("completed", &self.completed.is_some())
            .field("aborted", &self.aborted)
            .finish()
    }
}

impl StagingArea for VirtualStagingArea {
    fn begin<'a>(
        &'a mut self,
        transfer: TransferId,
        manifest: &'a TransferManifest,
    ) -> TransferFuture<'a, Result<(), TransferError>> {
        Box::pin(async move {
            if self.active.is_some() {
                return Err(TransferError::Platform);
            }
            if manifest.total_bytes() > self.max_bytes {
                return Err(TransferError::TransferTooLarge);
            }
            self.active = Some(ActiveTransfer {
                id: transfer,
                manifest: manifest.clone(),
                entries: vec![Vec::new(); manifest.entries().len()],
                written_bytes: 0,
            });
            self.completed = None;
            self.aborted = false;
            Ok(())
        })
    }

    fn write(&mut self, chunk: TransferChunk) -> TransferFuture<'_, Result<(), TransferError>> {
        Box::pin(async move {
            let active = self.active.as_mut().ok_or(TransferError::Platform)?;
            if chunk.transfer != active.id {
                return Err(TransferError::Platform);
            }
            chunk.validate(&active.manifest)?;
            let index =
                usize::try_from(chunk.entry_index).map_err(|_| TransferError::InvalidChunk)?;
            let entry = active
                .entries
                .get_mut(index)
                .ok_or(TransferError::InvalidChunk)?;
            if chunk.offset
                != u64::try_from(entry.len()).map_err(|_| TransferError::InvalidChunk)?
            {
                return Err(TransferError::InvalidChunk);
            }
            let next_total = active
                .written_bytes
                .checked_add(
                    u64::try_from(chunk.bytes.len())
                        .map_err(|_| TransferError::TransferTooLarge)?,
                )
                .ok_or(TransferError::TransferTooLarge)?;
            if next_total > self.max_bytes {
                return Err(TransferError::TransferTooLarge);
            }
            entry.extend_from_slice(&chunk.bytes);
            active.written_bytes = next_total;
            Ok(())
        })
    }

    fn finalize(&mut self, transfer: TransferId) -> TransferFuture<'_, Result<(), TransferError>> {
        Box::pin(async move {
            let active = self.active.take().ok_or(TransferError::Platform)?;
            if active.id != transfer {
                self.active = Some(active);
                return Err(TransferError::Platform);
            }

            let mut files = Vec::new();
            for (metadata, bytes) in active.manifest.entries().iter().zip(active.entries) {
                match metadata.kind {
                    EntryKind::Directory if bytes.is_empty() => {}
                    EntryKind::File
                        if u64::try_from(bytes.len()).ok() == Some(metadata.size)
                            && metadata.hash
                                == Some(nodavo_transfer::ContentHash::digest(&bytes)) =>
                    {
                        files.push((metadata.path.as_str().to_owned(), bytes));
                    }
                    EntryKind::File | EntryKind::Directory => {
                        return Err(TransferError::IntegrityMismatch);
                    }
                }
            }
            self.completed = Some(CompletedTransfer {
                id: transfer,
                files,
            });
            Ok(())
        })
    }

    fn abort(&mut self, transfer: TransferId) {
        if self
            .active
            .as_ref()
            .is_some_and(|active| active.id == transfer)
        {
            self.active = None;
            self.aborted = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nodavo_input::{HidUsage, KeyState, Modifiers};

    #[test]
    fn clock_clones_share_exact_monotonic_progress() {
        let clock = VirtualClock::new(MonotonicMillis::new(40));
        let observer = clock.clone();

        assert_eq!(clock.advance_millis(2).unwrap().get(), 42);
        assert_eq!(observer.now().get(), 42);
        assert_eq!(
            observer.advance_to(MonotonicMillis::new(41)),
            Err(ClockError::WouldMoveBackward)
        );
        assert_eq!(clock.now().get(), 42);
    }

    #[test]
    fn input_port_records_order_and_fails_at_a_deterministic_boundary() {
        let mut input = VirtualInputPort::new();
        input.reject_after(1);
        let pressed = InputEvent::Key {
            usage: HidUsage::new(7, 4),
            state: KeyState::Pressed,
            modifiers: Modifiers::empty(),
        };
        let released = InputEvent::Key {
            usage: HidUsage::new(7, 4),
            state: KeyState::Released,
            modifiers: Modifiers::empty(),
        };

        assert_eq!(input.inject(pressed), Ok(()));
        assert_eq!(input.inject(released), Err(VirtualInputError::Rejected));
        assert_eq!(input.events(), &[pressed]);
    }
}
