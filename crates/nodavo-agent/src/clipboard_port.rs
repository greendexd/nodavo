//! Platform clipboard boundary used by the authenticated peer runtime.

use bytes::Bytes;
use nodavo_clipboard::{
    AppliedClipboard, AppliedRepresentation, ClipboardEffect, LocalClipboardChange,
    NativeClipboardRevision, RepresentationKey, RepresentationKind,
};
use thiserror::Error;

#[derive(Clone, Debug)]
pub(crate) struct ClipboardObservation {
    pub(crate) revision: NativeClipboardRevision,
    pub(crate) change: LocalClipboardChange,
    pub(crate) applied: Option<AppliedClipboard>,
}

#[derive(Clone)]
pub(crate) enum ClipboardPortOutcome {
    Completed,
    LocalChunk {
        key: RepresentationKey,
        offset: u64,
        bytes: Option<Bytes>,
    },
    RemoteApplied {
        key: RepresentationKey,
    },
    #[cfg_attr(target_os = "windows", allow(dead_code))]
    RemoteCleared {
        origin: nodavo_protocol::DeviceId,
        revision: nodavo_clipboard::ClipboardRevision,
    },
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum ClipboardPortError {
    #[error("platform clipboard integration failed")]
    Platform,
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    #[error("clipboard representation is unsupported on this platform")]
    Unsupported,
}

pub(crate) trait ClipboardPort: Send {
    fn poll(&mut self) -> Result<Option<ClipboardObservation>, ClipboardPortError>;
    fn supports(&self, kind: RepresentationKind) -> bool;
    fn execute(
        &mut self,
        effect: ClipboardEffect,
    ) -> Result<ClipboardPortOutcome, ClipboardPortError>;
}

#[cfg(test)]
mod virtual_port {
    use std::sync::{Arc, Mutex};

    use nodavo_clipboard::{ContentHash, RepresentationMeta};

    use super::*;

    #[derive(Default)]
    struct VirtualState {
        observation: Option<ClipboardObservation>,
        source: Bytes,
        receive: Vec<u8>,
        applied: Vec<u8>,
    }

    #[derive(Clone, Default)]
    pub(crate) struct VirtualClipboardObserver {
        state: Arc<Mutex<VirtualState>>,
    }

    impl VirtualClipboardObserver {
        pub(crate) fn applied_bytes(&self) -> Vec<u8> {
            self.state
                .lock()
                .expect("virtual clipboard lock")
                .applied
                .clone()
        }
    }

    pub(crate) struct VirtualClipboardPort {
        state: Arc<Mutex<VirtualState>>,
    }

    impl VirtualClipboardPort {
        pub(crate) fn empty() -> (Self, VirtualClipboardObserver) {
            let state = Arc::new(Mutex::new(VirtualState::default()));
            (
                Self {
                    state: Arc::clone(&state),
                },
                VirtualClipboardObserver { state },
            )
        }

        pub(crate) fn with_local_text(
            revision: u64,
            bytes: &Bytes,
        ) -> (Self, VirtualClipboardObserver) {
            let (port, observer) = Self::empty();
            let hash = ContentHash::digest(bytes);
            {
                let mut state = port.state.lock().expect("virtual clipboard lock");
                state.source = bytes.clone();
                state.observation = Some(ClipboardObservation {
                    revision: NativeClipboardRevision::new(revision),
                    change: LocalClipboardChange::Content(vec![RepresentationMeta {
                        kind: RepresentationKind::Utf8Text,
                        byte_len: u64::try_from(bytes.len()).expect("test content length fits u64"),
                        hash,
                    }]),
                    applied: None,
                });
            }
            (port, observer)
        }
    }

    impl ClipboardPort for VirtualClipboardPort {
        fn poll(&mut self) -> Result<Option<ClipboardObservation>, ClipboardPortError> {
            Ok(self
                .state
                .lock()
                .map_err(|_| ClipboardPortError::Platform)?
                .observation
                .take())
        }

        fn supports(&self, kind: RepresentationKind) -> bool {
            kind == RepresentationKind::Utf8Text
        }

        fn execute(
            &mut self,
            effect: ClipboardEffect,
        ) -> Result<ClipboardPortOutcome, ClipboardPortError> {
            let mut state = self
                .state
                .lock()
                .map_err(|_| ClipboardPortError::Platform)?;
            match effect {
                ClipboardEffect::ReadLocalChunk {
                    key,
                    offset,
                    max_bytes,
                } => {
                    let start =
                        usize::try_from(offset).map_err(|_| ClipboardPortError::Platform)?;
                    let bytes = (start < state.source.len()).then(|| {
                        state
                            .source
                            .slice(start..start.saturating_add(max_bytes).min(state.source.len()))
                    });
                    Ok(ClipboardPortOutcome::LocalChunk { key, offset, bytes })
                }
                ClipboardEffect::BeginReceive { .. } | ClipboardEffect::AbortReceive { .. } => {
                    state.receive.clear();
                    Ok(ClipboardPortOutcome::Completed)
                }
                ClipboardEffect::WriteReceiveChunk { bytes, .. } => {
                    state.receive.extend_from_slice(&bytes);
                    Ok(ClipboardPortOutcome::Completed)
                }
                ClipboardEffect::CommitReceive { key } => {
                    state.applied = state.receive.clone();
                    Ok(ClipboardPortOutcome::RemoteApplied { key })
                }
                ClipboardEffect::ClearLocal { origin, revision } => {
                    state.applied.clear();
                    Ok(ClipboardPortOutcome::RemoteCleared { origin, revision })
                }
                _ => Err(ClipboardPortError::Unsupported),
            }
        }
    }
}

#[cfg(test)]
pub(crate) use virtual_port::VirtualClipboardPort;

#[allow(clippy::unnecessary_wraps)]
pub(crate) fn native_clipboard_port() -> Result<Box<dyn ClipboardPort>, ClipboardPortError> {
    #[cfg(target_os = "macos")]
    {
        Ok(Box::new(NativeClipboardPort::new()))
    }
    #[cfg(target_os = "windows")]
    {
        Ok(Box::new(NativeClipboardPort::new()?))
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        Ok(Box::new(UnavailableClipboardPort))
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
struct UnavailableClipboardPort;

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
impl ClipboardPort for UnavailableClipboardPort {
    fn poll(&mut self) -> Result<Option<ClipboardObservation>, ClipboardPortError> {
        Ok(None)
    }

    fn supports(&self, _kind: RepresentationKind) -> bool {
        false
    }

    fn execute(
        &mut self,
        _effect: ClipboardEffect,
    ) -> Result<ClipboardPortOutcome, ClipboardPortError> {
        Err(ClipboardPortError::Unsupported)
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use nodavo_platform_macos::{
        MacClipboard, MacClipboardEffectExecutor, MacClipboardEffectOutcome,
    };

    use super::{
        AppliedClipboard, AppliedRepresentation, ClipboardEffect, ClipboardObservation,
        ClipboardPort, ClipboardPortError, ClipboardPortOutcome, NativeClipboardRevision,
        RepresentationKind,
    };

    pub(crate) struct NativeClipboardPort {
        clipboard: MacClipboard,
        executor: MacClipboardEffectExecutor,
        observed_revision: Option<NativeClipboardRevision>,
        applied: Option<(NativeClipboardRevision, AppliedClipboard)>,
    }

    impl NativeClipboardPort {
        pub(crate) fn new() -> Self {
            let clipboard = MacClipboard::general();
            Self {
                executor: MacClipboardEffectExecutor::new(clipboard.clone()),
                clipboard,
                observed_revision: None,
                applied: None,
            }
        }
    }

    impl ClipboardPort for NativeClipboardPort {
        fn poll(&mut self) -> Result<Option<ClipboardObservation>, ClipboardPortError> {
            let revision = self
                .clipboard
                .change_count()
                .map_err(|_| ClipboardPortError::Platform)?;
            if self.observed_revision == Some(revision) {
                return Ok(None);
            }
            let snapshot = self
                .executor
                .observe()
                .map_err(|_| ClipboardPortError::Platform)?;
            let revision = snapshot.revision();
            let change = snapshot.local_change();
            self.observed_revision = Some(revision);
            let applied = self
                .applied
                .take()
                .and_then(|(expected, marker)| (expected == revision).then_some(marker));
            Ok(change.map(|change| ClipboardObservation {
                revision,
                change,
                applied,
            }))
        }

        fn supports(&self, kind: RepresentationKind) -> bool {
            matches!(
                kind,
                RepresentationKind::Utf8Text | RepresentationKind::Html | RepresentationKind::Png
            )
        }

        fn execute(
            &mut self,
            effect: ClipboardEffect,
        ) -> Result<ClipboardPortOutcome, ClipboardPortError> {
            match self
                .executor
                .execute(effect)
                .map_err(|_| ClipboardPortError::Platform)?
            {
                MacClipboardEffectOutcome::LocalChunkRead { key, offset, bytes } => {
                    Ok(ClipboardPortOutcome::LocalChunk { key, offset, bytes })
                }
                MacClipboardEffectOutcome::RemoteApplied {
                    key,
                    native_revision,
                } => {
                    self.applied = Some((
                        native_revision,
                        AppliedClipboard::Representation(AppliedRepresentation {
                            origin: key.origin,
                            revision: key.revision,
                            hash: key.hash,
                        }),
                    ));
                    Ok(ClipboardPortOutcome::RemoteApplied { key })
                }
                MacClipboardEffectOutcome::RemoteCleared {
                    origin,
                    revision,
                    native_revision,
                } => {
                    self.applied = Some((
                        native_revision,
                        AppliedClipboard::Cleared { origin, revision },
                    ));
                    Ok(ClipboardPortOutcome::RemoteCleared { origin, revision })
                }
                MacClipboardEffectOutcome::ReceiveBegun { .. }
                | MacClipboardEffectOutcome::ReceiveChunkWritten { .. }
                | MacClipboardEffectOutcome::ReceiveAborted { .. } => {
                    Ok(ClipboardPortOutcome::Completed)
                }
            }
        }
    }
}

#[cfg(target_os = "macos")]
pub(crate) use macos::NativeClipboardPort;

#[cfg(target_os = "windows")]
mod windows {
    use std::collections::HashMap;

    use nodavo_clipboard::{ContentHash, MAX_CLIPBOARD_CHUNK_BYTES, RepresentationMeta};
    use nodavo_platform_windows::{ClipboardFormat, WindowsClipboard};
    use zeroize::Zeroize;

    use super::{
        AppliedClipboard, AppliedRepresentation, Bytes, ClipboardEffect, ClipboardObservation,
        ClipboardPort, ClipboardPortError, ClipboardPortOutcome, LocalClipboardChange,
        NativeClipboardRevision, RepresentationKey, RepresentationKind,
    };

    struct ReceiveBuffer {
        expected_len: usize,
        bytes: Vec<u8>,
    }

    impl Drop for ReceiveBuffer {
        fn drop(&mut self) {
            self.bytes.zeroize();
        }
    }

    struct LocalRepresentation {
        kind: RepresentationKind,
        bytes: Vec<u8>,
        hash: ContentHash,
    }

    impl Drop for LocalRepresentation {
        fn drop(&mut self) {
            self.bytes.zeroize();
        }
    }

    struct LocalSnapshot {
        revision: u32,
        representations: Vec<LocalRepresentation>,
    }

    pub(crate) struct NativeClipboardPort {
        clipboard: WindowsClipboard,
        observed_revision: Option<u32>,
        local_snapshot: Option<LocalSnapshot>,
        incoming: HashMap<RepresentationKey, ReceiveBuffer>,
        applied: Option<(u32, AppliedClipboard)>,
    }

    impl NativeClipboardPort {
        pub(crate) fn new() -> Result<Self, ClipboardPortError> {
            Ok(Self {
                clipboard: WindowsClipboard::new().map_err(|_| ClipboardPortError::Platform)?,
                observed_revision: None,
                local_snapshot: None,
                incoming: HashMap::new(),
                applied: None,
            })
        }

        fn read_representation(
            &self,
            format: ClipboardFormat,
            sequence: u32,
        ) -> Result<Option<LocalRepresentation>, ClipboardPortError> {
            let (kind, bytes) = match format {
                ClipboardFormat::UnicodeText => (
                    RepresentationKind::Utf8Text,
                    self.clipboard
                        .read_text(sequence)
                        .map_err(|_| ClipboardPortError::Platform)?
                        .into_bytes(),
                ),
                ClipboardFormat::Html => (
                    RepresentationKind::Html,
                    self.clipboard
                        .read_html(sequence)
                        .map_err(|_| ClipboardPortError::Platform)?
                        .into_bytes(),
                ),
                ClipboardFormat::Png => (
                    RepresentationKind::Png,
                    self.clipboard
                        .read_png(sequence)
                        .map_err(|_| ClipboardPortError::Platform)?,
                ),
                ClipboardFormat::Bmp => (
                    RepresentationKind::Bmp,
                    self.clipboard
                        .read_bmp(sequence)
                        .map_err(|_| ClipboardPortError::Platform)?,
                ),
                ClipboardFormat::Dib | ClipboardFormat::DibV5 => return Ok(None),
            };
            let byte_len = u64::try_from(bytes.len()).map_err(|_| ClipboardPortError::Platform)?;
            if byte_len > kind.max_bytes()
                || (matches!(kind, RepresentationKind::Png | RepresentationKind::Bmp)
                    && bytes.is_empty())
            {
                return Err(ClipboardPortError::Platform);
            }
            let hash = ContentHash::digest(bytes.as_slice());
            Ok(Some(LocalRepresentation { kind, bytes, hash }))
        }

        fn take_applied(&mut self, sequence: u32) -> Option<AppliedClipboard> {
            self.applied
                .take()
                .and_then(|(expected, marker)| (expected == sequence).then_some(marker))
        }

        fn read_local_chunk(
            &self,
            key: RepresentationKey,
            offset: u64,
            max_bytes: usize,
        ) -> Result<ClipboardPortOutcome, ClipboardPortError> {
            if max_bytes == 0 || max_bytes > MAX_CLIPBOARD_CHUNK_BYTES {
                return Err(ClipboardPortError::Platform);
            }
            let snapshot = self
                .local_snapshot
                .as_ref()
                .ok_or(ClipboardPortError::Platform)?;
            if u64::from(snapshot.revision) != key.revision.get() {
                return Err(ClipboardPortError::Platform);
            }
            let representation = snapshot
                .representations
                .iter()
                .find(|representation| {
                    representation.kind == key.kind && representation.hash == key.hash
                })
                .ok_or(ClipboardPortError::Platform)?;
            let start = usize::try_from(offset).map_err(|_| ClipboardPortError::Platform)?;
            let chunk = (start < representation.bytes.len()).then(|| {
                Bytes::copy_from_slice(
                    &representation.bytes[start
                        ..start
                            .saturating_add(max_bytes)
                            .min(representation.bytes.len())],
                )
            });
            Ok(ClipboardPortOutcome::LocalChunk {
                key,
                offset,
                bytes: chunk,
            })
        }

        fn begin_receive(
            &mut self,
            key: RepresentationKey,
            byte_len: u64,
        ) -> Result<ClipboardPortOutcome, ClipboardPortError> {
            if !self.supports(key.kind)
                || byte_len > key.kind.max_bytes()
                || (matches!(key.kind, RepresentationKind::Png | RepresentationKind::Bmp)
                    && byte_len == 0)
                || self.incoming.contains_key(&key)
            {
                return Err(ClipboardPortError::Unsupported);
            }
            self.incoming.insert(
                key,
                ReceiveBuffer {
                    expected_len: usize::try_from(byte_len)
                        .map_err(|_| ClipboardPortError::Platform)?,
                    bytes: Vec::new(),
                },
            );
            Ok(ClipboardPortOutcome::Completed)
        }

        fn write_receive_chunk(
            &mut self,
            key: &RepresentationKey,
            offset: u64,
            bytes: &Bytes,
        ) -> Result<ClipboardPortOutcome, ClipboardPortError> {
            let sink = self
                .incoming
                .get_mut(key)
                .ok_or(ClipboardPortError::Platform)?;
            if usize::try_from(offset).ok() != Some(sink.bytes.len())
                || sink.bytes.len().saturating_add(bytes.len()) > sink.expected_len
            {
                return Err(ClipboardPortError::Platform);
            }
            sink.bytes.extend_from_slice(bytes);
            Ok(ClipboardPortOutcome::Completed)
        }

        fn commit_receive(
            &mut self,
            key: RepresentationKey,
        ) -> Result<ClipboardPortOutcome, ClipboardPortError> {
            let mut sink = self
                .incoming
                .remove(&key)
                .ok_or(ClipboardPortError::Platform)?;
            if sink.bytes.len() != sink.expected_len
                || ContentHash::digest(sink.bytes.as_slice()) != key.hash
            {
                return Err(ClipboardPortError::Platform);
            }
            let revision = match key.kind {
                RepresentationKind::Utf8Text => {
                    let text = std::str::from_utf8(&sink.bytes)
                        .map_err(|_| ClipboardPortError::Platform)?;
                    self.clipboard.write_text(text)
                }
                RepresentationKind::Html => {
                    let fragment = std::str::from_utf8(&sink.bytes)
                        .map_err(|_| ClipboardPortError::Platform)?;
                    self.clipboard.write_html(fragment)
                }
                RepresentationKind::Png => self.clipboard.write_png(&sink.bytes),
                RepresentationKind::Bmp => self.clipboard.write_bmp(&sink.bytes),
                RepresentationKind::FileList => return Err(ClipboardPortError::Unsupported),
            }
            .map_err(|_| ClipboardPortError::Platform)?;
            sink.bytes.zeroize();
            self.applied = Some((
                revision,
                AppliedClipboard::Representation(AppliedRepresentation {
                    origin: key.origin,
                    revision: key.revision,
                    hash: key.hash,
                }),
            ));
            Ok(ClipboardPortOutcome::RemoteApplied { key })
        }

        fn clear_local(
            &mut self,
            origin: nodavo_protocol::DeviceId,
            revision: nodavo_clipboard::ClipboardRevision,
        ) -> Result<ClipboardPortOutcome, ClipboardPortError> {
            let native_revision = self
                .clipboard
                .clear()
                .map_err(|_| ClipboardPortError::Platform)?;
            self.applied = Some((
                native_revision,
                AppliedClipboard::Cleared { origin, revision },
            ));
            Ok(ClipboardPortOutcome::RemoteCleared { origin, revision })
        }
    }

    impl ClipboardPort for NativeClipboardPort {
        fn poll(&mut self) -> Result<Option<ClipboardObservation>, ClipboardPortError> {
            let metadata = self
                .clipboard
                .metadata()
                .map_err(|_| ClipboardPortError::Platform)?;
            if self.observed_revision == Some(metadata.sequence_number) {
                return Ok(None);
            }
            let mut representations = Vec::with_capacity(metadata.formats.len());
            for format in metadata.formats {
                if let Some(representation) =
                    self.read_representation(format.format, metadata.sequence_number)?
                {
                    if representations
                        .iter()
                        .any(|existing: &LocalRepresentation| existing.kind == representation.kind)
                    {
                        return Err(ClipboardPortError::Platform);
                    }
                    representations.push(representation);
                }
            }
            self.observed_revision = Some(metadata.sequence_number);
            if representations.is_empty() {
                self.local_snapshot = None;
                if !metadata.native_types_empty {
                    return Ok(None);
                }
                let applied = self.take_applied(metadata.sequence_number);
                return Ok(Some(ClipboardObservation {
                    revision: NativeClipboardRevision::new(u64::from(metadata.sequence_number)),
                    change: LocalClipboardChange::Cleared,
                    applied,
                }));
            }
            let representation_metadata = representations
                .iter()
                .map(|representation| {
                    Ok(RepresentationMeta {
                        kind: representation.kind,
                        byte_len: u64::try_from(representation.bytes.len())
                            .map_err(|_| ClipboardPortError::Platform)?,
                        hash: representation.hash,
                    })
                })
                .collect::<Result<Vec<_>, ClipboardPortError>>()?;
            self.local_snapshot = Some(LocalSnapshot {
                revision: metadata.sequence_number,
                representations,
            });
            let revision = NativeClipboardRevision::new(u64::from(metadata.sequence_number));
            let applied = self.take_applied(metadata.sequence_number);
            Ok(Some(ClipboardObservation {
                revision,
                change: LocalClipboardChange::Content(representation_metadata),
                applied,
            }))
        }

        fn supports(&self, kind: RepresentationKind) -> bool {
            matches!(
                kind,
                RepresentationKind::Utf8Text
                    | RepresentationKind::Html
                    | RepresentationKind::Png
                    | RepresentationKind::Bmp
            )
        }

        fn execute(
            &mut self,
            effect: ClipboardEffect,
        ) -> Result<ClipboardPortOutcome, ClipboardPortError> {
            match effect {
                ClipboardEffect::ReadLocalChunk {
                    key,
                    offset,
                    max_bytes,
                } => self.read_local_chunk(key, offset, max_bytes),
                ClipboardEffect::BeginReceive { key, byte_len } => {
                    self.begin_receive(key, byte_len)
                }
                ClipboardEffect::WriteReceiveChunk { key, offset, bytes } => {
                    self.write_receive_chunk(&key, offset, &bytes)
                }
                ClipboardEffect::CommitReceive { key } => self.commit_receive(key),
                ClipboardEffect::AbortReceive { key } => {
                    if let Some(mut sink) = self.incoming.remove(&key) {
                        sink.bytes.zeroize();
                    }
                    Ok(ClipboardPortOutcome::Completed)
                }
                ClipboardEffect::ClearLocal { origin, revision } => {
                    self.clear_local(origin, revision)
                }
                _ => Err(ClipboardPortError::Platform),
            }
        }
    }
}

#[cfg(target_os = "windows")]
pub(crate) use windows::NativeClipboardPort;
