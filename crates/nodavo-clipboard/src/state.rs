//! Deterministic clipboard synchronization state and adapter effects.

use std::fmt;

use blake3::Hasher;
use bytes::Bytes;
use nodavo_protocol::DeviceId;

use crate::{
    AppliedRepresentation, ClipboardError, ClipboardOffer, ClipboardRevision, ContentHash,
    LoopGuard, MAX_CLIPBOARD_CHUNK_BYTES, MAX_REPRESENTATIONS, RepresentationKind,
    RepresentationMeta,
};

/// At most one transfer per representation in a valid offer may be active.
pub const MAX_ACTIVE_INCOMING_TRANSFERS: usize = MAX_REPRESENTATIONS;
/// At most one transfer per representation in the current local clipboard may be active.
pub const MAX_ACTIVE_OUTGOING_TRANSFERS: usize = MAX_REPRESENTATIONS;

const ABORT_CANCELLED: u16 = 1;
const ABORT_STALE: u16 = 2;
const ABORT_INTEGRITY: u16 = 3;
const ABORT_GRANT_REVOKED: u16 = 4;
const ABORT_INVALID_STREAM: u16 = 5;

/// A platform-native clipboard sequence or change counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NativeClipboardRevision(u64);

impl NativeClipboardRevision {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Independent decisions about a peer's access to the local clipboard.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PeerClipboardGrants {
    /// The peer may discover and request local clipboard representations.
    pub allow_peer_read: bool,
    /// The peer may offer, stream, and clear the local clipboard.
    pub allow_peer_write: bool,
}

/// Metadata identifying exactly one representation transfer.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RepresentationKey {
    pub origin: DeviceId,
    pub revision: ClipboardRevision,
    pub kind: RepresentationKind,
    pub hash: ContentHash,
}

/// Marker attached by a platform adapter to the native notification caused by
/// applying one remote operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AppliedClipboard {
    Representation(AppliedRepresentation),
    Cleared {
        origin: DeviceId,
        revision: ClipboardRevision,
    },
}

impl From<AppliedRepresentation> for AppliedClipboard {
    fn from(value: AppliedRepresentation) -> Self {
        Self::Representation(value)
    }
}

impl fmt::Debug for RepresentationKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RepresentationKey")
            .field("origin", &self.origin)
            .field("revision", &self.revision)
            .field("kind", &self.kind)
            .field("hash", &self.hash)
            .finish()
    }
}

/// Metadata observed at a platform clipboard boundary. Content stays in the adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalClipboardChange {
    Cleared,
    Content(Vec<RepresentationMeta>),
}

/// Commands for the agent, transport, and platform adapters.
///
/// Custom debug output redacts chunk bytes and content hashes.
#[derive(Clone, PartialEq, Eq)]
pub enum ClipboardEffect {
    SendOffer(ClipboardOffer),
    SendRequest(RepresentationKey),
    SendChunk {
        key: RepresentationKey,
        offset: u64,
        bytes: Bytes,
    },
    SendAbort {
        revision: ClipboardRevision,
        reason: u16,
    },
    RemoteOfferAvailable(ClipboardOffer),
    ReadLocalChunk {
        key: RepresentationKey,
        offset: u64,
        max_bytes: usize,
    },
    BeginReceive {
        key: RepresentationKey,
        byte_len: u64,
    },
    WriteReceiveChunk {
        key: RepresentationKey,
        offset: u64,
        bytes: Bytes,
    },
    CommitReceive {
        key: RepresentationKey,
    },
    AbortReceive {
        key: RepresentationKey,
    },
    ClearLocal {
        origin: DeviceId,
        revision: ClipboardRevision,
    },
}

impl fmt::Debug for ClipboardEffect {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SendOffer(offer) => formatter.debug_tuple("SendOffer").field(offer).finish(),
            Self::SendRequest(key) => formatter.debug_tuple("SendRequest").field(key).finish(),
            Self::SendChunk { key, offset, bytes } => formatter
                .debug_struct("SendChunk")
                .field("key", key)
                .field("offset", offset)
                .field("byte_len", &bytes.len())
                .finish(),
            Self::SendAbort { revision, reason } => formatter
                .debug_struct("SendAbort")
                .field("revision", revision)
                .field("reason", reason)
                .finish(),
            Self::RemoteOfferAvailable(offer) => formatter
                .debug_tuple("RemoteOfferAvailable")
                .field(offer)
                .finish(),
            Self::ReadLocalChunk {
                key,
                offset,
                max_bytes,
            } => formatter
                .debug_struct("ReadLocalChunk")
                .field("key", key)
                .field("offset", offset)
                .field("max_bytes", max_bytes)
                .finish(),
            Self::BeginReceive { key, byte_len } => formatter
                .debug_struct("BeginReceive")
                .field("key", key)
                .field("byte_len", byte_len)
                .finish(),
            Self::WriteReceiveChunk { key, offset, bytes } => formatter
                .debug_struct("WriteReceiveChunk")
                .field("key", key)
                .field("offset", offset)
                .field("byte_len", &bytes.len())
                .finish(),
            Self::CommitReceive { key } => formatter
                .debug_struct("CommitReceive")
                .field("key", key)
                .finish(),
            Self::AbortReceive { key } => formatter
                .debug_struct("AbortReceive")
                .field("key", key)
                .finish(),
            Self::ClearLocal { origin, revision } => formatter
                .debug_struct("ClearLocal")
                .field("origin", origin)
                .field("revision", revision)
                .finish(),
        }
    }
}

/// A rejected state transition plus any cleanup effects which still must run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClipboardFailure {
    pub error: ClipboardError,
    pub effects: Vec<ClipboardEffect>,
}

impl ClipboardFailure {
    fn new(error: ClipboardError) -> Self {
        Self {
            error,
            effects: Vec::new(),
        }
    }

    fn with_effects(error: ClipboardError, effects: Vec<ClipboardEffect>) -> Self {
        Self { error, effects }
    }
}

struct LocalSnapshot {
    native_revision: NativeClipboardRevision,
    offer: ClipboardOffer,
}

struct IncomingTransfer {
    key: RepresentationKey,
    byte_len: u64,
    next_offset: u64,
    local_revision_at_start: Option<NativeClipboardRevision>,
    hasher: Hasher,
    ready: bool,
}

struct OutgoingTransfer {
    key: RepresentationKey,
    byte_len: u64,
    next_offset: u64,
    hasher: Hasher,
}

/// One peer's platform-neutral clipboard synchronization state machine.
pub struct ClipboardState {
    local_device: DeviceId,
    peer_device: DeviceId,
    connected: bool,
    grants: PeerClipboardGrants,
    local: Option<LocalSnapshot>,
    last_native_revision: Option<NativeClipboardRevision>,
    remote: Option<ClipboardOffer>,
    last_remote_revision: Option<ClipboardRevision>,
    incoming: Vec<IncomingTransfer>,
    outgoing: Vec<OutgoingTransfer>,
    loop_guard: LoopGuard,
    applied_clears: Vec<(DeviceId, ClipboardRevision)>,
}

impl fmt::Debug for ClipboardState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClipboardState")
            .field("local_device", &self.local_device)
            .field("peer_device", &self.peer_device)
            .field("connected", &self.connected)
            .field("grants", &self.grants)
            .field("has_local_snapshot", &self.local.is_some())
            .field("last_native_revision", &self.last_native_revision)
            .field("has_remote_offer", &self.remote.is_some())
            .field("last_remote_revision", &self.last_remote_revision)
            .field("incoming_count", &self.incoming.len())
            .field("outgoing_count", &self.outgoing.len())
            .field("loop_marker_count", &self.loop_guard.applied.len())
            .field("applied_clear_count", &self.applied_clears.len())
            .finish()
    }
}

impl ClipboardState {
    #[must_use]
    pub fn new(local_device: DeviceId, peer_device: DeviceId, grants: PeerClipboardGrants) -> Self {
        Self {
            local_device,
            peer_device,
            connected: true,
            grants,
            local: None,
            last_native_revision: None,
            remote: None,
            last_remote_revision: None,
            incoming: Vec::new(),
            outgoing: Vec::new(),
            loop_guard: LoopGuard::default(),
            applied_clears: Vec::new(),
        }
    }

    #[must_use]
    pub const fn grants(&self) -> PeerClipboardGrants {
        self.grants
    }

    #[must_use]
    pub const fn is_connected(&self) -> bool {
        self.connected
    }

    #[must_use]
    pub fn active_incoming(&self) -> usize {
        self.incoming.len()
    }

    #[must_use]
    pub fn active_outgoing(&self) -> usize {
        self.outgoing.len()
    }

    /// Restarts this peer state after transport authentication and grant checks.
    pub fn reconnect(&mut self, grants: PeerClipboardGrants) -> Vec<ClipboardEffect> {
        let mut effects = self.disconnect();
        self.connected = true;
        self.grants = grants;
        self.last_remote_revision = None;
        if grants.allow_peer_read
            && let Some(local) = &self.local
        {
            effects.push(ClipboardEffect::SendOffer(local.offer.clone()));
        }
        effects
    }

    /// Applies independent peer grant decisions and synchronously cleans revoked work.
    pub fn set_grants(&mut self, grants: PeerClipboardGrants) -> Vec<ClipboardEffect> {
        let previous = self.grants;
        self.grants = grants;
        let mut effects = Vec::new();

        if previous.allow_peer_read && !grants.allow_peer_read {
            effects.extend(abort_outgoing(
                &mut self.outgoing,
                ABORT_GRANT_REVOKED,
                true,
            ));
        }
        if previous.allow_peer_write && !grants.allow_peer_write {
            effects.extend(abort_incoming(
                &mut self.incoming,
                ABORT_GRANT_REVOKED,
                true,
            ));
            self.remote = None;
            self.loop_guard.clear();
        }
        if !previous.allow_peer_read
            && grants.allow_peer_read
            && self.connected
            && let Some(local) = &self.local
        {
            effects.push(ClipboardEffect::SendOffer(local.offer.clone()));
        }
        effects
    }

    /// Observes a monotonically increasing native clipboard revision.
    ///
    /// # Errors
    ///
    /// Rejects disconnected, stale, or invalid local metadata transitions.
    pub fn observe_local_change(
        &mut self,
        native_revision: NativeClipboardRevision,
        change: LocalClipboardChange,
        applied: Option<AppliedClipboard>,
    ) -> Result<Vec<ClipboardEffect>, ClipboardFailure> {
        self.require_connected()?;

        if let Some(marker) = applied
            && self.consume_applied(marker)
        {
            let effects = abort_outgoing(&mut self.outgoing, ABORT_STALE, true);
            self.local = None;
            if self
                .last_native_revision
                .is_none_or(|current| native_revision > current)
            {
                self.last_native_revision = Some(native_revision);
            }
            return Ok(effects);
        }
        if self
            .last_native_revision
            .is_some_and(|current| native_revision <= current)
        {
            return Err(ClipboardFailure::new(ClipboardError::StaleRevision));
        }

        let revision = ClipboardRevision::new(native_revision.get());
        let offer = match change {
            LocalClipboardChange::Cleared => ClipboardOffer::Cleared {
                origin: self.local_device,
                revision,
            },
            LocalClipboardChange::Content(representations) => {
                ClipboardOffer::content(self.local_device, revision, representations)
                    .map_err(ClipboardFailure::new)?
            }
        };

        let mut effects = abort_incoming(&mut self.incoming, ABORT_STALE, true);
        effects.extend(abort_outgoing(&mut self.outgoing, ABORT_STALE, true));
        self.remote = None;
        self.last_native_revision = Some(native_revision);
        self.local = Some(LocalSnapshot {
            native_revision,
            offer: offer.clone(),
        });
        if self.grants.allow_peer_read {
            effects.push(ClipboardEffect::SendOffer(offer));
        }
        Ok(effects)
    }

    /// Accepts a peer metadata offer without selecting or allocating its content.
    ///
    /// # Errors
    ///
    /// Rejects unauthorized, invalid-origin, malformed, or stale offers.
    pub fn receive_offer(
        &mut self,
        offer: ClipboardOffer,
    ) -> Result<Vec<ClipboardEffect>, ClipboardFailure> {
        self.require_connected()?;
        self.require_peer_write()?;
        if offer.origin() != self.peer_device {
            return Err(ClipboardFailure::new(ClipboardError::InvalidOffer));
        }
        if let ClipboardOffer::Content {
            origin,
            revision,
            representations,
        } = &offer
        {
            ClipboardOffer::content(*origin, *revision, representations.clone())
                .map_err(ClipboardFailure::new)?;
        }

        if self
            .last_remote_revision
            .is_some_and(|current| offer.revision() <= current)
        {
            if self.remote.as_ref() == Some(&offer) {
                return Ok(Vec::new());
            }
            return Err(ClipboardFailure::new(ClipboardError::StaleRevision));
        }

        let mut effects = abort_incoming(&mut self.incoming, ABORT_STALE, true);
        self.last_remote_revision = Some(offer.revision());
        self.remote = Some(offer.clone());
        match &offer {
            ClipboardOffer::Content { .. } => {
                effects.push(ClipboardEffect::RemoteOfferAvailable(offer));
            }
            ClipboardOffer::Cleared { origin, revision } => {
                effects.push(ClipboardEffect::ClearLocal {
                    origin: *origin,
                    revision: *revision,
                });
            }
        }
        Ok(effects)
    }

    /// Selects one exact representation from the current remote offer.
    ///
    /// # Errors
    ///
    /// Rejects unauthorized, absent, duplicate, over-limit, or invalid empty
    /// representations. Cleanup effects accompany failures when required.
    pub fn request_remote(
        &mut self,
        revision: ClipboardRevision,
        kind: RepresentationKind,
    ) -> Result<Vec<ClipboardEffect>, ClipboardFailure> {
        self.require_connected()?;
        self.require_peer_write()?;
        let ClipboardOffer::Content {
            origin,
            revision: offered_revision,
            representations,
        } = self
            .remote
            .as_ref()
            .ok_or_else(|| ClipboardFailure::new(ClipboardError::TransferNotFound))?
        else {
            return Err(ClipboardFailure::new(ClipboardError::TransferNotFound));
        };
        if revision != *offered_revision {
            return Err(ClipboardFailure::new(ClipboardError::TransferNotFound));
        }
        let meta = representations
            .iter()
            .find(|representation| representation.kind == kind)
            .copied()
            .ok_or_else(|| ClipboardFailure::new(ClipboardError::TransferNotFound))?;
        let key = RepresentationKey {
            origin: *origin,
            revision,
            kind,
            hash: meta.hash,
        };
        if self.incoming.iter().any(|transfer| transfer.key == key) {
            return Err(ClipboardFailure::new(ClipboardError::TransferAlreadyActive));
        }
        if self.incoming.len() >= MAX_ACTIVE_INCOMING_TRANSFERS {
            return Err(ClipboardFailure::new(
                ClipboardError::TooManyActiveTransfers,
            ));
        }

        let hasher = Hasher::new();
        let empty_valid = meta.byte_len != 0 || hash_from_hasher(&hasher) == meta.hash;
        if !empty_valid {
            return Err(ClipboardFailure::with_effects(
                ClipboardError::IntegrityMismatch,
                vec![ClipboardEffect::SendAbort {
                    revision,
                    reason: ABORT_INTEGRITY,
                }],
            ));
        }
        self.incoming.push(IncomingTransfer {
            key,
            byte_len: meta.byte_len,
            next_offset: 0,
            local_revision_at_start: self.last_native_revision,
            hasher,
            ready: meta.byte_len == 0,
        });

        let mut effects = vec![ClipboardEffect::BeginReceive {
            key,
            byte_len: meta.byte_len,
        }];
        if meta.byte_len == 0 {
            effects.push(ClipboardEffect::CommitReceive { key });
        } else {
            effects.push(ClipboardEffect::SendRequest(key));
        }
        Ok(effects)
    }

    /// Consumes one inbound wire chunk after exact key and offset correlation.
    ///
    /// # Errors
    ///
    /// Rejects unauthorized, stale, uncorrelated, oversized, out-of-order, or
    /// integrity-failing chunks and returns required cleanup effects.
    pub fn receive_chunk(
        &mut self,
        key: RepresentationKey,
        offset: u64,
        bytes: Bytes,
    ) -> Result<Vec<ClipboardEffect>, ClipboardFailure> {
        self.require_connected()?;
        self.require_peer_write()?;
        let Some(index) = self
            .incoming
            .iter()
            .position(|transfer| transfer.key == key)
        else {
            return Err(ClipboardFailure::new(ClipboardError::TransferNotFound));
        };
        if self.incoming[index].ready {
            return Err(ClipboardFailure::new(ClipboardError::TransferNotReady));
        }
        if self.incoming[index].local_revision_at_start != self.last_native_revision {
            let transfer = self.incoming.remove(index);
            return Err(ClipboardFailure::with_effects(
                ClipboardError::StaleRevision,
                abort_transfer(transfer.key, ABORT_STALE, true),
            ));
        }
        if bytes.is_empty()
            || bytes.len() > MAX_CLIPBOARD_CHUNK_BYTES
            || offset != self.incoming[index].next_offset
        {
            let transfer = self.incoming.remove(index);
            return Err(ClipboardFailure::with_effects(
                ClipboardError::InvalidChunk,
                abort_transfer(transfer.key, ABORT_INVALID_STREAM, true),
            ));
        }
        let end = offset
            .checked_add(
                u64::try_from(bytes.len())
                    .map_err(|_| ClipboardFailure::new(ClipboardError::InvalidChunk))?,
            )
            .filter(|end| *end <= self.incoming[index].byte_len)
            .ok_or_else(|| ClipboardFailure::new(ClipboardError::InvalidChunk));
        let end = match end {
            Ok(end) => end,
            Err(failure) => {
                let transfer = self.incoming.remove(index);
                return Err(ClipboardFailure::with_effects(
                    failure.error,
                    abort_transfer(transfer.key, ABORT_INVALID_STREAM, true),
                ));
            }
        };

        self.incoming[index].hasher.update(&bytes);
        self.incoming[index].next_offset = end;
        if end == self.incoming[index].byte_len
            && hash_from_hasher(&self.incoming[index].hasher) != key.hash
        {
            let transfer = self.incoming.remove(index);
            return Err(ClipboardFailure::with_effects(
                ClipboardError::IntegrityMismatch,
                abort_transfer(transfer.key, ABORT_INTEGRITY, true),
            ));
        }

        let mut effects = vec![ClipboardEffect::WriteReceiveChunk { key, offset, bytes }];
        if end == self.incoming[index].byte_len {
            self.incoming[index].ready = true;
            effects.push(ClipboardEffect::CommitReceive { key });
        }
        Ok(effects)
    }

    /// Records successful platform application, or cleans up a failed sink.
    ///
    /// # Errors
    ///
    /// Rejects absent or incomplete transfers and reports platform or marker
    /// capacity failures.
    pub fn finish_remote_apply(
        &mut self,
        key: RepresentationKey,
        applied: bool,
    ) -> Result<Vec<ClipboardEffect>, ClipboardFailure> {
        let Some(index) = self
            .incoming
            .iter()
            .position(|transfer| transfer.key == key)
        else {
            return Err(ClipboardFailure::new(ClipboardError::TransferNotFound));
        };
        if !self.incoming[index].ready {
            return Err(ClipboardFailure::new(ClipboardError::TransferNotReady));
        }
        let transfer = self.incoming.remove(index);
        if !applied {
            return Err(ClipboardFailure::with_effects(
                ClipboardError::Platform,
                vec![ClipboardEffect::AbortReceive { key: transfer.key }],
            ));
        }
        self.loop_guard
            .record(AppliedRepresentation {
                origin: key.origin,
                revision: key.revision,
                hash: key.hash,
            })
            .map_err(ClipboardFailure::new)?;
        Ok(Vec::new())
    }

    /// Records a successful remote clear so its native notification is suppressed once.
    ///
    /// # Errors
    ///
    /// Rejects an uncorrelated clear, platform failure, or full marker guard.
    pub fn finish_remote_clear(
        &mut self,
        origin: DeviceId,
        revision: ClipboardRevision,
        applied: bool,
    ) -> Result<Vec<ClipboardEffect>, ClipboardFailure> {
        if !matches!(
            self.remote,
            Some(ClipboardOffer::Cleared {
                origin: offered_origin,
                revision: offered_revision,
            }) if offered_origin == origin && offered_revision == revision
        ) {
            return Err(ClipboardFailure::new(ClipboardError::TransferNotFound));
        }
        if !applied {
            return Err(ClipboardFailure::new(ClipboardError::Platform));
        }
        if self.applied_clears.len() >= MAX_REPRESENTATIONS
            && !self.applied_clears.contains(&(origin, revision))
        {
            return Err(ClipboardFailure::new(ClipboardError::LoopGuardFull));
        }
        if !self.applied_clears.contains(&(origin, revision)) {
            self.applied_clears.push((origin, revision));
        }
        Ok(Vec::new())
    }

    /// Accepts an exact peer request for the current local representation.
    ///
    /// # Errors
    ///
    /// Rejects unauthorized, stale, uncorrelated, duplicate, or over-limit
    /// requests.
    pub fn receive_request(
        &mut self,
        revision: ClipboardRevision,
        kind: RepresentationKind,
        hash: ContentHash,
    ) -> Result<Vec<ClipboardEffect>, ClipboardFailure> {
        self.require_connected()?;
        self.require_peer_read()?;
        let local = self
            .local
            .as_ref()
            .ok_or_else(|| ClipboardFailure::new(ClipboardError::TransferNotFound))?;
        let ClipboardOffer::Content {
            origin,
            revision: offered_revision,
            representations,
        } = &local.offer
        else {
            return Err(ClipboardFailure::new(ClipboardError::TransferNotFound));
        };
        if revision != *offered_revision {
            return Err(ClipboardFailure::new(ClipboardError::TransferNotFound));
        }
        let meta = representations
            .iter()
            .find(|representation| representation.kind == kind && representation.hash == hash)
            .copied()
            .ok_or_else(|| ClipboardFailure::new(ClipboardError::TransferNotFound))?;
        let key = RepresentationKey {
            origin: *origin,
            revision,
            kind,
            hash,
        };
        if self.outgoing.iter().any(|transfer| transfer.key == key) {
            return Err(ClipboardFailure::new(ClipboardError::TransferAlreadyActive));
        }
        if self.outgoing.len() >= MAX_ACTIVE_OUTGOING_TRANSFERS {
            return Err(ClipboardFailure::new(
                ClipboardError::TooManyActiveTransfers,
            ));
        }
        if meta.byte_len == 0 {
            return Ok(Vec::new());
        }
        self.outgoing.push(OutgoingTransfer {
            key,
            byte_len: meta.byte_len,
            next_offset: 0,
            hasher: Hasher::new(),
        });
        Ok(vec![ClipboardEffect::ReadLocalChunk {
            key,
            offset: 0,
            max_bytes: MAX_CLIPBOARD_CHUNK_BYTES,
        }])
    }

    /// Consumes a correlated platform source read and requests the next bounded read.
    ///
    /// # Errors
    ///
    /// Rejects unauthorized, stale, uncorrelated, empty, oversized,
    /// out-of-order, early-ending, or integrity-failing source reads.
    pub fn local_chunk_read(
        &mut self,
        key: RepresentationKey,
        offset: u64,
        bytes: Option<Bytes>,
    ) -> Result<Vec<ClipboardEffect>, ClipboardFailure> {
        self.require_connected()?;
        self.require_peer_read()?;
        let Some(index) = self
            .outgoing
            .iter()
            .position(|transfer| transfer.key == key)
        else {
            return Err(ClipboardFailure::new(ClipboardError::TransferNotFound));
        };
        if self.local.as_ref().map(|local| local.native_revision)
            != Some(NativeClipboardRevision::new(key.revision.get()))
        {
            let transfer = self.outgoing.remove(index);
            return Err(ClipboardFailure::with_effects(
                ClipboardError::StaleRevision,
                vec![ClipboardEffect::SendAbort {
                    revision: transfer.key.revision,
                    reason: ABORT_STALE,
                }],
            ));
        }
        if offset != self.outgoing[index].next_offset {
            let transfer = self.outgoing.remove(index);
            return Err(ClipboardFailure::with_effects(
                ClipboardError::InvalidChunk,
                vec![ClipboardEffect::SendAbort {
                    revision: transfer.key.revision,
                    reason: ABORT_INVALID_STREAM,
                }],
            ));
        }
        let Some(bytes) = bytes else {
            let transfer = self.outgoing.remove(index);
            return Err(ClipboardFailure::with_effects(
                ClipboardError::SourceEndedEarly,
                vec![ClipboardEffect::SendAbort {
                    revision: transfer.key.revision,
                    reason: ABORT_INVALID_STREAM,
                }],
            ));
        };
        if bytes.is_empty() || bytes.len() > MAX_CLIPBOARD_CHUNK_BYTES {
            let transfer = self.outgoing.remove(index);
            return Err(ClipboardFailure::with_effects(
                ClipboardError::InvalidChunk,
                vec![ClipboardEffect::SendAbort {
                    revision: transfer.key.revision,
                    reason: ABORT_INVALID_STREAM,
                }],
            ));
        }
        let end = offset
            .checked_add(
                u64::try_from(bytes.len())
                    .map_err(|_| ClipboardFailure::new(ClipboardError::InvalidChunk))?,
            )
            .filter(|end| *end <= self.outgoing[index].byte_len);
        let Some(end) = end else {
            let transfer = self.outgoing.remove(index);
            return Err(ClipboardFailure::with_effects(
                ClipboardError::InvalidChunk,
                vec![ClipboardEffect::SendAbort {
                    revision: transfer.key.revision,
                    reason: ABORT_INVALID_STREAM,
                }],
            ));
        };

        self.outgoing[index].hasher.update(&bytes);
        self.outgoing[index].next_offset = end;
        if end == self.outgoing[index].byte_len
            && hash_from_hasher(&self.outgoing[index].hasher) != key.hash
        {
            self.outgoing.remove(index);
            return Err(ClipboardFailure::with_effects(
                ClipboardError::IntegrityMismatch,
                vec![ClipboardEffect::SendAbort {
                    revision: key.revision,
                    reason: ABORT_INTEGRITY,
                }],
            ));
        }

        let mut effects = vec![ClipboardEffect::SendChunk { key, offset, bytes }];
        if end == self.outgoing[index].byte_len {
            self.outgoing.remove(index);
        } else {
            effects.push(ClipboardEffect::ReadLocalChunk {
                key,
                offset: end,
                max_bytes: MAX_CLIPBOARD_CHUNK_BYTES,
            });
        }
        Ok(effects)
    }

    /// Applies a protocol abort to all representations in the revision.
    pub fn receive_abort(&mut self, revision: ClipboardRevision) -> Vec<ClipboardEffect> {
        let mut effects = Vec::new();
        self.incoming.retain(|transfer| {
            if transfer.key.revision == revision {
                effects.push(ClipboardEffect::AbortReceive { key: transfer.key });
                false
            } else {
                true
            }
        });
        self.outgoing
            .retain(|transfer| transfer.key.revision != revision);
        effects
    }

    /// Cancels all local work for a revision and informs the connected peer once.
    pub fn cancel_revision(&mut self, revision: ClipboardRevision) -> Vec<ClipboardEffect> {
        let mut effects = self.receive_abort(revision);
        if self.connected {
            effects.push(ClipboardEffect::SendAbort {
                revision,
                reason: ABORT_CANCELLED,
            });
        }
        effects
    }

    /// Drops all peer-derived metadata, loop markers, and active platform sinks.
    pub fn disconnect(&mut self) -> Vec<ClipboardEffect> {
        let effects = abort_incoming(&mut self.incoming, ABORT_CANCELLED, false);
        self.outgoing.clear();
        self.remote = None;
        self.loop_guard.clear();
        self.applied_clears.clear();
        self.connected = false;
        effects
    }

    fn consume_applied(&mut self, marker: AppliedClipboard) -> bool {
        match marker {
            AppliedClipboard::Representation(marker) => self.loop_guard.consume_if_applied(&marker),
            AppliedClipboard::Cleared { origin, revision } => {
                let Some(index) = self
                    .applied_clears
                    .iter()
                    .position(|candidate| *candidate == (origin, revision))
                else {
                    return false;
                };
                self.applied_clears.remove(index);
                true
            }
        }
    }

    fn require_connected(&self) -> Result<(), ClipboardFailure> {
        if self.connected {
            Ok(())
        } else {
            Err(ClipboardFailure::new(ClipboardError::Disconnected))
        }
    }

    fn require_peer_read(&self) -> Result<(), ClipboardFailure> {
        if self.grants.allow_peer_read {
            Ok(())
        } else {
            Err(ClipboardFailure::new(ClipboardError::GrantDenied))
        }
    }

    fn require_peer_write(&self) -> Result<(), ClipboardFailure> {
        if self.grants.allow_peer_write {
            Ok(())
        } else {
            Err(ClipboardFailure::new(ClipboardError::GrantDenied))
        }
    }
}

fn hash_from_hasher(hasher: &Hasher) -> ContentHash {
    ContentHash::from_bytes(*hasher.finalize().as_bytes())
}

fn abort_transfer(key: RepresentationKey, reason: u16, notify_peer: bool) -> Vec<ClipboardEffect> {
    let mut effects = vec![ClipboardEffect::AbortReceive { key }];
    if notify_peer {
        effects.push(ClipboardEffect::SendAbort {
            revision: key.revision,
            reason,
        });
    }
    effects
}

fn abort_incoming(
    incoming: &mut Vec<IncomingTransfer>,
    reason: u16,
    notify_peer: bool,
) -> Vec<ClipboardEffect> {
    let mut effects = Vec::new();
    for transfer in incoming.drain(..) {
        effects.extend(abort_transfer(transfer.key, reason, notify_peer));
    }
    effects
}

fn abort_outgoing(
    outgoing: &mut Vec<OutgoingTransfer>,
    reason: u16,
    notify_peer: bool,
) -> Vec<ClipboardEffect> {
    let mut effects = Vec::new();
    for transfer in outgoing.drain(..) {
        if notify_peer
            && !effects.iter().any(|effect| {
                matches!(
                    effect,
                    ClipboardEffect::SendAbort { revision, .. }
                        if *revision == transfer.key.revision
                )
            })
        {
            effects.push(ClipboardEffect::SendAbort {
                revision: transfer.key.revision,
                reason,
            });
        }
    }
    effects
}

#[cfg(test)]
mod tests {
    use super::*;

    fn devices() -> (DeviceId, DeviceId) {
        (DeviceId::new([1; 32]), DeviceId::new([2; 32]))
    }

    fn text_meta(bytes: &[u8]) -> RepresentationMeta {
        RepresentationMeta {
            kind: RepresentationKind::Utf8Text,
            byte_len: bytes.len() as u64,
            hash: ContentHash::digest(bytes),
        }
    }

    fn writable_state() -> ClipboardState {
        let (local, peer) = devices();
        ClipboardState::new(
            local,
            peer,
            PeerClipboardGrants {
                allow_peer_read: true,
                allow_peer_write: true,
            },
        )
    }

    #[test]
    fn read_and_write_grants_are_independent() {
        let (local, peer) = devices();
        let mut state = ClipboardState::new(local, peer, PeerClipboardGrants::default());
        let effects = state
            .observe_local_change(
                NativeClipboardRevision::new(1),
                LocalClipboardChange::Content(vec![text_meta(b"local")]),
                None,
            )
            .unwrap();
        assert!(effects.is_empty());

        let remote =
            ClipboardOffer::content(peer, ClipboardRevision::new(1), vec![text_meta(b"remote")])
                .unwrap();
        assert_eq!(
            state.receive_offer(remote.clone()).unwrap_err().error,
            ClipboardError::GrantDenied
        );

        let effects = state.set_grants(PeerClipboardGrants {
            allow_peer_read: true,
            allow_peer_write: false,
        });
        assert!(matches!(
            effects.as_slice(),
            [ClipboardEffect::SendOffer(_)]
        ));
        assert_eq!(
            state.receive_offer(remote.clone()).unwrap_err().error,
            ClipboardError::GrantDenied
        );

        state.set_grants(PeerClipboardGrants {
            allow_peer_read: false,
            allow_peer_write: true,
        });
        assert!(matches!(
            state.receive_offer(remote).unwrap().as_slice(),
            [ClipboardEffect::RemoteOfferAvailable(_)]
        ));
        assert_eq!(
            state
                .receive_request(
                    ClipboardRevision::new(1),
                    RepresentationKind::Utf8Text,
                    text_meta(b"local").hash,
                )
                .unwrap_err()
                .error,
            ClipboardError::GrantDenied
        );
    }

    #[test]
    fn inbound_stream_correlates_and_hashes_incrementally() {
        let (_, peer) = devices();
        let content = b"six bytes";
        let meta = text_meta(content);
        let mut state = writable_state();
        state
            .receive_offer(
                ClipboardOffer::content(peer, ClipboardRevision::new(7), vec![meta]).unwrap(),
            )
            .unwrap();
        let effects = state
            .request_remote(ClipboardRevision::new(7), RepresentationKind::Utf8Text)
            .unwrap();
        let key = match effects.as_slice() {
            [
                ClipboardEffect::BeginReceive { key, .. },
                ClipboardEffect::SendRequest(request),
            ] => {
                assert_eq!(key, request);
                *key
            }
            other => panic!("unexpected effects: {other:?}"),
        };

        let first = state
            .receive_chunk(key, 0, Bytes::from_static(&content[..3]))
            .unwrap();
        assert!(matches!(
            first.as_slice(),
            [ClipboardEffect::WriteReceiveChunk { offset: 0, .. }]
        ));
        let failure = state
            .receive_chunk(key, 2, Bytes::from_static(&content[3..]))
            .unwrap_err();
        assert_eq!(failure.error, ClipboardError::InvalidChunk);
        assert!(matches!(
            failure.effects.as_slice(),
            [
                ClipboardEffect::AbortReceive { .. },
                ClipboardEffect::SendAbort { .. }
            ]
        ));
        assert_eq!(state.active_incoming(), 0);

        state
            .request_remote(ClipboardRevision::new(7), RepresentationKind::Utf8Text)
            .unwrap();
        state
            .receive_chunk(key, 0, Bytes::from_static(&content[..3]))
            .unwrap();
        let final_effects = state
            .receive_chunk(key, 3, Bytes::from_static(&content[3..]))
            .unwrap();
        assert!(matches!(
            final_effects.as_slice(),
            [
                ClipboardEffect::WriteReceiveChunk { offset: 3, .. },
                ClipboardEffect::CommitReceive { .. }
            ]
        ));
        state.finish_remote_apply(key, true).unwrap();
        assert_eq!(state.active_incoming(), 0);
    }

    #[test]
    fn integrity_failure_aborts_without_committing() {
        let (_, peer) = devices();
        let advertised = text_meta(b"right");
        let mut state = writable_state();
        state
            .receive_offer(
                ClipboardOffer::content(peer, ClipboardRevision::new(4), vec![advertised]).unwrap(),
            )
            .unwrap();
        let key = match state
            .request_remote(ClipboardRevision::new(4), RepresentationKind::Utf8Text)
            .unwrap()
            .as_slice()
        {
            [ClipboardEffect::BeginReceive { key, .. }, ..] => *key,
            other => panic!("unexpected effects: {other:?}"),
        };
        let failure = state
            .receive_chunk(key, 0, Bytes::from_static(b"wrong"))
            .unwrap_err();
        assert_eq!(failure.error, ClipboardError::IntegrityMismatch);
        assert!(
            !failure
                .effects
                .iter()
                .any(|effect| matches!(effect, ClipboardEffect::CommitReceive { .. }))
        );
        assert_eq!(state.active_incoming(), 0);
    }

    #[test]
    fn outbound_source_reads_are_bounded_and_correlated() {
        let content = Bytes::from_static(b"local content");
        let meta = text_meta(&content);
        let mut state = writable_state();
        state
            .observe_local_change(
                NativeClipboardRevision::new(5),
                LocalClipboardChange::Content(vec![meta]),
                None,
            )
            .unwrap();
        let effects = state
            .receive_request(
                ClipboardRevision::new(5),
                RepresentationKind::Utf8Text,
                meta.hash,
            )
            .unwrap();
        let key = match effects.as_slice() {
            [
                ClipboardEffect::ReadLocalChunk {
                    key,
                    offset: 0,
                    max_bytes,
                },
            ] => {
                assert_eq!(*max_bytes, MAX_CLIPBOARD_CHUNK_BYTES);
                *key
            }
            other => panic!("unexpected effects: {other:?}"),
        };

        let first = state
            .local_chunk_read(key, 0, Some(content.slice(..4)))
            .unwrap();
        assert!(matches!(
            first.as_slice(),
            [
                ClipboardEffect::SendChunk { offset: 0, .. },
                ClipboardEffect::ReadLocalChunk { offset: 4, .. }
            ]
        ));
        let final_effects = state
            .local_chunk_read(key, 4, Some(content.slice(4..)))
            .unwrap();
        assert!(matches!(
            final_effects.as_slice(),
            [ClipboardEffect::SendChunk { offset: 4, .. }]
        ));
        assert_eq!(state.active_outgoing(), 0);
    }

    #[test]
    fn local_change_prevents_stale_remote_overwrite() {
        let (_, peer) = devices();
        let mut state = writable_state();
        state
            .observe_local_change(
                NativeClipboardRevision::new(10),
                LocalClipboardChange::Content(vec![text_meta(b"old local")]),
                None,
            )
            .unwrap();
        state
            .receive_offer(
                ClipboardOffer::content(
                    peer,
                    ClipboardRevision::new(3),
                    vec![text_meta(b"remote")],
                )
                .unwrap(),
            )
            .unwrap();
        let key = match state
            .request_remote(ClipboardRevision::new(3), RepresentationKind::Utf8Text)
            .unwrap()
            .as_slice()
        {
            [ClipboardEffect::BeginReceive { key, .. }, ..] => *key,
            other => panic!("unexpected effects: {other:?}"),
        };

        let effects = state
            .observe_local_change(
                NativeClipboardRevision::new(11),
                LocalClipboardChange::Content(vec![text_meta(b"new local")]),
                None,
            )
            .unwrap();
        assert!(
            effects
                .iter()
                .any(|effect| matches!(effect, ClipboardEffect::AbortReceive { .. }))
        );
        assert_eq!(state.active_incoming(), 0);
        assert_eq!(
            state
                .receive_chunk(key, 0, Bytes::from_static(b"remote"))
                .unwrap_err()
                .error,
            ClipboardError::TransferNotFound
        );
    }

    #[test]
    fn applied_loop_marker_is_consumed_once() {
        let (_, peer) = devices();
        let content = b"remote";
        let mut state = writable_state();
        state
            .receive_offer(
                ClipboardOffer::content(peer, ClipboardRevision::new(2), vec![text_meta(content)])
                    .unwrap(),
            )
            .unwrap();
        let key = match state
            .request_remote(ClipboardRevision::new(2), RepresentationKind::Utf8Text)
            .unwrap()
            .as_slice()
        {
            [ClipboardEffect::BeginReceive { key, .. }, ..] => *key,
            other => panic!("unexpected effects: {other:?}"),
        };
        state
            .receive_chunk(key, 0, Bytes::from_static(content))
            .unwrap();
        state.finish_remote_apply(key, true).unwrap();
        let marker = AppliedRepresentation {
            origin: key.origin,
            revision: key.revision,
            hash: key.hash,
        };

        assert!(
            state
                .observe_local_change(
                    NativeClipboardRevision::new(20),
                    LocalClipboardChange::Content(vec![text_meta(content)]),
                    Some(marker.into()),
                )
                .unwrap()
                .is_empty()
        );
        assert!(matches!(
            state
                .observe_local_change(
                    NativeClipboardRevision::new(21),
                    LocalClipboardChange::Content(vec![text_meta(content)]),
                    Some(marker.into()),
                )
                .unwrap()
                .as_slice(),
            [ClipboardEffect::SendOffer(_)]
        ));
    }

    #[test]
    fn disconnect_aborts_sinks_and_forgets_peer_state() {
        let (_, peer) = devices();
        let mut state = writable_state();
        state
            .receive_offer(
                ClipboardOffer::content(
                    peer,
                    ClipboardRevision::new(8),
                    vec![text_meta(b"remote")],
                )
                .unwrap(),
            )
            .unwrap();
        state
            .request_remote(ClipboardRevision::new(8), RepresentationKind::Utf8Text)
            .unwrap();
        let effects = state.disconnect();
        assert!(matches!(
            effects.as_slice(),
            [ClipboardEffect::AbortReceive { .. }]
        ));
        assert_eq!(state.active_incoming(), 0);
        assert!(!state.is_connected());
        assert_eq!(
            state
                .request_remote(ClipboardRevision::new(8), RepresentationKind::Utf8Text)
                .unwrap_err()
                .error,
            ClipboardError::Disconnected
        );
    }

    #[test]
    fn clear_is_revisioned_and_stale_clear_is_rejected() {
        let (_, peer) = devices();
        let mut state = writable_state();
        let clear = ClipboardOffer::Cleared {
            origin: peer,
            revision: ClipboardRevision::new(12),
        };
        assert!(matches!(
            state.receive_offer(clear.clone()).unwrap().as_slice(),
            [ClipboardEffect::ClearLocal { revision, .. }] if *revision == ClipboardRevision::new(12)
        ));
        state
            .finish_remote_clear(peer, ClipboardRevision::new(12), true)
            .unwrap();
        assert!(
            state
                .observe_local_change(
                    NativeClipboardRevision::new(30),
                    LocalClipboardChange::Cleared,
                    Some(AppliedClipboard::Cleared {
                        origin: peer,
                        revision: ClipboardRevision::new(12),
                    }),
                )
                .unwrap()
                .is_empty()
        );
        assert!(state.receive_offer(clear).unwrap().is_empty());
        assert_eq!(
            state
                .receive_offer(ClipboardOffer::Cleared {
                    origin: peer,
                    revision: ClipboardRevision::new(11),
                })
                .unwrap_err()
                .error,
            ClipboardError::StaleRevision
        );
    }

    #[test]
    fn debug_never_contains_chunk_bytes_or_hash() {
        let (local, _) = devices();
        let bytes = Bytes::from_static(b"secret clipboard text");
        let key = RepresentationKey {
            origin: local,
            revision: ClipboardRevision::new(1),
            kind: RepresentationKind::Utf8Text,
            hash: ContentHash::digest(&bytes),
        };
        let debug = format!(
            "{:?}",
            ClipboardEffect::SendChunk {
                key,
                offset: 0,
                bytes,
            }
        );
        assert!(!debug.contains("secret clipboard text"));
        assert!(!debug.contains(&format!("{:?}", key.hash.as_bytes())));
    }
}
