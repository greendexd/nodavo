//! Capability-checked clipboard reducer and wire-effect executor.

use std::collections::VecDeque;

use bytes::Bytes;
use nodavo_clipboard::{
    ClipboardEffect, ClipboardOffer, ClipboardRevision, ClipboardState, PeerClipboardGrants,
    RepresentationKey, RepresentationKind,
};
use nodavo_protocol::{
    Capability, ClipboardMessage, DeviceId, EventMeta, GrantEpoch, Sequence, SessionId,
};
use thiserror::Error;

use crate::clipboard_port::{ClipboardPort, ClipboardPortError, ClipboardPortOutcome};

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum ClipboardRuntimeError {
    #[error("clipboard protocol validation failed")]
    Protocol,
    #[error("clipboard capability was not granted")]
    GrantDenied,
    #[error("clipboard platform operation failed")]
    Platform,
}

impl From<ClipboardPortError> for ClipboardRuntimeError {
    fn from(_: ClipboardPortError) -> Self {
        Self::Platform
    }
}

pub(crate) struct PeerClipboardRuntime {
    local_device: DeviceId,
    peer_device: DeviceId,
    session_id: SessionId,
    grant_epoch: GrantEpoch,
    local_grants: PeerClipboardGrants,
    peer_capabilities: Capability,
    state: ClipboardState,
    port: Box<dyn ClipboardPort>,
    outbound_sequence: u64,
    inbound_sequence: Option<Sequence>,
    deferred: VecDeque<ClipboardEffect>,
}

impl PeerClipboardRuntime {
    pub(crate) fn new(
        local_device: DeviceId,
        peer_device: DeviceId,
        session_id: SessionId,
        grant_epoch: GrantEpoch,
        local_grants: PeerClipboardGrants,
        peer_capabilities: Capability,
        port: Box<dyn ClipboardPort>,
    ) -> Self {
        let effective_grants = PeerClipboardGrants {
            allow_peer_read: local_grants.allow_peer_read
                && peer_capabilities.contains(Capability::CLIPBOARD_WRITE),
            allow_peer_write: local_grants.allow_peer_write
                && peer_capabilities.contains(Capability::CLIPBOARD_READ),
        };
        Self {
            local_device,
            peer_device,
            session_id,
            grant_epoch,
            local_grants,
            peer_capabilities,
            state: ClipboardState::new(local_device, peer_device, effective_grants),
            port,
            outbound_sequence: 0,
            inbound_sequence: None,
            deferred: VecDeque::new(),
        }
    }

    pub(crate) fn poll(&mut self) -> Result<Vec<ClipboardMessage>, ClipboardRuntimeError> {
        let grants = self.state.grants();
        if !grants.allow_peer_read && !grants.allow_peer_write {
            return Ok(Vec::new());
        }
        let effects = if let Some(observation) = self.port.poll()? {
            self.deferred.clear();
            match self.state.observe_local_change(
                observation.revision,
                observation.change,
                observation.applied,
            ) {
                Ok(effects) => effects,
                Err(failure) => failure.effects,
            }
        } else if let Some(effect) = self.deferred.pop_front() {
            vec![effect]
        } else {
            return Ok(Vec::new());
        };
        self.apply_effects(effects)
    }

    pub(crate) fn receive(
        &mut self,
        message: ClipboardMessage,
    ) -> Result<Vec<ClipboardMessage>, ClipboardRuntimeError> {
        let meta = *message.meta().ok_or(ClipboardRuntimeError::Protocol)?;
        if !message_capability_is_valid(&message, meta.capability()) {
            return Err(ClipboardRuntimeError::Protocol);
        }
        self.validate_remote_meta(&meta)?;
        self.inbound_sequence = Some(meta.sequence());
        let effects = match message {
            ClipboardMessage::Offer {
                revision,
                representations,
                ..
            } => self.state.receive_offer(
                ClipboardOffer::content(
                    self.peer_device,
                    revision.into(),
                    representations
                        .into_iter()
                        .map(TryInto::try_into)
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|_| ClipboardRuntimeError::Protocol)?,
                )
                .map_err(|_| ClipboardRuntimeError::Protocol)?,
            ),
            ClipboardMessage::Clear { revision, .. } => {
                self.state.receive_offer(ClipboardOffer::Cleared {
                    origin: self.peer_device,
                    revision: revision.into(),
                })
            }
            ClipboardMessage::Request {
                revision,
                kind,
                hash,
                ..
            } => self
                .state
                .receive_request(revision.into(), kind.into(), hash.into()),
            ClipboardMessage::Chunk {
                revision,
                kind,
                hash,
                offset,
                bytes,
                ..
            } => self.state.receive_chunk(
                RepresentationKey {
                    origin: self.peer_device,
                    revision: revision.into(),
                    kind: kind.into(),
                    hash: hash.into(),
                },
                offset,
                Bytes::from(bytes),
            ),
            ClipboardMessage::Abort { revision, .. } => {
                let effects = self.state.receive_abort(revision.into());
                return self.apply_effects(effects);
            }
            ClipboardMessage::Unknown { .. } => return Err(ClipboardRuntimeError::Protocol),
        };
        match effects {
            Ok(effects) => self.apply_effects(effects),
            Err(failure) => self.apply_effects(failure.effects),
        }
    }

    pub(crate) fn disconnect(&mut self) {
        self.deferred.clear();
        let effects = self.state.disconnect();
        let _ = self.apply_effects(effects);
    }

    #[allow(clippy::too_many_lines)]
    fn apply_effects(
        &mut self,
        effects: Vec<ClipboardEffect>,
    ) -> Result<Vec<ClipboardMessage>, ClipboardRuntimeError> {
        let mut pending = VecDeque::from(effects);
        let mut outbound = Vec::new();
        while let Some(effect) = pending.pop_front() {
            if matches!(effect, ClipboardEffect::ReadLocalChunk { .. })
                && outbound
                    .iter()
                    .any(|message| matches!(message, ClipboardMessage::Chunk { .. }))
            {
                self.deferred.push_back(effect);
                self.deferred.extend(pending);
                break;
            }
            match effect {
                ClipboardEffect::SendOffer(offer) => {
                    self.require_peer(Capability::CLIPBOARD_WRITE)?;
                    let meta = self.next_meta(Capability::CLIPBOARD_WRITE);
                    outbound.push(match offer {
                        ClipboardOffer::Cleared { revision, .. } => ClipboardMessage::Clear {
                            meta,
                            revision: revision.into(),
                        },
                        ClipboardOffer::Content {
                            revision,
                            representations,
                            ..
                        } => ClipboardMessage::Offer {
                            meta,
                            revision: revision.into(),
                            representations: representations.into_iter().map(Into::into).collect(),
                        },
                    });
                }
                ClipboardEffect::SendRequest(key) => {
                    self.require_peer(Capability::CLIPBOARD_READ)?;
                    outbound.push(ClipboardMessage::Request {
                        meta: self.next_meta(Capability::CLIPBOARD_READ),
                        revision: key.revision.into(),
                        kind: key.kind.into(),
                        hash: key.hash.into(),
                    });
                }
                ClipboardEffect::SendChunk { key, offset, bytes } => {
                    self.require_peer(Capability::CLIPBOARD_WRITE)?;
                    outbound.push(ClipboardMessage::Chunk {
                        meta: self.next_meta(Capability::CLIPBOARD_WRITE),
                        revision: key.revision.into(),
                        kind: key.kind.into(),
                        hash: key.hash.into(),
                        offset,
                        bytes: bytes.to_vec(),
                    });
                }
                ClipboardEffect::SendAbort { revision, reason } => {
                    let capability = if self.peer_capabilities.contains(Capability::CLIPBOARD_READ)
                    {
                        Capability::CLIPBOARD_READ
                    } else {
                        Capability::CLIPBOARD_WRITE
                    };
                    self.require_peer(capability)?;
                    outbound.push(ClipboardMessage::Abort {
                        meta: self.next_meta(capability),
                        revision: revision.into(),
                        reason,
                    });
                }
                ClipboardEffect::RemoteOfferAvailable(offer) => {
                    if let Some((revision, kind)) =
                        select_representation(&offer, self.port.as_ref())
                    {
                        match self.state.request_remote(revision, kind) {
                            Ok(effects) => pending.extend(effects),
                            Err(failure) => pending.extend(failure.effects),
                        }
                    }
                }
                platform_effect @ (ClipboardEffect::ReadLocalChunk { .. }
                | ClipboardEffect::BeginReceive { .. }
                | ClipboardEffect::WriteReceiveChunk { .. }
                | ClipboardEffect::CommitReceive { .. }
                | ClipboardEffect::AbortReceive { .. }
                | ClipboardEffect::ClearLocal { .. }) => {
                    let cleanup_revision = match &platform_effect {
                        ClipboardEffect::ReadLocalChunk { key, .. }
                        | ClipboardEffect::BeginReceive { key, .. }
                        | ClipboardEffect::WriteReceiveChunk { key, .. }
                        | ClipboardEffect::CommitReceive { key }
                        | ClipboardEffect::AbortReceive { key } => key.revision,
                        ClipboardEffect::ClearLocal { revision, .. } => *revision,
                        _ => unreachable!("platform clipboard effects are exhaustively matched"),
                    };
                    let Ok(outcome) = self.port.execute(platform_effect) else {
                        pending.extend(self.state.cancel_revision(cleanup_revision));
                        continue;
                    };
                    match outcome {
                        ClipboardPortOutcome::Completed => {}
                        ClipboardPortOutcome::LocalChunk { key, offset, bytes } => {
                            match self.state.local_chunk_read(key, offset, bytes) {
                                Ok(effects) => pending.extend(effects),
                                Err(failure) => pending.extend(failure.effects),
                            }
                        }
                        ClipboardPortOutcome::RemoteApplied { key } => {
                            match self.state.finish_remote_apply(key, true) {
                                Ok(effects) => pending.extend(effects),
                                Err(failure) => pending.extend(failure.effects),
                            }
                        }
                        ClipboardPortOutcome::RemoteCleared { origin, revision } => {
                            match self.state.finish_remote_clear(origin, revision, true) {
                                Ok(effects) => pending.extend(effects),
                                Err(failure) => pending.extend(failure.effects),
                            }
                        }
                    }
                }
            }
        }
        Ok(outbound)
    }

    fn validate_remote_meta(&self, meta: &EventMeta) -> Result<(), ClipboardRuntimeError> {
        if meta.session_id() != self.session_id
            || meta.origin() != self.peer_device
            || meta.grant_epoch() != self.grant_epoch
            || meta.sequence().is_zero()
            || self
                .inbound_sequence
                .is_some_and(|last| meta.sequence() <= last)
        {
            return Err(ClipboardRuntimeError::Protocol);
        }
        let allowed = match meta.capability() {
            Capability::CLIPBOARD_READ => self.local_grants.allow_peer_read,
            Capability::CLIPBOARD_WRITE => self.local_grants.allow_peer_write,
            _ => false,
        };
        if allowed {
            Ok(())
        } else {
            Err(ClipboardRuntimeError::GrantDenied)
        }
    }

    fn require_peer(&self, capability: Capability) -> Result<(), ClipboardRuntimeError> {
        if self.peer_capabilities.contains(capability) {
            Ok(())
        } else {
            Err(ClipboardRuntimeError::GrantDenied)
        }
    }

    fn next_meta(&mut self, capability: Capability) -> EventMeta {
        self.outbound_sequence = self.outbound_sequence.wrapping_add(1).max(1);
        EventMeta::new(
            self.session_id,
            self.local_device,
            Sequence::new(self.outbound_sequence),
            self.grant_epoch,
            capability,
        )
    }
}

impl Drop for PeerClipboardRuntime {
    fn drop(&mut self) {
        for effect in self.state.disconnect() {
            let _ = self.port.execute(effect);
        }
    }
}

fn select_representation(
    offer: &ClipboardOffer,
    port: &dyn ClipboardPort,
) -> Option<(ClipboardRevision, RepresentationKind)> {
    let ClipboardOffer::Content {
        revision,
        representations,
        ..
    } = offer
    else {
        return None;
    };
    [
        RepresentationKind::Utf8Text,
        RepresentationKind::Html,
        RepresentationKind::Png,
        RepresentationKind::Bmp,
    ]
    .into_iter()
    .find(|kind| {
        port.supports(*kind)
            && representations
                .iter()
                .any(|representation| representation.kind == *kind)
    })
    .map(|kind| (*revision, kind))
}

fn message_capability_is_valid(message: &ClipboardMessage, capability: Capability) -> bool {
    match message {
        ClipboardMessage::Offer { .. }
        | ClipboardMessage::Clear { .. }
        | ClipboardMessage::Chunk { .. } => capability == Capability::CLIPBOARD_WRITE,
        ClipboardMessage::Request { .. } => capability == Capability::CLIPBOARD_READ,
        ClipboardMessage::Abort { .. } => {
            capability == Capability::CLIPBOARD_READ || capability == Capability::CLIPBOARD_WRITE
        }
        ClipboardMessage::Unknown { .. } => false,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use nodavo_clipboard::{
        ContentHash, LocalClipboardChange, MAX_CLIPBOARD_CHUNK_BYTES, NativeClipboardRevision,
        RepresentationMeta,
    };

    use super::*;
    use crate::clipboard_port::{ClipboardObservation, ClipboardPortOutcome};

    struct MemoryPort {
        observation: Option<ClipboardObservation>,
        source: Bytes,
        receive: Vec<u8>,
        applied: Arc<Mutex<Vec<u8>>>,
    }

    impl ClipboardPort for MemoryPort {
        fn poll(&mut self) -> Result<Option<ClipboardObservation>, ClipboardPortError> {
            Ok(self.observation.take())
        }

        fn supports(&self, kind: RepresentationKind) -> bool {
            kind == RepresentationKind::Utf8Text
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
                } => {
                    let start = usize::try_from(offset).unwrap();
                    let bytes = (start < self.source.len()).then(|| {
                        self.source
                            .slice(start..start.saturating_add(max_bytes).min(self.source.len()))
                    });
                    Ok(ClipboardPortOutcome::LocalChunk { key, offset, bytes })
                }
                ClipboardEffect::BeginReceive { .. } | ClipboardEffect::AbortReceive { .. } => {
                    self.receive.clear();
                    Ok(ClipboardPortOutcome::Completed)
                }
                ClipboardEffect::WriteReceiveChunk { bytes, .. } => {
                    self.receive.extend_from_slice(&bytes);
                    Ok(ClipboardPortOutcome::Completed)
                }
                ClipboardEffect::CommitReceive { key } => {
                    *self.applied.lock().unwrap() = self.receive.clone();
                    Ok(ClipboardPortOutcome::RemoteApplied { key })
                }
                _ => Err(ClipboardPortError::Unsupported),
            }
        }
    }

    #[test]
    fn two_peers_stream_bounded_content_with_independent_grants() {
        let content = Bytes::from(vec![0x5a; MAX_CLIPBOARD_CHUNK_BYTES + 17]);
        let hash = ContentHash::digest(&content);
        let applied = Arc::new(Mutex::new(Vec::new()));
        let session = SessionId::new([8; 16]);
        let a_device = DeviceId::new([1; 32]);
        let b_device = DeviceId::new([2; 32]);
        let mut a = PeerClipboardRuntime::new(
            a_device,
            b_device,
            session,
            GrantEpoch::new(1),
            PeerClipboardGrants {
                allow_peer_read: true,
                allow_peer_write: false,
            },
            Capability::CLIPBOARD_WRITE,
            Box::new(MemoryPort {
                observation: Some(ClipboardObservation {
                    revision: NativeClipboardRevision::new(1),
                    change: LocalClipboardChange::Content(vec![RepresentationMeta {
                        kind: RepresentationKind::Utf8Text,
                        byte_len: u64::try_from(content.len()).unwrap(),
                        hash,
                    }]),
                    applied: None,
                }),
                source: content.clone(),
                receive: Vec::new(),
                applied: Arc::new(Mutex::new(Vec::new())),
            }),
        );
        let mut b = PeerClipboardRuntime::new(
            b_device,
            a_device,
            session,
            GrantEpoch::new(1),
            PeerClipboardGrants {
                allow_peer_read: false,
                allow_peer_write: true,
            },
            Capability::CLIPBOARD_READ,
            Box::new(MemoryPort {
                observation: None,
                source: Bytes::new(),
                receive: Vec::new(),
                applied: Arc::clone(&applied),
            }),
        );

        let offer = a.poll().unwrap().pop().unwrap();
        let request = b.receive(offer).unwrap().pop().unwrap();
        let first = a.receive(request).unwrap();
        assert!(matches!(
            first.as_slice(),
            [ClipboardMessage::Chunk { bytes, .. }] if bytes.len() == MAX_CLIPBOARD_CHUNK_BYTES
        ));
        assert!(
            b.receive(first.into_iter().next().unwrap())
                .unwrap()
                .is_empty()
        );
        let final_chunk = a.poll().unwrap();
        assert!(matches!(
            final_chunk.as_slice(),
            [ClipboardMessage::Chunk { bytes, .. }] if bytes.len() == 17
        ));
        assert!(
            b.receive(final_chunk.into_iter().next().unwrap())
                .unwrap()
                .is_empty()
        );
        assert_eq!(applied.lock().unwrap().as_slice(), content.as_ref());
    }
}
