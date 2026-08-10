//! Authenticated, bounded receive-side file-transfer coordination.
//!
//! Manifest/control and data frames deliberately keep independent replay
//! lanes. QUIC may deliver those channels independently, so sharing one
//! sequence watermark would reject valid traffic or admit a replay after a
//! channel reset.

use std::collections::{HashMap, HashSet, VecDeque};

use bytes::Bytes;
use nodavo_protocol::{
    Capability, ContentHash as WireContentHash, DeviceId, EventMeta, FileDataMessage,
    FileManifestMessage, GrantEpoch, ManifestEntry as WireManifestEntry,
    ManifestEntryKind as WireEntryKind, RelativePath as WireRelativePath, Sequence, SessionId,
    TransferId as WireTransferId, decode_file_data, decode_file_manifest, encode_file_data,
    encode_file_manifest,
};
use nodavo_transfer::{
    ContentHash, EntryKind, MAX_QUEUED_TRANSFERS, ManifestEntry, QueueEffect, ResumableStagingArea,
    StagingArea, TransferChunk, TransferError, TransferId, TransferManifest, TransferQueue,
    TransferQueueState,
};
use thiserror::Error;

use crate::transfer_status::MAX_LIFETIME_TRANSFER_IDENTITIES;

const MAX_COMPLETED_INBOUND_TOMBSTONES: usize = MAX_LIFETIME_TRANSFER_IDENTITIES;
const MAX_REJECTED_INBOUND_TOMBSTONES: usize = MAX_LIFETIME_TRANSFER_IDENTITIES * 2;
const MAX_CANCELLED_OUTBOUND_TOMBSTONES: usize = MAX_LIFETIME_TRANSFER_IDENTITIES;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub(crate) enum TransferRuntimeError {
    #[error("file-transfer frame or type conversion failed validation")]
    Protocol,
    #[error("file-transfer metadata does not match the authenticated peer session")]
    Authentication,
    #[error("the peer does not hold the required file-transfer grant")]
    GrantDenied,
    #[error("file-transfer sequence is zero, replayed, or out of order")]
    Replay,
    #[error("the bounded transfer owner must stop polling this transfer stream")]
    Backpressure,
    #[error("outbound file-transfer sequence space is exhausted")]
    SequenceExhausted,
    #[error("persisted inbound resume lacks a supported crash-durability guarantee")]
    ResumeDurabilityUnsupported,
    #[error("file-transfer receiver or queue transition failed")]
    Transfer(#[from] TransferError),
}

/// Filename-free actions for the session/transport integration layer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TransferRuntimeEffect {
    Admitted {
        transfer: WireTransferId,
        total_bytes: u64,
    },
    Started {
        transfer: WireTransferId,
    },
    Progress {
        transfer: WireTransferId,
        completed_bytes: u64,
        total_bytes: u64,
    },
    /// Stop polling this transfer's data stream until `BackpressureReleased`.
    Backpressured {
        transfer: WireTransferId,
    },
    BackpressureReleased {
        transfer: WireTransferId,
    },
    /// The manifest was not retained because the bounded queue is full.
    QueueSaturated {
        transfer: WireTransferId,
    },
    /// Send this staging-owned offset to accept/start peer data.
    ResumeRequired {
        transfer: WireTransferId,
        entry_index: u32,
        offset: u64,
    },
    Completed {
        transfer: WireTransferId,
    },
    /// Durable bytes and the authenticated peer terminal marker are both
    /// present. The worker must linearize finalization against local cancel
    /// before invoking slow integrity verification/publication.
    FinalizeRequired {
        transfer: WireTransferId,
    },
    Cancelled {
        transfer: WireTransferId,
    },
    /// Forward to the independently owned outbound-transfer source.
    PeerResumeRequested {
        transfer: WireTransferId,
        entry_index: u32,
        offset: u64,
    },
    /// The receiver rejected/cancelled one locally selected outbound source.
    PeerCancelRequested {
        transfer: WireTransferId,
    },
    /// The peer successfully published one outbound transfer and acknowledged
    /// its terminal marker on the response sequence lane. This does not imply
    /// unsupported platform power-loss guarantees.
    PeerCompleteAcknowledged {
        transfer: WireTransferId,
    },
    /// Re-acknowledge a transfer that this process already published. This
    /// prevents a lost terminal acknowledgement from creating a duplicate.
    CompletionAcknowledgementRequired {
        transfer: WireTransferId,
    },
    RejectionAcknowledgementRequired {
        transfer: WireTransferId,
    },
    AdvanceQueue,
}

#[derive(Clone, Copy)]
enum SequenceLane {
    Manifest,
    Data,
}

/// Owns one inbound staging receiver plus a bounded FIFO of peer manifests.
pub(crate) struct PeerTransferRuntime<S> {
    local_device: DeviceId,
    peer_device: DeviceId,
    session_id: SessionId,
    local_grant_epoch: GrantEpoch,
    peer_grant_epoch: GrantEpoch,
    local_allows_peer_transfer: bool,
    peer_capabilities: Capability,
    receiver: nodavo_transfer::TransferReceiver<S>,
    queue: TransferQueue,
    pending_manifests: HashMap<TransferId, TransferManifest>,
    pending_completion: HashSet<TransferId>,
    completed_inbound: HashSet<TransferId>,
    rejected_inbound: HashSet<TransferId>,
    cancelled_outbound: HashSet<TransferId>,
    known_persisted_inbound: HashSet<TransferId>,
    allow_untracked_persisted_resume: bool,
    backpressured: HashSet<TransferId>,
    deferred_queue_effects: VecDeque<QueueEffect>,
    inbound_manifest_sequence: Option<Sequence>,
    inbound_resume_sequence: Option<Sequence>,
    inbound_data_sequence: Option<Sequence>,
    outbound_manifest_sequence: u64,
    outbound_resume_sequence: u64,
    outbound_data_sequence: u64,
}

#[derive(Clone, Copy)]
pub(crate) struct PeerTransferConfig {
    pub(crate) local_device: DeviceId,
    pub(crate) peer_device: DeviceId,
    pub(crate) session_id: SessionId,
    pub(crate) local_grant_epoch: GrantEpoch,
    pub(crate) peer_grant_epoch: GrantEpoch,
    pub(crate) local_allows_peer_transfer: bool,
    pub(crate) peer_capabilities: Capability,
}

impl<S> PeerTransferRuntime<S>
where
    S: StagingArea,
{
    /// Creates a receiver with exactly one active staging owner.
    ///
    /// The underlying transfer queue still bounds retained queued/terminal
    /// records. Only one pre-read chunk may be retained for each queued
    /// transfer while the transport applies backpressure.
    pub(crate) fn new(config: PeerTransferConfig, staging: S) -> Self {
        Self {
            local_device: config.local_device,
            peer_device: config.peer_device,
            session_id: config.session_id,
            local_grant_epoch: config.local_grant_epoch,
            peer_grant_epoch: config.peer_grant_epoch,
            local_allows_peer_transfer: config.local_allows_peer_transfer,
            peer_capabilities: config.peer_capabilities,
            receiver: nodavo_transfer::TransferReceiver::new(staging),
            queue: TransferQueue::new(1).expect("one active transfer is within the fixed limit"),
            pending_manifests: HashMap::new(),
            pending_completion: HashSet::new(),
            completed_inbound: HashSet::new(),
            rejected_inbound: HashSet::new(),
            cancelled_outbound: HashSet::new(),
            known_persisted_inbound: HashSet::new(),
            allow_untracked_persisted_resume: true,
            backpressured: HashSet::new(),
            deferred_queue_effects: VecDeque::new(),
            inbound_manifest_sequence: None,
            inbound_resume_sequence: None,
            inbound_data_sequence: None,
            outbound_manifest_sequence: 0,
            outbound_resume_sequence: 0,
            outbound_data_sequence: 0,
        }
    }

    /// Applies a locally persisted permission epoch before its authenticated
    /// grant/revoke control is sent to the peer.
    #[cfg(test)]
    pub(crate) fn update_local_grants(
        &mut self,
        epoch: GrantEpoch,
        local_allows_peer_transfer: bool,
    ) -> Result<Vec<TransferRuntimeEffect>, TransferRuntimeError> {
        if !is_next_epoch(self.local_grant_epoch, epoch) {
            return Err(TransferRuntimeError::Protocol);
        }
        self.local_grant_epoch = epoch;
        self.local_allows_peer_transfer = local_allows_peer_transfer;
        self.inbound_manifest_sequence = None;
        self.inbound_data_sequence = None;
        self.outbound_resume_sequence = 0;
        if local_allows_peer_transfer {
            Ok(Vec::new())
        } else {
            self.abort_inbound()
        }
    }

    /// Decodes and applies one bounded manifest/control-channel frame.
    #[cfg(test)]
    pub(crate) async fn receive_manifest_frame(
        &mut self,
        frame: &[u8],
    ) -> Result<Vec<TransferRuntimeEffect>, TransferRuntimeError> {
        let message = decode_file_manifest(frame).map_err(|_| TransferRuntimeError::Protocol)?;
        let meta = *message.meta().ok_or(TransferRuntimeError::Protocol)?;
        self.validate_manifest_message_meta(&message, &meta)?;

        self.receive_manifest_message(message).await
    }

    async fn receive_manifest_message(
        &mut self,
        message: FileManifestMessage,
    ) -> Result<Vec<TransferRuntimeEffect>, TransferRuntimeError> {
        match message {
            FileManifestMessage::Manifest {
                transfer, entries, ..
            } => self.receive_manifest(transfer, entries).await,
            FileManifestMessage::Resume {
                transfer,
                entry_index,
                offset,
                ..
            } => {
                let core = transfer_from_wire(transfer)?;
                if self.cancelled_outbound.contains(&core) {
                    Ok(Vec::new())
                } else {
                    Ok(vec![TransferRuntimeEffect::PeerResumeRequested {
                        transfer,
                        entry_index,
                        offset,
                    }])
                }
            }
            FileManifestMessage::Cancel { transfer, .. } => {
                let core = transfer_from_wire(transfer)?;
                if self.rejected_inbound.contains(&core) {
                    Ok(Vec::new())
                } else if self.completed_inbound.contains(&core) {
                    Ok(vec![
                        TransferRuntimeEffect::CompletionAcknowledgementRequired { transfer },
                    ])
                } else if self.queue.get(core).is_some() {
                    self.receive_cancel(transfer).await
                } else if self.cancelled_outbound.contains(&core) {
                    Ok(Vec::new())
                } else {
                    Ok(vec![TransferRuntimeEffect::PeerCancelRequested {
                        transfer,
                    }])
                }
            }
            FileManifestMessage::Complete { transfer, .. } => {
                let core = transfer_from_wire(transfer)?;
                if self.rejected_inbound.contains(&core) {
                    Ok(vec![
                        TransferRuntimeEffect::RejectionAcknowledgementRequired { transfer },
                    ])
                } else if self.completed_inbound.contains(&core) {
                    Ok(vec![
                        TransferRuntimeEffect::CompletionAcknowledgementRequired { transfer },
                    ])
                } else if self.queue.get(core).is_some() {
                    self.receive_complete(transfer)
                } else if self.cancelled_outbound.contains(&core) {
                    Ok(Vec::new())
                } else {
                    Ok(vec![TransferRuntimeEffect::PeerCompleteAcknowledged {
                        transfer,
                    }])
                }
            }
            FileManifestMessage::Unknown { .. } => Err(TransferRuntimeError::Protocol),
        }
    }

    /// Decodes and applies one bounded file-data-channel frame.
    pub(crate) async fn receive_data_frame(
        &mut self,
        frame: &[u8],
    ) -> Result<Vec<TransferRuntimeEffect>, TransferRuntimeError> {
        let message = decode_file_data(frame).map_err(|_| TransferRuntimeError::Protocol)?;
        let meta = *message.meta().ok_or(TransferRuntimeError::Protocol)?;
        self.validate_remote_meta(&meta, SequenceLane::Data)?;

        let FileDataMessage::Chunk {
            transfer,
            entry_index,
            offset,
            bytes,
            ..
        } = message
        else {
            return Err(TransferRuntimeError::Protocol);
        };
        let transfer = transfer_from_wire(transfer)?;
        if self.rejected_inbound.contains(&transfer) || self.completed_inbound.contains(&transfer) {
            return Ok(Vec::new());
        }
        let chunk = TransferChunk {
            transfer,
            entry_index,
            offset,
            bytes: Bytes::from(bytes),
        };
        let state = self
            .queue
            .get(transfer)
            .map(nodavo_transfer::QueuedTransfer::state)
            .ok_or(TransferRuntimeError::Protocol)?;
        // Data is admitted only after this runtime has emitted every exact
        // Resume acceptance for the active manifest. Shared-channel transports
        // cannot flow-control one queued transfer independently, so retaining
        // even one pre-acceptance chunk would create an unauthorised buffer.
        if state != TransferQueueState::Active {
            return Err(TransferRuntimeError::Protocol);
        }

        self.receiver.write(chunk).await?;
        let snapshot = self
            .receiver
            .snapshot()
            .ok_or(TransferRuntimeError::Protocol)?;
        self.queue
            .record_progress(transfer, snapshot.completed_bytes())?;
        let mut effects = vec![TransferRuntimeEffect::Progress {
            transfer: transfer_to_wire(transfer),
            completed_bytes: snapshot.completed_bytes(),
            total_bytes: snapshot.total_bytes(),
        }];
        if snapshot.completed_bytes() == snapshot.total_bytes()
            && self.pending_completion.remove(&transfer)
        {
            effects.push(TransferRuntimeEffect::FinalizeRequired {
                transfer: transfer_to_wire(transfer),
            });
        }
        Ok(effects)
    }

    /// Encodes one validated outbound manifest using the manifest sequence lane.
    pub(crate) fn encode_manifest_frame(
        &mut self,
        transfer: TransferId,
        manifest: &TransferManifest,
    ) -> Result<Vec<u8>, TransferRuntimeError> {
        self.require_peer_transfer_grant()?;
        let message = FileManifestMessage::Manifest {
            meta: self.next_manifest_meta()?,
            transfer: transfer_to_wire(transfer),
            entries: manifest_to_wire(manifest)?,
        };
        encode_file_manifest(&message).map_err(|_| TransferRuntimeError::Protocol)
    }

    #[must_use]
    pub(crate) fn outbound_authorized(&self) -> bool {
        self.peer_capabilities.contains(Capability::FILE_TRANSFER)
    }

    /// Seeds process-lifetime terminal bindings into a new authenticated
    /// session runtime. The owning store keeps these bindings peer-scoped.
    pub(crate) fn remember_completed_inbound(
        &mut self,
        transfers: &[TransferId],
    ) -> Result<(), TransferRuntimeError> {
        extend_bounded_tombstones(
            &mut self.completed_inbound,
            transfers,
            MAX_COMPLETED_INBOUND_TOMBSTONES,
        )
    }

    pub(crate) fn remember_rejected_inbound(
        &mut self,
        transfers: &[TransferId],
    ) -> Result<(), TransferRuntimeError> {
        extend_bounded_tombstones(
            &mut self.rejected_inbound,
            transfers,
            MAX_REJECTED_INBOUND_TOMBSTONES,
        )
    }

    pub(crate) fn remember_cancelled_outbound(
        &mut self,
        transfers: &[TransferId],
    ) -> Result<(), TransferRuntimeError> {
        extend_bounded_tombstones(
            &mut self.cancelled_outbound,
            transfers,
            MAX_CANCELLED_OUTBOUND_TOMBSTONES,
        )
    }

    /// Encodes one authenticated exact resume/acceptance control.
    pub(crate) fn encode_resume_frame(
        &mut self,
        transfer: WireTransferId,
        entry_index: u32,
        offset: u64,
    ) -> Result<Vec<u8>, TransferRuntimeError> {
        if !self.local_allows_peer_transfer {
            return Err(TransferRuntimeError::GrantDenied);
        }
        encode_file_manifest(&FileManifestMessage::Resume {
            meta: self.next_response_meta()?,
            transfer,
            entry_index,
            offset,
        })
        .map_err(|_| TransferRuntimeError::Protocol)
    }

    /// Encodes a bounded receiver-side rejection under the original grant epoch.
    pub(crate) fn encode_cancel_frame(
        &mut self,
        transfer: WireTransferId,
        reason: u16,
    ) -> Result<Vec<u8>, TransferRuntimeError> {
        if !self.local_allows_peer_transfer {
            return Err(TransferRuntimeError::GrantDenied);
        }
        encode_file_manifest(&FileManifestMessage::Cancel {
            meta: self.next_response_meta()?,
            transfer,
            reason,
        })
        .map_err(|_| TransferRuntimeError::Protocol)
    }

    /// Encodes a locally initiated cancellation for a selected outbound
    /// source on the sender's authenticated manifest sequence lane.
    pub(crate) fn encode_outbound_cancel_frame(
        &mut self,
        transfer: TransferId,
        reason: u16,
    ) -> Result<Vec<u8>, TransferRuntimeError> {
        self.require_peer_transfer_grant()?;
        encode_file_manifest(&FileManifestMessage::Cancel {
            meta: self.next_manifest_meta()?,
            transfer: transfer_to_wire(transfer),
            reason,
        })
        .map_err(|_| TransferRuntimeError::Protocol)
    }

    /// Encodes one authenticated terminal marker after the source reaches EOF.
    pub(crate) fn encode_complete_frame(
        &mut self,
        transfer: TransferId,
    ) -> Result<Vec<u8>, TransferRuntimeError> {
        self.require_peer_transfer_grant()?;
        encode_file_manifest(&FileManifestMessage::Complete {
            meta: self.next_manifest_meta()?,
            transfer: transfer_to_wire(transfer),
        })
        .map_err(|_| TransferRuntimeError::Protocol)
    }

    /// Encodes a receiver-side publication acknowledgement on the response
    /// lane. The sender retains its source until this frame arrives.
    pub(crate) fn encode_complete_ack_frame(
        &mut self,
        transfer: WireTransferId,
    ) -> Result<Vec<u8>, TransferRuntimeError> {
        if !self.local_allows_peer_transfer {
            return Err(TransferRuntimeError::GrantDenied);
        }
        encode_file_manifest(&FileManifestMessage::Complete {
            meta: self.next_response_meta()?,
            transfer,
        })
        .map_err(|_| TransferRuntimeError::Protocol)
    }

    /// Encodes one authenticated bounded file chunk on the independent data lane.
    pub(crate) fn encode_data_frame(
        &mut self,
        chunk: &TransferChunk,
    ) -> Result<Vec<u8>, TransferRuntimeError> {
        self.require_peer_transfer_grant()?;
        self.outbound_data_sequence = self
            .outbound_data_sequence
            .checked_add(1)
            .ok_or(TransferRuntimeError::SequenceExhausted)?;
        encode_file_data(&FileDataMessage::Chunk {
            meta: EventMeta::new(
                self.session_id,
                self.local_device,
                Sequence::new(self.outbound_data_sequence),
                self.peer_grant_epoch,
                Capability::FILE_TRANSFER,
            ),
            transfer: transfer_to_wire(chunk.transfer),
            entry_index: chunk.entry_index,
            offset: chunk.offset,
            bytes: chunk.bytes.to_vec(),
        })
        .map_err(|_| TransferRuntimeError::Protocol)
    }

    /// Removes one acknowledged terminal queue record, releasing quota.
    pub(crate) fn remove_terminal(
        &mut self,
        transfer: WireTransferId,
    ) -> Result<(), TransferRuntimeError> {
        self.queue.remove_terminal(transfer_from_wire(transfer)?)?;
        Ok(())
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn into_staging(self) -> S {
        self.receiver.into_staging()
    }

    #[cfg(test)]
    fn retained_queue_len(&self) -> usize {
        self.queue.len()
    }

    pub(crate) fn abort_inbound(
        &mut self,
    ) -> Result<Vec<TransferRuntimeEffect>, TransferRuntimeError> {
        let mut transfers = HashSet::new();
        if let Some(snapshot) = self.receiver.snapshot() {
            let transfer = snapshot.transfer();
            self.receiver.cancel(transfer)?;
            transfers.insert(transfer);
        }
        transfers.extend(self.pending_manifests.keys().copied());
        transfers.extend(self.backpressured.iter().copied());
        self.pending_manifests.clear();
        self.pending_completion.clear();
        self.backpressured.clear();
        self.queue = TransferQueue::new(1).expect("the fixed active limit is valid");
        let mut transfers = transfers.into_iter().collect::<Vec<_>>();
        transfers.sort_unstable_by_key(|transfer| transfer.as_bytes());
        Ok(transfers
            .into_iter()
            .map(|transfer| TransferRuntimeEffect::Cancelled {
                transfer: transfer_to_wire(transfer),
            })
            .collect())
    }

    #[must_use]
    pub(crate) fn active_inbound_transfer(&self) -> Option<TransferId> {
        self.receiver
            .snapshot()
            .map(nodavo_transfer::ActiveReceiveSnapshot::transfer)
    }

    #[must_use]
    pub(crate) fn has_inbound_transfer(&self, transfer: TransferId) -> bool {
        self.queue.get(transfer).is_some()
    }

    #[must_use]
    pub(crate) fn active_inbound_progress(&self) -> Option<(TransferId, u64, u64)> {
        self.receiver.snapshot().map(|snapshot| {
            (
                snapshot.transfer(),
                snapshot.completed_bytes(),
                snapshot.total_bytes(),
            )
        })
    }

    pub(crate) async fn finalize_inbound(
        &mut self,
        transfer: TransferId,
    ) -> Result<Vec<TransferRuntimeEffect>, TransferRuntimeError> {
        self.receiver.complete(transfer).await?;
        self.pending_completion.remove(&transfer);
        let queue_effects = self.queue.complete(transfer)?;
        if !self.deferred_queue_effects.is_empty() {
            return Err(TransferRuntimeError::Protocol);
        }
        self.deferred_queue_effects.extend(queue_effects);
        Ok(vec![
            TransferRuntimeEffect::Completed {
                transfer: transfer_to_wire(transfer),
            },
            TransferRuntimeEffect::AdvanceQueue,
        ])
    }

    pub(crate) async fn advance_queue(
        &mut self,
    ) -> Result<Vec<TransferRuntimeEffect>, TransferRuntimeError> {
        let queue_effects = self.deferred_queue_effects.drain(..).collect();
        let mut effects = Vec::new();
        self.apply_queue_effects(queue_effects, &mut effects)
            .await?;
        Ok(effects)
    }

    pub(crate) async fn cancel_inbound(
        &mut self,
        transfer: TransferId,
    ) -> Result<Vec<TransferRuntimeEffect>, TransferRuntimeError> {
        self.receive_cancel(transfer_to_wire(transfer)).await
    }

    async fn receive_manifest(
        &mut self,
        wire_transfer: WireTransferId,
        entries: Vec<WireManifestEntry>,
    ) -> Result<Vec<TransferRuntimeEffect>, TransferRuntimeError> {
        let transfer = transfer_from_wire(wire_transfer)?;
        if self.completed_inbound.contains(&transfer) {
            return Ok(vec![
                TransferRuntimeEffect::CompletionAcknowledgementRequired {
                    transfer: wire_transfer,
                },
            ]);
        }
        if self.rejected_inbound.contains(&transfer) {
            return Ok(vec![
                TransferRuntimeEffect::RejectionAcknowledgementRequired {
                    transfer: wire_transfer,
                },
            ]);
        }
        let manifest = manifest_from_wire(entries)?;
        self.enqueue_manifest(wire_transfer, transfer, manifest)
            .await
    }

    async fn enqueue_manifest(
        &mut self,
        wire_transfer: WireTransferId,
        transfer: TransferId,
        manifest: TransferManifest,
    ) -> Result<Vec<TransferRuntimeEffect>, TransferRuntimeError> {
        let total_bytes = manifest.total_bytes();
        let queue_effects = match self.queue.enqueue(transfer, total_bytes) {
            Ok(effects) => effects,
            Err(TransferError::QueueFull) => {
                self.remember_rejected_inbound(&[transfer])?;
                return Ok(vec![TransferRuntimeEffect::QueueSaturated {
                    transfer: wire_transfer,
                }]);
            }
            Err(error) => return Err(error.into()),
        };
        self.pending_manifests.insert(transfer, manifest);
        let mut effects = vec![TransferRuntimeEffect::Admitted {
            transfer: wire_transfer,
            total_bytes,
        }];
        if queue_effects.is_empty() {
            self.backpressured.insert(transfer);
            effects.push(TransferRuntimeEffect::Backpressured {
                transfer: wire_transfer,
            });
        }
        self.apply_queue_effects(queue_effects, &mut effects)
            .await?;
        Ok(effects)
    }

    async fn receive_cancel(
        &mut self,
        wire_transfer: WireTransferId,
    ) -> Result<Vec<TransferRuntimeEffect>, TransferRuntimeError> {
        let transfer = transfer_from_wire(wire_transfer)?;
        let state = self
            .queue
            .get(transfer)
            .map(nodavo_transfer::QueuedTransfer::state)
            .ok_or(TransferRuntimeError::Protocol)?;
        if state == TransferQueueState::Active {
            self.receiver.cancel(transfer)?;
        } else if state != TransferQueueState::Queued && state != TransferQueueState::Paused {
            return Err(TransferRuntimeError::Protocol);
        }
        self.pending_manifests.remove(&transfer);
        self.pending_completion.remove(&transfer);
        self.backpressured.remove(&transfer);
        let queue_effects = self.queue.cancel(transfer)?;
        let mut effects = Vec::new();
        self.apply_queue_effects(queue_effects, &mut effects)
            .await?;
        // Cancelled terminal records must not pin the bounded queue. Local
        // grant abort resets the queue wholesale and never reaches this path.
        self.queue.remove_terminal(transfer)?;
        Ok(effects)
    }

    fn receive_complete(
        &mut self,
        wire_transfer: WireTransferId,
    ) -> Result<Vec<TransferRuntimeEffect>, TransferRuntimeError> {
        let transfer = transfer_from_wire(wire_transfer)?;
        if self
            .queue
            .get(transfer)
            .map(nodavo_transfer::QueuedTransfer::state)
            != Some(TransferQueueState::Active)
        {
            return Err(TransferRuntimeError::Protocol);
        }
        let snapshot = self
            .receiver
            .snapshot()
            .ok_or(TransferRuntimeError::Protocol)?;
        if snapshot.completed_bytes() != snapshot.total_bytes() {
            self.pending_completion.insert(transfer);
            return Ok(Vec::new());
        }
        Ok(vec![TransferRuntimeEffect::FinalizeRequired {
            transfer: wire_transfer,
        }])
    }

    async fn apply_queue_effects(
        &mut self,
        initial: Vec<QueueEffect>,
        effects: &mut Vec<TransferRuntimeEffect>,
    ) -> Result<(), TransferRuntimeError> {
        let mut pending = VecDeque::from(initial);
        while let Some(effect) = pending.pop_front() {
            match effect {
                QueueEffect::Start(transfer) => {
                    let manifest = self
                        .pending_manifests
                        .remove(&transfer)
                        .ok_or(TransferRuntimeError::Protocol)?;
                    let entry_count = manifest.entries().len();
                    self.receiver.begin(transfer, manifest).await?;
                    if self.backpressured.remove(&transfer) {
                        effects.push(TransferRuntimeEffect::BackpressureReleased {
                            transfer: transfer_to_wire(transfer),
                        });
                    }
                    effects.push(TransferRuntimeEffect::Started {
                        transfer: transfer_to_wire(transfer),
                    });
                    for index in 0..entry_count {
                        effects.push(TransferRuntimeEffect::ResumeRequired {
                            transfer: transfer_to_wire(transfer),
                            entry_index: u32::try_from(index)
                                .map_err(|_| TransferRuntimeError::Protocol)?,
                            offset: 0,
                        });
                    }
                }
                QueueEffect::Cancel(transfer) => {
                    effects.push(TransferRuntimeEffect::Cancelled {
                        transfer: transfer_to_wire(transfer),
                    });
                }
                QueueEffect::Pause(_) => return Err(TransferRuntimeError::Protocol),
            }
        }
        Ok(())
    }

    fn validate_remote_meta(
        &mut self,
        meta: &EventMeta,
        lane: SequenceLane,
    ) -> Result<(), TransferRuntimeError> {
        if meta.session_id() != self.session_id
            || meta.origin() != self.peer_device
            || meta.grant_epoch() != self.local_grant_epoch
        {
            return Err(TransferRuntimeError::Authentication);
        }
        if meta.capability() != Capability::FILE_TRANSFER || !self.local_allows_peer_transfer {
            return Err(TransferRuntimeError::GrantDenied);
        }
        let last = match lane {
            SequenceLane::Manifest => &mut self.inbound_manifest_sequence,
            SequenceLane::Data => &mut self.inbound_data_sequence,
        };
        if meta.sequence().is_zero() || last.is_some_and(|value| meta.sequence() <= value) {
            return Err(TransferRuntimeError::Replay);
        }
        *last = Some(meta.sequence());
        Ok(())
    }

    fn validate_remote_resume_meta(
        &mut self,
        meta: &EventMeta,
    ) -> Result<(), TransferRuntimeError> {
        if meta.session_id() != self.session_id
            || meta.origin() != self.peer_device
            || meta.grant_epoch() != self.peer_grant_epoch
        {
            return Err(TransferRuntimeError::Authentication);
        }
        if meta.capability() != Capability::FILE_TRANSFER
            || !self.peer_capabilities.contains(Capability::FILE_TRANSFER)
        {
            return Err(TransferRuntimeError::GrantDenied);
        }
        if meta.sequence().is_zero()
            || self
                .inbound_resume_sequence
                .is_some_and(|value| meta.sequence() <= value)
        {
            return Err(TransferRuntimeError::Replay);
        }
        self.inbound_resume_sequence = Some(meta.sequence());
        Ok(())
    }

    fn validate_manifest_message_meta(
        &mut self,
        message: &FileManifestMessage,
        meta: &EventMeta,
    ) -> Result<(), TransferRuntimeError> {
        let is_response = match message {
            FileManifestMessage::Resume { .. } => true,
            FileManifestMessage::Cancel { transfer, .. }
            | FileManifestMessage::Complete { transfer, .. } => {
                let transfer = transfer_from_wire(*transfer)?;
                self.queue.get(transfer).is_none()
                    && !self.rejected_inbound.contains(&transfer)
                    && !self.completed_inbound.contains(&transfer)
            }
            FileManifestMessage::Manifest { .. } | FileManifestMessage::Unknown { .. } => false,
        };
        if is_response {
            self.validate_remote_resume_meta(meta)
        } else {
            self.validate_remote_meta(meta, SequenceLane::Manifest)
        }
    }

    fn require_peer_transfer_grant(&self) -> Result<(), TransferRuntimeError> {
        if self.peer_capabilities.contains(Capability::FILE_TRANSFER) {
            Ok(())
        } else {
            Err(TransferRuntimeError::GrantDenied)
        }
    }

    fn next_manifest_meta(&mut self) -> Result<EventMeta, TransferRuntimeError> {
        self.outbound_manifest_sequence = self
            .outbound_manifest_sequence
            .checked_add(1)
            .ok_or(TransferRuntimeError::SequenceExhausted)?;
        Ok(EventMeta::new(
            self.session_id,
            self.local_device,
            Sequence::new(self.outbound_manifest_sequence),
            self.peer_grant_epoch,
            Capability::FILE_TRANSFER,
        ))
    }

    fn next_response_meta(&mut self) -> Result<EventMeta, TransferRuntimeError> {
        self.outbound_resume_sequence = self
            .outbound_resume_sequence
            .checked_add(1)
            .ok_or(TransferRuntimeError::SequenceExhausted)?;
        Ok(EventMeta::new(
            self.session_id,
            self.local_device,
            Sequence::new(self.outbound_resume_sequence),
            self.local_grant_epoch,
            Capability::FILE_TRANSFER,
        ))
    }
}

fn extend_bounded_tombstones(
    retained: &mut HashSet<TransferId>,
    transfers: &[TransferId],
    limit: usize,
) -> Result<(), TransferRuntimeError> {
    let new = transfers
        .iter()
        .copied()
        .filter(|transfer| !retained.contains(transfer))
        .collect::<HashSet<_>>();
    if retained.len().saturating_add(new.len()) > limit {
        return Err(TransferRuntimeError::Backpressure);
    }
    retained.extend(new);
    Ok(())
}

impl<S> PeerTransferRuntime<S>
where
    S: ResumableStagingArea,
{
    /// Decodes a manifest channel frame and resumes matching durable staging
    /// instead of mistaking it for a fresh transfer.
    pub(crate) async fn receive_manifest_frame_resumable(
        &mut self,
        frame: &[u8],
    ) -> Result<Vec<TransferRuntimeEffect>, TransferRuntimeError> {
        let message = decode_file_manifest(frame).map_err(|_| TransferRuntimeError::Protocol)?;
        let meta = *message.meta().ok_or(TransferRuntimeError::Protocol)?;
        self.validate_manifest_message_meta(&message, &meta)?;
        let FileManifestMessage::Manifest {
            transfer, entries, ..
        } = message
        else {
            return self.receive_manifest_message(message).await;
        };
        let core_transfer = transfer_from_wire(transfer)?;
        if self.completed_inbound.contains(&core_transfer) {
            return Ok(vec![
                TransferRuntimeEffect::CompletionAcknowledgementRequired { transfer },
            ]);
        }
        if self.rejected_inbound.contains(&core_transfer) {
            return Ok(vec![
                TransferRuntimeEffect::RejectionAcknowledgementRequired { transfer },
            ]);
        }
        let manifest = manifest_from_wire(entries)?;
        if self.receiver.has_persisted(core_transfer)? {
            if !self.allow_untracked_persisted_resume
                && !self.known_persisted_inbound.contains(&core_transfer)
            {
                return Err(TransferRuntimeError::ResumeDurabilityUnsupported);
            }
            self.resume_inbound(core_transfer, manifest)
        } else {
            self.enqueue_manifest(transfer, core_transfer, manifest)
                .await
        }
    }

    fn resume_inbound(
        &mut self,
        transfer: TransferId,
        manifest: TransferManifest,
    ) -> Result<Vec<TransferRuntimeEffect>, TransferRuntimeError> {
        if !self.local_allows_peer_transfer {
            return Err(TransferRuntimeError::GrantDenied);
        }
        if self.receiver.snapshot().is_some()
            || self.queue.active_count() != 0
            || self.queue.len() >= MAX_QUEUED_TRANSFERS
        {
            return Err(TransferRuntimeError::Transfer(
                TransferError::TransferNotActive,
            ));
        }
        let snapshot = self.receiver.resume(transfer, manifest)?;
        self.queue
            .restore_active(transfer, snapshot.total_bytes(), snapshot.completed_bytes())?;
        let state = self
            .receiver
            .resume_state()
            .ok_or(TransferRuntimeError::Protocol)?;
        let mut effects = vec![
            TransferRuntimeEffect::Admitted {
                transfer: transfer_to_wire(transfer),
                total_bytes: snapshot.total_bytes(),
            },
            TransferRuntimeEffect::Started {
                transfer: transfer_to_wire(transfer),
            },
        ];
        if snapshot.completed_bytes() != 0 {
            effects.push(TransferRuntimeEffect::Progress {
                transfer: transfer_to_wire(transfer),
                completed_bytes: snapshot.completed_bytes(),
                total_bytes: snapshot.total_bytes(),
            });
        }
        for index in 0..state.entry_count() {
            effects.push(TransferRuntimeEffect::ResumeRequired {
                transfer: transfer_to_wire(transfer),
                entry_index: u32::try_from(index).map_err(|_| TransferRuntimeError::Protocol)?,
                offset: state
                    .next_offset(index)
                    .ok_or(TransferRuntimeError::Protocol)?,
            });
        }
        Ok(effects)
    }

    pub(crate) fn configure_persisted_resume(
        &mut self,
        known_transfers: &[TransferId],
        allow_untracked: bool,
    ) {
        self.known_persisted_inbound
            .extend(known_transfers.iter().copied());
        self.allow_untracked_persisted_resume = allow_untracked;
    }
}

#[cfg(test)]
const fn is_next_epoch(current: GrantEpoch, next: GrantEpoch) -> bool {
    match current.get().checked_add(1) {
        Some(expected) => next.get() == expected,
        None => false,
    }
}

fn transfer_from_wire(wire: WireTransferId) -> Result<TransferId, TransferRuntimeError> {
    let bytes = *wire.as_bytes();
    if bytes == [0; 16] {
        return Err(TransferRuntimeError::Protocol);
    }
    Ok(TransferId::from_bytes(bytes))
}

const fn transfer_to_wire(transfer: TransferId) -> WireTransferId {
    WireTransferId::new(transfer.as_bytes())
}

fn manifest_from_wire(
    entries: Vec<WireManifestEntry>,
) -> Result<TransferManifest, TransferRuntimeError> {
    let entries = entries
        .into_iter()
        .map(|entry| {
            Ok(ManifestEntry {
                path: nodavo_transfer::RelativePath::parse(entry.path.as_str())?,
                kind: match entry.kind {
                    WireEntryKind::File => EntryKind::File,
                    WireEntryKind::Directory => EntryKind::Directory,
                },
                size: entry.size,
                hash: entry
                    .hash
                    .map(|hash| ContentHash::from_bytes(*hash.as_bytes())),
            })
        })
        .collect::<Result<Vec<_>, TransferError>>()?;
    Ok(TransferManifest::new(entries)?)
}

fn manifest_to_wire(
    manifest: &TransferManifest,
) -> Result<Vec<WireManifestEntry>, TransferRuntimeError> {
    manifest
        .entries()
        .iter()
        .map(|entry| {
            Ok(WireManifestEntry {
                path: WireRelativePath::parse(entry.path.as_str())
                    .map_err(|_| TransferRuntimeError::Protocol)?,
                kind: match entry.kind {
                    EntryKind::File => WireEntryKind::File,
                    EntryKind::Directory => WireEntryKind::Directory,
                },
                size: entry.size,
                hash: entry
                    .hash
                    .map(|hash| WireContentHash::new(*hash.as_bytes())),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use nodavo_protocol::{encode_file_data, encode_file_manifest};
    use nodavo_transfer::{FileSystemStagingArea, MAX_TRANSFER_BYTES, TransferFuture};

    use super::*;

    #[derive(Default)]
    struct MemoryStaging {
        active: Option<TransferId>,
        bytes: Vec<u8>,
        completed: Vec<TransferId>,
        cancelled: Vec<TransferId>,
        begin_count: usize,
        fail_begin_at: Option<usize>,
    }

    impl StagingArea for MemoryStaging {
        fn begin<'a>(
            &'a mut self,
            transfer: TransferId,
            _manifest: &'a TransferManifest,
        ) -> TransferFuture<'a, Result<(), TransferError>> {
            Box::pin(async move {
                if self.fail_begin_at == Some(self.begin_count) {
                    return Err(TransferError::Platform);
                }
                self.begin_count = self.begin_count.saturating_add(1);
                if self.active.replace(transfer).is_some() {
                    return Err(TransferError::TransferNotActive);
                }
                Ok(())
            })
        }

        fn write(&mut self, chunk: TransferChunk) -> TransferFuture<'_, Result<(), TransferError>> {
            Box::pin(async move {
                if self.active != Some(chunk.transfer) {
                    return Err(TransferError::TransferNotActive);
                }
                self.bytes.extend_from_slice(&chunk.bytes);
                Ok(())
            })
        }

        fn finalize(
            &mut self,
            transfer: TransferId,
        ) -> TransferFuture<'_, Result<(), TransferError>> {
            Box::pin(async move {
                if self.active.take() != Some(transfer) {
                    return Err(TransferError::TransferNotActive);
                }
                self.completed.push(transfer);
                Ok(())
            })
        }

        fn abort(&mut self, transfer: TransferId) {
            if self.active.take() == Some(transfer) {
                self.cancelled.push(transfer);
            }
        }
    }

    const LOCAL: DeviceId = DeviceId::new([1; 32]);
    const PEER: DeviceId = DeviceId::new([2; 32]);
    const SESSION: SessionId = SessionId::new([3; 16]);
    const LOCAL_EPOCH: GrantEpoch = GrantEpoch::new(9);
    const PEER_EPOCH: GrantEpoch = GrantEpoch::new(17);

    fn runtime() -> PeerTransferRuntime<MemoryStaging> {
        runtime_with_grants(true, Capability::FILE_TRANSFER)
    }

    fn runtime_with_grants(
        local_allows_peer_transfer: bool,
        peer_capabilities: Capability,
    ) -> PeerTransferRuntime<MemoryStaging> {
        PeerTransferRuntime::new(
            PeerTransferConfig {
                local_device: LOCAL,
                peer_device: PEER,
                session_id: SESSION,
                local_grant_epoch: LOCAL_EPOCH,
                peer_grant_epoch: PEER_EPOCH,
                local_allows_peer_transfer,
                peer_capabilities,
            },
            MemoryStaging::default(),
        )
    }

    fn meta(sequence: u64) -> EventMeta {
        EventMeta::new(
            SESSION,
            PEER,
            Sequence::new(sequence),
            LOCAL_EPOCH,
            Capability::FILE_TRANSFER,
        )
    }

    fn response_meta(sequence: u64) -> EventMeta {
        EventMeta::new(
            SESSION,
            PEER,
            Sequence::new(sequence),
            PEER_EPOCH,
            Capability::FILE_TRANSFER,
        )
    }

    fn temporary_directory() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "nodavo-agent-transfer-test-{}",
            TransferId::new().as_uuid()
        ));
        fs::create_dir(&path).unwrap();
        path
    }

    fn wire_transfer(byte: u8) -> WireTransferId {
        WireTransferId::new([byte; 16])
    }

    fn wire_manifest(
        sequence: u64,
        transfer: WireTransferId,
        payload: &[u8],
    ) -> FileManifestMessage {
        wire_manifest_with_meta(meta(sequence), transfer, payload)
    }

    fn wire_manifest_with_meta(
        meta: EventMeta,
        transfer: WireTransferId,
        payload: &[u8],
    ) -> FileManifestMessage {
        let hash = ContentHash::digest(payload);
        FileManifestMessage::Manifest {
            meta,
            transfer,
            entries: vec![WireManifestEntry {
                path: WireRelativePath::parse("received.bin").unwrap(),
                kind: WireEntryKind::File,
                size: u64::try_from(payload.len()).unwrap(),
                hash: Some(WireContentHash::new(*hash.as_bytes())),
            }],
        }
    }

    fn encode_manifest(message: &FileManifestMessage) -> Vec<u8> {
        encode_file_manifest(message).unwrap()
    }

    fn encode_chunk(sequence: u64, transfer: WireTransferId, payload: &'static [u8]) -> Vec<u8> {
        encode_file_data(&FileDataMessage::Chunk {
            meta: meta(sequence),
            transfer,
            entry_index: 0,
            offset: 0,
            bytes: payload.to_vec(),
        })
        .unwrap()
    }

    #[tokio::test]
    async fn authenticated_manifest_and_data_replay_lanes_are_independent() {
        let transfer = wire_transfer(7);
        let mut runtime = runtime();
        let effects = runtime
            .receive_manifest_frame(&encode_manifest(&wire_manifest(1, transfer, b"ok")))
            .await
            .unwrap();
        assert_eq!(
            effects,
            [
                TransferRuntimeEffect::Admitted {
                    transfer,
                    total_bytes: 2,
                },
                TransferRuntimeEffect::Started { transfer },
                TransferRuntimeEffect::ResumeRequired {
                    transfer,
                    entry_index: 0,
                    offset: 0,
                },
            ]
        );

        let chunk = encode_chunk(1, transfer, b"ok");
        assert!(matches!(
            runtime.receive_data_frame(&chunk).await.unwrap().as_slice(),
            [TransferRuntimeEffect::Progress {
                completed_bytes: 2,
                total_bytes: 2,
                ..
            }]
        ));
        assert_eq!(
            runtime.receive_data_frame(&chunk).await,
            Err(TransferRuntimeError::Replay)
        );

        let complete = encode_manifest(&FileManifestMessage::Complete {
            meta: meta(2),
            transfer,
        });
        assert_eq!(
            runtime.receive_manifest_frame(&complete).await.unwrap(),
            [TransferRuntimeEffect::FinalizeRequired { transfer }]
        );
        assert_eq!(
            runtime
                .finalize_inbound(TransferId::from_bytes(*transfer.as_bytes()))
                .await
                .unwrap(),
            [
                TransferRuntimeEffect::Completed { transfer },
                TransferRuntimeEffect::AdvanceQueue,
            ]
        );
        assert_eq!(
            runtime.receive_manifest_frame(&complete).await,
            Err(TransferRuntimeError::Replay)
        );
    }

    #[tokio::test]
    async fn rejects_wrong_session_origin_epoch_grant_and_zero_sequence() {
        let transfer = wire_transfer(8);
        let mut runtime = runtime();
        for invalid_meta in [
            EventMeta::new(
                SessionId::new([9; 16]),
                PEER,
                Sequence::new(1),
                LOCAL_EPOCH,
                Capability::FILE_TRANSFER,
            ),
            EventMeta::new(
                SESSION,
                DeviceId::new([9; 32]),
                Sequence::new(1),
                LOCAL_EPOCH,
                Capability::FILE_TRANSFER,
            ),
            EventMeta::new(
                SESSION,
                PEER,
                Sequence::new(1),
                GrantEpoch::new(10),
                Capability::FILE_TRANSFER,
            ),
        ] {
            let frame = encode_manifest(&wire_manifest_with_meta(invalid_meta, transfer, b"x"));
            assert_eq!(
                runtime.receive_manifest_frame(&frame).await,
                Err(TransferRuntimeError::Authentication)
            );
        }

        let zero = encode_manifest(&wire_manifest_with_meta(
            EventMeta::new(
                SESSION,
                PEER,
                Sequence::new(0),
                LOCAL_EPOCH,
                Capability::FILE_TRANSFER,
            ),
            transfer,
            b"x",
        ));
        assert_eq!(
            runtime.receive_manifest_frame(&zero).await,
            Err(TransferRuntimeError::Replay)
        );

        let mut denied = runtime_with_grants(false, Capability::FILE_TRANSFER);
        let valid = encode_manifest(&wire_manifest(1, transfer, b"x"));
        assert_eq!(
            denied.receive_manifest_frame(&valid).await,
            Err(TransferRuntimeError::GrantDenied)
        );
        assert!(
            encode_file_manifest(&FileManifestMessage::Complete {
                meta: EventMeta::new(
                    SESSION,
                    PEER,
                    Sequence::new(1),
                    LOCAL_EPOCH,
                    Capability::CLIPBOARD_WRITE,
                ),
                transfer,
            })
            .is_err()
        );
    }

    #[tokio::test]
    async fn queued_transfer_rejects_pre_acceptance_data_and_releases_in_order() {
        let first = wire_transfer(10);
        let second = wire_transfer(11);
        let mut runtime = runtime();
        runtime
            .receive_manifest_frame(&encode_manifest(&wire_manifest(1, first, b"a")))
            .await
            .unwrap();
        assert_eq!(
            runtime
                .receive_manifest_frame(&encode_manifest(&wire_manifest(2, second, b"b")))
                .await
                .unwrap(),
            [
                TransferRuntimeEffect::Admitted {
                    transfer: second,
                    total_bytes: 1,
                },
                TransferRuntimeEffect::Backpressured { transfer: second },
            ]
        );
        assert_eq!(
            runtime
                .receive_data_frame(&encode_chunk(1, second, b"b"))
                .await,
            Err(TransferRuntimeError::Protocol)
        );

        let cancel = encode_manifest(&FileManifestMessage::Cancel {
            meta: meta(3),
            transfer: first,
            reason: 1,
        });
        assert_eq!(
            runtime.receive_manifest_frame(&cancel).await.unwrap(),
            [
                TransferRuntimeEffect::Cancelled { transfer: first },
                TransferRuntimeEffect::BackpressureReleased { transfer: second },
                TransferRuntimeEffect::Started { transfer: second },
                TransferRuntimeEffect::ResumeRequired {
                    transfer: second,
                    entry_index: 0,
                    offset: 0,
                },
            ]
        );
        assert_eq!(
            runtime.retained_queue_len(),
            1,
            "cancelled terminal record retained quota"
        );
        assert_eq!(
            runtime
                .receive_data_frame(&encode_chunk(2, second, b"b"))
                .await
                .unwrap(),
            [TransferRuntimeEffect::Progress {
                transfer: second,
                completed_bytes: 1,
                total_bytes: 1,
            }]
        );
        assert_eq!(runtime.into_staging().bytes, b"b");
    }

    #[tokio::test]
    async fn completion_is_latched_until_independent_data_lane_is_durable() {
        let transfer = wire_transfer(12);
        let mut runtime = runtime();
        runtime
            .receive_manifest_frame(&encode_manifest(&wire_manifest(1, transfer, b"missing")))
            .await
            .unwrap();
        let complete = encode_manifest(&FileManifestMessage::Complete {
            meta: meta(2),
            transfer,
        });
        assert!(
            runtime
                .receive_manifest_frame(&complete)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            runtime
                .receive_data_frame(&encode_chunk(1, transfer, b"missing"))
                .await
                .unwrap(),
            [
                TransferRuntimeEffect::Progress {
                    transfer,
                    completed_bytes: 7,
                    total_bytes: 7,
                },
                TransferRuntimeEffect::FinalizeRequired { transfer },
            ]
        );
        assert_eq!(
            runtime
                .finalize_inbound(TransferId::from_bytes(*transfer.as_bytes()))
                .await
                .unwrap(),
            [
                TransferRuntimeEffect::Completed { transfer },
                TransferRuntimeEffect::AdvanceQueue,
            ]
        );
    }

    #[tokio::test]
    async fn earned_completion_precedes_a_later_queued_begin_failure() {
        let first = wire_transfer(51);
        let second = wire_transfer(52);
        let mut runtime = PeerTransferRuntime::new(
            PeerTransferConfig {
                local_device: LOCAL,
                peer_device: PEER,
                session_id: SESSION,
                local_grant_epoch: LOCAL_EPOCH,
                peer_grant_epoch: PEER_EPOCH,
                local_allows_peer_transfer: true,
                peer_capabilities: Capability::FILE_TRANSFER,
            },
            MemoryStaging {
                fail_begin_at: Some(1),
                ..MemoryStaging::default()
            },
        );
        runtime
            .receive_manifest_frame(&encode_manifest(&wire_manifest(1, first, b"a")))
            .await
            .unwrap();
        runtime
            .receive_manifest_frame(&encode_manifest(&wire_manifest(2, second, b"b")))
            .await
            .unwrap();
        runtime
            .receive_data_frame(&encode_chunk(1, first, b"a"))
            .await
            .unwrap();
        let complete = encode_manifest(&FileManifestMessage::Complete {
            meta: meta(3),
            transfer: first,
        });
        assert_eq!(
            runtime.receive_manifest_frame(&complete).await.unwrap(),
            [TransferRuntimeEffect::FinalizeRequired { transfer: first }]
        );
        assert_eq!(
            runtime
                .finalize_inbound(TransferId::from_bytes(*first.as_bytes()))
                .await
                .unwrap(),
            [
                TransferRuntimeEffect::Completed { transfer: first },
                TransferRuntimeEffect::AdvanceQueue,
            ]
        );
        assert_eq!(
            runtime.advance_queue().await,
            Err(TransferRuntimeError::Transfer(TransferError::Platform))
        );
        assert_eq!(
            runtime.into_staging().completed,
            [TransferId::from_bytes(*first.as_bytes())]
        );
    }

    #[tokio::test]
    async fn cancelled_inbound_absorbs_bounded_late_frames_without_affecting_unrelated_work() {
        let cancelled = wire_transfer(53);
        let unrelated = wire_transfer(54);
        let mut runtime = runtime();
        runtime
            .remember_rejected_inbound(&[TransferId::from_bytes(*cancelled.as_bytes())])
            .unwrap();

        assert!(
            runtime
                .receive_data_frame(&encode_chunk(1, cancelled, b"late"))
                .await
                .unwrap()
                .is_empty()
        );
        let late_complete = encode_manifest(&FileManifestMessage::Complete {
            meta: meta(1),
            transfer: cancelled,
        });
        assert_eq!(
            runtime
                .receive_manifest_frame(&late_complete)
                .await
                .unwrap(),
            [TransferRuntimeEffect::RejectionAcknowledgementRequired {
                transfer: cancelled,
            }]
        );
        assert_eq!(
            runtime
                .receive_manifest_frame(&encode_manifest(&wire_manifest(2, cancelled, b"late",)))
                .await
                .unwrap(),
            [TransferRuntimeEffect::RejectionAcknowledgementRequired {
                transfer: cancelled,
            }]
        );

        assert!(matches!(
            runtime
                .receive_manifest_frame(&encode_manifest(&wire_manifest(
                    3,
                    unrelated,
                    b"ok",
                )))
                .await
                .unwrap()
                .as_slice(),
            [
                TransferRuntimeEffect::Admitted { transfer, .. },
                TransferRuntimeEffect::Started { .. },
                ..
            ] if *transfer == unrelated
        ));
        assert!(matches!(
            runtime
                .receive_data_frame(&encode_chunk(2, unrelated, b"ok"))
                .await
                .unwrap()
                .as_slice(),
            [TransferRuntimeEffect::Progress {
                transfer,
                completed_bytes: 2,
                total_bytes: 2,
            }] if *transfer == unrelated
        ));
    }

    #[tokio::test]
    async fn cancelled_outbound_absorbs_only_exact_late_responses() {
        let cancelled = wire_transfer(55);
        let unknown = wire_transfer(56);
        let mut runtime = runtime();
        runtime
            .remember_cancelled_outbound(&[TransferId::from_bytes(*cancelled.as_bytes())])
            .unwrap();

        let late_resume = encode_manifest(&FileManifestMessage::Resume {
            meta: response_meta(1),
            transfer: cancelled,
            entry_index: 0,
            offset: 0,
        });
        assert!(
            runtime
                .receive_manifest_frame(&late_resume)
                .await
                .unwrap()
                .is_empty()
        );
        let late_complete = encode_manifest(&FileManifestMessage::Complete {
            meta: response_meta(2),
            transfer: cancelled,
        });
        assert!(
            runtime
                .receive_manifest_frame(&late_complete)
                .await
                .unwrap()
                .is_empty()
        );
        let late_cancel = encode_manifest(&FileManifestMessage::Cancel {
            meta: response_meta(3),
            transfer: cancelled,
            reason: 0,
        });
        assert!(
            runtime
                .receive_manifest_frame(&late_cancel)
                .await
                .unwrap()
                .is_empty()
        );

        let unknown_resume = encode_manifest(&FileManifestMessage::Resume {
            meta: response_meta(4),
            transfer: unknown,
            entry_index: 0,
            offset: 0,
        });
        assert_eq!(
            runtime
                .receive_manifest_frame(&unknown_resume)
                .await
                .unwrap(),
            [TransferRuntimeEffect::PeerResumeRequested {
                transfer: unknown,
                entry_index: 0,
                offset: 0,
            }]
        );
    }

    #[test]
    fn session_tombstone_sets_fail_before_exceeding_hard_caps() {
        let mut runtime = runtime();
        let rejected = (0..MAX_REJECTED_INBOUND_TOMBSTONES)
            .map(|index| {
                let mut bytes = [0_u8; 16];
                bytes[..8].copy_from_slice(&u64::try_from(index + 1).unwrap().to_le_bytes());
                TransferId::from_bytes(bytes)
            })
            .collect::<Vec<_>>();
        runtime.remember_rejected_inbound(&rejected).unwrap();
        runtime.remember_rejected_inbound(&rejected[..1]).unwrap();
        let mut novel = [0_u8; 16];
        novel[8..].copy_from_slice(&1_u64.to_le_bytes());
        assert_eq!(
            runtime.remember_rejected_inbound(&[TransferId::from_bytes(novel)]),
            Err(TransferRuntimeError::Backpressure)
        );
        assert_eq!(
            runtime.rejected_inbound.len(),
            MAX_REJECTED_INBOUND_TOMBSTONES
        );
    }

    #[test]
    fn conversions_preserve_exact_id_path_kind_hash_and_resume_sequences() {
        let transfer = TransferId::from_bytes([13; 16]);
        assert_eq!(
            transfer_from_wire(transfer_to_wire(transfer)).unwrap(),
            transfer
        );
        let manifest = TransferManifest::new(vec![ManifestEntry {
            path: nodavo_transfer::RelativePath::parse("folder/file.bin").unwrap(),
            kind: EntryKind::File,
            size: 4,
            hash: Some(ContentHash::digest(b"data")),
        }])
        .unwrap();
        assert_eq!(
            manifest_from_wire(manifest_to_wire(&manifest).unwrap())
                .unwrap()
                .entries(),
            manifest.entries()
        );

        let mut outbound_runtime = runtime();
        let encoded = outbound_runtime
            .encode_manifest_frame(transfer, &manifest)
            .unwrap();
        let FileManifestMessage::Manifest {
            meta,
            transfer: encoded_transfer,
            entries,
        } = decode_file_manifest(&encoded).unwrap()
        else {
            panic!("expected manifest message");
        };
        assert_eq!(encoded_transfer.as_bytes(), &[13; 16]);
        assert_eq!(meta.sequence(), Sequence::new(1));
        assert_eq!(meta.grant_epoch(), PEER_EPOCH);
        assert_eq!(manifest_from_wire(entries).unwrap(), manifest);

        let mut runtime = runtime();
        for (index, offset) in [4, 0].into_iter().enumerate() {
            let encoded = runtime
                .encode_resume_frame(
                    transfer_to_wire(transfer),
                    u32::try_from(index).unwrap(),
                    offset,
                )
                .unwrap();
            let message = decode_file_manifest(&encoded).unwrap();
            let FileManifestMessage::Resume {
                meta,
                transfer: resumed,
                entry_index,
                offset,
            } = message
            else {
                panic!("expected resume message");
            };
            assert_eq!(resumed.as_bytes(), &[13; 16]);
            assert_eq!(entry_index, u32::try_from(index).unwrap());
            assert_eq!(offset, [4, 0][index]);
            assert_eq!(meta.sequence(), Sequence::new((index + 1) as u64));
            assert_eq!(meta.origin(), LOCAL);
            assert_eq!(meta.grant_epoch(), LOCAL_EPOCH);
        }
        assert!(manifest.total_bytes() <= MAX_TRANSFER_BYTES);
    }

    #[tokio::test]
    async fn local_revoke_aborts_active_receive_and_advances_epoch() {
        let transfer = wire_transfer(14);
        let mut runtime = runtime();
        runtime
            .receive_manifest_frame(&encode_manifest(&wire_manifest(1, transfer, b"payload")))
            .await
            .unwrap();
        assert_eq!(
            runtime
                .update_local_grants(GrantEpoch::new(10), false)
                .unwrap(),
            [TransferRuntimeEffect::Cancelled { transfer }]
        );
        assert_eq!(
            runtime
                .receive_manifest_frame(&encode_manifest(&wire_manifest(2, transfer, b"payload")))
                .await,
            Err(TransferRuntimeError::Authentication)
        );
        let new_epoch = FileManifestMessage::Manifest {
            meta: EventMeta::new(
                SESSION,
                PEER,
                Sequence::new(1),
                GrantEpoch::new(10),
                Capability::FILE_TRANSFER,
            ),
            transfer,
            entries: match wire_manifest(1, transfer, b"payload") {
                FileManifestMessage::Manifest { entries, .. } => entries,
                _ => unreachable!(),
            },
        };
        assert_eq!(
            runtime
                .receive_manifest_frame(&encode_manifest(&new_epoch))
                .await,
            Err(TransferRuntimeError::GrantDenied)
        );
    }

    #[tokio::test]
    async fn durable_resume_uses_receiver_offsets_and_peer_epoch() {
        let root = temporary_directory();
        let payload = b"durable peer resume";
        let transfer = TransferId::from_bytes([15; 16]);
        let transfer_manifest = TransferManifest::new(vec![ManifestEntry {
            path: nodavo_transfer::RelativePath::parse("received.bin").unwrap(),
            kind: EntryKind::File,
            size: payload.len() as u64,
            hash: Some(ContentHash::digest(payload)),
        }])
        .unwrap();
        let split = 7_usize;
        {
            let mut staging = FileSystemStagingArea::new(&root).unwrap();
            staging.begin(transfer, &transfer_manifest).await.unwrap();
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

        let staging = FileSystemStagingArea::new(&root).unwrap();
        let mut runtime = PeerTransferRuntime::new(
            PeerTransferConfig {
                local_device: LOCAL,
                peer_device: PEER,
                session_id: SESSION,
                local_grant_epoch: LOCAL_EPOCH,
                peer_grant_epoch: PEER_EPOCH,
                local_allows_peer_transfer: true,
                peer_capabilities: Capability::FILE_TRANSFER,
            },
            staging,
        );
        let effects = runtime
            .receive_manifest_frame_resumable(&encode_manifest(&wire_manifest(
                1,
                wire_transfer(15),
                payload,
            )))
            .await
            .unwrap();
        assert_eq!(
            effects,
            [
                TransferRuntimeEffect::Admitted {
                    transfer: wire_transfer(15),
                    total_bytes: payload.len() as u64,
                },
                TransferRuntimeEffect::Started {
                    transfer: wire_transfer(15),
                },
                TransferRuntimeEffect::Progress {
                    transfer: wire_transfer(15),
                    completed_bytes: split as u64,
                    total_bytes: payload.len() as u64,
                },
                TransferRuntimeEffect::ResumeRequired {
                    transfer: wire_transfer(15),
                    entry_index: 0,
                    offset: split as u64,
                },
            ]
        );
        runtime
            .update_local_grants(GrantEpoch::new(10), false)
            .unwrap();
        drop(runtime);
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn unsupported_directory_crash_durability_rejects_untracked_restart_resume() {
        let root = temporary_directory();
        let payload = b"restart durability gate";
        let transfer = TransferId::from_bytes([16; 16]);
        let transfer_manifest = TransferManifest::new(vec![ManifestEntry {
            path: nodavo_transfer::RelativePath::parse("received.bin").unwrap(),
            kind: EntryKind::File,
            size: payload.len() as u64,
            hash: Some(ContentHash::digest(payload)),
        }])
        .unwrap();
        {
            let mut staging = FileSystemStagingArea::new(&root).unwrap();
            staging.begin(transfer, &transfer_manifest).await.unwrap();
            staging
                .write(TransferChunk {
                    transfer,
                    entry_index: 0,
                    offset: 0,
                    bytes: Bytes::copy_from_slice(&payload[..7]),
                })
                .await
                .unwrap();
        }

        let staging = FileSystemStagingArea::new(&root).unwrap();
        let mut runtime = PeerTransferRuntime::new(
            PeerTransferConfig {
                local_device: LOCAL,
                peer_device: PEER,
                session_id: SESSION,
                local_grant_epoch: LOCAL_EPOCH,
                peer_grant_epoch: PEER_EPOCH,
                local_allows_peer_transfer: true,
                peer_capabilities: Capability::FILE_TRANSFER,
            },
            staging,
        );
        runtime.configure_persisted_resume(&[], false);
        assert_eq!(
            runtime
                .receive_manifest_frame_resumable(&encode_manifest(&wire_manifest(
                    1,
                    wire_transfer(16),
                    payload,
                )))
                .await,
            Err(TransferRuntimeError::ResumeDurabilityUnsupported)
        );
        drop(runtime);
        let mut cleanup = FileSystemStagingArea::new(&root).unwrap();
        cleanup.discard_unopened_persisted(transfer).unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}
