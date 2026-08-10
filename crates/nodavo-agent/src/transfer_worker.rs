//! Bounded process-lifetime file-transfer ownership outside the session loop.
//!
//! The worker owns all scanning, hashing, source reads, durable staging writes,
//! fsync/finalize, and abort cleanup. The authenticated session loop exchanges
//! only bounded commands/events and can therefore prioritize safety signals.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use nodavo_protocol::{DeviceId, TransferId as WireTransferId};
use nodavo_transfer::{
    EntryKind, FileSystemStagingArea, OutboundResumePoint, OutboundTransferSource, TransferError,
    TransferId,
};
use tokio::runtime::Handle;
use tokio::sync::{mpsc, oneshot};

use crate::transfer_runtime::{PeerTransferRuntime, TransferRuntimeEffect, TransferRuntimeError};

/// Includes scans in progress, sources awaiting receiver acceptance, active
/// sends, and sources retained until durable completion acknowledgement.
pub(crate) const MAX_PENDING_OUTBOUND_TRANSFERS: usize = 4;
const COMMAND_CAPACITY: usize = 16;
const EVENT_CAPACITY: usize = 16;
const EFFECT_BUDGET: usize = 32;
const COMPLETION_TOMBSTONE_LIMIT: usize = 64;

const STOP: u8 = 1;
const ABORT_INBOUND: u8 = 1 << 1;
const ABORT_OUTBOUND: u8 = 1 << 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TransferStopMode {
    Suspend,
    AbortInbound,
    AbortOutbound,
    AbortAll,
}

impl TransferStopMode {
    const fn bits(self) -> u8 {
        match self {
            Self::Suspend => STOP,
            Self::AbortInbound => STOP | ABORT_INBOUND,
            Self::AbortOutbound => STOP | ABORT_OUTBOUND,
            Self::AbortAll => STOP | ABORT_INBOUND | ABORT_OUTBOUND,
        }
    }
}

#[derive(Debug)]
pub(crate) enum TransferWorkerEvent {
    SendManifest(Vec<u8>),
    SendData(Vec<u8>),
    Fatal(TransferRuntimeError),
}

#[derive(Default)]
struct StoreInner {
    outbound: HashMap<DeviceId, HashMap<TransferId, PendingOutboundTransfer>>,
    completed_inbound: VecDeque<(DeviceId, TransferId)>,
    completed_inbound_set: HashSet<(DeviceId, TransferId)>,
    inbound: HashMap<DeviceId, HashSet<TransferId>>,
    discard_required: HashMap<DeviceId, HashSet<TransferId>>,
    staging_root: Option<PathBuf>,
    active_workers: usize,
    cleanup_in_progress: bool,
    directory_entry_crash_durable: bool,
}

struct PendingOutboundTransfer {
    source: OutboundTransferSource,
    resume_offsets: Vec<Option<u64>>,
    remaining_resumes: usize,
    ready: bool,
    awaiting_completion_ack: bool,
}

/// Process-lifetime selected-source ownership. A future restart journal remains
/// a separate gate; this store intentionally makes no persistence claim.
#[derive(Clone, Default)]
pub(crate) struct TransferStore {
    inner: Arc<Mutex<StoreInner>>,
    outbound_slots: Arc<AtomicUsize>,
    poisoned: Arc<AtomicBool>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TransferCleanupState {
    Complete,
    Pending,
}

impl TransferStore {
    fn reserve_outbound(&self) -> Result<(), TransferError> {
        if self.is_poisoned() {
            return Err(TransferError::Platform);
        }
        self.outbound_slots
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < MAX_PENDING_OUTBOUND_TRANSFERS).then_some(current + 1)
            })
            .map(|_| ())
            .map_err(|_| TransferError::QueueFull)
    }

    fn release_outbound(&self) {
        let previous = self.outbound_slots.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous != 0, "outbound transfer reservation underflow");
    }

    fn completed_for(&self, peer: DeviceId) -> Vec<TransferId> {
        self.inner
            .lock()
            .expect("transfer store mutex poisoned")
            .completed_inbound
            .iter()
            .filter_map(|(owner, transfer)| (*owner == peer).then_some(*transfer))
            .collect()
    }

    pub(crate) fn register_staging_root(&self, root: PathBuf) -> Result<(), TransferError> {
        let mut inner = self.inner.lock().map_err(|_| TransferError::Platform)?;
        if inner
            .staging_root
            .as_ref()
            .is_some_and(|known| known != &root)
        {
            self.poisoned.store(true, Ordering::Release);
            return Err(TransferError::Platform);
        }
        inner.staging_root = Some(root);
        inner.directory_entry_crash_durable =
            FileSystemStagingArea::directory_entry_crash_durability_supported();
        Ok(())
    }

    fn resume_configuration(&self, peer: DeviceId) -> (Vec<TransferId>, bool) {
        let inner = self.inner.lock().expect("transfer store mutex poisoned");
        (
            inner
                .inbound
                .get(&peer)
                .map(|transfers| transfers.iter().copied().collect())
                .unwrap_or_default(),
            inner.directory_entry_crash_durable,
        )
    }

    pub(crate) fn remember_inbound(&self, peer: DeviceId, transfer: TransferId) {
        self.inner
            .lock()
            .expect("transfer store mutex poisoned")
            .inbound
            .entry(peer)
            .or_default()
            .insert(transfer);
    }

    fn forget_inbound(&self, peer: DeviceId, transfer: TransferId) {
        let mut inner = self.inner.lock().expect("transfer store mutex poisoned");
        if let Some(transfers) = inner.inbound.get_mut(&peer) {
            transfers.remove(&transfer);
            if transfers.is_empty() {
                inner.inbound.remove(&peer);
            }
        }
        if let Some(transfers) = inner.discard_required.get_mut(&peer) {
            transfers.remove(&transfer);
            if transfers.is_empty() {
                inner.discard_required.remove(&peer);
            }
        }
    }

    fn require_inbound_discard(&self, peer: DeviceId, transfer: TransferId) {
        let mut inner = self.inner.lock().expect("transfer store mutex poisoned");
        inner.inbound.entry(peer).or_default().insert(transfer);
        inner
            .discard_required
            .entry(peer)
            .or_default()
            .insert(transfer);
    }

    pub(crate) fn require_peer_inbound_discard(&self, peer: DeviceId) {
        let mut inner = self.inner.lock().expect("transfer store mutex poisoned");
        let transfers = inner.inbound.get(&peer).cloned().unwrap_or_default();
        inner
            .discard_required
            .entry(peer)
            .or_default()
            .extend(transfers);
    }

    pub(crate) fn require_all_inbound_discard(&self) -> Vec<DeviceId> {
        let mut inner = self.inner.lock().expect("transfer store mutex poisoned");
        let peers = inner.inbound.keys().copied().collect::<Vec<_>>();
        for peer in &peers {
            let transfers = inner.inbound.get(peer).cloned().unwrap_or_default();
            inner
                .discard_required
                .entry(*peer)
                .or_default()
                .extend(transfers);
        }
        peers
    }

    fn worker_started(&self) {
        let mut inner = self.inner.lock().expect("transfer store mutex poisoned");
        inner.active_workers = inner.active_workers.saturating_add(1);
    }

    fn worker_finished(&self, peer: DeviceId) {
        {
            let mut inner = self.inner.lock().expect("transfer store mutex poisoned");
            inner.active_workers = inner.active_workers.saturating_sub(1);
        }
        let _ = self.cleanup_peer_if_idle(peer);
    }

    pub(crate) fn cleanup_peer_if_idle(
        &self,
        peer: DeviceId,
    ) -> Result<TransferCleanupState, TransferError> {
        let (root, transfers) = {
            let mut inner = self.inner.lock().map_err(|_| TransferError::Platform)?;
            if inner.active_workers != 0 || inner.cleanup_in_progress {
                return Ok(TransferCleanupState::Pending);
            }
            let transfers = inner
                .discard_required
                .get(&peer)
                .cloned()
                .unwrap_or_default();
            if transfers.is_empty() {
                return if self.is_poisoned() {
                    Err(TransferError::Platform)
                } else {
                    Ok(TransferCleanupState::Complete)
                };
            }
            let Some(root) = inner.staging_root.clone() else {
                self.poisoned.store(true, Ordering::Release);
                return Err(TransferError::Platform);
            };
            inner.cleanup_in_progress = true;
            (root, transfers)
        };

        let result = (|| {
            let mut staging = FileSystemStagingArea::new(root)?;
            for transfer in &transfers {
                staging.discard_unopened_persisted(*transfer)?;
            }
            Ok(())
        })();
        let mut inner = self.inner.lock().map_err(|_| TransferError::Platform)?;
        inner.cleanup_in_progress = false;
        if let Err(error) = result {
            self.poisoned.store(true, Ordering::Release);
            return Err(error);
        }
        if let Some(required) = inner.discard_required.get_mut(&peer) {
            required.retain(|transfer| !transfers.contains(transfer));
            if required.is_empty() {
                inner.discard_required.remove(&peer);
            }
        }
        if let Some(inbound) = inner.inbound.get_mut(&peer) {
            inbound.retain(|transfer| !transfers.contains(transfer));
            if inbound.is_empty() {
                inner.inbound.remove(&peer);
            }
        }
        if self.is_poisoned() {
            Err(TransferError::Platform)
        } else {
            Ok(TransferCleanupState::Complete)
        }
    }

    #[must_use]
    pub(crate) fn is_poisoned(&self) -> bool {
        self.poisoned.load(Ordering::Acquire)
    }

    fn poison(&self) {
        self.poisoned.store(true, Ordering::Release);
    }

    fn remember_completed(&self, peer: DeviceId, transfer: TransferId) {
        let mut inner = self.inner.lock().expect("transfer store mutex poisoned");
        if !inner.completed_inbound_set.insert((peer, transfer)) {
            return;
        }
        inner.completed_inbound.push_back((peer, transfer));
        while inner.completed_inbound.len() > COMPLETION_TOMBSTONE_LIMIT {
            if let Some(expired) = inner.completed_inbound.pop_front() {
                inner.completed_inbound_set.remove(&expired);
            }
        }
    }

    fn purge_outbound(&self, peer: DeviceId) {
        let removed = self
            .inner
            .lock()
            .expect("transfer store mutex poisoned")
            .outbound
            .remove(&peer)
            .unwrap_or_default();
        for (_, mut pending) in removed {
            pending.source.cancel();
            self.release_outbound();
        }
    }

    pub(crate) fn mark_peer_revoked(&self, peer: DeviceId) {
        self.purge_outbound(peer);
        self.require_peer_inbound_discard(peer);
        let mut inner = self.inner.lock().expect("transfer store mutex poisoned");
        inner.completed_inbound.retain(|(owner, _)| *owner != peer);
        inner
            .completed_inbound_set
            .retain(|(owner, _)| *owner != peer);
    }

    #[cfg(test)]
    fn outbound_count(&self) -> usize {
        self.outbound_slots.load(Ordering::Acquire)
    }
}

enum WorkerCommand {
    ReceiveManifest(Vec<u8>),
    ReceiveData(Vec<u8>),
    StartOutbound {
        transfer: TransferId,
        paths: Vec<PathBuf>,
        acknowledgement: oneshot::Sender<Result<TransferId, TransferError>>,
    },
    PumpOutbound,
    Stop,
}

pub(crate) struct TransferWorker {
    commands: mpsc::Sender<WorkerCommand>,
    events: mpsc::Receiver<TransferWorkerEvent>,
    stop: Arc<AtomicU8>,
    store: TransferStore,
    #[cfg(test)]
    scan_active: Arc<AtomicBool>,
}

impl TransferWorker {
    pub(crate) fn start(
        peer: DeviceId,
        mut runtime: PeerTransferRuntime<FileSystemStagingArea>,
        store: TransferStore,
    ) -> Self {
        runtime.remember_completed_inbound(&store.completed_for(peer));
        let (known_persisted, allow_untracked) = store.resume_configuration(peer);
        runtime.configure_persisted_resume(&known_persisted, allow_untracked);
        let (command_tx, command_rx) = mpsc::channel(COMMAND_CAPACITY);
        let (event_tx, event_rx) = mpsc::channel(EVENT_CAPACITY);
        let stop = Arc::new(AtomicU8::new(0));
        let thread_stop = Arc::clone(&stop);
        #[cfg(test)]
        let scan_active = Arc::new(AtomicBool::new(false));
        #[cfg(test)]
        let thread_scan_active = Arc::clone(&scan_active);
        let thread_store = store.clone();
        let handle = Handle::current();
        store.worker_started();
        std::thread::Builder::new()
            .name("nodavo-transfer".to_owned())
            .spawn(move || {
                let mut state = WorkerState {
                    peer,
                    runtime,
                    store: thread_store.clone(),
                    commands: command_rx,
                    events: event_tx,
                    stop: thread_stop,
                    pending_effects: VecDeque::new(),
                    handle,
                    #[cfg(test)]
                    scan_active: thread_scan_active,
                };
                state.run();
                drop(state);
                thread_store.worker_finished(peer);
            })
            .expect("the bounded transfer worker thread must start");
        Self {
            commands: command_tx,
            events: event_rx,
            stop,
            store,
            #[cfg(test)]
            scan_active,
        }
    }

    pub(crate) fn try_receive_manifest(&self, frame: Vec<u8>) -> Result<(), TransferRuntimeError> {
        if self.store.is_poisoned() {
            return Err(TransferRuntimeError::Transfer(TransferError::Platform));
        }
        self.commands
            .try_send(WorkerCommand::ReceiveManifest(frame))
            .map_err(|_| TransferRuntimeError::Backpressure)
    }

    pub(crate) fn try_receive_data(&self, frame: Vec<u8>) -> Result<(), TransferRuntimeError> {
        if self.store.is_poisoned() {
            return Err(TransferRuntimeError::Transfer(TransferError::Platform));
        }
        self.commands
            .try_send(WorkerCommand::ReceiveData(frame))
            .map_err(|_| TransferRuntimeError::Backpressure)
    }

    pub(crate) fn try_start_outbound(
        &self,
        paths: Vec<PathBuf>,
        acknowledgement: oneshot::Sender<Result<TransferId, TransferError>>,
    ) {
        if let Err(error) = self.store.reserve_outbound() {
            let _ = acknowledgement.send(Err(error));
            return;
        }
        let transfer = TransferId::new();
        if let Err(error) = self.commands.try_send(WorkerCommand::StartOutbound {
            transfer,
            paths,
            acknowledgement,
        }) {
            self.store.release_outbound();
            if let WorkerCommand::StartOutbound {
                acknowledgement, ..
            } = error.into_inner()
            {
                let _ = acknowledgement.send(Err(TransferError::QueueFull));
            }
        }
    }

    pub(crate) fn try_pump(&self) -> Result<(), TransferRuntimeError> {
        match self.commands.try_send(WorkerCommand::PumpOutbound) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(WorkerCommand::PumpOutbound)) => Ok(()),
            Err(_) => Err(TransferRuntimeError::Backpressure),
        }
    }

    pub(crate) async fn next_event(&mut self) -> Option<TransferWorkerEvent> {
        self.events.recv().await
    }

    /// Atomically publishes cancellation intent before queueing cleanup. The
    /// worker checks this flag between bounded chunks/effects, so a saturated
    /// ordinary command queue cannot delay safety priority.
    pub(crate) fn stop(&self, mode: TransferStopMode) {
        self.stop.fetch_or(mode.bits(), Ordering::AcqRel);
        let _ = self.commands.try_send(WorkerCommand::Stop);
    }

    #[cfg(test)]
    fn scan_is_active(&self) -> bool {
        self.scan_active.load(Ordering::Acquire)
    }
}

struct WorkerState {
    peer: DeviceId,
    runtime: PeerTransferRuntime<FileSystemStagingArea>,
    store: TransferStore,
    commands: mpsc::Receiver<WorkerCommand>,
    events: mpsc::Sender<TransferWorkerEvent>,
    stop: Arc<AtomicU8>,
    pending_effects: VecDeque<TransferRuntimeEffect>,
    handle: Handle,
    #[cfg(test)]
    scan_active: Arc<AtomicBool>,
}

impl WorkerState {
    fn run(&mut self) {
        if let Err(error) = self.reannounce_outbound() {
            self.fail(error);
            return;
        }
        loop {
            if self.stop.load(Ordering::Acquire) & STOP != 0 {
                self.cleanup();
                return;
            }
            if let Err(error) = self.drain_effect_budget() {
                self.fail(error);
                return;
            }
            if !self.pending_effects.is_empty() {
                std::thread::yield_now();
                continue;
            }
            let command = self.commands.blocking_recv();
            let Some(command) = command else {
                self.cleanup();
                return;
            };
            if let Err(error) = self.handle_command(command) {
                self.fail(error);
                return;
            }
        }
    }

    fn handle_command(&mut self, command: WorkerCommand) -> Result<(), TransferRuntimeError> {
        match command {
            WorkerCommand::ReceiveManifest(frame) => {
                let effects = self
                    .handle
                    .block_on(self.runtime.receive_manifest_frame_resumable(&frame))?;
                self.pending_effects.extend(effects);
            }
            WorkerCommand::ReceiveData(frame) => {
                let effects = self
                    .handle
                    .block_on(self.runtime.receive_data_frame(&frame))?;
                self.pending_effects.extend(effects);
            }
            WorkerCommand::StartOutbound {
                transfer,
                paths,
                acknowledgement,
            } => self.start_outbound(transfer, paths, acknowledgement),
            WorkerCommand::PumpOutbound => self.pump_outbound()?,
            WorkerCommand::Stop => {}
        }
        Ok(())
    }

    fn start_outbound(
        &mut self,
        transfer: TransferId,
        paths: Vec<PathBuf>,
        acknowledgement: oneshot::Sender<Result<TransferId, TransferError>>,
    ) {
        #[cfg(test)]
        self.scan_active.store(true, Ordering::Release);
        let stop = Arc::clone(&self.stop);
        let result = OutboundTransferSource::scan_with_cancel(transfer, paths, || {
            stop.load(Ordering::Acquire) & STOP != 0
        })
        .and_then(|source| {
            if self.stop.load(Ordering::Acquire) & STOP != 0 {
                return Err(TransferError::Cancelled);
            }
            let entry_count = source.manifest().entries().len();
            let payload = self
                .runtime
                .encode_manifest_frame(transfer, source.manifest())
                .map_err(|_| TransferError::Cancelled)?;
            let pending = PendingOutboundTransfer {
                source,
                resume_offsets: vec![None; entry_count],
                remaining_resumes: entry_count,
                ready: false,
                awaiting_completion_ack: false,
            };
            self.store
                .inner
                .lock()
                .expect("transfer store mutex poisoned")
                .outbound
                .entry(self.peer)
                .or_default()
                .insert(transfer, pending);
            if self
                .events
                .blocking_send(TransferWorkerEvent::SendManifest(payload))
                .is_err()
            {
                return Err(TransferError::Cancelled);
            }
            Ok(transfer)
        });
        #[cfg(test)]
        self.scan_active.store(false, Ordering::Release);
        if result.is_err() && !self.remove_outbound(transfer) {
            self.store.release_outbound();
        }
        let _ = acknowledgement.send(result);
    }

    fn reannounce_outbound(&mut self) -> Result<(), TransferRuntimeError> {
        if self.store.is_poisoned() {
            self.store.purge_outbound(self.peer);
            return Ok(());
        }
        if !self.runtime.outbound_authorized() {
            self.store.purge_outbound(self.peer);
            return Ok(());
        }
        let payloads = {
            let mut inner = self
                .store
                .inner
                .lock()
                .expect("transfer store mutex poisoned");
            let Some(transfers) = inner.outbound.get_mut(&self.peer) else {
                return Ok(());
            };
            let mut payloads = Vec::with_capacity(transfers.len());
            for (transfer, pending) in transfers {
                let entry_count = pending.source.manifest().entries().len();
                pending.resume_offsets.fill(None);
                pending.remaining_resumes = entry_count;
                pending.ready = false;
                pending.awaiting_completion_ack = false;
                payloads.push(
                    self.runtime
                        .encode_manifest_frame(*transfer, pending.source.manifest())?,
                );
            }
            payloads
        };
        for payload in payloads {
            self.events
                .blocking_send(TransferWorkerEvent::SendManifest(payload))
                .map_err(|_| TransferRuntimeError::Backpressure)?;
        }
        Ok(())
    }

    fn drain_effect_budget(&mut self) -> Result<(), TransferRuntimeError> {
        for _ in 0..EFFECT_BUDGET {
            if self.stop.load(Ordering::Acquire) & STOP != 0 {
                break;
            }
            let Some(effect) = self.pending_effects.pop_front() else {
                break;
            };
            self.apply_effect(effect)?;
        }
        Ok(())
    }

    fn apply_effect(&mut self, effect: TransferRuntimeEffect) -> Result<(), TransferRuntimeError> {
        match effect {
            TransferRuntimeEffect::Completed { transfer } => {
                let core = TransferId::from_bytes(*transfer.as_bytes());
                self.store.forget_inbound(self.peer, core);
                self.store.remember_completed(self.peer, core);
                self.runtime.remember_completed_inbound(&[core]);
                self.runtime.remove_terminal(transfer)?;
                let payload = self.runtime.encode_complete_ack_frame(transfer)?;
                self.send_manifest(payload)?;
            }
            TransferRuntimeEffect::PeerCompleteAcknowledged { transfer }
            | TransferRuntimeEffect::PeerCancelRequested { transfer } => {
                if !self.remove_outbound(TransferId::from_bytes(*transfer.as_bytes())) {
                    return Err(TransferRuntimeError::Protocol);
                }
            }
            TransferRuntimeEffect::CompletionAcknowledgementRequired { transfer } => {
                let payload = self.runtime.encode_complete_ack_frame(transfer)?;
                self.send_manifest(payload)?;
            }
            TransferRuntimeEffect::PeerResumeRequested {
                transfer,
                entry_index,
                offset,
            } => self.handle_peer_resume(transfer, entry_index, offset)?,
            TransferRuntimeEffect::ResumeRequired {
                transfer,
                entry_index,
                offset,
            } => {
                let payload = self
                    .runtime
                    .encode_resume_frame(transfer, entry_index, offset)?;
                self.send_manifest(payload)?;
            }
            TransferRuntimeEffect::QueueSaturated { transfer } => {
                let payload = self.runtime.encode_cancel_frame(transfer, 1)?;
                self.send_manifest(payload)?;
            }
            TransferRuntimeEffect::Cancelled { transfer } => {
                self.store.require_inbound_discard(
                    self.peer,
                    TransferId::from_bytes(*transfer.as_bytes()),
                );
            }
            TransferRuntimeEffect::Started { transfer } => {
                self.store
                    .remember_inbound(self.peer, TransferId::from_bytes(*transfer.as_bytes()));
            }
            TransferRuntimeEffect::Progress { .. }
            | TransferRuntimeEffect::Backpressured { .. }
            | TransferRuntimeEffect::BackpressureReleased { .. } => {}
        }
        Ok(())
    }

    fn handle_peer_resume(
        &mut self,
        wire_transfer: WireTransferId,
        entry_index: u32,
        offset: u64,
    ) -> Result<(), TransferRuntimeError> {
        let transfer = TransferId::from_bytes(*wire_transfer.as_bytes());
        let mut inner = self
            .store
            .inner
            .lock()
            .expect("transfer store mutex poisoned");
        let pending = inner
            .outbound
            .get_mut(&self.peer)
            .and_then(|transfers| transfers.get_mut(&transfer))
            .ok_or(TransferRuntimeError::Protocol)?;
        if pending.ready || pending.awaiting_completion_ack {
            return Err(TransferRuntimeError::Protocol);
        }
        let index = usize::try_from(entry_index).map_err(|_| TransferRuntimeError::Protocol)?;
        let entry = pending
            .source
            .manifest()
            .entries()
            .get(index)
            .ok_or(TransferRuntimeError::Protocol)?;
        let valid_offset = match entry.kind {
            EntryKind::Directory => offset == 0,
            EntryKind::File => offset <= entry.size,
        };
        let slot = pending
            .resume_offsets
            .get_mut(index)
            .ok_or(TransferRuntimeError::Protocol)?;
        if !valid_offset || slot.replace(offset).is_some() {
            return Err(TransferRuntimeError::Protocol);
        }
        pending.remaining_resumes = pending
            .remaining_resumes
            .checked_sub(1)
            .ok_or(TransferRuntimeError::Protocol)?;
        if pending.remaining_resumes != 0 {
            return Ok(());
        }

        let entries = pending.source.manifest().entries();
        let mut first_incomplete = None;
        for (index, (entry, offset)) in entries.iter().zip(&pending.resume_offsets).enumerate() {
            let offset = offset.ok_or(TransferRuntimeError::Protocol)?;
            match entry.kind {
                EntryKind::File if first_incomplete.is_none() && offset == entry.size => {}
                EntryKind::File if first_incomplete.is_none() => {
                    first_incomplete = Some((index, offset));
                }
                EntryKind::Directory | EntryKind::File if offset == 0 => {}
                EntryKind::Directory | EntryKind::File => {
                    return Err(TransferRuntimeError::Protocol);
                }
            }
        }
        let resume = first_incomplete.or_else(|| {
            entries
                .len()
                .checked_sub(1)
                .map(|index| (index, pending.resume_offsets[index].unwrap_or(0)))
        });
        if let Some((index, offset)) = resume {
            pending
                .source
                .resume(OutboundResumePoint::new(
                    transfer,
                    u32::try_from(index).map_err(|_| TransferRuntimeError::Protocol)?,
                    offset,
                ))
                .map_err(TransferRuntimeError::Transfer)?;
        }
        pending.ready = true;
        Ok(())
    }

    fn pump_outbound(&mut self) -> Result<(), TransferRuntimeError> {
        let outcome = {
            let mut inner = self
                .store
                .inner
                .lock()
                .expect("transfer store mutex poisoned");
            let Some((transfer, pending)) = inner
                .outbound
                .get_mut(&self.peer)
                .and_then(|transfers| transfers.iter_mut().find(|(_, pending)| pending.ready))
            else {
                return Ok(());
            };
            if let Some(chunk) = pending.source.next_chunk()? {
                Some((self.runtime.encode_data_frame(&chunk)?, false, *transfer))
            } else {
                pending.ready = false;
                pending.awaiting_completion_ack = true;
                Some((
                    self.runtime.encode_complete_frame(*transfer)?,
                    true,
                    *transfer,
                ))
            }
        };
        if let Some((payload, complete, _transfer)) = outcome {
            if complete {
                self.send_manifest(payload)?;
            } else {
                self.events
                    .blocking_send(TransferWorkerEvent::SendData(payload))
                    .map_err(|_| TransferRuntimeError::Backpressure)?;
            }
        }
        Ok(())
    }

    fn send_manifest(&self, payload: Vec<u8>) -> Result<(), TransferRuntimeError> {
        self.events
            .blocking_send(TransferWorkerEvent::SendManifest(payload))
            .map_err(|_| TransferRuntimeError::Backpressure)
    }

    fn remove_outbound(&self, transfer: TransferId) -> bool {
        let removed = self
            .store
            .inner
            .lock()
            .expect("transfer store mutex poisoned")
            .outbound
            .get_mut(&self.peer)
            .and_then(|transfers| transfers.remove(&transfer));
        if let Some(mut pending) = removed {
            pending.source.cancel();
            self.store.release_outbound();
            true
        } else {
            false
        }
    }

    fn cleanup(&mut self) {
        while let Ok(command) = self.commands.try_recv() {
            if let WorkerCommand::StartOutbound {
                acknowledgement, ..
            } = command
            {
                self.store.release_outbound();
                let _ = acknowledgement.send(Err(TransferError::Cancelled));
            }
        }
        let mode = self.stop.load(Ordering::Acquire);
        if mode & ABORT_INBOUND != 0 {
            self.store.require_peer_inbound_discard(self.peer);
            if let Some(transfer) = self.runtime.active_inbound_transfer() {
                self.store.require_inbound_discard(self.peer, transfer);
            }
            let _ = self.runtime.abort_inbound();
        }
        if mode & ABORT_OUTBOUND != 0 {
            self.store.purge_outbound(self.peer);
        }
    }

    fn fail(&mut self, error: TransferRuntimeError) {
        if matches!(
            error,
            TransferRuntimeError::Transfer(TransferError::Platform)
        ) {
            self.store.poison();
        }
        self.stop
            .fetch_or(TransferStopMode::AbortAll.bits(), Ordering::AcqRel);
        self.cleanup();
        let _ = self.events.blocking_send(TransferWorkerEvent::Fatal(error));
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::Duration;

    use nodavo_protocol::{
        Capability, ContentHash as WireContentHash, EventMeta, FileDataMessage,
        FileManifestMessage, GrantEpoch, ManifestEntry as WireManifestEntry,
        ManifestEntryKind as WireEntryKind, RelativePath as WireRelativePath, Sequence, SessionId,
        decode_file_data, decode_file_manifest, encode_file_data, encode_file_manifest,
    };
    use tokio::time::timeout;

    use crate::transfer_runtime::{PeerTransferConfig, PeerTransferRuntime};
    use nodavo_transfer::{ContentHash, MAX_CHUNK_BYTES, ResumableStagingArea};

    use super::*;

    const LOCAL: DeviceId = DeviceId::new([1; 32]);
    const PEER: DeviceId = DeviceId::new([2; 32]);
    const LOCAL_EPOCH: GrantEpoch = GrantEpoch::new(3);
    const PEER_EPOCH: GrantEpoch = GrantEpoch::new(7);
    static FILE_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    fn temporary_directory(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "nodavo-transfer-worker-{label}-{}",
            TransferId::new().as_uuid()
        ));
        fs::create_dir(&path).unwrap();
        path
    }

    fn worker(
        store: TransferStore,
        session: SessionId,
        staging_root: &std::path::Path,
    ) -> TransferWorker {
        worker_with_capabilities(store, session, staging_root, Capability::FILE_TRANSFER)
    }

    fn worker_with_capabilities(
        store: TransferStore,
        session: SessionId,
        staging_root: &std::path::Path,
        peer_capabilities: Capability,
    ) -> TransferWorker {
        store
            .register_staging_root(staging_root.to_path_buf())
            .unwrap();
        let staging = FileSystemStagingArea::new(staging_root).unwrap();
        TransferWorker::start(
            PEER,
            PeerTransferRuntime::new(
                PeerTransferConfig {
                    local_device: LOCAL,
                    peer_device: PEER,
                    session_id: session,
                    local_grant_epoch: LOCAL_EPOCH,
                    peer_grant_epoch: PEER_EPOCH,
                    local_allows_peer_transfer: true,
                    peer_capabilities,
                },
                staging,
            ),
            store,
        )
    }

    async fn next_event(worker: &mut TransferWorker) -> TransferWorkerEvent {
        timeout(Duration::from_secs(2), worker.next_event())
            .await
            .unwrap()
            .unwrap()
    }

    fn resume_frame(
        session: SessionId,
        sequence: u64,
        transfer: WireTransferId,
        entry_index: u32,
        offset: u64,
    ) -> Vec<u8> {
        encode_file_manifest(&FileManifestMessage::Resume {
            meta: EventMeta::new(
                session,
                PEER,
                Sequence::new(sequence),
                PEER_EPOCH,
                Capability::FILE_TRANSFER,
            ),
            transfer,
            entry_index,
            offset,
        })
        .unwrap()
    }

    fn inbound_manifest_frame(
        session: SessionId,
        transfer: WireTransferId,
        payload: &[u8],
    ) -> Vec<u8> {
        encode_file_manifest(&FileManifestMessage::Manifest {
            meta: EventMeta::new(
                session,
                PEER,
                Sequence::new(1),
                LOCAL_EPOCH,
                Capability::FILE_TRANSFER,
            ),
            transfer,
            entries: vec![WireManifestEntry {
                path: WireRelativePath::parse("received.bin").unwrap(),
                kind: WireEntryKind::File,
                size: payload.len() as u64,
                hash: Some(WireContentHash::new(
                    *ContentHash::digest(payload).as_bytes(),
                )),
            }],
        })
        .unwrap()
    }

    fn inbound_data_frame(session: SessionId, transfer: WireTransferId, payload: &[u8]) -> Vec<u8> {
        encode_file_data(&FileDataMessage::Chunk {
            meta: EventMeta::new(
                session,
                PEER,
                Sequence::new(1),
                LOCAL_EPOCH,
                Capability::FILE_TRANSFER,
            ),
            transfer,
            entry_index: 0,
            offset: 0,
            bytes: payload.to_vec(),
        })
        .unwrap()
    }

    async fn wait_until_worker_releases_store(store: &TransferStore) {
        timeout(Duration::from_secs(2), async {
            loop {
                if store.cleanup_peer_if_idle(PEER).unwrap() == TransferCleanupState::Complete {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[test]
    fn outbound_reservations_are_bounded_before_scan() {
        let store = TransferStore::default();
        for _ in 0..MAX_PENDING_OUTBOUND_TRANSFERS {
            store.reserve_outbound().unwrap();
        }
        assert_eq!(store.outbound_count(), MAX_PENDING_OUTBOUND_TRANSFERS);
        assert_eq!(store.reserve_outbound(), Err(TransferError::QueueFull));
        for _ in 0..MAX_PENDING_OUTBOUND_TRANSFERS {
            store.release_outbound();
        }
        assert_eq!(store.outbound_count(), 0);
    }

    #[test]
    fn missing_cleanup_root_poisons_and_disables_later_file_work() {
        let store = TransferStore::default();
        let transfer = TransferId::from_bytes([31; 16]);
        store.remember_inbound(PEER, transfer);
        store.require_peer_inbound_discard(PEER);
        assert_eq!(
            store.cleanup_peer_if_idle(PEER),
            Err(TransferError::Platform)
        );
        assert!(store.is_poisoned());
        assert_eq!(store.reserve_outbound(), Err(TransferError::Platform));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn disconnect_cancels_an_in_progress_scan_and_releases_its_reservation() {
        let _guard = FILE_TEST_LOCK.lock().await;
        let source_root = temporary_directory("source-cancel-scan");
        let staging_root = temporary_directory("staging-cancel-scan");
        let selected = source_root.join("large.bin");
        fs::write(&selected, vec![b'c'; 32 * 1024 * 1024]).unwrap();
        let store = TransferStore::default();
        let worker = worker(store.clone(), SessionId::new([9; 16]), &staging_root);
        let (acknowledgement, acknowledged) = oneshot::channel();
        worker.try_start_outbound(vec![selected], acknowledgement);
        timeout(Duration::from_secs(2), async {
            while !worker.scan_is_active() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        worker.stop(TransferStopMode::Suspend);
        assert_eq!(
            timeout(Duration::from_secs(2), acknowledged)
                .await
                .unwrap()
                .unwrap(),
            Err(TransferError::Cancelled)
        );
        drop(worker);
        wait_until_worker_releases_store(&store).await;
        assert_eq!(store.outbound_count(), 0);
        fs::remove_dir_all(source_root).unwrap();
        fs::remove_dir_all(staging_root).unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn link_loss_reannounces_same_source_and_resumes_from_receiver_offset() {
        let _guard = FILE_TEST_LOCK.lock().await;
        let source_root = temporary_directory("source-resume");
        let staging_root = temporary_directory("staging-resume");
        let selected = source_root.join("resume.bin");
        fs::write(&selected, vec![b'r'; MAX_CHUNK_BYTES + 17]).unwrap();
        let store = TransferStore::default();
        let first_session = SessionId::new([3; 16]);
        let mut first = worker(store.clone(), first_session, &staging_root);
        let (acknowledgement, acknowledged) = oneshot::channel();
        first.try_start_outbound(vec![selected], acknowledgement);
        let transfer = acknowledged.await.unwrap().unwrap();
        let TransferWorkerEvent::SendManifest(first_manifest) = next_event(&mut first).await else {
            panic!("expected initial manifest");
        };
        let FileManifestMessage::Manifest {
            transfer: wire_transfer,
            ..
        } = decode_file_manifest(&first_manifest).unwrap()
        else {
            panic!("expected initial manifest message");
        };
        assert_eq!(wire_transfer.as_bytes(), &transfer.as_bytes());

        first
            .try_receive_manifest(resume_frame(first_session, 1, wire_transfer, 0, 0))
            .unwrap();
        first.try_pump().unwrap();
        let TransferWorkerEvent::SendData(first_data) = next_event(&mut first).await else {
            panic!("expected first data chunk");
        };
        let FileDataMessage::Chunk { offset, .. } = decode_file_data(&first_data).unwrap() else {
            panic!("expected first data chunk message");
        };
        assert_eq!(offset, 0);

        first.stop(TransferStopMode::Suspend);
        drop(first);
        tokio::time::sleep(Duration::from_millis(20)).await;

        let second_session = SessionId::new([4; 16]);
        let mut second = worker(store.clone(), second_session, &staging_root);
        let TransferWorkerEvent::SendManifest(second_manifest) = next_event(&mut second).await
        else {
            panic!("expected reannounced manifest");
        };
        let FileManifestMessage::Manifest {
            transfer: reannounced,
            ..
        } = decode_file_manifest(&second_manifest).unwrap()
        else {
            panic!("expected reannounced manifest message");
        };
        assert_eq!(reannounced, wire_transfer);

        second
            .try_receive_manifest(resume_frame(
                second_session,
                1,
                reannounced,
                0,
                MAX_CHUNK_BYTES as u64,
            ))
            .unwrap();
        second.try_pump().unwrap();
        let TransferWorkerEvent::SendData(resumed_data) = next_event(&mut second).await else {
            panic!("expected resumed data chunk");
        };
        let FileDataMessage::Chunk { offset, .. } = decode_file_data(&resumed_data).unwrap() else {
            panic!("expected resumed data message");
        };
        assert_eq!(offset, MAX_CHUNK_BYTES as u64);

        store.mark_peer_revoked(PEER);
        assert_eq!(store.outbound_count(), 0, "peer revoke retained source");
        second.stop(TransferStopMode::Suspend);
        drop(second);
        tokio::time::sleep(Duration::from_millis(20)).await;
        fs::remove_dir_all(source_root).unwrap();
        fs::remove_dir_all(staging_root).unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn all_complete_resume_including_zero_byte_source_goes_directly_to_complete() {
        let _guard = FILE_TEST_LOCK.lock().await;
        let source_root = temporary_directory("source-complete");
        let staging_root = temporary_directory("staging-complete");
        let empty = source_root.join("empty.bin");
        let content = source_root.join("full.bin");
        fs::write(&empty, []).unwrap();
        fs::write(&content, b"complete").unwrap();
        let store = TransferStore::default();
        let session = SessionId::new([5; 16]);
        let mut worker = worker(store.clone(), session, &staging_root);
        let (acknowledgement, acknowledged) = oneshot::channel();
        worker.try_start_outbound(vec![empty, content], acknowledgement);
        let transfer = acknowledged.await.unwrap().unwrap();
        let TransferWorkerEvent::SendManifest(manifest_frame) = next_event(&mut worker).await
        else {
            panic!("expected manifest");
        };
        let FileManifestMessage::Manifest {
            transfer: wire_transfer,
            entries,
            ..
        } = decode_file_manifest(&manifest_frame).unwrap()
        else {
            panic!("expected manifest message");
        };
        assert_eq!(wire_transfer.as_bytes(), &transfer.as_bytes());
        assert!(entries.iter().any(|entry| entry.size == 0));
        for (index, entry) in entries.iter().enumerate() {
            worker
                .try_receive_manifest(resume_frame(
                    session,
                    u64::try_from(index + 1).unwrap(),
                    wire_transfer,
                    u32::try_from(index).unwrap(),
                    entry.size,
                ))
                .unwrap();
        }
        worker.try_pump().unwrap();
        let TransferWorkerEvent::SendManifest(complete_frame) = next_event(&mut worker).await
        else {
            panic!("all-complete resume must not restart source data");
        };
        assert!(matches!(
            decode_file_manifest(&complete_frame).unwrap(),
            FileManifestMessage::Complete { transfer, .. } if transfer == wire_transfer
        ));

        worker.stop(TransferStopMode::AbortAll);
        drop(worker);
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(store.outbound_count(), 0);
        fs::remove_dir_all(source_root).unwrap();
        fs::remove_dir_all(staging_root).unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn reconnect_with_peer_file_grant_revoked_purges_retained_source() {
        let _guard = FILE_TEST_LOCK.lock().await;
        let source_root = temporary_directory("source-revoked");
        let staging_root = temporary_directory("staging-revoked");
        let selected = source_root.join("revoked.bin");
        fs::write(&selected, b"revoked").unwrap();
        let store = TransferStore::default();
        let mut first = worker(store.clone(), SessionId::new([6; 16]), &staging_root);
        let (acknowledgement, acknowledged) = oneshot::channel();
        first.try_start_outbound(vec![selected], acknowledgement);
        acknowledged.await.unwrap().unwrap();
        assert!(matches!(
            next_event(&mut first).await,
            TransferWorkerEvent::SendManifest(_)
        ));
        first.stop(TransferStopMode::Suspend);
        drop(first);
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(store.outbound_count(), 1);

        let second = worker_with_capabilities(
            store.clone(),
            SessionId::new([7; 16]),
            &staging_root,
            Capability::empty(),
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(store.outbound_count(), 0);
        second.stop(TransferStopMode::Suspend);
        drop(second);
        fs::remove_dir_all(source_root).unwrap();
        fs::remove_dir_all(staging_root).unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn suspended_authenticated_inbound_is_discarded_only_for_its_peer() {
        let _guard = FILE_TEST_LOCK.lock().await;
        let staging_root = temporary_directory("staging-offline-revoke");
        let store = TransferStore::default();
        let session = SessionId::new([8; 16]);
        let transfer = WireTransferId::new([21; 16]);
        let payload = b"partially durable inbound";
        let mut worker = worker(store.clone(), session, &staging_root);
        worker
            .try_receive_manifest(inbound_manifest_frame(session, transfer, payload))
            .unwrap();
        assert!(matches!(
            next_event(&mut worker).await,
            TransferWorkerEvent::SendManifest(_)
        ));
        worker
            .try_receive_data(inbound_data_frame(session, transfer, &payload[..8]))
            .unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        worker.stop(TransferStopMode::Suspend);
        drop(worker);
        wait_until_worker_releases_store(&store).await;

        let core_transfer = TransferId::from_bytes(*transfer.as_bytes());
        let staging = FileSystemStagingArea::new(&staging_root).unwrap();
        assert!(staging.has_persisted(core_transfer).unwrap());
        drop(staging);

        store.require_peer_inbound_discard(PEER);
        assert_eq!(
            store.cleanup_peer_if_idle(PEER).unwrap(),
            TransferCleanupState::Complete
        );
        let staging = FileSystemStagingArea::new(&staging_root).unwrap();
        assert!(!staging.has_persisted(core_transfer).unwrap());
        assert!(!store.is_poisoned());
        fs::remove_dir_all(staging_root).unwrap();
    }
}
