//! Bounded process-lifetime file-transfer ownership outside the session loop.
//!
//! The worker owns all scanning, hashing, source reads, durable staging writes,
//! fsync/finalize, and abort cleanup. The authenticated session loop exchanges
//! only bounded commands/events and can therefore prioritize safety signals.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use nodavo_local_ipc::{TransferDirection, TransferFailureCode, TransferPhase};
use nodavo_protocol::{DeviceId, TransferId as WireTransferId};
use nodavo_transfer::{
    EntryKind, FileSystemStagingArea, OutboundResumePoint, OutboundTransferSource, TransferError,
    TransferId,
};
use tokio::runtime::Handle;
use tokio::sync::{mpsc, oneshot};

use crate::transfer_runtime::{PeerTransferRuntime, TransferRuntimeEffect, TransferRuntimeError};
use crate::transfer_status::{
    CancelOutcome, CancelTarget, InboundAdmission, InboundUpdate, MAX_LIFETIME_TRANSFER_IDENTITIES,
    TransferAdmission, TransferListing, TransferRegistry, TransferRegistryError,
};

/// Includes scans in progress, sources awaiting receiver acceptance, active
/// sends, and sources retained until durable completion acknowledgement.
pub(crate) const MAX_PENDING_OUTBOUND_TRANSFERS: usize = 4;
const COMMAND_CAPACITY: usize = 16;
const EVENT_CAPACITY: usize = 16;
const EFFECT_BUDGET: usize = 32;
const MAX_RETAINED_WIRE_IDENTITIES: usize = MAX_LIFETIME_TRANSFER_IDENTITIES * 2;

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
    SendManifest {
        payload: Vec<u8>,
        update: Option<ReliableSendUpdate>,
    },
    SendData {
        payload: Vec<u8>,
        update: ReliableSendUpdate,
    },
    Fatal(TransferRuntimeError),
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum ReliableSendUpdate {
    Data {
        public_id: uuid::Uuid,
        processed_bytes: u64,
    },
    Finalizing {
        public_id: uuid::Uuid,
    },
}

#[derive(Default)]
struct StoreInner {
    outbound: HashMap<DeviceId, HashMap<TransferId, PendingOutboundTransfer>>,
    retained_wire: HashMap<RetainedWireKey, RetainedWireState>,
    inbound: HashMap<DeviceId, HashSet<TransferId>>,
    discard_required: HashMap<DeviceId, HashSet<TransferId>>,
    staging_roots: HashMap<DeviceId, PathBuf>,
    active_workers: usize,
    active_worker_peers: HashSet<DeviceId>,
    worker_admission_closed: bool,
    cleanup_in_progress: bool,
    directory_entry_crash_durable: bool,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct RetainedWireKey {
    peer: DeviceId,
    direction: TransferDirection,
    transfer: TransferId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RetainedWireState {
    Live,
    CompletedInbound,
    RejectedInbound,
    RetiredOutbound,
}

struct PendingOutboundTransfer {
    public_id: uuid::Uuid,
    cancellation: Arc<AtomicBool>,
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
    registry: TransferRegistry,
    outbound_slots: Arc<AtomicUsize>,
    poisoned: Arc<AtomicBool>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TransferCleanupState {
    Complete,
    Pending,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TransferWorkerAdmissionClosed;

impl TransferStore {
    pub(crate) fn transfer_listing(&self) -> TransferListing {
        self.registry.list()
    }

    pub(crate) fn request_cancel(
        &self,
        transfer_id: &str,
    ) -> Result<CancelOutcome, TransferRegistryError> {
        self.registry.request_cancel(transfer_id)
    }

    /// Releases an offline retained source. A live worker observes the same
    /// atomic token and sends the targeted authenticated cancel frame itself.
    pub(crate) fn cleanup_cancelled_if_offline(&self, target: CancelTarget) {
        let active = {
            self.inner
                .lock()
                .expect("transfer store mutex poisoned")
                .active_worker_peers
                .contains(&target.binding.peer)
        };
        if active {
            return;
        }
        if target.binding.direction == TransferDirection::Inbound {
            self.require_inbound_discard(target.binding.peer, target.binding.wire_id);
            let _ = self.cleanup_peer_if_idle(target.binding.peer);
            return;
        }
        let removed = {
            let mut inner = self.inner.lock().expect("transfer store mutex poisoned");
            inner
                .outbound
                .get_mut(&target.binding.peer)
                .and_then(|transfers| transfers.remove(&target.binding.wire_id))
        };
        if let Some(mut pending) = removed {
            pending.source.cancel();
            self.release_outbound();
        }
        if self
            .remember_cancelled_outbound(target.binding.peer, target.binding.wire_id)
            .is_err()
        {
            self.poison();
            self.registry
                .cleanup_failed(target.binding.peer, TransferDirection::Outbound);
            return;
        }
        self.registry.cancelled(target.binding.public_id);
    }

    pub(crate) fn close_worker_admission_for_safety(&self) {
        self.inner
            .lock()
            .expect("transfer store mutex poisoned")
            .worker_admission_closed = true;
    }

    pub(crate) fn reopen_worker_admission_after_safety(&self) {
        self.inner
            .lock()
            .expect("transfer store mutex poisoned")
            .worker_admission_closed = false;
    }

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

    fn admit_outbound(&self, peer: DeviceId) -> Result<TransferAdmission, TransferError> {
        self.reserve_outbound()?;
        let Ok(admission) = self.registry.admit_outbound(peer) else {
            self.release_outbound();
            return Err(TransferError::QueueFull);
        };
        if let Err(error) =
            self.reserve_retained(peer, TransferDirection::Outbound, admission.binding.wire_id)
        {
            self.registry
                .rollback_admission(admission.binding.public_id);
            self.release_outbound();
            return Err(error);
        }
        Ok(admission)
    }

    fn release_outbound(&self) {
        let previous = self.outbound_slots.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous != 0, "outbound transfer reservation underflow");
    }

    fn remove_outbound(&self, peer: DeviceId, transfer: TransferId) -> bool {
        let removed = self
            .inner
            .lock()
            .expect("transfer store mutex poisoned")
            .outbound
            .get_mut(&peer)
            .and_then(|transfers| transfers.remove(&transfer));
        if let Some(mut pending) = removed {
            pending.source.cancel();
            self.release_outbound();
            true
        } else {
            false
        }
    }

    fn completed_for(&self, peer: DeviceId) -> Vec<TransferId> {
        self.retained_for(
            peer,
            TransferDirection::Inbound,
            RetainedWireState::CompletedInbound,
        )
    }

    fn cancelled_for(&self, peer: DeviceId) -> Vec<TransferId> {
        self.retained_for(
            peer,
            TransferDirection::Inbound,
            RetainedWireState::RejectedInbound,
        )
    }

    fn remember_cancelled_inbound(
        &self,
        peer: DeviceId,
        transfer: TransferId,
    ) -> Result<(), TransferError> {
        self.transition_retained(
            peer,
            TransferDirection::Inbound,
            transfer,
            RetainedWireState::RejectedInbound,
        )
    }

    fn cancelled_outbound_for(&self, peer: DeviceId) -> Vec<TransferId> {
        self.retained_for(
            peer,
            TransferDirection::Outbound,
            RetainedWireState::RetiredOutbound,
        )
    }

    fn remember_cancelled_outbound(
        &self,
        peer: DeviceId,
        transfer: TransferId,
    ) -> Result<(), TransferError> {
        self.transition_retained(
            peer,
            TransferDirection::Outbound,
            transfer,
            RetainedWireState::RetiredOutbound,
        )
    }

    fn is_cancelled_outbound(&self, peer: DeviceId, transfer: TransferId) -> bool {
        self.inner
            .lock()
            .expect("transfer store mutex poisoned")
            .retained_wire
            .get(&retained_key(peer, TransferDirection::Outbound, transfer))
            == Some(&RetainedWireState::RetiredOutbound)
    }

    fn retained_for(
        &self,
        peer: DeviceId,
        direction: TransferDirection,
        state: RetainedWireState,
    ) -> Vec<TransferId> {
        self.inner
            .lock()
            .expect("transfer store mutex poisoned")
            .retained_wire
            .iter()
            .filter_map(|(key, retained)| {
                (key.peer == peer && key.direction == direction && *retained == state)
                    .then_some(key.transfer)
            })
            .collect()
    }

    fn reserve_retained(
        &self,
        peer: DeviceId,
        direction: TransferDirection,
        transfer: TransferId,
    ) -> Result<(), TransferError> {
        self.transition_retained(peer, direction, transfer, RetainedWireState::Live)
    }

    fn transition_retained(
        &self,
        peer: DeviceId,
        direction: TransferDirection,
        transfer: TransferId,
        next: RetainedWireState,
    ) -> Result<(), TransferError> {
        let mut inner = self.inner.lock().map_err(|_| TransferError::Platform)?;
        transition_retained_locked(&mut inner, retained_key(peer, direction, transfer), next)
    }

    pub(crate) fn register_staging_root(
        &self,
        peer: DeviceId,
        root: PathBuf,
    ) -> Result<(), TransferError> {
        let mut inner = self.inner.lock().map_err(|_| TransferError::Platform)?;
        if inner
            .staging_roots
            .get(&peer)
            .is_some_and(|known| known != &root)
        {
            self.poisoned.store(true, Ordering::Release);
            return Err(TransferError::Platform);
        }
        inner.staging_roots.insert(peer, root);
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

    pub(crate) fn remember_inbound(
        &self,
        peer: DeviceId,
        transfer: TransferId,
    ) -> Result<(), TransferError> {
        self.reserve_retained(peer, TransferDirection::Inbound, transfer)?;
        self.inner
            .lock()
            .map_err(|_| TransferError::Platform)?
            .inbound
            .entry(peer)
            .or_default()
            .insert(transfer);
        Ok(())
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
        self.registry
            .request_system_abort(peer, TransferDirection::Inbound);
        let mut inner = self.inner.lock().expect("transfer store mutex poisoned");
        let transfers = inner.inbound.get(&peer).cloned().unwrap_or_default();
        inner
            .discard_required
            .entry(peer)
            .or_default()
            .extend(transfers);
    }

    /// Atomically enrolls every known inbound transfer only after all session
    /// workers have stopped publishing new staging state.
    pub(crate) fn require_all_inbound_discard_if_idle(&self) -> Option<Vec<DeviceId>> {
        let mut inner = self.inner.lock().expect("transfer store mutex poisoned");
        if inner.active_workers != 0 || inner.cleanup_in_progress {
            return None;
        }
        let peers = inner.inbound.keys().copied().collect::<Vec<_>>();
        for peer in &peers {
            let transfers = inner.inbound.get(peer).cloned().unwrap_or_default();
            inner
                .discard_required
                .entry(*peer)
                .or_default()
                .extend(transfers);
        }
        Some(peers)
    }

    fn worker_started(&self, peer: DeviceId) -> Result<(), TransferWorkerAdmissionClosed> {
        let mut inner = self.inner.lock().expect("transfer store mutex poisoned");
        if inner.worker_admission_closed {
            return Err(TransferWorkerAdmissionClosed);
        }
        inner.active_workers = inner.active_workers.saturating_add(1);
        inner.active_worker_peers.insert(peer);
        Ok(())
    }

    fn worker_finished(&self, peer: DeviceId) {
        {
            let mut inner = self.inner.lock().expect("transfer store mutex poisoned");
            inner.active_workers = inner.active_workers.saturating_sub(1);
            inner.active_worker_peers.remove(&peer);
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
                let poisoned = self.is_poisoned();
                drop(inner);
                if poisoned {
                    return Err(TransferError::Platform);
                }
                self.registry
                    .finish_system_abort(peer, TransferDirection::Inbound);
                return Ok(TransferCleanupState::Complete);
            }
            let Some(root) = inner.staging_roots.get(&peer).cloned() else {
                self.poisoned.store(true, Ordering::Release);
                drop(inner);
                self.registry
                    .cleanup_failed(peer, TransferDirection::Inbound);
                return Err(TransferError::Platform);
            };
            let cleanup_keys = transfers
                .iter()
                .map(|transfer| retained_key(peer, TransferDirection::Inbound, *transfer))
                .collect::<Vec<_>>();
            if reserve_retained_keys_locked(&mut inner, &cleanup_keys).is_err() {
                self.poisoned.store(true, Ordering::Release);
                drop(inner);
                self.registry
                    .cleanup_failed(peer, TransferDirection::Inbound);
                return Err(TransferError::QueueFull);
            }
            inner.cleanup_in_progress = true;
            (root, transfers)
        };

        let result = (|| {
            let mut staging = FileSystemStagingArea::new_scoped(root, *peer.as_bytes())?;
            for transfer in &transfers {
                staging.discard_unopened_persisted(*transfer)?;
            }
            Ok(())
        })();
        let mut inner = self.inner.lock().map_err(|_| TransferError::Platform)?;
        inner.cleanup_in_progress = false;
        if let Err(error) = result {
            self.poisoned.store(true, Ordering::Release);
            drop(inner);
            self.registry
                .cleanup_failed(peer, TransferDirection::Inbound);
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
        let transitioned = transfers.iter().all(|transfer| {
            transition_reserved_locked(
                &mut inner,
                retained_key(peer, TransferDirection::Inbound, *transfer),
                RetainedWireState::RejectedInbound,
            )
        });
        if !transitioned {
            self.poisoned.store(true, Ordering::Release);
            drop(inner);
            self.registry
                .cleanup_failed(peer, TransferDirection::Inbound);
            return Err(TransferError::Platform);
        }
        let poisoned = self.is_poisoned();
        drop(inner);
        if poisoned {
            Err(TransferError::Platform)
        } else {
            self.registry
                .finish_system_abort(peer, TransferDirection::Inbound);
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

    fn remember_completed(
        &self,
        peer: DeviceId,
        transfer: TransferId,
    ) -> Result<(), TransferError> {
        self.transition_retained(
            peer,
            TransferDirection::Inbound,
            transfer,
            RetainedWireState::CompletedInbound,
        )
    }

    fn purge_outbound(&self, peer: DeviceId) {
        let removed = self
            .inner
            .lock()
            .expect("transfer store mutex poisoned")
            .outbound
            .remove(&peer)
            .unwrap_or_default();
        for (wire_id, mut pending) in removed {
            pending.source.cancel();
            if self.remember_cancelled_outbound(peer, wire_id).is_err() {
                self.poison();
                self.registry
                    .cleanup_failed(peer, TransferDirection::Outbound);
                return;
            }
            self.registry.cancelled(pending.public_id);
            self.release_outbound();
        }
    }

    pub(crate) fn mark_peer_revoked(&self, peer: DeviceId) {
        self.purge_outbound(peer);
        self.require_peer_inbound_discard(peer);
    }

    #[cfg(test)]
    fn outbound_count(&self) -> usize {
        self.outbound_slots.load(Ordering::Acquire)
    }
}

fn retained_key(
    peer: DeviceId,
    direction: TransferDirection,
    transfer: TransferId,
) -> RetainedWireKey {
    RetainedWireKey {
        peer,
        direction,
        transfer,
    }
}

fn transition_retained_locked(
    inner: &mut StoreInner,
    key: RetainedWireKey,
    next: RetainedWireState,
) -> Result<(), TransferError> {
    if let Some(current) = inner.retained_wire.get_mut(&key) {
        if *current == RetainedWireState::Live {
            *current = next;
        }
        return Ok(());
    }
    if inner.retained_wire.len() >= MAX_RETAINED_WIRE_IDENTITIES {
        return Err(TransferError::QueueFull);
    }
    inner.retained_wire.insert(key, next);
    Ok(())
}

fn reserve_retained_keys_locked(
    inner: &mut StoreInner,
    keys: &[RetainedWireKey],
) -> Result<(), TransferError> {
    let missing = keys
        .iter()
        .copied()
        .filter(|key| !inner.retained_wire.contains_key(key))
        .collect::<HashSet<_>>();
    if inner.retained_wire.len().saturating_add(missing.len()) > MAX_RETAINED_WIRE_IDENTITIES {
        return Err(TransferError::QueueFull);
    }
    inner.retained_wire.extend(
        missing
            .into_iter()
            .map(|key| (key, RetainedWireState::Live)),
    );
    Ok(())
}

fn transition_reserved_locked(
    inner: &mut StoreInner,
    key: RetainedWireKey,
    next: RetainedWireState,
) -> bool {
    let Some(current) = inner.retained_wire.get_mut(&key) else {
        return false;
    };
    if *current == RetainedWireState::Live {
        *current = next;
    }
    true
}

enum WorkerCommand {
    ReceiveManifest(Vec<u8>),
    ReceiveData(Vec<u8>),
    StartOutbound {
        admission: TransferAdmission,
        paths: Vec<PathBuf>,
    },
    PumpOutbound,
    Stop,
}

pub(crate) struct TransferWorker {
    peer: DeviceId,
    commands: mpsc::Sender<WorkerCommand>,
    events: mpsc::Receiver<TransferWorkerEvent>,
    stop: Arc<AtomicU8>,
    store: TransferStore,
    #[cfg(test)]
    scan_active: Arc<AtomicBool>,
    #[cfg(test)]
    finalize_pause: Arc<AtomicBool>,
    #[cfg(test)]
    finalize_entered: Arc<AtomicBool>,
}

impl TransferWorker {
    pub(crate) fn start(
        peer: DeviceId,
        mut runtime: PeerTransferRuntime<FileSystemStagingArea>,
        store: TransferStore,
    ) -> Result<Self, TransferWorkerAdmissionClosed> {
        if runtime
            .remember_completed_inbound(&store.completed_for(peer))
            .and_then(|()| runtime.remember_rejected_inbound(&store.cancelled_for(peer)))
            .and_then(|()| runtime.remember_cancelled_outbound(&store.cancelled_outbound_for(peer)))
            .is_err()
        {
            store.poison();
            return Err(TransferWorkerAdmissionClosed);
        }
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
        #[cfg(test)]
        let finalize_pause = Arc::new(AtomicBool::new(false));
        #[cfg(test)]
        let thread_finalize_pause = Arc::clone(&finalize_pause);
        #[cfg(test)]
        let finalize_entered = Arc::new(AtomicBool::new(false));
        #[cfg(test)]
        let thread_finalize_entered = Arc::clone(&finalize_entered);
        let thread_store = store.clone();
        let handle = Handle::current();
        store.worker_started(peer)?;
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
                    rejected_inbound: HashSet::new(),
                    handle,
                    #[cfg(test)]
                    scan_active: thread_scan_active,
                    #[cfg(test)]
                    finalize_pause: thread_finalize_pause,
                    #[cfg(test)]
                    finalize_entered: thread_finalize_entered,
                };
                state.run();
                drop(state);
                thread_store.worker_finished(peer);
            })
            .expect("the bounded transfer worker thread must start");
        Ok(Self {
            peer,
            commands: command_tx,
            events: event_rx,
            stop,
            store,
            #[cfg(test)]
            scan_active,
            #[cfg(test)]
            finalize_pause,
            #[cfg(test)]
            finalize_entered,
        })
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
        let admission = match self.store.admit_outbound(self.peer) {
            Ok(admission) => admission,
            Err(error) => {
                let _ = acknowledgement.send(Err(error));
                return;
            }
        };
        let public_transfer = TransferId::from_bytes(*admission.binding.public_id.as_bytes());
        if self
            .commands
            .try_send(WorkerCommand::StartOutbound {
                admission: admission.clone(),
                paths,
            })
            .is_err()
        {
            let _ = self
                .store
                .remember_cancelled_outbound(self.peer, admission.binding.wire_id);
            self.store
                .registry
                .rollback_admission(admission.binding.public_id);
            self.store.release_outbound();
            let _ = acknowledgement.send(Err(TransferError::QueueFull));
        } else {
            // Admission is the acknowledgement boundary. Scan and hashing are
            // worker-owned and may continue after the local IPC call returns.
            let _ = acknowledgement.send(Ok(public_transfer));
        }
    }

    pub(crate) fn try_pump(&self) -> Result<(), TransferRuntimeError> {
        match self.commands.try_send(WorkerCommand::PumpOutbound) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(WorkerCommand::PumpOutbound)) => Ok(()),
            Err(_) => Err(TransferRuntimeError::Backpressure),
        }
    }

    pub(crate) fn try_wake_cancellation(&self) -> Result<(), TransferRuntimeError> {
        self.try_pump()
    }

    pub(crate) async fn next_event(&mut self) -> Option<TransferWorkerEvent> {
        self.events.recv().await
    }

    pub(crate) fn reliable_send_succeeded(&self, update: ReliableSendUpdate) {
        match update {
            ReliableSendUpdate::Data {
                public_id,
                processed_bytes,
            } => self
                .store
                .registry
                .reliable_data_sent(public_id, processed_bytes),
            ReliableSendUpdate::Finalizing { public_id } => {
                self.store.registry.finalizing(public_id);
            }
        }
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

    #[cfg(test)]
    fn pause_finalize_for_test(&self) {
        self.finalize_pause.store(true, Ordering::Release);
    }

    #[cfg(test)]
    fn finalize_is_paused(&self) -> bool {
        self.finalize_entered.load(Ordering::Acquire)
    }

    #[cfg(test)]
    fn release_finalize_for_test(&self) {
        self.finalize_pause.store(false, Ordering::Release);
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
    rejected_inbound: HashSet<TransferId>,
    handle: Handle,
    #[cfg(test)]
    scan_active: Arc<AtomicBool>,
    #[cfg(test)]
    finalize_pause: Arc<AtomicBool>,
    #[cfg(test)]
    finalize_entered: Arc<AtomicBool>,
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
            if let Err(error) = self.handle_targeted_inbound_cancel() {
                self.fail(error);
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
            WorkerCommand::StartOutbound { admission, paths } => {
                self.start_outbound(&admission, paths)?;
            }
            WorkerCommand::PumpOutbound => self.pump_outbound()?,
            WorkerCommand::Stop => {}
        }
        Ok(())
    }

    fn start_outbound(
        &mut self,
        admission: &TransferAdmission,
        paths: Vec<PathBuf>,
    ) -> Result<(), TransferRuntimeError> {
        let transfer = admission.binding.wire_id;
        let public_id = admission.binding.public_id;
        #[cfg(test)]
        self.scan_active.store(true, Ordering::Release);
        let stop = Arc::clone(&self.stop);
        let cancellation = Arc::clone(&admission.cancellation);
        let result = OutboundTransferSource::scan_with_cancel(transfer, paths, || {
            stop.load(Ordering::Acquire) & STOP != 0
                || TransferRegistry::cancellation_requested(&cancellation)
        })
        .and_then(|source| {
            if self.stop.load(Ordering::Acquire) & STOP != 0
                || TransferRegistry::cancellation_requested(&admission.cancellation)
            {
                return Err(TransferError::Cancelled);
            }
            self.store
                .registry
                .manifest_ready(public_id, source.manifest().total_bytes());
            let entry_count = source.manifest().entries().len();
            let payload = self
                .runtime
                .encode_manifest_frame(transfer, source.manifest())
                .map_err(|_| TransferError::Cancelled)?;
            let pending = PendingOutboundTransfer {
                public_id,
                cancellation: Arc::clone(&admission.cancellation),
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
                .blocking_send(TransferWorkerEvent::SendManifest {
                    payload,
                    update: None,
                })
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
        match result {
            Ok(_) => {}
            Err(TransferError::Cancelled) => {
                self.store
                    .remember_cancelled_outbound(self.peer, transfer)?;
                self.runtime.remember_cancelled_outbound(&[transfer])?;
                self.store.registry.cancelled(public_id);
            }
            Err(_) => self
                .store
                .registry
                .fail(public_id, TransferFailureCode::SourceUnavailable),
        }
        Ok(())
    }

    fn reannounce_outbound(&mut self) -> Result<(), TransferRuntimeError> {
        if self.store.is_poisoned() {
            self.store.purge_outbound(self.peer);
            self.runtime
                .remember_cancelled_outbound(&self.store.cancelled_outbound_for(self.peer))?;
            return Ok(());
        }
        if !self.runtime.outbound_authorized() {
            self.store.purge_outbound(self.peer);
            self.runtime
                .remember_cancelled_outbound(&self.store.cancelled_outbound_for(self.peer))?;
            return Ok(());
        }
        let cancelled = {
            let inner = self
                .store
                .inner
                .lock()
                .expect("transfer store mutex poisoned");
            inner
                .outbound
                .get(&self.peer)
                .map(|transfers| {
                    transfers
                        .iter()
                        .filter_map(|(wire_id, pending)| {
                            TransferRegistry::cancellation_requested(&pending.cancellation)
                                .then_some((*wire_id, pending.public_id))
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        };
        for (wire_id, public_id) in cancelled {
            self.remove_outbound(wire_id);
            self.store.remember_cancelled_outbound(self.peer, wire_id)?;
            self.runtime.remember_cancelled_outbound(&[wire_id])?;
            self.store.registry.cancelled(public_id);
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
                .blocking_send(TransferWorkerEvent::SendManifest {
                    payload,
                    update: None,
                })
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

    #[allow(
        clippy::too_many_lines,
        reason = "one exhaustive worker effect dispatcher keeps transfer state transitions auditable"
    )]
    fn apply_effect(&mut self, effect: TransferRuntimeEffect) -> Result<(), TransferRuntimeError> {
        match effect {
            TransferRuntimeEffect::Admitted {
                transfer,
                total_bytes,
            } => {
                let core = TransferId::from_bytes(*transfer.as_bytes());
                match self
                    .store
                    .registry
                    .admit_inbound(self.peer, core, total_bytes)
                {
                    Ok(InboundAdmission::Live(binding)) => {
                        if self.store.remember_inbound(self.peer, core).is_err() {
                            let _ = self.handle.block_on(self.runtime.cancel_inbound(core))?;
                            self.store.registry.rollback_admission(binding.public_id);
                            return Err(TransferRuntimeError::Backpressure);
                        }
                    }
                    Ok(InboundAdmission::Terminal { .. })
                    | Err(TransferRegistryError::Full | TransferRegistryError::WireIdCollision) => {
                        self.reject_inbound(core, 1)?;
                    }
                    Err(TransferRegistryError::LifetimeFull) => {
                        let _ = self.handle.block_on(self.runtime.cancel_inbound(core))?;
                        return Err(TransferRuntimeError::Backpressure);
                    }
                    Err(_) => return Err(TransferRuntimeError::Protocol),
                }
            }
            TransferRuntimeEffect::AdvanceQueue => {
                let effects = self.handle.block_on(self.runtime.advance_queue())?;
                self.pending_effects.extend(effects);
            }
            TransferRuntimeEffect::FinalizeRequired { transfer } => {
                let core = TransferId::from_bytes(*transfer.as_bytes());
                let binding = self
                    .store
                    .registry
                    .binding_for_wire(self.peer, TransferDirection::Inbound, core)
                    .ok_or(TransferRuntimeError::Protocol)?;
                if self
                    .store
                    .registry
                    .begin_inbound_finalizing(binding.public_id)
                {
                    #[cfg(test)]
                    if self.finalize_pause.load(Ordering::Acquire) {
                        self.finalize_entered.store(true, Ordering::Release);
                        while self.finalize_pause.load(Ordering::Acquire) {
                            std::thread::yield_now();
                        }
                        self.finalize_entered.store(false, Ordering::Release);
                    }
                    let effects = self.handle.block_on(self.runtime.finalize_inbound(core))?;
                    for effect in effects {
                        if matches!(effect, TransferRuntimeEffect::Completed { .. }) {
                            // Durable publication has already succeeded. Commit
                            // the process tombstone and public terminal state
                            // before returning to the STOP-preemptible loop.
                            self.apply_effect(effect)?;
                        } else {
                            self.pending_effects.push_back(effect);
                        }
                    }
                } else {
                    match self.store.registry.phase(binding.public_id) {
                        Some(TransferPhase::CancelRequested) => {
                            self.cancel_inbound_binding(binding)?;
                        }
                        Some(TransferPhase::Cancelled) => {}
                        _ => return Err(TransferRuntimeError::Protocol),
                    }
                }
            }
            TransferRuntimeEffect::Completed { transfer } => {
                let core = TransferId::from_bytes(*transfer.as_bytes());
                let binding = self
                    .store
                    .registry
                    .binding_for_wire(self.peer, TransferDirection::Inbound, core)
                    .ok_or(TransferRuntimeError::Protocol)?;
                if matches!(
                    self.store.registry.phase(binding.public_id),
                    Some(TransferPhase::Cancelled | TransferPhase::Failed)
                ) {
                    return Ok(());
                }
                self.store.remember_completed(self.peer, core)?;
                self.runtime.remember_completed_inbound(&[core])?;
                self.store.forget_inbound(self.peer, core);
                self.runtime.remove_terminal(transfer)?;
                if !self.store.registry.complete(binding.public_id) {
                    return Err(TransferRuntimeError::Protocol);
                }
                let payload = self.runtime.encode_complete_ack_frame(transfer)?;
                self.send_manifest(payload, None)?;
            }
            TransferRuntimeEffect::PeerCompleteAcknowledged { transfer } => {
                let core = TransferId::from_bytes(*transfer.as_bytes());
                if self.store.is_cancelled_outbound(self.peer, core) {
                    return Ok(());
                }
                let binding = self
                    .store
                    .registry
                    .binding_for_wire(self.peer, TransferDirection::Outbound, core)
                    .ok_or(TransferRuntimeError::Protocol)?;
                let completion_won = self.store.registry.complete(binding.public_id);
                if !self.remove_outbound(core) {
                    return Err(TransferRuntimeError::Protocol);
                }
                self.store.remember_cancelled_outbound(self.peer, core)?;
                self.runtime.remember_cancelled_outbound(&[core])?;
                if !completion_won {
                    self.store.registry.cancelled(binding.public_id);
                }
            }
            TransferRuntimeEffect::PeerCancelRequested { transfer } => {
                let core = TransferId::from_bytes(*transfer.as_bytes());
                if self.store.is_cancelled_outbound(self.peer, core) {
                    return Ok(());
                }
                let binding = self
                    .store
                    .registry
                    .binding_for_wire(self.peer, TransferDirection::Outbound, core)
                    .ok_or(TransferRuntimeError::Protocol)?;
                if !self.remove_outbound(core) {
                    return Err(TransferRuntimeError::Protocol);
                }
                self.store.remember_cancelled_outbound(self.peer, core)?;
                self.runtime.remember_cancelled_outbound(&[core])?;
                self.store.registry.cancelled(binding.public_id);
            }
            TransferRuntimeEffect::CompletionAcknowledgementRequired { transfer } => {
                let payload = self.runtime.encode_complete_ack_frame(transfer)?;
                self.send_manifest(payload, None)?;
            }
            TransferRuntimeEffect::RejectionAcknowledgementRequired { transfer } => {
                let payload = self.runtime.encode_cancel_frame(transfer, 0)?;
                self.send_manifest(payload, None)?;
            }
            TransferRuntimeEffect::PeerResumeRequested {
                transfer,
                entry_index,
                offset,
            } => {
                let core = TransferId::from_bytes(*transfer.as_bytes());
                if !self.store.is_cancelled_outbound(self.peer, core) {
                    self.handle_peer_resume(transfer, entry_index, offset)?;
                }
            }
            TransferRuntimeEffect::ResumeRequired {
                transfer,
                entry_index,
                offset,
            } => {
                let core = TransferId::from_bytes(*transfer.as_bytes());
                if self.rejected_inbound.contains(&core)
                    || self
                        .store
                        .registry
                        .binding_for_wire(self.peer, TransferDirection::Inbound, core)
                        .is_some_and(|binding| {
                            self.store
                                .registry
                                .phase(binding.public_id)
                                .is_some_and(TransferPhase::is_terminal)
                        })
                {
                    return Ok(());
                }
                let payload = self
                    .runtime
                    .encode_resume_frame(transfer, entry_index, offset)?;
                self.send_manifest(payload, None)?;
            }
            TransferRuntimeEffect::QueueSaturated { transfer } => {
                let core = TransferId::from_bytes(*transfer.as_bytes());
                self.store.remember_cancelled_inbound(self.peer, core)?;
                self.remember_worker_rejection(core)?;
                let payload = self.runtime.encode_cancel_frame(transfer, 1)?;
                self.send_manifest(payload, None)?;
            }
            TransferRuntimeEffect::Cancelled { transfer } => {
                let core = TransferId::from_bytes(*transfer.as_bytes());
                if let Some(binding) = self.store.registry.binding_for_wire(
                    self.peer,
                    TransferDirection::Inbound,
                    core,
                ) {
                    self.store.registry.cancelled(binding.public_id);
                }
                self.store.remember_cancelled_inbound(self.peer, core)?;
                self.runtime.remember_rejected_inbound(&[core])?;
                self.store.forget_inbound(self.peer, core);
            }
            TransferRuntimeEffect::Started { transfer } => {
                let core = TransferId::from_bytes(*transfer.as_bytes());
                if self.rejected_inbound.contains(&core) {
                    return Ok(());
                }
                if self
                    .store
                    .registry
                    .binding_for_wire(self.peer, TransferDirection::Inbound, core)
                    .is_some_and(|binding| {
                        self.store
                            .registry
                            .phase(binding.public_id)
                            .is_some_and(TransferPhase::is_terminal)
                    })
                {
                    return Ok(());
                }
                let (active, processed_bytes, total_bytes) = self
                    .runtime
                    .active_inbound_progress()
                    .ok_or(TransferRuntimeError::Protocol)?;
                if active != core {
                    return Err(TransferRuntimeError::Protocol);
                }
                match self.store.registry.update_inbound(
                    self.peer,
                    core,
                    processed_bytes,
                    total_bytes,
                    TransferPhase::Transferring,
                ) {
                    InboundUpdate::Updated(_) => {}
                    InboundUpdate::Terminal(_) => return Ok(()),
                    InboundUpdate::Unknown => return Err(TransferRuntimeError::Protocol),
                }
                self.store.remember_inbound(self.peer, core)?;
            }
            TransferRuntimeEffect::Progress {
                transfer,
                completed_bytes,
                total_bytes,
            } => {
                let core = TransferId::from_bytes(*transfer.as_bytes());
                if self.rejected_inbound.contains(&core) {
                    return Ok(());
                }
                match self.store.registry.update_inbound(
                    self.peer,
                    core,
                    completed_bytes,
                    total_bytes,
                    TransferPhase::Transferring,
                ) {
                    InboundUpdate::Updated(_) => {}
                    InboundUpdate::Terminal(_) => return Ok(()),
                    InboundUpdate::Unknown => return Err(TransferRuntimeError::Protocol),
                }
            }
            TransferRuntimeEffect::Backpressured { .. }
            | TransferRuntimeEffect::BackpressureReleased { .. } => {}
        }
        Ok(())
    }

    fn reject_inbound(
        &mut self,
        transfer: TransferId,
        reason: u16,
    ) -> Result<(), TransferRuntimeError> {
        self.store.remember_cancelled_inbound(self.peer, transfer)?;
        self.runtime.remember_rejected_inbound(&[transfer])?;
        self.remember_worker_rejection(transfer)?;
        let effects = self
            .handle
            .block_on(self.runtime.cancel_inbound(transfer))?;
        for effect in effects {
            self.apply_effect(effect)?;
        }
        let payload = self
            .runtime
            .encode_cancel_frame(WireTransferId::new(transfer.as_bytes()), reason)?;
        self.send_manifest(payload, None)
    }

    fn remember_worker_rejection(
        &mut self,
        transfer: TransferId,
    ) -> Result<(), TransferRuntimeError> {
        if self.rejected_inbound.contains(&transfer) {
            return Ok(());
        }
        if self.rejected_inbound.len() >= MAX_RETAINED_WIRE_IDENTITIES {
            return Err(TransferRuntimeError::Backpressure);
        }
        self.rejected_inbound.insert(transfer);
        Ok(())
    }

    fn handle_targeted_inbound_cancel(&mut self) -> Result<(), TransferRuntimeError> {
        let Some(binding) = self
            .store
            .registry
            .cancellation_for_peer(self.peer, TransferDirection::Inbound)
        else {
            return Ok(());
        };
        if !self.runtime.has_inbound_transfer(binding.wire_id) {
            return Ok(());
        }
        self.cancel_inbound_binding(binding)
    }

    fn cancel_inbound_binding(
        &mut self,
        binding: crate::transfer_status::TransferBinding,
    ) -> Result<(), TransferRuntimeError> {
        let effects = self
            .handle
            .block_on(self.runtime.cancel_inbound(binding.wire_id))?;
        for effect in effects {
            self.apply_effect(effect)?;
        }
        let payload = self
            .runtime
            .encode_cancel_frame(WireTransferId::new(binding.wire_id.as_bytes()), 0)?;
        self.send_manifest(payload, None)
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
        let processed_bytes = entries.iter().zip(&pending.resume_offsets).try_fold(
            0_u64,
            |processed, (entry, offset)| {
                processed
                    .checked_add(match entry.kind {
                        EntryKind::File => offset.ok_or(TransferRuntimeError::Protocol)?,
                        EntryKind::Directory => 0,
                    })
                    .ok_or(TransferRuntimeError::Protocol)
            },
        )?;
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
        let public_id = pending.public_id;
        pending.ready = true;
        drop(inner);
        self.store
            .registry
            .resume_progress(public_id, processed_bytes);
        Ok(())
    }

    fn pump_outbound(&mut self) -> Result<(), TransferRuntimeError> {
        let cancelled = {
            let inner = self
                .store
                .inner
                .lock()
                .expect("transfer store mutex poisoned");
            inner.outbound.get(&self.peer).and_then(|transfers| {
                transfers.iter().find_map(|(wire_id, pending)| {
                    TransferRegistry::cancellation_requested(&pending.cancellation)
                        .then_some((*wire_id, pending.public_id))
                })
            })
        };
        if let Some((wire_id, public_id)) = cancelled {
            let payload = self.runtime.encode_outbound_cancel_frame(wire_id, 0)?;
            if !self.remove_outbound(wire_id) {
                return Err(TransferRuntimeError::Protocol);
            }
            self.store.remember_cancelled_outbound(self.peer, wire_id)?;
            self.runtime.remember_cancelled_outbound(&[wire_id])?;
            self.store.registry.cancelled(public_id);
            self.events
                .blocking_send(TransferWorkerEvent::SendManifest {
                    payload,
                    update: None,
                })
                .map_err(|_| TransferRuntimeError::Backpressure)?;
            return Ok(());
        }
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
                let processed_bytes = aggregate_processed(&pending.source, &chunk)?;
                Some((
                    self.runtime.encode_data_frame(&chunk)?,
                    false,
                    pending.public_id,
                    processed_bytes,
                ))
            } else {
                pending.ready = false;
                pending.awaiting_completion_ack = true;
                Some((
                    self.runtime.encode_complete_frame(*transfer)?,
                    true,
                    pending.public_id,
                    pending.source.manifest().total_bytes(),
                ))
            }
        };
        if let Some((payload, complete, public_id, processed_bytes)) = outcome {
            if complete {
                self.send_manifest(payload, Some(ReliableSendUpdate::Finalizing { public_id }))?;
            } else {
                self.events
                    .blocking_send(TransferWorkerEvent::SendData {
                        payload,
                        update: ReliableSendUpdate::Data {
                            public_id,
                            processed_bytes,
                        },
                    })
                    .map_err(|_| TransferRuntimeError::Backpressure)?;
            }
        }
        Ok(())
    }

    fn send_manifest(
        &self,
        payload: Vec<u8>,
        update: Option<ReliableSendUpdate>,
    ) -> Result<(), TransferRuntimeError> {
        self.events
            .blocking_send(TransferWorkerEvent::SendManifest { payload, update })
            .map_err(|_| TransferRuntimeError::Backpressure)
    }

    fn remove_outbound(&self, transfer: TransferId) -> bool {
        self.store.remove_outbound(self.peer, transfer)
    }

    fn cleanup(&mut self) {
        self.store.registry.pause_peer(self.peer);
        while let Ok(command) = self.commands.try_recv() {
            if let WorkerCommand::StartOutbound { admission, .. } = command {
                self.store.release_outbound();
                self.store.registry.cancelled(admission.binding.public_id);
            }
        }
        if let Some(binding) = self
            .store
            .registry
            .cancellation_for_peer(self.peer, TransferDirection::Inbound)
            && self.runtime.has_inbound_transfer(binding.wire_id)
        {
            if let Ok(effects) = self
                .handle
                .block_on(self.runtime.cancel_inbound(binding.wire_id))
            {
                for effect in effects {
                    if self.apply_effect(effect).is_err() {
                        self.store.poison();
                        self.store
                            .registry
                            .cleanup_failed(self.peer, TransferDirection::Inbound);
                        break;
                    }
                }
            } else {
                self.store.poison();
                self.store
                    .registry
                    .cleanup_failed(self.peer, TransferDirection::Inbound);
            }
        }
        let cancelled_outbound = {
            let inner = self
                .store
                .inner
                .lock()
                .expect("transfer store mutex poisoned");
            inner
                .outbound
                .get(&self.peer)
                .map(|transfers| {
                    transfers
                        .iter()
                        .filter_map(|(wire_id, pending)| {
                            TransferRegistry::cancellation_requested(&pending.cancellation)
                                .then_some((*wire_id, pending.public_id))
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        };
        for (wire_id, public_id) in cancelled_outbound {
            self.remove_outbound(wire_id);
            if self
                .store
                .remember_cancelled_outbound(self.peer, wire_id)
                .is_err()
                || self
                    .runtime
                    .remember_cancelled_outbound(&[wire_id])
                    .is_err()
            {
                self.store.poison();
                self.store
                    .registry
                    .cleanup_failed(self.peer, TransferDirection::Outbound);
                break;
            }
            self.store.registry.cancelled(public_id);
        }
        let mode = self.stop.load(Ordering::Acquire);
        if mode & ABORT_INBOUND != 0 {
            self.store.require_peer_inbound_discard(self.peer);
            if let Some(transfer) = self.runtime.active_inbound_transfer() {
                self.store.require_inbound_discard(self.peer, transfer);
            }
            if let Ok(effects) = self.runtime.abort_inbound() {
                for effect in effects {
                    if self.apply_effect(effect).is_err() {
                        self.store.poison();
                        self.store
                            .registry
                            .fail_peer(self.peer, TransferFailureCode::CleanupFailed);
                        break;
                    }
                }
            } else {
                self.store.poison();
                self.store
                    .registry
                    .fail_peer(self.peer, TransferFailureCode::CleanupFailed);
            }
        }
        if mode & ABORT_OUTBOUND != 0 {
            self.store.purge_outbound(self.peer);
        }
    }

    fn fail(&mut self, error: TransferRuntimeError) {
        let cleanup_failed = matches!(
            error,
            TransferRuntimeError::Transfer(TransferError::Platform)
        );
        if cleanup_failed {
            self.store.poison();
        }
        self.store.registry.fail_peer(
            self.peer,
            if cleanup_failed {
                TransferFailureCode::CleanupFailed
            } else {
                TransferFailureCode::Internal
            },
        );
        self.stop
            .fetch_or(TransferStopMode::AbortAll.bits(), Ordering::AcqRel);
        self.cleanup();
        let _ = self.events.blocking_send(TransferWorkerEvent::Fatal(error));
    }
}

fn aggregate_processed(
    source: &OutboundTransferSource,
    chunk: &nodavo_transfer::TransferChunk,
) -> Result<u64, TransferRuntimeError> {
    let index = usize::try_from(chunk.entry_index).map_err(|_| TransferRuntimeError::Protocol)?;
    let entries = source.manifest().entries();
    let entry = entries.get(index).ok_or(TransferRuntimeError::Protocol)?;
    if entry.kind != EntryKind::File {
        return Err(TransferRuntimeError::Protocol);
    }
    let before = entries[..index].iter().try_fold(0_u64, |sum, entry| {
        sum.checked_add(match entry.kind {
            EntryKind::File => entry.size,
            EntryKind::Directory => 0,
        })
        .ok_or(TransferRuntimeError::Protocol)
    })?;
    let length = u64::try_from(chunk.bytes.len()).map_err(|_| TransferRuntimeError::Protocol)?;
    before
        .checked_add(chunk.offset)
        .and_then(|processed| processed.checked_add(length))
        .filter(|processed| *processed <= source.manifest().total_bytes())
        .ok_or(TransferRuntimeError::Protocol)
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
            .register_staging_root(PEER, staging_root.to_path_buf())
            .unwrap();
        let staging = FileSystemStagingArea::new_scoped(staging_root, *PEER.as_bytes()).unwrap();
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
        .unwrap()
    }

    async fn next_event(worker: &mut TransferWorker) -> TransferWorkerEvent {
        timeout(Duration::from_secs(2), worker.next_event())
            .await
            .unwrap()
            .unwrap()
    }

    fn indexed_transfer(index: usize) -> TransferId {
        let mut bytes = [0_u8; 16];
        bytes[..8].copy_from_slice(&u64::try_from(index + 1).unwrap().to_le_bytes());
        TransferId::from_bytes(bytes)
    }

    #[test]
    fn retained_wire_ledger_is_hard_bounded_and_duplicates_work_at_capacity() {
        let store = TransferStore::default();
        for index in 0..MAX_RETAINED_WIRE_IDENTITIES {
            let transfer = indexed_transfer(index);
            match index % 3 {
                0 => store.remember_completed(PEER, transfer).unwrap(),
                1 => store.remember_cancelled_inbound(PEER, transfer).unwrap(),
                _ => store.remember_cancelled_outbound(PEER, transfer).unwrap(),
            }
        }
        assert_eq!(
            store.inner.lock().unwrap().retained_wire.len(),
            MAX_RETAINED_WIRE_IDENTITIES
        );
        store.remember_completed(PEER, indexed_transfer(0)).unwrap();
        store
            .remember_cancelled_inbound(PEER, indexed_transfer(1))
            .unwrap();
        store
            .remember_cancelled_outbound(PEER, indexed_transfer(2))
            .unwrap();
        assert_eq!(
            store
                .remember_cancelled_inbound(PEER, indexed_transfer(MAX_RETAINED_WIRE_IDENTITIES),)
                .unwrap_err(),
            TransferError::QueueFull
        );
        assert_eq!(
            store.inner.lock().unwrap().retained_wire.len(),
            MAX_RETAINED_WIRE_IDENTITIES
        );
        assert_eq!(
            store.completed_for(PEER).len()
                + store.cancelled_for(PEER).len()
                + store.cancelled_outbound_for(PEER).len(),
            MAX_RETAINED_WIRE_IDENTITIES
        );
    }

    #[test]
    fn cleanup_reservation_survives_concurrent_capacity_consumption() {
        let mut inner = StoreInner::default();
        for index in 0..MAX_RETAINED_WIRE_IDENTITIES - 2 {
            transition_retained_locked(
                &mut inner,
                retained_key(LOCAL, TransferDirection::Outbound, indexed_transfer(index)),
                RetainedWireState::RetiredOutbound,
            )
            .unwrap();
        }
        let cleanup_key = retained_key(
            PEER,
            TransferDirection::Inbound,
            indexed_transfer(MAX_RETAINED_WIRE_IDENTITIES),
        );
        reserve_retained_keys_locked(&mut inner, &[cleanup_key]).unwrap();

        transition_retained_locked(
            &mut inner,
            retained_key(
                LOCAL,
                TransferDirection::Inbound,
                indexed_transfer(MAX_RETAINED_WIRE_IDENTITIES + 1),
            ),
            RetainedWireState::RejectedInbound,
        )
        .unwrap();
        assert_eq!(inner.retained_wire.len(), MAX_RETAINED_WIRE_IDENTITIES);
        assert!(transition_reserved_locked(
            &mut inner,
            cleanup_key,
            RetainedWireState::RejectedInbound,
        ));
        assert_eq!(
            inner.retained_wire.get(&cleanup_key),
            Some(&RetainedWireState::RejectedInbound)
        );
        assert_eq!(
            transition_retained_locked(
                &mut inner,
                retained_key(
                    PEER,
                    TransferDirection::Inbound,
                    indexed_transfer(MAX_RETAINED_WIRE_IDENTITIES + 2),
                ),
                RetainedWireState::RejectedInbound,
            ),
            Err(TransferError::QueueFull)
        );
    }

    #[test]
    fn retention_backpressure_rolls_back_outbound_rows_and_slots_but_burns_ids() {
        let store = TransferStore::default();
        for index in 0..MAX_RETAINED_WIRE_IDENTITIES {
            store
                .transition_retained(
                    LOCAL,
                    TransferDirection::Outbound,
                    indexed_transfer(index),
                    RetainedWireState::RetiredOutbound,
                )
                .unwrap();
        }

        for _ in 0..MAX_LIFETIME_TRANSFER_IDENTITIES {
            assert_eq!(
                store.admit_outbound(PEER).err().unwrap(),
                TransferError::QueueFull
            );
            assert_eq!(store.outbound_count(), 0);
            assert!(store.transfer_listing().transfers.is_empty());
        }
        assert_eq!(
            store.admit_outbound(PEER).err().unwrap(),
            TransferError::QueueFull
        );
        assert_eq!(
            store.registry.admit_outbound(PEER).err(),
            Some(TransferRegistryError::LifetimeFull)
        );
        assert_eq!(
            store.inner.lock().unwrap().retained_wire.len(),
            MAX_RETAINED_WIRE_IDENTITIES
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn reconnect_retains_oldest_completion_beyond_legacy_fifo() {
        let _guard = FILE_TEST_LOCK.lock().await;
        let staging_root = temporary_directory("staging-long-completion-ledger");
        let store = TransferStore::default();
        let oldest = indexed_transfer(0);
        for index in 0..65 {
            let transfer = indexed_transfer(index);
            store
                .reserve_retained(PEER, TransferDirection::Inbound, transfer)
                .unwrap();
            store.remember_completed(PEER, transfer).unwrap();
        }

        let session = SessionId::new([72; 16]);
        let mut worker = worker(store.clone(), session, &staging_root);
        let wire = WireTransferId::new(oldest.as_bytes());
        worker
            .try_receive_data(inbound_data_frame(session, wire, b"late"))
            .unwrap();
        worker
            .try_receive_manifest(inbound_manifest_frame(session, wire, b"late"))
            .unwrap();
        let TransferWorkerEvent::SendManifest { payload, .. } = next_event(&mut worker).await
        else {
            panic!("old completed wire identity must be re-acknowledged");
        };
        assert!(matches!(
            decode_file_manifest(&payload).unwrap(),
            FileManifestMessage::Complete { transfer, .. } if transfer == wire
        ));
        assert_eq!(store.completed_for(PEER).len(), 65);
        worker.stop(TransferStopMode::AbortAll);
        drop(worker);
        fs::remove_dir_all(staging_root).unwrap();
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

    fn complete_response_frame(
        session: SessionId,
        sequence: u64,
        transfer: WireTransferId,
    ) -> Vec<u8> {
        encode_file_manifest(&FileManifestMessage::Complete {
            meta: EventMeta::new(
                session,
                PEER,
                Sequence::new(sequence),
                PEER_EPOCH,
                Capability::FILE_TRANSFER,
            ),
            transfer,
        })
        .unwrap()
    }

    fn cancel_response_frame(
        session: SessionId,
        sequence: u64,
        transfer: WireTransferId,
    ) -> Vec<u8> {
        encode_file_manifest(&FileManifestMessage::Cancel {
            meta: EventMeta::new(
                session,
                PEER,
                Sequence::new(sequence),
                PEER_EPOCH,
                Capability::FILE_TRANSFER,
            ),
            transfer,
            reason: 0,
        })
        .unwrap()
    }

    fn inbound_complete_frame(
        session: SessionId,
        sequence: u64,
        transfer: WireTransferId,
    ) -> Vec<u8> {
        encode_file_manifest(&FileManifestMessage::Complete {
            meta: EventMeta::new(
                session,
                PEER,
                Sequence::new(sequence),
                LOCAL_EPOCH,
                Capability::FILE_TRANSFER,
            ),
            transfer,
        })
        .unwrap()
    }

    fn inbound_manifest_frame(
        session: SessionId,
        transfer: WireTransferId,
        payload: &[u8],
    ) -> Vec<u8> {
        inbound_manifest_frame_at(session, 1, transfer, payload)
    }

    fn inbound_manifest_frame_at(
        session: SessionId,
        sequence: u64,
        transfer: WireTransferId,
        payload: &[u8],
    ) -> Vec<u8> {
        encode_file_manifest(&FileManifestMessage::Manifest {
            meta: EventMeta::new(
                session,
                PEER,
                Sequence::new(sequence),
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
        store.remember_inbound(PEER, transfer).unwrap();
        store.require_peer_inbound_discard(PEER);
        assert_eq!(
            store.cleanup_peer_if_idle(PEER),
            Err(TransferError::Platform)
        );
        assert!(store.is_poisoned());
        assert_eq!(store.reserve_outbound(), Err(TransferError::Platform));
    }

    #[test]
    fn global_cleanup_enrollment_waits_for_late_worker_publication() {
        let store = TransferStore::default();
        let transfer = TransferId::from_bytes([32; 16]);
        store.worker_started(PEER).unwrap();
        assert_eq!(store.require_all_inbound_discard_if_idle(), None);

        // A live worker may publish Started after safety shutdown begins.
        store.remember_inbound(PEER, transfer).unwrap();
        assert_eq!(store.require_all_inbound_discard_if_idle(), None);
        store
            .inner
            .lock()
            .expect("transfer store mutex poisoned")
            .active_workers = 0;

        assert_eq!(
            store.require_all_inbound_discard_if_idle(),
            Some(vec![PEER])
        );
        assert!(
            store
                .inner
                .lock()
                .expect("transfer store mutex poisoned")
                .discard_required
                .get(&PEER)
                .is_some_and(|transfers| transfers.contains(&transfer))
        );
    }

    #[test]
    fn global_cleanup_barrier_rejects_post_enrollment_worker() {
        let store = TransferStore::default();
        store.close_worker_admission_for_safety();

        assert_eq!(
            store.require_all_inbound_discard_if_idle(),
            Some(Vec::new())
        );
        assert_eq!(
            store.worker_started(PEER),
            Err(TransferWorkerAdmissionClosed)
        );

        store.reopen_worker_admission_after_safety();
        assert_eq!(store.worker_started(PEER), Ok(()));
        store.worker_finished(PEER);
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
        let public_transfer = timeout(Duration::from_secs(2), acknowledged)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        timeout(Duration::from_secs(2), async {
            while !worker.scan_is_active() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        worker.stop(TransferStopMode::Suspend);
        drop(worker);
        wait_until_worker_releases_store(&store).await;
        assert_eq!(store.outbound_count(), 0);
        let listing = store.transfer_listing();
        assert!(listing.transfers.iter().any(|snapshot| {
            snapshot.transfer_id() == public_transfer.as_uuid().hyphenated().to_string()
                && snapshot.phase() == TransferPhase::Cancelled
        }));
        fs::remove_dir_all(source_root).unwrap();
        fs::remove_dir_all(staging_root).unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    #[allow(
        clippy::too_many_lines,
        reason = "the reconnect regression proves one continuous public-ID lifecycle"
    )]
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
        let TransferWorkerEvent::SendManifest {
            payload: first_manifest,
            ..
        } = next_event(&mut first).await
        else {
            panic!("expected initial manifest");
        };
        let FileManifestMessage::Manifest {
            transfer: wire_transfer,
            ..
        } = decode_file_manifest(&first_manifest).unwrap()
        else {
            panic!("expected initial manifest message");
        };
        assert_ne!(wire_transfer.as_bytes(), &transfer.as_bytes());

        first
            .try_receive_manifest(resume_frame(first_session, 1, wire_transfer, 0, 0))
            .unwrap();
        first.try_pump().unwrap();
        let TransferWorkerEvent::SendData {
            payload: first_data,
            update: first_update,
        } = next_event(&mut first).await
        else {
            panic!("expected first data chunk");
        };
        let FileDataMessage::Chunk { offset, .. } = decode_file_data(&first_data).unwrap() else {
            panic!("expected first data chunk message");
        };
        assert_eq!(offset, 0);
        let public_id = transfer.as_uuid().hyphenated().to_string();
        assert_eq!(
            store
                .transfer_listing()
                .transfers
                .iter()
                .find(|snapshot| snapshot.transfer_id() == public_id)
                .unwrap()
                .processed_bytes(),
            Some(0),
            "reading a source chunk must not advance public progress"
        );
        first.reliable_send_succeeded(first_update);
        assert!(
            store
                .transfer_listing()
                .transfers
                .iter()
                .find(|snapshot| snapshot.transfer_id() == public_id)
                .unwrap()
                .processed_bytes()
                .unwrap()
                > 0
        );

        first.stop(TransferStopMode::Suspend);
        drop(first);
        tokio::time::sleep(Duration::from_millis(20)).await;
        let paused = store.transfer_listing();
        let paused = paused
            .transfers
            .iter()
            .find(|snapshot| snapshot.transfer_id() == public_id)
            .unwrap();
        assert_eq!(paused.phase(), TransferPhase::Paused);

        let second_session = SessionId::new([4; 16]);
        let mut second = worker(store.clone(), second_session, &staging_root);
        let TransferWorkerEvent::SendManifest {
            payload: second_manifest,
            ..
        } = next_event(&mut second).await
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
        assert!(
            store
                .transfer_listing()
                .transfers
                .iter()
                .any(|snapshot| snapshot.transfer_id() == public_id)
        );

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
        let TransferWorkerEvent::SendData {
            payload: resumed_data,
            ..
        } = next_event(&mut second).await
        else {
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
    #[allow(
        clippy::too_many_lines,
        reason = "the full completion and late-response interleaving is intentionally explicit"
    )]
    async fn completed_outbound_absorbs_late_responses_and_zero_byte_resume() {
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
        let public_transfer = acknowledged.await.unwrap().unwrap();
        let TransferWorkerEvent::SendManifest {
            payload: manifest_frame,
            ..
        } = next_event(&mut worker).await
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
        assert_ne!(wire_transfer.as_bytes(), &public_transfer.as_bytes());
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
        let TransferWorkerEvent::SendManifest {
            payload: complete_frame,
            ..
        } = next_event(&mut worker).await
        else {
            panic!("all-complete resume must not restart source data");
        };
        assert!(matches!(
            decode_file_manifest(&complete_frame).unwrap(),
            FileManifestMessage::Complete { transfer, .. } if transfer == wire_transfer
        ));

        let completion_sequence = u64::try_from(entries.len() + 1).unwrap();
        worker
            .try_receive_manifest(complete_response_frame(
                session,
                completion_sequence,
                wire_transfer,
            ))
            .unwrap();
        worker
            .try_receive_manifest(resume_frame(
                session,
                completion_sequence + 1,
                wire_transfer,
                0,
                0,
            ))
            .unwrap();
        worker
            .try_receive_manifest(complete_response_frame(
                session,
                completion_sequence + 2,
                wire_transfer,
            ))
            .unwrap();
        worker
            .try_receive_manifest(cancel_response_frame(
                session,
                completion_sequence + 3,
                wire_transfer,
            ))
            .unwrap();

        let second = source_root.join("second.bin");
        fs::write(&second, b"still alive").unwrap();
        let (acknowledgement, acknowledged) = oneshot::channel();
        worker.try_start_outbound(vec![second], acknowledgement);
        acknowledged.await.unwrap().unwrap();
        assert!(matches!(
            next_event(&mut worker).await,
            TransferWorkerEvent::SendManifest { .. }
        ));
        assert_eq!(
            store.registry.phase(public_transfer.as_uuid()),
            Some(TransferPhase::Completed)
        );
        assert!(!store.is_poisoned());

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
            TransferWorkerEvent::SendManifest { .. }
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
    async fn targeted_inbound_cancel_confirms_cleanup_before_cancelled() {
        let _guard = FILE_TEST_LOCK.lock().await;
        let staging_root = temporary_directory("staging-targeted-inbound-cancel");
        let store = TransferStore::default();
        let session = SessionId::new([12; 16]);
        let wire = WireTransferId::new([41; 16]);
        let payload = b"durable inbound cancellation";
        let mut first_worker = worker(store.clone(), session, &staging_root);
        first_worker
            .try_receive_manifest(inbound_manifest_frame(session, wire, payload))
            .unwrap();
        assert!(matches!(
            next_event(&mut first_worker).await,
            TransferWorkerEvent::SendManifest { .. }
        ));
        first_worker
            .try_receive_data(inbound_data_frame(session, wire, &payload[..8]))
            .unwrap();
        timeout(Duration::from_secs(2), async {
            loop {
                if store
                    .transfer_listing()
                    .transfers
                    .first()
                    .is_some_and(|snapshot| snapshot.processed_bytes() == Some(8))
                {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let public_id = store.transfer_listing().transfers[0]
            .transfer_id()
            .to_owned();
        let requested = store.request_cancel(&public_id).unwrap();
        assert_eq!(
            requested.listing.transfers[0].phase(),
            TransferPhase::CancelRequested
        );
        first_worker.try_wake_cancellation().unwrap();
        let TransferWorkerEvent::SendManifest {
            payload: cancel_frame,
            ..
        } = next_event(&mut first_worker).await
        else {
            panic!("targeted cancellation must notify the authenticated peer");
        };
        assert!(matches!(
            decode_file_manifest(&cancel_frame).unwrap(),
            FileManifestMessage::Cancel { transfer, .. } if transfer == wire
        ));
        let cancelled = store.transfer_listing();
        assert_eq!(cancelled.transfers[0].phase(), TransferPhase::Cancelled);
        let staging = FileSystemStagingArea::new_scoped(&staging_root, *PEER.as_bytes()).unwrap();
        assert!(
            !staging
                .has_persisted(TransferId::from_bytes(*wire.as_bytes()))
                .unwrap()
        );
        assert!(!store.is_poisoned());
        first_worker.stop(TransferStopMode::Suspend);
        drop(first_worker);

        wait_until_worker_releases_store(&store).await;
        let second_session = SessionId::new([15; 16]);
        let mut second = worker(store.clone(), second_session, &staging_root);
        second
            .try_receive_manifest(inbound_manifest_frame(second_session, wire, payload))
            .unwrap();
        let TransferWorkerEvent::SendManifest { payload, .. } = next_event(&mut second).await
        else {
            panic!("cancelled inbound reannounce must be rejected");
        };
        assert!(matches!(
            decode_file_manifest(&payload).unwrap(),
            FileManifestMessage::Cancel { transfer, .. } if transfer == wire
        ));
        assert_eq!(store.transfer_listing().transfers.len(), 1);
        assert_eq!(
            store.transfer_listing().transfers[0].transfer_id(),
            public_id
        );
        second.stop(TransferStopMode::Suspend);
        drop(second);
        fs::remove_dir_all(staging_root).unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn stop_during_durable_finalize_cannot_preempt_earned_completion() {
        let _guard = FILE_TEST_LOCK.lock().await;
        let staging_root = temporary_directory("staging-stop-during-finalize");
        let store = TransferStore::default();
        let session = SessionId::new([19; 16]);
        let wire = WireTransferId::new([64; 16]);
        let payload = b"durably published before stop";
        let mut first = worker(store.clone(), session, &staging_root);
        first
            .try_receive_manifest(inbound_manifest_frame(session, wire, payload))
            .unwrap();
        assert!(matches!(
            next_event(&mut first).await,
            TransferWorkerEvent::SendManifest { .. }
        ));
        first
            .try_receive_data(inbound_data_frame(session, wire, payload))
            .unwrap();
        first.pause_finalize_for_test();
        first
            .try_receive_manifest(inbound_complete_frame(session, 2, wire))
            .unwrap();
        timeout(Duration::from_secs(2), async {
            while !first.finalize_is_paused() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        first.stop(TransferStopMode::Suspend);
        first.release_finalize_for_test();

        let TransferWorkerEvent::SendManifest { payload: ack, .. } = next_event(&mut first).await
        else {
            panic!("earned completion must queue its acknowledgement");
        };
        assert!(matches!(
            decode_file_manifest(&ack).unwrap(),
            FileManifestMessage::Complete { transfer, .. } if transfer == wire
        ));
        let completed = store.transfer_listing();
        assert_eq!(completed.transfers.len(), 1);
        assert_eq!(completed.transfers[0].phase(), TransferPhase::Completed);
        assert_eq!(
            fs::read(staging_root.join("received.bin")).unwrap(),
            payload
        );
        let public_id = completed.transfers[0].transfer_id().to_owned();
        let terminal_cancel = store.request_cancel(&public_id).unwrap();
        assert!(terminal_cancel.target.is_none());
        assert_eq!(terminal_cancel.listing, completed);
        drop(first);
        wait_until_worker_releases_store(&store).await;

        let reconnect_session = SessionId::new([20; 16]);
        let mut reconnect = worker(store.clone(), reconnect_session, &staging_root);
        reconnect
            .try_receive_manifest(inbound_manifest_frame(reconnect_session, wire, payload))
            .unwrap();
        let TransferWorkerEvent::SendManifest { payload: ack, .. } =
            next_event(&mut reconnect).await
        else {
            panic!("reconnect must re-acknowledge the earned completion");
        };
        assert!(matches!(
            decode_file_manifest(&ack).unwrap(),
            FileManifestMessage::Complete { transfer, .. } if transfer == wire
        ));
        assert_eq!(store.transfer_listing().transfers.len(), 1);
        assert_eq!(
            store.transfer_listing().transfers[0].phase(),
            TransferPhase::Completed
        );
        reconnect.stop(TransferStopMode::Suspend);
        drop(reconnect);
        fs::remove_dir_all(staging_root).unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn queued_inbound_is_listed_and_targeted_cancel_does_not_affect_active() {
        let _guard = FILE_TEST_LOCK.lock().await;
        let staging_root = temporary_directory("staging-queued-inbound-cancel");
        let store = TransferStore::default();
        let session = SessionId::new([16; 16]);
        let first = WireTransferId::new([61; 16]);
        let second = WireTransferId::new([62; 16]);
        let mut worker = worker(store.clone(), session, &staging_root);
        worker
            .try_receive_manifest(inbound_manifest_frame_at(session, 1, first, b"a"))
            .unwrap();
        assert!(matches!(
            next_event(&mut worker).await,
            TransferWorkerEvent::SendManifest { .. }
        ));
        worker
            .try_receive_manifest(inbound_manifest_frame_at(session, 2, second, b"b"))
            .unwrap();
        timeout(Duration::from_secs(2), async {
            while store.transfer_listing().transfers.len() != 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let second_binding = store
            .registry
            .binding_for_wire(
                PEER,
                TransferDirection::Inbound,
                TransferId::from_bytes(*second.as_bytes()),
            )
            .unwrap();
        let listing = store.transfer_listing();
        assert_eq!(
            listing
                .transfers
                .iter()
                .find(|snapshot| {
                    snapshot.transfer_id() == second_binding.public_id.hyphenated().to_string()
                })
                .unwrap()
                .phase(),
            TransferPhase::Queued
        );
        store
            .request_cancel(&second_binding.public_id.hyphenated().to_string())
            .unwrap();
        worker.try_wake_cancellation().unwrap();
        let TransferWorkerEvent::SendManifest { payload, .. } = next_event(&mut worker).await
        else {
            panic!("queued cancel must notify the peer");
        };
        assert!(matches!(
            decode_file_manifest(&payload).unwrap(),
            FileManifestMessage::Cancel { transfer, .. } if transfer == second
        ));
        let listing = store.transfer_listing();
        assert!(listing.transfers.iter().any(|snapshot| {
            snapshot.transfer_id() == second_binding.public_id.hyphenated().to_string()
                && snapshot.phase() == TransferPhase::Cancelled
        }));
        assert!(listing.transfers.iter().any(|snapshot| {
            snapshot.direction() == TransferDirection::Inbound
                && snapshot.phase() == TransferPhase::Transferring
        }));
        worker.stop(TransferStopMode::AbortAll);
        drop(worker);
        fs::remove_dir_all(staging_root).unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn process_wide_live_cap_rejects_extra_authenticated_inbound() {
        let _guard = FILE_TEST_LOCK.lock().await;
        let staging_root = temporary_directory("staging-global-live-cap");
        let store = TransferStore::default();
        for _ in 0..nodavo_local_ipc::MAX_NONTERMINAL_TRANSFERS {
            store.registry.admit_outbound(LOCAL).unwrap();
        }
        let session = SessionId::new([17; 16]);
        let wire = WireTransferId::new([63; 16]);
        let mut worker = worker(store.clone(), session, &staging_root);
        worker
            .try_receive_manifest(inbound_manifest_frame(session, wire, b"x"))
            .unwrap();
        let TransferWorkerEvent::SendManifest { payload, .. } = next_event(&mut worker).await
        else {
            panic!("global live cap must reject the extra inbound manifest");
        };
        assert!(matches!(
            decode_file_manifest(&payload).unwrap(),
            FileManifestMessage::Cancel { transfer, .. } if transfer == wire
        ));
        let listing = store.transfer_listing();
        assert_eq!(
            listing.transfers.len(),
            nodavo_local_ipc::MAX_NONTERMINAL_TRANSFERS
        );
        assert!(
            listing
                .transfers
                .iter()
                .all(|snapshot| snapshot.direction() == TransferDirection::Outbound)
        );
        worker.stop(TransferStopMode::AbortAll);
        drop(worker);
        fs::remove_dir_all(staging_root).unwrap();
    }

    #[test]
    fn offline_inbound_cleanup_failure_is_failed_and_poisons_later_file_work() {
        let store = TransferStore::default();
        let wire = TransferId::from_bytes([42; 16]);
        let InboundAdmission::Live(binding) = store.registry.admit_inbound(PEER, wire, 2).unwrap()
        else {
            panic!("inbound admission must be live");
        };
        assert!(matches!(
            store
                .registry
                .update_inbound(PEER, wire, 1, 2, TransferPhase::Paused),
            InboundUpdate::Updated(_)
        ));
        store.remember_inbound(PEER, wire).unwrap();
        let requested = store
            .request_cancel(&binding.public_id.hyphenated().to_string())
            .unwrap();
        store.cleanup_cancelled_if_offline(requested.target.unwrap());
        assert!(store.is_poisoned());
        let failed = store.transfer_listing();
        assert_eq!(failed.transfers[0].phase(), TransferPhase::Failed);
        assert_eq!(
            failed.transfers[0].failure(),
            Some(TransferFailureCode::CleanupFailed)
        );
        assert_eq!(store.reserve_outbound(), Err(TransferError::Platform));
    }

    #[test]
    fn listing_never_waits_for_the_slow_transfer_store_mutex() {
        let store = TransferStore::default();
        let _slow_guard = store.inner.lock().unwrap();
        let listing = store.transfer_listing();
        assert_ne!(listing.revision, 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn offline_cancelled_outbound_is_never_reannounced() {
        let _guard = FILE_TEST_LOCK.lock().await;
        let source_root = temporary_directory("source-offline-cancel");
        let staging_root = temporary_directory("staging-offline-cancel");
        let selected = source_root.join("cancelled.bin");
        fs::write(&selected, b"cancelled while offline").unwrap();
        let store = TransferStore::default();
        let mut first = worker(store.clone(), SessionId::new([13; 16]), &staging_root);
        let (acknowledgement, acknowledged) = oneshot::channel();
        first.try_start_outbound(vec![selected], acknowledgement);
        let public = acknowledged.await.unwrap().unwrap();
        assert!(matches!(
            next_event(&mut first).await,
            TransferWorkerEvent::SendManifest { .. }
        ));
        first.stop(TransferStopMode::Suspend);
        drop(first);
        wait_until_worker_releases_store(&store).await;
        let requested = store
            .request_cancel(&public.as_uuid().hyphenated().to_string())
            .unwrap();
        store.cleanup_cancelled_if_offline(requested.target.unwrap());
        assert_eq!(store.outbound_count(), 0);
        assert_eq!(
            store.transfer_listing().transfers[0].phase(),
            TransferPhase::Cancelled
        );

        let mut second = worker(store.clone(), SessionId::new([14; 16]), &staging_root);
        assert!(
            timeout(Duration::from_millis(100), second.next_event())
                .await
                .is_err()
        );
        second.stop(TransferStopMode::Suspend);
        drop(second);
        fs::remove_dir_all(source_root).unwrap();
        fs::remove_dir_all(staging_root).unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    #[allow(
        clippy::too_many_lines,
        reason = "the interleaving proves three late response types and unrelated liveness"
    )]
    async fn cancelled_outbound_absorbs_in_flight_peer_responses_without_stopping_worker() {
        let _guard = FILE_TEST_LOCK.lock().await;
        let source_root = temporary_directory("source-cancel-late-responses");
        let staging_root = temporary_directory("staging-cancel-late-responses");
        let first_path = source_root.join("first.bin");
        let second_path = source_root.join("second.bin");
        fs::write(&first_path, b"first").unwrap();
        fs::write(&second_path, b"second").unwrap();
        let store = TransferStore::default();
        let session = SessionId::new([18; 16]);
        let mut worker = worker(store.clone(), session, &staging_root);

        let (acknowledgement, acknowledged) = oneshot::channel();
        worker.try_start_outbound(vec![first_path], acknowledgement);
        let public = acknowledged.await.unwrap().unwrap();
        let TransferWorkerEvent::SendManifest { payload, .. } = next_event(&mut worker).await
        else {
            panic!("expected first manifest");
        };
        let FileManifestMessage::Manifest {
            transfer: cancelled_wire,
            ..
        } = decode_file_manifest(&payload).unwrap()
        else {
            panic!("expected manifest frame");
        };
        store
            .request_cancel(&public.as_uuid().hyphenated().to_string())
            .unwrap();
        worker.try_wake_cancellation().unwrap();
        let TransferWorkerEvent::SendManifest { payload, .. } = next_event(&mut worker).await
        else {
            panic!("expected outbound cancel frame");
        };
        assert!(matches!(
            decode_file_manifest(&payload).unwrap(),
            FileManifestMessage::Cancel { transfer, .. } if transfer == cancelled_wire
        ));

        worker
            .try_receive_manifest(resume_frame(session, 1, cancelled_wire, 0, 0))
            .unwrap();
        worker
            .try_receive_manifest(complete_response_frame(session, 2, cancelled_wire))
            .unwrap();
        worker
            .try_receive_manifest(cancel_response_frame(session, 3, cancelled_wire))
            .unwrap();

        let (acknowledgement, acknowledged) = oneshot::channel();
        worker.try_start_outbound(vec![second_path], acknowledgement);
        acknowledged.await.unwrap().unwrap();
        let event = next_event(&mut worker).await;
        assert!(matches!(event, TransferWorkerEvent::SendManifest { .. }));
        assert_eq!(
            store.registry.phase(public.as_uuid()),
            Some(TransferPhase::Cancelled)
        );
        assert!(!store.is_poisoned());

        worker.stop(TransferStopMode::AbortAll);
        drop(worker);
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
            TransferWorkerEvent::SendManifest { .. }
        ));
        worker
            .try_receive_data(inbound_data_frame(session, transfer, &payload[..8]))
            .unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        worker.stop(TransferStopMode::Suspend);
        drop(worker);
        wait_until_worker_releases_store(&store).await;

        let core_transfer = TransferId::from_bytes(*transfer.as_bytes());
        let staging = FileSystemStagingArea::new_scoped(&staging_root, *PEER.as_bytes()).unwrap();
        assert!(staging.has_persisted(core_transfer).unwrap());
        drop(staging);

        store.require_peer_inbound_discard(PEER);
        assert_eq!(
            store.cleanup_peer_if_idle(PEER).unwrap(),
            TransferCleanupState::Complete
        );
        let staging = FileSystemStagingArea::new_scoped(&staging_root, *PEER.as_bytes()).unwrap();
        assert!(!staging.has_persisted(core_transfer).unwrap());
        assert!(!store.is_poisoned());
        fs::remove_dir_all(staging_root).unwrap();
    }
}
