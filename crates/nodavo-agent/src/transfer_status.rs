//! Short-held, content-free public transfer registry.
//!
//! This registry is deliberately independent from source and staging
//! ownership. Listing and cancellation intent therefore never wait for source
//! scans, reads, durable writes, finalization, or cleanup.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use nodavo_local_ipc::{
    MAX_NONTERMINAL_TRANSFERS, MAX_TERMINAL_TRANSFERS, TransferDirection, TransferFailureCode,
    TransferPhase, TransferSnapshot,
};
use nodavo_protocol::DeviceId;
use nodavo_transfer::TransferId;
use uuid::Uuid;

/// Hard process-lifetime identity budget. Retired public and wire identifiers
/// are never evicted because doing so could alias a delayed authenticated
/// frame. Once exhausted, new admission fails closed until process restart.
pub(crate) const MAX_LIFETIME_TRANSFER_IDENTITIES: usize = 4_096;

const _: () =
    assert!(MAX_LIFETIME_TRANSFER_IDENTITIES >= MAX_NONTERMINAL_TRANSFERS + MAX_TERMINAL_TRANSFERS);

#[derive(Clone)]
pub(crate) struct TransferRegistry {
    instance_id: String,
    inner: Arc<Mutex<RegistryInner>>,
}

struct RegistryInner {
    revision: u64,
    next_generation: u64,
    truncated: bool,
    entries: HashMap<Uuid, RegistryEntry>,
    by_wire: HashMap<WireScope, Uuid>,
    terminal_history: HashMap<Uuid, TerminalRecord>,
    all_public_ids: HashSet<Uuid>,
    all_wire_ids: HashSet<TransferId>,
    terminal_fifo: VecDeque<Uuid>,
}

#[derive(Clone, Copy)]
struct TerminalRecord {
    binding: TransferBinding,
    phase: TransferPhase,
}

struct RegistryEntry {
    public_id: Uuid,
    binding: TransferBinding,
    phase: TransferPhase,
    processed_bytes: Option<u64>,
    total_bytes: Option<u64>,
    cancellable: bool,
    failure: Option<TransferFailureCode>,
    cancel: Arc<AtomicBool>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct WireScope {
    peer: DeviceId,
    direction: TransferDirection,
    wire_id: TransferId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TransferBinding {
    pub(crate) public_id: Uuid,
    pub(crate) peer: DeviceId,
    pub(crate) direction: TransferDirection,
    pub(crate) wire_id: TransferId,
    pub(crate) generation: u64,
}

#[derive(Clone)]
pub(crate) struct TransferAdmission {
    pub(crate) binding: TransferBinding,
    pub(crate) cancellation: Arc<AtomicBool>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TransferListing {
    pub(crate) instance_id: String,
    pub(crate) revision: u64,
    pub(crate) truncated: bool,
    pub(crate) transfers: Vec<TransferSnapshot>,
}

#[derive(Clone, Copy)]
pub(crate) struct CancelTarget {
    pub(crate) binding: TransferBinding,
}

pub(crate) struct CancelOutcome {
    pub(crate) listing: TransferListing,
    pub(crate) target: Option<CancelTarget>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TransferRegistryError {
    Full,
    LifetimeFull,
    InvalidId,
    NotFound,
    NotCancellable,
    WireIdCollision,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InboundAdmission {
    Live(TransferBinding),
    Terminal {
        binding: TransferBinding,
        phase: TransferPhase,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InboundUpdate {
    Updated(TransferBinding),
    Terminal(TransferBinding),
    Unknown,
}

impl Default for TransferRegistry {
    fn default() -> Self {
        Self {
            instance_id: Uuid::new_v4().hyphenated().to_string(),
            inner: Arc::new(Mutex::new(RegistryInner {
                revision: 1,
                next_generation: 1,
                truncated: false,
                entries: HashMap::new(),
                by_wire: HashMap::new(),
                terminal_history: HashMap::new(),
                all_public_ids: HashSet::new(),
                all_wire_ids: HashSet::new(),
                terminal_fifo: VecDeque::new(),
            })),
        }
    }
}

impl TransferRegistry {
    pub(crate) fn list(&self) -> TransferListing {
        let inner = self.inner.lock().expect("transfer registry mutex poisoned");
        self.list_locked(&inner)
    }

    pub(crate) fn admit_outbound(
        &self,
        peer: DeviceId,
    ) -> Result<TransferAdmission, TransferRegistryError> {
        let mut inner = self.inner.lock().expect("transfer registry mutex poisoned");
        if nonterminal_count(&inner) >= MAX_NONTERMINAL_TRANSFERS {
            return Err(TransferRegistryError::Full);
        }
        if lifetime_identity_count(&inner) >= MAX_LIFETIME_TRANSFER_IDENTITIES {
            return Err(TransferRegistryError::LifetimeFull);
        }
        let public_id = fresh_public_id(&inner);
        let mut wire_id = TransferId::new();
        while inner
            .all_public_ids
            .contains(&Uuid::from_bytes(wire_id.as_bytes()))
            || inner.all_wire_ids.contains(&wire_id)
        {
            wire_id = TransferId::new();
        }
        inner.all_public_ids.insert(public_id);
        inner.all_wire_ids.insert(wire_id);
        let generation = next_generation(&mut inner);
        let binding = TransferBinding {
            public_id,
            peer,
            direction: TransferDirection::Outbound,
            wire_id,
            generation,
        };
        let cancellation = Arc::new(AtomicBool::new(false));
        insert_entry(
            &mut inner,
            binding,
            TransferPhase::Preparing,
            None,
            None,
            true,
            Arc::clone(&cancellation),
        );
        bump_revision(&mut inner);
        Ok(TransferAdmission {
            binding,
            cancellation,
        })
    }

    pub(crate) fn rollback_admission(&self, public_id: Uuid) {
        let mut inner = self.inner.lock().expect("transfer registry mutex poisoned");
        if let Some(entry) = inner.entries.remove(&public_id) {
            inner.by_wire.remove(&scope(entry.binding));
            bump_revision(&mut inner);
        }
    }

    pub(crate) fn admit_inbound(
        &self,
        peer: DeviceId,
        wire_id: TransferId,
        total_bytes: u64,
    ) -> Result<InboundAdmission, TransferRegistryError> {
        let mut inner = self.inner.lock().expect("transfer registry mutex poisoned");
        let wire_scope = WireScope {
            peer,
            direction: TransferDirection::Inbound,
            wire_id,
        };
        if let Some(public_id) = inner.by_wire.get(&wire_scope).copied() {
            if let Some(entry) = inner.entries.get_mut(&public_id) {
                if entry.phase.is_terminal() {
                    return Ok(InboundAdmission::Terminal {
                        binding: entry.binding,
                        phase: entry.phase,
                    });
                }
                if entry.phase != TransferPhase::CancelRequested {
                    if entry.total_bytes != Some(total_bytes) {
                        return Err(TransferRegistryError::InvalidId);
                    }
                    entry.phase = TransferPhase::Queued;
                    entry.cancellable = true;
                    let binding = entry.binding;
                    bump_revision(&mut inner);
                    return Ok(InboundAdmission::Live(binding));
                }
                return Ok(InboundAdmission::Live(entry.binding));
            }
            if let Some(record) = inner.terminal_history.get(&public_id) {
                return Ok(InboundAdmission::Terminal {
                    binding: record.binding,
                    phase: record.phase,
                });
            }
            return Err(TransferRegistryError::InvalidId);
        }
        if nonterminal_count(&inner) >= MAX_NONTERMINAL_TRANSFERS {
            return Err(TransferRegistryError::Full);
        }
        if lifetime_identity_count(&inner) >= MAX_LIFETIME_TRANSFER_IDENTITIES {
            return Err(TransferRegistryError::LifetimeFull);
        }
        let wire_uuid = Uuid::from_bytes(wire_id.as_bytes());
        if inner.all_public_ids.contains(&wire_uuid) {
            return Err(TransferRegistryError::WireIdCollision);
        }
        inner.all_wire_ids.insert(wire_id);
        let public_id = fresh_public_id(&inner);
        inner.all_public_ids.insert(public_id);
        let binding = TransferBinding {
            public_id,
            peer,
            direction: TransferDirection::Inbound,
            wire_id,
            generation: next_generation(&mut inner),
        };
        insert_entry(
            &mut inner,
            binding,
            TransferPhase::Queued,
            Some(0),
            Some(total_bytes),
            true,
            Arc::new(AtomicBool::new(false)),
        );
        bump_revision(&mut inner);
        Ok(InboundAdmission::Live(binding))
    }

    pub(crate) fn update_inbound(
        &self,
        peer: DeviceId,
        wire_id: TransferId,
        processed_bytes: u64,
        total_bytes: u64,
        phase: TransferPhase,
    ) -> InboundUpdate {
        let mut inner = self.inner.lock().expect("transfer registry mutex poisoned");
        let Some(public_id) = inner
            .by_wire
            .get(&WireScope {
                peer,
                direction: TransferDirection::Inbound,
                wire_id,
            })
            .copied()
        else {
            return InboundUpdate::Unknown;
        };
        let Some(entry) = inner.entries.get_mut(&public_id) else {
            return if let Some(record) = inner.terminal_history.get(&public_id) {
                InboundUpdate::Terminal(record.binding)
            } else {
                InboundUpdate::Unknown
            };
        };
        if entry.phase.is_terminal() || entry.phase == TransferPhase::CancelRequested {
            return InboundUpdate::Terminal(entry.binding);
        }
        if processed_bytes > total_bytes || entry.total_bytes != Some(total_bytes) {
            return InboundUpdate::Unknown;
        }
        entry.processed_bytes = Some(processed_bytes);
        entry.phase = phase;
        entry.cancellable = true;
        let binding = entry.binding;
        bump_revision(&mut inner);
        InboundUpdate::Updated(binding)
    }

    pub(crate) fn manifest_ready(&self, public_id: Uuid, total_bytes: u64) {
        self.mutate_live(public_id, |entry| {
            if entry.phase != TransferPhase::CancelRequested {
                entry.phase = TransferPhase::Queued;
                entry.processed_bytes = Some(0);
                entry.total_bytes = Some(total_bytes);
            }
        });
    }

    pub(crate) fn resume_progress(&self, public_id: Uuid, processed_bytes: u64) {
        self.mutate_live(public_id, |entry| {
            if entry.phase != TransferPhase::CancelRequested
                && entry
                    .total_bytes
                    .is_some_and(|total| processed_bytes <= total)
            {
                entry.phase = TransferPhase::Queued;
                entry.processed_bytes = Some(processed_bytes);
            }
        });
    }

    pub(crate) fn reliable_data_sent(&self, public_id: Uuid, processed_bytes: u64) {
        self.mutate_live(public_id, |entry| {
            if entry.phase != TransferPhase::CancelRequested
                && entry
                    .total_bytes
                    .is_some_and(|total| processed_bytes <= total)
                && entry
                    .processed_bytes
                    .is_none_or(|processed| processed_bytes >= processed)
            {
                entry.phase = TransferPhase::Transferring;
                entry.processed_bytes = Some(processed_bytes);
            }
        });
    }

    pub(crate) fn finalizing(&self, public_id: Uuid) {
        self.mutate_live(public_id, |entry| {
            if entry.phase != TransferPhase::CancelRequested {
                entry.phase = TransferPhase::Finalizing;
                entry.processed_bytes = entry.total_bytes;
            }
        });
    }

    /// Linearizes inbound completion against local cancellation before slow
    /// integrity verification and publication begins.
    pub(crate) fn begin_inbound_finalizing(&self, public_id: Uuid) -> bool {
        let mut inner = self.inner.lock().expect("transfer registry mutex poisoned");
        let Some(entry) = inner.entries.get_mut(&public_id) else {
            return false;
        };
        if entry.phase.is_terminal()
            || entry.phase == TransferPhase::CancelRequested
            || entry.binding.direction != TransferDirection::Inbound
            || entry.processed_bytes != entry.total_bytes
        {
            return false;
        }
        entry.phase = TransferPhase::Finalizing;
        entry.cancellable = false;
        bump_revision(&mut inner);
        true
    }

    /// Returns true only when completion wins the terminal-state race.
    pub(crate) fn complete(&self, public_id: Uuid) -> bool {
        self.finish(public_id, |entry| {
            if entry.phase == TransferPhase::CancelRequested {
                return false;
            }
            entry.phase = TransferPhase::Completed;
            entry.processed_bytes = entry.total_bytes;
            entry.cancellable = false;
            entry.failure = None;
            true
        })
    }

    pub(crate) fn cancelled(&self, public_id: Uuid) {
        let _ = self.finish(public_id, |entry| {
            entry.phase = TransferPhase::Cancelled;
            entry.cancellable = false;
            entry.failure = None;
            true
        });
    }

    pub(crate) fn fail(&self, public_id: Uuid, failure: TransferFailureCode) {
        let _ = self.finish(public_id, |entry| {
            if entry.phase == TransferPhase::CancelRequested {
                return false;
            }
            entry.phase = TransferPhase::Failed;
            entry.cancellable = false;
            entry.failure = Some(failure);
            true
        });
    }

    pub(crate) fn binding_for_wire(
        &self,
        peer: DeviceId,
        direction: TransferDirection,
        wire_id: TransferId,
    ) -> Option<TransferBinding> {
        let inner = self.inner.lock().expect("transfer registry mutex poisoned");
        let public = inner
            .by_wire
            .get(&WireScope {
                peer,
                direction,
                wire_id,
            })
            .copied()?;
        inner
            .entries
            .get(&public)
            .map(|entry| entry.binding)
            .or_else(|| {
                inner
                    .terminal_history
                    .get(&public)
                    .map(|record| record.binding)
            })
    }

    pub(crate) fn phase(&self, public_id: Uuid) -> Option<TransferPhase> {
        let inner = self.inner.lock().expect("transfer registry mutex poisoned");
        inner
            .entries
            .get(&public_id)
            .map(|entry| entry.phase)
            .or_else(|| {
                inner
                    .terminal_history
                    .get(&public_id)
                    .map(|record| record.phase)
            })
    }

    pub(crate) fn cancellation_for_peer(
        &self,
        peer: DeviceId,
        direction: TransferDirection,
    ) -> Option<TransferBinding> {
        let inner = self.inner.lock().expect("transfer registry mutex poisoned");
        inner
            .entries
            .values()
            .filter(|entry| {
                entry.binding.peer == peer
                    && entry.binding.direction == direction
                    && entry.phase == TransferPhase::CancelRequested
                    && entry.cancel.load(Ordering::Acquire)
            })
            .min_by_key(|entry| entry.binding.generation)
            .map(|entry| entry.binding)
    }

    pub(crate) fn request_cancel(
        &self,
        transfer_id: &str,
    ) -> Result<CancelOutcome, TransferRegistryError> {
        let parsed = Uuid::parse_str(transfer_id).map_err(|_| TransferRegistryError::InvalidId)?;
        if parsed.is_nil() || parsed.hyphenated().to_string() != transfer_id {
            return Err(TransferRegistryError::InvalidId);
        }
        let mut inner = self.inner.lock().expect("transfer registry mutex poisoned");
        let Some(entry) = inner.entries.get_mut(&parsed) else {
            return Err(TransferRegistryError::NotFound);
        };
        let target = if entry.phase.is_terminal() || entry.phase == TransferPhase::CancelRequested {
            None
        } else if !entry.cancellable {
            return Err(TransferRegistryError::NotCancellable);
        } else {
            entry.phase = TransferPhase::CancelRequested;
            entry.cancellable = false;
            entry.cancel.store(true, Ordering::Release);
            let target = CancelTarget {
                binding: entry.binding,
            };
            bump_revision(&mut inner);
            Some(target)
        };
        Ok(CancelOutcome {
            listing: self.list_locked(&inner),
            target,
        })
    }

    pub(crate) fn pause_peer(&self, peer: DeviceId) {
        let mut inner = self.inner.lock().expect("transfer registry mutex poisoned");
        let mut changed = false;
        for entry in inner
            .entries
            .values_mut()
            .filter(|entry| entry.binding.peer == peer && !entry.phase.is_terminal())
        {
            match entry.phase {
                TransferPhase::Preparing => {
                    entry.phase = TransferPhase::CancelRequested;
                    entry.cancellable = false;
                    entry.cancel.store(true, Ordering::Release);
                    changed = true;
                }
                TransferPhase::CancelRequested => {}
                _ => {
                    entry.phase = TransferPhase::Paused;
                    changed = true;
                }
            }
        }
        if changed {
            bump_revision(&mut inner);
        }
    }

    pub(crate) fn fail_peer(&self, peer: DeviceId, failure: TransferFailureCode) {
        let ids = {
            let inner = self.inner.lock().expect("transfer registry mutex poisoned");
            inner
                .entries
                .values()
                .filter(|entry| entry.binding.peer == peer && !entry.phase.is_terminal())
                .map(|entry| entry.public_id)
                .collect::<Vec<_>>()
        };
        for id in ids {
            self.fail_irreversible(id, failure);
        }
    }

    pub(crate) fn request_system_abort(&self, peer: DeviceId, direction: TransferDirection) {
        let mut inner = self.inner.lock().expect("transfer registry mutex poisoned");
        let mut changed = false;
        for entry in inner.entries.values_mut().filter(|entry| {
            entry.binding.peer == peer
                && entry.binding.direction == direction
                && !entry.phase.is_terminal()
        }) {
            entry.phase = TransferPhase::CancelRequested;
            entry.cancellable = false;
            entry.cancel.store(true, Ordering::Release);
            changed = true;
        }
        if changed {
            bump_revision(&mut inner);
        }
    }

    pub(crate) fn finish_system_abort(&self, peer: DeviceId, direction: TransferDirection) {
        let ids = {
            let inner = self.inner.lock().expect("transfer registry mutex poisoned");
            inner
                .entries
                .values()
                .filter(|entry| {
                    entry.binding.peer == peer
                        && entry.binding.direction == direction
                        && entry.phase == TransferPhase::CancelRequested
                })
                .map(|entry| entry.public_id)
                .collect::<Vec<_>>()
        };
        for id in ids {
            self.cancelled(id);
        }
    }

    pub(crate) fn cleanup_failed(&self, peer: DeviceId, direction: TransferDirection) {
        let ids = {
            let inner = self.inner.lock().expect("transfer registry mutex poisoned");
            inner
                .entries
                .values()
                .filter(|entry| {
                    entry.binding.peer == peer
                        && entry.binding.direction == direction
                        && !entry.phase.is_terminal()
                })
                .map(|entry| entry.public_id)
                .collect::<Vec<_>>()
        };
        for id in ids {
            self.fail_irreversible(id, TransferFailureCode::CleanupFailed);
        }
    }

    fn fail_irreversible(&self, public_id: Uuid, failure: TransferFailureCode) {
        let _ = self.finish(public_id, |entry| {
            entry.phase = TransferPhase::Failed;
            entry.cancellable = false;
            entry.failure = Some(failure);
            true
        });
    }

    pub(crate) fn cancellation_requested(cancellation: &AtomicBool) -> bool {
        cancellation.load(Ordering::Acquire)
    }

    fn mutate_live(&self, public_id: Uuid, mutate: impl FnOnce(&mut RegistryEntry)) {
        let mut inner = self.inner.lock().expect("transfer registry mutex poisoned");
        let Some(entry) = inner.entries.get_mut(&public_id) else {
            return;
        };
        if entry.phase.is_terminal() {
            return;
        }
        mutate(entry);
        bump_revision(&mut inner);
    }

    fn finish(&self, public_id: Uuid, mutate: impl FnOnce(&mut RegistryEntry) -> bool) -> bool {
        let mut inner = self.inner.lock().expect("transfer registry mutex poisoned");
        let Some(entry) = inner.entries.get_mut(&public_id) else {
            return false;
        };
        if entry.phase.is_terminal() || !mutate(entry) {
            return false;
        }
        let terminal = TerminalRecord {
            binding: entry.binding,
            phase: entry.phase,
        };
        inner.terminal_history.insert(public_id, terminal);
        inner.terminal_fifo.push_back(public_id);
        while inner.terminal_fifo.len() > MAX_TERMINAL_TRANSFERS {
            if let Some(expired) = inner.terminal_fifo.pop_front()
                && inner.entries.remove(&expired).is_some()
            {
                inner.truncated = true;
            }
        }
        bump_revision(&mut inner);
        true
    }

    fn list_locked(&self, inner: &RegistryInner) -> TransferListing {
        let mut live = inner
            .entries
            .values()
            .filter(|entry| !entry.phase.is_terminal())
            .collect::<Vec<_>>();
        live.sort_unstable_by_key(|entry| entry.binding.generation);
        let terminal = inner
            .terminal_fifo
            .iter()
            .filter_map(|id| inner.entries.get(id));
        let transfers = live.into_iter().chain(terminal).map(snapshot).collect();
        TransferListing {
            instance_id: self.instance_id.clone(),
            revision: inner.revision,
            truncated: inner.truncated,
            transfers,
        }
    }
}

fn insert_entry(
    inner: &mut RegistryInner,
    binding: TransferBinding,
    phase: TransferPhase,
    processed_bytes: Option<u64>,
    total_bytes: Option<u64>,
    cancellable: bool,
    cancel: Arc<AtomicBool>,
) {
    inner.by_wire.insert(scope(binding), binding.public_id);
    inner.entries.insert(
        binding.public_id,
        RegistryEntry {
            public_id: binding.public_id,
            binding,
            phase,
            processed_bytes,
            total_bytes,
            cancellable,
            failure: None,
            cancel,
        },
    );
}

fn snapshot(entry: &RegistryEntry) -> TransferSnapshot {
    TransferSnapshot::new(
        entry.public_id.hyphenated().to_string(),
        entry.binding.direction,
        entry.phase,
        entry.processed_bytes,
        entry.total_bytes,
        entry.cancellable,
        entry.failure,
    )
    .expect("registry transitions preserve public snapshot invariants")
}

fn scope(binding: TransferBinding) -> WireScope {
    WireScope {
        peer: binding.peer,
        direction: binding.direction,
        wire_id: binding.wire_id,
    }
}

fn nonterminal_count(inner: &RegistryInner) -> usize {
    inner
        .entries
        .values()
        .filter(|entry| !entry.phase.is_terminal())
        .count()
}

fn lifetime_identity_count(inner: &RegistryInner) -> usize {
    inner.all_public_ids.len()
}

fn fresh_public_id(inner: &RegistryInner) -> Uuid {
    loop {
        let candidate = Uuid::new_v4();
        if public_id_available(inner, candidate) {
            return candidate;
        }
    }
}

fn public_id_available(inner: &RegistryInner, candidate: Uuid) -> bool {
    !candidate.is_nil()
        && !inner.all_public_ids.contains(&candidate)
        && !inner
            .all_wire_ids
            .contains(&TransferId::from_bytes(*candidate.as_bytes()))
}

fn next_generation(inner: &mut RegistryInner) -> u64 {
    let generation = inner.next_generation;
    inner.next_generation = inner
        .next_generation
        .checked_add(1)
        .expect("a process cannot admit u64::MAX transfer generations");
    generation
}

fn bump_revision(inner: &mut RegistryInner) {
    inner.revision = inner
        .revision
        .checked_add(1)
        .expect("a process cannot publish u64::MAX transfer revisions");
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    const FIRST_PEER: DeviceId = DeviceId::new([1; 32]);
    const SECOND_PEER: DeviceId = DeviceId::new([2; 32]);

    #[test]
    fn instance_revision_and_public_ids_are_nonzero_canonical_and_unique() {
        let registry = TransferRegistry::default();
        let initial = registry.list();
        let instance = Uuid::parse_str(&initial.instance_id).unwrap();
        assert!(!instance.is_nil());
        assert_eq!(instance.hyphenated().to_string(), initial.instance_id);
        assert_ne!(initial.revision, 0);

        for _ in 0..MAX_NONTERMINAL_TRANSFERS {
            registry.admit_outbound(FIRST_PEER).unwrap();
        }
        assert_eq!(
            registry.admit_outbound(FIRST_PEER).err(),
            Some(TransferRegistryError::Full)
        );
        let listing = registry.list();
        assert_eq!(listing.transfers.len(), MAX_NONTERMINAL_TRANSFERS);
        let ids = listing
            .transfers
            .iter()
            .map(nodavo_local_ipc::TransferSnapshot::transfer_id)
            .collect::<HashSet<_>>();
        assert_eq!(ids.len(), MAX_NONTERMINAL_TRANSFERS);
    }

    #[test]
    fn cancellation_and_completion_are_linearized_and_idempotent() {
        let completion_first = TransferRegistry::default();
        let admission = completion_first.admit_outbound(FIRST_PEER).unwrap();
        completion_first.manifest_ready(admission.binding.public_id, 10);
        completion_first.reliable_data_sent(admission.binding.public_id, 10);
        completion_first.finalizing(admission.binding.public_id);
        assert!(completion_first.complete(admission.binding.public_id));
        let completed = completion_first.list();
        let repeated = completion_first
            .request_cancel(&admission.binding.public_id.hyphenated().to_string())
            .unwrap();
        assert!(repeated.target.is_none());
        assert_eq!(repeated.listing, completed);

        let cancellation_first = TransferRegistry::default();
        let admission = cancellation_first.admit_outbound(FIRST_PEER).unwrap();
        cancellation_first.manifest_ready(admission.binding.public_id, 10);
        let requested = cancellation_first
            .request_cancel(&admission.binding.public_id.hyphenated().to_string())
            .unwrap();
        assert!(requested.target.is_some());
        assert_eq!(
            requested.listing.transfers[0].phase(),
            TransferPhase::CancelRequested
        );
        assert!(!cancellation_first.complete(admission.binding.public_id));
        cancellation_first.cancelled(admission.binding.public_id);
        let cancelled = cancellation_first.list();
        assert_eq!(cancelled.transfers[0].phase(), TransferPhase::Cancelled);
        let repeated = cancellation_first
            .request_cancel(&admission.binding.public_id.hyphenated().to_string())
            .unwrap();
        assert!(repeated.target.is_none());
        assert_eq!(repeated.listing, cancelled);
    }

    #[test]
    fn counters_never_regress_and_equality_does_not_imply_completion() {
        let registry = TransferRegistry::default();
        let admission = registry.admit_outbound(FIRST_PEER).unwrap();
        registry.manifest_ready(admission.binding.public_id, 10);
        registry.reliable_data_sent(admission.binding.public_id, 8);
        registry.reliable_data_sent(admission.binding.public_id, 4);
        let listing = registry.list();
        assert_eq!(listing.transfers[0].processed_bytes(), Some(8));
        registry.reliable_data_sent(admission.binding.public_id, 10);
        let equal = registry.list();
        assert_eq!(equal.transfers[0].processed_bytes(), Some(10));
        assert_eq!(equal.transfers[0].phase(), TransferPhase::Transferring);
        registry.finalizing(admission.binding.public_id);
        assert_eq!(
            registry.list().transfers[0].phase(),
            TransferPhase::Finalizing
        );
    }

    #[test]
    fn wire_id_collisions_and_reuse_are_isolated_by_peer_direction_and_generation() {
        let registry = TransferRegistry::default();
        let wire = TransferId::from_bytes([9; 16]);
        let InboundAdmission::Live(first) = registry.admit_inbound(FIRST_PEER, wire, 1).unwrap()
        else {
            panic!("first wire admission must be live");
        };
        let InboundAdmission::Live(second) = registry.admit_inbound(SECOND_PEER, wire, 1).unwrap()
        else {
            panic!("second peer wire collision must be isolated");
        };
        assert_ne!(first.public_id, second.public_id);
        assert_eq!(
            registry
                .binding_for_wire(FIRST_PEER, TransferDirection::Inbound, wire)
                .unwrap(),
            first
        );
        assert_eq!(
            registry
                .binding_for_wire(SECOND_PEER, TransferDirection::Inbound, wire)
                .unwrap(),
            second
        );

        registry.cancelled(first.public_id);
        assert_eq!(
            registry.admit_inbound(FIRST_PEER, wire, 1).unwrap(),
            InboundAdmission::Terminal {
                binding: first,
                phase: TransferPhase::Cancelled,
            }
        );
        assert_eq!(registry.list().transfers.len(), 2);
    }

    #[test]
    fn terminal_fifo_is_bounded_and_reports_truncation() {
        let registry = TransferRegistry::default();
        let mut first = None;
        for index in 0..=MAX_TERMINAL_TRANSFERS {
            let admission = registry.admit_outbound(FIRST_PEER).unwrap();
            if index == 0 {
                first = Some(admission.binding);
            }
            registry.manifest_ready(admission.binding.public_id, 0);
            registry.finalizing(admission.binding.public_id);
            assert!(registry.complete(admission.binding.public_id));
        }
        let listing = registry.list();
        assert_eq!(listing.transfers.len(), MAX_TERMINAL_TRANSFERS);
        assert!(listing.truncated);
        assert!(
            listing
                .transfers
                .iter()
                .all(|snapshot| snapshot.phase() == TransferPhase::Completed)
        );
        let first = first.unwrap();
        assert_eq!(
            registry.binding_for_wire(FIRST_PEER, TransferDirection::Outbound, first.wire_id,),
            Some(first),
            "UI FIFO eviction must not erase process-lifetime wire tombstones"
        );
    }

    #[test]
    fn lifetime_identity_ledger_fails_closed_after_terminal_churn() {
        let registry = TransferRegistry::default();
        for _ in 0..MAX_LIFETIME_TRANSFER_IDENTITIES {
            let admission = registry.admit_outbound(FIRST_PEER).unwrap();
            registry.manifest_ready(admission.binding.public_id, 0);
            registry.finalizing(admission.binding.public_id);
            assert!(registry.complete(admission.binding.public_id));
        }

        assert_eq!(
            registry.admit_outbound(FIRST_PEER).err(),
            Some(TransferRegistryError::LifetimeFull)
        );
        let inner = registry.inner.lock().unwrap();
        assert_eq!(inner.all_public_ids.len(), MAX_LIFETIME_TRANSFER_IDENTITIES);
        assert_eq!(inner.all_wire_ids.len(), MAX_LIFETIME_TRANSFER_IDENTITIES);
        assert_eq!(inner.by_wire.len(), MAX_LIFETIME_TRANSFER_IDENTITIES);
        assert_eq!(
            inner.terminal_history.len(),
            MAX_LIFETIME_TRANSFER_IDENTITIES
        );
        assert_eq!(inner.terminal_fifo.len(), MAX_TERMINAL_TRANSFERS);
        assert!(inner.entries.len() <= MAX_TERMINAL_TRANSFERS);
    }

    #[test]
    fn admission_rollbacks_consume_but_never_exceed_identity_ledger() {
        let registry = TransferRegistry::default();
        for _ in 0..MAX_LIFETIME_TRANSFER_IDENTITIES {
            let admission = registry.admit_outbound(FIRST_PEER).unwrap();
            registry.rollback_admission(admission.binding.public_id);
        }

        assert_eq!(
            registry.admit_outbound(FIRST_PEER).err(),
            Some(TransferRegistryError::LifetimeFull)
        );
        let inner = registry.inner.lock().unwrap();
        assert!(inner.entries.is_empty());
        assert!(inner.by_wire.is_empty());
        assert!(inner.terminal_history.is_empty());
        assert_eq!(inner.all_public_ids.len(), MAX_LIFETIME_TRANSFER_IDENTITIES);
        assert_eq!(inner.all_wire_ids.len(), MAX_LIFETIME_TRANSFER_IDENTITIES);
    }

    #[test]
    fn full_lifetime_ledger_allows_exact_terminal_replay_but_no_novel_identity() {
        let registry = TransferRegistry::default();
        let retained_wire = TransferId::from_bytes([71; 16]);
        let InboundAdmission::Live(retained) = registry
            .admit_inbound(FIRST_PEER, retained_wire, 0)
            .unwrap()
        else {
            panic!("initial inbound admission must be live");
        };
        registry.cancelled(retained.public_id);
        for _ in 1..MAX_LIFETIME_TRANSFER_IDENTITIES {
            let admission = registry.admit_outbound(FIRST_PEER).unwrap();
            registry.rollback_admission(admission.binding.public_id);
        }

        let before = {
            let inner = registry.inner.lock().unwrap();
            (
                inner.all_public_ids.len(),
                inner.all_wire_ids.len(),
                inner.by_wire.len(),
                inner.terminal_history.len(),
            )
        };
        assert_eq!(
            registry
                .admit_inbound(FIRST_PEER, retained_wire, 0)
                .unwrap(),
            InboundAdmission::Terminal {
                binding: retained,
                phase: TransferPhase::Cancelled,
            }
        );
        assert_eq!(
            registry
                .admit_inbound(FIRST_PEER, TransferId::from_bytes([72; 16]), 0)
                .unwrap_err(),
            TransferRegistryError::LifetimeFull
        );
        let inner = registry.inner.lock().unwrap();
        assert_eq!(
            before,
            (
                inner.all_public_ids.len(),
                inner.all_wire_ids.len(),
                inner.by_wire.len(),
                inner.terminal_history.len(),
            )
        );
    }

    #[test]
    fn public_ids_exclude_all_current_and_retired_wire_and_public_ids() {
        let registry = TransferRegistry::default();
        let admission = registry.admit_outbound(FIRST_PEER).unwrap();
        let public = admission.binding.public_id;
        let wire = Uuid::from_bytes(admission.binding.wire_id.as_bytes());
        registry.cancelled(public);
        let inner = registry.inner.lock().unwrap();
        assert!(!public_id_available(&inner, public));
        assert!(!public_id_available(&inner, wire));
        drop(inner);

        assert_eq!(
            registry
                .admit_inbound(SECOND_PEER, TransferId::from_bytes(*public.as_bytes()), 1,)
                .unwrap_err(),
            TransferRegistryError::WireIdCollision,
            "a peer wire ID may never alias any retired local public ID"
        );
    }

    #[test]
    fn inbound_is_visible_and_enters_cancel_requested_without_touching_slow_storage() {
        let registry = TransferRegistry::default();
        let wire = TransferId::from_bytes([7; 16]);
        let InboundAdmission::Live(binding) = registry.admit_inbound(FIRST_PEER, wire, 2).unwrap()
        else {
            panic!("inbound admission must be live");
        };
        assert!(matches!(
            registry.update_inbound(FIRST_PEER, wire, 1, 2, TransferPhase::Transferring),
            InboundUpdate::Updated(_)
        ));
        let outcome = registry
            .request_cancel(&binding.public_id.hyphenated().to_string())
            .unwrap();
        assert!(outcome.target.is_some());
        assert_eq!(outcome.listing.transfers[0].processed_bytes(), Some(1));
        assert_eq!(
            outcome.listing.transfers[0].phase(),
            TransferPhase::CancelRequested
        );
    }

    #[test]
    fn stale_inbound_effects_never_resurrect_a_cancelled_wire_generation() {
        let registry = TransferRegistry::default();
        let wire = TransferId::from_bytes([33; 16]);
        let InboundAdmission::Live(binding) = registry.admit_inbound(FIRST_PEER, wire, 8).unwrap()
        else {
            panic!("first inbound admission must be live");
        };
        assert!(matches!(
            registry.update_inbound(FIRST_PEER, wire, 4, 8, TransferPhase::Transferring),
            InboundUpdate::Updated(_)
        ));
        registry
            .request_cancel(&binding.public_id.hyphenated().to_string())
            .unwrap();
        registry.cancelled(binding.public_id);

        assert_eq!(
            registry.update_inbound(FIRST_PEER, wire, 8, 8, TransferPhase::Transferring),
            InboundUpdate::Terminal(binding)
        );
        assert_eq!(
            registry.admit_inbound(FIRST_PEER, wire, 8).unwrap(),
            InboundAdmission::Terminal {
                binding,
                phase: TransferPhase::Cancelled,
            }
        );
        let listing = registry.list();
        assert_eq!(listing.transfers.len(), 1);
        assert_eq!(listing.transfers[0].phase(), TransferPhase::Cancelled);
    }

    #[test]
    fn cleanup_failure_irreversibly_wins_over_cancel_requested() {
        let registry = TransferRegistry::default();
        let wire = TransferId::from_bytes([34; 16]);
        let InboundAdmission::Live(binding) = registry.admit_inbound(FIRST_PEER, wire, 8).unwrap()
        else {
            panic!("inbound admission must be live");
        };
        registry
            .request_cancel(&binding.public_id.hyphenated().to_string())
            .unwrap();
        registry.cleanup_failed(FIRST_PEER, TransferDirection::Inbound);
        registry.cancelled(binding.public_id);
        let listing = registry.list();
        assert_eq!(listing.transfers[0].phase(), TransferPhase::Failed);
        assert_eq!(
            listing.transfers[0].failure(),
            Some(TransferFailureCode::CleanupFailed)
        );
    }
}
