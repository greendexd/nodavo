//! Deterministic bounded scheduling for transfer orchestration.

use std::collections::{HashMap, VecDeque};

use crate::{TransferError, TransferId};

/// Maximum transfers retained by one queue, including active and paused work.
pub const MAX_QUEUED_TRANSFERS: usize = 128;
/// Hard maximum concurrent transfers allowed by the queue reducer.
pub const MAX_ACTIVE_TRANSFERS: usize = 4;

/// Lifecycle state of one queued transfer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransferQueueState {
    Queued,
    Active,
    Paused,
    Completed,
    Cancelled,
    Failed,
}

/// Public progress snapshot without filenames or content metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueuedTransfer {
    id: TransferId,
    state: TransferQueueState,
    total_bytes: u64,
    completed_bytes: u64,
}

impl QueuedTransfer {
    #[must_use]
    pub const fn id(self) -> TransferId {
        self.id
    }

    #[must_use]
    pub const fn state(self) -> TransferQueueState {
        self.state
    }

    #[must_use]
    pub const fn total_bytes(self) -> u64 {
        self.total_bytes
    }

    #[must_use]
    pub const fn completed_bytes(self) -> u64 {
        self.completed_bytes
    }
}

/// Commands for the network/staging owner emitted by queue transitions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueueEffect {
    Start(TransferId),
    Pause(TransferId),
    Cancel(TransferId),
}

/// Pure FIFO scheduler with bounded retained and active transfer counts.
#[derive(Debug)]
pub struct TransferQueue {
    maximum_active: usize,
    entries: HashMap<TransferId, QueuedTransfer>,
    waiting: VecDeque<TransferId>,
    active_count: usize,
}

impl TransferQueue {
    /// Creates a queue with a bounded concurrency limit.
    ///
    /// # Errors
    ///
    /// Rejects zero or values above [`MAX_ACTIVE_TRANSFERS`].
    pub fn new(maximum_active: usize) -> Result<Self, TransferError> {
        if maximum_active == 0 || maximum_active > MAX_ACTIVE_TRANSFERS {
            return Err(TransferError::InvalidQueueTransition);
        }
        Ok(Self {
            maximum_active,
            entries: HashMap::new(),
            waiting: VecDeque::new(),
            active_count: 0,
        })
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[must_use]
    pub const fn active_count(&self) -> usize {
        self.active_count
    }

    #[must_use]
    pub fn get(&self, transfer: TransferId) -> Option<QueuedTransfer> {
        self.entries.get(&transfer).copied()
    }

    /// Adds a transfer and immediately fills any available active slot.
    ///
    /// # Errors
    ///
    /// Rejects duplicate IDs, zero/oversized transfers, and a full queue.
    pub fn enqueue(
        &mut self,
        transfer: TransferId,
        total_bytes: u64,
    ) -> Result<Vec<QueueEffect>, TransferError> {
        if self.entries.contains_key(&transfer) {
            return Err(TransferError::DuplicateTransfer);
        }
        if self.entries.len() >= MAX_QUEUED_TRANSFERS {
            return Err(TransferError::QueueFull);
        }
        if total_bytes > crate::MAX_TRANSFER_BYTES {
            return Err(TransferError::TransferTooLarge);
        }
        self.entries.insert(
            transfer,
            QueuedTransfer {
                id: transfer,
                state: TransferQueueState::Queued,
                total_bytes,
                completed_bytes: 0,
            },
        );
        self.waiting.push_back(transfer);
        Ok(self.fill_active_slots())
    }

    /// Advances exact monotonic progress for an active transfer.
    ///
    /// # Errors
    ///
    /// Rejects missing/non-active transfers, regressions, and values above the
    /// declared total.
    pub fn record_progress(
        &mut self,
        transfer: TransferId,
        completed_bytes: u64,
    ) -> Result<(), TransferError> {
        let entry = self
            .entries
            .get_mut(&transfer)
            .ok_or(TransferError::TransferNotActive)?;
        if entry.state != TransferQueueState::Active
            || completed_bytes < entry.completed_bytes
            || completed_bytes > entry.total_bytes
        {
            return Err(TransferError::InvalidQueueTransition);
        }
        entry.completed_bytes = completed_bytes;
        Ok(())
    }

    /// Marks a fully received active transfer completed and starts queued work.
    ///
    /// # Errors
    ///
    /// Rejects missing/non-active transfers and incomplete byte progress.
    pub fn complete(&mut self, transfer: TransferId) -> Result<Vec<QueueEffect>, TransferError> {
        let entry = self.active_mut(transfer)?;
        if entry.completed_bytes != entry.total_bytes {
            return Err(TransferError::InvalidQueueTransition);
        }
        entry.state = TransferQueueState::Completed;
        self.active_count = self.active_count.saturating_sub(1);
        Ok(self.fill_active_slots())
    }

    /// Pauses active work without discarding durable staging progress.
    ///
    /// # Errors
    ///
    /// Rejects a transfer that is missing or not active.
    pub fn pause(&mut self, transfer: TransferId) -> Result<Vec<QueueEffect>, TransferError> {
        let entry = self.active_mut(transfer)?;
        entry.state = TransferQueueState::Paused;
        self.active_count = self.active_count.saturating_sub(1);
        let mut effects = vec![QueueEffect::Pause(transfer)];
        effects.extend(self.fill_active_slots());
        Ok(effects)
    }

    /// Places paused work at the tail and fills active slots in FIFO order.
    ///
    /// # Errors
    ///
    /// Rejects a transfer that is missing or not paused.
    pub fn resume(&mut self, transfer: TransferId) -> Result<Vec<QueueEffect>, TransferError> {
        let entry = self
            .entries
            .get_mut(&transfer)
            .ok_or(TransferError::TransferNotActive)?;
        if entry.state != TransferQueueState::Paused {
            return Err(TransferError::InvalidQueueTransition);
        }
        entry.state = TransferQueueState::Queued;
        self.waiting.push_back(transfer);
        Ok(self.fill_active_slots())
    }

    /// Cancels queued, active, or paused work and schedules the next transfer.
    ///
    /// # Errors
    ///
    /// Rejects missing or already-terminal transfers.
    pub fn cancel(&mut self, transfer: TransferId) -> Result<Vec<QueueEffect>, TransferError> {
        let entry = self
            .entries
            .get_mut(&transfer)
            .ok_or(TransferError::TransferNotActive)?;
        if matches!(
            entry.state,
            TransferQueueState::Completed
                | TransferQueueState::Cancelled
                | TransferQueueState::Failed
        ) {
            return Err(TransferError::InvalidQueueTransition);
        }
        let was_active = entry.state == TransferQueueState::Active;
        entry.state = TransferQueueState::Cancelled;
        if was_active {
            self.active_count = self.active_count.saturating_sub(1);
        }
        self.waiting.retain(|queued| *queued != transfer);
        let mut effects = vec![QueueEffect::Cancel(transfer)];
        effects.extend(self.fill_active_slots());
        Ok(effects)
    }

    /// Marks active work failed and schedules the next transfer.
    ///
    /// # Errors
    ///
    /// Rejects a transfer that is missing or not active.
    pub fn fail(&mut self, transfer: TransferId) -> Result<Vec<QueueEffect>, TransferError> {
        let entry = self.active_mut(transfer)?;
        entry.state = TransferQueueState::Failed;
        self.active_count = self.active_count.saturating_sub(1);
        Ok(self.fill_active_slots())
    }

    /// Removes terminal entries from retained history.
    ///
    /// # Errors
    ///
    /// Rejects missing or non-terminal transfers.
    pub fn remove_terminal(&mut self, transfer: TransferId) -> Result<(), TransferError> {
        let entry = self
            .entries
            .get(&transfer)
            .ok_or(TransferError::TransferNotActive)?;
        if !matches!(
            entry.state,
            TransferQueueState::Completed
                | TransferQueueState::Cancelled
                | TransferQueueState::Failed
        ) {
            return Err(TransferError::InvalidQueueTransition);
        }
        self.entries.remove(&transfer);
        Ok(())
    }

    fn active_mut(&mut self, transfer: TransferId) -> Result<&mut QueuedTransfer, TransferError> {
        self.entries
            .get_mut(&transfer)
            .filter(|entry| entry.state == TransferQueueState::Active)
            .ok_or(TransferError::TransferNotActive)
    }

    fn fill_active_slots(&mut self) -> Vec<QueueEffect> {
        let mut effects = Vec::new();
        while self.active_count < self.maximum_active {
            let Some(transfer) = self.waiting.pop_front() else {
                break;
            };
            let Some(entry) = self.entries.get_mut(&transfer) else {
                continue;
            };
            if entry.state != TransferQueueState::Queued {
                continue;
            }
            entry.state = TransferQueueState::Active;
            self.active_count += 1;
            effects.push(QueueEffect::Start(transfer));
        }
        effects
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fifo_pause_resume_cancel_and_completion_are_bounded() {
        let mut queue = TransferQueue::new(1).unwrap();
        let first = TransferId::new();
        let second = TransferId::new();
        assert_eq!(
            queue.enqueue(first, 10).unwrap(),
            [QueueEffect::Start(first)]
        );
        assert!(queue.enqueue(second, 20).unwrap().is_empty());
        assert_eq!(
            queue.pause(first).unwrap(),
            [QueueEffect::Pause(first), QueueEffect::Start(second)]
        );
        assert!(queue.resume(first).unwrap().is_empty());
        queue.record_progress(second, 20).unwrap();
        assert_eq!(queue.complete(second).unwrap(), [QueueEffect::Start(first)]);
        assert_eq!(queue.cancel(first).unwrap(), [QueueEffect::Cancel(first)]);
        assert_eq!(queue.active_count(), 0);
    }

    #[test]
    fn progress_is_monotonic_and_terminal_history_is_explicit() {
        let mut queue = TransferQueue::new(2).unwrap();
        let transfer = TransferId::new();
        queue.enqueue(transfer, 5).unwrap();
        queue.record_progress(transfer, 3).unwrap();
        assert_eq!(
            queue.record_progress(transfer, 2),
            Err(TransferError::InvalidQueueTransition)
        );
        queue.record_progress(transfer, 5).unwrap();
        queue.complete(transfer).unwrap();
        assert_eq!(
            queue.get(transfer).unwrap().state(),
            TransferQueueState::Completed
        );
        queue.remove_terminal(transfer).unwrap();
        assert!(queue.is_empty());
    }
}
