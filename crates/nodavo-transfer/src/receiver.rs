//! Ordered receive-side orchestration over a platform staging boundary.

use crate::{EntryKind, StagingArea, TransferChunk, TransferError, TransferId, TransferManifest};

/// Filename-free progress suitable for local status surfaces.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActiveReceiveSnapshot {
    transfer: TransferId,
    total_bytes: u64,
    completed_bytes: u64,
}

impl ActiveReceiveSnapshot {
    #[must_use]
    pub const fn transfer(self) -> TransferId {
        self.transfer
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

#[derive(Debug)]
struct ActiveReceive {
    id: TransferId,
    manifest: TransferManifest,
    next_offsets: Vec<u64>,
    completed_bytes: u64,
}

/// Owns one bounded inbound transfer and serializes staging mutations.
///
/// A peer may advertise a queue, but only the queue-selected transfer is
/// admitted here. This keeps a single staging owner and prevents many remote
/// manifests from pinning memory or filesystem state concurrently.
pub struct TransferReceiver<S> {
    staging: S,
    active: Option<ActiveReceive>,
}

impl<S> TransferReceiver<S>
where
    S: StagingArea,
{
    #[must_use]
    pub const fn new(staging: S) -> Self {
        Self {
            staging,
            active: None,
        }
    }

    #[must_use]
    pub fn snapshot(&self) -> Option<ActiveReceiveSnapshot> {
        self.active.as_ref().map(|active| ActiveReceiveSnapshot {
            transfer: active.id,
            total_bytes: active.manifest.total_bytes(),
            completed_bytes: active.completed_bytes,
        })
    }

    /// Begins exactly one validated inbound transfer.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::TransferNotActive`] when another inbound
    /// transfer owns the staging boundary, or forwards a staging failure.
    pub async fn begin(
        &mut self,
        transfer: TransferId,
        manifest: TransferManifest,
    ) -> Result<(), TransferError> {
        if self.active.is_some() {
            return Err(TransferError::TransferNotActive);
        }
        self.staging.begin(transfer, &manifest).await?;
        let next_offsets = vec![0_u64; manifest.entries().len()];
        self.active = Some(ActiveReceive {
            id: transfer,
            manifest,
            next_offsets,
            completed_bytes: 0,
        });
        Ok(())
    }

    /// Writes one nonempty chunk at the exact next offset for its file.
    ///
    /// The in-memory progress advances only after the staging implementation
    /// acknowledges its durable write.
    ///
    /// # Errors
    ///
    /// Rejects the wrong transfer, a missing/directory entry, an out-of-order
    /// chunk, overflow, or any platform staging failure.
    pub async fn write(&mut self, chunk: TransferChunk) -> Result<(), TransferError> {
        let active = self
            .active
            .as_ref()
            .filter(|active| active.id == chunk.transfer)
            .ok_or(TransferError::TransferNotActive)?;
        chunk.validate(&active.manifest)?;
        let index = usize::try_from(chunk.entry_index).map_err(|_| TransferError::InvalidChunk)?;
        let expected = active
            .next_offsets
            .get(index)
            .copied()
            .ok_or(TransferError::InvalidChunk)?;
        if chunk.offset != expected {
            return Err(TransferError::NonSequentialChunk);
        }
        let length = u64::try_from(chunk.bytes.len()).map_err(|_| TransferError::InvalidChunk)?;
        let next = expected
            .checked_add(length)
            .ok_or(TransferError::InvalidChunk)?;

        self.staging.write(chunk).await?;
        let active = self
            .active
            .as_mut()
            .ok_or(TransferError::TransferNotActive)?;
        active.next_offsets[index] = next;
        active.completed_bytes = active
            .completed_bytes
            .checked_add(length)
            .ok_or(TransferError::InvalidChunk)?;
        Ok(())
    }

    /// Verifies exact completion and atomically publishes staged entries.
    ///
    /// # Errors
    ///
    /// Rejects the wrong transfer or incomplete files and forwards integrity,
    /// destination, or platform failures from the staging implementation.
    pub async fn complete(&mut self, transfer: TransferId) -> Result<(), TransferError> {
        let active = self
            .active
            .as_ref()
            .filter(|active| active.id == transfer)
            .ok_or(TransferError::TransferNotActive)?;
        let complete = active
            .manifest
            .entries()
            .iter()
            .zip(&active.next_offsets)
            .all(|(entry, offset)| match entry.kind {
                EntryKind::File => *offset == entry.size,
                EntryKind::Directory => *offset == 0,
            });
        if !complete || active.completed_bytes != active.manifest.total_bytes() {
            return Err(TransferError::IncompleteTransfer);
        }
        self.staging.finalize(transfer).await?;
        self.active = None;
        Ok(())
    }

    /// Explicitly discards the currently active transfer and its staged data.
    ///
    /// # Errors
    ///
    /// Rejects a cancellation for any transfer other than the active one.
    pub fn cancel(&mut self, transfer: TransferId) -> Result<(), TransferError> {
        if self.active.as_ref().map(|active| active.id) != Some(transfer) {
            return Err(TransferError::TransferNotActive);
        }
        self.staging.abort(transfer);
        self.active = None;
        Ok(())
    }

    #[must_use]
    pub fn into_staging(self) -> S {
        self.staging
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;
    use crate::{ContentHash, ManifestEntry, RelativePath, TransferFuture};

    #[derive(Default)]
    struct MemoryStaging {
        active: Option<TransferId>,
        bytes: Vec<u8>,
        finalized: bool,
        aborted: bool,
    }

    impl StagingArea for MemoryStaging {
        fn begin<'a>(
            &'a mut self,
            transfer: TransferId,
            _manifest: &'a TransferManifest,
        ) -> TransferFuture<'a, Result<(), TransferError>> {
            Box::pin(async move {
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
                self.finalized = true;
                Ok(())
            })
        }

        fn abort(&mut self, transfer: TransferId) {
            if self.active.take() == Some(transfer) {
                self.aborted = true;
            }
        }
    }

    fn manifest(bytes: &[u8]) -> TransferManifest {
        TransferManifest::new(vec![ManifestEntry {
            path: RelativePath::parse("received.bin").unwrap(),
            kind: EntryKind::File,
            size: u64::try_from(bytes.len()).unwrap(),
            hash: Some(ContentHash::digest(bytes)),
        }])
        .unwrap()
    }

    #[tokio::test]
    async fn advances_only_acknowledged_exact_chunks_and_finalizes() {
        let transfer = TransferId::from_bytes([7; 16]);
        let mut receiver = TransferReceiver::new(MemoryStaging::default());
        receiver.begin(transfer, manifest(b"hello")).await.unwrap();
        receiver
            .write(TransferChunk {
                transfer,
                entry_index: 0,
                offset: 0,
                bytes: Bytes::from_static(b"he"),
            })
            .await
            .unwrap();
        assert_eq!(receiver.snapshot().unwrap().completed_bytes(), 2);
        assert_eq!(
            receiver
                .write(TransferChunk {
                    transfer,
                    entry_index: 0,
                    offset: 1,
                    bytes: Bytes::from_static(b"llo"),
                })
                .await,
            Err(TransferError::NonSequentialChunk)
        );
        assert_eq!(
            receiver.complete(transfer).await,
            Err(TransferError::IncompleteTransfer)
        );
        receiver
            .write(TransferChunk {
                transfer,
                entry_index: 0,
                offset: 2,
                bytes: Bytes::from_static(b"llo"),
            })
            .await
            .unwrap();
        receiver.complete(transfer).await.unwrap();
        let staging = receiver.into_staging();
        assert_eq!(staging.bytes, b"hello");
        assert!(staging.finalized);
        assert!(!staging.aborted);
    }

    #[tokio::test]
    async fn rejects_parallel_work_and_cancels_only_the_active_transfer() {
        let transfer = TransferId::from_bytes([1; 16]);
        let other = TransferId::from_bytes([2; 16]);
        let mut receiver = TransferReceiver::new(MemoryStaging::default());
        receiver.begin(transfer, manifest(b"x")).await.unwrap();
        assert_eq!(
            receiver.begin(other, manifest(b"y")).await,
            Err(TransferError::TransferNotActive)
        );
        assert_eq!(
            receiver.cancel(other),
            Err(TransferError::TransferNotActive)
        );
        receiver.cancel(transfer).unwrap();
        let staging = receiver.into_staging();
        assert!(staging.aborted);
        assert!(!staging.finalized);
    }
}
