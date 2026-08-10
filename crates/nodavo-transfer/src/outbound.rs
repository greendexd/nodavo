//! Deterministic, capability-rooted outbound filesystem scanning and streaming.

mod platform;

use std::collections::{HashSet, VecDeque};
use std::ffi::{OsStr, OsString};
use std::io::Read;
use std::path::{Path, PathBuf};

use bytes::Bytes;
use cap_std::ambient_authority;
use cap_std::fs::{Dir, File};

use self::platform::{FileIdentity, StableEvidence};
use crate::{
    ContentHash, EntryKind, MAX_CHUNK_BYTES, MAX_MANIFEST_BYTES, MAX_MANIFEST_ENTRIES,
    MAX_TRANSFER_BYTES, ManifestEntry, RelativePath, TransferChunk, TransferError, TransferId,
    TransferManifest,
};

const MAX_SELECTED_ROOTS: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutboundResumePoint {
    transfer: TransferId,
    entry_index: u32,
    offset: u64,
}

impl OutboundResumePoint {
    #[must_use]
    pub const fn new(transfer: TransferId, entry_index: u32, offset: u64) -> Self {
        Self {
            transfer,
            entry_index,
            offset,
        }
    }

    #[must_use]
    pub const fn transfer(self) -> TransferId {
        self.transfer
    }

    #[must_use]
    pub const fn entry_index(self) -> u32 {
        self.entry_index
    }

    #[must_use]
    pub const fn offset(self) -> u64 {
        self.offset
    }
}

struct SourceFile {
    root_index: usize,
    components: Vec<OsString>,
    evidence: StableEvidence,
    prefix_hashes: Vec<(u64, ContentHash)>,
}

struct ScannedEntry {
    manifest: ManifestEntry,
    source: Option<SourceFile>,
}

struct PendingDirectory {
    root_index: usize,
    components: Vec<OsString>,
    manifest_path: RelativePath,
    identity: FileIdentity,
}

struct ActiveFile {
    entry_index: usize,
    file: File,
    evidence: StableEvidence,
    offset: u64,
    hasher: blake3::Hasher,
}

/// A one-transfer, pull-based source over an authenticated deterministic manifest.
///
/// The source holds one capability directory per explicit selected root and at
/// most one active content file. Each descendant component is reopened without
/// following links, so cancellation or drop does not retain a descriptor per
/// manifest entry.
pub struct OutboundTransferSource {
    transfer: TransferId,
    manifest: TransferManifest,
    roots: Vec<Dir>,
    files: Vec<Option<SourceFile>>,
    next_entry: usize,
    active: Option<ActiveFile>,
    failed_or_cancelled: bool,
}

impl std::fmt::Debug for OutboundTransferSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OutboundTransferSource")
            .field("transfer", &self.transfer)
            .field("entries", &self.manifest.entries().len())
            .field("next_entry", &self.next_entry)
            .field(
                "active",
                &self.active.as_ref().map(|active| active.entry_index),
            )
            .field("failed_or_cancelled", &self.failed_or_cancelled)
            .finish_non_exhaustive()
    }
}

impl OutboundTransferSource {
    /// Scans explicit regular files and directories into a deterministic manifest.
    ///
    /// # Errors
    ///
    /// Rejects empty/overlapping selections, non-Unicode or unsafe names,
    /// links/reparse points, sparse or special files, cycles, source mutation,
    /// collisions, and all manifest or aggregate limits.
    pub fn scan<I, P>(transfer: TransferId, sources: I) -> Result<Self, TransferError>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        Self::scan_with_cancel(transfer, sources, || false)
    }

    /// Scans sources while cooperatively polling a cancellation callback.
    ///
    /// The callback is checked before opening each selected root, before and
    /// during directory enumeration, and at every bounded file-hash chunk.
    /// Returning `true` aborts without constructing a partial source.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::Cancelled`] when the callback requests
    /// cancellation, in addition to the validation failures documented by
    /// [`Self::scan`].
    pub fn scan_with_cancel<I, P, C>(
        transfer: TransferId,
        sources: I,
        mut is_cancelled: C,
    ) -> Result<Self, TransferError>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
        C: FnMut() -> bool,
    {
        let selected = prepare_roots(sources, &mut is_cancelled)?;
        let mut scanned = Vec::new();
        let mut directories = VecDeque::new();
        let mut entity_identities = HashSet::new();
        let mut aggregate_bytes = 0_u64;
        let mut manifest_bytes = 0_usize;
        let mut roots = Vec::with_capacity(selected.len());

        for root in selected {
            check_cancelled(&mut is_cancelled)?;
            let root_index = roots.len();
            let root_name = unicode_name(&root.name)?;
            let manifest_path = RelativePath::parse(root_name)?;
            match root.entity {
                OpenedEntity::File(file) => {
                    roots.push(root.anchor);
                    scan_file(
                        file,
                        root_index,
                        vec![root.name],
                        manifest_path,
                        &mut scanned,
                        &mut aggregate_bytes,
                        &mut manifest_bytes,
                        &mut entity_identities,
                        &mut is_cancelled,
                    )?;
                }
                OpenedEntity::Directory(directory) => {
                    let identity = platform::directory_identity(&directory)?;
                    if !entity_identities.insert(identity) {
                        return Err(TransferError::SourceCycle);
                    }
                    push_directory(&mut scanned, manifest_path.clone(), &mut manifest_bytes)?;
                    roots.push(root.anchor);
                    directories.push_back(PendingDirectory {
                        root_index,
                        components: Vec::new(),
                        manifest_path,
                        identity,
                    });
                }
            }
        }

        while let Some(pending) = directories.pop_front() {
            check_cancelled(&mut is_cancelled)?;
            scan_directory(
                &roots,
                &pending,
                &mut scanned,
                &mut directories,
                &mut entity_identities,
                &mut aggregate_bytes,
                &mut manifest_bytes,
                &mut is_cancelled,
            )?;
        }

        check_cancelled(&mut is_cancelled)?;
        scanned.sort_by(|left, right| {
            left.manifest
                .path
                .as_str()
                .cmp(right.manifest.path.as_str())
        });
        check_cancelled(&mut is_cancelled)?;
        let entries = scanned.iter().map(|entry| entry.manifest.clone()).collect();
        let manifest = TransferManifest::new(entries)?;
        let files = scanned.into_iter().map(|entry| entry.source).collect();
        Ok(Self {
            transfer,
            manifest,
            roots,
            files,
            next_entry: 0,
            active: None,
            failed_or_cancelled: false,
        })
    }

    #[must_use]
    pub const fn transfer(&self) -> TransferId {
        self.transfer
    }

    #[must_use]
    pub const fn manifest(&self) -> &TransferManifest {
        &self.manifest
    }

    /// Cancels the source and synchronously closes its active content handle.
    pub fn cancel(&mut self) {
        self.active = None;
        self.failed_or_cancelled = true;
    }

    /// Repositions to an authenticated exact manifest entry and source offset.
    ///
    /// Offsets must be source chunk boundaries (or exact EOF). The complete
    /// prefix is re-read, checked against scan-time prefix evidence, and fed
    /// into the continuing BLAKE3 state before any resumed chunk is returned.
    ///
    /// # Errors
    ///
    /// Rejects another transfer, invalid entry/offset, or any source mutation.
    pub fn resume(&mut self, point: OutboundResumePoint) -> Result<(), TransferError> {
        if self.failed_or_cancelled {
            return Err(TransferError::Cancelled);
        }
        if point.transfer != self.transfer {
            return Err(TransferError::InvalidResumeState);
        }
        let index =
            usize::try_from(point.entry_index).map_err(|_| TransferError::InvalidResumeState)?;
        let entry = self
            .manifest
            .entries()
            .get(index)
            .ok_or(TransferError::InvalidResumeState)?;
        self.active = None;
        if entry.kind == EntryKind::Directory {
            if point.offset != 0 {
                return Err(TransferError::InvalidResumeState);
            }
            self.next_entry = index + 1;
            return Ok(());
        }
        let result = self.prepare_file(index, point.offset);
        if result.is_err() {
            self.failed_or_cancelled = true;
            self.active = None;
        }
        result
    }

    /// Pulls the next bounded sequential chunk, yielding `None` at completion.
    ///
    /// # Errors
    ///
    /// Fails closed if the source was cancelled or if identity, size,
    /// modification time, prefix evidence, or the final BLAKE3 hash differs.
    pub fn next_chunk(&mut self) -> Result<Option<TransferChunk>, TransferError> {
        if self.failed_or_cancelled {
            return Err(TransferError::Cancelled);
        }
        let result = self.next_chunk_inner();
        if result.is_err() {
            self.active = None;
            self.failed_or_cancelled = true;
        }
        result
    }

    fn next_chunk_inner(&mut self) -> Result<Option<TransferChunk>, TransferError> {
        loop {
            if self.active.is_none() {
                while self.next_entry < self.files.len() && self.files[self.next_entry].is_none() {
                    self.next_entry += 1;
                }
                if self.next_entry == self.files.len() {
                    return Ok(None);
                }
                self.prepare_file(self.next_entry, 0)?;
                if self.active.is_none() {
                    continue;
                }
            }

            let (entry_index, offset, bytes, finished) = {
                let active = self.active.as_mut().ok_or(TransferError::SourceChanged)?;
                let source = self.files[active.entry_index]
                    .as_ref()
                    .ok_or(TransferError::SourceChanged)?;
                require_evidence(&active.file, source.evidence)?;
                let remaining = source
                    .evidence
                    .size
                    .checked_sub(active.offset)
                    .ok_or(TransferError::SourceChanged)?;
                let chunk_len = usize::try_from(remaining.min(MAX_CHUNK_BYTES as u64))
                    .map_err(|_| TransferError::SourceChanged)?;
                if chunk_len == 0 {
                    return Err(TransferError::SourceChanged);
                }
                let mut bytes = vec![0_u8; chunk_len];
                active
                    .file
                    .read_exact(&mut bytes)
                    .map_err(|_| TransferError::SourceChanged)?;
                active.hasher.update(&bytes);
                let offset = active.offset;
                active.offset = active
                    .offset
                    .checked_add(
                        u64::try_from(bytes.len()).map_err(|_| TransferError::SourceChanged)?,
                    )
                    .ok_or(TransferError::SourceChanged)?;
                require_evidence(&active.file, source.evidence)?;
                let finished = active.offset == source.evidence.size;
                if finished {
                    finish_active(&self.manifest, source, active)?;
                }
                (active.entry_index, offset, bytes, finished)
            };
            if finished {
                self.active = None;
                self.next_entry += 1;
            }
            return Ok(Some(TransferChunk {
                transfer: self.transfer,
                entry_index: u32::try_from(entry_index)
                    .map_err(|_| TransferError::SourceChanged)?,
                offset,
                bytes: Bytes::from(bytes),
            }));
        }
    }

    fn prepare_file(&mut self, index: usize, offset: u64) -> Result<(), TransferError> {
        let source = self.files[index]
            .as_ref()
            .ok_or(TransferError::InvalidResumeState)?;
        if offset > source.evidence.size {
            return Err(TransferError::InvalidResumeState);
        }
        let expected_prefix = source
            .prefix_hashes
            .iter()
            .find_map(|(boundary, hash)| (*boundary == offset).then_some(*hash))
            .ok_or(TransferError::InvalidResumeState)?;
        let root = self
            .roots
            .get(source.root_index)
            .ok_or(TransferError::SourceChanged)?;
        let mut file = open_relative_file(root, &source.components)?;
        require_evidence(&file, source.evidence)?;
        let mut hasher = blake3::Hasher::new();
        hash_exact_prefix(&mut file, offset, &mut hasher)?;
        if ContentHash::from_bytes(*hasher.clone().finalize().as_bytes()) != expected_prefix {
            return Err(TransferError::SourceChanged);
        }
        require_evidence(&file, source.evidence)?;
        let active = ActiveFile {
            entry_index: index,
            file,
            evidence: source.evidence,
            offset,
            hasher,
        };
        if offset == source.evidence.size {
            finish_active(&self.manifest, source, &active)?;
            self.next_entry = index + 1;
        } else {
            self.next_entry = index;
            self.active = Some(active);
        }
        Ok(())
    }
}

struct SelectedRoot {
    canonical: PathBuf,
    name: OsString,
    anchor: Dir,
    entity: OpenedEntity,
}

fn open_selected_root(path: &Path) -> Result<SelectedRoot, TransferError> {
    open_selected_root_with_hook(path, || {})
}

fn open_selected_root_with_hook(
    path: &Path,
    mut after_anchor: impl FnMut(),
) -> Result<SelectedRoot, TransferError> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| TransferError::InvalidSource)?
            .join(path)
    };
    let name = absolute
        .file_name()
        .ok_or(TransferError::UnsafeSourceRoots)?
        .to_os_string();
    let parent_path = absolute.parent().ok_or(TransferError::UnsafeSourceRoots)?;
    let parent = Dir::open_ambient_dir(parent_path, ambient_authority())
        .map_err(|_| TransferError::InvalidSource)?;
    let entity = open_relative_entity(&parent, std::slice::from_ref(&name))?;
    after_anchor();

    let canonical = absolute
        .canonicalize()
        .map_err(|_| TransferError::InvalidSource)?;
    let canonical_name = canonical
        .file_name()
        .ok_or(TransferError::UnsafeSourceRoots)?;
    let canonical_parent = Dir::open_ambient_dir(
        canonical.parent().ok_or(TransferError::UnsafeSourceRoots)?,
        ambient_authority(),
    )
    .map_err(|_| TransferError::InvalidSource)?;
    let canonical_entity =
        open_relative_entity(&canonical_parent, &[canonical_name.to_os_string()])?;
    if !same_entity(&entity, &canonical_entity)? {
        return Err(TransferError::SourceChanged);
    }

    let anchor = match &entity {
        OpenedEntity::File(_) => parent,
        OpenedEntity::Directory(directory) => directory
            .try_clone()
            .map_err(|_| TransferError::InvalidSource)?,
    };
    Ok(SelectedRoot {
        canonical,
        name,
        anchor,
        entity,
    })
}

fn same_entity(left: &OpenedEntity, right: &OpenedEntity) -> Result<bool, TransferError> {
    match (left, right) {
        (OpenedEntity::File(left), OpenedEntity::File(right)) => {
            Ok(platform::file_evidence(left)? == platform::file_evidence(right)?)
        }
        (OpenedEntity::Directory(left), OpenedEntity::Directory(right)) => {
            Ok(platform::directory_identity(left)? == platform::directory_identity(right)?)
        }
        _ => Ok(false),
    }
}

fn check_cancelled(is_cancelled: &mut impl FnMut() -> bool) -> Result<(), TransferError> {
    if is_cancelled() {
        Err(TransferError::Cancelled)
    } else {
        Ok(())
    }
}

fn prepare_roots<I, P, C>(
    sources: I,
    is_cancelled: &mut C,
) -> Result<Vec<SelectedRoot>, TransferError>
where
    I: IntoIterator<Item = P>,
    P: AsRef<Path>,
    C: FnMut() -> bool,
{
    let mut selected = Vec::new();
    for source in sources {
        check_cancelled(is_cancelled)?;
        if selected.len() >= MAX_SELECTED_ROOTS {
            return Err(TransferError::InvalidSource);
        }
        selected.push(open_selected_root(source.as_ref())?);
    }
    if selected.is_empty() {
        return Err(TransferError::InvalidSource);
    }
    check_cancelled(is_cancelled)?;
    selected.sort_by(|left, right| left.canonical.cmp(&right.canonical));
    check_cancelled(is_cancelled)?;
    for pair in selected.windows(2) {
        let left = &pair[0].canonical;
        let right = &pair[1].canonical;
        if left == right || right.starts_with(left) {
            return Err(TransferError::UnsafeSourceRoots);
        }
    }
    Ok(selected)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn scan_directory<C>(
    roots: &[Dir],
    pending: &PendingDirectory,
    scanned: &mut Vec<ScannedEntry>,
    directories: &mut VecDeque<PendingDirectory>,
    entity_identities: &mut HashSet<FileIdentity>,
    aggregate_bytes: &mut u64,
    manifest_bytes: &mut usize,
    is_cancelled: &mut C,
) -> Result<(), TransferError>
where
    C: FnMut() -> bool,
{
    let root = roots
        .get(pending.root_index)
        .ok_or(TransferError::SourceChanged)?;
    let directory = open_rooted_directory(root, &pending.components)?;
    if platform::directory_identity(&directory)? != pending.identity {
        return Err(TransferError::SourceChanged);
    }
    let available = MAX_MANIFEST_ENTRIES.saturating_sub(scanned.len());
    let children = enumerate_children(&directory, &pending.manifest_path, available, is_cancelled)?;

    for (manifest_path, raw_name) in children {
        check_cancelled(is_cancelled)?;
        let mut components = pending.components.clone();
        components.push(raw_name.clone());
        match open_relative_entity(&directory, &[raw_name])? {
            OpenedEntity::File(file) => {
                scan_file(
                    file,
                    pending.root_index,
                    components,
                    manifest_path,
                    scanned,
                    aggregate_bytes,
                    manifest_bytes,
                    entity_identities,
                    is_cancelled,
                )?;
            }
            OpenedEntity::Directory(child) => {
                let identity = platform::directory_identity(&child)?;
                if !entity_identities.insert(identity) {
                    return Err(TransferError::SourceCycle);
                }
                push_directory(scanned, manifest_path.clone(), manifest_bytes)?;
                directories.push_back(PendingDirectory {
                    root_index: pending.root_index,
                    components,
                    manifest_path,
                    identity,
                });
            }
        }
    }
    Ok(())
}

fn open_rooted_directory(root: &Dir, components: &[OsString]) -> Result<Dir, TransferError> {
    if components.is_empty() {
        root.try_clone().map_err(|_| TransferError::InvalidSource)
    } else {
        let (parent, name) = open_parent(root, components)?;
        platform::open_dir_no_follow(&parent, name)
    }
}

fn enumerate_children<C>(
    directory: &Dir,
    manifest_path: &RelativePath,
    limit: usize,
    is_cancelled: &mut C,
) -> Result<Vec<(RelativePath, OsString)>, TransferError>
where
    C: FnMut() -> bool,
{
    check_cancelled(is_cancelled)?;
    let mut children = Vec::new();
    for entry in directory
        .entries()
        .map_err(|_| TransferError::InvalidSource)?
    {
        check_cancelled(is_cancelled)?;
        if children.len() >= limit {
            return Err(TransferError::InvalidManifest);
        }
        let entry = entry.map_err(|_| TransferError::InvalidSource)?;
        let raw_name = entry.file_name();
        let unicode = unicode_name(&raw_name)?;
        let normalized_path =
            RelativePath::parse(&format!("{}/{}", manifest_path.as_str(), unicode))?;
        children.push((normalized_path, raw_name));
    }
    children.sort_by(|left, right| left.0.as_str().cmp(right.0.as_str()));
    Ok(children)
}

fn push_directory(
    scanned: &mut Vec<ScannedEntry>,
    manifest_path: RelativePath,
    manifest_bytes: &mut usize,
) -> Result<(), TransferError> {
    reserve_manifest_entry(scanned.len(), &manifest_path, manifest_bytes)?;
    scanned.push(ScannedEntry {
        manifest: ManifestEntry {
            path: manifest_path,
            kind: EntryKind::Directory,
            size: 0,
            hash: None,
        },
        source: None,
    });
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn scan_file<C>(
    mut file: File,
    root_index: usize,
    components: Vec<OsString>,
    manifest_path: RelativePath,
    scanned: &mut Vec<ScannedEntry>,
    aggregate_bytes: &mut u64,
    manifest_bytes: &mut usize,
    entity_identities: &mut HashSet<FileIdentity>,
    is_cancelled: &mut C,
) -> Result<(), TransferError>
where
    C: FnMut() -> bool,
{
    check_cancelled(is_cancelled)?;
    reserve_manifest_entry(scanned.len(), &manifest_path, manifest_bytes)?;
    let evidence = platform::file_evidence(&file)?;
    if !entity_identities.insert(evidence.identity) {
        return Err(TransferError::SourceCycle);
    }
    *aggregate_bytes = aggregate_bytes
        .checked_add(evidence.size)
        .ok_or(TransferError::TransferTooLarge)?;
    if *aggregate_bytes > MAX_TRANSFER_BYTES {
        return Err(TransferError::TransferTooLarge);
    }
    let (hash, prefix_hashes) = hash_file(&mut file, evidence, is_cancelled)?;
    scanned.push(ScannedEntry {
        manifest: ManifestEntry {
            path: manifest_path,
            kind: EntryKind::File,
            size: evidence.size,
            hash: Some(hash),
        },
        source: Some(SourceFile {
            root_index,
            components,
            evidence,
            prefix_hashes,
        }),
    });
    Ok(())
}

fn reserve_manifest_entry(
    entry_count: usize,
    path: &RelativePath,
    manifest_bytes: &mut usize,
) -> Result<(), TransferError> {
    if entry_count >= MAX_MANIFEST_ENTRIES {
        return Err(TransferError::InvalidManifest);
    }
    let next = manifest_bytes
        .checked_add(path.as_str().len() + 64)
        .ok_or(TransferError::ManifestTooLarge)?;
    if next > MAX_MANIFEST_BYTES {
        return Err(TransferError::ManifestTooLarge);
    }
    *manifest_bytes = next;
    Ok(())
}

fn hash_file<C>(
    file: &mut File,
    evidence: StableEvidence,
    is_cancelled: &mut C,
) -> Result<(ContentHash, Vec<(u64, ContentHash)>), TransferError>
where
    C: FnMut() -> bool,
{
    check_cancelled(is_cancelled)?;
    let mut hasher = blake3::Hasher::new();
    let mut prefix_hashes = vec![(
        0,
        ContentHash::from_bytes(*hasher.clone().finalize().as_bytes()),
    )];
    let mut offset = 0_u64;
    let mut buffer = vec![0_u8; MAX_CHUNK_BYTES];
    while offset < evidence.size {
        check_cancelled(is_cancelled)?;
        require_evidence(file, evidence)?;
        let remaining = evidence.size - offset;
        let read_len = usize::try_from(remaining.min(MAX_CHUNK_BYTES as u64))
            .map_err(|_| TransferError::SourceChanged)?;
        file.read_exact(&mut buffer[..read_len])
            .map_err(|_| TransferError::SourceChanged)?;
        hasher.update(&buffer[..read_len]);
        offset = offset
            .checked_add(u64::try_from(read_len).map_err(|_| TransferError::SourceChanged)?)
            .ok_or(TransferError::SourceChanged)?;
        prefix_hashes.push((
            offset,
            ContentHash::from_bytes(*hasher.clone().finalize().as_bytes()),
        ));
        check_cancelled(is_cancelled)?;
    }
    require_evidence(file, evidence)?;
    Ok((
        ContentHash::from_bytes(*hasher.finalize().as_bytes()),
        prefix_hashes,
    ))
}

enum OpenedEntity {
    File(File),
    Directory(Dir),
}

fn open_relative_entity(
    base: &Dir,
    components: &[OsString],
) -> Result<OpenedEntity, TransferError> {
    let (parent, name) = open_parent(base, components)?;
    let metadata = parent
        .symlink_metadata(name)
        .map_err(|_| TransferError::InvalidSource)?;
    if metadata.file_type().is_symlink() {
        return Err(TransferError::UnsafeSourceType);
    }
    if metadata.is_file() {
        platform::open_file_no_follow(&parent, name).map(OpenedEntity::File)
    } else if metadata.is_dir() {
        platform::open_dir_no_follow(&parent, name).map(OpenedEntity::Directory)
    } else {
        Err(TransferError::UnsafeSourceType)
    }
}

fn open_relative_file(base: &Dir, components: &[OsString]) -> Result<File, TransferError> {
    let (parent, name) = open_parent(base, components)?;
    platform::open_file_no_follow(&parent, name)
}

fn open_parent<'a>(
    base: &Dir,
    components: &'a [OsString],
) -> Result<(Dir, &'a Path), TransferError> {
    let (name, ancestors) = components
        .split_last()
        .ok_or(TransferError::InvalidSource)?;
    let mut parent = base.try_clone().map_err(|_| TransferError::InvalidSource)?;
    for component in ancestors {
        parent = platform::open_dir_no_follow(&parent, Path::new(component))?;
    }
    Ok((parent, Path::new(name)))
}

fn require_evidence(file: &File, expected: StableEvidence) -> Result<(), TransferError> {
    let current = platform::file_evidence(file)?;
    if current == expected {
        Ok(())
    } else {
        Err(TransferError::SourceChanged)
    }
}

fn hash_exact_prefix(
    file: &mut File,
    length: u64,
    hasher: &mut blake3::Hasher,
) -> Result<(), TransferError> {
    let mut remaining = length;
    let mut buffer = vec![0_u8; MAX_CHUNK_BYTES];
    while remaining != 0 {
        let read_len = usize::try_from(remaining.min(MAX_CHUNK_BYTES as u64))
            .map_err(|_| TransferError::SourceChanged)?;
        file.read_exact(&mut buffer[..read_len])
            .map_err(|_| TransferError::SourceChanged)?;
        hasher.update(&buffer[..read_len]);
        remaining -= u64::try_from(read_len).map_err(|_| TransferError::SourceChanged)?;
    }
    Ok(())
}

fn finish_active(
    manifest: &TransferManifest,
    source: &SourceFile,
    active: &ActiveFile,
) -> Result<(), TransferError> {
    require_evidence(&active.file, active.evidence)?;
    let expected = manifest
        .entries()
        .get(active.entry_index)
        .and_then(|entry| entry.hash)
        .ok_or(TransferError::SourceChanged)?;
    let actual = ContentHash::from_bytes(*active.hasher.clone().finalize().as_bytes());
    if active.offset != source.evidence.size || actual != expected {
        return Err(TransferError::SourceChanged);
    }
    Ok(())
}

fn unicode_name(name: &OsStr) -> Result<&str, TransferError> {
    name.to_str().ok_or(TransferError::InvalidSource)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    struct TemporaryDirectory(PathBuf);

    impl TemporaryDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "nodavo-outbound-source-test-{}",
                uuid::Uuid::new_v4()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TemporaryDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn patterned_bytes(length: usize) -> Vec<u8> {
        (0_u8..=250).cycle().take(length).collect()
    }

    #[test]
    fn scan_with_cancel_matches_scan_when_not_cancelled() {
        let temp = TemporaryDirectory::new();
        let selected = temp.path().join("selected");
        fs::create_dir(&selected).unwrap();
        fs::write(selected.join("one.txt"), b"one").unwrap();
        let ordinary = OutboundTransferSource::scan(TransferId::new(), [&selected]).unwrap();
        let cancellable =
            OutboundTransferSource::scan_with_cancel(TransferId::new(), [&selected], || false)
                .unwrap();
        assert_eq!(ordinary.manifest(), cancellable.manifest());
    }

    #[test]
    fn scan_cancellation_is_polled_between_file_hash_chunks() {
        let temp = TemporaryDirectory::new();
        let path = temp.path().join("large.bin");
        fs::write(&path, patterned_bytes(MAX_CHUNK_BYTES * 3)).unwrap();
        let mut polls = 0_usize;
        let result = OutboundTransferSource::scan_with_cancel(TransferId::new(), [&path], || {
            polls += 1;
            polls >= 9
        });
        assert!(matches!(result, Err(TransferError::Cancelled)));
        assert!(polls >= 9);
    }

    #[test]
    fn directory_enumeration_stops_at_its_preallocation_bound() {
        let temp = TemporaryDirectory::new();
        for name in ["a", "b", "c"] {
            fs::write(temp.path().join(name), name.as_bytes()).unwrap();
        }
        let directory = Dir::open_ambient_dir(temp.path(), ambient_authority()).unwrap();
        let mut never_cancelled = || false;
        assert!(matches!(
            enumerate_children(
                &directory,
                &RelativePath::parse("root").unwrap(),
                2,
                &mut never_cancelled,
            ),
            Err(TransferError::InvalidManifest)
        ));
    }

    #[test]
    fn selected_leaf_replacement_between_anchor_and_canonicalization_is_rejected() {
        let temp = TemporaryDirectory::new();
        let path = temp.path().join("selected.txt");
        let original = temp.path().join("original.txt");
        fs::write(&path, b"original").unwrap();
        let result = open_selected_root_with_hook(&path, || {
            fs::rename(&path, &original).unwrap();
            fs::write(&path, b"replacement").unwrap();
        });
        assert!(matches!(result, Err(TransferError::SourceChanged)));
    }

    #[cfg(unix)]
    #[test]
    fn stable_identity_aliases_across_roots_are_rejected() {
        let temp = TemporaryDirectory::new();
        let first = temp.path().join("first.txt");
        let second = temp.path().join("second.txt");
        fs::write(&first, b"same inode").unwrap();
        fs::hard_link(&first, &second).unwrap();
        assert!(matches!(
            OutboundTransferSource::scan(TransferId::new(), [&first, &second]),
            Err(TransferError::SourceCycle)
        ));
    }

    #[test]
    fn manifest_is_sorted_unicode_stable_and_zero_byte_safe() {
        let temp = TemporaryDirectory::new();
        let selected = temp.path().join("данные");
        fs::create_dir(&selected).unwrap();
        fs::write(selected.join("é.txt"), b"unicode").unwrap();
        fs::write(selected.join("a.txt"), b"alpha").unwrap();
        fs::write(selected.join("empty.txt"), b"").unwrap();

        let first = OutboundTransferSource::scan(TransferId::new(), [&selected]).unwrap();
        let second = OutboundTransferSource::scan(TransferId::new(), [&selected]).unwrap();
        assert_eq!(first.manifest(), second.manifest());
        let paths = first
            .manifest()
            .entries()
            .iter()
            .map(|entry| entry.path.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            paths,
            ["данные", "данные/a.txt", "данные/empty.txt", "данные/é.txt"]
        );
        let empty = first
            .manifest()
            .entries()
            .iter()
            .find(|entry| entry.path.as_str().ends_with("empty.txt"))
            .unwrap();
        assert_eq!(empty.size, 0);
        assert_eq!(empty.hash, Some(ContentHash::digest(b"")));
    }

    #[test]
    fn sequential_chunks_are_bounded_and_resume_rechecks_prefix() {
        let temp = TemporaryDirectory::new();
        let path = temp.path().join("large.bin");
        let payload = patterned_bytes(MAX_CHUNK_BYTES * 2 + 31);
        fs::write(&path, &payload).unwrap();
        let transfer = TransferId::new();
        let mut source = OutboundTransferSource::scan(transfer, [&path]).unwrap();

        let first = source.next_chunk().unwrap().unwrap();
        assert_eq!(first.offset, 0);
        assert_eq!(first.bytes.len(), MAX_CHUNK_BYTES);
        let resume_offset = u64::try_from(first.bytes.len()).unwrap();
        source
            .resume(OutboundResumePoint::new(
                transfer,
                first.entry_index,
                resume_offset,
            ))
            .unwrap();

        let mut received = first.bytes.to_vec();
        let mut expected_offset = resume_offset;
        while let Some(chunk) = source.next_chunk().unwrap() {
            assert_eq!(chunk.entry_index, first.entry_index);
            assert_eq!(chunk.offset, expected_offset);
            assert!(!chunk.bytes.is_empty());
            assert!(chunk.bytes.len() <= MAX_CHUNK_BYTES);
            expected_offset += u64::try_from(chunk.bytes.len()).unwrap();
            received.extend_from_slice(&chunk.bytes);
        }
        assert_eq!(received, payload);
    }

    #[test]
    fn zero_byte_source_completes_without_an_empty_chunk() {
        let temp = TemporaryDirectory::new();
        let path = temp.path().join("empty.txt");
        fs::write(&path, b"").unwrap();
        let mut source = OutboundTransferSource::scan(TransferId::new(), [&path]).unwrap();
        assert_eq!(source.manifest().total_bytes(), 0);
        assert!(source.next_chunk().unwrap().is_none());
    }

    #[test]
    fn replacement_after_hashing_fails_stable_identity_check() {
        let temp = TemporaryDirectory::new();
        let path = temp.path().join("mutable.txt");
        let old = temp.path().join("old.txt");
        fs::write(&path, b"same-length").unwrap();
        let mut source = OutboundTransferSource::scan(TransferId::new(), [&path]).unwrap();
        fs::rename(&path, &old).unwrap();
        fs::write(&path, b"same-length").unwrap();

        assert_eq!(source.next_chunk(), Err(TransferError::SourceChanged));
        assert_eq!(source.next_chunk(), Err(TransferError::Cancelled));
    }

    #[test]
    fn case_colliding_explicit_roots_and_overlapping_roots_are_rejected() {
        let temp = TemporaryDirectory::new();
        let left = temp.path().join("left");
        let right = temp.path().join("right");
        fs::create_dir(&left).unwrap();
        fs::create_dir(&right).unwrap();
        let upper = left.join("Report.TXT");
        let lower = right.join("report.txt");
        fs::write(&upper, b"a").unwrap();
        fs::write(&lower, b"b").unwrap();
        assert!(matches!(
            OutboundTransferSource::scan(TransferId::new(), [&upper, &lower]),
            Err(TransferError::PathCollision)
        ));

        let folder = temp.path().join("folder");
        fs::create_dir(&folder).unwrap();
        let child = folder.join("child.txt");
        fs::write(&child, b"child").unwrap();
        assert!(matches!(
            OutboundTransferSource::scan(TransferId::new(), [&folder, &child]),
            Err(TransferError::UnsafeSourceRoots)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_special_files_and_sparse_files_are_rejected() {
        use std::os::unix::fs::symlink;
        use std::os::unix::net::UnixListener;

        let temp = TemporaryDirectory::new();
        let linked_folder = temp.path().join("linked");
        fs::create_dir(&linked_folder).unwrap();
        fs::write(linked_folder.join("target.txt"), b"target").unwrap();
        symlink("target.txt", linked_folder.join("alias.txt")).unwrap();
        assert!(matches!(
            OutboundTransferSource::scan(TransferId::new(), [&linked_folder.join("alias.txt")]),
            Err(TransferError::UnsafeSourceType)
        ));
        assert!(matches!(
            OutboundTransferSource::scan(TransferId::new(), [&linked_folder]),
            Err(TransferError::UnsafeSourceType)
        ));

        let socket_path = PathBuf::from("/tmp").join(format!(
            "nd-{}.sock",
            &uuid::Uuid::new_v4().simple().to_string()[..12]
        ));
        let listener = UnixListener::bind(&socket_path).unwrap();
        assert!(matches!(
            OutboundTransferSource::scan(TransferId::new(), [&socket_path]),
            Err(TransferError::UnsafeSourceType)
        ));
        drop(listener);
        fs::remove_file(socket_path).unwrap();

        let sparse = temp.path().join("sparse.bin");
        std::fs::File::create(&sparse)
            .unwrap()
            .set_len(1024 * 1024)
            .unwrap();
        assert!(matches!(
            OutboundTransferSource::scan(TransferId::new(), [&sparse]),
            Err(TransferError::UnsafeSourceType)
        ));
    }

    #[test]
    fn cancellation_drops_the_active_handle() {
        let temp = TemporaryDirectory::new();
        let path = temp.path().join("cancel.bin");
        fs::write(&path, patterned_bytes(MAX_CHUNK_BYTES + 1)).unwrap();
        let mut source = OutboundTransferSource::scan(TransferId::new(), [&path]).unwrap();
        assert!(source.next_chunk().unwrap().is_some());
        source.cancel();
        assert_eq!(source.next_chunk(), Err(TransferError::Cancelled));
        drop(source);
        fs::remove_file(path).unwrap();
    }
}
