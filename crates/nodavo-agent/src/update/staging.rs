#[cfg(unix)]
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

#[cfg(unix)]
use cap_fs_ext::{DirExt as _, FollowSymlinks, OpenOptionsFollowExt as _, OpenOptionsSyncExt as _};
#[cfg(unix)]
use cap_std::fs::{Dir, File, OpenOptions};
#[cfg(unix)]
use fs2::FileExt as _;
#[cfg(unix)]
use nodavo_update::MAX_ARTIFACT_BYTES;
use nodavo_update::{ArtifactId, ArtifactStaging, ExternalEffectError, StagedArtifactState};

#[cfg(unix)]
const LEASE_NAME: &str = ".coordinator.lock";
#[cfg(unix)]
const MAX_STAGE_ENTRIES: usize = 6;
#[cfg(unix)]
const MAX_RETAINED_SEALED: usize = 2;
#[cfg(unix)]
const MAX_STAGE_TOTAL_BYTES: u64 = MAX_ARTIFACT_BYTES * 2;

/// Private content-addressed staging retained as a capability root.
///
/// After construction, every entry operation is relative to `root`; replacing
/// the ambient pathname cannot redirect reads, writes, sealing, or cleanup.
pub(super) struct PrivateFileStaging {
    #[cfg(unix)]
    root: Dir,
    #[cfg(unix)]
    _lease: std::fs::File,
    #[cfg(unix)]
    poisoned: bool,
    #[cfg(not(unix))]
    _unavailable: (),
}

impl PrivateFileStaging {
    pub(super) fn new(path: &Path) -> Result<Self, ExternalEffectError> {
        #[cfg(unix)]
        {
            let root = open_private_stage_root(path)?;
            let lease = acquire_exclusive_lease(&root)?;
            cleanup_and_bound_stage(&root, None)?;
            Ok(Self {
                root,
                _lease: lease,
                poisoned: false,
            })
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            Err(ExternalEffectError)
        }
    }

    #[cfg(unix)]
    fn require_usable(&self) -> Result<(), ExternalEffectError> {
        if self.poisoned {
            Err(ExternalEffectError)
        } else {
            Ok(())
        }
    }

    #[cfg(unix)]
    fn partial_name(artifact: ArtifactId) -> String {
        format!(
            "{}-{}.partial",
            encode_hex(artifact.sha256()),
            artifact.size()
        )
    }

    #[cfg(unix)]
    fn sealed_name(artifact: ArtifactId) -> String {
        format!(
            "{}-{}.sealed",
            encode_hex(artifact.sha256()),
            artifact.size()
        )
    }

    #[cfg(unix)]
    fn sync_root(&self) -> Result<(), ExternalEffectError> {
        self.root
            .try_clone()
            .and_then(|clone| clone.into_std_file().sync_all())
            .map_err(|_| ExternalEffectError)
    }
}

impl ArtifactStaging for PrivateFileStaging {
    fn inspect(
        &mut self,
        artifact: ArtifactId,
    ) -> Result<StagedArtifactState, ExternalEffectError> {
        #[cfg(unix)]
        {
            self.require_usable()?;
            require_private_directory(&self.root)?;
            let partial = inspect_regular_file(&self.root, &Self::partial_name(artifact))?;
            let sealed = inspect_regular_file(&self.root, &Self::sealed_name(artifact))?;
            match (partial, sealed) {
                (None, None) => Ok(StagedArtifactState::Missing),
                (Some(length), None) => Ok(StagedArtifactState::Partial(length)),
                (None, Some(length)) => Ok(StagedArtifactState::Sealed(length)),
                (Some(_), Some(_)) => Err(ExternalEffectError),
            }
        }
        #[cfg(not(unix))]
        {
            let _ = artifact;
            Err(ExternalEffectError)
        }
    }

    fn read_at(
        &mut self,
        artifact: ArtifactId,
        offset: u64,
        buffer: &mut [u8],
    ) -> Result<usize, ExternalEffectError> {
        #[cfg(unix)]
        {
            self.require_usable()?;
            require_private_directory(&self.root)?;
            let partial = Self::partial_name(artifact);
            let sealed = Self::sealed_name(artifact);
            let name = match (
                inspect_regular_file(&self.root, &partial)?,
                inspect_regular_file(&self.root, &sealed)?,
            ) {
                (Some(_), None) => partial,
                (None, Some(_)) => sealed,
                _ => return Err(ExternalEffectError),
            };
            let mut file = open_regular_no_follow(&self.root, &name, false, false)?;
            file.seek(SeekFrom::Start(offset))
                .map_err(|_| ExternalEffectError)?;
            file.read(buffer).map_err(|_| ExternalEffectError)
        }
        #[cfg(not(unix))]
        {
            let _ = (artifact, offset, buffer);
            Err(ExternalEffectError)
        }
    }

    fn append(
        &mut self,
        artifact: ArtifactId,
        expected_offset: u64,
        bytes: &[u8],
    ) -> Result<(), ExternalEffectError> {
        #[cfg(unix)]
        {
            self.require_usable()?;
            require_private_directory(&self.root)?;
            if bytes.is_empty()
                || inspect_regular_file(&self.root, &Self::sealed_name(artifact))?.is_some()
            {
                return Err(ExternalEffectError);
            }
            let partial = Self::partial_name(artifact);
            let existing = inspect_regular_file(&self.root, &partial)?;
            let additional = u64::try_from(bytes.len()).map_err(|_| ExternalEffectError)?;
            ensure_stage_capacity(&self.root, usize::from(existing.is_none()), additional)?;
            let mut file = if existing.is_none() {
                let file = create_private_file(&self.root, &partial)?;
                file.sync_all().map_err(|_| ExternalEffectError)?;
                self.sync_root()?;
                file
            } else {
                open_regular_no_follow(&self.root, &partial, false, true)?
            };
            if file.metadata().map_err(|_| ExternalEffectError)?.len() != expected_offset {
                return Err(ExternalEffectError);
            }
            file.seek(SeekFrom::End(0))
                .map_err(|_| ExternalEffectError)?;
            file.write_all(bytes).map_err(|_| ExternalEffectError)?;
            file.sync_all().map_err(|_| ExternalEffectError)
        }
        #[cfg(not(unix))]
        {
            let _ = (artifact, expected_offset, bytes);
            Err(ExternalEffectError)
        }
    }

    fn reset(&mut self, artifact: ArtifactId) -> Result<(), ExternalEffectError> {
        #[cfg(unix)]
        {
            self.require_usable()?;
            require_private_directory(&self.root)?;
            if inspect_regular_file(&self.root, &Self::sealed_name(artifact))?.is_some() {
                return Err(ExternalEffectError);
            }
            let temporary = format!(
                "{}-{}.reset-{}",
                encode_hex(artifact.sha256()),
                artifact.size(),
                uuid::Uuid::new_v4().simple()
            );
            let file = create_private_file(&self.root, &temporary)?;
            file.sync_all().map_err(|_| ExternalEffectError)?;
            self.sync_root()?;
            let partial = Self::partial_name(artifact);
            if inspect_regular_file(&self.root, &partial)?.is_some() {
                self.root
                    .remove_file(Path::new(&partial))
                    .map_err(|_| ExternalEffectError)?;
                self.sync_root()?;
            }
            self.root
                .hard_link(Path::new(&temporary), &self.root, Path::new(&partial))
                .map_err(|_| ExternalEffectError)?;
            self.sync_root()?;
            self.root
                .remove_file(Path::new(&temporary))
                .map_err(|_| ExternalEffectError)?;
            self.sync_root()
        }
        #[cfg(not(unix))]
        {
            let _ = artifact;
            Err(ExternalEffectError)
        }
    }

    fn seal(&mut self, artifact: ArtifactId) -> Result<(), ExternalEffectError> {
        #[cfg(unix)]
        {
            self.require_usable()?;
            require_private_directory(&self.root)?;
            let partial = Self::partial_name(artifact);
            let sealed = Self::sealed_name(artifact);
            if inspect_regular_file(&self.root, &sealed)?.is_some() {
                return Err(ExternalEffectError);
            }
            let file = open_regular_no_follow(&self.root, &partial, false, false)?;
            if file.metadata().map_err(|_| ExternalEffectError)?.len() != artifact.size() {
                return Err(ExternalEffectError);
            }
            file.sync_all().map_err(|_| ExternalEffectError)?;
            self.root
                .hard_link(Path::new(&partial), &self.root, Path::new(&sealed))
                .map_err(|_| ExternalEffectError)?;
            self.sync_root()?;
            self.root
                .remove_file(Path::new(&partial))
                .map_err(|_| ExternalEffectError)?;
            self.sync_root()?;
            cleanup_and_bound_stage(&self.root, Some(&sealed))
        }
        #[cfg(not(unix))]
        {
            let _ = artifact;
            Err(ExternalEffectError)
        }
    }

    fn discard(&mut self, artifact: ArtifactId) -> Result<(), ExternalEffectError> {
        #[cfg(unix)]
        {
            self.require_usable()?;
            let result = (|| {
                require_private_directory(&self.root)?;
                for name in [Self::partial_name(artifact), Self::sealed_name(artifact)] {
                    if inspect_regular_file(&self.root, &name)?.is_some() {
                        self.root
                            .remove_file(Path::new(&name))
                            .map_err(|_| ExternalEffectError)?;
                    }
                }
                self.sync_root()
            })();
            if result.is_err() {
                self.poisoned = true;
            }
            result
        }
        #[cfg(not(unix))]
        {
            let _ = artifact;
            Err(ExternalEffectError)
        }
    }
}

#[cfg(unix)]
#[derive(Clone)]
struct StageEntry {
    name: String,
    key: String,
    length: u64,
    sealed: bool,
    modified: std::time::SystemTime,
}

#[cfg(unix)]
fn acquire_exclusive_lease(root: &Dir) -> Result<std::fs::File, ExternalEffectError> {
    let lease = if inspect_regular_file(root, LEASE_NAME)?.is_some() {
        open_regular_no_follow(root, LEASE_NAME, false, true)?
    } else {
        let lease = create_private_file(root, LEASE_NAME)?;
        lease.sync_all().map_err(|_| ExternalEffectError)?;
        sync_directory(root)?;
        lease
    };
    let lease = lease.into_std();
    lease
        .try_lock_exclusive()
        .map_err(|_| ExternalEffectError)?;
    Ok(lease)
}

#[cfg(unix)]
fn cleanup_and_bound_stage(
    root: &Dir,
    preserve_sealed: Option<&str>,
) -> Result<(), ExternalEffectError> {
    require_private_directory(root)?;
    remove_reset_temps(root)?;
    reconcile_interrupted_seals(root)?;
    let mut entries = stage_entries(root)?;
    let mut sealed = entries
        .iter()
        .filter(|entry| entry.sealed)
        .cloned()
        .collect::<Vec<_>>();
    sealed.sort_by_key(|entry| entry.modified);
    while sealed.len() > MAX_RETAINED_SEALED {
        let index = sealed
            .iter()
            .position(|entry| preserve_sealed != Some(entry.name.as_str()))
            .ok_or(ExternalEffectError)?;
        let removed = sealed.remove(index);
        root.remove_file(Path::new(&removed.name))
            .map_err(|_| ExternalEffectError)?;
        sync_directory(root)?;
        entries.retain(|entry| entry.name != removed.name);
    }

    while stage_totals(&entries).is_err() {
        let index = entries
            .iter()
            .position(|entry| entry.sealed && preserve_sealed != Some(entry.name.as_str()))
            .ok_or(ExternalEffectError)?;
        let removed = entries.remove(index);
        root.remove_file(Path::new(&removed.name))
            .map_err(|_| ExternalEffectError)?;
        sync_directory(root)?;
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_stage_capacity(
    root: &Dir,
    additional_entries: usize,
    additional_bytes: u64,
) -> Result<(), ExternalEffectError> {
    cleanup_and_bound_stage(root, None)?;
    let entries = stage_entries(root)?;
    let (count, bytes) = stage_totals(&entries)?;
    if count
        .checked_add(additional_entries)
        .is_none_or(|next| next > MAX_STAGE_ENTRIES)
        || bytes
            .checked_add(additional_bytes)
            .is_none_or(|next| next > MAX_STAGE_TOTAL_BYTES)
    {
        return Err(ExternalEffectError);
    }
    Ok(())
}

#[cfg(unix)]
fn stage_totals(entries: &[StageEntry]) -> Result<(usize, u64), ExternalEffectError> {
    let mut bytes = 0_u64;
    for entry in entries {
        bytes = bytes.checked_add(entry.length).ok_or(ExternalEffectError)?;
    }
    if entries.len() > MAX_STAGE_ENTRIES || bytes > MAX_STAGE_TOTAL_BYTES {
        return Err(ExternalEffectError);
    }
    Ok((entries.len(), bytes))
}

#[cfg(unix)]
fn stage_entries(root: &Dir) -> Result<Vec<StageEntry>, ExternalEffectError> {
    let mut entries = Vec::new();
    let directory = root.entries().map_err(|_| ExternalEffectError)?;
    for entry in directory {
        let entry = entry.map_err(|_| ExternalEffectError)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| ExternalEffectError)?;
        if name == LEASE_NAME {
            continue;
        }
        let (key, sealed) = parse_stage_name(&name).ok_or(ExternalEffectError)?;
        let file = open_regular_no_follow(root, &name, false, false)?;
        let metadata = file.metadata().map_err(|_| ExternalEffectError)?;
        entries.push(StageEntry {
            name,
            key,
            length: metadata.len(),
            sealed,
            modified: metadata
                .modified()
                .map_err(|_| ExternalEffectError)?
                .into_std(),
        });
    }
    Ok(entries)
}

#[cfg(unix)]
fn remove_reset_temps(root: &Dir) -> Result<(), ExternalEffectError> {
    let mut removed = false;
    let directory = root.entries().map_err(|_| ExternalEffectError)?;
    for entry in directory {
        let entry = entry.map_err(|_| ExternalEffectError)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| ExternalEffectError)?;
        if is_reset_temp_name(&name) {
            open_regular_no_follow(root, &name, false, false)?;
            root.remove_file(Path::new(&name))
                .map_err(|_| ExternalEffectError)?;
            removed = true;
        }
    }
    if removed {
        sync_directory(root)?;
    }
    Ok(())
}

#[cfg(unix)]
fn reconcile_interrupted_seals(root: &Dir) -> Result<(), ExternalEffectError> {
    use cap_std::fs::MetadataExt as _;

    let entries = stage_entries(root)?;
    let mut changed = false;
    for partial in entries.iter().filter(|entry| !entry.sealed) {
        let Some(sealed) = entries
            .iter()
            .find(|entry| entry.sealed && entry.key == partial.key)
        else {
            continue;
        };
        let partial_file = open_regular_no_follow(root, &partial.name, false, false)?;
        let sealed_file = open_regular_no_follow(root, &sealed.name, false, false)?;
        let partial_metadata = partial_file.metadata().map_err(|_| ExternalEffectError)?;
        let sealed_metadata = sealed_file.metadata().map_err(|_| ExternalEffectError)?;
        if partial_metadata.dev() != sealed_metadata.dev()
            || partial_metadata.ino() != sealed_metadata.ino()
        {
            return Err(ExternalEffectError);
        }
        root.remove_file(Path::new(&partial.name))
            .map_err(|_| ExternalEffectError)?;
        changed = true;
    }
    if changed {
        sync_directory(root)?;
    }
    Ok(())
}

#[cfg(unix)]
fn parse_stage_name(name: &str) -> Option<(String, bool)> {
    let (base, sealed) = if let Some(base) = name.strip_suffix(".partial") {
        (base, false)
    } else if let Some(base) = name.strip_suffix(".sealed") {
        (base, true)
    } else {
        return None;
    };
    if base.len() < 66
        || !base.as_bytes()[..64]
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        || base.as_bytes()[64] != b'-'
    {
        return None;
    }
    let size = &base[65..];
    let Ok(parsed_size) = size.parse::<u64>() else {
        return None;
    };
    if size.is_empty()
        || (size.starts_with('0') && size.len() > 1)
        || parsed_size == 0
        || parsed_size > MAX_ARTIFACT_BYTES
    {
        return None;
    }
    Some((base.to_owned(), sealed))
}

#[cfg(unix)]
fn is_reset_temp_name(name: &str) -> bool {
    let Some((base, suffix)) = name.rsplit_once(".reset-") else {
        return false;
    };
    parse_stage_name(&format!("{base}.partial")).is_some()
        && suffix.len() == 32
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(unix)]
fn open_private_stage_root(path: &Path) -> Result<Dir, ExternalEffectError> {
    use cap_std::ambient_authority;
    use cap_std::fs::{DirBuilder, DirBuilderExt as _};

    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| ExternalEffectError)?
            .join(path)
    };
    let name = absolute.file_name().ok_or(ExternalEffectError)?;
    let parent_path = absolute.parent().ok_or(ExternalEffectError)?;
    let parent =
        Dir::open_ambient_dir(parent_path, ambient_authority()).map_err(|_| ExternalEffectError)?;
    match parent.symlink_metadata(Path::new(name)) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(ExternalEffectError);
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = DirBuilder::new();
            builder.mode(0o700);
            parent
                .create_dir_with(Path::new(name), &builder)
                .map_err(|_| ExternalEffectError)?;
            sync_directory(&parent)?;
        }
        Err(_) => return Err(ExternalEffectError),
    }
    let root = parent
        .open_dir_nofollow(Path::new(name))
        .map_err(|_| ExternalEffectError)?;
    require_private_directory(&root)?;
    Ok(root)
}

#[cfg(unix)]
fn require_private_directory(directory: &Dir) -> Result<(), ExternalEffectError> {
    use cap_std::fs::MetadataExt as _;

    let metadata = directory.dir_metadata().map_err(|_| ExternalEffectError)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || metadata.mode() & 0o777 != 0o700 {
        return Err(ExternalEffectError);
    }
    Ok(())
}

#[cfg(unix)]
fn inspect_regular_file(root: &Dir, name: &str) -> Result<Option<u64>, ExternalEffectError> {
    match root.symlink_metadata(Path::new(name)) {
        Ok(metadata) => {
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(ExternalEffectError);
            }
            let file = open_regular_no_follow(root, name, false, false)?;
            Ok(Some(
                file.metadata().map_err(|_| ExternalEffectError)?.len(),
            ))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(ExternalEffectError),
    }
}

#[cfg(unix)]
fn open_regular_no_follow(
    root: &Dir,
    name: &str,
    create: bool,
    writable: bool,
) -> Result<File, ExternalEffectError> {
    use cap_std::fs::{MetadataExt as _, OpenOptionsExt as _};

    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(writable)
        .follow(FollowSymlinks::No)
        .nonblock(true);
    if create {
        options.create(true).mode(0o600);
    }
    let file = root
        .open_with(Path::new(name), &options)
        .map_err(|_| ExternalEffectError)?;
    let metadata = file.metadata().map_err(|_| ExternalEffectError)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.mode() & 0o777 != 0o600
    {
        return Err(ExternalEffectError);
    }
    Ok(file)
}

#[cfg(unix)]
fn create_private_file(root: &Dir, name: &str) -> Result<File, ExternalEffectError> {
    use cap_std::fs::{MetadataExt as _, OpenOptionsExt as _};

    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create_new(true)
        .follow(FollowSymlinks::No)
        .nonblock(true)
        .mode(0o600);
    let file = root
        .open_with(Path::new(name), &options)
        .map_err(|_| ExternalEffectError)?;
    let metadata = file.metadata().map_err(|_| ExternalEffectError)?;
    if !metadata.is_file() || metadata.mode() & 0o777 != 0o600 {
        return Err(ExternalEffectError);
    }
    Ok(file)
}

#[cfg(unix)]
fn sync_directory(directory: &Dir) -> Result<(), ExternalEffectError> {
    directory
        .try_clone()
        .and_then(|clone| clone.into_std_file().sync_all())
        .map_err(|_| ExternalEffectError)
}

#[cfg(unix)]
fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    use std::path::PathBuf;

    use super::*;

    fn temporary_parent() -> PathBuf {
        let parent = std::env::temp_dir().join(format!(
            "nodavo-update-stage-test-{}",
            uuid::Uuid::new_v4().simple()
        ));
        fs::create_dir(&parent).unwrap();
        parent
    }

    fn artifact() -> ArtifactId {
        ArtifactId::new([0x5a; 32], 6).unwrap()
    }

    fn distinct_artifact(byte: u8) -> ArtifactId {
        ArtifactId::new([byte; 32], 1).unwrap()
    }

    #[test]
    fn stage_is_private_resumable_and_atomically_sealed() {
        let parent = temporary_parent();
        let path = parent.join("stage");
        let mut staging = PrivateFileStaging::new(&path).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o700
        );

        let artifact = artifact();
        staging.append(artifact, 0, b"abc").unwrap();
        assert_eq!(
            staging.inspect(artifact).unwrap(),
            StagedArtifactState::Partial(3)
        );
        staging.append(artifact, 3, b"def").unwrap();
        staging.seal(artifact).unwrap();
        assert_eq!(
            staging.inspect(artifact).unwrap(),
            StagedArtifactState::Sealed(6)
        );
        assert_eq!(
            fs::metadata(path.join(PrivateFileStaging::sealed_name(artifact)))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn no_follow_rejects_substituted_stage_entry() {
        let parent = temporary_parent();
        let path = parent.join("stage");
        let mut staging = PrivateFileStaging::new(&path).unwrap();
        let artifact = artifact();
        let outside = parent.join("outside");
        fs::write(&outside, b"secret").unwrap();
        symlink(
            &outside,
            path.join(PrivateFileStaging::partial_name(artifact)),
        )
        .unwrap();

        assert!(staging.inspect(artifact).is_err());
        assert!(staging.append(artifact, 0, b"abc").is_err());
        assert_eq!(fs::read(&outside).unwrap(), b"secret");
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn retained_root_is_not_redirected_by_ambient_path_replacement() {
        let parent = temporary_parent();
        let path = parent.join("stage");
        let saved = parent.join("retained");
        let outside = parent.join("outside");
        fs::create_dir(&outside).unwrap();
        let mut staging = PrivateFileStaging::new(&path).unwrap();
        fs::rename(&path, &saved).unwrap();
        symlink(&outside, &path).unwrap();

        let artifact = artifact();
        staging.append(artifact, 0, b"abc").unwrap();
        assert!(
            saved
                .join(PrivateFileStaging::partial_name(artifact))
                .is_file()
        );
        assert!(fs::read_dir(&outside).unwrap().next().is_none());

        fs::remove_file(path).unwrap();
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn process_wide_stage_lease_rejects_a_second_coordinator() {
        let parent = temporary_parent();
        let path = parent.join("stage");
        let first = PrivateFileStaging::new(&path).unwrap();
        assert!(PrivateFileStaging::new(&path).is_err());
        drop(first);
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn seal_never_replaces_an_existing_destination() {
        let parent = temporary_parent();
        let path = parent.join("stage");
        let mut staging = PrivateFileStaging::new(&path).unwrap();
        let artifact = artifact();
        staging.append(artifact, 0, b"abcdef").unwrap();
        let sealed = path.join(PrivateFileStaging::sealed_name(artifact));
        fs::write(&sealed, b"attacker").unwrap();
        fs::set_permissions(&sealed, fs::Permissions::from_mode(0o600)).unwrap();

        assert!(staging.seal(artifact).is_err());
        assert_eq!(fs::read(sealed).unwrap(), b"attacker");
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn nonblocking_no_follow_open_rejects_fifo_stage_entry() {
        let parent = temporary_parent();
        let path = parent.join("stage");
        let mut staging = PrivateFileStaging::new(&path).unwrap();
        let artifact = artifact();
        let fifo = path.join(PrivateFileStaging::partial_name(artifact));
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        fs::set_permissions(&fifo, fs::Permissions::from_mode(0o600)).unwrap();

        assert!(staging.inspect(artifact).is_err());
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn sealed_retention_is_bounded_and_preserves_the_new_stage() {
        let parent = temporary_parent();
        let path = parent.join("stage");
        let mut staging = PrivateFileStaging::new(&path).unwrap();
        for byte in 1..=3 {
            let artifact = distinct_artifact(byte);
            staging.append(artifact, 0, &[byte]).unwrap();
            staging.seal(artifact).unwrap();
        }

        let sealed = fs::read_dir(&path)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".sealed"))
            .count();
        assert_eq!(sealed, MAX_RETAINED_SEALED);
        assert!(
            path.join(PrivateFileStaging::sealed_name(distinct_artifact(3)))
                .is_file()
        );
        fs::remove_dir_all(parent).unwrap();
    }
}
