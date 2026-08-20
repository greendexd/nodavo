//! Fixed, user-visible receive destination resolved by the current macOS user
//! domain. No environment-derived path or caller-selected leaf enters this
//! boundary.

use std::os::unix::ffi::OsStrExt as _;
use std::path::{Component, Path, PathBuf};

use crate::MacReceiveDestinationError;

use super::ffi;

/// Retained no-follow handle for the fixed current-user receive directory.
///
/// The resolved path is deliberately absent so downstream code cannot reopen
/// ambient authority after this platform validation boundary.
pub struct MacReceiveDestination {
    directory: std::fs::File,
}

impl MacReceiveDestination {
    #[must_use]
    pub fn into_file(self) -> std::fs::File {
        self.directory
    }
}

impl std::fmt::Debug for MacReceiveDestination {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MacReceiveDestination([retained directory])")
    }
}

trait DownloadsResolver {
    fn resolve(&self) -> Result<PathBuf, MacReceiveDestinationError>;
}

struct NativeDownloadsResolver;

impl DownloadsResolver for NativeDownloadsResolver {
    fn resolve(&self) -> Result<PathBuf, MacReceiveDestinationError> {
        ffi::resolve_user_downloads_directory()
    }
}

/// Resolves and prepares the exact current-user `Downloads/Nodavo` directory.
///
/// Resolution always uses `NSFileManager`'s user-domain Downloads directory.
/// It never consults `HOME` or another environment variable, follows no
/// caller-provided leaf, and does not cache a denial: a later explicit runtime
/// operation can retry after the user changes macOS privacy access.
///
/// # Errors
///
/// Fails closed when macOS denies or cannot resolve Downloads, the bounded
/// native path is malformed, or the fixed leaf is not an owner-only real
/// directory.
pub fn prepare_receive_destination() -> Result<MacReceiveDestination, MacReceiveDestinationError> {
    prepare_receive_destination_with(&NativeDownloadsResolver)
}

fn prepare_receive_destination_with(
    resolver: &impl DownloadsResolver,
) -> Result<MacReceiveDestination, MacReceiveDestinationError> {
    let downloads = resolver.resolve()?;
    validate_downloads_root(&downloads)?;
    let directory = ffi::prepare_receive_destination(&downloads)?;
    Ok(MacReceiveDestination { directory })
}

fn validate_downloads_root(downloads: &Path) -> Result<(), MacReceiveDestinationError> {
    let bytes = downloads.as_os_str().as_bytes();
    if !downloads.is_absolute()
        || bytes.is_empty()
        || bytes.len() >= ffi::DOWNLOADS_PATH_CAPACITY
        || downloads
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(MacReceiveDestinationError::UnsafeDestination);
    }
    if bytes.len() + "/Nodavo".len() >= ffi::DOWNLOADS_PATH_CAPACITY {
        return Err(MacReceiveDestinationError::UnsafeDestination);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
    use std::process::Command;
    use std::sync::Mutex;

    use uuid::Uuid;

    use super::*;

    struct FakeResolver {
        outcomes: Mutex<VecDeque<Result<PathBuf, MacReceiveDestinationError>>>,
    }

    impl FakeResolver {
        fn new(
            outcomes: impl IntoIterator<Item = Result<PathBuf, MacReceiveDestinationError>>,
        ) -> Self {
            Self {
                outcomes: Mutex::new(outcomes.into_iter().collect()),
            }
        }
    }

    impl DownloadsResolver for FakeResolver {
        fn resolve(&self) -> Result<PathBuf, MacReceiveDestinationError> {
            self.outcomes
                .lock()
                .expect("fake resolver mutex poisoned")
                .pop_front()
                .expect("unexpected resolver call")
        }
    }

    struct IsolatedDirectory(PathBuf);

    impl IsolatedDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "nodavo-macos-receive-destination-test-{}",
                Uuid::new_v4()
            ));
            fs::create_dir(&path).expect("create isolated test directory");
            Self(fs::canonicalize(path).expect("canonical isolated test directory"))
        }
    }

    impl Drop for IsolatedDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn fixed_leaf_is_created_owner_only_below_the_resolved_downloads_root() {
        let root = IsolatedDirectory::new();
        let downloads = root.0.join("Official Downloads");
        fs::create_dir(&downloads).unwrap();
        let retained =
            prepare_receive_destination_with(&FakeResolver::new([Ok(downloads.clone())])).unwrap();

        let destination = downloads.join("Nodavo");
        let metadata = retained.into_file().metadata().unwrap();
        assert!(destination.is_dir());
        assert!(metadata.file_type().is_dir());
        assert!(!metadata.file_type().is_symlink());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
    }

    #[test]
    fn permission_denial_is_content_free_and_a_later_call_retries_resolution() {
        let root = IsolatedDirectory::new();
        let downloads = root.0.join("Downloads");
        fs::create_dir(&downloads).unwrap();
        let resolver = FakeResolver::new([
            Err(MacReceiveDestinationError::PermissionDenied),
            Ok(downloads.clone()),
        ]);

        assert!(matches!(
            prepare_receive_destination_with(&resolver),
            Err(MacReceiveDestinationError::PermissionDenied)
        ));
        let retained = prepare_receive_destination_with(&resolver).unwrap();
        assert!(retained.into_file().metadata().unwrap().is_dir());
    }

    #[test]
    fn malformed_roots_and_existing_unsafe_leafs_fail_closed() {
        assert_eq!(
            validate_downloads_root(Path::new("relative/Downloads")),
            Err(MacReceiveDestinationError::UnsafeDestination)
        );
        assert_eq!(
            validate_downloads_root(Path::new("/Users/example/../Downloads")),
            Err(MacReceiveDestinationError::UnsafeDestination)
        );
        let oversized = PathBuf::from("/").join("x".repeat(ffi::DOWNLOADS_PATH_CAPACITY));
        assert_eq!(
            validate_downloads_root(&oversized),
            Err(MacReceiveDestinationError::UnsafeDestination)
        );

        let root = IsolatedDirectory::new();
        let downloads = root.0.join("Downloads");
        let outside = root.0.join("outside");
        fs::create_dir(&downloads).unwrap();
        fs::create_dir(&outside).unwrap();
        symlink(&outside, downloads.join("Nodavo")).unwrap();
        let resolver = FakeResolver::new([Ok(downloads)]);
        assert!(matches!(
            prepare_receive_destination_with(&resolver),
            Err(MacReceiveDestinationError::UnsafeDestination)
        ));
    }

    #[test]
    fn preexisting_destination_must_already_have_exact_owner_only_mode() {
        let root = IsolatedDirectory::new();
        let downloads = root.0.join("Downloads");
        let destination = downloads.join("Nodavo");
        fs::create_dir(&downloads).unwrap();
        fs::create_dir(&destination).unwrap();
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o755)).unwrap();

        assert!(matches!(
            prepare_receive_destination_with(&FakeResolver::new([Ok(downloads)])),
            Err(MacReceiveDestinationError::UnsafeDestination)
        ));
    }

    #[test]
    fn final_handle_rejects_preexisting_and_newly_inherited_extended_acl() {
        let root = IsolatedDirectory::new();
        let downloads = root.0.join("Downloads");
        let destination = downloads.join("Nodavo");
        fs::create_dir(&downloads).unwrap();
        fs::set_permissions(&downloads, fs::Permissions::from_mode(0o700)).unwrap();

        let inherited = Command::new("/bin/chmod")
            .args(["+a", "everyone allow read,search,directory_inherit"])
            .arg(&downloads)
            .status()
            .unwrap();
        if !inherited.success() {
            return;
        }
        assert!(matches!(
            prepare_receive_destination_with(&FakeResolver::new([Ok(downloads.clone())])),
            Err(MacReceiveDestinationError::UnsafeDestination)
        ));
        assert!(destination.is_dir());

        assert!(
            Command::new("/bin/chmod")
                .arg("-N")
                .arg(&downloads)
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new("/bin/chmod")
                .arg("-N")
                .arg(&destination)
                .status()
                .unwrap()
                .success()
        );
        let retained =
            prepare_receive_destination_with(&FakeResolver::new([Ok(downloads.clone())])).unwrap();
        drop(retained);

        assert!(
            Command::new("/bin/chmod")
                .args(["+a", "everyone allow read"])
                .arg(&destination)
                .status()
                .unwrap()
                .success()
        );
        assert!(matches!(
            prepare_receive_destination_with(&FakeResolver::new([Ok(downloads)])),
            Err(MacReceiveDestinationError::UnsafeDestination)
        ));
        assert!(
            Command::new("/bin/chmod")
                .arg("-N")
                .arg(&destination)
                .status()
                .unwrap()
                .success()
        );
    }

    #[test]
    fn symlinked_parent_component_is_rejected_by_descriptor_walk() {
        let root = IsolatedDirectory::new();
        let real_parent = root.0.join("real-parent");
        let alias = root.0.join("parent-alias");
        let downloads = alias.join("Downloads");
        fs::create_dir(&real_parent).unwrap();
        fs::create_dir(real_parent.join("Downloads")).unwrap();
        symlink(&real_parent, &alias).unwrap();

        assert!(matches!(
            prepare_receive_destination_with(&FakeResolver::new([Ok(downloads)])),
            Err(MacReceiveDestinationError::UnsafeDestination)
        ));
        assert!(!real_parent.join("Downloads/Nodavo").exists());
    }

    #[test]
    fn retained_handle_cannot_be_redirected_by_ambient_leaf_replacement() {
        let root = IsolatedDirectory::new();
        let downloads = root.0.join("Downloads");
        let destination = downloads.join("Nodavo");
        let moved = downloads.join("Nodavo-original");
        fs::create_dir(&downloads).unwrap();
        let retained =
            prepare_receive_destination_with(&FakeResolver::new([Ok(downloads)])).unwrap();
        assert_eq!(
            format!("{retained:?}"),
            "MacReceiveDestination([retained directory])"
        );
        let original = retained.into_file();
        let original_metadata = original.metadata().unwrap();

        fs::rename(&destination, &moved).unwrap();
        fs::create_dir(&destination).unwrap();
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o700)).unwrap();
        let replacement_metadata = fs::symlink_metadata(&destination).unwrap();

        assert_eq!(original.metadata().unwrap().ino(), original_metadata.ino());
        assert_ne!(original_metadata.ino(), replacement_metadata.ino());
    }
}
