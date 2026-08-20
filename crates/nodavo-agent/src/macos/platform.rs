//! Content-free agent bridge to fixed macOS platform locations.

use std::fs::File;

/// Resolves and prepares the exact current-user `Downloads/Nodavo` directory.
///
/// The concrete platform error is collapsed before it can reach logging or
/// local IPC. This module is compiled only for the signed-XPC release path;
/// development-unverified local IPC remains isolated from user Downloads.
pub(crate) fn resolve_downloads_nodavo_directory() -> Result<File, ()> {
    nodavo_platform_macos::prepare_receive_destination()
        .map(nodavo_platform_macos::MacReceiveDestination::into_file)
        .map_err(|_| ())
}
