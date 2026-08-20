//! macOS production adapters owned by the per-user agent.

#[cfg(feature = "development-unverified-local-ipc")]
mod ipc;
#[cfg(all(not(feature = "development-unverified-local-ipc"), not(test)))]
mod platform;
mod storage;
#[cfg(not(feature = "development-unverified-local-ipc"))]
mod xpc;

#[cfg(feature = "development-unverified-local-ipc")]
pub(crate) use ipc::{
    authenticate_ui_connection, ensure_local_ipc_auth_configured, local_ipc_self_check,
};
#[cfg(all(not(feature = "development-unverified-local-ipc"), not(test)))]
pub(crate) use platform::resolve_downloads_nodavo_directory;
pub(crate) use storage::MacKeychainStorage;
#[cfg(not(feature = "development-unverified-local-ipc"))]
pub(crate) use xpc::{LocalXpcServer, local_ipc_self_check};
