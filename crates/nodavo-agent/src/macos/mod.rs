//! macOS production adapters owned by the per-user agent.

#[cfg(feature = "development-unverified-local-ipc")]
mod ipc;
mod storage;
#[cfg(not(feature = "development-unverified-local-ipc"))]
mod xpc;

#[cfg(feature = "development-unverified-local-ipc")]
pub(crate) use ipc::{
    authenticate_ui_connection, ensure_local_ipc_auth_configured, local_ipc_self_check,
};
pub(crate) use storage::MacKeychainStorage;
#[cfg(not(feature = "development-unverified-local-ipc"))]
pub(crate) use xpc::{LocalXpcServer, local_ipc_self_check};
