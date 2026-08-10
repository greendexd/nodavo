//! macOS production adapters owned by the per-user agent.

mod storage;

pub(crate) use storage::MacKeychainStorage;
