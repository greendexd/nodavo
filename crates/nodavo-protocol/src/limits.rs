//! Public protocol hard limits.

/// Maximum encoded control-stream message size (64 KiB).
pub const CONTROL_MESSAGE_LIMIT: usize = 64 * 1024;
/// Maximum encoded reliable-input-stream message size (1 KiB).
pub const RELIABLE_INPUT_MESSAGE_LIMIT: usize = 1024;
/// Maximum encoded pointer-fallback message size (1 KiB).
pub const POINTER_FALLBACK_MESSAGE_LIMIT: usize = 1024;
/// Maximum encoded QUIC datagram message size (1200 bytes).
pub const DATAGRAM_MESSAGE_LIMIT: usize = 1200;
/// Maximum magnitude of one semantic relative pointer delta axis.
pub const MAX_POINTER_DELTA_MAGNITUDE: u32 = 32_767;
/// Maximum encoded file manifest size (1 MiB).
pub const MANIFEST_MESSAGE_LIMIT: usize = 1024 * 1024;
/// Maximum UTF-8 byte length of one manifest path.
pub const PATH_BYTE_LIMIT: usize = 1024;
/// Maximum number of entries in one manifest.
pub const MANIFEST_ENTRY_LIMIT: usize = 10_000;
/// Maximum aggregate logical file size described by one manifest (10 GiB).
pub const MANIFEST_AGGREGATE_LIMIT: u64 = 10 * 1024 * 1024 * 1024;
/// Maximum number of bytes in one clipboard or file-data chunk (256 KiB).
pub const BULK_CHUNK_LIMIT: usize = 256 * 1024;
/// Maximum encoded clipboard message size, including bounded envelope overhead.
pub const CLIPBOARD_MESSAGE_LIMIT: usize = BULK_CHUNK_LIMIT + 1024;
/// Maximum encoded file-data message size, including bounded envelope overhead.
pub const FILE_DATA_MESSAGE_LIMIT: usize = BULK_CHUNK_LIMIT + 1024;

// Conventional aliases keep the units explicit for transport and parser call
// sites while preserving the shorter protocol vocabulary above.
pub const MAX_CONTROL_MESSAGE_BYTES: usize = CONTROL_MESSAGE_LIMIT;
pub const MAX_RELIABLE_INPUT_BYTES: usize = RELIABLE_INPUT_MESSAGE_LIMIT;
pub const MAX_POINTER_FALLBACK_BYTES: usize = POINTER_FALLBACK_MESSAGE_LIMIT;
pub const MAX_DATAGRAM_BYTES: usize = DATAGRAM_MESSAGE_LIMIT;
pub const MAX_MANIFEST_BYTES: usize = MANIFEST_MESSAGE_LIMIT;
pub const MAX_PATH_BYTES: usize = PATH_BYTE_LIMIT;
pub const MAX_MANIFEST_ENTRIES: usize = MANIFEST_ENTRY_LIMIT;
pub const MAX_MANIFEST_AGGREGATE_BYTES: u64 = MANIFEST_AGGREGATE_LIMIT;
pub const MAX_BULK_CHUNK_BYTES: usize = BULK_CHUNK_LIMIT;
pub const MAX_FILE_CHUNK_BYTES: usize = BULK_CHUNK_LIMIT;
pub const MAX_CLIPBOARD_MESSAGE_BYTES: usize = CLIPBOARD_MESSAGE_LIMIT;
pub const MAX_FILE_DATA_MESSAGE_BYTES: usize = FILE_DATA_MESSAGE_LIMIT;
