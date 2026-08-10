//! Transport-independent wire types and bounded canonical CBOR codecs.
//!
//! This crate deliberately has no async runtime or platform dependencies. Callers
//! choose a codec entry point matching the QUIC channel they are reading; the
//! entry point applies the channel's hard limit before CBOR decoding allocates.

mod bulk_codec;
mod clipboard;
mod codec;
mod limits;
mod message;
mod topology;
mod transfer;
mod types;

pub use bulk_codec::{
    decode_clipboard, decode_file_data, decode_file_manifest, encode_clipboard, encode_file_data,
    encode_file_manifest,
};
pub use clipboard::{
    ClipboardMessage, ClipboardRepresentation, ClipboardRepresentationKind, ClipboardRevision,
    ContentHash, MAX_CLIPBOARD_CHUNK_BYTES, MAX_CLIPBOARD_FILE_LIST_BYTES,
    MAX_CLIPBOARD_HTML_BYTES, MAX_CLIPBOARD_IMAGE_BYTES, MAX_CLIPBOARD_REPRESENTATIONS,
    MAX_CLIPBOARD_TEXT_BYTES,
};
pub use codec::{
    DecodeError, EncodeError, decode_control, decode_datagram, decode_pointer_fallback,
    decode_reliable_input, encode_control, encode_datagram, encode_pointer_fallback,
    encode_reliable_input,
};
pub use limits::{
    BULK_CHUNK_LIMIT, CLIPBOARD_MESSAGE_LIMIT, CONTROL_MESSAGE_LIMIT, DATAGRAM_MESSAGE_LIMIT,
    FILE_DATA_MESSAGE_LIMIT, MANIFEST_AGGREGATE_LIMIT, MANIFEST_ENTRY_LIMIT,
    MANIFEST_MESSAGE_LIMIT, MAX_BULK_CHUNK_BYTES, MAX_CLIPBOARD_MESSAGE_BYTES,
    MAX_CONTROL_MESSAGE_BYTES, MAX_DATAGRAM_BYTES, MAX_FILE_CHUNK_BYTES,
    MAX_FILE_DATA_MESSAGE_BYTES, MAX_MANIFEST_AGGREGATE_BYTES, MAX_MANIFEST_BYTES,
    MAX_MANIFEST_ENTRIES, MAX_PATH_BYTES, MAX_POINTER_DELTA_MAGNITUDE, MAX_POINTER_FALLBACK_BYTES,
    MAX_RELIABLE_INPUT_BYTES, PATH_BYTE_LIMIT, POINTER_FALLBACK_MESSAGE_LIMIT,
    RELIABLE_INPUT_MESSAGE_LIMIT,
};
pub use message::{
    ButtonState, ControlMessage, InputMessage, KeyEvent, KeyState, PointerButtonEvent,
    PointerDeltaEvent, PointerEnterEvent, PointerMotionEvent, ProtocolErrorCode, ReleaseAllEvent,
    ScrollEvent, ScrollUnit, WireMessage,
};
pub use topology::{
    DISPLAY_TOPOLOGY_SCHEMA_VERSION, DisplayDescriptor, DisplayRotation, DisplayTopology,
    MAX_DISPLAY_ORIGIN_MILLI, MAX_DISPLAY_PIXEL_DIMENSION, MAX_DISPLAY_SCALE_MILLI,
    MAX_TOPOLOGY_DISPLAYS, MIN_DISPLAY_SCALE_MILLI, SessionDisplayId, TopologyValidationError,
};
pub use transfer::{
    FileDataMessage, FileManifestMessage, ManifestEntry, ManifestEntryKind, RelativePath,
    TransferId,
};
pub use types::{
    Capability, DeviceId, EventMeta, GrantEpoch, ProtocolVersion, Sequence, SessionId,
};
