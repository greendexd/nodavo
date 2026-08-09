//! Clipboard wire semantics.
//!
//! Clipboard tags occupy `0x2000..=0x20ff`; the implemented critical tags are
//! `0x2000` offer, `0x2001` clear, `0x2002` request, `0x2003` chunk, and
//! `0x2004` abort. This range is disjoint from control (`0x0000`), input
//! (`0x1000`), file-manifest (`0x3000`), and file-data (`0x4000`) tags.

use core::fmt;

use minicbor::{Decode, Decoder, Encode, Encoder, decode, encode};
use serde::{Deserialize, Serialize};

use crate::EventMeta;

pub const MAX_CLIPBOARD_REPRESENTATIONS: usize = 8;
pub const MAX_CLIPBOARD_TEXT_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_CLIPBOARD_HTML_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_CLIPBOARD_IMAGE_BYTES: u64 = 100 * 1024 * 1024;
pub const MAX_CLIPBOARD_FILE_LIST_BYTES: u64 = 1024 * 1024;
pub const MAX_CLIPBOARD_CHUNK_BYTES: usize = 256 * 1024;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ContentHash([u8; 32]);

impl ContentHash {
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for ContentHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ContentHash([redacted])")
    }
}

impl<C> Encode<C> for ContentHash {
    fn encode<W: encode::Write>(
        &self,
        encoder: &mut Encoder<W>,
        _context: &mut C,
    ) -> Result<(), encode::Error<W::Error>> {
        encoder.bytes(&self.0)?;
        Ok(())
    }
}

impl<'bytes, C> Decode<'bytes, C> for ContentHash {
    fn decode(decoder: &mut Decoder<'bytes>, _context: &mut C) -> Result<Self, decode::Error> {
        let bytes: [u8; 32] = decoder
            .bytes()?
            .try_into()
            .map_err(|_| decode::Error::message("content hash must contain exactly 32 bytes"))?;
        Ok(Self(bytes))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Encode, Decode)]
#[cbor(transparent)]
pub struct ClipboardRevision(#[n(0)] u64);

impl ClipboardRevision {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Encode, Decode)]
#[cbor(index_only)]
pub enum ClipboardRepresentationKind {
    #[n(0)]
    Utf8Text,
    #[n(1)]
    Html,
    #[n(2)]
    Png,
    #[n(3)]
    Bmp,
    #[n(4)]
    FileList,
}

impl ClipboardRepresentationKind {
    #[must_use]
    pub const fn max_bytes(self) -> u64 {
        match self {
            Self::Utf8Text => MAX_CLIPBOARD_TEXT_BYTES,
            Self::Html => MAX_CLIPBOARD_HTML_BYTES,
            Self::Png | Self::Bmp => MAX_CLIPBOARD_IMAGE_BYTES,
            Self::FileList => MAX_CLIPBOARD_FILE_LIST_BYTES,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Encode, Decode)]
#[cbor(map)]
pub struct ClipboardRepresentation {
    #[n(0)]
    pub kind: ClipboardRepresentationKind,
    #[n(1)]
    pub byte_len: u64,
    #[n(2)]
    pub hash: ContentHash,
}

impl ClipboardRepresentation {
    pub(crate) const fn is_valid(self) -> bool {
        self.byte_len <= self.kind.max_bytes()
            && (self.byte_len != 0
                || !matches!(
                    self.kind,
                    ClipboardRepresentationKind::Png | ClipboardRepresentationKind::Bmp
                ))
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClipboardMessage {
    Offer {
        meta: EventMeta,
        revision: ClipboardRevision,
        representations: Vec<ClipboardRepresentation>,
    },
    Clear {
        meta: EventMeta,
        revision: ClipboardRevision,
    },
    Request {
        meta: EventMeta,
        revision: ClipboardRevision,
        kind: ClipboardRepresentationKind,
        hash: ContentHash,
    },
    Chunk {
        meta: EventMeta,
        revision: ClipboardRevision,
        kind: ClipboardRepresentationKind,
        hash: ContentHash,
        offset: u64,
        bytes: Vec<u8>,
    },
    Abort {
        meta: EventMeta,
        revision: ClipboardRevision,
        reason: u16,
    },
    Unknown {
        tag: u16,
        payload: Vec<u8>,
    },
}

impl ClipboardMessage {
    #[must_use]
    pub const fn meta(&self) -> Option<&EventMeta> {
        match self {
            Self::Offer { meta, .. }
            | Self::Clear { meta, .. }
            | Self::Request { meta, .. }
            | Self::Chunk { meta, .. }
            | Self::Abort { meta, .. } => Some(meta),
            Self::Unknown { .. } => None,
        }
    }
}

impl fmt::Debug for ClipboardMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Offer { .. } => formatter.write_str("ClipboardMessage::Offer([redacted])"),
            Self::Clear { .. } => formatter.write_str("ClipboardMessage::Clear([redacted])"),
            Self::Request { .. } => formatter.write_str("ClipboardMessage::Request([redacted])"),
            Self::Chunk { .. } => formatter.write_str("ClipboardMessage::Chunk([redacted])"),
            Self::Abort { .. } => formatter.write_str("ClipboardMessage::Abort([redacted])"),
            Self::Unknown { tag, .. } => formatter
                .debug_struct("ClipboardMessage::Unknown")
                .field("tag", tag)
                .field("payload", &"[redacted]")
                .finish(),
        }
    }
}
