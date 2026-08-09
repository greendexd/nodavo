//! File-transfer wire semantics.
//!
//! Manifest/control tags occupy `0x3000..=0x30ff`: `0x3000` manifest,
//! `0x3001` resume, `0x3002` cancel, and `0x3003` complete. File data occupies
//! `0x4000..=0x40ff`, with `0x4000` chunk. These ranges do not overlap the
//! control, input, or clipboard ranges.

use core::fmt;
use std::collections::{HashMap, HashSet};

use minicbor::{Decode, Decoder, Encode, Encoder, decode, encode};
use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization as _;

use crate::{
    ContentHash, EventMeta, MANIFEST_AGGREGATE_LIMIT, MANIFEST_ENTRY_LIMIT, PATH_BYTE_LIMIT,
};

#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TransferId([u8; 16]);

impl TransferId {
    #[must_use]
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub(crate) fn is_valid(self) -> bool {
        self.0 != [0; 16]
    }
}

impl fmt::Debug for TransferId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TransferId([redacted])")
    }
}

impl<C> Encode<C> for TransferId {
    fn encode<W: encode::Write>(
        &self,
        encoder: &mut Encoder<W>,
        _context: &mut C,
    ) -> Result<(), encode::Error<W::Error>> {
        encoder.bytes(&self.0)?;
        Ok(())
    }
}

impl<'bytes, C> Decode<'bytes, C> for TransferId {
    fn decode(decoder: &mut Decoder<'bytes>, _context: &mut C) -> Result<Self, decode::Error> {
        let bytes: [u8; 16] = decoder
            .bytes()?
            .try_into()
            .map_err(|_| decode::Error::message("transfer ID must contain exactly 16 bytes"))?;
        Ok(Self(bytes))
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RelativePath(String);

impl RelativePath {
    /// Parses and NFC-normalizes a portable relative path.
    ///
    /// # Errors
    ///
    /// Rejects empty, absolute, traversal, backslash-containing, control,
    /// Windows-reserved, ambiguous trailing-dot/space, or oversized paths.
    pub fn parse(input: &str) -> Result<Self, &'static str> {
        if input.is_empty() || input.len() > PATH_BYTE_LIMIT {
            return Err("file path must contain between 1 and 1024 UTF-8 bytes");
        }
        if input.starts_with('/') || input.starts_with('\\') || input.contains('\\') {
            return Err("file path must be relative and use forward slashes");
        }
        let normalized = input.nfc().collect::<String>();
        if normalized.len() > PATH_BYTE_LIMIT {
            return Err("normalized file path exceeds 1024 UTF-8 bytes");
        }
        for segment in normalized.split('/') {
            if segment.is_empty()
                || matches!(segment, "." | "..")
                || segment.ends_with(['.', ' '])
                || segment.chars().any(is_unsafe_filename_character)
                || is_windows_reserved_name(segment)
            {
                return Err("file path contains an unsafe segment");
            }
        }
        Ok(Self(normalized))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn collision_key(&self) -> String {
        self.0.to_lowercase()
    }
}

impl fmt::Debug for RelativePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RelativePath([redacted])")
    }
}

impl<C> Encode<C> for RelativePath {
    fn encode<W: encode::Write>(
        &self,
        encoder: &mut Encoder<W>,
        _context: &mut C,
    ) -> Result<(), encode::Error<W::Error>> {
        encoder.str(&self.0)?;
        Ok(())
    }
}

impl<'bytes, C> Decode<'bytes, C> for RelativePath {
    fn decode(decoder: &mut Decoder<'bytes>, _context: &mut C) -> Result<Self, decode::Error> {
        Self::parse(decoder.str()?).map_err(decode::Error::message)
    }
}

fn is_unsafe_filename_character(character: char) -> bool {
    character.is_control() || matches!(character, '\0' | ':' | '*' | '?' | '"' | '<' | '>' | '|')
}

fn is_windows_reserved_name(segment: &str) -> bool {
    let stem = segment
        .split('.')
        .next()
        .unwrap_or(segment)
        .to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || stem
            .strip_prefix("COM")
            .or_else(|| stem.strip_prefix("LPT"))
            .is_some_and(|suffix| {
                suffix.len() == 1 && matches!(suffix.as_bytes().first(), Some(b'1'..=b'9'))
            })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[cbor(index_only)]
pub enum ManifestEntryKind {
    #[n(0)]
    File,
    #[n(1)]
    Directory,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[cbor(map)]
pub struct ManifestEntry {
    #[n(0)]
    pub path: RelativePath,
    #[n(1)]
    pub kind: ManifestEntryKind,
    #[n(2)]
    pub size: u64,
    #[n(3)]
    pub hash: Option<ContentHash>,
}

pub(crate) fn validate_manifest(entries: &[ManifestEntry]) -> Result<(), &'static str> {
    if entries.is_empty() || entries.len() > MANIFEST_ENTRY_LIMIT {
        return Err("manifest must contain between 1 and 10000 entries");
    }

    let mut total = 0_u64;
    let mut kinds = HashMap::with_capacity(entries.len());
    let mut paths = HashSet::with_capacity(entries.len());
    for entry in entries {
        let key = entry.path.collision_key();
        if !paths.insert(key.clone()) {
            return Err("manifest contains a case-insensitive path collision");
        }
        match entry.kind {
            ManifestEntryKind::File if entry.hash.is_some() => {
                total = total
                    .checked_add(entry.size)
                    .ok_or("manifest aggregate size overflows")?;
                if total > MANIFEST_AGGREGATE_LIMIT {
                    return Err("manifest aggregate size exceeds 10 GiB");
                }
            }
            ManifestEntryKind::Directory if entry.size == 0 && entry.hash.is_none() => {}
            ManifestEntryKind::File => return Err("file entry requires a 32-byte hash"),
            ManifestEntryKind::Directory => {
                return Err("directory entry must have zero size and no hash");
            }
        }
        kinds.insert(key, entry.kind);
    }

    for entry in entries {
        let mut ancestor = String::new();
        let segments = entry.path.as_str().split('/').collect::<Vec<_>>();
        for segment in &segments[..segments.len().saturating_sub(1)] {
            if !ancestor.is_empty() {
                ancestor.push('/');
            }
            ancestor.push_str(segment);
            if kinds.get(&ancestor.to_lowercase()) == Some(&ManifestEntryKind::File) {
                return Err("manifest places an entry below a file");
            }
        }
    }
    Ok(())
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileManifestMessage {
    Manifest {
        meta: EventMeta,
        transfer: TransferId,
        entries: Vec<ManifestEntry>,
    },
    Resume {
        meta: EventMeta,
        transfer: TransferId,
        entry_index: u32,
        offset: u64,
    },
    Cancel {
        meta: EventMeta,
        transfer: TransferId,
        reason: u16,
    },
    Complete {
        meta: EventMeta,
        transfer: TransferId,
    },
    Unknown {
        tag: u16,
        payload: Vec<u8>,
    },
}

impl FileManifestMessage {
    #[must_use]
    pub const fn meta(&self) -> Option<&EventMeta> {
        match self {
            Self::Manifest { meta, .. }
            | Self::Resume { meta, .. }
            | Self::Cancel { meta, .. }
            | Self::Complete { meta, .. } => Some(meta),
            Self::Unknown { .. } => None,
        }
    }
}

impl fmt::Debug for FileManifestMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Manifest { .. } => "Manifest",
            Self::Resume { .. } => "Resume",
            Self::Cancel { .. } => "Cancel",
            Self::Complete { .. } => "Complete",
            Self::Unknown { .. } => "Unknown",
        };
        write!(formatter, "FileManifestMessage::{name}([redacted])")
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileDataMessage {
    Chunk {
        meta: EventMeta,
        transfer: TransferId,
        entry_index: u32,
        offset: u64,
        bytes: Vec<u8>,
    },
    Unknown {
        tag: u16,
        payload: Vec<u8>,
    },
}

impl FileDataMessage {
    #[must_use]
    pub const fn meta(&self) -> Option<&EventMeta> {
        match self {
            Self::Chunk { meta, .. } => Some(meta),
            Self::Unknown { .. } => None,
        }
    }
}

impl fmt::Debug for FileDataMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Chunk { .. } => formatter.write_str("FileDataMessage::Chunk([redacted])"),
            Self::Unknown { .. } => formatter.write_str("FileDataMessage::Unknown([redacted])"),
        }
    }
}
