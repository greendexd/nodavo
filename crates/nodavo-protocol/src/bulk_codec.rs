//! Canonical CBOR codecs for the separately backpressured bulk-data channels.
//!
//! Reserved wire ranges are clipboard `0x2000..=0x20ff`, file-manifest
//! `0x3000..=0x30ff`, and file-data `0x4000..=0x40ff`. Implemented messages
//! are critical. An unknown non-critical tag is retained only on its own
//! channel; an unknown critical tag fails closed.

use core::convert::Infallible;

use minicbor::{Decode, Decoder, Encode};

use crate::clipboard::{MAX_CLIPBOARD_CHUNK_BYTES, MAX_CLIPBOARD_REPRESENTATIONS};
use crate::transfer::validate_manifest;
use crate::{BULK_CHUNK_LIMIT, CLIPBOARD_MESSAGE_LIMIT};
use crate::{
    Capability, ClipboardMessage, ClipboardRepresentation, ClipboardRepresentationKind,
    ClipboardRevision, ContentHash, DecodeError, EncodeError, EventMeta, FILE_DATA_MESSAGE_LIMIT,
    FileDataMessage, FileManifestMessage, MANIFEST_AGGREGATE_LIMIT, MANIFEST_ENTRY_LIMIT,
    MANIFEST_MESSAGE_LIMIT, ManifestEntry, ProtocolVersion, TransferId,
};

pub(crate) const CLIPBOARD_TAG_RANGE: core::ops::RangeInclusive<u16> = 0x2000..=0x20ff;
pub(crate) const FILE_MANIFEST_TAG_RANGE: core::ops::RangeInclusive<u16> = 0x3000..=0x30ff;
pub(crate) const FILE_DATA_TAG_RANGE: core::ops::RangeInclusive<u16> = 0x4000..=0x40ff;

const TAG_CLIPBOARD_OFFER: u16 = 0x2000;
const TAG_CLIPBOARD_CLEAR: u16 = 0x2001;
const TAG_CLIPBOARD_REQUEST: u16 = 0x2002;
const TAG_CLIPBOARD_CHUNK: u16 = 0x2003;
const TAG_CLIPBOARD_ABORT: u16 = 0x2004;

const TAG_FILE_MANIFEST: u16 = 0x3000;
const TAG_FILE_RESUME: u16 = 0x3001;
const TAG_FILE_CANCEL: u16 = 0x3002;
const TAG_FILE_COMPLETE: u16 = 0x3003;

const TAG_FILE_CHUNK: u16 = 0x4000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BulkChannel {
    Clipboard,
    FileManifest,
    FileData,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
struct Envelope {
    #[n(0)]
    version: ProtocolVersion,
    #[n(1)]
    tag: u16,
    #[n(2)]
    critical: bool,
    #[n(3)]
    payload: CborBytes,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CborBytes(Vec<u8>);

impl<C> Encode<C> for CborBytes {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        _context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.bytes(&self.0)?;
        Ok(())
    }
}

impl<'bytes, C> Decode<'bytes, C> for CborBytes {
    fn decode(
        decoder: &mut Decoder<'bytes>,
        _context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        Ok(Self(decoder.bytes()?.to_vec()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct BoundedRepresentations(Vec<ClipboardRepresentation>);

impl<C> Encode<C> for BoundedRepresentations {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(self.0.len() as u64)?;
        for representation in &self.0 {
            representation.encode(encoder, context)?;
        }
        Ok(())
    }
}

impl<'bytes, C> Decode<'bytes, C> for BoundedRepresentations {
    fn decode(
        decoder: &mut Decoder<'bytes>,
        context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        let length = decoder
            .array()?
            .ok_or_else(|| minicbor::decode::Error::message("indefinite representation array"))?;
        if length == 0 || length > MAX_CLIPBOARD_REPRESENTATIONS as u64 {
            return Err(minicbor::decode::Error::message(
                "clipboard representation count exceeds limit",
            ));
        }
        let capacity = usize::try_from(length)
            .map_err(|_| minicbor::decode::Error::message("representation count overflows"))?;
        let mut values = Vec::with_capacity(capacity);
        for _ in 0..length {
            values.push(ClipboardRepresentation::decode(decoder, context)?);
        }
        Ok(Self(values))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct BoundedEntries(Vec<ManifestEntry>);

impl<C> Encode<C> for BoundedEntries {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(self.0.len() as u64)?;
        for entry in &self.0 {
            entry.encode(encoder, context)?;
        }
        Ok(())
    }
}

impl<'bytes, C> Decode<'bytes, C> for BoundedEntries {
    fn decode(
        decoder: &mut Decoder<'bytes>,
        context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        let length = decoder
            .array()?
            .ok_or_else(|| minicbor::decode::Error::message("indefinite manifest array"))?;
        if length == 0 || length > MANIFEST_ENTRY_LIMIT as u64 {
            return Err(minicbor::decode::Error::message(
                "manifest entry count exceeds limit",
            ));
        }
        let capacity = usize::try_from(length)
            .map_err(|_| minicbor::decode::Error::message("manifest entry count overflows"))?;
        let mut values = Vec::with_capacity(capacity);
        for _ in 0..length {
            values.push(ManifestEntry::decode(decoder, context)?);
        }
        Ok(Self(values))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
struct ClipboardOfferBody {
    #[n(0)]
    meta: EventMeta,
    #[n(1)]
    revision: ClipboardRevision,
    #[n(2)]
    representations: BoundedRepresentations,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
struct ClipboardClearBody {
    #[n(0)]
    meta: EventMeta,
    #[n(1)]
    revision: ClipboardRevision,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
struct ClipboardRequestBody {
    #[n(0)]
    meta: EventMeta,
    #[n(1)]
    revision: ClipboardRevision,
    #[n(2)]
    kind: ClipboardRepresentationKind,
    #[n(3)]
    hash: ContentHash,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
struct ClipboardChunkBody {
    #[n(0)]
    meta: EventMeta,
    #[n(1)]
    revision: ClipboardRevision,
    #[n(2)]
    kind: ClipboardRepresentationKind,
    #[n(3)]
    hash: ContentHash,
    #[n(4)]
    offset: u64,
    #[n(5)]
    bytes: CborBytes,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
struct ClipboardAbortBody {
    #[n(0)]
    meta: EventMeta,
    #[n(1)]
    revision: ClipboardRevision,
    #[n(2)]
    reason: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
struct ManifestBody {
    #[n(0)]
    meta: EventMeta,
    #[n(1)]
    transfer: TransferId,
    #[n(2)]
    entries: BoundedEntries,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
struct ResumeBody {
    #[n(0)]
    meta: EventMeta,
    #[n(1)]
    transfer: TransferId,
    #[n(2)]
    entry_index: u32,
    #[n(3)]
    offset: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
struct CancelBody {
    #[n(0)]
    meta: EventMeta,
    #[n(1)]
    transfer: TransferId,
    #[n(2)]
    reason: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
struct CompleteBody {
    #[n(0)]
    meta: EventMeta,
    #[n(1)]
    transfer: TransferId,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
struct FileChunkBody {
    #[n(0)]
    meta: EventMeta,
    #[n(1)]
    transfer: TransferId,
    #[n(2)]
    entry_index: u32,
    #[n(3)]
    offset: u64,
    #[n(4)]
    bytes: CborBytes,
}

/// Encodes one clipboard-channel message as bounded canonical CBOR.
///
/// # Errors
///
/// Returns an error for invalid semantics, reserved cross-channel tags,
/// encoding failure, or an encoded message above the channel limit.
pub fn encode_clipboard(message: &ClipboardMessage) -> Result<Vec<u8>, EncodeError> {
    validate_clipboard(message).map_err(EncodeError::InvalidMessage)?;
    let (tag, critical, payload) = encode_clipboard_payload(message)?;
    encode_envelope(tag, critical, payload, CLIPBOARD_MESSAGE_LIMIT)
}

/// Decodes one clipboard-channel message, including canonical body validation.
///
/// # Errors
///
/// Returns an error for oversized, malformed, non-canonical, cross-channel,
/// unsupported, invalid, or unknown critical messages.
pub fn decode_clipboard(bytes: &[u8]) -> Result<ClipboardMessage, DecodeError> {
    let envelope = decode_envelope(bytes, BulkChannel::Clipboard, CLIPBOARD_MESSAGE_LIMIT)?;
    if !is_implemented_clipboard_tag(envelope.tag) {
        return Ok(ClipboardMessage::Unknown {
            tag: envelope.tag,
            payload: envelope.payload.0,
        });
    }
    let message = decode_clipboard_payload(envelope.tag, &envelope.payload.0)?;
    validate_clipboard(&message).map_err(DecodeError::InvalidMessage)?;
    Ok(message)
}

/// Encodes one file-manifest/control-channel message as bounded canonical CBOR.
///
/// # Errors
///
/// Returns an error for invalid manifest semantics, reserved cross-channel
/// tags, encoding failure, or a message above one MiB.
pub fn encode_file_manifest(message: &FileManifestMessage) -> Result<Vec<u8>, EncodeError> {
    validate_file_manifest(message).map_err(EncodeError::InvalidMessage)?;
    let (tag, critical, payload) = encode_file_manifest_payload(message)?;
    encode_envelope(tag, critical, payload, MANIFEST_MESSAGE_LIMIT)
}

/// Decodes one file-manifest/control-channel message before exposing its paths.
///
/// # Errors
///
/// Returns an error for oversized, malformed, non-canonical, cross-channel,
/// unsupported, invalid, or unknown critical messages.
pub fn decode_file_manifest(bytes: &[u8]) -> Result<FileManifestMessage, DecodeError> {
    let envelope = decode_envelope(bytes, BulkChannel::FileManifest, MANIFEST_MESSAGE_LIMIT)?;
    if !is_implemented_manifest_tag(envelope.tag) {
        return Ok(FileManifestMessage::Unknown {
            tag: envelope.tag,
            payload: envelope.payload.0,
        });
    }
    let message = decode_file_manifest_payload(envelope.tag, &envelope.payload.0)?;
    validate_file_manifest(&message).map_err(DecodeError::InvalidMessage)?;
    Ok(message)
}

/// Encodes one file-data-channel message as bounded canonical CBOR.
///
/// # Errors
///
/// Returns an error for invalid chunks, reserved cross-channel tags, encoding
/// failure, or a message above the channel limit.
pub fn encode_file_data(message: &FileDataMessage) -> Result<Vec<u8>, EncodeError> {
    validate_file_data(message).map_err(EncodeError::InvalidMessage)?;
    let (tag, critical, payload) = encode_file_data_payload(message)?;
    encode_envelope(tag, critical, payload, FILE_DATA_MESSAGE_LIMIT)
}

/// Decodes one file-data-channel message, including canonical body validation.
///
/// # Errors
///
/// Returns an error for oversized, malformed, non-canonical, cross-channel,
/// unsupported, invalid, or unknown critical messages.
pub fn decode_file_data(bytes: &[u8]) -> Result<FileDataMessage, DecodeError> {
    let envelope = decode_envelope(bytes, BulkChannel::FileData, FILE_DATA_MESSAGE_LIMIT)?;
    if !is_implemented_file_data_tag(envelope.tag) {
        return Ok(FileDataMessage::Unknown {
            tag: envelope.tag,
            payload: envelope.payload.0,
        });
    }
    let message = decode_file_data_payload(envelope.tag, &envelope.payload.0)?;
    validate_file_data(&message).map_err(DecodeError::InvalidMessage)?;
    Ok(message)
}

fn encode_envelope(
    tag: u16,
    critical: bool,
    payload: Vec<u8>,
    limit: usize,
) -> Result<Vec<u8>, EncodeError> {
    let bytes = cbor_encode(&Envelope {
        version: ProtocolVersion::CURRENT,
        tag,
        critical,
        payload: CborBytes(payload),
    })?;
    if bytes.len() > limit {
        return Err(EncodeError::MessageTooLarge {
            actual: bytes.len(),
            limit,
        });
    }
    Ok(bytes)
}

fn decode_envelope(
    bytes: &[u8],
    channel: BulkChannel,
    limit: usize,
) -> Result<Envelope, DecodeError> {
    if bytes.len() > limit {
        return Err(DecodeError::MessageTooLarge {
            actual: bytes.len(),
            limit,
        });
    }
    let envelope: Envelope = cbor_decode(bytes)?;
    if cbor_encode_decode(&envelope)? != bytes {
        return Err(DecodeError::NonCanonical);
    }
    if !envelope.version.is_well_formed() {
        return Err(DecodeError::InvalidVersion);
    }
    if envelope.version != ProtocolVersion::CURRENT {
        return Err(DecodeError::UnsupportedVersion {
            major: envelope.version.major(),
            minor: envelope.version.minor(),
        });
    }

    if let Some(tag_channel) = reserved_bulk_channel(envelope.tag) {
        if tag_channel != channel {
            return Err(DecodeError::WrongChannel);
        }
        if is_implemented_bulk_tag(envelope.tag) {
            if !envelope.critical {
                return Err(DecodeError::InvalidMessage(
                    "message criticality does not match its tag",
                ));
            }
            return Ok(envelope);
        }
    } else if is_existing_protocol_tag(envelope.tag) {
        return Err(DecodeError::WrongChannel);
    }

    if envelope.critical {
        return Err(DecodeError::UnknownCriticalMessage { tag: envelope.tag });
    }
    Ok(envelope)
}

fn encode_clipboard_payload(
    message: &ClipboardMessage,
) -> Result<(u16, bool, Vec<u8>), EncodeError> {
    let encoded = match message {
        ClipboardMessage::Offer {
            meta,
            revision,
            representations,
        } => (
            TAG_CLIPBOARD_OFFER,
            true,
            encode_body(&ClipboardOfferBody {
                meta: *meta,
                revision: *revision,
                representations: BoundedRepresentations(representations.clone()),
            })?,
        ),
        ClipboardMessage::Clear { meta, revision } => (
            TAG_CLIPBOARD_CLEAR,
            true,
            encode_body(&ClipboardClearBody {
                meta: *meta,
                revision: *revision,
            })?,
        ),
        ClipboardMessage::Request {
            meta,
            revision,
            kind,
            hash,
        } => (
            TAG_CLIPBOARD_REQUEST,
            true,
            encode_body(&ClipboardRequestBody {
                meta: *meta,
                revision: *revision,
                kind: *kind,
                hash: *hash,
            })?,
        ),
        ClipboardMessage::Chunk {
            meta,
            revision,
            kind,
            hash,
            offset,
            bytes,
        } => (
            TAG_CLIPBOARD_CHUNK,
            true,
            encode_body(&ClipboardChunkBody {
                meta: *meta,
                revision: *revision,
                kind: *kind,
                hash: *hash,
                offset: *offset,
                bytes: CborBytes(bytes.clone()),
            })?,
        ),
        ClipboardMessage::Abort {
            meta,
            revision,
            reason,
        } => (
            TAG_CLIPBOARD_ABORT,
            true,
            encode_body(&ClipboardAbortBody {
                meta: *meta,
                revision: *revision,
                reason: *reason,
            })?,
        ),
        ClipboardMessage::Unknown { tag, payload } => (*tag, false, payload.clone()),
    };
    Ok(encoded)
}

fn decode_clipboard_payload(tag: u16, payload: &[u8]) -> Result<ClipboardMessage, DecodeError> {
    let message = match tag {
        TAG_CLIPBOARD_OFFER => {
            let body: ClipboardOfferBody = decode_body(payload)?;
            ClipboardMessage::Offer {
                meta: body.meta,
                revision: body.revision,
                representations: body.representations.0,
            }
        }
        TAG_CLIPBOARD_CLEAR => {
            let body: ClipboardClearBody = decode_body(payload)?;
            ClipboardMessage::Clear {
                meta: body.meta,
                revision: body.revision,
            }
        }
        TAG_CLIPBOARD_REQUEST => {
            let body: ClipboardRequestBody = decode_body(payload)?;
            ClipboardMessage::Request {
                meta: body.meta,
                revision: body.revision,
                kind: body.kind,
                hash: body.hash,
            }
        }
        TAG_CLIPBOARD_CHUNK => {
            let body: ClipboardChunkBody = decode_body(payload)?;
            ClipboardMessage::Chunk {
                meta: body.meta,
                revision: body.revision,
                kind: body.kind,
                hash: body.hash,
                offset: body.offset,
                bytes: body.bytes.0,
            }
        }
        TAG_CLIPBOARD_ABORT => {
            let body: ClipboardAbortBody = decode_body(payload)?;
            ClipboardMessage::Abort {
                meta: body.meta,
                revision: body.revision,
                reason: body.reason,
            }
        }
        _ => unreachable!("implemented clipboard tags are exhaustively matched"),
    };
    Ok(message)
}

fn encode_file_manifest_payload(
    message: &FileManifestMessage,
) -> Result<(u16, bool, Vec<u8>), EncodeError> {
    let encoded = match message {
        FileManifestMessage::Manifest {
            meta,
            transfer,
            entries,
        } => (
            TAG_FILE_MANIFEST,
            true,
            encode_body(&ManifestBody {
                meta: *meta,
                transfer: *transfer,
                entries: BoundedEntries(entries.clone()),
            })?,
        ),
        FileManifestMessage::Resume {
            meta,
            transfer,
            entry_index,
            offset,
        } => (
            TAG_FILE_RESUME,
            true,
            encode_body(&ResumeBody {
                meta: *meta,
                transfer: *transfer,
                entry_index: *entry_index,
                offset: *offset,
            })?,
        ),
        FileManifestMessage::Cancel {
            meta,
            transfer,
            reason,
        } => (
            TAG_FILE_CANCEL,
            true,
            encode_body(&CancelBody {
                meta: *meta,
                transfer: *transfer,
                reason: *reason,
            })?,
        ),
        FileManifestMessage::Complete { meta, transfer } => (
            TAG_FILE_COMPLETE,
            true,
            encode_body(&CompleteBody {
                meta: *meta,
                transfer: *transfer,
            })?,
        ),
        FileManifestMessage::Unknown { tag, payload } => (*tag, false, payload.clone()),
    };
    Ok(encoded)
}

fn decode_file_manifest_payload(
    tag: u16,
    payload: &[u8],
) -> Result<FileManifestMessage, DecodeError> {
    let message = match tag {
        TAG_FILE_MANIFEST => {
            let body: ManifestBody = decode_body(payload)?;
            FileManifestMessage::Manifest {
                meta: body.meta,
                transfer: body.transfer,
                entries: body.entries.0,
            }
        }
        TAG_FILE_RESUME => {
            let body: ResumeBody = decode_body(payload)?;
            FileManifestMessage::Resume {
                meta: body.meta,
                transfer: body.transfer,
                entry_index: body.entry_index,
                offset: body.offset,
            }
        }
        TAG_FILE_CANCEL => {
            let body: CancelBody = decode_body(payload)?;
            FileManifestMessage::Cancel {
                meta: body.meta,
                transfer: body.transfer,
                reason: body.reason,
            }
        }
        TAG_FILE_COMPLETE => {
            let body: CompleteBody = decode_body(payload)?;
            FileManifestMessage::Complete {
                meta: body.meta,
                transfer: body.transfer,
            }
        }
        _ => unreachable!("implemented file-manifest tags are exhaustively matched"),
    };
    Ok(message)
}

fn encode_file_data_payload(
    message: &FileDataMessage,
) -> Result<(u16, bool, Vec<u8>), EncodeError> {
    let encoded = match message {
        FileDataMessage::Chunk {
            meta,
            transfer,
            entry_index,
            offset,
            bytes,
        } => (
            TAG_FILE_CHUNK,
            true,
            encode_body(&FileChunkBody {
                meta: *meta,
                transfer: *transfer,
                entry_index: *entry_index,
                offset: *offset,
                bytes: CborBytes(bytes.clone()),
            })?,
        ),
        FileDataMessage::Unknown { tag, payload } => (*tag, false, payload.clone()),
    };
    Ok(encoded)
}

fn decode_file_data_payload(tag: u16, payload: &[u8]) -> Result<FileDataMessage, DecodeError> {
    match tag {
        TAG_FILE_CHUNK => {
            let body: FileChunkBody = decode_body(payload)?;
            Ok(FileDataMessage::Chunk {
                meta: body.meta,
                transfer: body.transfer,
                entry_index: body.entry_index,
                offset: body.offset,
                bytes: body.bytes.0,
            })
        }
        _ => unreachable!("implemented file-data tags are exhaustively matched"),
    }
}

fn validate_clipboard(message: &ClipboardMessage) -> Result<(), &'static str> {
    match message {
        ClipboardMessage::Offer {
            meta,
            representations,
            ..
        } => {
            validate_clipboard_write_meta(meta)?;
            if representations.is_empty() || representations.len() > MAX_CLIPBOARD_REPRESENTATIONS {
                return Err("clipboard offer must contain between 1 and 8 representations");
            }
            let mut kinds = 0_u8;
            for representation in representations {
                if !representation.is_valid() {
                    return Err("clipboard representation exceeds its kind limit");
                }
                let bit = 1_u8 << (representation.kind as u8);
                if kinds & bit != 0 {
                    return Err("clipboard offer repeats a representation kind");
                }
                kinds |= bit;
            }
        }
        ClipboardMessage::Clear { meta, .. } => validate_clipboard_write_meta(meta)?,
        ClipboardMessage::Request { meta, .. } => validate_clipboard_read_meta(meta)?,
        ClipboardMessage::Abort { meta, .. } => validate_clipboard_meta(meta)?,
        ClipboardMessage::Chunk {
            meta,
            kind,
            offset,
            bytes,
            ..
        } => {
            validate_clipboard_write_meta(meta)?;
            if bytes.is_empty() || bytes.len() > MAX_CLIPBOARD_CHUNK_BYTES {
                return Err("clipboard chunk must contain between 1 and 262144 bytes");
            }
            let end = offset
                .checked_add(bytes.len() as u64)
                .ok_or("clipboard chunk range overflows")?;
            if end > kind.max_bytes() {
                return Err("clipboard chunk exceeds its representation kind limit");
            }
        }
        ClipboardMessage::Unknown { tag, .. } => {
            validate_unknown_tag(*tag, BulkChannel::Clipboard)?;
        }
    }
    Ok(())
}

fn validate_clipboard_meta(meta: &EventMeta) -> Result<(), &'static str> {
    let capability = meta.capability();
    if capability != Capability::CLIPBOARD_READ && capability != Capability::CLIPBOARD_WRITE {
        return Err("clipboard messages require exactly one clipboard capability");
    }
    Ok(())
}

fn validate_clipboard_read_meta(meta: &EventMeta) -> Result<(), &'static str> {
    if meta.capability() != Capability::CLIPBOARD_READ {
        return Err("clipboard requests require exactly clipboard-read capability");
    }
    Ok(())
}

fn validate_clipboard_write_meta(meta: &EventMeta) -> Result<(), &'static str> {
    if meta.capability() != Capability::CLIPBOARD_WRITE {
        return Err("clipboard content requires exactly clipboard-write capability");
    }
    Ok(())
}

fn validate_file_manifest(message: &FileManifestMessage) -> Result<(), &'static str> {
    match message {
        FileManifestMessage::Manifest {
            meta,
            transfer,
            entries,
        } => {
            validate_file_meta(meta)?;
            validate_transfer(*transfer)?;
            validate_manifest(entries)?;
        }
        FileManifestMessage::Resume {
            meta,
            transfer,
            entry_index,
            offset,
        } => {
            validate_file_meta(meta)?;
            validate_transfer(*transfer)?;
            if *entry_index as usize >= MANIFEST_ENTRY_LIMIT || *offset > MANIFEST_AGGREGATE_LIMIT {
                return Err("file resume position exceeds transfer limits");
            }
        }
        FileManifestMessage::Cancel { meta, transfer, .. }
        | FileManifestMessage::Complete { meta, transfer } => {
            validate_file_meta(meta)?;
            validate_transfer(*transfer)?;
        }
        FileManifestMessage::Unknown { tag, .. } => {
            validate_unknown_tag(*tag, BulkChannel::FileManifest)?;
        }
    }
    Ok(())
}

fn validate_file_data(message: &FileDataMessage) -> Result<(), &'static str> {
    match message {
        FileDataMessage::Chunk {
            meta,
            transfer,
            entry_index,
            offset,
            bytes,
        } => {
            validate_file_meta(meta)?;
            validate_transfer(*transfer)?;
            if *entry_index as usize >= MANIFEST_ENTRY_LIMIT
                || bytes.is_empty()
                || bytes.len() > BULK_CHUNK_LIMIT
            {
                return Err("file chunk exceeds entry or chunk limits");
            }
            let end = offset
                .checked_add(bytes.len() as u64)
                .ok_or("file chunk range overflows")?;
            if end > MANIFEST_AGGREGATE_LIMIT {
                return Err("file chunk range exceeds 10 GiB");
            }
        }
        FileDataMessage::Unknown { tag, .. } => {
            validate_unknown_tag(*tag, BulkChannel::FileData)?;
        }
    }
    Ok(())
}

fn validate_file_meta(meta: &EventMeta) -> Result<(), &'static str> {
    if meta.capability() != Capability::FILE_TRANSFER {
        return Err("file messages require exactly the file-transfer capability");
    }
    Ok(())
}

fn validate_transfer(transfer: TransferId) -> Result<(), &'static str> {
    if !transfer.is_valid() {
        return Err("transfer ID must be nonzero");
    }
    Ok(())
}

fn validate_unknown_tag(tag: u16, channel: BulkChannel) -> Result<(), &'static str> {
    if is_existing_protocol_tag(tag) || is_implemented_bulk_tag(tag) {
        return Err("unknown message uses a reserved known tag");
    }
    if reserved_bulk_channel(tag).is_some_and(|reserved| reserved != channel) {
        return Err("unknown message belongs on a different protocol channel");
    }
    Ok(())
}

pub(crate) fn is_reserved_bulk_tag(tag: u16) -> bool {
    reserved_bulk_channel(tag).is_some()
}

fn reserved_bulk_channel(tag: u16) -> Option<BulkChannel> {
    if CLIPBOARD_TAG_RANGE.contains(&tag) {
        Some(BulkChannel::Clipboard)
    } else if FILE_MANIFEST_TAG_RANGE.contains(&tag) {
        Some(BulkChannel::FileManifest)
    } else if FILE_DATA_TAG_RANGE.contains(&tag) {
        Some(BulkChannel::FileData)
    } else {
        None
    }
}

fn is_existing_protocol_tag(tag: u16) -> bool {
    matches!(tag, 0..=11 | 0x1000..=0x1004)
}

fn is_implemented_bulk_tag(tag: u16) -> bool {
    is_implemented_clipboard_tag(tag)
        || is_implemented_manifest_tag(tag)
        || is_implemented_file_data_tag(tag)
}

fn is_implemented_clipboard_tag(tag: u16) -> bool {
    matches!(
        tag,
        TAG_CLIPBOARD_OFFER
            | TAG_CLIPBOARD_CLEAR
            | TAG_CLIPBOARD_REQUEST
            | TAG_CLIPBOARD_CHUNK
            | TAG_CLIPBOARD_ABORT
    )
}

fn is_implemented_manifest_tag(tag: u16) -> bool {
    matches!(
        tag,
        TAG_FILE_MANIFEST | TAG_FILE_RESUME | TAG_FILE_CANCEL | TAG_FILE_COMPLETE
    )
}

fn is_implemented_file_data_tag(tag: u16) -> bool {
    tag == TAG_FILE_CHUNK
}

fn cbor_encode<T: Encode<()>>(value: &T) -> Result<Vec<u8>, EncodeError> {
    minicbor::to_vec(value)
        .map_err(|error: minicbor::encode::Error<Infallible>| EncodeError::Cbor(error.to_string()))
}

fn cbor_encode_decode<T: Encode<()>>(value: &T) -> Result<Vec<u8>, DecodeError> {
    minicbor::to_vec(value)
        .map_err(|error: minicbor::encode::Error<Infallible>| DecodeError::Cbor(error.to_string()))
}

fn cbor_decode<'bytes, T: Decode<'bytes, ()>>(bytes: &'bytes [u8]) -> Result<T, DecodeError> {
    let mut decoder = Decoder::new(bytes);
    let value = decoder
        .decode::<T>()
        .map_err(|error| DecodeError::Cbor(error.to_string()))?;
    if decoder.position() != bytes.len() {
        return Err(DecodeError::Cbor("trailing data".to_owned()));
    }
    Ok(value)
}

fn encode_body<T: Encode<()>>(body: &T) -> Result<Vec<u8>, EncodeError> {
    cbor_encode(body)
}

fn decode_body<'bytes, T>(bytes: &'bytes [u8]) -> Result<T, DecodeError>
where
    T: Decode<'bytes, ()> + Encode<()>,
{
    let value: T = cbor_decode(bytes)?;
    if cbor_encode_decode(&value)? != bytes {
        return Err(DecodeError::NonCanonical);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DeviceId, GrantEpoch, ManifestEntryKind, RelativePath, Sequence, SessionId};

    fn meta(capability: Capability) -> EventMeta {
        EventMeta::new(
            SessionId::new([3; 16]),
            DeviceId::new([7; 32]),
            Sequence::new(42),
            GrantEpoch::new(9),
            capability,
        )
    }

    fn hash() -> ContentHash {
        ContentHash::new([5; 32])
    }

    fn transfer() -> TransferId {
        TransferId::new([8; 16])
    }

    #[test]
    fn clipboard_offer_and_chunk_round_trip_with_redacted_debug() {
        let offer = ClipboardMessage::Offer {
            meta: meta(Capability::CLIPBOARD_WRITE),
            revision: ClipboardRevision::new(4),
            representations: vec![ClipboardRepresentation {
                kind: ClipboardRepresentationKind::Utf8Text,
                byte_len: 6,
                hash: hash(),
            }],
        };
        let encoded = encode_clipboard(&offer).unwrap();
        assert_eq!(decode_clipboard(&encoded).unwrap(), offer);

        let chunk = ClipboardMessage::Chunk {
            meta: meta(Capability::CLIPBOARD_WRITE),
            revision: ClipboardRevision::new(4),
            kind: ClipboardRepresentationKind::Utf8Text,
            hash: hash(),
            offset: 0,
            bytes: b"secret clipboard value".to_vec(),
        };
        let debug = format!("{chunk:?}");
        assert!(!debug.contains("secret clipboard value"));
        assert_eq!(
            decode_clipboard(&encode_clipboard(&chunk).unwrap()).unwrap(),
            chunk
        );
    }

    #[test]
    fn clipboard_limits_and_capability_are_enforced() {
        let duplicate = ClipboardMessage::Offer {
            meta: meta(Capability::CLIPBOARD_READ),
            revision: ClipboardRevision::new(1),
            representations: vec![
                ClipboardRepresentation {
                    kind: ClipboardRepresentationKind::Png,
                    byte_len: 1,
                    hash: hash(),
                },
                ClipboardRepresentation {
                    kind: ClipboardRepresentationKind::Png,
                    byte_len: 2,
                    hash: hash(),
                },
            ],
        };
        assert!(matches!(
            encode_clipboard(&duplicate),
            Err(EncodeError::InvalidMessage(_))
        ));

        let wrong_capability = ClipboardMessage::Clear {
            meta: meta(Capability::FILE_TRANSFER),
            revision: ClipboardRevision::new(2),
        };
        assert!(matches!(
            encode_clipboard(&wrong_capability),
            Err(EncodeError::InvalidMessage(_))
        ));
    }

    #[test]
    fn manifest_round_trip_rejects_unsafe_topology_and_redacts_paths() {
        let entry = ManifestEntry {
            path: RelativePath::parse("private/report.txt").unwrap(),
            kind: ManifestEntryKind::File,
            size: 5,
            hash: Some(hash()),
        };
        assert!(!format!("{entry:?}").contains("report.txt"));
        let message = FileManifestMessage::Manifest {
            meta: meta(Capability::FILE_TRANSFER),
            transfer: transfer(),
            entries: vec![entry],
        };
        assert_eq!(
            decode_file_manifest(&encode_file_manifest(&message).unwrap()).unwrap(),
            message
        );

        let conflict = FileManifestMessage::Manifest {
            meta: meta(Capability::FILE_TRANSFER),
            transfer: transfer(),
            entries: vec![
                ManifestEntry {
                    path: RelativePath::parse("folder").unwrap(),
                    kind: ManifestEntryKind::File,
                    size: 1,
                    hash: Some(hash()),
                },
                ManifestEntry {
                    path: RelativePath::parse("folder/child").unwrap(),
                    kind: ManifestEntryKind::File,
                    size: 1,
                    hash: Some(hash()),
                },
            ],
        };
        assert!(matches!(
            encode_file_manifest(&conflict),
            Err(EncodeError::InvalidMessage(_))
        ));
    }

    #[test]
    fn paths_reject_traversal_reserved_names_controls_and_case_collisions() {
        for path in [
            "../secret",
            "safe\\escape",
            "CON.txt",
            "a/./b",
            "bad\u{1}name",
        ] {
            assert!(RelativePath::parse(path).is_err(), "accepted {path:?}");
        }
        assert_eq!(
            RelativePath::parse("Cafe\u{301}.txt").unwrap().as_str(),
            "Caf\u{e9}.txt"
        );
        let collision = FileManifestMessage::Manifest {
            meta: meta(Capability::FILE_TRANSFER),
            transfer: transfer(),
            entries: vec![
                ManifestEntry {
                    path: RelativePath::parse("File.txt").unwrap(),
                    kind: ManifestEntryKind::File,
                    size: 0,
                    hash: Some(hash()),
                },
                ManifestEntry {
                    path: RelativePath::parse("file.TXT").unwrap(),
                    kind: ManifestEntryKind::Directory,
                    size: 0,
                    hash: None,
                },
            ],
        };
        assert!(matches!(
            encode_file_manifest(&collision),
            Err(EncodeError::InvalidMessage(_))
        ));
    }

    #[test]
    fn chunk_limit_channel_separation_and_unknown_critical_fail_closed() {
        let valid = FileDataMessage::Chunk {
            meta: meta(Capability::FILE_TRANSFER),
            transfer: transfer(),
            entry_index: 0,
            offset: 7,
            bytes: b"file bytes".to_vec(),
        };
        assert_eq!(
            decode_file_data(&encode_file_data(&valid).unwrap()).unwrap(),
            valid
        );

        let too_large = FileDataMessage::Chunk {
            meta: meta(Capability::FILE_TRANSFER),
            transfer: transfer(),
            entry_index: 0,
            offset: 0,
            bytes: vec![0; BULK_CHUNK_LIMIT + 1],
        };
        assert!(matches!(
            encode_file_data(&too_large),
            Err(EncodeError::InvalidMessage(_))
        ));

        let clear = ClipboardMessage::Clear {
            meta: meta(Capability::CLIPBOARD_WRITE),
            revision: ClipboardRevision::new(1),
        };
        assert_eq!(
            decode_file_manifest(&encode_clipboard(&clear).unwrap()),
            Err(DecodeError::WrongChannel)
        );

        let unknown = Envelope {
            version: ProtocolVersion::CURRENT,
            tag: 0x20fe,
            critical: true,
            payload: CborBytes(vec![0xf6]),
        };
        assert_eq!(
            decode_clipboard(&cbor_encode(&unknown).unwrap()),
            Err(DecodeError::UnknownCriticalMessage { tag: 0x20fe })
        );

        let oversized_manifest = vec![0; MANIFEST_MESSAGE_LIMIT + 1];
        assert_eq!(
            decode_file_manifest(&oversized_manifest),
            Err(DecodeError::MessageTooLarge {
                actual: MANIFEST_MESSAGE_LIMIT + 1,
                limit: MANIFEST_MESSAGE_LIMIT,
            })
        );
    }

    #[test]
    fn rejects_noncanonical_body_before_exposing_clipboard_bytes() {
        let body = ClipboardClearBody {
            meta: meta(Capability::CLIPBOARD_WRITE),
            revision: ClipboardRevision::new(1),
        };
        let mut payload = encode_body(&body).unwrap();
        assert_eq!(payload[1], 0x00);
        payload.splice(1..2, [0x18, 0x00]);
        let envelope = Envelope {
            version: ProtocolVersion::CURRENT,
            tag: TAG_CLIPBOARD_CLEAR,
            critical: true,
            payload: CborBytes(payload),
        };
        assert_eq!(
            decode_clipboard(&cbor_encode(&envelope).unwrap()),
            Err(DecodeError::NonCanonical)
        );
    }
}
