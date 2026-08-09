use core::convert::Infallible;

use minicbor::{Decode, Decoder, Encode};
use thiserror::Error;

use crate::{CONTROL_MESSAGE_LIMIT, EventMeta};
use crate::{
    Capability, ControlMessage, DATAGRAM_MESSAGE_LIMIT, InputMessage,
    POINTER_FALLBACK_MESSAGE_LIMIT, ProtocolVersion, RELIABLE_INPUT_MESSAGE_LIMIT, WireMessage,
};

const TAG_HELLO: u16 = 0;
const TAG_CAPABILITY_GRANT: u16 = 1;
const TAG_CAPABILITY_REVOKE: u16 = 2;
const TAG_SESSION_OPEN: u16 = 3;
const TAG_SESSION_CLOSE: u16 = 4;
const TAG_FOCUS_LEASE_REQUEST: u16 = 5;
const TAG_FOCUS_LEASE_GRANT: u16 = 6;
const TAG_FOCUS_LEASE_RELEASE: u16 = 7;
const TAG_PING: u16 = 8;
const TAG_PONG: u16 = 9;
const TAG_EMERGENCY_DISCONNECT: u16 = 10;
const TAG_ERROR: u16 = 11;

const TAG_KEY: u16 = 0x1000;
const TAG_POINTER_BUTTON: u16 = 0x1001;
const TAG_POINTER_MOTION: u16 = 0x1002;
const TAG_SCROLL: u16 = 0x1003;
const TAG_RELEASE_ALL: u16 = 0x1004;

const MAX_NEGOTIATED_VERSIONS: usize = 16;
const MAX_LEASE_TTL_MS: u32 = 30_000;
const KNOWN_MODIFIER_BITS: u16 = (1 << 11) - 1;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EncodeError {
    #[error("message belongs on a different protocol channel")]
    WrongChannel,
    #[error("invalid message: {0}")]
    InvalidMessage(&'static str),
    #[error("encoded message is {actual} bytes; limit is {limit} bytes")]
    MessageTooLarge { actual: usize, limit: usize },
    #[error("CBOR encoding failed: {0}")]
    Cbor(String),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DecodeError {
    #[error("encoded message is {actual} bytes; limit is {limit} bytes")]
    MessageTooLarge { actual: usize, limit: usize },
    #[error("CBOR decoding failed: {0}")]
    Cbor(String),
    #[error("message is not in canonical CBOR form")]
    NonCanonical,
    #[error("protocol version 0 is invalid")]
    InvalidVersion,
    #[error("unsupported protocol version {major}.{minor}")]
    UnsupportedVersion { major: u16, minor: u16 },
    #[error("unknown critical message tag {tag}")]
    UnknownCriticalMessage { tag: u16 },
    #[error("message belongs on a different protocol channel")]
    WrongChannel,
    #[error("invalid message: {0}")]
    InvalidMessage(&'static str),
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

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
struct HelloBody {
    #[n(0)]
    versions: Vec<ProtocolVersion>,
    #[n(1)]
    capabilities: Capability,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
struct CapabilityBody {
    #[n(0)]
    peer: crate::DeviceId,
    #[n(1)]
    capabilities: Capability,
    #[n(2)]
    epoch: crate::GrantEpoch,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
struct SessionOpenBody {
    #[n(0)]
    session_id: crate::SessionId,
    #[n(1)]
    peer: crate::DeviceId,
    #[n(2)]
    epoch: crate::GrantEpoch,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
struct SessionCloseBody {
    #[n(0)]
    session_id: crate::SessionId,
    #[n(1)]
    reason: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
struct FocusLeaseBody {
    #[n(0)]
    meta: EventMeta,
    #[n(1)]
    lease_id: u64,
    #[n(2)]
    ttl_ms: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
struct FocusLeaseReleaseBody {
    #[n(0)]
    meta: EventMeta,
    #[n(1)]
    lease_id: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
struct NonceBody {
    #[n(0)]
    nonce: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
struct DisconnectBody {
    #[n(0)]
    session_id: crate::SessionId,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
struct ErrorBody {
    #[n(0)]
    code: crate::ProtocolErrorCode,
    #[n(1)]
    related_tag: Option<u16>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Channel {
    Control,
    ReliableInput,
    Datagram,
    PointerFallback,
}

/// Encodes a control-stream message using canonical CBOR.
///
/// # Errors
///
/// Returns an error if the message is invalid, belongs on another channel, or
/// exceeds [`CONTROL_MESSAGE_LIMIT`].
pub fn encode_control(message: &WireMessage) -> Result<Vec<u8>, EncodeError> {
    encode_for(message, Channel::Control, CONTROL_MESSAGE_LIMIT)
}

/// Encodes an ordered input-stream message using canonical CBOR.
///
/// # Errors
///
/// Returns an error if the event is invalid, replaceable rather than reliable,
/// or exceeds [`RELIABLE_INPUT_MESSAGE_LIMIT`].
pub fn encode_reliable_input(message: &WireMessage) -> Result<Vec<u8>, EncodeError> {
    encode_for(
        message,
        Channel::ReliableInput,
        RELIABLE_INPUT_MESSAGE_LIMIT,
    )
}

/// Encodes a replaceable input event as a bounded datagram payload.
///
/// # Errors
///
/// Returns an error if the event is invalid, requires reliable delivery, or
/// exceeds [`DATAGRAM_MESSAGE_LIMIT`].
pub fn encode_datagram(message: &WireMessage) -> Result<Vec<u8>, EncodeError> {
    encode_for(message, Channel::Datagram, DATAGRAM_MESSAGE_LIMIT)
}

/// Encodes replaceable pointer input on the reliable fallback channel.
///
/// # Errors
///
/// Returns an error if the event is invalid, is not replaceable pointer input,
/// or exceeds [`POINTER_FALLBACK_MESSAGE_LIMIT`].
pub fn encode_pointer_fallback(message: &WireMessage) -> Result<Vec<u8>, EncodeError> {
    encode_for(
        message,
        Channel::PointerFallback,
        POINTER_FALLBACK_MESSAGE_LIMIT,
    )
}

/// Decodes and validates one control-stream message.
///
/// # Errors
///
/// Returns an error before the message is usable if it is oversized,
/// non-canonical, malformed, unsupported, critical and unknown, or on the wrong
/// channel.
pub fn decode_control(bytes: &[u8]) -> Result<WireMessage, DecodeError> {
    decode_for(bytes, Channel::Control, CONTROL_MESSAGE_LIMIT)
}

/// Decodes and validates one ordered input-stream message.
///
/// # Errors
///
/// Returns an error before the event is usable if it is oversized,
/// non-canonical, malformed, unsupported, or on the wrong channel.
pub fn decode_reliable_input(bytes: &[u8]) -> Result<WireMessage, DecodeError> {
    decode_for(bytes, Channel::ReliableInput, RELIABLE_INPUT_MESSAGE_LIMIT)
}

/// Decodes and validates one replaceable input datagram.
///
/// # Errors
///
/// Returns an error before the event is usable if it is oversized,
/// non-canonical, malformed, unsupported, or on the wrong channel.
pub fn decode_datagram(bytes: &[u8]) -> Result<WireMessage, DecodeError> {
    decode_for(bytes, Channel::Datagram, DATAGRAM_MESSAGE_LIMIT)
}

/// Decodes and validates one replaceable pointer event from its reliable
/// fallback channel.
///
/// # Errors
///
/// Returns an error before the event is usable if it is oversized,
/// non-canonical, malformed, unsupported, or on the wrong channel.
pub fn decode_pointer_fallback(bytes: &[u8]) -> Result<WireMessage, DecodeError> {
    decode_for(
        bytes,
        Channel::PointerFallback,
        POINTER_FALLBACK_MESSAGE_LIMIT,
    )
}

fn encode_for(
    message: &WireMessage,
    channel: Channel,
    limit: usize,
) -> Result<Vec<u8>, EncodeError> {
    validate_wire(message, channel).map_err(EncodeError::InvalidMessage)?;
    let (tag, critical, payload) = encode_payload(message)?;
    let envelope = Envelope {
        version: ProtocolVersion::CURRENT,
        tag,
        critical,
        payload: CborBytes(payload),
    };
    let bytes = cbor_encode(&envelope)?;
    if bytes.len() > limit {
        return Err(EncodeError::MessageTooLarge {
            actual: bytes.len(),
            limit,
        });
    }
    Ok(bytes)
}

fn decode_for(bytes: &[u8], channel: Channel, limit: usize) -> Result<WireMessage, DecodeError> {
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

    if crate::bulk_codec::is_reserved_bulk_tag(envelope.tag) {
        return Err(DecodeError::WrongChannel);
    }

    let Some(expected_critical) = expected_critical(envelope.tag) else {
        if envelope.critical {
            return Err(DecodeError::UnknownCriticalMessage { tag: envelope.tag });
        }
        return Ok(WireMessage::Unknown {
            tag: envelope.tag,
            payload: envelope.payload.0,
        });
    };
    if envelope.critical != expected_critical {
        return Err(DecodeError::InvalidMessage(
            "message criticality does not match its tag",
        ));
    }

    let message = decode_payload(envelope.tag, &envelope.payload.0)?;
    validate_wire(&message, channel).map_err(DecodeError::InvalidMessage)?;
    Ok(message)
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

fn encode_payload(message: &WireMessage) -> Result<(u16, bool, Vec<u8>), EncodeError> {
    match message {
        WireMessage::Control(control) => encode_control_payload(control),
        WireMessage::Input(input) => encode_input_payload(input),
        WireMessage::Unknown { tag, payload } => Ok((*tag, false, payload.clone())),
    }
}

fn encode_control_payload(message: &ControlMessage) -> Result<(u16, bool, Vec<u8>), EncodeError> {
    let encoded = match message {
        ControlMessage::Hello {
            versions,
            capabilities,
        } => (
            TAG_HELLO,
            true,
            encode_body(&HelloBody {
                versions: versions.clone(),
                capabilities: *capabilities,
            })?,
        ),
        ControlMessage::CapabilityGrant {
            peer,
            capabilities,
            epoch,
        } => encode_capability_payload(TAG_CAPABILITY_GRANT, *peer, *capabilities, *epoch)?,
        ControlMessage::CapabilityRevoke {
            peer,
            capabilities,
            epoch,
        } => encode_capability_payload(TAG_CAPABILITY_REVOKE, *peer, *capabilities, *epoch)?,
        ControlMessage::SessionOpen {
            session_id,
            peer,
            epoch,
        } => (
            TAG_SESSION_OPEN,
            true,
            encode_body(&SessionOpenBody {
                session_id: *session_id,
                peer: *peer,
                epoch: *epoch,
            })?,
        ),
        ControlMessage::SessionClose { session_id, reason } => (
            TAG_SESSION_CLOSE,
            true,
            encode_body(&SessionCloseBody {
                session_id: *session_id,
                reason: *reason,
            })?,
        ),
        ControlMessage::FocusLeaseRequest {
            meta,
            lease_id,
            ttl_ms,
        } => encode_focus_lease_payload(TAG_FOCUS_LEASE_REQUEST, *meta, *lease_id, *ttl_ms)?,
        ControlMessage::FocusLeaseGrant {
            meta,
            lease_id,
            ttl_ms,
        } => encode_focus_lease_payload(TAG_FOCUS_LEASE_GRANT, *meta, *lease_id, *ttl_ms)?,
        ControlMessage::FocusLeaseRelease { meta, lease_id } => (
            TAG_FOCUS_LEASE_RELEASE,
            true,
            encode_body(&FocusLeaseReleaseBody {
                meta: *meta,
                lease_id: *lease_id,
            })?,
        ),
        ControlMessage::Ping { nonce } => {
            (TAG_PING, false, encode_body(&NonceBody { nonce: *nonce })?)
        }
        ControlMessage::Pong { nonce } => {
            (TAG_PONG, false, encode_body(&NonceBody { nonce: *nonce })?)
        }
        ControlMessage::EmergencyDisconnect { session_id } => (
            TAG_EMERGENCY_DISCONNECT,
            true,
            encode_body(&DisconnectBody {
                session_id: *session_id,
            })?,
        ),
        ControlMessage::Error { code, related_tag } => (
            TAG_ERROR,
            false,
            encode_body(&ErrorBody {
                code: *code,
                related_tag: *related_tag,
            })?,
        ),
    };
    Ok(encoded)
}

fn encode_capability_payload(
    tag: u16,
    peer: crate::DeviceId,
    capabilities: Capability,
    epoch: crate::GrantEpoch,
) -> Result<(u16, bool, Vec<u8>), EncodeError> {
    Ok((
        tag,
        true,
        encode_body(&CapabilityBody {
            peer,
            capabilities,
            epoch,
        })?,
    ))
}

fn encode_focus_lease_payload(
    tag: u16,
    meta: EventMeta,
    lease_id: u64,
    ttl_ms: u32,
) -> Result<(u16, bool, Vec<u8>), EncodeError> {
    Ok((
        tag,
        true,
        encode_body(&FocusLeaseBody {
            meta,
            lease_id,
            ttl_ms,
        })?,
    ))
}

fn encode_input_payload(message: &InputMessage) -> Result<(u16, bool, Vec<u8>), EncodeError> {
    let encoded = match message {
        InputMessage::Key(event) => (TAG_KEY, true, encode_body(event)?),
        InputMessage::PointerButton(event) => (TAG_POINTER_BUTTON, true, encode_body(event)?),
        InputMessage::PointerMotion(event) => (TAG_POINTER_MOTION, false, encode_body(event)?),
        InputMessage::Scroll(event) => (TAG_SCROLL, false, encode_body(event)?),
        InputMessage::ReleaseAll(meta) => (TAG_RELEASE_ALL, true, encode_body(meta)?),
    };
    Ok(encoded)
}

fn decode_payload(tag: u16, payload: &[u8]) -> Result<WireMessage, DecodeError> {
    let message = match tag {
        TAG_HELLO => {
            let body: HelloBody = decode_body(payload)?;
            WireMessage::Control(ControlMessage::Hello {
                versions: body.versions,
                capabilities: body.capabilities,
            })
        }
        TAG_CAPABILITY_GRANT | TAG_CAPABILITY_REVOKE => {
            let body: CapabilityBody = decode_body(payload)?;
            let message = if tag == TAG_CAPABILITY_GRANT {
                ControlMessage::CapabilityGrant {
                    peer: body.peer,
                    capabilities: body.capabilities,
                    epoch: body.epoch,
                }
            } else {
                ControlMessage::CapabilityRevoke {
                    peer: body.peer,
                    capabilities: body.capabilities,
                    epoch: body.epoch,
                }
            };
            WireMessage::Control(message)
        }
        TAG_SESSION_OPEN => {
            let body: SessionOpenBody = decode_body(payload)?;
            WireMessage::Control(ControlMessage::SessionOpen {
                session_id: body.session_id,
                peer: body.peer,
                epoch: body.epoch,
            })
        }
        TAG_SESSION_CLOSE => {
            let body: SessionCloseBody = decode_body(payload)?;
            WireMessage::Control(ControlMessage::SessionClose {
                session_id: body.session_id,
                reason: body.reason,
            })
        }
        TAG_FOCUS_LEASE_REQUEST | TAG_FOCUS_LEASE_GRANT => {
            let body: FocusLeaseBody = decode_body(payload)?;
            let message = if tag == TAG_FOCUS_LEASE_REQUEST {
                ControlMessage::FocusLeaseRequest {
                    meta: body.meta,
                    lease_id: body.lease_id,
                    ttl_ms: body.ttl_ms,
                }
            } else {
                ControlMessage::FocusLeaseGrant {
                    meta: body.meta,
                    lease_id: body.lease_id,
                    ttl_ms: body.ttl_ms,
                }
            };
            WireMessage::Control(message)
        }
        TAG_FOCUS_LEASE_RELEASE => {
            let body: FocusLeaseReleaseBody = decode_body(payload)?;
            WireMessage::Control(ControlMessage::FocusLeaseRelease {
                meta: body.meta,
                lease_id: body.lease_id,
            })
        }
        TAG_PING | TAG_PONG => {
            let body: NonceBody = decode_body(payload)?;
            let message = if tag == TAG_PING {
                ControlMessage::Ping { nonce: body.nonce }
            } else {
                ControlMessage::Pong { nonce: body.nonce }
            };
            WireMessage::Control(message)
        }
        TAG_EMERGENCY_DISCONNECT => {
            let body: DisconnectBody = decode_body(payload)?;
            WireMessage::Control(ControlMessage::EmergencyDisconnect {
                session_id: body.session_id,
            })
        }
        TAG_ERROR => {
            let body: ErrorBody = decode_body(payload)?;
            WireMessage::Control(ControlMessage::Error {
                code: body.code,
                related_tag: body.related_tag,
            })
        }
        TAG_KEY => WireMessage::Input(InputMessage::Key(decode_body(payload)?)),
        TAG_POINTER_BUTTON => {
            WireMessage::Input(InputMessage::PointerButton(decode_body(payload)?))
        }
        TAG_POINTER_MOTION => {
            WireMessage::Input(InputMessage::PointerMotion(decode_body(payload)?))
        }
        TAG_SCROLL => WireMessage::Input(InputMessage::Scroll(decode_body(payload)?)),
        TAG_RELEASE_ALL => WireMessage::Input(InputMessage::ReleaseAll(decode_body(payload)?)),
        _ => unreachable!("known tags are exhaustively matched"),
    };
    Ok(message)
}

fn expected_critical(tag: u16) -> Option<bool> {
    match tag {
        TAG_HELLO
        | TAG_CAPABILITY_GRANT
        | TAG_CAPABILITY_REVOKE
        | TAG_SESSION_OPEN
        | TAG_SESSION_CLOSE
        | TAG_FOCUS_LEASE_REQUEST
        | TAG_FOCUS_LEASE_GRANT
        | TAG_FOCUS_LEASE_RELEASE
        | TAG_EMERGENCY_DISCONNECT
        | TAG_KEY
        | TAG_POINTER_BUTTON
        | TAG_RELEASE_ALL => Some(true),
        TAG_PING | TAG_PONG | TAG_ERROR | TAG_POINTER_MOTION | TAG_SCROLL => Some(false),
        _ => None,
    }
}

fn validate_meta(meta: &EventMeta) -> Result<(), &'static str> {
    if meta.session_id().is_zero() {
        return Err("event session ID must be nonzero");
    }
    if meta.origin().is_zero() {
        return Err("event origin must be nonzero");
    }
    if meta.sequence().is_zero() {
        return Err("event sequence must be nonzero");
    }
    if meta.grant_epoch().is_zero() {
        return Err("event grant epoch must be nonzero");
    }
    if meta.capability() != Capability::REMOTE_INPUT {
        return Err("input events require exactly the remote-input capability");
    }
    Ok(())
}

fn validate_wire(message: &WireMessage, channel: Channel) -> Result<(), &'static str> {
    match message {
        WireMessage::Control(control) => validate_control_message(control, channel)?,
        WireMessage::Input(input) => validate_input_message(input, channel)?,
        WireMessage::Unknown { tag, .. } => {
            if expected_critical(*tag).is_some() || crate::bulk_codec::is_reserved_bulk_tag(*tag) {
                return Err("unknown message uses a reserved known tag");
            }
        }
    }
    Ok(())
}

fn validate_control_message(
    control: &ControlMessage,
    channel: Channel,
) -> Result<(), &'static str> {
    if channel != Channel::Control {
        return Err("control message on input channel");
    }
    match control {
        ControlMessage::Hello { versions, .. } => {
            if versions.is_empty() || versions.len() > MAX_NEGOTIATED_VERSIONS {
                return Err("version list must contain between 1 and 16 entries");
            }
            if versions.iter().any(|version| !version.is_well_formed()) {
                return Err("version list contains an invalid version");
            }
        }
        ControlMessage::CapabilityGrant {
            peer,
            capabilities,
            epoch,
        }
        | ControlMessage::CapabilityRevoke {
            peer,
            capabilities,
            epoch,
        } => validate_capability_update(*peer, *capabilities, *epoch)?,
        ControlMessage::SessionOpen {
            session_id,
            peer,
            epoch,
        } => {
            if session_id.is_zero() {
                return Err("session ID must be nonzero");
            }
            if peer.is_zero() {
                return Err("session peer must be nonzero");
            }
            if epoch.is_zero() {
                return Err("session grant epoch must be nonzero");
            }
        }
        ControlMessage::SessionClose { session_id, .. }
        | ControlMessage::EmergencyDisconnect { session_id } => {
            if session_id.is_zero() {
                return Err("session ID must be nonzero");
            }
        }
        ControlMessage::FocusLeaseRequest {
            meta,
            lease_id,
            ttl_ms,
        }
        | ControlMessage::FocusLeaseGrant {
            meta,
            lease_id,
            ttl_ms,
        } => validate_focus_lease(meta, *lease_id, Some(*ttl_ms))?,
        ControlMessage::FocusLeaseRelease { meta, lease_id } => {
            validate_focus_lease(meta, *lease_id, None)?;
        }
        _ => {}
    }
    Ok(())
}

fn validate_capability_update(
    peer: crate::DeviceId,
    capabilities: Capability,
    epoch: crate::GrantEpoch,
) -> Result<(), &'static str> {
    if capabilities.is_empty() {
        return Err("capability update must not be empty");
    }
    if peer.is_zero() {
        return Err("capability peer must be nonzero");
    }
    if epoch.is_zero() {
        return Err("capability epoch must be nonzero");
    }
    Ok(())
}

fn validate_focus_lease(
    meta: &EventMeta,
    lease_id: u64,
    ttl_ms: Option<u32>,
) -> Result<(), &'static str> {
    validate_meta(meta)?;
    if lease_id == 0 {
        return Err("focus lease ID must be nonzero");
    }
    if ttl_ms.is_some_and(|ttl_ms| ttl_ms == 0 || ttl_ms > MAX_LEASE_TTL_MS) {
        return Err("focus lease TTL must be between 1 and 30000 ms");
    }
    Ok(())
}

fn validate_input_message(input: &InputMessage, channel: Channel) -> Result<(), &'static str> {
    if input.lease_id() == 0 {
        return Err("input lease ID must be nonzero");
    }
    match input {
        InputMessage::Key(event) => {
            if channel != Channel::ReliableInput {
                return Err("key event must use the reliable input stream");
            }
            if event.usage_page == 0 || event.usage_id == 0 {
                return Err("HID usage page and usage ID must be nonzero");
            }
            if event.modifiers & !KNOWN_MODIFIER_BITS != 0 {
                return Err("key event contains unknown modifier bits");
            }
        }
        InputMessage::PointerButton(event) => {
            if channel != Channel::ReliableInput {
                return Err("pointer button event must use the reliable input stream");
            }
            if event.button == 0 || event.button > 32 {
                return Err("pointer button must be between 1 and 32");
            }
        }
        InputMessage::ReleaseAll(_) => {
            if channel != Channel::ReliableInput {
                return Err("release-all must use the reliable input stream");
            }
        }
        InputMessage::PointerMotion(event) => {
            validate_replaceable_channel(channel)?;
            if event.display_id == 0 {
                return Err("pointer display ID must be nonzero");
            }
        }
        InputMessage::Scroll(event) => {
            validate_replaceable_channel(channel)?;
            if event.delta_x == 0 && event.delta_y == 0 {
                return Err("scroll event must contain a nonzero delta");
            }
        }
    }
    validate_meta(input.meta())
}

fn validate_replaceable_channel(channel: Channel) -> Result<(), &'static str> {
    if channel == Channel::Datagram || channel == Channel::PointerFallback {
        Ok(())
    } else {
        Err("replaceable pointer event must use a datagram or pointer fallback")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DeviceId, GrantEpoch, Sequence, SessionId};

    fn meta() -> EventMeta {
        EventMeta::new(
            SessionId::new([3; 16]),
            DeviceId::new([7; 32]),
            Sequence::new(42),
            GrantEpoch::new(2),
            Capability::REMOTE_INPUT,
        )
    }

    #[test]
    fn canonical_control_round_trip_is_stable() {
        let message = WireMessage::Control(ControlMessage::Hello {
            versions: vec![ProtocolVersion::CURRENT],
            capabilities: Capability::REMOTE_INPUT
                | Capability::CLIPBOARD_READ
                | Capability::CLIPBOARD_WRITE,
        });
        let first = encode_control(&message).unwrap();
        let decoded = decode_control(&first).unwrap();
        let second = encode_control(&decoded).unwrap();
        assert_eq!(message, decoded);
        assert_eq!(first, second);
    }

    #[test]
    fn rejects_non_canonical_outer_integer_encoding() {
        let message = WireMessage::Control(ControlMessage::Ping { nonce: 9 });
        let canonical = encode_control(&message).unwrap();
        assert_eq!(canonical[0], 0xa4); // Four-entry envelope map.
        assert_eq!(canonical[1], 0x00); // Canonical field key zero.

        let mut non_canonical = canonical;
        non_canonical.splice(1..2, [0x18, 0x00]);
        assert_eq!(
            decode_control(&non_canonical),
            Err(DecodeError::NonCanonical)
        );
    }

    #[test]
    fn enforces_limit_before_decoding() {
        let oversized = vec![0; RELIABLE_INPUT_MESSAGE_LIMIT + 1];
        assert_eq!(
            decode_reliable_input(&oversized),
            Err(DecodeError::MessageTooLarge {
                actual: RELIABLE_INPUT_MESSAGE_LIMIT + 1,
                limit: RELIABLE_INPUT_MESSAGE_LIMIT,
            })
        );
    }

    #[test]
    fn rejects_invalid_and_unsupported_envelope_versions() {
        let payload = encode_body(&NonceBody { nonce: 1 }).unwrap();
        let invalid = Envelope {
            version: ProtocolVersion::new(0, 1),
            tag: TAG_PING,
            critical: false,
            payload: CborBytes(payload.clone()),
        };
        assert_eq!(
            decode_control(&cbor_encode(&invalid).unwrap()),
            Err(DecodeError::InvalidVersion)
        );

        let future = Envelope {
            version: ProtocolVersion::new(2, 0),
            tag: TAG_PING,
            critical: false,
            payload: CborBytes(payload),
        };
        assert_eq!(
            decode_control(&cbor_encode(&future).unwrap()),
            Err(DecodeError::UnsupportedVersion { major: 2, minor: 0 })
        );
    }

    #[test]
    fn rejects_unknown_critical_but_preserves_unknown_noncritical() {
        let critical = Envelope {
            version: ProtocolVersion::CURRENT,
            tag: 900,
            critical: true,
            payload: CborBytes(vec![0xf6]),
        };
        assert_eq!(
            decode_control(&cbor_encode(&critical).unwrap()),
            Err(DecodeError::UnknownCriticalMessage { tag: 900 })
        );

        let noncritical = Envelope {
            critical: false,
            ..critical
        };
        assert_eq!(
            decode_control(&cbor_encode(&noncritical).unwrap()).unwrap(),
            WireMessage::Unknown {
                tag: 900,
                payload: vec![0xf6],
            }
        );
    }

    #[test]
    fn input_channel_and_capability_context_are_enforced() {
        let key = WireMessage::Input(InputMessage::Key(crate::KeyEvent {
            meta: meta(),
            usage_page: 7,
            usage_id: 4,
            state: crate::KeyState::Down,
            modifiers: 0,
            lease_id: 19,
        }));
        let encoded = encode_reliable_input(&key).unwrap();
        assert_eq!(decode_reliable_input(&encoded).unwrap(), key);
        assert_eq!(
            encode_datagram(&key),
            Err(EncodeError::InvalidMessage(
                "key event must use the reliable input stream"
            ))
        );

        let bad = WireMessage::Input(InputMessage::ReleaseAll(crate::ReleaseAllEvent {
            meta: EventMeta::new(
                SessionId::new([3; 16]),
                DeviceId::new([7; 32]),
                Sequence::new(43),
                GrantEpoch::new(2),
                Capability::CLIPBOARD_READ,
            ),
            lease_id: 19,
        }));
        assert_eq!(
            encode_reliable_input(&bad),
            Err(EncodeError::InvalidMessage(
                "input events require exactly the remote-input capability"
            ))
        );
    }

    #[test]
    fn input_debug_output_is_redacted() {
        let event = crate::KeyEvent {
            meta: meta(),
            usage_page: 0x1234,
            usage_id: 0x5678,
            state: crate::KeyState::Down,
            modifiers: 0xabcd,
            lease_id: 19,
        };
        let debug = format!("{event:?}");
        assert_eq!(debug, "KeyEvent([redacted])");
        assert!(!debug.contains("4660"));
        assert!(!debug.contains("22136"));
    }

    #[test]
    fn focus_lease_round_trip_carries_replay_context_and_lease_identity() {
        let message = WireMessage::Control(ControlMessage::FocusLeaseGrant {
            meta: meta(),
            lease_id: 17,
            ttl_ms: 5_000,
        });
        let encoded = encode_control(&message).unwrap();
        assert_eq!(decode_control(&encoded).unwrap(), message);

        let invalid = WireMessage::Control(ControlMessage::FocusLeaseRelease {
            meta: meta(),
            lease_id: 0,
        });
        assert_eq!(
            encode_control(&invalid),
            Err(EncodeError::InvalidMessage(
                "focus lease ID must be nonzero"
            ))
        );
    }

    #[test]
    fn pointer_button_range_is_bounded() {
        let event = WireMessage::Input(InputMessage::PointerButton(crate::PointerButtonEvent {
            meta: meta(),
            button: 33,
            state: crate::ButtonState::Down,
            lease_id: 19,
        }));
        assert_eq!(
            encode_reliable_input(&event),
            Err(EncodeError::InvalidMessage(
                "pointer button must be between 1 and 32"
            ))
        );
    }

    #[test]
    fn every_input_requires_nonzero_lease_and_preserves_meta() {
        let expected_meta = meta();
        let message = WireMessage::Input(InputMessage::ReleaseAll(crate::ReleaseAllEvent {
            meta: expected_meta,
            lease_id: 73,
        }));
        let encoded = encode_reliable_input(&message).unwrap();
        let decoded = decode_reliable_input(&encoded).unwrap();
        assert_eq!(decoded, message);
        let WireMessage::Input(decoded) = decoded else {
            panic!("decoded input expected");
        };
        assert_eq!(*decoded.meta(), expected_meta);
        assert_eq!(decoded.lease_id(), 73);

        let invalid = WireMessage::Input(InputMessage::ReleaseAll(crate::ReleaseAllEvent {
            meta: expected_meta,
            lease_id: 0,
        }));
        assert_eq!(
            encode_reliable_input(&invalid),
            Err(EncodeError::InvalidMessage(
                "input lease ID must be nonzero"
            ))
        );
    }

    #[test]
    fn pointer_fallback_round_trips_only_replaceable_input() {
        let motion = WireMessage::Input(InputMessage::PointerMotion(crate::PointerMotionEvent {
            meta: meta(),
            display_id: 1,
            x: 12,
            y: 34,
            lease_id: 8,
        }));
        let encoded = encode_pointer_fallback(&motion).unwrap();
        assert_eq!(decode_pointer_fallback(&encoded).unwrap(), motion);
        assert_eq!(
            decode_reliable_input(&encoded),
            Err(DecodeError::InvalidMessage(
                "replaceable pointer event must use a datagram or pointer fallback"
            ))
        );

        let key = WireMessage::Input(InputMessage::Key(crate::KeyEvent {
            meta: meta(),
            usage_page: 7,
            usage_id: 4,
            state: crate::KeyState::Down,
            modifiers: 0,
            lease_id: 8,
        }));
        assert_eq!(
            encode_pointer_fallback(&key),
            Err(EncodeError::InvalidMessage(
                "key event must use the reliable input stream"
            ))
        );
    }

    #[test]
    fn scroll_units_round_trip_and_unknown_modifiers_fail_closed() {
        for unit in [crate::ScrollUnit::Lines, crate::ScrollUnit::Precise] {
            let scroll = WireMessage::Input(InputMessage::Scroll(crate::ScrollEvent {
                meta: meta(),
                delta_x: 0,
                delta_y: -3,
                unit,
                lease_id: 6,
            }));
            let encoded = encode_datagram(&scroll).unwrap();
            assert_eq!(decode_datagram(&encoded).unwrap(), scroll);
        }

        let key = WireMessage::Input(InputMessage::Key(crate::KeyEvent {
            meta: meta(),
            usage_page: 7,
            usage_id: 4,
            state: crate::KeyState::Down,
            modifiers: 1 << 15,
            lease_id: 6,
        }));
        assert_eq!(
            encode_reliable_input(&key),
            Err(EncodeError::InvalidMessage(
                "key event contains unknown modifier bits"
            ))
        );
    }

    #[test]
    fn malformed_zero_context_and_payload_fields_fail_closed() {
        let zero_sequence = EventMeta::new(
            SessionId::new([3; 16]),
            DeviceId::new([7; 32]),
            Sequence::new(0),
            GrantEpoch::new(2),
            Capability::REMOTE_INPUT,
        );
        let release = WireMessage::Input(InputMessage::ReleaseAll(crate::ReleaseAllEvent {
            meta: zero_sequence,
            lease_id: 1,
        }));
        assert_eq!(
            encode_reliable_input(&release),
            Err(EncodeError::InvalidMessage(
                "event sequence must be nonzero"
            ))
        );

        let no_op_scroll = WireMessage::Input(InputMessage::Scroll(crate::ScrollEvent {
            meta: meta(),
            delta_x: 0,
            delta_y: 0,
            unit: crate::ScrollUnit::Lines,
            lease_id: 1,
        }));
        assert_eq!(
            encode_datagram(&no_op_scroll),
            Err(EncodeError::InvalidMessage(
                "scroll event must contain a nonzero delta"
            ))
        );
    }
}
