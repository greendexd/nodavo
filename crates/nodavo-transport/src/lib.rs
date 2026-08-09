//! Runtime-neutral transport boundaries for Nodavo.
//!
//! This crate defines the contract implemented by a future QUIC/TLS backend.
//! It intentionally exposes no Quinn, rustls, or Tokio types. Initial pairing
//! connections remain untrusted until the identity crate completes explicit
//! SAS confirmation; established connections must use a pinned peer key.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU16;
use std::pin::Pin;

use bytes::Bytes;
use thiserror::Error;

pub mod quinn_backend;

/// Largest application frame accepted on a reliable channel.
///
/// Larger objects must be chunked and bounded by their owning protocol. This
/// limit is checked before a backend queues or allocates framing state.
pub const MAX_RELIABLE_FRAME_BYTES: usize = 1024 * 1024;
/// Largest application datagram Nodavo will emit or accept.
///
/// The conservative 1200-byte ceiling avoids depending on IP fragmentation.
pub const MAX_DATAGRAM_PAYLOAD_BYTES: usize = 1_200;
/// Hard per-connection ceiling for simultaneously open application channels.
pub const MAX_OPEN_CHANNELS: usize = 64;
/// Length of an Ed25519 public key carried at the transport boundary.
pub const PEER_PUBLIC_KEY_BYTES: usize = 32;
/// Smallest exporter accepted by the transport boundary.
pub const MIN_KEYING_MATERIAL_BYTES: usize = 32;
/// Largest exporter returned through the transport boundary.
pub const MAX_KEYING_MATERIAL_BYTES: usize = 256;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A validated unicast network location.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Endpoint(SocketAddr);

impl Endpoint {
    /// Creates a validated remote unicast endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::InvalidEndpoint`] for port zero or an
    /// unspecified, multicast, or broadcast address.
    pub fn new(address: SocketAddr) -> Result<Self, TransportError> {
        let ip = address.ip();
        let unusable = address.port() == 0
            || ip.is_unspecified()
            || ip.is_multicast()
            || matches!(ip, IpAddr::V4(ipv4) if ipv4.is_broadcast());
        if unusable {
            Err(TransportError::InvalidEndpoint)
        } else {
            Ok(Self(address))
        }
    }

    #[must_use]
    pub const fn address(self) -> SocketAddr {
        self.0
    }
}

/// Authentication policy for a new connection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthMode {
    /// An encrypted, ephemeral connection used only to run explicit pairing.
    ///
    /// This mode never creates trust on connect. The backend must make TLS
    /// exporter material available to the pairing layer through its private
    /// integration boundary.
    Pairing { protocol_version: u16 },
    /// Mutual authentication against an already pinned persistent identity.
    ///
    /// Local credential selection belongs to the backend configuration and OS
    /// key store, so no private-key material crosses this API.
    PinnedMutual {
        expected_peer_public_key: [u8; PEER_PUBLIC_KEY_BYTES],
    },
}

impl AuthMode {
    /// Creates an explicit pairing mode for a nonzero protocol version.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::InvalidProtocolVersion`] for version zero.
    pub fn pairing(protocol_version: u16) -> Result<Self, TransportError> {
        if protocol_version == 0 {
            Err(TransportError::InvalidProtocolVersion)
        } else {
            Ok(Self::Pairing { protocol_version })
        }
    }
}

/// An application channel with an independent reliability/backpressure domain.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ChannelKind {
    Control,
    ReliableInput,
    /// Reliable latest-wins pointer fallback when datagrams are unavailable.
    PointerFallback,
    Clipboard,
    FileManifest,
    FileData,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChannelDirection {
    Bidirectional,
    SendOnly,
    ReceiveOnly,
}

/// Backend-assigned identifier scoped to one peer connection.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ChannelId(u64);

impl ChannelId {
    #[must_use]
    pub const fn from_backend(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Negotiated datagram support after applying Nodavo's hard payload ceiling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatagramAvailability {
    Unavailable,
    Available(DatagramLimit),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DatagramLimit(NonZeroU16);

impl DatagramLimit {
    /// Intersects the backend's negotiated maximum with Nodavo's hard limit.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::InvalidLimit`] when the backend reports zero.
    pub fn negotiated(backend_max_payload: usize) -> Result<Self, TransportError> {
        let bounded = backend_max_payload.min(MAX_DATAGRAM_PAYLOAD_BYTES);
        let bounded = u16::try_from(bounded).map_err(|_| TransportError::InvalidLimit)?;
        NonZeroU16::new(bounded)
            .map(Self)
            .ok_or(TransportError::InvalidLimit)
    }

    #[must_use]
    pub const fn max_payload_bytes(self) -> usize {
        self.0.get() as usize
    }
}

/// Commands accepted by a peer connection.
///
/// Only replaceable pointer motion and high-frequency scrolling belong in
/// `SendDatagram`. When datagrams are unavailable, callers open a
/// `PointerFallback` reliable channel, retain sequence numbers in their
/// protocol payload, and discard stale motion after decode. Keys, buttons,
/// control, clipboard, and file data never fall back to unreliable delivery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransportCommand {
    OpenChannel {
        kind: ChannelKind,
        direction: ChannelDirection,
    },
    SendReliable {
        channel: ChannelId,
        payload: Bytes,
        end_of_stream: bool,
    },
    SendDatagram {
        payload: Bytes,
    },
    Close(CloseReason),
}

impl TransportCommand {
    /// Applies context-free hard limits before a command reaches a backend.
    ///
    /// Backends must additionally enforce negotiated datagram limits, channel
    /// counts, flow control, deadlines, and channel ownership.
    ///
    /// # Errors
    ///
    /// Returns the corresponding size or empty-datagram error when a payload
    /// violates a context-free hard limit.
    pub fn validate(&self) -> Result<(), TransportError> {
        match self {
            Self::SendReliable { payload, .. } if payload.len() > MAX_RELIABLE_FRAME_BYTES => {
                Err(TransportError::ReliableFrameTooLarge)
            }
            Self::SendDatagram { payload } if payload.len() > MAX_DATAGRAM_PAYLOAD_BYTES => {
                Err(TransportError::DatagramTooLarge)
            }
            Self::SendDatagram { payload } if payload.is_empty() => {
                Err(TransportError::EmptyDatagram)
            }
            _ => Ok(()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransportEvent {
    Connected {
        remote: Endpoint,
        datagrams: DatagramAvailability,
    },
    ChannelOpened {
        channel: ChannelId,
        kind: ChannelKind,
        direction: ChannelDirection,
    },
    ReliableData {
        channel: ChannelId,
        payload: Bytes,
        end_of_stream: bool,
    },
    Datagram {
        payload: Bytes,
    },
    ChannelClosed {
        channel: ChannelId,
    },
    Closed(CloseReason),
}

impl TransportEvent {
    /// Validates payload sizes before dispatch to a protocol decoder.
    ///
    /// # Errors
    ///
    /// Returns the corresponding size, empty-datagram, or negotiation error
    /// when an inbound payload violates the effective limits.
    pub fn validate(&self, datagrams: DatagramAvailability) -> Result<(), TransportError> {
        match self {
            Self::ReliableData { payload, .. } if payload.len() > MAX_RELIABLE_FRAME_BYTES => {
                Err(TransportError::ReliableFrameTooLarge)
            }
            Self::Datagram { .. } if datagrams == DatagramAvailability::Unavailable => {
                Err(TransportError::DatagramsNotNegotiated)
            }
            Self::Datagram { payload } => {
                let DatagramAvailability::Available(limit) = datagrams else {
                    return Err(TransportError::DatagramsNotNegotiated);
                };
                if payload.is_empty() {
                    Err(TransportError::EmptyDatagram)
                } else if payload.len() > limit.max_payload_bytes() {
                    Err(TransportError::DatagramTooLarge)
                } else {
                    Ok(())
                }
            }
            _ => Ok(()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CloseReason {
    Requested,
    EmergencyDisconnect,
    AuthenticationFailed,
    ProtocolViolation,
    VersionMismatch,
    LimitExceeded,
    IdleTimeout,
    LocalShutdown,
    TransportFailure,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[non_exhaustive]
pub enum TransportError {
    #[error("the endpoint is not a usable unicast address")]
    InvalidEndpoint,
    #[error("the protocol version must be non-zero")]
    InvalidProtocolVersion,
    #[error("the negotiated transport limit is invalid")]
    InvalidLimit,
    #[error("the reliable frame exceeds the hard size limit")]
    ReliableFrameTooLarge,
    #[error("the datagram exceeds the negotiated or hard size limit")]
    DatagramTooLarge,
    #[error("empty datagrams are not valid Nodavo messages")]
    EmptyDatagram,
    #[error("datagrams were not negotiated for this connection")]
    DatagramsNotNegotiated,
    #[error("the per-connection channel limit was reached")]
    ChannelLimitReached,
    #[error("the channel is unknown, closed, or has the wrong direction")]
    InvalidChannel,
    #[error("peer authentication failed")]
    AuthenticationFailed,
    #[error("the transport operation timed out")]
    TimedOut,
    #[error("the requested TLS exporter length is outside the accepted bounds")]
    InvalidKeyingMaterialLength,
    #[error("the transport configuration is invalid")]
    InvalidConfiguration,
    #[error("the connection is closed")]
    Closed,
    #[error("the backend rejected the transport operation")]
    Backend,
}

/// QUIC-independent connection contract.
pub trait PeerConnection: Send {
    fn remote_endpoint(&self) -> Endpoint;

    fn datagram_availability(&self) -> DatagramAvailability;

    /// Derives connection-specific TLS exporter bytes for channel binding.
    ///
    /// The label and context are supplied by the pairing protocol. No backend
    /// TLS or QUIC types cross this boundary.
    ///
    /// # Errors
    ///
    /// Returns an error when the requested length is outside the hard bounds,
    /// the label is invalid, or the backend cannot export keying material.
    fn export_keying_material(
        &self,
        label: &[u8],
        context: &[u8],
        output_len: usize,
    ) -> Result<Bytes, TransportError>;

    /// Executes a validated command with backend flow control and deadlines.
    fn execute(&mut self, command: TransportCommand) -> BoxFuture<'_, Result<(), TransportError>>;

    /// Returns the next bounded event. Implementations must unblock this call
    /// when a local close or emergency disconnect is requested.
    fn next_event(&mut self) -> BoxFuture<'_, Result<TransportEvent, TransportError>>;
}

/// Connection factory/listener contract implemented by a concrete backend.
pub trait Transport: Send + Sync {
    fn connect(
        &self,
        endpoint: Endpoint,
        auth: AuthMode,
    ) -> BoxFuture<'_, Result<Box<dyn PeerConnection>, TransportError>>;

    fn accept(&self) -> BoxFuture<'_, Result<Box<dyn PeerConnection>, TransportError>>;
}
