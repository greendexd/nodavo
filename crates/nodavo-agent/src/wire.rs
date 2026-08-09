//! Versioned and bounded messages used only by the M1 pairing coordinator.

use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use nodavo_identity::{
    CapabilityGrants, DeviceSignature, PairingAcceptance, PairingNonce, PairingRole,
    PublicIdentity, TransportCertificate,
};
use nodavo_transport::{
    ChannelDirection, ChannelId, ChannelKind, CloseReason, PeerConnection, TransportCommand,
    TransportEvent,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

pub(crate) const PAIRING_PROTOCOL_VERSION: u16 = 1;
pub(crate) const EXPORTER_LABEL: &[u8] = b"EXPORTER-nodavo-pairing-v1";
pub(crate) const EXPORTER_CONTEXT: &[u8] = b"nodavo-agent-m1";
pub(crate) const EXPORTER_BYTES: usize = 32;

const BOOTSTRAP_MAGIC: &str = "nodavo-pairing-bootstrap";
const RECONNECT_MAGIC: &str = "nodavo-pinned-reconnect";
const MAX_BOOTSTRAP_FRAME_BYTES: usize = 96 * 1024;
const MAX_PAIRING_FRAME_BYTES: usize = 96 * 1024;
const MAX_CERTIFICATE_BYTES: usize = 64 * 1024;
const MAX_NAME_BYTES: usize = 63;
const MAX_SERVER_NAME_BYTES: usize = 253;
const IO_DEADLINE: Duration = Duration::from_secs(10);

#[derive(Debug, Error)]
pub(crate) enum WireError {
    #[error("pairing message is invalid")]
    InvalidMessage,
    #[error("pairing message exceeds its hard limit")]
    MessageTooLarge,
    #[error("pairing I/O timed out")]
    TimedOut,
    #[error("pairing connection closed")]
    Closed,
    #[error("pairing transport failed")]
    Transport,
    #[error("pairing I/O failed")]
    Io,
}

pub(crate) struct BootstrapIdentity {
    pub(crate) certificate_der: Vec<u8>,
    pub(crate) server_name: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BootstrapFrame {
    magic: String,
    version: u16,
    certificate_der: String,
    server_name: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReconnectFrame {
    magic: String,
    version: u16,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReconnectReadyFrame {
    magic: String,
    version: u16,
    ready: bool,
}

impl BootstrapFrame {
    fn new(certificate_der: &[u8], server_name: &str) -> Result<Self, WireError> {
        validate_certificate(certificate_der)?;
        validate_server_name(server_name)?;
        Ok(Self {
            magic: BOOTSTRAP_MAGIC.to_owned(),
            version: PAIRING_PROTOCOL_VERSION,
            certificate_der: STANDARD.encode(certificate_der),
            server_name: server_name.to_owned(),
        })
    }

    fn into_identity(self) -> Result<BootstrapIdentity, WireError> {
        if self.magic != BOOTSTRAP_MAGIC || self.version != PAIRING_PROTOCOL_VERSION {
            return Err(WireError::InvalidMessage);
        }
        validate_server_name(&self.server_name)?;
        let certificate_der = decode_bounded(&self.certificate_der, MAX_CERTIFICATE_BYTES)?;
        validate_certificate(&certificate_der)?;
        Ok(BootstrapIdentity {
            certificate_der,
            server_name: self.server_name,
        })
    }
}

pub(crate) async fn send_bootstrap<W>(
    writer: &mut W,
    certificate_der: &[u8],
    server_name: &str,
) -> Result<(), WireError>
where
    W: AsyncWrite + Unpin,
{
    let frame = BootstrapFrame::new(certificate_der, server_name)?;
    write_json_frame(writer, &frame).await
}

pub(crate) async fn receive_bootstrap<R>(reader: &mut R) -> Result<BootstrapIdentity, WireError>
where
    R: AsyncRead + Unpin,
{
    let frame: BootstrapFrame = read_json_frame(reader).await?;
    frame.into_identity()
}

pub(crate) async fn send_reconnect_request<W>(writer: &mut W) -> Result<(), WireError>
where
    W: AsyncWrite + Unpin,
{
    write_json_frame(
        writer,
        &ReconnectFrame {
            magic: RECONNECT_MAGIC.to_owned(),
            version: PAIRING_PROTOCOL_VERSION,
        },
    )
    .await
}

pub(crate) async fn receive_reconnect_request<R>(reader: &mut R) -> Result<(), WireError>
where
    R: AsyncRead + Unpin,
{
    let frame: ReconnectFrame = read_json_frame(reader).await?;
    if frame.magic != RECONNECT_MAGIC || frame.version != PAIRING_PROTOCOL_VERSION {
        return Err(WireError::InvalidMessage);
    }
    Ok(())
}

pub(crate) async fn send_reconnect_ready<W>(writer: &mut W) -> Result<(), WireError>
where
    W: AsyncWrite + Unpin,
{
    write_json_frame(
        writer,
        &ReconnectReadyFrame {
            magic: RECONNECT_MAGIC.to_owned(),
            version: PAIRING_PROTOCOL_VERSION,
            ready: true,
        },
    )
    .await
}

pub(crate) async fn receive_reconnect_ready<R>(reader: &mut R) -> Result<(), WireError>
where
    R: AsyncRead + Unpin,
{
    let frame: ReconnectReadyFrame = read_json_frame(reader).await?;
    if frame.magic != RECONNECT_MAGIC || frame.version != PAIRING_PROTOCOL_VERSION || !frame.ready {
        return Err(WireError::InvalidMessage);
    }
    Ok(())
}

async fn write_json_frame<W, T>(writer: &mut W, frame: &T) -> Result<(), WireError>
where
    W: AsyncWrite + Unpin,
    T: Serialize + ?Sized,
{
    let encoded = serde_json::to_vec(frame).map_err(|_| WireError::InvalidMessage)?;
    if encoded.len() > MAX_BOOTSTRAP_FRAME_BYTES {
        return Err(WireError::MessageTooLarge);
    }
    let length = u32::try_from(encoded.len()).map_err(|_| WireError::MessageTooLarge)?;
    timeout(IO_DEADLINE, async {
        writer.write_u32(length).await?;
        writer.write_all(&encoded).await?;
        writer.flush().await
    })
    .await
    .map_err(|_| WireError::TimedOut)?
    .map_err(|_| WireError::Io)
}

async fn read_json_frame<R, T>(reader: &mut R) -> Result<T, WireError>
where
    R: AsyncRead + Unpin,
    T: serde::de::DeserializeOwned,
{
    let length = timeout(IO_DEADLINE, reader.read_u32())
        .await
        .map_err(|_| WireError::TimedOut)?
        .map_err(|_| WireError::Io)?;
    let length = usize::try_from(length).map_err(|_| WireError::MessageTooLarge)?;
    if length > MAX_BOOTSTRAP_FRAME_BYTES {
        return Err(WireError::MessageTooLarge);
    }
    let mut encoded = vec![0_u8; length];
    timeout(IO_DEADLINE, reader.read_exact(&mut encoded))
        .await
        .map_err(|_| WireError::TimedOut)?
        .map_err(|_| WireError::Io)?;
    serde_json::from_slice(&encoded).map_err(|_| WireError::InvalidMessage)
}

#[derive(Clone)]
pub(crate) struct PeerHello {
    pub(crate) name: String,
    pub(crate) identity: PublicIdentity,
    pub(crate) certificate: TransportCertificate,
    pub(crate) grants: CapabilityGrants,
    pub(crate) nonce: PairingNonce,
    pub(crate) server_name: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "message", rename_all = "snake_case", deny_unknown_fields)]
enum PairingFrame {
    Hello {
        version: u16,
        name: String,
        public_key: String,
        certificate_der: String,
        grants: u8,
        nonce: String,
        server_name: String,
    },
    Confirmation {
        accepted: bool,
    },
    Acceptance {
        role: WireRole,
        signature: String,
    },
    ReadyToCommit,
    Committed,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum WireRole {
    Initiator,
    Responder,
}

impl From<PairingRole> for WireRole {
    fn from(value: PairingRole) -> Self {
        match value {
            PairingRole::Initiator => Self::Initiator,
            PairingRole::Responder => Self::Responder,
        }
    }
}

impl From<WireRole> for PairingRole {
    fn from(value: WireRole) -> Self {
        match value {
            WireRole::Initiator => Self::Initiator,
            WireRole::Responder => Self::Responder,
        }
    }
}

pub(crate) enum PairingMessage {
    Hello(PeerHello),
    Confirmation(bool),
    Acceptance(PairingAcceptance),
    ReadyToCommit,
    Committed,
}

impl PairingFrame {
    fn from_message(message: &PairingMessage) -> Self {
        match message {
            PairingMessage::Hello(hello) => Self::Hello {
                version: PAIRING_PROTOCOL_VERSION,
                name: hello.name.clone(),
                public_key: STANDARD.encode(hello.identity.public_key_bytes()),
                certificate_der: STANDARD.encode(hello.certificate.der()),
                grants: hello.grants.bits(),
                nonce: STANDARD.encode(hello.nonce.as_bytes()),
                server_name: hello.server_name.clone(),
            },
            PairingMessage::Confirmation(accepted) => Self::Confirmation {
                accepted: *accepted,
            },
            PairingMessage::Acceptance(acceptance) => Self::Acceptance {
                role: acceptance.role().into(),
                signature: STANDARD.encode(acceptance.signature().as_bytes()),
            },
            PairingMessage::ReadyToCommit => Self::ReadyToCommit,
            PairingMessage::Committed => Self::Committed,
        }
    }

    fn into_message(self) -> Result<PairingMessage, WireError> {
        match self {
            Self::Hello {
                version,
                name,
                public_key,
                certificate_der,
                grants,
                nonce,
                server_name,
            } => {
                if version != PAIRING_PROTOCOL_VERSION {
                    return Err(WireError::InvalidMessage);
                }
                validate_name(&name)?;
                validate_server_name(&server_name)?;
                let public_key = decode_array::<32>(&public_key)?;
                let certificate_der = decode_bounded(&certificate_der, MAX_CERTIFICATE_BYTES)?;
                let certificate = TransportCertificate::from_der(certificate_der)
                    .map_err(|_| WireError::InvalidMessage)?;
                let grants =
                    CapabilityGrants::from_bits(grants).map_err(|_| WireError::InvalidMessage)?;
                let nonce = PairingNonce::from_bytes(decode_array::<32>(&nonce)?);
                Ok(PairingMessage::Hello(PeerHello {
                    name,
                    identity: PublicIdentity::from_public_key(public_key),
                    certificate,
                    grants,
                    nonce,
                    server_name,
                }))
            }
            Self::Confirmation { accepted } => Ok(PairingMessage::Confirmation(accepted)),
            Self::Acceptance { role, signature } => {
                let signature = DeviceSignature::from_bytes(decode_array::<64>(&signature)?);
                Ok(PairingMessage::Acceptance(PairingAcceptance::from_parts(
                    role.into(),
                    signature,
                )))
            }
            Self::ReadyToCommit => Ok(PairingMessage::ReadyToCommit),
            Self::Committed => Ok(PairingMessage::Committed),
        }
    }
}

pub(crate) async fn open_control_channel(
    connection: &mut dyn PeerConnection,
) -> Result<ChannelId, WireError> {
    connection
        .execute(TransportCommand::OpenChannel {
            kind: ChannelKind::Control,
            direction: ChannelDirection::Bidirectional,
        })
        .await
        .map_err(|_| WireError::Transport)?;
    loop {
        match connection
            .next_event()
            .await
            .map_err(|_| WireError::Transport)?
        {
            TransportEvent::Connected { .. } => {}
            TransportEvent::ChannelOpened {
                channel,
                kind: ChannelKind::Control,
                direction: ChannelDirection::Bidirectional,
            } => return Ok(channel),
            TransportEvent::Closed(_) => return Err(WireError::Closed),
            _ => return Err(WireError::InvalidMessage),
        }
    }
}

pub(crate) async fn accept_control_channel(
    connection: &mut dyn PeerConnection,
) -> Result<ChannelId, WireError> {
    loop {
        match connection
            .next_event()
            .await
            .map_err(|_| WireError::Transport)?
        {
            TransportEvent::Connected { .. } => {}
            TransportEvent::ChannelOpened {
                channel,
                kind: ChannelKind::Control,
                direction: ChannelDirection::Bidirectional,
            } => return Ok(channel),
            TransportEvent::Closed(_) => return Err(WireError::Closed),
            _ => return Err(WireError::InvalidMessage),
        }
    }
}

pub(crate) async fn send_pairing_message(
    connection: &mut dyn PeerConnection,
    channel: ChannelId,
    message: &PairingMessage,
) -> Result<(), WireError> {
    let frame = PairingFrame::from_message(message);
    let encoded = serde_json::to_vec(&frame).map_err(|_| WireError::InvalidMessage)?;
    if encoded.len() > MAX_PAIRING_FRAME_BYTES {
        return Err(WireError::MessageTooLarge);
    }
    connection
        .execute(TransportCommand::SendReliable {
            channel,
            payload: Bytes::from(encoded),
            end_of_stream: false,
        })
        .await
        .map_err(|_| WireError::Transport)
}

pub(crate) async fn receive_pairing_message(
    connection: &mut dyn PeerConnection,
    channel: ChannelId,
) -> Result<PairingMessage, WireError> {
    loop {
        match connection
            .next_event()
            .await
            .map_err(|_| WireError::Transport)?
        {
            TransportEvent::ReliableData {
                channel: received_channel,
                payload,
                end_of_stream: false,
            } if received_channel == channel => {
                if payload.len() > MAX_PAIRING_FRAME_BYTES {
                    return Err(WireError::MessageTooLarge);
                }
                let frame: PairingFrame =
                    serde_json::from_slice(&payload).map_err(|_| WireError::InvalidMessage)?;
                return frame.into_message();
            }
            TransportEvent::Closed(_) => return Err(WireError::Closed),
            TransportEvent::ChannelClosed { channel: value } if value == channel => {
                return Err(WireError::Closed);
            }
            TransportEvent::Connected { .. } => {}
            _ => return Err(WireError::InvalidMessage),
        }
    }
}

pub(crate) async fn close_pairing_connection(connection: &mut dyn PeerConnection) {
    let _ = connection
        .execute(TransportCommand::Close(CloseReason::Requested))
        .await;
}

fn validate_certificate(certificate: &[u8]) -> Result<(), WireError> {
    if certificate.is_empty() || certificate.len() > MAX_CERTIFICATE_BYTES {
        Err(WireError::InvalidMessage)
    } else {
        Ok(())
    }
}

fn validate_name(name: &str) -> Result<(), WireError> {
    if name.is_empty()
        || name.len() > MAX_NAME_BYTES
        || name.trim() != name
        || name.chars().any(char::is_control)
    {
        Err(WireError::InvalidMessage)
    } else {
        Ok(())
    }
}

fn validate_server_name(name: &str) -> Result<(), WireError> {
    if name.is_empty() || name.len() > MAX_SERVER_NAME_BYTES || !name.is_ascii() {
        Err(WireError::InvalidMessage)
    } else {
        Ok(())
    }
}

fn decode_array<const N: usize>(encoded: &str) -> Result<[u8; N], WireError> {
    if encoded.len() > N.saturating_mul(2) {
        return Err(WireError::InvalidMessage);
    }
    STANDARD
        .decode(encoded)
        .map_err(|_| WireError::InvalidMessage)?
        .try_into()
        .map_err(|_| WireError::InvalidMessage)
}

fn decode_bounded(encoded: &str, maximum: usize) -> Result<Vec<u8>, WireError> {
    if encoded.len() > maximum.saturating_mul(2) {
        return Err(WireError::MessageTooLarge);
    }
    let decoded = STANDARD
        .decode(encoded)
        .map_err(|_| WireError::InvalidMessage)?;
    if decoded.is_empty() || decoded.len() > maximum {
        return Err(WireError::InvalidMessage);
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bootstrap_rejects_oversized_length_before_allocation() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(
            &u32::try_from(MAX_BOOTSTRAP_FRAME_BYTES + 1)
                .unwrap()
                .to_be_bytes(),
        );
        assert!(matches!(
            receive_bootstrap(&mut bytes.as_slice()).await,
            Err(WireError::MessageTooLarge)
        ));
    }

    #[tokio::test]
    async fn reconnect_preflight_round_trip_is_bounded_and_versioned() {
        let mut encoded = Vec::new();
        send_reconnect_request(&mut encoded).await.unwrap();
        receive_reconnect_request(&mut encoded.as_slice())
            .await
            .unwrap();
        let frame: serde_json::Value = serde_json::from_slice(&encoded[4..]).unwrap();
        assert_eq!(frame.as_object().unwrap().len(), 2);
    }

    #[test]
    fn hello_rejects_unknown_capability_bits() {
        let frame = PairingFrame::Hello {
            version: PAIRING_PROTOCOL_VERSION,
            name: "peer".to_owned(),
            public_key: STANDARD.encode([3_u8; 32]),
            certificate_der: STANDARD.encode([4_u8; 32]),
            grants: 0x80,
            nonce: STANDARD.encode([5_u8; 32]),
            server_name: "peer.nodavo.invalid".to_owned(),
        };
        assert!(matches!(
            frame.into_message(),
            Err(WireError::InvalidMessage)
        ));
    }
}
