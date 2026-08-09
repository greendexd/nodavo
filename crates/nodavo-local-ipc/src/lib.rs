//! Bounded, local-only messages exchanged between a native UI and the Nodavo agent.
//!
//! This is not the peer-to-peer wire protocol. The native shells use this API to
//! request actions from the per-user agent without receiving private key material.

use std::io;

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum serialized size of a single local IPC message.
pub const MAX_IPC_MESSAGE_SIZE: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum UiCommand {
    GetStatus,
    BeginPairing {
        endpoint: String,
        #[serde(default)]
        capabilities: Vec<CapabilityName>,
    },
    ConfirmPairing {
        pairing_id: String,
        accepted: bool,
    },
    SetCapability {
        peer_id: String,
        capability: CapabilityName,
        enabled: bool,
    },
    RevokePeer {
        peer_id: String,
    },
    /// Requests a bounded focus lease on the connected peer.
    RequestRemoteFocus {
        ttl_ms: u32,
    },
    /// Returns focus to the local device without tearing down the peer link.
    ReleaseFocus,
    /// Reports a trusted local workstation-lock notification.
    LocalLocked,
    /// Reports a trusted local system-sleep notification.
    LocalSleeping,
    EmergencyStop,
    Shutdown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityName {
    Input,
    ClipboardRead,
    ClipboardWrite,
    Files,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum AgentEvent {
    Status(AgentStatus),
    PairingCode {
        pairing_id: String,
        peer_name: String,
        code: String,
    },
    PairingFinished {
        pairing_id: String,
        paired: bool,
    },
    CapabilityChanged {
        peer_id: String,
        capability: CapabilityName,
        enabled: bool,
    },
    Error {
        code: String,
        message: String,
    },
    ShutdownAccepted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentStatus {
    pub phase: AgentPhase,
    pub connected_peer: Option<String>,
    pub input_owner: InputOwner,
    /// Direction of the active input focus lease.
    ///
    /// This is distinct from `input_owner`: a local device controlling its
    /// peer still owns no input on behalf of the remote device.
    #[serde(default)]
    pub focus_state: FocusState,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FocusState {
    #[default]
    Local,
    ControllingPeer,
    ControlledByPeer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentPhase {
    Starting,
    Ready,
    Pairing,
    Connected,
    Stopping,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputOwner {
    Local,
    Remote,
}

#[derive(Debug, Error)]
pub enum IpcError {
    #[error("local IPC message is larger than {MAX_IPC_MESSAGE_SIZE} bytes")]
    MessageTooLarge,
    #[error("local IPC peer closed the connection")]
    Closed,
    #[error("invalid local IPC message: {0}")]
    InvalidMessage(#[from] serde_json::Error),
    #[error("local IPC I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("refusing unsafe local IPC path: {0}")]
    UnsafePath(String),
}

/// Writes a length-prefixed JSON frame after enforcing the local IPC limit.
///
/// # Errors
///
/// Returns [`IpcError::MessageTooLarge`] when serialization exceeds the bound,
/// [`IpcError::InvalidMessage`] when serialization fails, or [`IpcError::Io`]
/// when the local stream cannot be written.
pub async fn write_frame<W, T>(writer: &mut W, message: &T) -> Result<(), IpcError>
where
    W: AsyncWrite + Unpin,
    T: Serialize + ?Sized,
{
    let encoded = serde_json::to_vec(message)?;
    if encoded.len() > MAX_IPC_MESSAGE_SIZE {
        return Err(IpcError::MessageTooLarge);
    }

    let length = u32::try_from(encoded.len()).map_err(|_| IpcError::MessageTooLarge)?;
    writer.write_u32(length).await?;
    writer.write_all(&encoded).await?;
    writer.flush().await?;
    Ok(())
}

/// Reads exactly one bounded length-prefixed JSON frame.
///
/// # Errors
///
/// Returns [`IpcError::Closed`] for an orderly peer close, rejects oversized or
/// malformed frames, and reports local stream failures as [`IpcError::Io`].
pub async fn read_frame<R, T>(reader: &mut R) -> Result<T, IpcError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let length = match reader.read_u32().await {
        Ok(length) => usize::try_from(length).map_err(|_| IpcError::MessageTooLarge)?,
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
            return Err(IpcError::Closed);
        }
        Err(error) => return Err(IpcError::Io(error)),
    };
    if length > MAX_IPC_MESSAGE_SIZE {
        return Err(IpcError::MessageTooLarge);
    }

    let mut encoded = vec![0_u8; length];
    reader.read_exact(&mut encoded).await?;
    Ok(serde_json::from_slice(&encoded)?)
}

#[cfg(unix)]
pub mod unix {
    use std::fs;
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    use std::path::Path;

    use tokio::net::UnixListener;

    use super::IpcError;

    /// Binds a user-owned Unix socket inside a private directory.
    ///
    /// Directory and socket permissions are the authentication boundary for the
    /// initial per-user agent. The socket never permits group or other access.
    ///
    /// # Errors
    ///
    /// Returns [`IpcError::UnsafePath`] for an unsafe existing path and
    /// [`IpcError::Io`] when directory, permission, or socket operations fail.
    pub fn bind_private(path: &Path) -> Result<UnixListener, IpcError> {
        let parent = path.parent().ok_or_else(|| {
            IpcError::UnsafePath("socket path has no parent directory".to_owned())
        })?;
        fs::create_dir_all(parent)?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;

        if let Ok(metadata) = fs::symlink_metadata(path) {
            if !metadata.file_type().is_socket() {
                return Err(IpcError::UnsafePath(
                    "existing IPC path is not a Unix socket".to_owned(),
                ));
            }
            fs::remove_file(path)?;
        }

        let listener = UnixListener::bind(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        Ok(listener)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CapabilityName, IpcError, MAX_IPC_MESSAGE_SIZE, UiCommand, read_frame, write_frame,
    };

    #[tokio::test]
    async fn rejects_oversized_frame_before_allocation() {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(
            &u32::try_from(MAX_IPC_MESSAGE_SIZE + 1)
                .unwrap()
                .to_be_bytes(),
        );
        let error = read_frame::<_, UiCommand>(&mut encoded.as_slice())
            .await
            .expect_err("oversized frame must fail");
        assert!(matches!(error, IpcError::MessageTooLarge));
    }

    #[tokio::test]
    async fn command_round_trip() {
        let expected = UiCommand::EmergencyStop;
        let mut encoded = Vec::new();
        write_frame(&mut encoded, &expected).await.unwrap();
        let actual = read_frame::<_, UiCommand>(&mut encoded.as_slice())
            .await
            .unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn pairing_capabilities_are_explicit_and_legacy_requests_grant_nothing() {
        let legacy: UiCommand =
            serde_json::from_str(r#"{"command":"begin_pairing","endpoint":"listen"}"#).unwrap();
        assert_eq!(
            legacy,
            UiCommand::BeginPairing {
                endpoint: "listen".to_owned(),
                capabilities: Vec::new(),
            }
        );

        let selected = UiCommand::BeginPairing {
            endpoint: "192.0.2.4:44310".to_owned(),
            capabilities: vec![CapabilityName::Input, CapabilityName::ClipboardWrite],
        };
        let encoded = serde_json::to_vec(&selected).unwrap();
        assert_eq!(
            serde_json::from_slice::<UiCommand>(&encoded).unwrap(),
            selected
        );
    }

    #[test]
    fn focus_and_safety_commands_have_stable_wire_names() {
        let request: UiCommand =
            serde_json::from_str(r#"{"command":"request_remote_focus","ttl_ms":5000}"#).unwrap();
        assert_eq!(request, UiCommand::RequestRemoteFocus { ttl_ms: 5_000 });
        assert_eq!(
            serde_json::from_str::<UiCommand>(r#"{"command":"release_focus"}"#).unwrap(),
            UiCommand::ReleaseFocus
        );
        assert_eq!(
            serde_json::from_str::<UiCommand>(r#"{"command":"local_locked"}"#).unwrap(),
            UiCommand::LocalLocked
        );
        assert_eq!(
            serde_json::from_str::<UiCommand>(r#"{"command":"local_sleeping"}"#).unwrap(),
            UiCommand::LocalSleeping
        );
    }

    #[test]
    fn legacy_status_defaults_to_local_focus() {
        let status: super::AgentStatus = serde_json::from_str(
            r#"{"phase":"connected","connected_peer":"peer","input_owner":"local"}"#,
        )
        .unwrap();
        assert_eq!(status.focus_state, super::FocusState::Local);

        let encoded = serde_json::to_value(status).unwrap();
        assert_eq!(encoded["focus_state"], "local");
    }
}
