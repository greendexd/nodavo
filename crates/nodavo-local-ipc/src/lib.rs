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
/// Maximum number of trusted-device summaries returned by one local IPC call.
pub const MAX_TRUSTED_PEERS: usize = 32;
/// Maximum explicit filesystem selections accepted by one send request.
pub const MAX_SELECTED_PATHS: usize = 32;
/// Maximum UTF-8 bytes accepted for one local selected path.
pub const MAX_SELECTED_PATH_BYTES: usize = 4 * 1024;
/// Maximum public semantic-version text returned by updater IPC.
pub const MAX_UPDATE_VERSION_BYTES: usize = 128;
/// Maximum aggregate payload represented by one public file-transfer record.
pub const MAX_TRANSFER_BYTES: u64 = 10 * 1024 * 1024 * 1024;
/// Maximum live records retained by the process-lifetime transfer registry.
pub const MAX_NONTERMINAL_TRANSFERS: usize = 128;
/// Maximum terminal records retained in completion-order FIFO order.
pub const MAX_TERMINAL_TRANSFERS: usize = 32;
/// Absolute maximum rows returned by one transfer listing.
pub const MAX_TRANSFER_SNAPSHOTS: usize = MAX_NONTERMINAL_TRANSFERS + MAX_TERMINAL_TRANSFERS;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum UiCommand {
    GetStatus {},
    /// Prompts for macOS Accessibility access in the agent process and then
    /// returns a freshly checked status. Other platforms reject this command.
    RequestAccessibilityPermission {},
    ListTrustedPeers {},
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
    /// Sends only paths explicitly selected by the local user interface.
    SendFiles {
        paths: Vec<String>,
    },
    ListTransfers {},
    CancelTransfer {
        transfer_id: String,
    },
    /// Requests a bounded focus lease on the connected peer.
    RequestRemoteFocus {
        ttl_ms: u32,
    },
    /// Returns focus to the local device without tearing down the peer link.
    ReleaseFocus {},
    /// Reports a trusted local workstation-lock notification.
    LocalLocked {},
    /// Reports a trusted local system-sleep notification.
    LocalSleeping {},
    /// Returns the current public updater state without starting network work.
    GetUpdateStatus {},
    /// Starts an explicitly requested update check.
    CheckForUpdate {},
    /// Records a decision for exactly the currently offered update identifier.
    DecideUpdate {
        #[serde(deserialize_with = "deserialize_offer_id")]
        offer_id: String,
        accepted: bool,
    },
    EmergencyStop {},
    Shutdown {},
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityName {
    Input,
    ClipboardRead,
    ClipboardWrite,
    Files,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustedPeerState {
    Active,
    Revoked,
}

/// Public local summary of one trust record.
///
/// Certificate material, network locations, grant epochs, and private storage
/// metadata are deliberately absent from this UI boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedPeerSummary {
    pub peer_id: String,
    pub display_name: String,
    pub state: TrustedPeerState,
    pub local_grants: Vec<CapabilityName>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum AgentEvent {
    Status(AgentStatus),
    TrustedPeers {
        peers: Vec<TrustedPeerSummary>,
    },
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
    TransferQueued {
        transfer_id: String,
    },
    Transfers {
        instance_id: String,
        revision: u64,
        truncated: bool,
        transfers: Vec<TransferSnapshot>,
    },
    UpdateStatus(UpdateSnapshot),
    Error {
        code: String,
        message: String,
    },
    ShutdownAccepted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferDirection {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferPhase {
    Preparing,
    Queued,
    Transferring,
    Paused,
    Finalizing,
    CancelRequested,
    Completed,
    Cancelled,
    Failed,
}

impl TransferPhase {
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Cancelled | Self::Failed)
    }
}

/// Stable, bounded failure categories safe to expose across local IPC.
///
/// Raw platform, transport, and source errors deliberately remain inside the
/// agent process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferFailureCode {
    AdmissionFailed,
    SourceUnavailable,
    AuthorizationRevoked,
    TransportFailed,
    CleanupFailed,
    Internal,
}

/// Content-free local status for one transfer.
///
/// The identifier is process-local and is never a peer protocol identifier.
/// Paths, names, hashes, peer identities, endpoints, epochs, timestamps, and
/// raw error strings cannot be represented by this type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TransferSnapshot {
    transfer_id: String,
    direction: TransferDirection,
    phase: TransferPhase,
    processed_bytes: Option<u64>,
    total_bytes: Option<u64>,
    cancellable: bool,
    failure: Option<TransferFailureCode>,
}

impl TransferSnapshot {
    /// Constructs a snapshot only when its phase and counters agree.
    ///
    /// # Errors
    ///
    /// Rejects noncanonical or nil identifiers, inconsistent counters, totals
    /// over 10 GiB, terminal records marked cancellable, and failure fields on
    /// any phase other than `failed`.
    pub fn new(
        transfer_id: String,
        direction: TransferDirection,
        phase: TransferPhase,
        processed_bytes: Option<u64>,
        total_bytes: Option<u64>,
        cancellable: bool,
        failure: Option<TransferFailureCode>,
    ) -> Result<Self, TransferSnapshotError> {
        let snapshot = Self {
            transfer_id,
            direction,
            phase,
            processed_bytes,
            total_bytes,
            cancellable,
            failure,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    #[must_use]
    pub fn transfer_id(&self) -> &str {
        &self.transfer_id
    }

    #[must_use]
    pub const fn direction(&self) -> TransferDirection {
        self.direction
    }

    #[must_use]
    pub const fn phase(&self) -> TransferPhase {
        self.phase
    }

    #[must_use]
    pub const fn processed_bytes(&self) -> Option<u64> {
        self.processed_bytes
    }

    #[must_use]
    pub const fn total_bytes(&self) -> Option<u64> {
        self.total_bytes
    }

    #[must_use]
    pub const fn cancellable(&self) -> bool {
        self.cancellable
    }

    #[must_use]
    pub const fn failure(&self) -> Option<TransferFailureCode> {
        self.failure
    }

    fn validate(&self) -> Result<(), TransferSnapshotError> {
        let id = uuid::Uuid::parse_str(&self.transfer_id)
            .map_err(|_| TransferSnapshotError::InvalidPublicField)?;
        if id.is_nil() || id.hyphenated().to_string() != self.transfer_id {
            return Err(TransferSnapshotError::InvalidPublicField);
        }
        let counters_valid = match (self.processed_bytes, self.total_bytes) {
            (Some(processed), Some(total)) => processed <= total && total <= MAX_TRANSFER_BYTES,
            (None, None) => matches!(
                self.phase,
                TransferPhase::Preparing
                    | TransferPhase::CancelRequested
                    | TransferPhase::Cancelled
                    | TransferPhase::Failed
            ),
            (Some(_), None) | (None, Some(_)) => false,
        };
        if !counters_valid
            || (self.phase == TransferPhase::Completed && self.processed_bytes != self.total_bytes)
            || (self.phase.is_terminal() && self.cancellable)
            || (self.phase == TransferPhase::CancelRequested && self.cancellable)
            || (self.phase == TransferPhase::Failed) != self.failure.is_some()
        {
            return Err(TransferSnapshotError::InvalidPhaseFields);
        }
        Ok(())
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum TransferSnapshotError {
    #[error("a public transfer field is invalid")]
    InvalidPublicField,
    #[error("transfer fields do not match the phase")]
    InvalidPhaseFields,
}

impl<'de> Deserialize<'de> for TransferSnapshot {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct RawTransferSnapshot {
            transfer_id: String,
            direction: TransferDirection,
            phase: TransferPhase,
            processed_bytes: Option<u64>,
            total_bytes: Option<u64>,
            cancellable: bool,
            failure: Option<TransferFailureCode>,
        }

        let raw = RawTransferSnapshot::deserialize(deserializer)?;
        Self::new(
            raw.transfer_id,
            raw.direction,
            raw.phase,
            raw.processed_bytes,
            raw.total_bytes,
            raw.cancellable,
            raw.failure,
        )
        .map_err(serde::de::Error::custom)
    }
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
    /// Public, content-free readiness of the local platform and peer session.
    ///
    /// Legacy agents omitted this field. Such payloads deserialize to a
    /// deliberately unavailable local snapshot and never infer readiness.
    #[serde(default)]
    pub readiness: ReadinessSnapshot,
}

/// Public readiness exposed to the native UI.
///
/// This contains no paths, process or display identifiers, permission prompt
/// state, or other stable machine metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadinessSnapshot {
    pub accessibility: AccessibilityReadiness,
    pub input: InputReadiness,
    pub local_topology: LocalTopologyReadiness,
    pub session_topology: SessionTopologyReadiness,
}

impl Default for ReadinessSnapshot {
    fn default() -> Self {
        Self {
            accessibility: AccessibilityReadiness::Unavailable,
            input: InputReadiness::Unavailable,
            local_topology: LocalTopologyReadiness::Unavailable,
            session_topology: SessionTopologyReadiness::NotConnected,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessibilityReadiness {
    Granted,
    ActionRequired,
    NotApplicable,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputReadiness {
    /// Platform prerequisites and the injection API are available. A live
    /// capture runtime is verified only inside an authenticated peer session.
    Ready,
    BlockedByPermission,
    BlockedByDesktop,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalTopologyReadiness {
    Available,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionTopologyReadiness {
    NotConnected,
    Synchronizing,
    Ready,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdatePhase {
    Idle,
    Checking,
    UpToDate,
    OfferAvailable,
    ConsentRecorded,
    Downloading,
    DownloadPaused,
    VerifiedStaged,
    Declined,
    Unavailable,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateFailureCode {
    NotConfigured,
    Busy,
    ManifestRejected,
    Network,
    Staging,
    Verification,
    Internal,
}

/// Bounded updater state exposed to the local UI.
///
/// URLs, local paths, artifact digests, signing keys, and remote filenames are
/// deliberately absent. Construction validates phase-specific field
/// invariants so byte counters and exact-consent identifiers cannot disagree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UpdateSnapshot {
    phase: UpdatePhase,
    offer_id: Option<String>,
    version: Option<String>,
    received_bytes: Option<u64>,
    total_bytes: Option<u64>,
    failure: Option<UpdateFailureCode>,
}

impl UpdateSnapshot {
    /// Creates a public updater snapshot after validating its bounded shape.
    ///
    /// # Errors
    ///
    /// Rejects noncanonical offer identifiers, unbounded version text,
    /// inconsistent byte counters, and fields that are invalid for the phase.
    pub fn new(
        phase: UpdatePhase,
        offer_id: Option<String>,
        version: Option<String>,
        received_bytes: Option<u64>,
        total_bytes: Option<u64>,
        failure: Option<UpdateFailureCode>,
    ) -> Result<Self, UpdateSnapshotError> {
        let snapshot = Self {
            phase,
            offer_id,
            version,
            received_bytes,
            total_bytes,
            failure,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    #[must_use]
    pub const fn phase(&self) -> UpdatePhase {
        self.phase
    }

    #[must_use]
    pub fn offer_id(&self) -> Option<&str> {
        self.offer_id.as_deref()
    }

    #[must_use]
    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }

    #[must_use]
    pub const fn received_bytes(&self) -> Option<u64> {
        self.received_bytes
    }

    #[must_use]
    pub const fn total_bytes(&self) -> Option<u64> {
        self.total_bytes
    }

    #[must_use]
    pub const fn failure(&self) -> Option<UpdateFailureCode> {
        self.failure
    }

    fn validate(&self) -> Result<(), UpdateSnapshotError> {
        if self
            .offer_id
            .as_deref()
            .is_some_and(|value| !is_canonical_offer_id(value))
            || self.version.as_deref().is_some_and(|value| {
                value.is_empty()
                    || value.len() > MAX_UPDATE_VERSION_BYTES
                    || match semver::Version::parse(value) {
                        Ok(parsed) => parsed.to_string() != value,
                        Err(_) => true,
                    }
            })
        {
            return Err(UpdateSnapshotError::InvalidPublicField);
        }

        let empty = self.offer_id.is_none()
            && self.version.is_none()
            && self.received_bytes.is_none()
            && self.total_bytes.is_none();
        let offered = self.offer_id.is_some()
            && self.version.is_some()
            && self.received_bytes.is_none()
            && self.total_bytes.is_some_and(|total| total > 0);
        let progress = self.offer_id.is_some()
            && self.version.is_some()
            && self
                .received_bytes
                .zip(self.total_bytes)
                .is_some_and(|(received, total)| total > 0 && received <= total);
        let complete = progress && self.received_bytes == self.total_bytes;

        let valid = match self.phase {
            UpdatePhase::Idle
            | UpdatePhase::Checking
            | UpdatePhase::UpToDate
            | UpdatePhase::Declined => empty && self.failure.is_none(),
            UpdatePhase::OfferAvailable | UpdatePhase::ConsentRecorded => {
                offered && self.failure.is_none()
            }
            UpdatePhase::Downloading | UpdatePhase::DownloadPaused => {
                progress && self.failure.is_none()
            }
            UpdatePhase::VerifiedStaged => complete && self.failure.is_none(),
            UpdatePhase::Unavailable | UpdatePhase::Failed => empty && self.failure.is_some(),
        };
        if valid {
            Ok(())
        } else {
            Err(UpdateSnapshotError::InvalidPhaseFields)
        }
    }
}

impl<'de> Deserialize<'de> for UpdateSnapshot {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireSnapshot {
            phase: UpdatePhase,
            offer_id: Option<String>,
            version: Option<String>,
            received_bytes: Option<u64>,
            total_bytes: Option<u64>,
            failure: Option<UpdateFailureCode>,
        }

        let wire = WireSnapshot::deserialize(deserializer)?;
        Self::new(
            wire.phase,
            wire.offer_id,
            wire.version,
            wire.received_bytes,
            wire.total_bytes,
            wire.failure,
        )
        .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum UpdateSnapshotError {
    #[error("the public updater snapshot contains an invalid bounded field")]
    InvalidPublicField,
    #[error("the public updater snapshot fields are inconsistent with its phase")]
    InvalidPhaseFields,
}

fn is_canonical_offer_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
            }
        })
}

fn deserialize_offer_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if is_canonical_offer_id(&value) {
        Ok(value)
    } else {
        Err(serde::de::Error::custom(
            "update offer identifier must be a canonical lowercase UUID",
        ))
    }
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
        AccessibilityReadiness, AgentEvent, CapabilityName, InputReadiness, IpcError,
        LocalTopologyReadiness, MAX_IPC_MESSAGE_SIZE, MAX_TERMINAL_TRANSFERS, MAX_TRANSFER_BYTES,
        MAX_TRANSFER_SNAPSHOTS, MAX_TRUSTED_PEERS, MAX_UPDATE_VERSION_BYTES, ReadinessSnapshot,
        SessionTopologyReadiness, TransferDirection, TransferFailureCode, TransferPhase,
        TransferSnapshot, TransferSnapshotError, TrustedPeerState, TrustedPeerSummary, UiCommand,
        UpdateFailureCode, UpdatePhase, UpdateSnapshot, UpdateSnapshotError, read_frame,
        write_frame,
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
        let expected = UiCommand::EmergencyStop {};
        let mut encoded = Vec::new();
        write_frame(&mut encoded, &expected).await.unwrap();
        let actual = read_frame::<_, UiCommand>(&mut encoded.as_slice())
            .await
            .unwrap();
        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn command_decoder_rejects_unknown_fields_directly_and_in_a_frame() {
        let unexpected = br#"{"command":"get_status","queued_before_exec":true}"#;
        assert!(serde_json::from_slice::<UiCommand>(unexpected).is_err());

        let mut framed = u32::try_from(unexpected.len())
            .unwrap()
            .to_be_bytes()
            .to_vec();
        framed.extend_from_slice(unexpected);
        assert!(matches!(
            read_frame::<_, UiCommand>(&mut framed.as_slice()).await,
            Err(IpcError::InvalidMessage(_))
        ));

        assert!(
            serde_json::from_str::<UiCommand>(
                r#"{"command":"begin_pairing","endpoint":"listen","unexpected":1}"#
            )
            .is_err()
        );
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
            UiCommand::ReleaseFocus {}
        );
        assert_eq!(
            serde_json::from_str::<UiCommand>(r#"{"command":"local_locked"}"#).unwrap(),
            UiCommand::LocalLocked {}
        );
        assert_eq!(
            serde_json::from_str::<UiCommand>(r#"{"command":"local_sleeping"}"#).unwrap(),
            UiCommand::LocalSleeping {}
        );
    }

    #[test]
    fn accessibility_command_and_readiness_have_exact_stable_wire_names() {
        assert_eq!(
            serde_json::from_str::<UiCommand>(r#"{"command":"request_accessibility_permission"}"#)
                .unwrap(),
            UiCommand::RequestAccessibilityPermission {}
        );
        assert!(
            serde_json::from_str::<UiCommand>(
                r#"{"command":"request_accessibility_permission","prompt":true}"#
            )
            .is_err()
        );

        let snapshot = ReadinessSnapshot {
            accessibility: AccessibilityReadiness::ActionRequired,
            input: InputReadiness::BlockedByPermission,
            local_topology: LocalTopologyReadiness::Available,
            session_topology: SessionTopologyReadiness::Synchronizing,
        };
        let encoded = serde_json::to_value(snapshot).unwrap();
        assert_eq!(encoded["accessibility"], "action_required");
        assert_eq!(encoded["input"], "blocked_by_permission");
        assert_eq!(encoded["local_topology"], "available");
        assert_eq!(encoded["session_topology"], "synchronizing");
        assert_eq!(
            serde_json::from_value::<ReadinessSnapshot>(encoded).unwrap(),
            snapshot
        );
    }

    #[test]
    fn readiness_snapshot_is_bounded_public_data_and_rejects_unknown_fields() {
        let snapshot = ReadinessSnapshot {
            accessibility: AccessibilityReadiness::Granted,
            input: InputReadiness::Ready,
            local_topology: LocalTopologyReadiness::Available,
            session_topology: SessionTopologyReadiness::Ready,
        };
        let encoded = serde_json::to_value(snapshot).unwrap();
        assert!(serde_json::to_vec(&encoded).unwrap().len() < MAX_IPC_MESSAGE_SIZE);
        for private_field in [
            "path",
            "pid",
            "process_id",
            "display_id",
            "desktop_name",
            "pairing_code",
        ] {
            assert!(encoded.get(private_field).is_none());
        }
        assert!(
            serde_json::from_str::<ReadinessSnapshot>(
                r#"{"accessibility":"granted","input":"ready","local_topology":"available","session_topology":"ready","pid":7}"#
            )
            .is_err()
        );
        assert!(serde_json::from_str::<AccessibilityReadiness>(r#""unknown""#).is_err());
        assert!(serde_json::from_str::<InputReadiness>(r#""unknown""#).is_err());
    }

    #[test]
    fn trusted_peer_response_is_bounded_and_contains_only_public_local_fields() {
        let peers = (0..MAX_TRUSTED_PEERS)
            .map(|index| TrustedPeerSummary {
                peer_id: format!("{index:064x}"),
                display_name: "x".repeat(63),
                state: if index % 2 == 0 {
                    TrustedPeerState::Active
                } else {
                    TrustedPeerState::Revoked
                },
                local_grants: vec![
                    CapabilityName::Input,
                    CapabilityName::ClipboardRead,
                    CapabilityName::ClipboardWrite,
                    CapabilityName::Files,
                ],
            })
            .collect();
        let encoded = serde_json::to_value(AgentEvent::TrustedPeers { peers }).unwrap();
        assert!(serde_json::to_vec(&encoded).unwrap().len() < MAX_IPC_MESSAGE_SIZE);
        let first = &encoded["peers"][0];
        assert_eq!(first["state"], "active");
        assert!(first.get("certificate_der").is_none());
        assert!(first.get("last_endpoint").is_none());
        assert!(first.get("grant_epoch").is_none());
    }

    #[test]
    fn trusted_peer_listing_has_a_stable_command_name() {
        assert_eq!(
            serde_json::from_str::<UiCommand>(r#"{"command":"list_trusted_peers"}"#).unwrap(),
            UiCommand::ListTrustedPeers {}
        );
    }

    #[test]
    fn selected_file_request_has_a_stable_bounded_shape() {
        let request = UiCommand::SendFiles {
            paths: vec!["/Users/example/Documents/report.pdf".to_owned()],
        };
        let encoded = serde_json::to_vec(&request).unwrap();
        assert!(encoded.len() < MAX_IPC_MESSAGE_SIZE);
        assert_eq!(
            serde_json::from_slice::<UiCommand>(&encoded).unwrap(),
            request
        );
    }

    #[test]
    fn transfer_commands_and_event_have_exact_snake_case_wire_names() {
        assert_eq!(
            serde_json::from_str::<UiCommand>(r#"{"command":"list_transfers"}"#).unwrap(),
            UiCommand::ListTransfers {}
        );
        assert_eq!(
            serde_json::from_str::<UiCommand>(
                r#"{"command":"cancel_transfer","transfer_id":"01234567-89ab-cdef-0123-456789abcdef"}"#,
            )
            .unwrap(),
            UiCommand::CancelTransfer {
                transfer_id: "01234567-89ab-cdef-0123-456789abcdef".to_owned(),
            }
        );
        let snapshot = TransferSnapshot::new(
            "01234567-89ab-cdef-0123-456789abcdef".to_owned(),
            TransferDirection::Outbound,
            TransferPhase::CancelRequested,
            Some(4),
            Some(10),
            false,
            None,
        )
        .unwrap();
        let event = serde_json::to_value(AgentEvent::Transfers {
            instance_id: "fedcba98-7654-4321-8fed-cba987654321".to_owned(),
            revision: 7,
            truncated: false,
            transfers: vec![snapshot],
        })
        .unwrap();
        assert_eq!(event["event"], "transfers");
        assert_eq!(event["transfers"][0]["phase"], "cancel_requested");
        assert_eq!(event["transfers"][0]["direction"], "outbound");
    }

    #[test]
    fn transfer_snapshot_enforces_phase_counter_failure_and_identifier_invariants() {
        let id = "01234567-89ab-cdef-0123-456789abcdef".to_owned();
        assert_eq!(
            TransferSnapshot::new(
                id.clone(),
                TransferDirection::Inbound,
                TransferPhase::Transferring,
                Some(11),
                Some(10),
                false,
                None,
            ),
            Err(TransferSnapshotError::InvalidPhaseFields)
        );
        assert_eq!(
            TransferSnapshot::new(
                id.clone(),
                TransferDirection::Outbound,
                TransferPhase::Completed,
                Some(9),
                Some(10),
                false,
                None,
            ),
            Err(TransferSnapshotError::InvalidPhaseFields)
        );
        assert_eq!(
            TransferSnapshot::new(
                id.clone(),
                TransferDirection::Outbound,
                TransferPhase::Failed,
                None,
                None,
                false,
                None,
            ),
            Err(TransferSnapshotError::InvalidPhaseFields)
        );
        assert_eq!(
            TransferSnapshot::new(
                id.clone(),
                TransferDirection::Outbound,
                TransferPhase::Preparing,
                None,
                None,
                true,
                Some(TransferFailureCode::Internal),
            ),
            Err(TransferSnapshotError::InvalidPhaseFields)
        );
        assert_eq!(
            TransferSnapshot::new(
                id,
                TransferDirection::Inbound,
                TransferPhase::Queued,
                Some(0),
                Some(MAX_TRANSFER_BYTES + 1),
                false,
                None,
            ),
            Err(TransferSnapshotError::InvalidPhaseFields)
        );
        for invalid in [
            "00000000-0000-0000-0000-000000000000",
            "01234567-89AB-CDEF-0123-456789ABCDEF",
            "peer-wire-id",
        ] {
            assert_eq!(
                TransferSnapshot::new(
                    invalid.to_owned(),
                    TransferDirection::Outbound,
                    TransferPhase::Preparing,
                    None,
                    None,
                    true,
                    None,
                ),
                Err(TransferSnapshotError::InvalidPublicField)
            );
        }
    }

    #[test]
    fn maximum_transfer_event_is_unique_private_field_free_and_below_ipc_limit() {
        let transfers = (0..MAX_TRANSFER_SNAPSHOTS)
            .map(|index| {
                let mut bytes = [0_u8; 16];
                bytes[8..].copy_from_slice(&u64::try_from(index + 1).unwrap().to_be_bytes());
                let id = uuid::Uuid::from_bytes(bytes).hyphenated().to_string();
                TransferSnapshot::new(
                    id,
                    if index % 2 == 0 {
                        TransferDirection::Inbound
                    } else {
                        TransferDirection::Outbound
                    },
                    if index < MAX_TERMINAL_TRANSFERS {
                        TransferPhase::Failed
                    } else {
                        TransferPhase::Transferring
                    },
                    Some(MAX_TRANSFER_BYTES),
                    Some(MAX_TRANSFER_BYTES),
                    false,
                    (index < MAX_TERMINAL_TRANSFERS).then_some(TransferFailureCode::CleanupFailed),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let event = AgentEvent::Transfers {
            instance_id: "fedcba98-7654-4321-8fed-cba987654321".to_owned(),
            revision: u64::MAX,
            truncated: true,
            transfers,
        };
        let encoded = serde_json::to_vec(&event).unwrap();
        assert!(
            encoded.len() < MAX_IPC_MESSAGE_SIZE,
            "{} bytes",
            encoded.len()
        );
        let text = String::from_utf8(encoded).unwrap();
        for private_name in [
            "path",
            "name",
            "hash",
            "peer_id",
            "endpoint",
            "timestamp",
            "epoch",
            "raw_error",
        ] {
            assert!(!text.contains(private_name), "leaked field {private_name}");
        }
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        let ids = value["transfers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["transfer_id"].as_str().unwrap())
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(ids.len(), MAX_TRANSFER_SNAPSHOTS);
    }

    #[test]
    fn legacy_status_defaults_to_local_focus() {
        let status: super::AgentStatus = serde_json::from_str(
            r#"{"phase":"connected","connected_peer":"peer","input_owner":"local"}"#,
        )
        .unwrap();
        assert_eq!(status.focus_state, super::FocusState::Local);
        assert_eq!(status.readiness, ReadinessSnapshot::default());

        let encoded = serde_json::to_value(status).unwrap();
        assert_eq!(encoded["focus_state"], "local");
        assert_eq!(encoded["readiness"]["accessibility"], "unavailable");
        assert_eq!(encoded["readiness"]["input"], "unavailable");
        assert_eq!(encoded["readiness"]["local_topology"], "unavailable");
        assert_eq!(encoded["readiness"]["session_topology"], "not_connected");
    }

    #[test]
    fn updater_commands_have_stable_exact_offer_shape() {
        assert_eq!(
            serde_json::from_str::<UiCommand>(r#"{"command":"get_update_status"}"#).unwrap(),
            UiCommand::GetUpdateStatus {}
        );
        assert_eq!(
            serde_json::from_str::<UiCommand>(r#"{"command":"check_for_update"}"#).unwrap(),
            UiCommand::CheckForUpdate {}
        );
        let decision = UiCommand::DecideUpdate {
            offer_id: "01234567-89ab-cdef-0123-456789abcdef".to_owned(),
            accepted: true,
        };
        assert_eq!(
            serde_json::from_slice::<UiCommand>(&serde_json::to_vec(&decision).unwrap()).unwrap(),
            decision
        );
        assert!(serde_json::from_str::<UiCommand>(
            r#"{"command":"decide_update","offer_id":"01234567-89AB-CDEF-0123-456789ABCDEF","accepted":true}"#
        )
        .is_err());
    }

    #[test]
    fn updater_snapshot_enforces_public_bounds_and_progress_invariants() {
        let id = "01234567-89ab-cdef-0123-456789abcdef".to_owned();
        let progress = UpdateSnapshot::new(
            UpdatePhase::Downloading,
            Some(id.clone()),
            Some("1.2.3".to_owned()),
            Some(4),
            Some(10),
            None,
        )
        .unwrap();
        let encoded = serde_json::to_value(AgentEvent::UpdateStatus(progress)).unwrap();
        assert_eq!(encoded["phase"], "downloading");
        assert!(encoded.get("artifact_url").is_none());
        assert!(encoded.get("artifact_sha256").is_none());
        assert!(encoded.get("path").is_none());

        assert_eq!(
            UpdateSnapshot::new(
                UpdatePhase::Downloading,
                Some(id.clone()),
                Some("1.2.3".to_owned()),
                Some(11),
                Some(10),
                None,
            ),
            Err(UpdateSnapshotError::InvalidPhaseFields)
        );
        assert_eq!(
            UpdateSnapshot::new(
                UpdatePhase::OfferAvailable,
                Some(id.to_uppercase()),
                Some("1.2.3".to_owned()),
                None,
                Some(10),
                None,
            ),
            Err(UpdateSnapshotError::InvalidPublicField)
        );
        assert!(
            UpdateSnapshot::new(
                UpdatePhase::Unavailable,
                None,
                None,
                None,
                None,
                Some(UpdateFailureCode::NotConfigured),
            )
            .is_ok()
        );

        let invalid_semver = r#"{"phase":"offer_available","offer_id":"01234567-89ab-cdef-0123-456789abcdef","version":"01.2.3","received_bytes":null,"total_bytes":10,"failure":null}"#;
        assert!(serde_json::from_str::<UpdateSnapshot>(invalid_semver).is_err());
        let overbound = format!(
            r#"{{"phase":"offer_available","offer_id":"01234567-89ab-cdef-0123-456789abcdef","version":"{}","received_bytes":null,"total_bytes":10,"failure":null}}"#,
            "1".repeat(MAX_UPDATE_VERSION_BYTES + 1)
        );
        assert!(serde_json::from_str::<UpdateSnapshot>(&overbound).is_err());
    }
}
