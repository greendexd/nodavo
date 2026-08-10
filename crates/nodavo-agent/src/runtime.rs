use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use nodavo_discovery::{DiscoveryLocation, DiscoveryRuntimeEvent, MdnsRuntime};
use nodavo_identity::{
    Capability as TrustedCapability, CapabilityGrants, DeviceSigner as _, PairingAction,
    PairingError, PairingNonce, PairingRole, PairingTxn, PendingTrust, TransportCertificate,
};
use nodavo_local_ipc::{
    AgentPhase, AgentStatus, CapabilityName, FocusState, InputOwner, MAX_SELECTED_PATH_BYTES,
    MAX_SELECTED_PATHS, ReadinessSnapshot, SessionTopologyReadiness, TrustedPeerState,
    TrustedPeerSummary,
};
use nodavo_protocol::{Capability as ProtocolCapability, GrantEpoch};
use nodavo_transfer::{FileSystemStagingArea, TransferId};
use nodavo_transport::quinn_backend::{
    EphemeralPairingConfiguration, EphemeralPairingIdentity, PinnedMutualConfiguration,
    QuinnBackendOptions, QuinnTransport,
};
use nodavo_transport::{
    AuthMode, CloseReason, Endpoint, PeerConnection, Transport as _, TransportCommand,
    TransportError, TransportEvent,
};
use thiserror::Error;
use tokio::net::TcpStream;
use tokio::sync::{Mutex, RwLock, mpsc, oneshot, watch};
use tokio::time::{sleep, timeout};

use crate::clipboard_port::native_clipboard_port;
use crate::native_bridge::{native_input_channel, platform_safety_channel};
#[cfg(target_os = "macos")]
use crate::platform_port::MacPlatformPort;
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
use crate::platform_port::UnavailablePlatformPort;
use crate::platform_readiness::{self, LocalPlatformReadiness, ReadinessRequestError};
use crate::session_runtime::{
    LocalSessionCommand, NativeSessionEvents, SessionConfig, SessionRole, SessionRuntimeError,
    SessionSafetyState, command_channel, run_peer_session,
};
use crate::storage::{DevelopmentStorage, DeviceMaterial, PeerRecord, device_id_text};
use crate::transfer_status::{TransferListing, TransferRegistryError};
use crate::transfer_worker::{TransferCleanupState, TransferStore};
#[cfg(target_os = "windows")]
use crate::windows::WindowsPlatformPort;
use crate::wire::{
    EXPORTER_BYTES, EXPORTER_CONTEXT, EXPORTER_LABEL, PAIRING_PROTOCOL_VERSION, PairingMessage,
    PeerHello, WireError, accept_control_channel, close_pairing_connection, open_control_channel,
    receive_bootstrap, receive_pairing_message, receive_reconnect_ready, receive_reconnect_request,
    send_bootstrap, send_pairing_message, send_reconnect_ready, send_reconnect_request,
};

const NETWORK_DEADLINE: Duration = Duration::from_secs(10);
const CONFIRMATION_DEADLINE: Duration = Duration::from_mins(2);
const MDNS_LOOKUP_DEADLINE: Duration = Duration::from_secs(5);
const SAFETY_RECOVERY_DEADLINE: Duration = Duration::from_secs(5);
/// One end-to-end ceiling for stop delivery, acknowledgement, and all staged
/// peer cleanup before the agent latches a fail-closed stopping state.
const SAFETY_OPERATION_DEADLINE: Duration = Duration::from_secs(20);
const LOCAL_READINESS_CACHE_TTL: Duration = Duration::from_secs(1);

#[derive(Debug, Error)]
pub(crate) enum AgentError {
    #[error("another pairing or peer session is already active")]
    Busy,
    #[error("the manual or mDNS endpoint is invalid")]
    InvalidEndpoint,
    #[error("no matching mDNS advertisement was found")]
    DiscoveryUnavailable,
    #[error("the peer did not connect before the pairing deadline")]
    PairingTimedOut,
    #[error("the pairing protocol failed")]
    PairingFailed,
    #[error("pinned peer authentication or reconnect failed")]
    ReconnectFailed,
    #[error("the requested pairing transaction does not exist")]
    PairingNotFound,
    #[error("the pairing transaction was already confirmed")]
    AlreadyConfirmed,
    #[error("the trusted peer does not exist or is already revoked")]
    PeerNotFound,
    #[error("development trust storage failed")]
    Storage,
    #[error("the local capability grant epoch is exhausted")]
    GrantEpochExhausted,
    #[error("no authenticated peer session is connected")]
    NotConnected,
    #[error("the focus request is not authorized or valid")]
    FocusRejected,
    #[error("local input release and ownership restore did not complete")]
    SafetyRecoveryFailed,
    #[error("the selected file transfer could not be prepared or queued")]
    TransferFailed,
    #[error("the local transfer does not exist")]
    TransferNotFound,
    #[error("the local transfer cannot be cancelled")]
    TransferNotCancellable,
}

impl From<WireError> for AgentError {
    fn from(_: WireError) -> Self {
        Self::PairingFailed
    }
}

impl From<TransportError> for AgentError {
    fn from(_: TransportError) -> Self {
        Self::PairingFailed
    }
}

impl From<PairingError> for AgentError {
    fn from(_: PairingError) -> Self {
        Self::PairingFailed
    }
}

pub(crate) struct PairingStarted {
    pub(crate) pairing_id: String,
    pub(crate) peer_name: String,
    pub(crate) code: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PairingOutcome {
    Pending,
    Finished(bool),
    Failed,
}

struct PairingControl {
    pairing_id: String,
    confirmation: Option<oneshot::Sender<bool>>,
    outcome: watch::Receiver<PairingOutcome>,
}

struct PreparedPairing {
    role: PairingRole,
    transaction: PairingTxn,
    peer: PeerHello,
    connection: Box<dyn PeerConnection>,
    channel: nodavo_transport::ChannelId,
    remote_endpoint: SocketAddr,
}

pub(crate) struct AgentRuntime {
    status: RwLock<AgentStatus>,
    readiness_probe_gate: Mutex<()>,
    readiness_cache_completed_at: Mutex<Option<Instant>>,
    readiness_transition_epoch: AtomicU64,
    session_safety: Arc<SessionSafetyState>,
    storage: Arc<dyn DevelopmentStorage>,
    material: Arc<DeviceMaterial>,
    peers: Mutex<Vec<PeerRecord>>,
    pairing: Mutex<Option<PairingControl>>,
    inbound_waiter: Mutex<Option<oneshot::Sender<TcpStream>>>,
    busy: AtomicBool,
    disconnect: watch::Sender<u64>,
    session_commands: Mutex<Option<mpsc::Sender<LocalSessionCommand>>>,
    transfer_store: TransferStore,
    quic_bind_address: SocketAddr,
    device_name: String,
}

impl AgentRuntime {
    pub(crate) fn new(
        storage: Arc<dyn DevelopmentStorage>,
        material: DeviceMaterial,
        peers: Vec<PeerRecord>,
        quic_bind_address: SocketAddr,
        device_name: String,
    ) -> Arc<Self> {
        let (disconnect, _) = watch::channel(0_u64);
        Arc::new(Self {
            status: RwLock::new(AgentStatus {
                phase: AgentPhase::Ready,
                connected_peer: None,
                input_owner: InputOwner::Local,
                focus_state: FocusState::Local,
                readiness: ReadinessSnapshot::default(),
            }),
            readiness_probe_gate: Mutex::new(()),
            readiness_cache_completed_at: Mutex::new(None),
            readiness_transition_epoch: AtomicU64::new(0),
            session_safety: Arc::new(SessionSafetyState::default()),
            storage,
            material: Arc::new(material),
            peers: Mutex::new(peers),
            pairing: Mutex::new(None),
            inbound_waiter: Mutex::new(None),
            busy: AtomicBool::new(false),
            disconnect,
            session_commands: Mutex::new(None),
            transfer_store: TransferStore::default(),
            quic_bind_address,
            device_name,
        })
    }

    pub(crate) async fn status(&self) -> AgentStatus {
        self.status.read().await.clone()
    }

    async fn begin_session_operation(&self) -> Result<(), AgentError> {
        let _status = self.status.write().await;
        if self.session_safety.failure_latched() {
            return Err(AgentError::SafetyRecoveryFailed);
        }
        if self.session_safety.operation_active() {
            return Err(AgentError::Busy);
        }
        self.busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| AgentError::Busy)
    }

    async fn publish_connected_if_safety_allows(&self, peer_id: String) -> Result<(), AgentError> {
        let mut status = self.status.write().await;
        if self.session_safety.failure_latched() {
            return Err(AgentError::SafetyRecoveryFailed);
        }
        if self.session_safety.operation_active() {
            return Err(AgentError::Busy);
        }
        status.phase = AgentPhase::Connected;
        status.connected_peer = Some(peer_id);
        status.input_owner = InputOwner::Local;
        status.focus_state = FocusState::Local;
        status.readiness.session_topology = SessionTopologyReadiness::Synchronizing;
        self.record_readiness_transition();
        Ok(())
    }

    pub(crate) async fn refresh_platform_readiness(&self) -> AgentStatus {
        self.refresh_platform_readiness_with(platform_readiness::probe(), std::future::ready(()))
            .await
    }

    async fn refresh_platform_readiness_with(
        &self,
        probe: impl Future<Output = LocalPlatformReadiness>,
        after_eligibility: impl Future<Output = ()>,
    ) -> AgentStatus {
        // A dedicated gate coalesces followers behind the active probe. Cache
        // timestamps therefore describe completed accepted probes only and are
        // never overloaded as an in-flight marker.
        let _probe_guard = self.readiness_probe_gate.lock().await;
        // Session start publishes Synchronizing before advancing this epoch.
        // Reading the epoch first therefore cannot pair a new generation with
        // an old NotConnected snapshot.
        let observed_transition_epoch = self.readiness_transition_epoch.load(Ordering::Acquire);
        if self.status.read().await.readiness.session_topology
            != SessionTopologyReadiness::NotConnected
        {
            return self.status().await;
        }
        after_eligibility.await;
        let now = Instant::now();
        if self
            .readiness_cache_completed_at
            .lock()
            .await
            .is_some_and(|completed| now.duration_since(completed) < LOCAL_READINESS_CACHE_TTL)
        {
            return self.status().await;
        }
        let local = probe.await;
        let mut status = self.status.write().await;
        let accepted = self.readiness_transition_epoch.load(Ordering::Acquire)
            == observed_transition_epoch
            && status.readiness.session_topology == SessionTopologyReadiness::NotConnected;
        if accepted {
            status.readiness = local.snapshot(SessionTopologyReadiness::NotConnected);
        }
        drop(status);
        if accepted {
            *self.readiness_cache_completed_at.lock().await = Some(Instant::now());
        }
        self.status().await
    }

    pub(crate) async fn request_accessibility_permission(
        &self,
    ) -> Result<AgentStatus, ReadinessRequestError> {
        let _probe_guard = self.readiness_probe_gate.lock().await;
        let local = platform_readiness::request_accessibility_permission().await?;
        let mut status = self.status.write().await;
        let session_topology = status.readiness.session_topology;
        status.readiness = local.snapshot(session_topology);
        drop(status);
        *self.readiness_cache_completed_at.lock().await = Some(Instant::now());
        Ok(self.status().await)
    }

    pub(crate) async fn trusted_peers(&self) -> Vec<TrustedPeerSummary> {
        self.peers
            .lock()
            .await
            .iter()
            .map(|record| TrustedPeerSummary {
                peer_id: device_id_text(record.device_id()),
                display_name: record.display_name.clone(),
                state: if record.is_active() {
                    TrustedPeerState::Active
                } else {
                    TrustedPeerState::Revoked
                },
                local_grants: capability_names(record.grants),
            })
            .collect()
    }

    pub(crate) async fn set_capability(
        &self,
        peer_id: &str,
        capability: TrustedCapability,
        enabled: bool,
    ) -> Result<(), AgentError> {
        let (grants, epoch, peer_device) = {
            let mut peers = self.peers.lock().await;
            let previous = peers.clone();
            let record = peers
                .iter_mut()
                .find(|record| device_id_text(record.device_id()) == peer_id && record.is_active())
                .ok_or(AgentError::PeerNotFound)?;
            if record.grants.contains(capability) == enabled {
                return Ok(());
            }
            let next = record
                .grant_epoch
                .get()
                .checked_add(1)
                .map(GrantEpoch::new)
                .ok_or(AgentError::GrantEpochExhausted)?;
            record.grants = set_capability(record.grants, capability, enabled)?;
            record.grant_epoch = next;
            let updated = (
                record.grants,
                record.grant_epoch,
                protocol_device_id(record.device_id()),
            );
            if self.storage.store_peers(&peers).is_err() {
                *peers = previous;
                return Err(AgentError::Storage);
            }
            updated
        };

        let discard_inbound = capability == TrustedCapability::FileTransfer && !enabled;
        if discard_inbound {
            self.transfer_store
                .require_peer_inbound_discard(peer_device);
        }
        if let Some(sender) = self.session_commands.lock().await.clone() {
            let (acknowledgement, received) = oneshot::channel();
            let command = LocalSessionCommand::UpdateLocalGrant {
                grants,
                epoch,
                capability: protocol_capability(capability),
                enabled,
                acknowledgement,
            };
            let delivered = timeout(SAFETY_RECOVERY_DEADLINE, sender.send(command)).await;
            let applied = if let Ok(Ok(())) = delivered {
                timeout(SAFETY_RECOVERY_DEADLINE, received).await
            } else {
                self.disconnect_all();
                if discard_inbound {
                    self.wait_transfer_cleanup(peer_device).await?;
                }
                return Ok(());
            };
            if !matches!(applied, Ok(Ok(Ok(())))) {
                // Persistence is already committed. Closing the authenticated
                // session makes the new grant authoritative on reconnect even
                // when the in-session notification cannot complete.
                self.disconnect_all();
            }
        }
        if discard_inbound {
            self.wait_transfer_cleanup(peer_device).await?;
        }
        Ok(())
    }

    pub(crate) async fn send_files(&self, paths: Vec<String>) -> Result<TransferId, AgentError> {
        if paths.is_empty() || paths.len() > MAX_SELECTED_PATHS {
            return Err(AgentError::TransferFailed);
        }
        let paths = paths
            .into_iter()
            .map(|path| {
                if path.is_empty()
                    || path.len() > MAX_SELECTED_PATH_BYTES
                    || path.as_bytes().contains(&0)
                {
                    return Err(AgentError::TransferFailed);
                }
                let path = PathBuf::from(path);
                path.is_absolute()
                    .then_some(path)
                    .ok_or(AgentError::TransferFailed)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let sender = self
            .session_commands
            .lock()
            .await
            .clone()
            .ok_or(AgentError::NotConnected)?;
        let (acknowledgement, received) = oneshot::channel();
        timeout(
            SAFETY_RECOVERY_DEADLINE,
            sender.send(LocalSessionCommand::SendFiles {
                paths,
                acknowledgement,
            }),
        )
        .await
        .map_err(|_| AgentError::TransferFailed)?
        .map_err(|_| AgentError::NotConnected)?;
        timeout(SAFETY_RECOVERY_DEADLINE, received)
            .await
            .map_err(|_| AgentError::TransferFailed)?
            .map_err(|_| AgentError::NotConnected)?
            .map_err(|_| AgentError::TransferFailed)
    }

    pub(crate) fn transfer_listing(&self) -> TransferListing {
        self.transfer_store.transfer_listing()
    }

    pub(crate) async fn cancel_transfer(
        &self,
        transfer_id: &str,
    ) -> Result<TransferListing, AgentError> {
        let outcome =
            self.transfer_store
                .request_cancel(transfer_id)
                .map_err(|error| match error {
                    TransferRegistryError::InvalidId | TransferRegistryError::NotFound => {
                        AgentError::TransferNotFound
                    }
                    TransferRegistryError::NotCancellable => AgentError::TransferNotCancellable,
                    TransferRegistryError::Full
                    | TransferRegistryError::LifetimeFull
                    | TransferRegistryError::WireIdCollision => AgentError::TransferFailed,
                })?;
        if let Some(target) = outcome.target {
            if let Some(sender) = self.session_commands.lock().await.clone() {
                let _ = sender.try_send(LocalSessionCommand::WakeTransferCancellation);
            }
            let store = self.transfer_store.clone();
            tokio::task::spawn_blocking(move || store.cleanup_cancelled_if_offline(target));
        }
        Ok(outcome.listing)
    }

    pub(crate) fn is_reconnect_request(endpoint: &str) -> bool {
        endpoint.starts_with("reconnect:") || endpoint.starts_with("reconnect-listen:")
    }

    pub(crate) async fn reconnect(
        self: &Arc<Self>,
        request: &str,
    ) -> Result<AgentStatus, AgentError> {
        if self.session_safety.failure_latched() {
            return Err(AgentError::SafetyRecoveryFailed);
        }
        let mode = parse_reconnect_request(request)?;
        self.begin_session_operation().await?;
        let mut disconnect = self.disconnect.subscribe();
        let peer_id = mode.peer_id().to_owned();
        let peer = match self.active_peer(&peer_id).await {
            Ok(peer) => peer,
            Err(error) => {
                self.busy.store(false, Ordering::Release);
                return Err(error);
            }
        };

        let role = match &mode {
            ReconnectMode::Listen { .. } => SessionRole::Acceptor,
            ReconnectMode::Connect { .. } => SessionRole::Opener,
        };
        let connected: Result<Box<dyn PeerConnection>, AgentError> = tokio::select! {
            result = async {
                match mode {
                    ReconnectMode::Listen { .. } => self.prepare_pinned_responder(&peer).await,
                    ReconnectMode::Connect { endpoint, .. } => {
                        let address = match endpoint {
                            Some(value) => resolve_endpoint(&value).await?,
                            None => peer.last_endpoint.ok_or(AgentError::InvalidEndpoint)?,
                        };
                        let mut connection = self.prepare_pinned_initiator(&peer, address).await?;
                        if let Err(error) = self.update_peer_endpoint(&peer_id, address).await {
                            close_emergency(connection.as_mut()).await;
                            return Err(error);
                        }
                        Ok(connection)
                    }
                }
            } => result,
            changed = disconnect.changed() => {
                let _ = changed;
                Err(AgentError::SafetyRecoveryFailed)
            }
        };
        let mut connection = match connected {
            Ok(connection) => connection,
            Err(error) => {
                self.inbound_waiter.lock().await.take();
                self.busy.store(false, Ordering::Release);
                return Err(error);
            }
        };

        if let Err(error) = self.publish_connected_if_safety_allows(peer_id).await {
            close_emergency(connection.as_mut()).await;
            self.busy.store(false, Ordering::Release);
            return Err(error);
        }
        let result = self.status().await;
        let (session_tx, session_rx) = command_channel();
        *self.session_commands.lock().await = Some(session_tx);
        let config = SessionConfig {
            role,
            local_device: protocol_device_id(self.material.signer.public_identity().device_id()),
            peer_device: protocol_device_id(peer.device_id()),
            local_grants_to_peer: peer.grants,
            local_grant_epoch: peer.grant_epoch,
            peer_grants_to_local: None,
            peer_grant_epoch: None,
            existing_control: None,
        };
        let runtime = Arc::clone(self);
        tokio::spawn(async move {
            let result = run_platform_session(
                connection,
                config,
                session_rx,
                disconnect,
                &runtime.status,
                Arc::clone(&runtime.session_safety),
                runtime.transfer_store.clone(),
            )
            .await;
            runtime.session_commands.lock().await.take();
            runtime
                .publish_session_finished_status(matches!(
                    result,
                    Err(SessionRuntimeError::SafetyRecoveryFailed)
                ))
                .await;
            runtime.busy.store(false, Ordering::Release);
        });
        Ok(result)
    }

    pub(crate) async fn deliver_inbound(&self, stream: TcpStream) {
        if let Some(waiter) = self.inbound_waiter.lock().await.take() {
            let _ = waiter.send(stream);
        }
    }

    pub(crate) async fn begin_pairing(
        self: &Arc<Self>,
        endpoint: String,
        local_grants: CapabilityGrants,
    ) -> Result<PairingStarted, AgentError> {
        self.begin_session_operation().await?;
        {
            let mut status = self.status.write().await;
            if self.session_safety.failure_latched() {
                self.busy.store(false, Ordering::Release);
                return Err(AgentError::SafetyRecoveryFailed);
            }
            if self.session_safety.operation_active() {
                self.busy.store(false, Ordering::Release);
                return Err(AgentError::Busy);
            }
            status.phase = AgentPhase::Pairing;
            status.connected_peer = None;
            status.input_owner = InputOwner::Local;
            status.focus_state = FocusState::Local;
            status.readiness.session_topology = SessionTopologyReadiness::NotConnected;
        }

        let mut disconnect = self.disconnect.subscribe();
        let prepared = tokio::select! {
            result = async {
                if endpoint == "listen" {
                    self.prepare_responder(local_grants).await
                } else {
                    self.prepare_initiator(&endpoint, local_grants).await
                }
            } => result,
            changed = disconnect.changed() => {
                let _ = changed;
                Err(AgentError::PairingFailed)
            }
        };
        let prepared = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                let mut status = self.status.write().await;
                let safety_blocked = self.session_safety.blocks_ready();
                status.phase = if safety_blocked {
                    AgentPhase::Stopping
                } else {
                    AgentPhase::Ready
                };
                status.readiness.session_topology = SessionTopologyReadiness::NotConnected;
                let error = if self.session_safety.failure_latched() {
                    AgentError::SafetyRecoveryFailed
                } else if self.session_safety.operation_active() {
                    AgentError::Busy
                } else {
                    error
                };
                drop(status);
                self.inbound_waiter.lock().await.take();
                self.busy.store(false, Ordering::Release);
                return Err(error);
            }
        };

        let pairing_id = random_id();
        let code = prepared.transaction.sas().to_string();
        let peer_name = prepared.peer.name.clone();
        let (confirmation, confirmation_rx) = oneshot::channel();
        let (outcome_tx, outcome_rx) = watch::channel(PairingOutcome::Pending);
        *self.pairing.lock().await = Some(PairingControl {
            pairing_id: pairing_id.clone(),
            confirmation: Some(confirmation),
            outcome: outcome_rx,
        });

        let runtime = Arc::clone(self);
        tokio::spawn(async move {
            runtime
                .run_pairing(prepared, confirmation_rx, outcome_tx, disconnect)
                .await;
        });

        Ok(PairingStarted {
            pairing_id,
            peer_name,
            code,
        })
    }

    pub(crate) async fn confirm_pairing(
        &self,
        pairing_id: &str,
        accepted: bool,
    ) -> Result<PairingOutcome, AgentError> {
        let mut outcome = {
            let mut pairing = self.pairing.lock().await;
            let control = pairing.as_mut().ok_or(AgentError::PairingNotFound)?;
            if control.pairing_id != pairing_id {
                return Err(AgentError::PairingNotFound);
            }
            let confirmation = control
                .confirmation
                .take()
                .ok_or(AgentError::AlreadyConfirmed)?;
            confirmation
                .send(accepted)
                .map_err(|_| AgentError::PairingFailed)?;
            control.outcome.clone()
        };

        if *outcome.borrow() == PairingOutcome::Pending {
            timeout(CONFIRMATION_DEADLINE, outcome.changed())
                .await
                .map_err(|_| AgentError::PairingTimedOut)?
                .map_err(|_| AgentError::PairingFailed)?;
        }
        Ok(*outcome.borrow())
    }

    pub(crate) async fn revoke_peer(&self, peer_id: &str) -> Result<(), AgentError> {
        let now = unix_time_ms();
        let mut peers = self.peers.lock().await;
        let previous = peers.clone();
        let record = peers
            .iter_mut()
            .find(|record| device_id_text(record.device_id()) == peer_id && record.is_active())
            .ok_or(AgentError::PeerNotFound)?;
        let revoked_peer = protocol_device_id(record.device_id());
        record.revoked_at_unix_ms = Some(now.max(record.established_at_unix_ms));
        if self.storage.store_peers(&peers).is_err() {
            *peers = previous;
            return Err(AgentError::Storage);
        }
        drop(peers);
        self.transfer_store.mark_peer_revoked(revoked_peer);

        if self.session_commands.lock().await.is_some() {
            self.disconnect_all();
            self.status.write().await.readiness.session_topology =
                SessionTopologyReadiness::NotConnected;
        }
        self.wait_transfer_cleanup(revoked_peer).await?;
        Ok(())
    }

    async fn wait_transfer_cleanup(
        &self,
        peer: nodavo_protocol::DeviceId,
    ) -> Result<(), AgentError> {
        let store = self.transfer_store.clone();
        timeout(SAFETY_RECOVERY_DEADLINE, async move {
            loop {
                let cleanup_store = store.clone();
                let state =
                    tokio::task::spawn_blocking(move || cleanup_store.cleanup_peer_if_idle(peer))
                        .await
                        .map_err(|_| AgentError::TransferFailed)?
                        .map_err(|_| AgentError::TransferFailed)?;
                if state == TransferCleanupState::Complete {
                    return Ok(());
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .map_err(|_| AgentError::TransferFailed)?
    }

    async fn enroll_all_inbound_cleanup_after_workers_stop(
        &self,
    ) -> Result<Vec<nodavo_protocol::DeviceId>, AgentError> {
        loop {
            let store = self.transfer_store.clone();
            let enrolled =
                tokio::task::spawn_blocking(move || store.require_all_inbound_discard_if_idle())
                    .await
                    .map_err(|_| AgentError::SafetyRecoveryFailed)?;
            if let Some(peers) = enrolled {
                return Ok(peers);
            }
            sleep(Duration::from_millis(10)).await;
        }
    }

    async fn wait_for_session_operation_idle(&self) {
        while self.busy.load(Ordering::Acquire) {
            sleep(Duration::from_millis(10)).await;
        }
    }

    pub(crate) async fn emergency_stop(&self) -> Result<AgentStatus, AgentError> {
        self.handle_safety_stop(SessionStop::Emergency).await
    }

    pub(crate) async fn local_locked(&self) -> Result<AgentStatus, AgentError> {
        self.handle_safety_stop(SessionStop::Locked).await
    }

    pub(crate) async fn local_sleeping(&self) -> Result<AgentStatus, AgentError> {
        self.handle_safety_stop(SessionStop::Sleeping).await
    }

    pub(crate) async fn request_remote_focus(
        &self,
        ttl_ms: u32,
    ) -> Result<AgentStatus, AgentError> {
        let sender = self.session_sender().await?;
        let (acknowledgement, received) = oneshot::channel();
        sender
            .send(LocalSessionCommand::RequestFocus {
                ttl_ms,
                acknowledgement,
            })
            .await
            .map_err(|_| AgentError::NotConnected)?;
        received
            .await
            .map_err(|_| AgentError::NotConnected)?
            .map_err(map_session_error)?;
        Ok(self.status().await)
    }

    pub(crate) async fn release_focus(&self) -> Result<AgentStatus, AgentError> {
        let sender = self.session_sender().await?;
        let (acknowledgement, received) = oneshot::channel();
        sender
            .send(LocalSessionCommand::ReleaseFocus { acknowledgement })
            .await
            .map_err(|_| AgentError::NotConnected)?;
        received
            .await
            .map_err(|_| AgentError::NotConnected)?
            .map_err(map_session_error)?;
        Ok(self.status().await)
    }

    async fn session_sender(&self) -> Result<mpsc::Sender<LocalSessionCommand>, AgentError> {
        self.session_commands
            .lock()
            .await
            .clone()
            .ok_or(AgentError::NotConnected)
    }

    async fn stop_session(&self, reason: SessionStop) -> Result<bool, AgentError> {
        let Ok(sender) = self.session_sender().await else {
            return Ok(false);
        };
        let (acknowledgement, received) = oneshot::channel();
        let command = match reason {
            SessionStop::Emergency => LocalSessionCommand::EmergencyStop { acknowledgement },
            SessionStop::Locked => LocalSessionCommand::LocalLocked { acknowledgement },
            SessionStop::Sleeping => LocalSessionCommand::LocalSleeping { acknowledgement },
        };
        timeout(SAFETY_RECOVERY_DEADLINE, sender.send(command))
            .await
            .map_err(|_| AgentError::SafetyRecoveryFailed)?
            .map_err(|_| AgentError::SafetyRecoveryFailed)?;
        timeout(SAFETY_RECOVERY_DEADLINE, received)
            .await
            .map_err(|_| AgentError::SafetyRecoveryFailed)?
            .map_err(|_| AgentError::SafetyRecoveryFailed)?
            .map_err(map_session_error)?;
        Ok(true)
    }

    async fn handle_safety_stop(&self, reason: SessionStop) -> Result<AgentStatus, AgentError> {
        self.handle_safety_stop_with_deadline(reason, SAFETY_OPERATION_DEADLINE)
            .await
    }

    async fn handle_safety_stop_with_deadline(
        &self,
        reason: SessionStop,
        deadline: Duration,
    ) -> Result<AgentStatus, AgentError> {
        {
            let mut status = self.status.write().await;
            if self.session_safety.failure_latched() {
                return Err(AgentError::SafetyRecoveryFailed);
            }
            if self.session_safety.operation_active() {
                return Err(AgentError::Busy);
            }
            self.transfer_store.close_worker_admission_for_safety();
            self.session_safety.set_operation_active(true);
            status.phase = AgentPhase::Stopping;
            status.readiness.session_topology = SessionTopologyReadiness::NotConnected;
        }
        let operation = timeout(deadline, self.handle_safety_stop_inner(reason)).await;
        if let Ok(Ok(())) = operation {
            self.finish_safety_stop_success().await
        } else {
            self.fail_closed_safety_stop().await;
            Err(AgentError::SafetyRecoveryFailed)
        }
    }

    async fn handle_safety_stop_inner(&self, reason: SessionStop) -> Result<(), AgentError> {
        match self.stop_session(reason).await {
            Ok(true) => {}
            Ok(false) => self.disconnect_all(),
            Err(_) => return Err(AgentError::SafetyRecoveryFailed),
        }
        self.wait_for_session_operation_idle().await;
        let cleanup_peers = self.enroll_all_inbound_cleanup_after_workers_stop().await?;
        for peer in cleanup_peers {
            self.wait_transfer_cleanup(peer)
                .await
                .map_err(|_| AgentError::SafetyRecoveryFailed)?;
        }
        Ok(())
    }

    async fn finish_safety_stop_success(&self) -> Result<AgentStatus, AgentError> {
        let mut status = self.status.write().await;
        if self.session_safety.failure_latched() {
            status.phase = AgentPhase::Stopping;
            status.readiness.session_topology = SessionTopologyReadiness::NotConnected;
            return Err(AgentError::SafetyRecoveryFailed);
        }
        self.transfer_store.reopen_worker_admission_after_safety();
        self.session_safety.set_operation_active(false);
        status.input_owner = InputOwner::Local;
        status.focus_state = FocusState::Local;
        status.connected_peer = None;
        status.phase = AgentPhase::Ready;
        status.readiness.session_topology = SessionTopologyReadiness::NotConnected;
        Ok(status.clone())
    }

    async fn fail_closed_safety_stop(&self) {
        let mut status = self.status.write().await;
        self.session_safety.latch_failure();
        self.disconnect_all();
        status.input_owner = InputOwner::Local;
        status.focus_state = FocusState::Local;
        status.connected_peer = None;
        status.phase = AgentPhase::Stopping;
        status.readiness.session_topology = SessionTopologyReadiness::NotConnected;
    }

    async fn publish_session_finished_status(&self, session_safety_failed: bool) {
        let mut status = self.status.write().await;
        status.input_owner = InputOwner::Local;
        status.focus_state = FocusState::Local;
        status.connected_peer = None;
        status.readiness.session_topology = SessionTopologyReadiness::NotConnected;
        status.phase = if session_safety_failed || self.session_safety.blocks_ready() {
            AgentPhase::Stopping
        } else {
            AgentPhase::Ready
        };
    }

    fn record_readiness_transition(&self) {
        self.readiness_transition_epoch
            .fetch_add(1, Ordering::Release);
    }

    pub(crate) fn disconnect_all(&self) {
        let next = self.disconnect.borrow().wrapping_add(1);
        let _ = self.disconnect.send(next);
    }

    async fn prepare_responder(
        &self,
        local_grants: CapabilityGrants,
    ) -> Result<PreparedPairing, AgentError> {
        let (sender, receiver) = oneshot::channel();
        {
            let mut waiter = self.inbound_waiter.lock().await;
            if waiter.is_some() {
                return Err(AgentError::Busy);
            }
            *waiter = Some(sender);
        }
        let mut stream = timeout(CONFIRMATION_DEADLINE, receiver)
            .await
            .map_err(|_| AgentError::PairingTimedOut)?
            .map_err(|_| AgentError::PairingFailed)?;
        let peer_bootstrap = receive_bootstrap(&mut stream).await?;

        let local_ephemeral =
            EphemeralPairingIdentity::generate("responder.pairing.nodavo.invalid")?;
        let local_certificate = local_ephemeral.certificate_der().to_vec();
        let local_server_name = local_ephemeral.server_name().to_owned();
        let configuration = EphemeralPairingConfiguration::new(
            PAIRING_PROTOCOL_VERSION,
            local_ephemeral,
            peer_bootstrap.certificate_der,
            peer_bootstrap.server_name,
        )?;
        let transport = QuinnTransport::bind_ephemeral_pairing(
            self.quic_bind_address,
            configuration,
            QuinnBackendOptions::default(),
        )?;
        send_bootstrap(&mut stream, &local_certificate, &local_server_name).await?;
        drop(stream);

        let mut connection = transport.accept().await?;
        let remote_endpoint = connection.remote_endpoint().address();
        let exporter =
            connection.export_keying_material(EXPORTER_LABEL, EXPORTER_CONTEXT, EXPORTER_BYTES)?;
        let channel = accept_control_channel(connection.as_mut()).await?;
        let peer = expect_hello(receive_pairing_message(connection.as_mut(), channel).await?)?;
        let local = self.local_hello(local_grants)?;
        send_pairing_message(
            connection.as_mut(),
            channel,
            &PairingMessage::Hello(local.clone()),
        )
        .await?;
        let transaction = PairingTxn::new(
            PAIRING_PROTOCOL_VERSION,
            &exporter,
            PendingTrust::new(peer.identity, peer.grants, peer.certificate.clone()),
            peer.nonce,
            PendingTrust::new(local.identity, local.grants, local.certificate),
            local.nonce,
        )?;
        Ok(PreparedPairing {
            role: PairingRole::Responder,
            transaction,
            peer,
            connection,
            channel,
            remote_endpoint,
        })
    }

    async fn prepare_pinned_responder(
        &self,
        peer: &PeerRecord,
    ) -> Result<Box<dyn PeerConnection>, AgentError> {
        let (sender, receiver) = oneshot::channel();
        {
            let mut waiter = self.inbound_waiter.lock().await;
            if waiter.is_some() {
                return Err(AgentError::Busy);
            }
            *waiter = Some(sender);
        }
        let mut stream = timeout(CONFIRMATION_DEADLINE, receiver)
            .await
            .map_err(|_| AgentError::PairingTimedOut)?
            .map_err(|_| AgentError::ReconnectFailed)?;
        receive_reconnect_request(&mut stream)
            .await
            .map_err(|_| AgentError::ReconnectFailed)?;
        let trust = peer.restored_trust().map_err(|_| AgentError::Storage)?;
        let binding = trust.transport_binding().ok_or(AgentError::PeerNotFound)?;
        let configuration = PinnedMutualConfiguration::new(
            self.material
                .credentials()
                .map_err(|_| AgentError::Storage)?,
            binding,
            peer.certificate_der.clone(),
            peer.server_name.clone(),
        )
        .map_err(|_| AgentError::ReconnectFailed)?;
        let transport = QuinnTransport::bind_pinned_mutual(
            self.quic_bind_address,
            configuration,
            QuinnBackendOptions::default(),
        )
        .map_err(|_| AgentError::ReconnectFailed)?;
        send_reconnect_ready(&mut stream)
            .await
            .map_err(|_| AgentError::ReconnectFailed)?;
        drop(stream);
        let mut connection = transport
            .accept()
            .await
            .map_err(|_| AgentError::ReconnectFailed)?;
        expect_connected(connection.as_mut()).await?;
        Ok(connection)
    }

    async fn prepare_pinned_initiator(
        &self,
        peer: &PeerRecord,
        remote_address: SocketAddr,
    ) -> Result<Box<dyn PeerConnection>, AgentError> {
        let mut stream = timeout(NETWORK_DEADLINE, TcpStream::connect(remote_address))
            .await
            .map_err(|_| AgentError::PairingTimedOut)?
            .map_err(|_| AgentError::ReconnectFailed)?;
        send_reconnect_request(&mut stream)
            .await
            .map_err(|_| AgentError::ReconnectFailed)?;
        receive_reconnect_ready(&mut stream)
            .await
            .map_err(|_| AgentError::ReconnectFailed)?;
        drop(stream);

        let trust = peer.restored_trust().map_err(|_| AgentError::Storage)?;
        let binding = trust.transport_binding().ok_or(AgentError::PeerNotFound)?;
        let bind_address = match remote_address.ip() {
            IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        };
        let configuration = PinnedMutualConfiguration::new(
            self.material
                .credentials()
                .map_err(|_| AgentError::Storage)?,
            binding,
            peer.certificate_der.clone(),
            peer.server_name.clone(),
        )
        .map_err(|_| AgentError::ReconnectFailed)?;
        let transport = QuinnTransport::bind_pinned_mutual(
            bind_address,
            configuration,
            QuinnBackendOptions::default(),
        )
        .map_err(|_| AgentError::ReconnectFailed)?;
        let endpoint = Endpoint::new(remote_address).map_err(|_| AgentError::InvalidEndpoint)?;
        let mut connection = transport
            .connect(
                endpoint,
                AuthMode::PinnedMutual {
                    expected_peer_public_key: peer.public_key,
                },
            )
            .await
            .map_err(|_| AgentError::ReconnectFailed)?;
        expect_connected(connection.as_mut()).await?;
        Ok(connection)
    }

    async fn prepare_initiator(
        &self,
        requested: &str,
        local_grants: CapabilityGrants,
    ) -> Result<PreparedPairing, AgentError> {
        let remote_address = resolve_endpoint(requested).await?;
        let mut stream = timeout(NETWORK_DEADLINE, TcpStream::connect(remote_address))
            .await
            .map_err(|_| AgentError::PairingTimedOut)?
            .map_err(|_| AgentError::PairingFailed)?;
        let local_ephemeral =
            EphemeralPairingIdentity::generate("initiator.pairing.nodavo.invalid")?;
        let local_certificate = local_ephemeral.certificate_der().to_vec();
        let local_server_name = local_ephemeral.server_name().to_owned();
        send_bootstrap(&mut stream, &local_certificate, &local_server_name).await?;
        let peer_bootstrap = receive_bootstrap(&mut stream).await?;
        drop(stream);

        let bind_address = match remote_address.ip() {
            IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        };
        let configuration = EphemeralPairingConfiguration::new(
            PAIRING_PROTOCOL_VERSION,
            local_ephemeral,
            peer_bootstrap.certificate_der,
            peer_bootstrap.server_name,
        )?;
        let transport = QuinnTransport::bind_ephemeral_pairing(
            bind_address,
            configuration,
            QuinnBackendOptions::default(),
        )?;
        let endpoint = Endpoint::new(remote_address)?;
        let mut connection = transport
            .connect(endpoint, AuthMode::pairing(PAIRING_PROTOCOL_VERSION)?)
            .await?;
        let exporter =
            connection.export_keying_material(EXPORTER_LABEL, EXPORTER_CONTEXT, EXPORTER_BYTES)?;
        let channel = open_control_channel(connection.as_mut()).await?;
        let local = self.local_hello(local_grants)?;
        send_pairing_message(
            connection.as_mut(),
            channel,
            &PairingMessage::Hello(local.clone()),
        )
        .await?;
        let peer = expect_hello(receive_pairing_message(connection.as_mut(), channel).await?)?;
        let transaction = PairingTxn::new(
            PAIRING_PROTOCOL_VERSION,
            &exporter,
            PendingTrust::new(local.identity, local.grants, local.certificate),
            local.nonce,
            PendingTrust::new(peer.identity, peer.grants, peer.certificate.clone()),
            peer.nonce,
        )?;
        Ok(PreparedPairing {
            role: PairingRole::Initiator,
            transaction,
            peer,
            connection,
            channel,
            remote_endpoint: remote_address,
        })
    }

    fn local_hello(&self, grants: CapabilityGrants) -> Result<PeerHello, AgentError> {
        let certificate = TransportCertificate::from_der(self.material.certificate_der.clone())
            .map_err(|_| AgentError::Storage)?;
        Ok(PeerHello {
            name: self.device_name.clone(),
            identity: self.material.signer.public_identity(),
            certificate,
            grants,
            nonce: PairingNonce::generate(),
            server_name: self.material.server_name.clone(),
        })
    }

    async fn run_pairing(
        self: Arc<Self>,
        prepared: PreparedPairing,
        confirmation_rx: oneshot::Receiver<bool>,
        outcome: watch::Sender<PairingOutcome>,
        mut disconnect: watch::Receiver<u64>,
    ) {
        let result = self
            .complete_pairing(prepared, confirmation_rx, &mut disconnect, &outcome)
            .await;
        if result.is_err() {
            let _ = outcome.send(PairingOutcome::Failed);
        }
        self.publish_session_finished_status(matches!(
            result,
            Err(AgentError::SafetyRecoveryFailed)
        ))
        .await;
        self.busy.store(false, Ordering::Release);
    }

    // Keeping the signed two-party transition linear makes its security order
    // reviewable; extracting individual sends would obscure reducer ordering.
    #[allow(clippy::too_many_lines)]
    async fn complete_pairing(
        &self,
        mut prepared: PreparedPairing,
        confirmation_rx: oneshot::Receiver<bool>,
        disconnect: &mut watch::Receiver<u64>,
        outcome: &watch::Sender<PairingOutcome>,
    ) -> Result<(), AgentError> {
        let local_accepted = tokio::select! {
            result = timeout(CONFIRMATION_DEADLINE, confirmation_rx) => {
                result.map_err(|_| AgentError::PairingTimedOut)?
                    .map_err(|_| AgentError::PairingFailed)?
            }
            changed = disconnect.changed() => {
                changed.map_err(|_| AgentError::PairingFailed)?;
                close_emergency(prepared.connection.as_mut()).await;
                return Ok(());
            }
        };
        if !local_accepted {
            let _ = prepared.transaction.reduce(PairingAction::Abort);
            send_pairing_message(
                prepared.connection.as_mut(),
                prepared.channel,
                &PairingMessage::Confirmation(false),
            )
            .await?;
            close_pairing_connection(prepared.connection.as_mut()).await;
            let _ = outcome.send(PairingOutcome::Finished(false));
            return Ok(());
        }

        let sas = prepared.transaction.sas();
        prepared.transaction.reduce(PairingAction::ConfirmSas {
            role: prepared.role,
            sas,
        })?;
        send_pairing_message(
            prepared.connection.as_mut(),
            prepared.channel,
            &PairingMessage::Confirmation(true),
        )
        .await?;
        match receive_or_disconnect(&mut prepared, disconnect).await? {
            Some(PairingMessage::Confirmation(true)) => {}
            Some(PairingMessage::Confirmation(false)) => {
                let _ = prepared.transaction.reduce(PairingAction::Abort);
                close_pairing_connection(prepared.connection.as_mut()).await;
                let _ = outcome.send(PairingOutcome::Finished(false));
                return Ok(());
            }
            Some(_) => return Err(AgentError::PairingFailed),
            None => return Ok(()),
        }
        prepared.transaction.reduce(PairingAction::ConfirmSas {
            role: peer_role(prepared.role),
            sas,
        })?;

        let local_acceptance = prepared
            .transaction
            .create_acceptance(prepared.role, &self.material.signer)?;
        prepared
            .transaction
            .reduce(PairingAction::SubmitAcceptance(local_acceptance))?;
        send_pairing_message(
            prepared.connection.as_mut(),
            prepared.channel,
            &PairingMessage::Acceptance(local_acceptance),
        )
        .await?;
        let peer_acceptance = match receive_or_disconnect(&mut prepared, disconnect).await? {
            Some(PairingMessage::Acceptance(value)) if value.role() == peer_role(prepared.role) => {
                value
            }
            Some(_) => return Err(AgentError::PairingFailed),
            None => return Ok(()),
        };
        prepared
            .transaction
            .reduce(PairingAction::SubmitAcceptance(peer_acceptance))?;

        send_pairing_message(
            prepared.connection.as_mut(),
            prepared.channel,
            &PairingMessage::ReadyToCommit,
        )
        .await?;
        match receive_or_disconnect(&mut prepared, disconnect).await? {
            Some(PairingMessage::ReadyToCommit) => {}
            Some(_) => return Err(AgentError::PairingFailed),
            None => return Ok(()),
        }

        let established_at_unix_ms = unix_time_ms();
        prepared.transaction.reduce(PairingAction::Commit {
            established_at_unix_ms,
        })?;
        let committed = prepared.transaction.committed_trust_for(prepared.role)?;
        let binding = committed.transport_binding();
        if binding.peer_identity() != prepared.peer.identity
            || !binding.matches_certificate_der(prepared.peer.certificate.der())
        {
            return Err(AgentError::PairingFailed);
        }
        let peer_id = device_id_text(binding.peer_identity().device_id());
        let record = PeerRecord {
            public_key: *binding.peer_identity().public_key_bytes(),
            certificate_der: binding.certificate_der().to_vec(),
            grants: committed.record().grants(),
            grant_epoch: nodavo_protocol::GrantEpoch::new(1),
            display_name: prepared.peer.name.clone(),
            established_at_unix_ms,
            revoked_at_unix_ms: None,
            server_name: prepared.peer.server_name.clone(),
            last_endpoint: Some(prepared.remote_endpoint),
        };
        self.persist_peer(record.clone()).await?;

        send_pairing_message(
            prepared.connection.as_mut(),
            prepared.channel,
            &PairingMessage::Committed,
        )
        .await?;
        match receive_or_disconnect(&mut prepared, disconnect).await? {
            Some(PairingMessage::Committed) => {}
            Some(_) => return Err(AgentError::PairingFailed),
            None => return Ok(()),
        }

        if let Err(error) = self.publish_connected_if_safety_allows(peer_id).await {
            close_emergency(prepared.connection.as_mut()).await;
            return Err(error);
        }
        let _ = outcome.send(PairingOutcome::Finished(true));
        let (session_tx, session_rx) = command_channel();
        *self.session_commands.lock().await = Some(session_tx);
        let config = SessionConfig {
            role: match prepared.role {
                PairingRole::Initiator => SessionRole::Opener,
                PairingRole::Responder => SessionRole::Acceptor,
            },
            local_device: protocol_device_id(self.material.signer.public_identity().device_id()),
            peer_device: protocol_device_id(record.device_id()),
            local_grants_to_peer: record.grants,
            local_grant_epoch: record.grant_epoch,
            peer_grants_to_local: Some(prepared.peer.grants),
            peer_grant_epoch: Some(nodavo_protocol::GrantEpoch::new(1)),
            existing_control: Some(prepared.channel),
        };
        let session_result = run_platform_session(
            prepared.connection,
            config,
            session_rx,
            disconnect.clone(),
            &self.status,
            Arc::clone(&self.session_safety),
            self.transfer_store.clone(),
        )
        .await;
        self.session_commands.lock().await.take();
        session_result.map_err(map_session_error)?;
        Ok(())
    }

    async fn persist_peer(&self, record: PeerRecord) -> Result<(), AgentError> {
        let mut peers = self.peers.lock().await;
        let previous = peers.clone();
        if let Some(existing) = peers
            .iter_mut()
            .find(|value| value.device_id() == record.device_id())
        {
            *existing = record;
        } else {
            peers.push(record);
        }
        if self.storage.store_peers(&peers).is_err() {
            *peers = previous;
            return Err(AgentError::Storage);
        }
        Ok(())
    }

    async fn active_peer(&self, peer_id: &str) -> Result<PeerRecord, AgentError> {
        self.peers
            .lock()
            .await
            .iter()
            .find(|record| device_id_text(record.device_id()) == peer_id && record.is_active())
            .cloned()
            .ok_or(AgentError::PeerNotFound)
    }

    async fn update_peer_endpoint(
        &self,
        peer_id: &str,
        endpoint: SocketAddr,
    ) -> Result<(), AgentError> {
        let mut peers = self.peers.lock().await;
        let previous = peers.clone();
        let record = peers
            .iter_mut()
            .find(|record| device_id_text(record.device_id()) == peer_id && record.is_active())
            .ok_or(AgentError::PeerNotFound)?;
        record.last_endpoint = Some(endpoint);
        if self.storage.store_peers(&peers).is_err() {
            *peers = previous;
            return Err(AgentError::Storage);
        }
        Ok(())
    }
}

async fn run_platform_session(
    connection: Box<dyn PeerConnection>,
    config: SessionConfig,
    commands: mpsc::Receiver<LocalSessionCommand>,
    disconnect: watch::Receiver<u64>,
    status: &RwLock<AgentStatus>,
    session_safety: Arc<SessionSafetyState>,
    transfer_store: TransferStore,
) -> Result<(), SessionRuntimeError> {
    let (native_sender, native_receiver) = native_input_channel();
    let (safety_sender, safety_receiver) = platform_safety_channel();
    let clipboard = native_clipboard_port().map_err(|_| SessionRuntimeError::Platform)?;
    let transfer = native_transfer_staging(&transfer_store, config.peer_device)?;

    #[cfg(target_os = "macos")]
    let mut platform = MacPlatformPort::new(native_sender, &safety_sender);
    #[cfg(target_os = "windows")]
    let mut platform = WindowsPlatformPort::new(native_sender, &safety_sender);
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let mut platform = {
        let _native_sender = native_sender;
        let _safety_sender = safety_sender;
        UnavailablePlatformPort
    };

    run_peer_session(
        connection,
        config,
        commands,
        NativeSessionEvents {
            input: native_receiver,
            safety: safety_receiver,
            clipboard,
            transfer,
            transfer_store,
            session_safety,
        },
        disconnect,
        status,
        &mut platform,
    )
    .await
}

fn native_transfer_staging(
    transfer_store: &TransferStore,
    peer: nodavo_protocol::DeviceId,
) -> Result<FileSystemStagingArea, SessionRuntimeError> {
    #[cfg(unix)]
    let state_root = crate::default_state_directory().map_err(|_| SessionRuntimeError::Platform)?;
    #[cfg(target_os = "windows")]
    let state_root =
        crate::windows::default_state_directory().map_err(|_| SessionRuntimeError::Platform)?;
    let inbox = state_root.join("Received Files");
    std::fs::create_dir_all(&inbox).map_err(|_| SessionRuntimeError::Platform)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        std::fs::set_permissions(&inbox, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| SessionRuntimeError::Platform)?;
    }
    transfer_store
        .register_staging_root(peer, inbox.clone())
        .map_err(|_| SessionRuntimeError::Platform)?;
    FileSystemStagingArea::new_scoped(inbox, *peer.as_bytes())
        .map_err(|_| SessionRuntimeError::Platform)
}

enum ReconnectMode {
    Listen {
        peer_id: String,
    },
    Connect {
        peer_id: String,
        endpoint: Option<String>,
    },
}

impl ReconnectMode {
    fn peer_id(&self) -> &str {
        match self {
            Self::Listen { peer_id } | Self::Connect { peer_id, .. } => peer_id,
        }
    }
}

fn parse_reconnect_request(request: &str) -> Result<ReconnectMode, AgentError> {
    if let Some(peer_id) = request.strip_prefix("reconnect-listen:") {
        validate_peer_id_text(peer_id)?;
        return Ok(ReconnectMode::Listen {
            peer_id: peer_id.to_owned(),
        });
    }
    let remainder = request
        .strip_prefix("reconnect:")
        .ok_or(AgentError::InvalidEndpoint)?;
    let (peer_id, endpoint) = remainder
        .split_once('@')
        .map_or((remainder, None), |(peer_id, endpoint)| {
            (peer_id, Some(endpoint.to_owned()))
        });
    validate_peer_id_text(peer_id)?;
    if endpoint.as_deref().is_some_and(str::is_empty) {
        return Err(AgentError::InvalidEndpoint);
    }
    Ok(ReconnectMode::Connect {
        peer_id: peer_id.to_owned(),
        endpoint,
    })
}

fn validate_peer_id_text(peer_id: &str) -> Result<(), AgentError> {
    if peer_id.len() == 64
        && peer_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(AgentError::InvalidEndpoint)
    }
}

async fn expect_connected(connection: &mut dyn PeerConnection) -> Result<(), AgentError> {
    match connection.next_event().await {
        Ok(TransportEvent::Connected { .. }) => Ok(()),
        _ => Err(AgentError::ReconnectFailed),
    }
}

async fn receive_or_disconnect(
    prepared: &mut PreparedPairing,
    disconnect: &mut watch::Receiver<u64>,
) -> Result<Option<PairingMessage>, AgentError> {
    tokio::select! {
        message = receive_pairing_message(prepared.connection.as_mut(), prepared.channel) => {
            Ok(Some(message?))
        }
        changed = disconnect.changed() => {
            changed.map_err(|_| AgentError::PairingFailed)?;
            close_emergency(prepared.connection.as_mut()).await;
            Ok(None)
        }
    }
}

async fn close_emergency(connection: &mut dyn PeerConnection) {
    let _ = connection
        .execute(TransportCommand::Close(CloseReason::EmergencyDisconnect))
        .await;
}

#[derive(Clone, Copy)]
enum SessionStop {
    Emergency,
    Locked,
    Sleeping,
}

fn map_session_error(error: SessionRuntimeError) -> AgentError {
    match error {
        SessionRuntimeError::Transport => AgentError::NotConnected,
        SessionRuntimeError::FocusRejected => AgentError::FocusRejected,
        SessionRuntimeError::SafetyRecoveryFailed => AgentError::SafetyRecoveryFailed,
        SessionRuntimeError::ProtocolViolation | SessionRuntimeError::Platform => {
            AgentError::PairingFailed
        }
    }
}

fn protocol_device_id(device_id: nodavo_identity::DeviceId) -> nodavo_protocol::DeviceId {
    nodavo_protocol::DeviceId::new(*device_id.as_bytes())
}

fn set_capability(
    grants: CapabilityGrants,
    capability: TrustedCapability,
    enabled: bool,
) -> Result<CapabilityGrants, AgentError> {
    if enabled {
        Ok(grants.with(capability))
    } else {
        CapabilityGrants::from_bits(grants.bits() & !(capability as u8))
            .map_err(|_| AgentError::Storage)
    }
}

const fn protocol_capability(capability: TrustedCapability) -> ProtocolCapability {
    match capability {
        TrustedCapability::RemoteInput => ProtocolCapability::REMOTE_INPUT,
        TrustedCapability::ClipboardRead => ProtocolCapability::CLIPBOARD_READ,
        TrustedCapability::ClipboardWrite => ProtocolCapability::CLIPBOARD_WRITE,
        TrustedCapability::FileTransfer => ProtocolCapability::FILE_TRANSFER,
    }
}

fn capability_names(grants: CapabilityGrants) -> Vec<CapabilityName> {
    [
        (TrustedCapability::RemoteInput, CapabilityName::Input),
        (
            TrustedCapability::ClipboardRead,
            CapabilityName::ClipboardRead,
        ),
        (
            TrustedCapability::ClipboardWrite,
            CapabilityName::ClipboardWrite,
        ),
        (TrustedCapability::FileTransfer, CapabilityName::Files),
    ]
    .into_iter()
    .filter_map(|(capability, name)| grants.contains(capability).then_some(name))
    .collect()
}

fn expect_hello(message: PairingMessage) -> Result<PeerHello, AgentError> {
    match message {
        PairingMessage::Hello(hello) => Ok(hello),
        _ => Err(AgentError::PairingFailed),
    }
}

const fn peer_role(role: PairingRole) -> PairingRole {
    match role {
        PairingRole::Initiator => PairingRole::Responder,
        PairingRole::Responder => PairingRole::Initiator,
    }
}

async fn resolve_endpoint(requested: &str) -> Result<SocketAddr, AgentError> {
    if let Some(instance) = requested.strip_prefix("mdns:") {
        return resolve_mdns(instance).await;
    }
    let address = requested
        .parse::<SocketAddr>()
        .map_err(|_| AgentError::InvalidEndpoint)?;
    DiscoveryLocation::manual(address)
        .map_err(|_| AgentError::InvalidEndpoint)
        .map(|location| location.address())
}

async fn resolve_mdns(instance: &str) -> Result<SocketAddr, AgentError> {
    if instance.is_empty()
        || instance.len() > 63
        || instance.trim() != instance
        || instance.chars().any(char::is_control)
    {
        return Err(AgentError::InvalidEndpoint);
    }
    let instance = instance.to_owned();
    tokio::task::spawn_blocking(move || {
        let runtime = MdnsRuntime::new().map_err(|_| AgentError::DiscoveryUnavailable)?;
        let browser = runtime
            .browse()
            .map_err(|_| AgentError::DiscoveryUnavailable)?;
        let deadline = Instant::now() + MDNS_LOOKUP_DEADLINE;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(AgentError::DiscoveryUnavailable);
            }
            match browser.recv_timeout(remaining.min(Duration::from_millis(500))) {
                Ok(DiscoveryRuntimeEvent::Resolved { locations, .. }) => {
                    if let Some(address) =
                        locations.into_iter().find_map(|location| match &location {
                            DiscoveryLocation::Mdns { record, .. }
                                if record.instance_name() == instance =>
                            {
                                Some(location.address())
                            }
                            _ => None,
                        })
                    {
                        return Ok(address);
                    }
                }
                Ok(
                    DiscoveryRuntimeEvent::Removed { .. }
                    | DiscoveryRuntimeEvent::InvalidAdvertisement,
                )
                | Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(AgentError::DiscoveryUnavailable);
                }
            }
        }
    })
    .await
    .map_err(|_| AgentError::DiscoveryUnavailable)?
}

fn random_id() -> String {
    let mut value = String::with_capacity(32);
    for byte in rand::random::<[u8; 16]>() {
        use std::fmt::Write as _;
        let _ = write!(value, "{byte:02x}");
    }
    value
}

fn unix_time_ms() -> u64 {
    let milliseconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    u64::try_from(milliseconds).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::Mutex as StdMutex;

    use bytes::Bytes;
    use nodavo_local_ipc::{AccessibilityReadiness, InputReadiness, LocalTopologyReadiness};
    use nodavo_transfer::{
        ContentHash, EntryKind, ManifestEntry, RelativePath, ResumableStagingArea, StagingArea,
        TransferChunk, TransferManifest,
    };

    use super::*;
    use crate::storage::{StorageError, create_identity};

    struct MemoryStorage {
        peers: StdMutex<Vec<PeerRecord>>,
        fail_store: AtomicBool,
    }

    impl DevelopmentStorage for MemoryStorage {
        fn load_or_create_identity(&self) -> Result<DeviceMaterial, StorageError> {
            create_identity().map(|(material, _)| material)
        }

        fn load_peers(&self) -> Result<Vec<PeerRecord>, StorageError> {
            Ok(self.peers.lock().unwrap().clone())
        }

        fn store_peers(&self, peers: &[PeerRecord]) -> Result<(), StorageError> {
            if self.fail_store.load(Ordering::Acquire) {
                return Err(StorageError::InvalidData);
            }
            *self.peers.lock().unwrap() = peers.to_vec();
            Ok(())
        }
    }

    fn readiness_runtime() -> Arc<AgentRuntime> {
        let storage = Arc::new(MemoryStorage {
            peers: StdMutex::new(Vec::new()),
            fail_store: AtomicBool::new(false),
        });
        AgentRuntime::new(
            storage,
            create_identity().unwrap().0,
            Vec::new(),
            "127.0.0.1:0".parse().unwrap(),
            "Readiness test".to_owned(),
        )
    }

    async fn publish_synchronizing_test_session(runtime: &AgentRuntime) {
        {
            let mut status = runtime.status.write().await;
            status.phase = AgentPhase::Connected;
            status.connected_peer = Some("test-peer".to_owned());
            status.readiness.session_topology = SessionTopologyReadiness::Synchronizing;
        }
        runtime.record_readiness_transition();
    }

    #[tokio::test]
    async fn readiness_cache_hit_returns_latest_concurrent_session_state() {
        let runtime = readiness_runtime();
        {
            let mut status = runtime.status.write().await;
            status.readiness.accessibility = AccessibilityReadiness::Granted;
            status.readiness.input = InputReadiness::Ready;
            status.readiness.local_topology = LocalTopologyReadiness::Available;
        }
        *runtime.readiness_cache_completed_at.lock().await = Some(Instant::now());

        let (eligibility_checked, checked) = oneshot::channel();
        let (resume, resumed) = oneshot::channel();
        let probe_called = Arc::new(AtomicBool::new(false));
        let called = Arc::clone(&probe_called);
        let task_runtime = Arc::clone(&runtime);
        let refresh = tokio::spawn(async move {
            task_runtime
                .refresh_platform_readiness_with(
                    async move {
                        called.store(true, Ordering::Release);
                        LocalPlatformReadiness::default()
                    },
                    async move {
                        let _ = eligibility_checked.send(());
                        let _ = resumed.await;
                    },
                )
                .await
        });

        checked.await.unwrap();
        publish_synchronizing_test_session(&runtime).await;
        resume.send(()).unwrap();
        let refreshed = refresh.await.unwrap();

        assert!(!probe_called.load(Ordering::Acquire));
        assert_eq!(refreshed.phase, AgentPhase::Connected);
        assert_eq!(refreshed.connected_peer.as_deref(), Some("test-peer"));
        assert_eq!(
            refreshed.readiness.session_topology,
            SessionTopologyReadiness::Synchronizing
        );
    }

    #[tokio::test]
    async fn concurrent_readiness_follower_waits_for_completed_probe() {
        let runtime = readiness_runtime();
        runtime.status.write().await.readiness.accessibility = AccessibilityReadiness::Granted;

        let (probe_started, started) = oneshot::channel();
        let (resume, resumed) = oneshot::channel();
        let leader_runtime = Arc::clone(&runtime);
        let leader = tokio::spawn(async move {
            leader_runtime
                .refresh_platform_readiness_with(
                    async move {
                        let _ = probe_started.send(());
                        let _ = resumed.await;
                        LocalPlatformReadiness::default()
                    },
                    std::future::ready(()),
                )
                .await
        });
        started.await.unwrap();

        let follower_probe_called = Arc::new(AtomicBool::new(false));
        let called = Arc::clone(&follower_probe_called);
        let (follower_started, follower_entered) = oneshot::channel();
        let follower_runtime = Arc::clone(&runtime);
        let mut follower = tokio::spawn(async move {
            let _ = follower_started.send(());
            follower_runtime
                .refresh_platform_readiness_with(
                    async move {
                        called.store(true, Ordering::Release);
                        LocalPlatformReadiness::default()
                    },
                    std::future::ready(()),
                )
                .await
        });
        follower_entered.await.unwrap();
        assert!(
            timeout(Duration::from_millis(50), &mut follower)
                .await
                .is_err(),
            "follower returned stale readiness while the leader was in flight"
        );

        resume.send(()).unwrap();
        let leader_status = leader.await.unwrap();
        let follower_status = follower.await.unwrap();
        assert_eq!(
            leader_status.readiness.accessibility,
            AccessibilityReadiness::Unavailable
        );
        assert_eq!(follower_status, leader_status);
        assert!(!follower_probe_called.load(Ordering::Acquire));
        assert!(runtime.readiness_cache_completed_at.lock().await.is_some());
    }

    #[tokio::test]
    async fn invalidated_readiness_probe_neither_publishes_nor_populates_cache() {
        let runtime = readiness_runtime();
        {
            let mut status = runtime.status.write().await;
            status.readiness.accessibility = AccessibilityReadiness::Granted;
            status.readiness.input = InputReadiness::Ready;
            status.readiness.local_topology = LocalTopologyReadiness::Available;
        }

        let (probe_started, started) = oneshot::channel();
        let (resume, resumed) = oneshot::channel();
        let task_runtime = Arc::clone(&runtime);
        let refresh = tokio::spawn(async move {
            task_runtime
                .refresh_platform_readiness_with(
                    async move {
                        let _ = probe_started.send(());
                        let _ = resumed.await;
                        LocalPlatformReadiness::default()
                    },
                    std::future::ready(()),
                )
                .await
        });

        started.await.unwrap();
        publish_synchronizing_test_session(&runtime).await;
        resume.send(()).unwrap();
        let refreshed = refresh.await.unwrap();

        assert_eq!(refreshed.phase, AgentPhase::Connected);
        assert_eq!(
            refreshed.readiness.session_topology,
            SessionTopologyReadiness::Synchronizing
        );
        assert_eq!(
            refreshed.readiness.accessibility,
            AccessibilityReadiness::Granted
        );
        assert_eq!(refreshed.readiness.input, InputReadiness::Ready);
        assert_eq!(
            refreshed.readiness.local_topology,
            LocalTopologyReadiness::Available
        );
        assert!(runtime.readiness_cache_completed_at.lock().await.is_none());

        {
            let mut status = runtime.status.write().await;
            status.phase = AgentPhase::Ready;
            status.connected_peer = None;
            status.readiness.session_topology = SessionTopologyReadiness::NotConnected;
        }
        let retry_called = Arc::new(AtomicBool::new(false));
        let called = Arc::clone(&retry_called);
        let retried = runtime
            .refresh_platform_readiness_with(
                async move {
                    called.store(true, Ordering::Release);
                    LocalPlatformReadiness::default()
                },
                std::future::ready(()),
            )
            .await;
        assert!(retry_called.load(Ordering::Acquire));
        assert_eq!(
            retried.readiness.accessibility,
            AccessibilityReadiness::Unavailable
        );
        assert!(runtime.readiness_cache_completed_at.lock().await.is_some());
    }

    #[tokio::test]
    async fn overall_safety_deadline_latches_stopping_before_ready() {
        let runtime = readiness_runtime();
        {
            let mut status = runtime.status.write().await;
            status.phase = AgentPhase::Connected;
            status.connected_peer = Some("test-peer".to_owned());
            status.readiness.session_topology = SessionTopologyReadiness::Ready;
        }
        let (commands, _unserviced_commands) = command_channel();
        *runtime.session_commands.lock().await = Some(commands);
        let disconnect_observer = runtime.disconnect.subscribe();
        let disconnect_before = *disconnect_observer.borrow();

        assert!(matches!(
            runtime
                .handle_safety_stop_with_deadline(SessionStop::Emergency, Duration::ZERO)
                .await,
            Err(AgentError::SafetyRecoveryFailed)
        ));

        assert!(runtime.session_safety.failure_latched());
        assert_ne!(*disconnect_observer.borrow(), disconnect_before);
        let status = runtime.status().await;
        assert_eq!(status.phase, AgentPhase::Stopping);
        assert_eq!(status.connected_peer, None);
        assert_eq!(status.input_owner, InputOwner::Local);
        assert_eq!(status.focus_state, FocusState::Local);
        assert_eq!(
            status.readiness.session_topology,
            SessionTopologyReadiness::NotConnected
        );
        runtime.publish_session_finished_status(false).await;
        assert_eq!(runtime.status().await.phase, AgentPhase::Stopping);
        assert!(matches!(
            runtime.reconnect("reconnect:ignored").await,
            Err(AgentError::SafetyRecoveryFailed)
        ));
    }

    #[tokio::test]
    async fn safety_operation_owns_ready_after_session_finalizer_and_cleanup() {
        let runtime = readiness_runtime();
        {
            let mut status = runtime.status.write().await;
            status.phase = AgentPhase::Connected;
            status.connected_peer = Some("test-peer".to_owned());
            runtime.session_safety.set_operation_active(true);
        }

        runtime.publish_session_finished_status(false).await;
        assert_eq!(runtime.status().await.phase, AgentPhase::Stopping);
        assert!(runtime.session_safety.operation_active());

        let completed = runtime.finish_safety_stop_success().await.unwrap();
        assert_eq!(completed.phase, AgentPhase::Ready);
        assert_eq!(completed.connected_peer, None);
        assert!(!runtime.session_safety.operation_active());
    }

    #[tokio::test]
    async fn safety_waits_for_preexisting_handshake_generation_before_ready() {
        let runtime = readiness_runtime();
        runtime.busy.store(true, Ordering::Release);
        let task_runtime = Arc::clone(&runtime);
        let safety = tokio::spawn(async move {
            task_runtime
                .handle_safety_stop_with_deadline(SessionStop::Emergency, Duration::from_secs(1))
                .await
        });

        while !runtime.session_safety.operation_active() {
            tokio::task::yield_now().await;
        }
        assert_eq!(runtime.status().await.phase, AgentPhase::Stopping);
        assert!(!safety.is_finished());
        assert!(matches!(
            runtime
                .publish_connected_if_safety_allows("stale-peer".to_owned())
                .await,
            Err(AgentError::Busy)
        ));

        runtime.busy.store(false, Ordering::Release);
        let status = safety.await.unwrap().unwrap();
        assert_eq!(status.phase, AgentPhase::Ready);
        assert!(!runtime.session_safety.operation_active());
        assert!(!runtime.session_safety.failure_latched());
    }

    #[tokio::test]
    async fn capability_change_persists_epoch_atomically_and_listing_stays_public() {
        let generated =
            rcgen::generate_simple_self_signed(vec!["peer.nodavo.invalid".to_owned()]).unwrap();
        let peer = PeerRecord {
            public_key: [4; 32],
            certificate_der: generated.cert.der().to_vec(),
            grants: CapabilityGrants::NONE,
            grant_epoch: GrantEpoch::new(1),
            display_name: "Office PC".to_owned(),
            established_at_unix_ms: 1,
            revoked_at_unix_ms: None,
            server_name: "peer.nodavo.invalid".to_owned(),
            last_endpoint: Some("127.0.0.1:44310".parse().unwrap()),
        };
        let peer_id = device_id_text(peer.device_id());
        let storage = Arc::new(MemoryStorage {
            peers: StdMutex::new(vec![peer.clone()]),
            fail_store: AtomicBool::new(false),
        });
        let material = create_identity().unwrap().0;
        let runtime = AgentRuntime::new(
            Arc::clone(&storage) as Arc<dyn DevelopmentStorage>,
            material,
            vec![peer],
            "127.0.0.1:0".parse().unwrap(),
            "Test device".to_owned(),
        );

        runtime
            .set_capability(&peer_id, TrustedCapability::RemoteInput, true)
            .await
            .unwrap();
        let stored = storage.peers.lock().unwrap().clone();
        assert_eq!(stored[0].grant_epoch, GrantEpoch::new(2));
        assert!(stored[0].grants.contains(TrustedCapability::RemoteInput));
        assert_eq!(
            runtime.trusted_peers().await,
            vec![TrustedPeerSummary {
                peer_id: peer_id.clone(),
                display_name: "Office PC".to_owned(),
                state: TrustedPeerState::Active,
                local_grants: vec![CapabilityName::Input],
            }]
        );

        storage.fail_store.store(true, Ordering::Release);
        assert!(matches!(
            runtime
                .set_capability(&peer_id, TrustedCapability::ClipboardRead, true)
                .await,
            Err(AgentError::Storage)
        ));
        let listed = runtime.trusted_peers().await;
        assert_eq!(listed[0].local_grants, vec![CapabilityName::Input]);
        assert_eq!(
            storage.peers.lock().unwrap()[0].grant_epoch,
            GrantEpoch::new(2)
        );
    }

    #[tokio::test]
    async fn offline_file_grant_revoke_discards_only_authenticated_peer_staging() {
        let generated =
            rcgen::generate_simple_self_signed(vec!["peer.nodavo.invalid".to_owned()]).unwrap();
        let peer = PeerRecord {
            public_key: [5; 32],
            certificate_der: generated.cert.der().to_vec(),
            grants: CapabilityGrants::NONE.with(TrustedCapability::FileTransfer),
            grant_epoch: GrantEpoch::new(1),
            display_name: "Offline peer".to_owned(),
            established_at_unix_ms: 1,
            revoked_at_unix_ms: None,
            server_name: "peer.nodavo.invalid".to_owned(),
            last_endpoint: Some("127.0.0.1:44310".parse().unwrap()),
        };
        let peer_id = device_id_text(peer.device_id());
        let protocol_peer = protocol_device_id(peer.device_id());
        let storage = Arc::new(MemoryStorage {
            peers: StdMutex::new(vec![peer.clone()]),
            fail_store: AtomicBool::new(false),
        });
        let runtime = AgentRuntime::new(
            Arc::clone(&storage) as Arc<dyn DevelopmentStorage>,
            create_identity().unwrap().0,
            vec![peer],
            "127.0.0.1:0".parse().unwrap(),
            "Test device".to_owned(),
        );
        let root = std::env::temp_dir().join(format!(
            "nodavo-runtime-offline-revoke-{}",
            TransferId::new().as_uuid()
        ));
        fs::create_dir(&root).unwrap();
        runtime
            .transfer_store
            .register_staging_root(protocol_peer, root.clone())
            .unwrap();
        let transfer = TransferId::new();
        let payload = b"offline partial";
        let manifest = TransferManifest::new(vec![ManifestEntry {
            path: RelativePath::parse("partial.bin").unwrap(),
            kind: EntryKind::File,
            size: payload.len() as u64,
            hash: Some(ContentHash::digest(payload)),
        }])
        .unwrap();
        {
            let mut staging =
                FileSystemStagingArea::new_scoped(&root, *protocol_peer.as_bytes()).unwrap();
            staging.begin(transfer, &manifest).await.unwrap();
            staging
                .write(TransferChunk {
                    transfer,
                    entry_index: 0,
                    offset: 0,
                    bytes: Bytes::copy_from_slice(&payload[..7]),
                })
                .await
                .unwrap();
        }
        runtime
            .transfer_store
            .remember_inbound(protocol_peer, transfer)
            .unwrap();

        runtime
            .set_capability(&peer_id, TrustedCapability::FileTransfer, false)
            .await
            .unwrap();
        let staging = FileSystemStagingArea::new(&root).unwrap();
        assert!(!staging.has_persisted(transfer).unwrap());
        assert!(
            !storage.peers.lock().unwrap()[0]
                .grants
                .contains(TrustedCapability::FileTransfer)
        );
        assert!(!runtime.transfer_store.is_poisoned());
        fs::remove_dir_all(root).unwrap();
    }
}
