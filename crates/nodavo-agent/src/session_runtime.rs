//! Symmetric authenticated peer-session orchestration over one transport connection.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use nodavo_clipboard::PeerClipboardGrants;
use nodavo_identity::{Capability as TrustedCapability, CapabilityGrants};
use nodavo_input::{InputEvent, NormalizedPosition};
#[cfg(test)]
use nodavo_local_ipc::ReadinessSnapshot;
use nodavo_local_ipc::{
    AgentStatus, FocusState as AgentFocusState, InputOwner, PeerPlacement, SessionTopologyReadiness,
};
use nodavo_protocol::{
    Capability, ClipboardMessage, ControlMessage, DeviceId, EventMeta, GrantEpoch, ProtocolVersion,
    Sequence, SessionId, WireMessage, decode_clipboard, decode_control, decode_datagram,
    decode_pointer_fallback, decode_reliable_input, encode_clipboard, encode_control,
    encode_datagram, encode_pointer_fallback, encode_reliable_input,
};
use nodavo_session::{
    DisconnectReason, Effect, Event, FocusState as CoreFocusState, LeaseId, LinkState,
    MonotonicMillis, SessionCore,
};
#[cfg(test)]
use nodavo_transfer::FileSystemStagingArea;
use nodavo_transfer::{ReceiveStagingArea, TransferError, TransferId};
use nodavo_transport::{
    ChannelDirection, ChannelId, ChannelKind, CloseReason, DatagramAvailability, PeerConnection,
    TransportCommand, TransportError, TransportEvent,
};
use thiserror::Error;
use tokio::sync::{RwLock, mpsc, oneshot, watch};
use tokio::time::{MissedTickBehavior, interval, sleep};

use crate::clipboard_port::ClipboardPort;
use crate::clipboard_runtime::{ClipboardRuntimeError, PeerClipboardRuntime};
use crate::input_wire::{
    DecodedInput, decode_event, encode_event, encode_pointer_enter, encode_release_all,
};
use crate::native_bridge::{NativeInputReceiver, PlatformSafetyEvent, PlatformSafetyReceiver};
use crate::platform_port::{PlatformPort, PlatformPortError};
use crate::topology_runtime::{LocalPointerAction, LocalTopologyCandidate, PeerTopologyState};
use crate::transfer_runtime::{PeerTransferConfig, PeerTransferRuntime, TransferRuntimeError};
use crate::transfer_worker::{
    TransferStopMode, TransferStore, TransferWorker, TransferWorkerEvent,
};

const SESSION_COMMAND_CAPACITY: usize = 32;
const MIN_LEASE_TTL_MS: u32 = 1_000;
const MAX_LEASE_TTL_MS: u32 = 30_000;
const DEFAULT_LEASE_TTL_MS: u32 = 5_000;
const TIMER_INTERVAL: Duration = Duration::from_millis(100);
const INITIAL_TOPOLOGY_TIMEOUT: Duration = Duration::from_secs(5);
const TOPOLOGY_REFRESH_PHASE_TIMEOUT_MS: u64 = 5_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SessionRole {
    Opener,
    Acceptor,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PeerGrantState {
    capabilities: Capability,
    epoch: GrantEpoch,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct SessionConfig {
    pub(crate) role: SessionRole,
    pub(crate) local_device: DeviceId,
    pub(crate) peer_device: DeviceId,
    pub(crate) local_grants_to_peer: CapabilityGrants,
    pub(crate) local_grant_epoch: GrantEpoch,
    pub(crate) peer_grants_to_local: Option<CapabilityGrants>,
    pub(crate) peer_grant_epoch: Option<GrantEpoch>,
    pub(crate) peer_placement: PeerPlacement,
    pub(crate) existing_control: Option<ChannelId>,
}

#[derive(Clone, Copy, Debug, Error)]
pub(crate) enum SessionRuntimeError {
    #[error("the requested focus transition is not authorized or valid")]
    FocusRejected,
    #[error("the authenticated peer sent an invalid session message")]
    ProtocolViolation,
    #[error("peer transport failed")]
    Transport,
    #[error("native platform input integration failed")]
    Platform,
    #[error("local input release or ownership restore failed")]
    SafetyRecoveryFailed,
    #[error("native display geometry changed before input injection")]
    TopologyRefreshRequired,
}

impl From<TransportError> for SessionRuntimeError {
    fn from(_: TransportError) -> Self {
        Self::Transport
    }
}

impl From<PlatformPortError> for SessionRuntimeError {
    fn from(_: PlatformPortError) -> Self {
        Self::Platform
    }
}

impl From<ClipboardRuntimeError> for SessionRuntimeError {
    fn from(error: ClipboardRuntimeError) -> Self {
        match error {
            ClipboardRuntimeError::Protocol | ClipboardRuntimeError::GrantDenied => {
                Self::ProtocolViolation
            }
            ClipboardRuntimeError::Platform => Self::Platform,
        }
    }
}

impl From<TransferRuntimeError> for SessionRuntimeError {
    fn from(error: TransferRuntimeError) -> Self {
        match error {
            TransferRuntimeError::Transfer(
                TransferError::Platform
                | TransferError::DestinationExists
                | TransferError::IntegrityMismatch,
            )
            | TransferRuntimeError::ResumeDurabilityUnsupported => Self::Platform,
            TransferRuntimeError::Protocol
            | TransferRuntimeError::Authentication
            | TransferRuntimeError::GrantDenied
            | TransferRuntimeError::Replay
            | TransferRuntimeError::Backpressure
            | TransferRuntimeError::SequenceExhausted
            | TransferRuntimeError::Transfer(_) => Self::ProtocolViolation,
        }
    }
}

pub(crate) enum LocalSessionCommand {
    RequestFocus {
        ttl_ms: u32,
        acknowledgement: oneshot::Sender<Result<(), SessionRuntimeError>>,
    },
    ReleaseFocus {
        acknowledgement: oneshot::Sender<Result<(), SessionRuntimeError>>,
    },
    EmergencyStop {
        acknowledgement: oneshot::Sender<Result<(), SessionRuntimeError>>,
    },
    LocalLocked {
        acknowledgement: oneshot::Sender<Result<(), SessionRuntimeError>>,
    },
    LocalSleeping {
        acknowledgement: oneshot::Sender<Result<(), SessionRuntimeError>>,
    },
    UpdateLocalGrant {
        grants: CapabilityGrants,
        epoch: GrantEpoch,
        capability: Capability,
        enabled: bool,
        acknowledgement: oneshot::Sender<Result<(), SessionRuntimeError>>,
    },
    UpdatePeerPlacement {
        placement: PeerPlacement,
        acknowledgement: oneshot::Sender<Result<(), SessionRuntimeError>>,
    },
    SendFiles {
        paths: Vec<PathBuf>,
        acknowledgement: oneshot::Sender<Result<TransferId, TransferError>>,
    },
    WakeTransferCancellation,
}

const fn placement_update_recovery_event(focus: CoreFocusState) -> Option<Event> {
    match focus {
        CoreFocusState::Local => None,
        CoreFocusState::RequestingRemote { .. }
        | CoreFocusState::ControllingRemote { .. }
        | CoreFocusState::ControlledByRemote { .. } => Some(Event::ReconnectRequested),
    }
}

pub(crate) fn command_channel() -> (
    mpsc::Sender<LocalSessionCommand>,
    mpsc::Receiver<LocalSessionCommand>,
) {
    mpsc::channel(SESSION_COMMAND_CAPACITY)
}

pub(crate) struct NativeSessionEvents {
    pub(crate) input: NativeInputReceiver,
    pub(crate) safety: PlatformSafetyReceiver,
    pub(crate) clipboard: Box<dyn ClipboardPort>,
    pub(crate) transfer: ReceiveStagingArea,
    pub(crate) transfer_store: TransferStore,
    pub(crate) session_safety: Arc<SessionSafetyState>,
}

#[derive(Debug, Default)]
pub(crate) struct SessionSafetyState {
    failure_latched: AtomicBool,
    operation_active: AtomicBool,
}

impl SessionSafetyState {
    pub(crate) fn failure_latched(&self) -> bool {
        self.failure_latched.load(Ordering::Acquire)
    }

    pub(crate) fn operation_active(&self) -> bool {
        self.operation_active.load(Ordering::Acquire)
    }

    pub(crate) fn blocks_ready(&self) -> bool {
        self.failure_latched() || self.operation_active()
    }

    pub(crate) fn set_operation_active(&self, active: bool) {
        self.operation_active.store(active, Ordering::Release);
    }

    pub(crate) fn latch_failure(&self) {
        self.failure_latched.store(true, Ordering::Release);
        self.operation_active.store(true, Ordering::Release);
    }
}

struct Channels {
    control: ChannelId,
    reliable_input: ChannelId,
    pointer_fallback: Option<ChannelId>,
    clipboard: ChannelId,
    file_manifest: ChannelId,
    file_data: ChannelId,
    datagrams: DatagramAvailability,
}

#[derive(Debug, Default)]
struct LocalTopologyRefresh {
    pending: Option<LocalTopologyCandidate>,
    injection_retry: Option<PendingInjectionRetry>,
    snapshot_deadline: Option<MonotonicMillis>,
    ack_deadline: Option<MonotonicMillis>,
}

#[derive(Debug)]
struct PendingInjectionRetry {
    input: InputEvent,
    remaining_effects: Vec<Effect>,
}

enum RefreshOutcome {
    Completed(Result<Result<(), SessionRuntimeError>, tokio::time::error::Elapsed>),
    PlatformSafety(Option<PlatformSafetyEvent>),
    Disconnect,
}

impl LocalTopologyRefresh {
    fn coalesce(&mut self, candidate: Option<LocalTopologyCandidate>) {
        self.pending = candidate;
    }

    fn take_pending(&mut self) -> Option<LocalTopologyCandidate> {
        self.pending.take()
    }

    fn queue_injection_retry(
        &mut self,
        input: InputEvent,
        remaining_effects: Vec<Effect>,
    ) -> Result<(), SessionRuntimeError> {
        if !matches!(input, InputEvent::PointerMotion { .. }) || self.injection_retry.is_some() {
            return Err(SessionRuntimeError::Platform);
        }
        self.injection_retry = Some(PendingInjectionRetry {
            input,
            remaining_effects,
        });
        Ok(())
    }

    fn take_injection_retry(&mut self) -> Option<PendingInjectionRetry> {
        self.injection_retry.take()
    }

    fn begin_snapshot(&mut self, now: MonotonicMillis) {
        if self.snapshot_deadline.is_none() {
            self.snapshot_deadline = Some(now.saturating_add(TOPOLOGY_REFRESH_PHASE_TIMEOUT_MS));
        }
    }

    fn finish_snapshot(&mut self) {
        self.snapshot_deadline = None;
    }

    fn snapshot_pending(&self) -> bool {
        self.snapshot_deadline.is_some()
    }

    fn arm_ack_deadline(&mut self, now: MonotonicMillis) {
        self.ack_deadline = Some(now.saturating_add(TOPOLOGY_REFRESH_PHASE_TIMEOUT_MS));
    }

    fn acknowledge(&mut self) {
        self.ack_deadline = None;
    }

    fn timed_out(&self, now: MonotonicMillis) -> bool {
        self.snapshot_deadline
            .is_some_and(|deadline| now >= deadline)
            || self.ack_deadline.is_some_and(|deadline| now >= deadline)
    }
}

struct PeerSession<'a> {
    connection: Box<dyn PeerConnection>,
    config: SessionConfig,
    channels: Channels,
    core: SessionCore,
    platform: &'a mut dyn PlatformPort,
    status: &'a RwLock<AgentStatus>,
    session_safety: Arc<SessionSafetyState>,
    started: Instant,
    session_id: SessionId,
    control_sequence: u64,
    reliable_sequence: u64,
    replaceable_sequence: u64,
    renewal_pending: bool,
    routing_to_peer: bool,
    topology: PeerTopologyState,
    topology_refresh: LocalTopologyRefresh,
    topology_initialized: bool,
    clipboard: PeerClipboardRuntime,
    transfer: TransferWorker,
    local_grant_epoch: GrantEpoch,
    peer_grant_epoch: GrantEpoch,
    peer_capabilities: Capability,
}

#[allow(
    clippy::too_many_lines,
    reason = "one linear setup/teardown path keeps session safety ordering auditable"
)]
pub(crate) async fn run_peer_session(
    mut connection: Box<dyn PeerConnection>,
    config: SessionConfig,
    mut commands: mpsc::Receiver<LocalSessionCommand>,
    native_events: NativeSessionEvents,
    mut disconnect: watch::Receiver<u64>,
    status: &RwLock<AgentStatus>,
    platform: &mut dyn PlatformPort,
) -> Result<(), SessionRuntimeError> {
    let channels = establish_channels(connection.as_mut(), &config).await?;
    let (session_id, peer_grant) =
        negotiate_session(connection.as_mut(), &config, &channels).await?;
    let NativeSessionEvents {
        mut input,
        mut safety,
        clipboard: clipboard_port,
        transfer: staging,
        transfer_store,
        session_safety,
    } = native_events;
    let clipboard = PeerClipboardRuntime::new(
        config.local_device,
        config.peer_device,
        session_id,
        config.local_grant_epoch,
        peer_grant.epoch,
        clipboard_grants(config.local_grants_to_peer),
        peer_grant.capabilities,
        clipboard_port,
    );
    let transfer = start_transfer_worker(&config, session_id, peer_grant, staging, transfer_store)?;
    let mut core = SessionCore::default();
    let _ = core.handle(Event::ConnectStarted);
    let _ = core.handle(Event::TransportConnected);
    let _ = core.handle(Event::AuthenticationSucceeded);
    let effects = core.handle(Event::SessionEstablished {
        session_id,
        peer_id: config.peer_device,
        local_grant_epoch: config.local_grant_epoch,
        peer_grant_epoch: peer_grant.epoch,
        local_grant_allows_peer_input: allows_input(config.local_grants_to_peer),
        peer_grant_allows_local_input: peer_grant.capabilities.contains(Capability::REMOTE_INPUT),
    });
    if !effects.is_empty() {
        return Err(SessionRuntimeError::ProtocolViolation);
    }

    let mut session = PeerSession {
        connection,
        config,
        channels,
        core,
        platform,
        status,
        session_safety,
        started: Instant::now(),
        session_id,
        control_sequence: 0,
        reliable_sequence: 0,
        replaceable_sequence: 0,
        renewal_pending: false,
        routing_to_peer: false,
        topology: PeerTopologyState::from_environment(
            config.peer_placement,
            peer_grant.capabilities.contains(Capability::REMOTE_INPUT),
        )
        .map_err(|_| SessionRuntimeError::Platform)?,
        topology_refresh: LocalTopologyRefresh::default(),
        topology_initialized: false,
        clipboard,
        transfer,
        local_grant_epoch: config.local_grant_epoch,
        peer_grant_epoch: peer_grant.epoch,
        peer_capabilities: peer_grant.capabilities,
    };
    if session.platform.start_capture().is_err() {
        if session
            .force_recovery(Event::LocalEmergencyStop)
            .await
            .is_err()
        {
            return Err(SessionRuntimeError::SafetyRecoveryFailed);
        }
        return Err(SessionRuntimeError::Platform);
    }
    if session
        .initialize_topology(&mut safety, &mut disconnect)
        .await
        .is_err()
    {
        if session.core.link_state() != LinkState::Down
            && session
                .force_recovery(Event::LocalEmergencyStop)
                .await
                .is_err()
        {
            return Err(SessionRuntimeError::SafetyRecoveryFailed);
        }
        return Err(SessionRuntimeError::Platform);
    }
    session.topology_initialized = true;
    session
        .preflight_local_topology_refresh(Some(&mut input), None, &mut safety, &mut disconnect)
        .await?;
    if !session.core.local_topology_refresh_pending() {
        session
            .set_session_topology_readiness(SessionTopologyReadiness::Ready)
            .await?;
    }
    session.update_status().await;
    let result = session
        .event_loop(&mut commands, &mut input, &mut safety, &mut disconnect)
        .await;
    if result.is_err()
        && session.core.link_state() != LinkState::Down
        && session
            .force_recovery(Event::LocalEmergencyStop)
            .await
            .is_err()
    {
        return Err(SessionRuntimeError::SafetyRecoveryFailed);
    }
    result
}

fn start_transfer_worker(
    config: &SessionConfig,
    session_id: SessionId,
    peer_grant: PeerGrantState,
    staging: ReceiveStagingArea,
    transfer_store: TransferStore,
) -> Result<TransferWorker, SessionRuntimeError> {
    TransferWorker::start(
        config.peer_device,
        new_transfer_runtime(config, session_id, peer_grant, staging),
        transfer_store,
    )
    .map_err(|_| SessionRuntimeError::SafetyRecoveryFailed)
}

fn new_transfer_runtime(
    config: &SessionConfig,
    session_id: SessionId,
    peer_grant: PeerGrantState,
    staging: ReceiveStagingArea,
) -> PeerTransferRuntime<ReceiveStagingArea> {
    PeerTransferRuntime::new(
        PeerTransferConfig {
            local_device: config.local_device,
            peer_device: config.peer_device,
            session_id,
            local_grant_epoch: config.local_grant_epoch,
            peer_grant_epoch: peer_grant.epoch,
            local_allows_peer_transfer: config
                .local_grants_to_peer
                .contains(TrustedCapability::FileTransfer),
            peer_capabilities: peer_grant.capabilities,
        },
        staging,
    )
}

impl PeerSession<'_> {
    #[allow(
        clippy::too_many_lines,
        reason = "one biased select keeps safety, refresh, and dispatch priority auditable"
    )]
    async fn event_loop(
        &mut self,
        commands: &mut mpsc::Receiver<LocalSessionCommand>,
        native_input: &mut NativeInputReceiver,
        platform_safety: &mut PlatformSafetyReceiver,
        disconnect: &mut watch::Receiver<u64>,
    ) -> Result<(), SessionRuntimeError> {
        let mut timer = interval(TIMER_INTERVAL);
        timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            if let Some(event) = platform_safety.pending() {
                self.handle_local_command(
                    platform_safety_command(event),
                    native_input,
                    platform_safety,
                    disconnect,
                )
                .await?;
                return Ok(());
            }
            if self.topology_refresh.timed_out(self.now()) {
                self.force_recovery(Event::LocalEmergencyStop).await?;
                return Ok(());
            }
            tokio::select! {
                biased;
                changed = disconnect.changed() => {
                    if changed.is_ok() {
                        self.force_recovery(Event::LocalEmergencyStop).await?;
                    }
                    return Ok(());
                }
                event = platform_safety.changed() => {
                    let Some(event) = event else {
                        continue;
                    };
                    if self.handle_local_command(
                        platform_safety_command(event),
                        native_input,
                        platform_safety,
                        disconnect,
                    ).await? {
                        return Ok(());
                    }
                }
                Some(command) = commands.recv() => {
                    let priority = matches!(
                        &command,
                        LocalSessionCommand::EmergencyStop { .. }
                            | LocalSessionCommand::LocalLocked { .. }
                            | LocalSessionCommand::LocalSleeping { .. }
                            | LocalSessionCommand::UpdateLocalGrant { .. }
                            | LocalSessionCommand::UpdatePeerPlacement { .. }
                    );
                    if !priority {
                        self.preflight_local_topology_refresh(
                            Some(native_input),
                            None,
                            platform_safety,
                            disconnect,
                        ).await?;
                    }
                    if self.handle_local_command(
                        command,
                        native_input,
                        platform_safety,
                        disconnect,
                    ).await? {
                        return Ok(());
                    }
                }
                event = self.transfer.next_event() => {
                    let Some(event) = event else {
                        self.force_recovery(Event::LocalEmergencyStop).await?;
                        return Err(SessionRuntimeError::Platform);
                    };
                    self.preflight_local_topology_refresh(
                        Some(native_input),
                        None,
                        platform_safety,
                        disconnect,
                    ).await?;
                    if let Err(error) = self.handle_transfer_worker_event(event).await {
                        if transfer_send_failure_is_link_loss(error) {
                            self.force_recovery(Event::LinkDisconnected).await?;
                        }
                        return Err(error);
                    }
                }
                event = self.connection.next_event() => {
                    let event = match event {
                        Ok(event) => event,
                        Err(TransportError::TimedOut) => continue,
                        Err(_) => {
                            self.force_recovery(Event::LinkDisconnected).await?;
                            return Err(SessionRuntimeError::Transport);
                        }
                    };
                    if self.handle_transport_event(
                        event,
                        Some(native_input),
                        platform_safety,
                        disconnect,
                    ).await? {
                        return Ok(());
                    }
                }
                input = native_input.recv() => {
                    let Ok(input) = input else {
                        self.force_recovery(Event::LocalEmergencyStop).await?;
                        return Err(SessionRuntimeError::Platform);
                    };
                    self.handle_native_input(
                        input,
                        native_input,
                        platform_safety,
                        disconnect,
                    ).await?;
                }
                _ = timer.tick() => {
                    if self.handle_timer(native_input, platform_safety, disconnect).await? {
                        return Ok(());
                    }
                }
            }
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one exhaustive command match keeps acknowledgement and safety ordering auditable"
    )]
    async fn handle_local_command(
        &mut self,
        command: LocalSessionCommand,
        native_input: &mut NativeInputReceiver,
        platform_safety: &mut PlatformSafetyReceiver,
        disconnect: &mut watch::Receiver<u64>,
    ) -> Result<bool, SessionRuntimeError> {
        match command {
            LocalSessionCommand::RequestFocus {
                ttl_ms,
                acknowledgement,
            } => {
                let result = match self
                    .preflight_local_topology_refresh(
                        Some(native_input),
                        None,
                        platform_safety,
                        disconnect,
                    )
                    .await
                {
                    Err(error) => Err(error),
                    Ok(_) if self.topology.prepare_manual_focus().is_err() => {
                        Err(SessionRuntimeError::FocusRejected)
                    }
                    Ok(_) => {
                        let pointer_enter_required = self.topology.pointer_enter_required();
                        self.request_focus(ttl_ms, pointer_enter_required).await
                    }
                };
                let failed = result.is_err();
                let _ = acknowledgement.send(result);
                if failed {
                    return Ok(false);
                }
            }
            LocalSessionCommand::ReleaseFocus { acknowledgement } => {
                let effects = self.core.handle(Event::LocalFocusReleased);
                let result = self.apply_local_effects(effects).await;
                let _ = acknowledgement.send(result);
            }
            LocalSessionCommand::EmergencyStop { acknowledgement } => {
                let result = self.force_recovery(Event::LocalEmergencyStop).await;
                let failed = result.is_err();
                let _ = acknowledgement.send(result);
                return if failed {
                    Err(SessionRuntimeError::SafetyRecoveryFailed)
                } else {
                    Ok(true)
                };
            }
            LocalSessionCommand::LocalLocked { acknowledgement } => {
                let result = self.force_recovery(Event::LocalLocked).await;
                let failed = result.is_err();
                let _ = acknowledgement.send(result);
                return if failed {
                    Err(SessionRuntimeError::SafetyRecoveryFailed)
                } else {
                    Ok(true)
                };
            }
            LocalSessionCommand::LocalSleeping { acknowledgement } => {
                let result = self.force_recovery(Event::LocalSleeping).await;
                let failed = result.is_err();
                let _ = acknowledgement.send(result);
                return if failed {
                    Err(SessionRuntimeError::SafetyRecoveryFailed)
                } else {
                    Ok(true)
                };
            }
            LocalSessionCommand::UpdateLocalGrant {
                grants,
                epoch,
                capability,
                enabled,
                acknowledgement,
            } => {
                let result = self
                    .handle_local_grant_update(grants, epoch, capability, enabled)
                    .await;
                let failed = result.is_err();
                let _ = acknowledgement.send(result);
                if failed {
                    return Ok(false);
                }
                self.update_status().await;
                return Ok(true);
            }
            LocalSessionCommand::UpdatePeerPlacement {
                placement,
                acknowledgement,
            } => {
                let recovery = placement_update_recovery_event(self.core.focus_state());
                let result = if let Some(event) = recovery {
                    match self.force_recovery(event).await {
                        Ok(()) => Err(SessionRuntimeError::FocusRejected),
                        Err(error) => Err(error),
                    }
                } else {
                    self.topology
                        .set_peer_placement(placement)
                        .map_err(|_| SessionRuntimeError::Platform)
                };
                if result.is_ok() {
                    self.config.peer_placement = placement;
                }
                let failed = result.is_err();
                let safety_failed =
                    matches!(result, Err(SessionRuntimeError::SafetyRecoveryFailed));
                let link_down = self.core.link_state() == LinkState::Down;
                let _ = acknowledgement.send(result);
                if link_down {
                    return if safety_failed {
                        Err(SessionRuntimeError::SafetyRecoveryFailed)
                    } else {
                        Ok(true)
                    };
                }
                if failed {
                    return Ok(false);
                }
            }
            LocalSessionCommand::SendFiles {
                paths,
                acknowledgement,
            } => {
                if !self.peer_capabilities.contains(Capability::FILE_TRANSFER) || paths.is_empty() {
                    let _ = acknowledgement.send(Err(TransferError::Cancelled));
                } else {
                    self.transfer.try_start_outbound(paths, acknowledgement);
                }
            }
            LocalSessionCommand::WakeTransferCancellation => {
                self.transfer.try_wake_cancellation()?;
            }
        }
        self.update_status().await;
        Ok(false)
    }

    async fn handle_native_input(
        &mut self,
        input: InputEvent,
        native_input: &mut NativeInputReceiver,
        platform_safety: &mut PlatformSafetyReceiver,
        disconnect: &mut watch::Receiver<u64>,
    ) -> Result<(), SessionRuntimeError> {
        if !self
            .preflight_local_topology_refresh(
                Some(native_input),
                Some(input),
                platform_safety,
                disconnect,
            )
            .await?
        {
            self.handle_local_input(input).await?;
        }
        self.update_status().await;
        Ok(())
    }

    async fn handle_timer(
        &mut self,
        native_input: &mut NativeInputReceiver,
        platform_safety: &mut PlatformSafetyReceiver,
        disconnect: &mut watch::Receiver<u64>,
    ) -> Result<bool, SessionRuntimeError> {
        if self.topology_refresh.timed_out(self.now()) {
            self.force_recovery(Event::LocalEmergencyStop).await?;
            return Ok(true);
        }
        self.preflight_local_topology_refresh(
            Some(native_input),
            None,
            platform_safety,
            disconnect,
        )
        .await?;
        if self.platform.ensure_healthy().is_err() {
            self.force_recovery(Event::LocalEmergencyStop).await?;
            return Err(SessionRuntimeError::Platform);
        }
        if self.topology_refresh.timed_out(self.now()) {
            self.force_recovery(Event::LocalEmergencyStop).await?;
            return Ok(true);
        }
        let clipboard_messages = self.clipboard.poll()?;
        self.send_clipboard_messages(clipboard_messages).await?;
        self.transfer.try_pump()?;
        let now = self.now();
        if let CoreFocusState::ControllingRemote {
            lease_id,
            expires_at,
        } = self.core.focus_state()
            && !self.renewal_pending
            && expires_at.get().saturating_sub(now.get()) <= u64::from(DEFAULT_LEASE_TTL_MS / 3)
        {
            let renewed_until = now.saturating_add(u64::from(DEFAULT_LEASE_TTL_MS));
            let effects = self.core.handle(Event::LocalLeaseRenewalRequested {
                lease_id,
                expires_at: renewed_until,
            });
            self.apply_remote_effects(effects).await?;
            self.renewal_pending = true;
        }
        let effects = self.core.handle(Event::TimerElapsed { now });
        let disconnect = effects_disconnect(&effects);
        self.apply_remote_effects(effects).await?;
        self.update_status().await;
        Ok(disconnect)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one exhaustive channel dispatch keeps preflight and close ordering explicit"
    )]
    async fn handle_transport_event(
        &mut self,
        event: TransportEvent,
        mut native_input: Option<&mut NativeInputReceiver>,
        platform_safety: &mut PlatformSafetyReceiver,
        disconnect: &mut watch::Receiver<u64>,
    ) -> Result<bool, SessionRuntimeError> {
        event
            .validate(self.channels.datagrams)
            .map_err(|_| SessionRuntimeError::ProtocolViolation)?;
        let control_dispatch = matches!(
            &event,
            TransportEvent::ReliableData { channel, .. } if *channel == self.channels.control
        );
        let terminal_dispatch = matches!(&event, TransportEvent::Closed(_))
            || matches!(
                &event,
                TransportEvent::ChannelClosed { channel }
                    if *channel == self.channels.control
                        || *channel == self.channels.reliable_input
                        || *channel == self.channels.clipboard
                        || *channel == self.channels.file_manifest
                        || *channel == self.channels.file_data
            );
        if !control_dispatch && !terminal_dispatch {
            self.preflight_local_topology_refresh(
                native_input.as_deref_mut(),
                None,
                platform_safety,
                disconnect,
            )
            .await?;
        }
        let outcome = match event {
            TransportEvent::ReliableData {
                channel, payload, ..
            } if channel == self.channels.control => {
                self.handle_control(&payload, native_input, platform_safety, disconnect)
                    .await?
            }
            TransportEvent::ReliableData {
                channel, payload, ..
            } if channel == self.channels.reliable_input => {
                let message = decode_reliable_input(&payload)
                    .map_err(|_| SessionRuntimeError::ProtocolViolation)?;
                self.handle_input(message, native_input, platform_safety, disconnect)
                    .await?;
                false
            }
            TransportEvent::ReliableData {
                channel, payload, ..
            } if Some(channel) == self.channels.pointer_fallback => {
                let message = decode_pointer_fallback(&payload)
                    .map_err(|_| SessionRuntimeError::ProtocolViolation)?;
                self.handle_input(message, native_input, platform_safety, disconnect)
                    .await?;
                false
            }
            TransportEvent::ReliableData {
                channel, payload, ..
            } if channel == self.channels.clipboard => {
                let message = decode_clipboard(&payload)
                    .map_err(|_| SessionRuntimeError::ProtocolViolation)?;
                let outbound = self.clipboard.receive(message)?;
                self.send_clipboard_messages(outbound).await?;
                false
            }
            TransportEvent::ReliableData {
                channel, payload, ..
            } if channel == self.channels.file_manifest => {
                self.transfer.try_receive_manifest(payload.to_vec())?;
                false
            }
            TransportEvent::ReliableData {
                channel, payload, ..
            } if channel == self.channels.file_data => {
                self.transfer.try_receive_data(payload.to_vec())?;
                false
            }
            TransportEvent::Datagram { payload } => {
                let message = decode_datagram(&payload)
                    .map_err(|_| SessionRuntimeError::ProtocolViolation)?;
                self.handle_input(message, native_input, platform_safety, disconnect)
                    .await?;
                false
            }
            TransportEvent::Closed(reason) => {
                let event = if reason == CloseReason::EmergencyDisconnect {
                    Event::LocalEmergencyStop
                } else {
                    Event::LinkDisconnected
                };
                self.force_recovery(event).await?;
                true
            }
            TransportEvent::ChannelClosed { channel }
                if channel == self.channels.control
                    || channel == self.channels.reliable_input
                    || channel == self.channels.clipboard
                    || channel == self.channels.file_manifest
                    || channel == self.channels.file_data =>
            {
                self.force_recovery(Event::LinkDisconnected).await?;
                true
            }
            _ => return Err(SessionRuntimeError::ProtocolViolation),
        };
        self.update_status().await;
        Ok(outcome)
    }

    #[allow(clippy::too_many_lines)]
    async fn handle_control(
        &mut self,
        payload: &[u8],
        native_input: Option<&mut NativeInputReceiver>,
        platform_safety: &mut PlatformSafetyReceiver,
        disconnect: &mut watch::Receiver<u64>,
    ) -> Result<bool, SessionRuntimeError> {
        let message =
            decode_control(payload).map_err(|_| SessionRuntimeError::ProtocolViolation)?;
        let WireMessage::Control(control) = message else {
            return Err(SessionRuntimeError::ProtocolViolation);
        };
        let priority = matches!(
            &control,
            ControlMessage::CapabilityGrant { .. }
                | ControlMessage::CapabilityRevoke { .. }
                | ControlMessage::SessionClose { .. }
                | ControlMessage::EmergencyDisconnect { .. }
        );
        if !priority {
            self.preflight_local_topology_refresh(native_input, None, platform_safety, disconnect)
                .await?;
        }
        let local_topology_ack = matches!(&control, ControlMessage::DisplayTopologyAck { .. });
        let (effects, disconnect) = match control {
            ControlMessage::CapabilityGrant {
                peer,
                capabilities,
                epoch,
            } => {
                self.handle_peer_grant_update(peer, capabilities, epoch, true)
                    .await?;
                (Vec::new(), true)
            }
            ControlMessage::CapabilityRevoke {
                peer,
                capabilities,
                epoch,
            } => {
                self.handle_peer_grant_update(peer, capabilities, epoch, false)
                    .await?;
                (Vec::new(), true)
            }
            ControlMessage::FocusLeaseRequest {
                meta,
                lease_id,
                ttl_ms,
                pointer_enter_required,
            } => {
                let expires_at = self.now().saturating_add(u64::from(ttl_ms));
                (
                    self.core.handle(Event::RemoteFocusRequested {
                        meta,
                        lease_id: LeaseId::new(lease_id),
                        expires_at,
                        pointer_enter_required,
                    }),
                    false,
                )
            }
            ControlMessage::FocusLeaseGrant {
                meta,
                lease_id,
                ttl_ms,
                pointer_enter_required,
            } => {
                let expires_at = self.now().saturating_add(u64::from(ttl_ms));
                let event = if matches!(
                    self.core.focus_state(),
                    CoreFocusState::RequestingRemote { .. }
                ) {
                    Event::RemoteFocusGranted {
                        meta,
                        lease_id: LeaseId::new(lease_id),
                        expires_at,
                        pointer_enter_required,
                    }
                } else {
                    self.renewal_pending = false;
                    Event::RemoteLeaseRenewed {
                        meta,
                        lease_id: LeaseId::new(lease_id),
                        expires_at,
                        pointer_enter_required,
                    }
                };
                let mut effects = self.core.handle(event);
                if !effects
                    .iter()
                    .any(|effect| matches!(effect, Effect::Rejected { .. }))
                    && matches!(
                        self.core.focus_state(),
                        CoreFocusState::ControllingRemote { .. }
                    )
                    && let Some(target) = self.topology.take_pending_target()
                {
                    let InputEvent::PointerMotion { position } = target else {
                        return Err(SessionRuntimeError::ProtocolViolation);
                    };
                    effects.extend(self.core.handle(Event::LocalPointerEnter { position }));
                }
                (effects, false)
            }
            ControlMessage::FocusLeaseRelease { meta, lease_id } => (
                self.core.handle(Event::RemoteFocusReleased {
                    meta,
                    lease_id: LeaseId::new(lease_id),
                }),
                false,
            ),
            ControlMessage::DisplayTopology { meta, topology } => {
                let revision = topology.revision();
                let effects = self
                    .core
                    .handle(Event::RemoteTopologyReceived { meta, revision });
                if effects.iter().any(|effect| {
                    matches!(
                        effect,
                        Effect::AcceptRemoteTopology {
                            revision: accepted
                        } if *accepted == revision
                    )
                }) {
                    self.topology
                        .stage_remote(topology, revision)
                        .map_err(|_| SessionRuntimeError::ProtocolViolation)?;
                }
                (effects, false)
            }
            ControlMessage::DisplayTopologyAck { meta, revision } => (
                self.core
                    .handle(Event::RemoteTopologyAcknowledged { meta, revision }),
                false,
            ),
            ControlMessage::PointerEnterAck { meta, lease_id } => (
                self.core.handle(Event::RemotePointerEnterAcknowledged {
                    meta,
                    lease_id: LeaseId::new(lease_id),
                }),
                false,
            ),
            ControlMessage::Ping { nonce } => {
                self.send_control(ControlMessage::Pong { nonce }).await?;
                (Vec::new(), false)
            }
            ControlMessage::Pong { .. } | ControlMessage::Error { .. } => (Vec::new(), false),
            ControlMessage::SessionClose { session_id, .. } if session_id == self.session_id => {
                (self.core.handle(Event::ReconnectRequested), true)
            }
            ControlMessage::EmergencyDisconnect { session_id } if session_id == self.session_id => {
                (self.core.handle(Event::LocalEmergencyStop), true)
            }
            _ => return Err(SessionRuntimeError::ProtocolViolation),
        };
        self.apply_remote_effects(effects).await?;
        if local_topology_ack && self.topology_initialized {
            self.drive_local_topology_refresh().await?;
        }
        Ok(disconnect)
    }

    async fn handle_input(
        &mut self,
        message: WireMessage,
        native_input: Option<&mut NativeInputReceiver>,
        platform_safety: &mut PlatformSafetyReceiver,
        disconnect: &mut watch::Receiver<u64>,
    ) -> Result<(), SessionRuntimeError> {
        let WireMessage::Input(input) = message else {
            return Err(SessionRuntimeError::ProtocolViolation);
        };
        let received_at = self.now();
        let effects = match decode_event(&input)
            .map_err(|_| SessionRuntimeError::ProtocolViolation)?
        {
            DecodedInput::Event(event) => self.core.handle(Event::RemoteInput {
                meta: *input.meta(),
                lease_id: LeaseId::new(input.lease_id()),
                received_at,
                input: event,
            }),
            DecodedInput::PointerEnter(position) => self.core.handle(Event::RemotePointerEnter {
                meta: *input.meta(),
                lease_id: LeaseId::new(input.lease_id()),
                received_at,
                position,
            }),
            DecodedInput::ReleaseAll => self.core.handle(Event::RemoteReleaseAll {
                meta: *input.meta(),
                lease_id: LeaseId::new(input.lease_id()),
                received_at,
            }),
        };
        if let Err(error) = self.apply_remote_effects(effects).await {
            if matches!(error, SessionRuntimeError::TopologyRefreshRequired) {
                self.preflight_required_local_topology_refresh(
                    native_input,
                    platform_safety,
                    disconnect,
                )
                .await?;
                return Ok(());
            }
            if self
                .force_recovery(Event::LocalEmergencyStop)
                .await
                .is_err()
            {
                return Err(SessionRuntimeError::SafetyRecoveryFailed);
            }
            return Err(error);
        }
        Ok(())
    }

    async fn apply_local_effects(
        &mut self,
        effects: Vec<Effect>,
    ) -> Result<(), SessionRuntimeError> {
        if effects
            .iter()
            .any(|effect| matches!(effect, Effect::Rejected { .. }))
        {
            return Err(SessionRuntimeError::FocusRejected);
        }
        self.apply_remote_effects(effects).await
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one exhaustive dispatcher keeps safety effect ordering explicit and auditable"
    )]
    async fn apply_remote_effects(
        &mut self,
        effects: Vec<Effect>,
    ) -> Result<(), SessionRuntimeError> {
        let route_to_peer = self.core.local_pointer_routing_ready();
        if route_to_peer != self.routing_to_peer {
            if self.platform.set_routing_to_peer(route_to_peer).is_err() {
                let _ = self.platform.restore_local_ownership();
                self.session_safety.latch_failure();
                self.routing_to_peer = false;
                return Err(SessionRuntimeError::Platform);
            }
            self.routing_to_peer = route_to_peer;
        }
        let mut deferred_platform_error = None;
        let mut effects = effects.into_iter();
        while let Some(effect) = effects.next() {
            match effect {
                Effect::RequestRemoteFocus {
                    lease_id,
                    expires_at,
                    pointer_enter_required,
                } => {
                    self.send_focus(
                        ControlMessageKind::Request,
                        lease_id,
                        expires_at,
                        pointer_enter_required,
                    )
                    .await?;
                }
                Effect::RenewRemoteFocus {
                    lease_id,
                    expires_at,
                } => {
                    self.send_focus(
                        ControlMessageKind::Request,
                        lease_id,
                        expires_at,
                        self.core.outbound_pointer_enter_required(),
                    )
                    .await?;
                }
                Effect::GrantRemoteFocus {
                    lease_id,
                    expires_at,
                    pointer_enter_required,
                } => {
                    self.send_focus(
                        ControlMessageKind::Grant,
                        lease_id,
                        expires_at,
                        pointer_enter_required,
                    )
                    .await?;
                }
                Effect::ReleaseRemoteFocus { lease_id } => {
                    let meta = self.next_meta(SequenceKind::Control);
                    self.send_control(ControlMessage::FocusLeaseRelease {
                        meta,
                        lease_id: lease_id.get(),
                    })
                    .await?;
                }
                Effect::SendInput { lease_id, input } => {
                    self.send_input(lease_id, input).await?;
                }
                Effect::SendPointerEnter { lease_id, position } => {
                    self.send_pointer_enter(lease_id, position).await?;
                }
                Effect::AcknowledgePointerEnter { lease_id } => {
                    let meta = self.next_meta(SequenceKind::Control);
                    self.send_control(ControlMessage::PointerEnterAck {
                        meta,
                        lease_id: lease_id.get(),
                    })
                    .await?;
                }
                Effect::SendReleaseAll { lease_id } => {
                    self.send_release_all(lease_id).await?;
                }
                Effect::InjectInput(input) => {
                    let native_input = self
                        .topology
                        .resolve_incoming(input)
                        .map_err(|_| SessionRuntimeError::ProtocolViolation)?;
                    match self.platform.inject(native_input) {
                        Ok(()) => {}
                        Err(PlatformPortError::DisplaySnapshotPending) => {
                            self.topology_refresh
                                .queue_injection_retry(input, effects.collect())?;
                            return Err(SessionRuntimeError::TopologyRefreshRequired);
                        }
                        Err(_) => {
                            self.session_safety.latch_failure();
                            return Err(SessionRuntimeError::Platform);
                        }
                    }
                }
                Effect::ReleaseInjectedInput { releases } => {
                    if self.platform.release_injected(&releases).is_err() {
                        self.session_safety.latch_failure();
                        deferred_platform_error = Some(SessionRuntimeError::Platform);
                    }
                }
                Effect::ReleaseRoutedInput { lease_id, releases } => {
                    for release in releases {
                        // Recovery releases are best effort. A lost link must not
                        // prevent local restore and the final close command.
                        let _ = self.send_input(lease_id, release).await;
                    }
                }
                Effect::RestoreLocalOwnership => {
                    if self.platform.restore_local_ownership().is_err() {
                        self.session_safety.latch_failure();
                        deferred_platform_error = Some(SessionRuntimeError::Platform);
                    }
                    self.routing_to_peer = false;
                    self.topology.clear_focus_route();
                }
                Effect::Disconnect { reason } => {
                    self.disconnect_transport(reason).await;
                }
                Effect::AcceptRemoteTopology { revision } => {
                    self.topology
                        .commit_remote(revision)
                        .map_err(|_| SessionRuntimeError::ProtocolViolation)?;
                }
                Effect::AcknowledgeRemoteTopology { revision } => {
                    let meta = self.next_meta(SequenceKind::Control);
                    self.send_control(ControlMessage::DisplayTopologyAck { meta, revision })
                        .await?;
                }
                Effect::LocalTopologyReady { revision } => {
                    self.topology
                        .mark_local_ready(revision)
                        .map_err(|_| SessionRuntimeError::ProtocolViolation)?;
                }
                Effect::ArmFocusLease { .. } | Effect::CancelFocusLease => {}
                Effect::SuspendContentOperations => {
                    self.clipboard.disconnect();
                    self.transfer.stop(TransferStopMode::Suspend);
                }
                Effect::AbortContentOperations => {
                    self.clipboard.disconnect();
                    self.transfer.stop(TransferStopMode::AbortAll);
                }
                Effect::Rejected { .. } => return Err(SessionRuntimeError::ProtocolViolation),
            }
        }
        deferred_platform_error.map_or(Ok(()), Err)
    }

    async fn send_focus(
        &mut self,
        kind: ControlMessageKind,
        lease_id: LeaseId,
        expires_at: MonotonicMillis,
        pointer_enter_required: bool,
    ) -> Result<(), SessionRuntimeError> {
        let ttl_ms = expires_at.get().saturating_sub(self.now().get());
        let ttl_ms = u32::try_from(ttl_ms)
            .unwrap_or(MAX_LEASE_TTL_MS)
            .clamp(1, MAX_LEASE_TTL_MS);
        let meta = self.next_meta(SequenceKind::Control);
        let message = match kind {
            ControlMessageKind::Request => ControlMessage::FocusLeaseRequest {
                meta,
                lease_id: lease_id.get(),
                ttl_ms,
                pointer_enter_required,
            },
            ControlMessageKind::Grant => ControlMessage::FocusLeaseGrant {
                meta,
                lease_id: lease_id.get(),
                ttl_ms,
                pointer_enter_required,
            },
        };
        self.send_control(message).await
    }

    async fn initialize_topology(
        &mut self,
        platform_safety: &mut PlatformSafetyReceiver,
        disconnect: &mut watch::Receiver<u64>,
    ) -> Result<(), SessionRuntimeError> {
        let acquisition = async {
            loop {
                match self.platform.display_snapshot() {
                    Ok(snapshots) => {
                        return self
                            .topology
                            .prepare_local_candidate(&snapshots)
                            .map_err(|_| SessionRuntimeError::Platform)?
                            .ok_or(SessionRuntimeError::Platform);
                    }
                    Err(PlatformPortError::DisplaySnapshotPending) => {}
                    Err(error) => return Err(error.into()),
                }
                tokio::select! {
                    biased;
                    changed = disconnect.changed() => {
                        if changed.is_ok() {
                            self.force_recovery(Event::LocalEmergencyStop).await?;
                        }
                        return Err(SessionRuntimeError::Platform);
                    }
                    event = platform_safety.changed() => {
                        let Some(event) = event else {
                            continue;
                        };
                        self.force_recovery(core_event_for_platform_safety(event)).await?;
                        return Err(SessionRuntimeError::Platform);
                    }
                    () = sleep(TIMER_INTERVAL) => {}
                }
            }
        };
        let candidate = tokio::time::timeout(INITIAL_TOPOLOGY_TIMEOUT, acquisition)
            .await
            .map_err(|_| SessionRuntimeError::Platform)??;
        let unpublished_local = if self.core.local_grant_allows_peer_input() {
            self.publish_local_candidate(candidate).await?;
            false
        } else {
            self.topology
                .commit_local_candidate(candidate)
                .map_err(|_| SessionRuntimeError::Platform)?;
            true
        };
        let effects = self.core.handle(Event::LocalTopologyRefreshStarted);
        self.apply_local_effects(effects).await?;
        if unpublished_local {
            self.topology
                .mark_unpublished_local_ready()
                .map_err(|_| SessionRuntimeError::Platform)?;
        }

        let needs_remote = self.core.peer_grant_allows_local_input();
        let needs_ack = self.core.local_grant_allows_peer_input();
        let exchange = async {
            loop {
                let remote_ready = !needs_remote || self.core.remote_topology_revision().is_some();
                let local_ready =
                    !needs_ack || self.core.acknowledged_topology_revision().is_some();
                if remote_ready && local_ready {
                    return Ok(());
                }
                tokio::select! {
                    biased;
                    changed = disconnect.changed() => {
                        if changed.is_ok() {
                            self.force_recovery(Event::LocalEmergencyStop).await?;
                        }
                        return Err(SessionRuntimeError::Platform);
                    }
                    event = platform_safety.changed() => {
                        let Some(event) = event else {
                            continue;
                        };
                        self.force_recovery(core_event_for_platform_safety(event)).await?;
                        return Err(SessionRuntimeError::Platform);
                    }
                    event = self.connection.next_event() => {
                        if self
                            .handle_transport_event(
                                event?,
                                None,
                                platform_safety,
                                disconnect,
                            )
                            .await?
                        {
                            return Err(SessionRuntimeError::Transport);
                        }
                    }
                }
            }
        };
        tokio::time::timeout(INITIAL_TOPOLOGY_TIMEOUT, exchange)
            .await
            .map_err(|_| SessionRuntimeError::Transport)??;
        let effects = self.core.handle(Event::LocalTopologyRefreshUnchanged);
        self.apply_local_effects(effects).await
    }

    async fn preflight_local_topology_refresh(
        &mut self,
        native_input: Option<&mut NativeInputReceiver>,
        admitted_input: Option<InputEvent>,
        platform_safety: &mut PlatformSafetyReceiver,
        disconnect: &mut watch::Receiver<u64>,
    ) -> Result<bool, SessionRuntimeError> {
        if !self.topology_initialized {
            return Ok(false);
        }
        if !self.platform.display_change_pending()? && !self.topology_refresh.snapshot_pending() {
            return Ok(false);
        }
        self.run_local_topology_refresh_with_priority(
            native_input,
            admitted_input,
            platform_safety,
            disconnect,
        )
        .await?;
        Ok(true)
    }

    async fn preflight_required_local_topology_refresh(
        &mut self,
        native_input: Option<&mut NativeInputReceiver>,
        platform_safety: &mut PlatformSafetyReceiver,
        disconnect: &mut watch::Receiver<u64>,
    ) -> Result<(), SessionRuntimeError> {
        self.run_local_topology_refresh_with_priority(
            native_input,
            None,
            platform_safety,
            disconnect,
        )
        .await
    }

    async fn run_local_topology_refresh_with_priority(
        &mut self,
        native_input: Option<&mut NativeInputReceiver>,
        admitted_input: Option<InputEvent>,
        platform_safety: &mut PlatformSafetyReceiver,
        disconnect: &mut watch::Receiver<u64>,
    ) -> Result<(), SessionRuntimeError> {
        if let Some(event) = platform_safety.pending() {
            self.force_recovery(core_event_for_platform_safety(event))
                .await?;
            return Err(SessionRuntimeError::Platform);
        }

        let outcome = {
            let refresh = tokio::time::timeout(
                Duration::from_millis(TOPOLOGY_REFRESH_PHASE_TIMEOUT_MS),
                self.observe_local_topology_change(native_input, admitted_input),
            );
            tokio::select! {
                biased;
                changed = disconnect.changed() => {
                    let _ = changed;
                    RefreshOutcome::Disconnect
                }
                event = platform_safety.changed() => RefreshOutcome::PlatformSafety(event),
                result = refresh => RefreshOutcome::Completed(result),
            }
        };

        match outcome {
            RefreshOutcome::Completed(Ok(result)) => result,
            RefreshOutcome::Completed(Err(_))
            | RefreshOutcome::Disconnect
            | RefreshOutcome::PlatformSafety(None) => {
                self.force_recovery(Event::LocalEmergencyStop).await?;
                Err(SessionRuntimeError::Platform)
            }
            RefreshOutcome::PlatformSafety(Some(event)) => {
                self.force_recovery(core_event_for_platform_safety(event))
                    .await?;
                Err(SessionRuntimeError::Platform)
            }
        }
    }

    async fn observe_local_topology_change(
        &mut self,
        native_input: Option<&mut NativeInputReceiver>,
        admitted_input: Option<InputEvent>,
    ) -> Result<(), SessionRuntimeError> {
        if !self.topology_refresh.snapshot_pending() {
            self.set_session_topology_readiness(SessionTopologyReadiness::Synchronizing)
                .await?;
            self.topology_refresh.begin_snapshot(self.now());
            self.platform.set_routing_to_peer(false)?;
            self.routing_to_peer = false;
            self.platform.pause_input_admission()?;
            self.topology
                .begin_local_transition()
                .map_err(|_| SessionRuntimeError::Platform)?;
            if let Some(native_input) = native_input {
                let mut admitted = admitted_input.into_iter().collect::<Vec<_>>();
                admitted.extend(
                    native_input
                        .drain_pending()
                        .map_err(|_| SessionRuntimeError::Platform)?,
                );
                if matches!(
                    self.core.focus_state(),
                    CoreFocusState::ControllingRemote { .. }
                ) {
                    for input in admitted {
                        self.handle_local_input(input).await?;
                    }
                }
            }
            let effects = self.core.handle(Event::LocalTopologyRefreshStarted);
            self.apply_local_effects(effects).await?;
        }
        let snapshots = match self.platform.display_snapshot() {
            Ok(snapshots) => snapshots,
            Err(PlatformPortError::DisplaySnapshotPending) => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        if self.topology_refresh.timed_out(self.now()) {
            return Err(SessionRuntimeError::Platform);
        }
        let candidate = self
            .topology
            .prepare_local_candidate(&snapshots)
            .map_err(|_| SessionRuntimeError::Platform)?;
        let changed = candidate.is_some();
        self.topology_refresh.coalesce(candidate);
        self.topology_refresh.finish_snapshot();
        if !changed {
            let effects = self.core.handle(Event::LocalTopologyRefreshUnchanged);
            self.apply_local_effects(effects).await?;
            self.topology
                .finish_unchanged_local_transition()
                .map_err(|_| SessionRuntimeError::Platform)?;
            self.platform.resume_input_admission();
        } else if !self.core.local_grant_allows_peer_input() {
            let candidate = self
                .topology_refresh
                .take_pending()
                .ok_or(SessionRuntimeError::Platform)?;
            self.topology
                .commit_local_candidate(candidate)
                .map_err(|_| SessionRuntimeError::Platform)?;
            let effects = self.core.handle(Event::LocalTopologyRefreshUnchanged);
            self.apply_local_effects(effects).await?;
            self.topology
                .mark_unpublished_local_ready()
                .map_err(|_| SessionRuntimeError::Platform)?;
            self.platform.resume_input_admission();
            self.set_session_topology_readiness(SessionTopologyReadiness::Ready)
                .await?;
            self.retry_pending_injection().await?;
            return Ok(());
        }
        self.drive_local_topology_refresh().await?;
        self.retry_pending_injection().await
    }

    async fn retry_pending_injection(&mut self) -> Result<(), SessionRuntimeError> {
        let Some(retry) = self.topology_refresh.take_injection_retry() else {
            return Ok(());
        };
        let Ok(input) = self.topology.resolve_incoming(retry.input) else {
            // The admitted pointer targeted a display removed by the stable
            // replacement graph. It must never resolve to a retired native ID.
            return Ok(());
        };
        if self.platform.inject(input).is_ok() {
            self.apply_remote_effects(retry.remaining_effects).await
        } else {
            // One stable-snapshot retry is the hard bound. A second transition
            // or any native failure is recovered fail-closed by the caller.
            self.session_safety.latch_failure();
            Err(SessionRuntimeError::Platform)
        }
    }

    async fn drive_local_topology_refresh(&mut self) -> Result<(), SessionRuntimeError> {
        if !self.topology.local_ack_pending() {
            self.topology_refresh.acknowledge();
        }
        if self.topology.local_ack_pending() || self.topology_refresh.snapshot_pending() {
            return Ok(());
        }
        if let Some(candidate) = self.topology_refresh.take_pending() {
            return self.publish_local_candidate(candidate).await;
        }
        if !self.core.local_grant_allows_peer_input() || self.topology.local_is_ready() {
            self.set_session_topology_readiness(SessionTopologyReadiness::Ready)
                .await?;
        }
        Ok(())
    }

    async fn publish_local_candidate(
        &mut self,
        candidate: LocalTopologyCandidate,
    ) -> Result<(), SessionRuntimeError> {
        let revision = candidate.revision();
        let effects = self.core.handle(Event::LocalTopologyPublished { revision });
        self.apply_local_effects(effects).await?;
        let topology = self
            .topology
            .commit_local_candidate(candidate)
            .map_err(|_| SessionRuntimeError::Platform)?;
        if topology.revision() != revision {
            return Err(SessionRuntimeError::ProtocolViolation);
        }
        self.topology.record_local_publish(revision);
        let meta = self.next_meta(SequenceKind::Control);
        self.send_control(ControlMessage::DisplayTopology { meta, topology })
            .await?;
        self.platform.resume_input_admission();
        if self.topology_initialized {
            self.topology_refresh.arm_ack_deadline(self.now());
        }
        Ok(())
    }

    async fn request_focus(
        &mut self,
        ttl_ms: u32,
        pointer_enter_required: bool,
    ) -> Result<(), SessionRuntimeError> {
        let ttl_ms = ttl_ms.clamp(MIN_LEASE_TTL_MS, MAX_LEASE_TTL_MS);
        let lease_id = LeaseId::new(nonzero_random_u64());
        let expires_at = self.now().saturating_add(u64::from(ttl_ms));
        let effects = self.core.handle(Event::LocalFocusRequested {
            lease_id,
            expires_at,
            pointer_enter_required,
        });
        self.apply_local_effects(effects).await
    }

    async fn handle_local_input(&mut self, event: InputEvent) -> Result<(), SessionRuntimeError> {
        if self.core.local_topology_refresh_pending() {
            return Ok(());
        }
        if let InputEvent::PointerMotion { position } = event {
            let action = self
                .topology
                .local_pointer(position, self.core.focus_state(), self.now())
                .map_err(|_| SessionRuntimeError::Platform)?;
            match action {
                LocalPointerAction::Local | LocalPointerAction::Suppressed => return Ok(()),
                LocalPointerAction::RequestFocus => {
                    return self.request_focus(DEFAULT_LEASE_TTL_MS, true).await;
                }
            }
        }
        let effects = self.core.handle(Event::LocalInput(event));
        self.apply_local_effects(effects).await
    }

    async fn handle_local_grant_update(
        &mut self,
        grants: CapabilityGrants,
        epoch: GrantEpoch,
        capability: Capability,
        enabled: bool,
    ) -> Result<(), SessionRuntimeError> {
        if !is_single_capability(capability) || !is_next_epoch(self.local_grant_epoch, epoch) {
            return Err(SessionRuntimeError::ProtocolViolation);
        }
        let previous = protocol_capabilities(self.config.local_grants_to_peer);
        if previous.contains(capability) == enabled {
            return Err(SessionRuntimeError::ProtocolViolation);
        }
        let mut expected = previous;
        expected.set(capability, enabled);
        if protocol_capabilities(grants) != expected {
            return Err(SessionRuntimeError::ProtocolViolation);
        }
        self.transfer
            .stop(if capability == Capability::FILE_TRANSFER && !enabled {
                TransferStopMode::AbortInbound
            } else {
                TransferStopMode::Suspend
            });

        let effects = self.core.handle(Event::LocalGrantUpdated {
            local_grant_epoch: epoch,
            local_grant_allows_peer_input: grants.contains(TrustedCapability::RemoteInput),
        });
        if effects
            .iter()
            .any(|effect| matches!(effect, Effect::Rejected { .. }))
        {
            return Err(SessionRuntimeError::ProtocolViolation);
        }
        self.local_grant_epoch = epoch;
        self.config.local_grants_to_peer = grants;
        self.topology.invalidate_local_authorization();
        let _clipboard_messages = self
            .clipboard
            .update_local_grants(epoch, clipboard_grants(grants))?;
        self.apply_remote_effects(effects).await?;
        self.force_recovery(Event::ReconnectRequested).await
    }

    async fn handle_peer_grant_update(
        &mut self,
        peer: DeviceId,
        capability: Capability,
        epoch: GrantEpoch,
        enabled: bool,
    ) -> Result<(), SessionRuntimeError> {
        if peer != self.config.local_device
            || !is_single_capability(capability)
            || !is_next_epoch(self.peer_grant_epoch, epoch)
            || self.peer_capabilities.contains(capability) == enabled
        {
            return Err(SessionRuntimeError::ProtocolViolation);
        }

        let mut capabilities = self.peer_capabilities;
        capabilities.set(capability, enabled);
        self.transfer
            .stop(if capability == Capability::FILE_TRANSFER && !enabled {
                TransferStopMode::AbortOutbound
            } else {
                TransferStopMode::Suspend
            });
        let effects = self.core.handle(Event::PeerGrantUpdated {
            peer_grant_epoch: epoch,
            peer_grant_allows_local_input: capabilities.contains(Capability::REMOTE_INPUT),
        });
        if effects
            .iter()
            .any(|effect| matches!(effect, Effect::Rejected { .. }))
        {
            return Err(SessionRuntimeError::ProtocolViolation);
        }

        self.peer_grant_epoch = epoch;
        self.peer_capabilities = capabilities;
        self.control_sequence = 0;
        self.reliable_sequence = 0;
        self.replaceable_sequence = 0;
        self.topology.invalidate_remote_authorization();
        let _clipboard_messages = self.clipboard.update_peer_grants(epoch, capabilities)?;
        self.apply_remote_effects(effects).await?;
        self.force_recovery(Event::ReconnectRequested).await
    }

    async fn send_control(&mut self, message: ControlMessage) -> Result<(), SessionRuntimeError> {
        let encoded = encode_control(&WireMessage::Control(message))
            .map_err(|_| SessionRuntimeError::ProtocolViolation)?;
        self.send_reliable(self.channels.control, encoded).await
    }

    async fn send_release_all(&mut self, lease_id: LeaseId) -> Result<(), SessionRuntimeError> {
        let meta = self.next_meta(SequenceKind::Reliable);
        let message = encode_release_all(meta, lease_id.get());
        let encoded = encode_reliable_input(&WireMessage::Input(message))
            .map_err(|_| SessionRuntimeError::ProtocolViolation)?;
        self.send_reliable(self.channels.reliable_input, encoded)
            .await
    }

    async fn send_pointer_enter(
        &mut self,
        lease_id: LeaseId,
        position: NormalizedPosition,
    ) -> Result<(), SessionRuntimeError> {
        let meta = self.next_meta(SequenceKind::Reliable);
        let message = encode_pointer_enter(position, meta, lease_id.get())
            .map_err(|_| SessionRuntimeError::ProtocolViolation)?;
        let encoded = encode_reliable_input(&WireMessage::Input(message))
            .map_err(|_| SessionRuntimeError::ProtocolViolation)?;
        self.send_reliable(self.channels.reliable_input, encoded)
            .await
    }

    async fn send_input(
        &mut self,
        lease_id: LeaseId,
        input: InputEvent,
    ) -> Result<(), SessionRuntimeError> {
        let replaceable = is_replaceable(input);
        let meta = self.next_meta(if replaceable {
            SequenceKind::Replaceable
        } else {
            SequenceKind::Reliable
        });
        let input = encode_event(input, meta, lease_id.get())
            .map_err(|_| SessionRuntimeError::ProtocolViolation)?;
        if replaceable {
            if matches!(self.channels.datagrams, DatagramAvailability::Available(_)) {
                let payload = encode_datagram(&WireMessage::Input(input))
                    .map_err(|_| SessionRuntimeError::ProtocolViolation)?;
                tokio::time::timeout(
                    Duration::from_millis(TOPOLOGY_REFRESH_PHASE_TIMEOUT_MS),
                    self.connection.execute(TransportCommand::SendDatagram {
                        payload: Bytes::from(payload),
                    }),
                )
                .await
                .map_err(|_| SessionRuntimeError::Transport)??;
            } else {
                let channel = self
                    .channels
                    .pointer_fallback
                    .ok_or(SessionRuntimeError::ProtocolViolation)?;
                let payload = encode_pointer_fallback(&WireMessage::Input(input))
                    .map_err(|_| SessionRuntimeError::ProtocolViolation)?;
                self.send_reliable(channel, payload).await?;
            }
        } else {
            let payload = encode_reliable_input(&WireMessage::Input(input))
                .map_err(|_| SessionRuntimeError::ProtocolViolation)?;
            self.send_reliable(self.channels.reliable_input, payload)
                .await?;
        }
        Ok(())
    }

    async fn send_reliable(
        &mut self,
        channel: ChannelId,
        payload: Vec<u8>,
    ) -> Result<(), SessionRuntimeError> {
        tokio::time::timeout(
            Duration::from_millis(TOPOLOGY_REFRESH_PHASE_TIMEOUT_MS),
            self.connection.execute(TransportCommand::SendReliable {
                channel,
                payload: Bytes::from(payload),
                end_of_stream: false,
            }),
        )
        .await
        .map_err(|_| SessionRuntimeError::Transport)??;
        Ok(())
    }

    async fn send_clipboard_messages(
        &mut self,
        messages: Vec<ClipboardMessage>,
    ) -> Result<(), SessionRuntimeError> {
        for message in messages {
            let payload =
                encode_clipboard(&message).map_err(|_| SessionRuntimeError::ProtocolViolation)?;
            self.send_reliable(self.channels.clipboard, payload).await?;
        }
        Ok(())
    }

    async fn handle_transfer_worker_event(
        &mut self,
        event: TransferWorkerEvent,
    ) -> Result<(), SessionRuntimeError> {
        match event {
            TransferWorkerEvent::SendManifest { payload, update } => {
                self.send_reliable(self.channels.file_manifest, payload)
                    .await?;
                if let Some(update) = update {
                    self.transfer.reliable_send_succeeded(update);
                }
                Ok(())
            }
            TransferWorkerEvent::SendData { payload, update } => {
                self.send_reliable(self.channels.file_data, payload).await?;
                // Public outbound progress advances only after the reliable
                // transport accepts the exact frame.
                self.transfer.reliable_send_succeeded(update);
                Ok(())
            }
            TransferWorkerEvent::Fatal(error) => Err(error.into()),
        }
    }

    async fn disconnect_transport(&mut self, reason: DisconnectReason) {
        if matches!(
            reason,
            DisconnectReason::EmergencyStop
                | DisconnectReason::LocalLocked
                | DisconnectReason::LocalSleeping
        ) {
            let _ = self
                .send_control(ControlMessage::EmergencyDisconnect {
                    session_id: self.session_id,
                })
                .await;
        }
        let close_reason = match reason {
            DisconnectReason::EmergencyStop
            | DisconnectReason::LocalLocked
            | DisconnectReason::LocalSleeping => CloseReason::EmergencyDisconnect,
            DisconnectReason::LinkLost => CloseReason::TransportFailure,
            DisconnectReason::RequestedReconnect | DisconnectReason::FocusLeaseExpired => {
                CloseReason::Requested
            }
        };
        let _ = self
            .connection
            .execute(TransportCommand::Close(close_reason))
            .await;
    }

    async fn force_recovery(&mut self, event: Event) -> Result<(), SessionRuntimeError> {
        let effects = self.core.handle(event);
        let result = self.apply_remote_effects(effects).await;
        if result.is_ok() {
            self.update_status().await;
            self.set_session_topology_readiness(SessionTopologyReadiness::NotConnected)
                .await?;
            Ok(())
        } else {
            if matches!(
                result,
                Err(SessionRuntimeError::Platform | SessionRuntimeError::SafetyRecoveryFailed)
            ) {
                // Publish the irreversible admission fence before any awaited
                // status work or error return can race a replacement session.
                self.session_safety.latch_failure();
            }
            let mut status = self.status.write().await;
            status.input_owner = InputOwner::Local;
            status.focus_state = AgentFocusState::Local;
            status.phase = nodavo_local_ipc::AgentPhase::Stopping;
            status.readiness.session_topology = SessionTopologyReadiness::NotConnected;
            Err(SessionRuntimeError::SafetyRecoveryFailed)
        }
    }

    fn next_meta(&mut self, kind: SequenceKind) -> EventMeta {
        let sequence = match kind {
            SequenceKind::Control => next_sequence(&mut self.control_sequence),
            SequenceKind::Reliable => next_sequence(&mut self.reliable_sequence),
            SequenceKind::Replaceable => next_sequence(&mut self.replaceable_sequence),
        };
        EventMeta::new(
            self.session_id,
            self.config.local_device,
            sequence,
            self.peer_grant_epoch,
            Capability::REMOTE_INPUT,
        )
    }

    fn now(&self) -> MonotonicMillis {
        let millis = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        MonotonicMillis::new(millis)
    }

    async fn update_status(&mut self) {
        let focus = self.core.focus_state();
        let mut status = self.status.write().await;
        status.input_owner = if matches!(focus, CoreFocusState::ControlledByRemote { .. }) {
            InputOwner::Remote
        } else {
            InputOwner::Local
        };
        status.focus_state = match focus {
            CoreFocusState::ControllingRemote { .. } => AgentFocusState::ControllingPeer,
            CoreFocusState::ControlledByRemote { .. } => AgentFocusState::ControlledByPeer,
            CoreFocusState::Local | CoreFocusState::RequestingRemote { .. } => {
                AgentFocusState::Local
            }
        };
    }

    async fn set_session_topology_readiness(
        &mut self,
        readiness: SessionTopologyReadiness,
    ) -> Result<(), SessionRuntimeError> {
        publish_session_topology_readiness(self.status, self.session_safety.as_ref(), readiness)
            .await
    }
}

const fn transfer_send_failure_is_link_loss(error: SessionRuntimeError) -> bool {
    matches!(error, SessionRuntimeError::Transport)
}

async fn publish_session_topology_readiness(
    status: &RwLock<AgentStatus>,
    session_safety: &SessionSafetyState,
    readiness: SessionTopologyReadiness,
) -> Result<(), SessionRuntimeError> {
    let mut status = status.write().await;
    if readiness != SessionTopologyReadiness::NotConnected && session_safety.blocks_ready() {
        status.phase = nodavo_local_ipc::AgentPhase::Stopping;
        status.readiness.session_topology = SessionTopologyReadiness::NotConnected;
        return Err(SessionRuntimeError::SafetyRecoveryFailed);
    }
    status.readiness.session_topology = readiness;
    Ok(())
}

fn platform_safety_command(event: PlatformSafetyEvent) -> LocalSessionCommand {
    let (acknowledgement, _received) = oneshot::channel();
    match event {
        PlatformSafetyEvent::LocalLocked => LocalSessionCommand::LocalLocked { acknowledgement },
        PlatformSafetyEvent::LocalSleeping => {
            LocalSessionCommand::LocalSleeping { acknowledgement }
        }
        PlatformSafetyEvent::CaptureFailed => {
            LocalSessionCommand::EmergencyStop { acknowledgement }
        }
    }
}

const fn core_event_for_platform_safety(event: PlatformSafetyEvent) -> Event {
    match event {
        PlatformSafetyEvent::LocalLocked => Event::LocalLocked,
        PlatformSafetyEvent::LocalSleeping => Event::LocalSleeping,
        PlatformSafetyEvent::CaptureFailed => Event::LocalEmergencyStop,
    }
}

#[derive(Clone, Copy)]
enum SequenceKind {
    Control,
    Reliable,
    Replaceable,
}

#[derive(Clone, Copy)]
enum ControlMessageKind {
    Request,
    Grant,
}

async fn establish_channels(
    connection: &mut dyn PeerConnection,
    config: &SessionConfig,
) -> Result<Channels, SessionRuntimeError> {
    let control = if let Some(channel) = config.existing_control {
        // Pairing frames never end the bidirectional control stream. Once both
        // `Committed` frames are consumed, the same authenticated connection
        // and channel continue directly into peer-session negotiation.
        channel
    } else {
        establish_channel(connection, config.role, ChannelKind::Control).await?
    };
    let reliable_input =
        establish_channel(connection, config.role, ChannelKind::ReliableInput).await?;
    let datagrams = connection.datagram_availability();
    let pointer_fallback = if datagrams == DatagramAvailability::Unavailable {
        Some(establish_channel(connection, config.role, ChannelKind::PointerFallback).await?)
    } else {
        None
    };
    let clipboard = establish_channel(connection, config.role, ChannelKind::Clipboard).await?;
    let file_manifest =
        establish_channel(connection, config.role, ChannelKind::FileManifest).await?;
    let file_data = establish_channel(connection, config.role, ChannelKind::FileData).await?;
    Ok(Channels {
        control,
        reliable_input,
        pointer_fallback,
        clipboard,
        file_manifest,
        file_data,
        datagrams,
    })
}

async fn establish_channel(
    connection: &mut dyn PeerConnection,
    role: SessionRole,
    kind: ChannelKind,
) -> Result<ChannelId, SessionRuntimeError> {
    if role == SessionRole::Opener {
        connection
            .execute(TransportCommand::OpenChannel {
                kind,
                direction: ChannelDirection::Bidirectional,
            })
            .await?;
    }
    match connection.next_event().await? {
        TransportEvent::ChannelOpened {
            channel,
            kind: actual,
            direction: ChannelDirection::Bidirectional,
        } if actual == kind => Ok(channel),
        _ => Err(SessionRuntimeError::ProtocolViolation),
    }
}

async fn negotiate_session(
    connection: &mut dyn PeerConnection,
    config: &SessionConfig,
    channels: &Channels,
) -> Result<(SessionId, PeerGrantState), SessionRuntimeError> {
    let local_capabilities = protocol_capabilities(config.local_grants_to_peer);
    match config.role {
        SessionRole::Opener => {
            let session_id = SessionId::new(nonzero_random_16());
            send_handshake(
                connection,
                channels.control,
                config,
                session_id,
                local_capabilities,
            )
            .await?;
            let peer_grant = receive_handshake(connection, channels, config, session_id).await?;
            Ok((session_id, peer_grant))
        }
        SessionRole::Acceptor => {
            let (session_id, peer_grant) =
                receive_opening_handshake(connection, channels, config).await?;
            send_handshake(
                connection,
                channels.control,
                config,
                session_id,
                local_capabilities,
            )
            .await?;
            Ok((session_id, peer_grant))
        }
    }
}

async fn send_handshake(
    connection: &mut dyn PeerConnection,
    channel: ChannelId,
    config: &SessionConfig,
    session_id: SessionId,
    capabilities: Capability,
) -> Result<(), SessionRuntimeError> {
    let mut messages = vec![ControlMessage::Hello {
        versions: vec![ProtocolVersion::CURRENT],
        capabilities,
    }];
    if !capabilities.is_empty() {
        messages.push(ControlMessage::CapabilityGrant {
            // `peer` is the grant recipient/target, not the sender. The receiver
            // therefore requires this to equal its own pinned device identity.
            peer: config.peer_device,
            capabilities,
            epoch: config.local_grant_epoch,
        });
    }
    messages.push(ControlMessage::SessionOpen {
        session_id,
        // SessionOpen uses the same recipient/target convention.
        peer: config.peer_device,
        epoch: config.local_grant_epoch,
    });
    for message in messages {
        let payload = encode_control(&WireMessage::Control(message))
            .map_err(|_| SessionRuntimeError::ProtocolViolation)?;
        connection
            .execute(TransportCommand::SendReliable {
                channel,
                payload: Bytes::from(payload),
                end_of_stream: false,
            })
            .await?;
    }
    Ok(())
}

async fn receive_opening_handshake(
    connection: &mut dyn PeerConnection,
    channels: &Channels,
    config: &SessionConfig,
) -> Result<(SessionId, PeerGrantState), SessionRuntimeError> {
    let (hello, grant, session) = receive_handshake_frames(connection, channels.control).await?;
    let (capabilities, granted, peer, session_id, session_peer, epoch) =
        unpack_handshake(&hello, grant.as_ref(), &session)?;
    validate_handshake(config, capabilities, granted, peer, session_peer, epoch)?;
    Ok((
        session_id,
        PeerGrantState {
            capabilities,
            epoch,
        },
    ))
}

async fn receive_handshake(
    connection: &mut dyn PeerConnection,
    channels: &Channels,
    config: &SessionConfig,
    expected_session: SessionId,
) -> Result<PeerGrantState, SessionRuntimeError> {
    let (hello, grant, session) = receive_handshake_frames(connection, channels.control).await?;
    let (capabilities, granted, peer, session_id, session_peer, epoch) =
        unpack_handshake(&hello, grant.as_ref(), &session)?;
    validate_handshake(config, capabilities, granted, peer, session_peer, epoch)?;
    if session_id != expected_session {
        return Err(SessionRuntimeError::ProtocolViolation);
    }
    Ok(PeerGrantState {
        capabilities,
        epoch,
    })
}

async fn receive_handshake_frames(
    connection: &mut dyn PeerConnection,
    control: ChannelId,
) -> Result<(ControlMessage, Option<ControlMessage>, ControlMessage), SessionRuntimeError> {
    let hello = receive_control_frame(connection, control).await?;
    let next = receive_control_frame(connection, control).await?;
    if matches!(next, ControlMessage::CapabilityGrant { .. }) {
        Ok((
            hello,
            Some(next),
            receive_control_frame(connection, control).await?,
        ))
    } else {
        Ok((hello, None, next))
    }
}

async fn receive_control_frame(
    connection: &mut dyn PeerConnection,
    control: ChannelId,
) -> Result<ControlMessage, SessionRuntimeError> {
    let TransportEvent::ReliableData {
        channel,
        payload,
        end_of_stream: false,
    } = connection.next_event().await?
    else {
        return Err(SessionRuntimeError::ProtocolViolation);
    };
    if channel != control {
        return Err(SessionRuntimeError::ProtocolViolation);
    }
    match decode_control(&payload).map_err(|_| SessionRuntimeError::ProtocolViolation)? {
        WireMessage::Control(message) => Ok(message),
        _ => Err(SessionRuntimeError::ProtocolViolation),
    }
}

fn unpack_handshake(
    hello: &ControlMessage,
    grant: Option<&ControlMessage>,
    session: &ControlMessage,
) -> Result<
    (
        Capability,
        Capability,
        DeviceId,
        SessionId,
        DeviceId,
        GrantEpoch,
    ),
    SessionRuntimeError,
> {
    let ControlMessage::Hello {
        versions,
        capabilities,
    } = hello
    else {
        return Err(SessionRuntimeError::ProtocolViolation);
    };
    if versions.as_slice() != [ProtocolVersion::CURRENT] {
        return Err(SessionRuntimeError::ProtocolViolation);
    }
    let ControlMessage::SessionOpen {
        session_id,
        peer: session_peer,
        epoch: session_epoch,
    } = session
    else {
        return Err(SessionRuntimeError::ProtocolViolation);
    };
    let (peer, granted, epoch) = match grant {
        Some(ControlMessage::CapabilityGrant {
            peer,
            capabilities: granted,
            epoch,
        }) if !granted.is_empty() => (*peer, *granted, *epoch),
        None if capabilities.is_empty() => (*session_peer, *capabilities, *session_epoch),
        _ => return Err(SessionRuntimeError::ProtocolViolation),
    };
    if *session_epoch != epoch {
        return Err(SessionRuntimeError::ProtocolViolation);
    }
    Ok((
        *capabilities,
        granted,
        peer,
        *session_id,
        *session_peer,
        epoch,
    ))
}

fn validate_handshake(
    config: &SessionConfig,
    capabilities: Capability,
    granted: Capability,
    peer: DeviceId,
    session_peer: DeviceId,
    epoch: GrantEpoch,
) -> Result<(), SessionRuntimeError> {
    if capabilities != granted
        || peer != config.local_device
        || session_peer != config.local_device
        || config
            .peer_grant_epoch
            .is_some_and(|expected| expected != epoch)
        || config
            .peer_grants_to_local
            .is_some_and(|expected| protocol_capabilities(expected) != capabilities)
    {
        Err(SessionRuntimeError::ProtocolViolation)
    } else {
        Ok(())
    }
}

const fn allows_input(grants: CapabilityGrants) -> bool {
    grants.contains(TrustedCapability::RemoteInput)
}

const fn clipboard_grants(grants: CapabilityGrants) -> PeerClipboardGrants {
    PeerClipboardGrants {
        allow_peer_read: grants.contains(TrustedCapability::ClipboardRead),
        allow_peer_write: grants.contains(TrustedCapability::ClipboardWrite),
    }
}

fn protocol_capabilities(grants: CapabilityGrants) -> Capability {
    let mut capabilities = Capability::empty();
    if grants.contains(TrustedCapability::RemoteInput) {
        capabilities |= Capability::REMOTE_INPUT;
    }
    if grants.contains(TrustedCapability::ClipboardRead) {
        capabilities |= Capability::CLIPBOARD_READ;
    }
    if grants.contains(TrustedCapability::ClipboardWrite) {
        capabilities |= Capability::CLIPBOARD_WRITE;
    }
    if grants.contains(TrustedCapability::FileTransfer) {
        capabilities |= Capability::FILE_TRANSFER;
    }
    capabilities
}

const fn is_single_capability(capability: Capability) -> bool {
    capability.bits().is_power_of_two()
}

const fn is_next_epoch(current: GrantEpoch, next: GrantEpoch) -> bool {
    match current.get().checked_add(1) {
        Some(expected) => next.get() == expected,
        None => false,
    }
}

const fn is_replaceable(event: InputEvent) -> bool {
    matches!(
        event,
        InputEvent::PointerMotion { .. }
            | InputEvent::PointerDelta { .. }
            | InputEvent::Scroll { .. }
    )
}

fn effects_disconnect(effects: &[Effect]) -> bool {
    effects
        .iter()
        .any(|effect| matches!(effect, Effect::Disconnect { .. }))
}

fn next_sequence(value: &mut u64) -> Sequence {
    *value = value.wrapping_add(1);
    if *value == 0 {
        *value = 1;
    }
    Sequence::new(*value)
}

fn nonzero_random_u64() -> u64 {
    let value = rand::random::<u64>();
    if value == 0 { 1 } else { value }
}

fn nonzero_random_16() -> [u8; 16] {
    let mut value = rand::random::<[u8; 16]>();
    if value.iter().all(|byte| *byte == 0) {
        value[0] = 1;
    }
    value
}

trait SaturatingMonotonic {
    fn saturating_add(self, delta: u64) -> Self;
}

impl SaturatingMonotonic for MonotonicMillis {
    fn saturating_add(self, delta: u64) -> Self {
        Self::new(self.get().saturating_add(delta))
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use nodavo_identity::Capability as TrustedCapability;
    use nodavo_input::{HidUsage, KEYBOARD_PAGE, KeyState, Modifiers, PointerDelta};
    use nodavo_transport::{BoxFuture, DatagramAvailability, Endpoint};
    use tokio::time::timeout;

    use crate::platform_port::VirtualPlatformPort;
    use crate::topology_runtime::NativeDisplaySnapshot;

    use super::*;

    #[test]
    fn transfer_reliable_send_transport_failure_is_link_loss_only() {
        assert!(transfer_send_failure_is_link_loss(
            SessionRuntimeError::Transport
        ));
        assert!(!transfer_send_failure_is_link_loss(
            SessionRuntimeError::ProtocolViolation
        ));
        assert!(!transfer_send_failure_is_link_loss(
            SessionRuntimeError::Platform
        ));
        assert!(!transfer_send_failure_is_link_loss(
            SessionRuntimeError::SafetyRecoveryFailed
        ));
    }

    #[test]
    fn placement_during_requesting_remote_requires_exact_reconnect_recovery() {
        let focus = CoreFocusState::RequestingRemote {
            lease_id: LeaseId::new(7),
            expires_at: MonotonicMillis::new(5_000),
        };
        assert_eq!(
            placement_update_recovery_event(focus),
            Some(Event::ReconnectRequested)
        );
    }

    #[test]
    fn placement_during_controlling_remote_requires_exact_reconnect_recovery() {
        let focus = CoreFocusState::ControllingRemote {
            lease_id: LeaseId::new(8),
            expires_at: MonotonicMillis::new(5_000),
        };
        assert_eq!(
            placement_update_recovery_event(focus),
            Some(Event::ReconnectRequested)
        );
        assert_eq!(placement_update_recovery_event(CoreFocusState::Local), None);
    }

    fn display_snapshot(native_id: u64, pixel_width: u32) -> NativeDisplaySnapshot {
        NativeDisplaySnapshot {
            native_id: nodavo_input::DisplayId::new(native_id),
            origin_x_milli: 0,
            origin_y_milli: 0,
            pixel_width,
            pixel_height: 1_080,
            scale_x_milli: 1_000,
            scale_y_milli: 1_000,
            rotation: nodavo_protocol::DisplayRotation::Degrees0,
        }
    }

    #[test]
    fn missing_refresh_ack_deadline_survives_a_dirty_storm_and_latest_wins() {
        let mut topology = PeerTopologyState::from_environment(PeerPlacement::Right, true).unwrap();
        let mut refresh = LocalTopologyRefresh::default();
        refresh.arm_ack_deadline(MonotonicMillis::new(10));

        for width in [1_280, 1_440, 1_920] {
            let candidate = topology
                .prepare_local_candidate(&[display_snapshot(101, width)])
                .unwrap();
            refresh.coalesce(candidate);
        }

        assert!(!refresh.timed_out(MonotonicMillis::new(5_009)));
        assert!(refresh.timed_out(MonotonicMillis::new(5_010)));
        let committed = topology
            .commit_local_candidate(refresh.take_pending().unwrap())
            .unwrap();
        assert_eq!(committed.displays()[0].pixel_width(), 1_920);
        assert!(refresh.take_pending().is_none());

        let mut snapshot_refresh = LocalTopologyRefresh::default();
        snapshot_refresh.begin_snapshot(MonotonicMillis::new(10));
        for ready_event_at in [11, 100, 1_000, 5_009] {
            snapshot_refresh.begin_snapshot(MonotonicMillis::new(ready_event_at));
            assert!(!snapshot_refresh.timed_out(MonotonicMillis::new(5_009)));
        }
        assert!(snapshot_refresh.timed_out(MonotonicMillis::new(5_010)));
    }

    struct MemoryConnection {
        remote: Endpoint,
        inbound: mpsc::UnboundedReceiver<TransportEvent>,
        local_events: mpsc::UnboundedSender<TransportEvent>,
        peer_events: mpsc::UnboundedSender<TransportEvent>,
        next_channel: Arc<AtomicU64>,
        closed: bool,
        required_safety_fence_on_close: Option<Arc<SessionSafetyState>>,
    }

    impl PeerConnection for MemoryConnection {
        fn remote_endpoint(&self) -> Endpoint {
            self.remote
        }

        fn datagram_availability(&self) -> DatagramAvailability {
            DatagramAvailability::Unavailable
        }

        fn export_keying_material(
            &self,
            _label: &[u8],
            _context: &[u8],
            output_len: usize,
        ) -> Result<Bytes, TransportError> {
            Ok(Bytes::from(vec![7; output_len]))
        }

        fn execute(
            &mut self,
            command: TransportCommand,
        ) -> BoxFuture<'_, Result<(), TransportError>> {
            Box::pin(async move {
                if self.closed {
                    return Err(TransportError::Closed);
                }
                match command {
                    TransportCommand::OpenChannel { kind, direction } => {
                        let id = self.next_channel.fetch_add(1, Ordering::SeqCst);
                        let channel = ChannelId::from_backend(id);
                        let event = TransportEvent::ChannelOpened {
                            channel,
                            kind,
                            direction,
                        };
                        self.local_events
                            .send(event.clone())
                            .map_err(|_| TransportError::Closed)?;
                        self.peer_events
                            .send(event)
                            .map_err(|_| TransportError::Closed)?;
                    }
                    TransportCommand::SendReliable {
                        channel,
                        payload,
                        end_of_stream,
                    } => self
                        .peer_events
                        .send(TransportEvent::ReliableData {
                            channel,
                            payload,
                            end_of_stream,
                        })
                        .map_err(|_| TransportError::Closed)?,
                    TransportCommand::SendDatagram { payload } => self
                        .peer_events
                        .send(TransportEvent::Datagram { payload })
                        .map_err(|_| TransportError::Closed)?,
                    TransportCommand::Close(reason) => {
                        if let Some(safety) = &self.required_safety_fence_on_close {
                            assert!(
                                safety.failure_latched(),
                                "native recovery failure was not fenced before transport close"
                            );
                        }
                        self.closed = true;
                        let _ = self.peer_events.send(TransportEvent::Closed(reason));
                    }
                }
                Ok(())
            })
        }

        fn next_event(&mut self) -> BoxFuture<'_, Result<TransportEvent, TransportError>> {
            Box::pin(async move { self.inbound.recv().await.ok_or(TransportError::Closed) })
        }
    }

    fn memory_pair(
        b_close_safety: Option<Arc<SessionSafetyState>>,
    ) -> (Box<dyn PeerConnection>, Box<dyn PeerConnection>) {
        let (a_tx, a_rx) = mpsc::unbounded_channel();
        let (b_tx, b_rx) = mpsc::unbounded_channel();
        let next_channel = Arc::new(AtomicU64::new(1));
        let a_endpoint =
            Endpoint::new(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40_001)).unwrap();
        let b_endpoint =
            Endpoint::new(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40_002)).unwrap();
        (
            Box::new(MemoryConnection {
                remote: b_endpoint,
                inbound: a_rx,
                local_events: a_tx.clone(),
                peer_events: b_tx.clone(),
                next_channel: Arc::clone(&next_channel),
                closed: false,
                required_safety_fence_on_close: None,
            }),
            Box::new(MemoryConnection {
                remote: a_endpoint,
                inbound: b_rx,
                local_events: b_tx,
                peer_events: a_tx,
                next_channel,
                closed: false,
                required_safety_fence_on_close: b_close_safety,
            }),
        )
    }

    fn connected_status() -> AgentStatus {
        AgentStatus {
            phase: nodavo_local_ipc::AgentPhase::Connected,
            connected_peer: Some("test-peer".to_owned()),
            input_owner: InputOwner::Local,
            focus_state: AgentFocusState::Local,
            readiness: ReadinessSnapshot {
                session_topology: SessionTopologyReadiness::Synchronizing,
                ..ReadinessSnapshot::default()
            },
        }
    }

    fn test_transfer_staging(owner: DeviceId) -> (ReceiveStagingArea, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "nodavo-session-transfer-test-{}",
            nodavo_transfer::TransferId::new().as_uuid()
        ));
        fs::create_dir(&root).unwrap();
        (
            FileSystemStagingArea::new_scoped(&root, *owner.as_bytes())
                .unwrap()
                .into(),
            root,
        )
    }

    async fn wait_for_owner(status: &RwLock<AgentStatus>, owner: InputOwner) {
        timeout(Duration::from_secs(2), async {
            loop {
                if status.read().await.input_owner == owner {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("focus transition timed out");
    }

    async fn wait_for_focus(status: &RwLock<AgentStatus>, focus: AgentFocusState) {
        timeout(Duration::from_secs(2), async {
            loop {
                if status.read().await.focus_state == focus {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("focus direction transition timed out");
    }

    #[tokio::test]
    async fn safety_latch_refuses_late_topology_ready_publication() {
        let status = RwLock::new(connected_status());
        let session_safety = SessionSafetyState::default();
        session_safety.latch_failure();
        assert!(matches!(
            publish_session_topology_readiness(
                &status,
                &session_safety,
                SessionTopologyReadiness::Ready,
            )
            .await,
            Err(SessionRuntimeError::SafetyRecoveryFailed)
        ));
        let status = status.read().await;
        assert_eq!(status.phase, nodavo_local_ipc::AgentPhase::Stopping);
        assert_eq!(
            status.readiness.session_topology,
            SessionTopologyReadiness::NotConnected
        );

        let status = RwLock::new(connected_status());
        let session_safety = SessionSafetyState::default();
        session_safety.set_operation_active(true);
        assert!(matches!(
            publish_session_topology_readiness(
                &status,
                &session_safety,
                SessionTopologyReadiness::Ready,
            )
            .await,
            Err(SessionRuntimeError::SafetyRecoveryFailed)
        ));
        assert_eq!(
            status.read().await.readiness.session_topology,
            SessionTopologyReadiness::NotConnected
        );
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn two_peers_return_focus_on_same_link_and_recover_before_acknowledgement() {
        let a_session_safety = Arc::new(SessionSafetyState::default());
        let b_session_safety = Arc::new(SessionSafetyState::default());
        let (a_connection, b_connection) = memory_pair(Some(Arc::clone(&b_session_safety)));
        let grants = CapabilityGrants::NONE
            .with(TrustedCapability::RemoteInput)
            .with(TrustedCapability::ClipboardRead)
            .with(TrustedCapability::ClipboardWrite)
            .with(TrustedCapability::FileTransfer);
        let a_status = Arc::new(RwLock::new(connected_status()));
        let b_status = Arc::new(RwLock::new(connected_status()));
        let a_platform = VirtualPlatformPort::default();
        let b_platform = VirtualPlatformPort::default();
        let a_observer = a_platform.clone();
        let b_observer = b_platform.clone();
        b_observer.signal_unstable_display_change();
        let (a_commands, a_receiver) = command_channel();
        let (b_commands, b_receiver) = command_channel();
        let (a_native_sender, a_native_receiver) = crate::native_bridge::native_input_channel();
        let (b_native_sender, b_native_receiver) = crate::native_bridge::native_input_channel();
        let (_a_safety_sender, a_safety_receiver) = crate::native_bridge::platform_safety_channel();
        let (_b_safety_sender, b_safety_receiver) = crate::native_bridge::platform_safety_channel();
        let clipboard_content = Bytes::from_static(b"clipboard channel integration proof");
        let (a_clipboard, _a_clipboard_observer) =
            crate::clipboard_port::VirtualClipboardPort::with_local_text(1, &clipboard_content);
        let (b_clipboard, b_clipboard_observer) =
            crate::clipboard_port::VirtualClipboardPort::empty();
        let a_peer = DeviceId::new([2; 32]);
        let b_peer = DeviceId::new([1; 32]);
        let (a_transfer, a_transfer_root) = test_transfer_staging(a_peer);
        let (b_transfer, b_transfer_root) = test_transfer_staging(b_peer);
        let a_transfer_store = TransferStore::default();
        a_transfer_store
            .register_staging_root(a_peer, a_transfer_root.clone())
            .unwrap();
        let b_transfer_store = TransferStore::default();
        b_transfer_store
            .register_staging_root(b_peer, b_transfer_root.clone())
            .unwrap();
        let outbound_path = a_transfer_root.join("session-transfer-proof.txt");
        let outbound_content = b"authenticated session file transfer proof";
        fs::write(&outbound_path, outbound_content).unwrap();
        let (_a_disconnect, a_disconnect) = watch::channel(0_u64);
        let (_b_disconnect, b_disconnect) = watch::channel(0_u64);
        let a_status_task = Arc::clone(&a_status);
        let a_session_safety_task = Arc::clone(&a_session_safety);
        let a_task = tokio::spawn(async move {
            let mut platform = a_platform;
            run_peer_session(
                a_connection,
                SessionConfig {
                    role: SessionRole::Opener,
                    local_device: DeviceId::new([1; 32]),
                    peer_device: DeviceId::new([2; 32]),
                    local_grants_to_peer: grants,
                    local_grant_epoch: GrantEpoch::new(3),
                    peer_grants_to_local: Some(grants),
                    peer_grant_epoch: Some(GrantEpoch::new(7)),
                    peer_placement: PeerPlacement::Right,
                    existing_control: None,
                },
                a_receiver,
                NativeSessionEvents {
                    input: a_native_receiver,
                    safety: a_safety_receiver,
                    clipboard: Box::new(a_clipboard),
                    transfer: a_transfer,
                    transfer_store: a_transfer_store,
                    session_safety: a_session_safety_task,
                },
                a_disconnect,
                &a_status_task,
                &mut platform,
            )
            .await
        });
        let b_status_task = Arc::clone(&b_status);
        let b_session_safety_task = Arc::clone(&b_session_safety);
        let b_task = tokio::spawn(async move {
            let mut platform = b_platform;
            run_peer_session(
                b_connection,
                SessionConfig {
                    role: SessionRole::Acceptor,
                    local_device: DeviceId::new([2; 32]),
                    peer_device: DeviceId::new([1; 32]),
                    local_grants_to_peer: grants,
                    local_grant_epoch: GrantEpoch::new(7),
                    peer_grants_to_local: Some(grants),
                    peer_grant_epoch: Some(GrantEpoch::new(3)),
                    peer_placement: PeerPlacement::Right,
                    existing_control: None,
                },
                b_receiver,
                NativeSessionEvents {
                    input: b_native_receiver,
                    safety: b_safety_receiver,
                    clipboard: Box::new(b_clipboard),
                    transfer: b_transfer,
                    transfer_store: b_transfer_store,
                    session_safety: b_session_safety_task,
                },
                b_disconnect,
                &b_status_task,
                &mut platform,
            )
            .await
        });

        timeout(Duration::from_secs(2), async {
            while b_observer.snapshot().display_snapshot_attempts == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("initial topology acquisition did not retry a pending snapshot");
        assert_eq!(
            b_status.read().await.readiness.session_topology,
            SessionTopologyReadiness::Synchronizing
        );
        assert!(!b_task.is_finished());
        b_observer.stabilize_display_change(vec![display_snapshot(101, 1_920)]);

        timeout(Duration::from_secs(2), async {
            while b_clipboard_observer.applied_bytes() != clipboard_content {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("clipboard content did not cross the dedicated session channel");
        assert_eq!(
            a_status.read().await.readiness.session_topology,
            SessionTopologyReadiness::Ready
        );
        assert_eq!(
            b_status.read().await.readiness.session_topology,
            SessionTopologyReadiness::Ready
        );

        let (transfer_ack, transfer_result) = oneshot::channel();
        a_commands
            .send(LocalSessionCommand::SendFiles {
                paths: vec![outbound_path],
                acknowledgement: transfer_ack,
            })
            .await
            .unwrap();
        transfer_result.await.unwrap().unwrap();
        timeout(Duration::from_secs(3), async {
            let received = b_transfer_root.join("session-transfer-proof.txt");
            loop {
                if fs::read(&received).ok().as_deref() == Some(outbound_content) {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("file did not cross the dedicated manifest/data channels");

        // A platform transition discovered by absolute placement is retried
        // exactly once after a stable snapshot. Refresh quiescence retires the
        // interrupted lease, so the next focus request starts from Local.
        b_observer.fail_next_pointer_injection_for_topology();
        let (ack, received) = oneshot::channel();
        a_commands
            .send(LocalSessionCommand::RequestFocus {
                ttl_ms: 5_000,
                acknowledgement: ack,
            })
            .await
            .unwrap();
        received.await.unwrap().unwrap();
        timeout(Duration::from_secs(2), async {
            loop {
                let state = b_observer.snapshot();
                if state.injection_attempts >= 2
                    && a_status.read().await.focus_state == AgentFocusState::Local
                    && b_status.read().await.focus_state == AgentFocusState::Local
                {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("absolute injection was not retried after topology stabilization");
        assert_eq!(
            b_observer
                .snapshot()
                .injected
                .iter()
                .filter(|event| matches!(event, InputEvent::PointerMotion { .. }))
                .count(),
            1
        );

        let (ack, received) = oneshot::channel();
        a_commands
            .send(LocalSessionCommand::RequestFocus {
                ttl_ms: 5_000,
                acknowledgement: ack,
            })
            .await
            .unwrap();
        received.await.unwrap().unwrap();
        wait_for_owner(&b_status, InputOwner::Remote).await;
        wait_for_focus(&a_status, AgentFocusState::ControllingPeer).await;
        wait_for_focus(&b_status, AgentFocusState::ControlledByPeer).await;
        timeout(Duration::from_secs(2), async {
            while !a_observer.snapshot().routing_to_peer {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("routing started before reliable pointer-enter acknowledgement");
        assert!(!b_observer.snapshot().routing_to_peer);
        assert!(b_observer.snapshot().injected.iter().any(|event| {
            matches!(
                event,
                InputEvent::PointerMotion { position }
                    if position.display() == nodavo_input::DisplayId::new(101)
            )
        }));
        let relative = InputEvent::PointerDelta {
            delta: PointerDelta::new(12, -5).unwrap(),
        };
        a_native_sender.send(relative).unwrap();
        timeout(Duration::from_secs(2), async {
            while !b_observer.snapshot().injected.contains(&relative) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("relative pointer delta did not follow reliable entry placement");

        // The stable revision becomes available entirely between timer ticks;
        // the per-monitor revision cursor must still retain that edge.
        a_observer.stabilize_display_change(vec![display_snapshot(101, 1_440)]);
        wait_for_owner(&b_status, InputOwner::Local).await;
        wait_for_focus(&a_status, AgentFocusState::Local).await;
        assert!(!a_observer.snapshot().routing_to_peer);
        timeout(Duration::from_secs(2), async {
            loop {
                if a_status.read().await.readiness.session_topology
                    == SessionTopologyReadiness::Ready
                {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("hot-plug topology acknowledgement timed out");
        assert!(!a_observer.snapshot().routing_to_peer);

        a_observer.signal_unstable_display_change();
        let (ack, received) = oneshot::channel();
        b_commands
            .send(LocalSessionCommand::RequestFocus {
                ttl_ms: 5_000,
                acknowledgement: ack,
            })
            .await
            .unwrap();
        received.await.unwrap().unwrap();
        timeout(Duration::from_secs(2), async {
            loop {
                if a_status.read().await.readiness.session_topology
                    == SessionTopologyReadiness::Synchronizing
                {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("focus request did not yield to pre-dispatch topology refresh");
        wait_for_owner(&a_status, InputOwner::Local).await;
        wait_for_focus(&b_status, AgentFocusState::Local).await;
        assert!(!b_observer.snapshot().routing_to_peer);
        a_observer.stabilize_display_change(vec![display_snapshot(101, 1_500)]);
        timeout(Duration::from_secs(2), async {
            loop {
                if a_status.read().await.readiness.session_topology
                    == SessionTopologyReadiness::Ready
                {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("focus-gated topology refresh did not complete");

        let (ack, received) = oneshot::channel();
        a_commands
            .send(LocalSessionCommand::RequestFocus {
                ttl_ms: 5_000,
                acknowledgement: ack,
            })
            .await
            .unwrap();
        received.await.unwrap().unwrap();
        wait_for_focus(&a_status, AgentFocusState::ControllingPeer).await;
        wait_for_focus(&b_status, AgentFocusState::ControlledByPeer).await;
        b_observer.signal_unstable_display_change();
        a_native_sender
            .send(InputEvent::Key {
                usage: HidUsage::new(KEYBOARD_PAGE, 5),
                state: KeyState::Pressed,
                modifiers: Modifiers::empty(),
            })
            .unwrap();
        wait_for_focus(&a_status, AgentFocusState::Local).await;
        wait_for_focus(&b_status, AgentFocusState::Local).await;
        timeout(Duration::from_secs(2), async {
            loop {
                if b_status.read().await.readiness.session_topology
                    == SessionTopologyReadiness::Synchronizing
                {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("remote input did not yield to pre-dispatch topology refresh");
        assert!(!b_observer.snapshot().injected.iter().any(|event| {
            matches!(
                event,
                InputEvent::Key {
                    usage,
                    state: KeyState::Pressed,
                    ..
                } if *usage == HidUsage::new(KEYBOARD_PAGE, 5)
            )
        }));
        b_observer.stabilize_display_change(vec![display_snapshot(101, 1_440)]);
        timeout(Duration::from_secs(2), async {
            loop {
                if b_status.read().await.readiness.session_topology
                    == SessionTopologyReadiness::Ready
                {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("peer topology did not recover after pre-dispatch refresh");

        let (ack, received) = oneshot::channel();
        b_commands
            .send(LocalSessionCommand::RequestFocus {
                ttl_ms: 5_000,
                acknowledgement: ack,
            })
            .await
            .unwrap();
        received.await.unwrap().unwrap();
        wait_for_owner(&a_status, InputOwner::Remote).await;
        wait_for_focus(&b_status, AgentFocusState::ControllingPeer).await;
        assert!(b_observer.snapshot().routing_to_peer);
        let queued_press = InputEvent::Key {
            usage: HidUsage::new(KEYBOARD_PAGE, 4),
            state: KeyState::Pressed,
            modifiers: Modifiers::empty(),
        };
        let queued_release = InputEvent::Key {
            usage: HidUsage::new(KEYBOARD_PAGE, 4),
            state: KeyState::Released,
            modifiers: Modifiers::empty(),
        };
        b_native_sender.send(queued_press).unwrap();
        b_native_sender.send(queued_release).unwrap();
        b_observer.signal_unstable_display_change();
        wait_for_owner(&a_status, InputOwner::Local).await;
        wait_for_focus(&a_status, AgentFocusState::Local).await;
        wait_for_focus(&b_status, AgentFocusState::Local).await;
        timeout(Duration::from_secs(2), async {
            loop {
                if b_status.read().await.readiness.session_topology
                    == SessionTopologyReadiness::Synchronizing
                {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("unstable hot-plug did not enter synchronizing state");
        assert!(!b_observer.snapshot().routing_to_peer);

        b_observer.stabilize_display_change(vec![display_snapshot(101, 1_600)]);
        timeout(Duration::from_secs(2), async {
            loop {
                if b_status.read().await.readiness.session_topology
                    == SessionTopologyReadiness::Ready
                {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("in-progress hot-plug did not publish after stabilization");

        let grants_without_input =
            CapabilityGrants::from_bits(grants.bits() & !(TrustedCapability::RemoteInput as u8))
                .unwrap();
        // Peer B faults while restoring native ownership during the revoke's
        // directional shutdown. The process-wide safety fence must be latched
        // before its session future can return.
        b_observer.fail_restore_local_ownership();
        let (ack, received) = oneshot::channel();
        a_commands
            .send(LocalSessionCommand::UpdateLocalGrant {
                grants: grants_without_input,
                epoch: GrantEpoch::new(4),
                capability: Capability::REMOTE_INPUT,
                enabled: false,
                acknowledgement: ack,
            })
            .await
            .unwrap();
        received.await.unwrap().unwrap();
        wait_for_owner(&a_status, InputOwner::Local).await;
        wait_for_focus(&a_status, AgentFocusState::Local).await;
        wait_for_focus(&b_status, AgentFocusState::Local).await;
        assert!(!b_observer.snapshot().routing_to_peer);
        assert!(a_observer.snapshot().forced_releases.is_empty());

        let recovered = a_observer.snapshot();
        assert!(recovered.forced_releases.is_empty());
        assert!(!recovered.routing_to_peer);
        assert_eq!(a_status.read().await.input_owner, InputOwner::Local);
        assert_eq!(a_status.read().await.focus_state, AgentFocusState::Local);

        assert!(
            timeout(Duration::from_secs(2), a_task)
                .await
                .unwrap()
                .unwrap()
                .is_ok()
        );
        let b_result = timeout(Duration::from_secs(2), b_task)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            b_result,
            Err(SessionRuntimeError::SafetyRecoveryFailed)
        ));
        assert!(b_session_safety.failure_latched());
        assert!(b_session_safety.blocks_ready());
        assert_eq!(
            b_status.read().await.phase,
            nodavo_local_ipc::AgentPhase::Stopping
        );
        assert!(matches!(
            publish_session_topology_readiness(
                &b_status,
                b_session_safety.as_ref(),
                SessionTopologyReadiness::Ready,
            )
            .await,
            Err(SessionRuntimeError::SafetyRecoveryFailed)
        ));
        assert_eq!(
            a_status.read().await.readiness.session_topology,
            SessionTopologyReadiness::NotConnected
        );
        assert_eq!(
            b_status.read().await.readiness.session_topology,
            SessionTopologyReadiness::NotConnected
        );
        fs::remove_dir_all(a_transfer_root).unwrap();
        fs::remove_dir_all(b_transfer_root).unwrap();
    }
}
