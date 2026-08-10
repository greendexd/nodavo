//! Deterministic session and focus-ownership state machine.
//!
//! The reducer accepts semantic events and returns semantic effects. It owns no
//! clock, transport, filesystem, or platform handle, so the same transitions can
//! be tested and used by every runtime adapter.

mod edge;

pub use edge::{
    DisplayEdge, EdgeAlignment, EdgeConfigError, EdgeRoute, EdgeSwitchConfig, EdgeSwitchController,
    EdgeSwitchDecision, MAX_EDGE_BAND_MILLI, MAX_EDGE_COOLDOWN_MS, MAX_EDGE_DEBOUNCE_MS,
    MAX_EDGE_ROUTES, PointerSample, TargetPointerPosition, map_pointer_across_route,
};

use nodavo_input::{InputEvent, NormalizedPosition, PressedState};
use nodavo_protocol::{Capability, DeviceId, EventMeta, GrantEpoch, Sequence, SessionId};

/// Connection progress at the authenticated session layer.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum LinkState {
    #[default]
    Down,
    Connecting,
    Authenticating,
    Negotiating,
    Ready,
}

/// A runtime-supplied monotonic timestamp in milliseconds.
///
/// Values are meaningful only within one process lifetime. They must not be
/// persisted or compared with wall-clock time.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MonotonicMillis(u64);

impl MonotonicMillis {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// An opaque focus lease identifier, unique within a session.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LeaseId(u64);

impl LeaseId {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }
}

/// Independent replay-protection lanes for remote session traffic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SequenceLane {
    Control,
    ReliableInput,
    ReplaceableInput,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct SequenceWatermarks {
    control: Option<Sequence>,
    reliable_input: Option<Sequence>,
    replaceable_input: Option<Sequence>,
}

impl SequenceWatermarks {
    const fn get(self, lane: SequenceLane) -> Option<Sequence> {
        match lane {
            SequenceLane::Control => self.control,
            SequenceLane::ReliableInput => self.reliable_input,
            SequenceLane::ReplaceableInput => self.replaceable_input,
        }
    }

    fn commit(&mut self, lane: SequenceLane, sequence: Sequence) {
        match lane {
            SequenceLane::Control => self.control = Some(sequence),
            SequenceLane::ReliableInput => self.reliable_input = Some(sequence),
            SequenceLane::ReplaceableInput => self.replaceable_input = Some(sequence),
        }
    }
}

/// Current focus ownership for the two-device session.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum FocusState {
    #[default]
    Local,
    RequestingRemote {
        lease_id: LeaseId,
        expires_at: MonotonicMillis,
    },
    ControllingRemote {
        lease_id: LeaseId,
        expires_at: MonotonicMillis,
    },
    ControlledByRemote {
        lease_id: LeaseId,
        expires_at: MonotonicMillis,
    },
}

impl FocusState {
    #[must_use]
    pub const fn lease(self) -> Option<(LeaseId, MonotonicMillis)> {
        match self {
            Self::Local => None,
            Self::RequestingRemote {
                lease_id,
                expires_at,
            }
            | Self::ControllingRemote {
                lease_id,
                expires_at,
            }
            | Self::ControlledByRemote {
                lease_id,
                expires_at,
            } => Some((lease_id, expires_at)),
        }
    }
}

/// A trusted local or authenticated remote event delivered to the reducer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event {
    ConnectStarted,
    TransportConnected,
    AuthenticationSucceeded,
    SessionEstablished {
        session_id: SessionId,
        peer_id: DeviceId,
        local_grant_epoch: GrantEpoch,
        peer_grant_epoch: GrantEpoch,
        local_grant_allows_peer_input: bool,
        peer_grant_allows_local_input: bool,
    },
    /// A trusted local authorization update. Epochs must advance exactly once.
    LocalGrantUpdated {
        local_grant_epoch: GrantEpoch,
        local_grant_allows_peer_input: bool,
    },
    /// An authenticated update to the capabilities granted by the peer.
    PeerGrantUpdated {
        peer_grant_epoch: GrantEpoch,
        peer_grant_allows_local_input: bool,
    },
    /// Begins a local display refresh before any potentially blocking native
    /// snapshot acquisition. Focus stays gated until a candidate is published
    /// and acknowledged, or the refresh is confirmed unchanged.
    LocalTopologyRefreshStarted,
    /// Completes a refresh whose fully validated snapshot matches the active
    /// local topology.
    LocalTopologyRefreshUnchanged,
    /// Begins publication of an already-validated local revision. This
    /// transition invalidates the prior acknowledgement and quiesces any focus
    /// lease before the runtime commits and sends the candidate snapshot.
    LocalTopologyPublished {
        revision: u64,
    },
    /// Authorizes an already-decoded peer snapshot against the authenticated
    /// session and the shared control replay lane.
    RemoteTopologyReceived {
        meta: EventMeta,
        revision: u64,
    },
    /// Confirms installation of the exact local revision currently published.
    RemoteTopologyAcknowledged {
        meta: EventMeta,
        revision: u64,
    },
    LocalFocusRequested {
        lease_id: LeaseId,
        expires_at: MonotonicMillis,
        pointer_enter_required: bool,
    },
    /// An authenticated peer request to control this device.
    RemoteFocusRequested {
        meta: EventMeta,
        lease_id: LeaseId,
        expires_at: MonotonicMillis,
        pointer_enter_required: bool,
    },
    /// The peer accepted our focus request.
    RemoteFocusGranted {
        meta: EventMeta,
        lease_id: LeaseId,
        expires_at: MonotonicMillis,
        pointer_enter_required: bool,
    },
    /// Requests renewal while this device controls the peer.
    LocalLeaseRenewalRequested {
        lease_id: LeaseId,
        expires_at: MonotonicMillis,
    },
    RemoteLeaseRenewed {
        meta: EventMeta,
        lease_id: LeaseId,
        expires_at: MonotonicMillis,
        pointer_enter_required: bool,
    },
    LocalInput(InputEvent),
    LocalPointerEnter {
        position: NormalizedPosition,
    },
    RemoteInput {
        meta: EventMeta,
        lease_id: LeaseId,
        received_at: MonotonicMillis,
        input: InputEvent,
    },
    LocalReleaseAll,
    RemoteReleaseAll {
        meta: EventMeta,
        lease_id: LeaseId,
        received_at: MonotonicMillis,
    },
    RemotePointerEnter {
        meta: EventMeta,
        lease_id: LeaseId,
        received_at: MonotonicMillis,
        position: NormalizedPosition,
    },
    RemotePointerEnterAcknowledged {
        meta: EventMeta,
        lease_id: LeaseId,
    },
    LocalFocusReleased,
    RemoteFocusReleased {
        meta: EventMeta,
        lease_id: LeaseId,
    },
    TimerElapsed {
        now: MonotonicMillis,
    },
    LocalEmergencyStop,
    LocalLocked,
    LocalSleeping,
    /// Close an authenticated session so persisted configuration becomes
    /// authoritative on a fresh set of streams. Durable content may resume.
    ReconnectRequested,
    LinkDisconnected,
}

/// Why safety recovery closed the active connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DisconnectReason {
    EmergencyStop,
    LocalLocked,
    LocalSleeping,
    RequestedReconnect,
    LinkLost,
    FocusLeaseExpired,
}

/// Why an event was rejected without applying its requested action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RejectReason {
    InvalidTransition,
    NoSession,
    WrongSession,
    WrongOrigin,
    WrongGrantEpoch,
    WrongCapability,
    StaleSequence,
    PeerInputNotAuthorized,
    LocalInputNotAuthorized,
    LeaseMismatch,
    LeaseExpired,
    InvalidLease,
    LeaseDidNotExtend,
    GrantEpochDidNotIncrease,
    TopologyNotAuthorized,
    InvalidTopologyRevision,
    StaleTopologyRevision,
    TopologyRevisionMismatch,
    TopologyUnavailable,
}

/// A command for runtime adapters. Effects contain no runtime-specific types.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Effect {
    RequestRemoteFocus {
        lease_id: LeaseId,
        expires_at: MonotonicMillis,
        pointer_enter_required: bool,
    },
    GrantRemoteFocus {
        lease_id: LeaseId,
        expires_at: MonotonicMillis,
        pointer_enter_required: bool,
    },
    RenewRemoteFocus {
        lease_id: LeaseId,
        expires_at: MonotonicMillis,
    },
    ReleaseRemoteFocus {
        lease_id: LeaseId,
    },
    ArmFocusLease {
        lease_id: LeaseId,
        expires_at: MonotonicMillis,
    },
    CancelFocusLease,
    /// The runtime may install the separately validated topology payload, then
    /// send an acknowledgement for this revision.
    AcceptRemoteTopology {
        revision: u64,
    },
    AcknowledgeRemoteTopology {
        revision: u64,
    },
    LocalTopologyReady {
        revision: u64,
    },
    SendInput {
        lease_id: LeaseId,
        input: InputEvent,
    },
    SendPointerEnter {
        lease_id: LeaseId,
        position: NormalizedPosition,
    },
    AcknowledgePointerEnter {
        lease_id: LeaseId,
    },
    SendReleaseAll {
        lease_id: LeaseId,
    },
    InjectInput(InputEvent),
    /// Releases presses injected on this device. This effect is always emitted
    /// during recovery, even when `releases` is empty.
    ReleaseInjectedInput {
        releases: Vec<InputEvent>,
    },
    /// Best-effort releases for presses previously routed to the peer.
    ReleaseRoutedInput {
        lease_id: LeaseId,
        releases: Vec<InputEvent>,
    },
    RestoreLocalOwnership,
    /// Stop session-bound content work while retaining durable/restartable
    /// state for a newly authenticated session.
    SuspendContentOperations,
    /// Cancel content work and discard durable partial state.
    AbortContentOperations,
    Disconnect {
        reason: DisconnectReason,
    },
    Rejected {
        reason: RejectReason,
    },
}

/// The pure session reducer.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum PointerEnterState {
    #[default]
    NotRequired,
    Awaiting,
    Ready,
}

impl PointerEnterState {
    const fn new(required: bool) -> Self {
        if required {
            Self::Awaiting
        } else {
            Self::NotRequired
        }
    }

    const fn is_required(self) -> bool {
        !matches!(self, Self::NotRequired)
    }

    const fn is_ready(self) -> bool {
        matches!(self, Self::NotRequired | Self::Ready)
    }
}

/// The pure session reducer.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SessionCore {
    link: LinkState,
    focus: FocusState,
    session_id: Option<SessionId>,
    peer_id: Option<DeviceId>,
    local_grant_epoch: Option<GrantEpoch>,
    peer_grant_epoch: Option<GrantEpoch>,
    remote_sequences: SequenceWatermarks,
    local_grant_allows_peer_input: bool,
    peer_grant_allows_local_input: bool,
    published_topology_revision: Option<u64>,
    acknowledged_topology_revision: Option<u64>,
    local_topology_snapshot_pending: bool,
    remote_topology_revision: Option<u64>,
    injected_pressed: PressedState,
    routed_pressed: PressedState,
    outbound_pointer_enter: PointerEnterState,
    inbound_pointer_enter: PointerEnterState,
}

impl SessionCore {
    #[must_use]
    pub const fn link_state(&self) -> LinkState {
        self.link
    }

    #[must_use]
    pub const fn focus_state(&self) -> FocusState {
        self.focus
    }

    #[must_use]
    pub const fn session_id(&self) -> Option<SessionId> {
        self.session_id
    }

    #[must_use]
    pub const fn peer_id(&self) -> Option<DeviceId> {
        self.peer_id
    }

    #[must_use]
    pub const fn local_grant_epoch(&self) -> Option<GrantEpoch> {
        self.local_grant_epoch
    }

    #[must_use]
    pub const fn peer_grant_epoch(&self) -> Option<GrantEpoch> {
        self.peer_grant_epoch
    }

    #[must_use]
    pub const fn last_remote_sequence(&self, lane: SequenceLane) -> Option<Sequence> {
        self.remote_sequences.get(lane)
    }

    #[must_use]
    pub const fn local_grant_allows_peer_input(&self) -> bool {
        self.local_grant_allows_peer_input
    }

    #[must_use]
    pub const fn peer_grant_allows_local_input(&self) -> bool {
        self.peer_grant_allows_local_input
    }

    #[must_use]
    pub const fn published_topology_revision(&self) -> Option<u64> {
        self.published_topology_revision
    }

    #[must_use]
    pub const fn acknowledged_topology_revision(&self) -> Option<u64> {
        self.acknowledged_topology_revision
    }

    #[must_use]
    pub fn local_topology_refresh_pending(&self) -> bool {
        self.local_topology_snapshot_pending
            || self.published_topology_revision != self.acknowledged_topology_revision
    }

    #[must_use]
    pub const fn remote_topology_revision(&self) -> Option<u64> {
        self.remote_topology_revision
    }

    #[must_use]
    pub fn injected_input_is_clear(&self) -> bool {
        self.injected_pressed.is_empty()
    }

    #[must_use]
    pub fn routed_input_is_clear(&self) -> bool {
        self.routed_pressed.is_empty()
    }

    /// Whether native suppression may begin for this outbound lease.
    #[must_use]
    pub const fn local_pointer_routing_ready(&self) -> bool {
        matches!(self.focus, FocusState::ControllingRemote { .. })
            && self.outbound_pointer_enter.is_ready()
    }

    #[must_use]
    pub const fn outbound_pointer_enter_required(&self) -> bool {
        self.outbound_pointer_enter.is_required()
    }

    /// Applies one event and returns deterministic effects in execution order.
    ///
    /// Recovery transitions clear leases and pressed-state collections before
    /// constructing any effects. A runtime can therefore execute the returned
    /// local release and restore effects synchronously, then perform the final
    /// disconnect command.
    #[must_use]
    #[allow(
        clippy::too_many_lines,
        reason = "one exhaustive match keeps safety transition ordering auditable"
    )]
    pub fn handle(&mut self, event: Event) -> Vec<Effect> {
        match event {
            Event::ConnectStarted if self.link == LinkState::Down => {
                self.link = LinkState::Connecting;
                Vec::new()
            }
            Event::TransportConnected if self.link == LinkState::Connecting => {
                self.link = LinkState::Authenticating;
                Vec::new()
            }
            Event::AuthenticationSucceeded if self.link == LinkState::Authenticating => {
                self.link = LinkState::Negotiating;
                Vec::new()
            }
            Event::SessionEstablished {
                session_id,
                peer_id,
                local_grant_epoch,
                peer_grant_epoch,
                local_grant_allows_peer_input,
                peer_grant_allows_local_input,
            } if self.link == LinkState::Negotiating => {
                self.link = LinkState::Ready;
                self.focus = FocusState::Local;
                self.session_id = Some(session_id);
                self.peer_id = Some(peer_id);
                self.local_grant_epoch = Some(local_grant_epoch);
                self.peer_grant_epoch = Some(peer_grant_epoch);
                self.remote_sequences = SequenceWatermarks::default();
                self.local_grant_allows_peer_input = local_grant_allows_peer_input;
                self.peer_grant_allows_local_input = peer_grant_allows_local_input;
                self.published_topology_revision = None;
                self.acknowledged_topology_revision = None;
                self.local_topology_snapshot_pending = false;
                self.remote_topology_revision = None;
                self.clear_pointer_enter_state();
                Vec::new()
            }
            Event::LocalGrantUpdated {
                local_grant_epoch,
                local_grant_allows_peer_input,
            } => self.update_local_grant(local_grant_epoch, local_grant_allows_peer_input),
            Event::PeerGrantUpdated {
                peer_grant_epoch,
                peer_grant_allows_local_input,
            } => self.update_peer_grant(peer_grant_epoch, peer_grant_allows_local_input),
            Event::LocalTopologyRefreshStarted => self.begin_local_topology_refresh(),
            Event::LocalTopologyRefreshUnchanged => self.finish_unchanged_local_topology_refresh(),
            Event::LocalTopologyPublished { revision } => self.publish_local_topology(revision),
            Event::RemoteTopologyReceived { meta, revision } => {
                self.accept_remote_topology(meta, revision)
            }
            Event::RemoteTopologyAcknowledged { meta, revision } => {
                self.acknowledge_local_topology(meta, revision)
            }
            Event::LocalFocusRequested {
                lease_id,
                expires_at: _,
                pointer_enter_required: _,
            } if lease_id.is_zero() => rejected(RejectReason::InvalidLease),
            Event::LocalFocusRequested { .. } if !self.peer_grant_allows_local_input => {
                rejected(RejectReason::LocalInputNotAuthorized)
            }
            Event::LocalFocusRequested { .. } if self.remote_topology_revision.is_none() => {
                rejected(RejectReason::TopologyUnavailable)
            }
            Event::LocalFocusRequested { .. } if self.local_topology_refresh_pending() => {
                rejected(RejectReason::TopologyUnavailable)
            }
            Event::LocalFocusRequested {
                lease_id,
                expires_at,
                pointer_enter_required,
            } if self.link == LinkState::Ready && self.focus == FocusState::Local => {
                self.outbound_pointer_enter = PointerEnterState::new(pointer_enter_required);
                self.focus = FocusState::RequestingRemote {
                    lease_id,
                    expires_at,
                };
                vec![
                    Effect::RequestRemoteFocus {
                        lease_id,
                        expires_at,
                        pointer_enter_required,
                    },
                    Effect::ArmFocusLease {
                        lease_id,
                        expires_at,
                    },
                ]
            }
            Event::RemoteFocusRequested {
                meta,
                lease_id,
                expires_at,
                pointer_enter_required,
            } => {
                self.handle_remote_focus_request(meta, lease_id, expires_at, pointer_enter_required)
            }
            Event::RemoteFocusGranted {
                meta,
                lease_id,
                expires_at,
                pointer_enter_required,
            } => {
                if let Err(reason) = self.validate_remote_meta(&meta, SequenceLane::Control) {
                    return rejected(reason);
                }
                if lease_id.is_zero() {
                    return rejected(RejectReason::InvalidLease);
                }
                if !self.peer_grant_allows_local_input {
                    return rejected(RejectReason::LocalInputNotAuthorized);
                }
                if self.focus == FocusState::Local {
                    self.commit_remote_sequence(SequenceLane::Control, meta.sequence());
                    return Vec::new();
                }
                let accepted = matches!(
                    self.focus,
                    FocusState::RequestingRemote {
                        lease_id: expected, ..
                    } if expected == lease_id
                );
                if !accepted {
                    return rejected(RejectReason::LeaseMismatch);
                }
                if pointer_enter_required != self.outbound_pointer_enter.is_required() {
                    return rejected(RejectReason::InvalidTransition);
                }
                self.commit_remote_sequence(SequenceLane::Control, meta.sequence());
                self.outbound_pointer_enter = PointerEnterState::new(pointer_enter_required);
                self.focus = FocusState::ControllingRemote {
                    lease_id,
                    expires_at,
                };
                vec![Effect::ArmFocusLease {
                    lease_id,
                    expires_at,
                }]
            }
            Event::LocalLeaseRenewalRequested {
                lease_id,
                expires_at,
            } => self.request_lease_renewal(lease_id, expires_at),
            Event::RemoteLeaseRenewed {
                meta,
                lease_id,
                expires_at,
                pointer_enter_required,
            } => {
                self.handle_remote_lease_renewal(meta, lease_id, expires_at, pointer_enter_required)
            }
            Event::LocalInput(input) => match self.focus {
                FocusState::ControllingRemote { .. } if !self.peer_grant_allows_local_input => {
                    rejected(RejectReason::LocalInputNotAuthorized)
                }
                FocusState::ControllingRemote { lease_id, .. } => {
                    if !self.outbound_pointer_enter.is_ready() {
                        return rejected(RejectReason::InvalidTransition);
                    }
                    self.routed_pressed.apply(&input);
                    vec![Effect::SendInput { lease_id, input }]
                }
                _ => Vec::new(),
            },
            Event::LocalPointerEnter { position } => {
                let FocusState::ControllingRemote { lease_id, .. } = self.focus else {
                    return rejected(RejectReason::InvalidTransition);
                };
                if !matches!(self.outbound_pointer_enter, PointerEnterState::Awaiting) {
                    return rejected(RejectReason::InvalidTransition);
                }
                vec![Effect::SendPointerEnter { lease_id, position }]
            }
            Event::RemoteInput {
                meta,
                lease_id,
                received_at,
                input,
            } => self.handle_remote_input(meta, lease_id, received_at, input),
            Event::LocalReleaseAll => self.release_all_routed_input(),
            Event::RemoteReleaseAll {
                meta,
                lease_id,
                received_at,
            } => self.handle_remote_release_all(meta, lease_id, received_at),
            Event::RemotePointerEnter {
                meta,
                lease_id,
                received_at,
                position,
            } => self.handle_remote_pointer_enter(meta, lease_id, received_at, position),
            Event::RemotePointerEnterAcknowledged { meta, lease_id } => {
                self.handle_remote_pointer_enter_ack(meta, lease_id)
            }
            Event::LocalFocusReleased if self.focus != FocusState::Local => {
                self.release_focus(true)
            }
            Event::RemoteFocusReleased { meta, lease_id } => {
                if let Err(reason) = self.validate_remote_meta(&meta, SequenceLane::Control) {
                    return rejected(reason);
                }
                if lease_id.is_zero() {
                    return rejected(RejectReason::InvalidLease);
                }
                if self.focus == FocusState::Local {
                    self.commit_remote_sequence(SequenceLane::Control, meta.sequence());
                    return Vec::new();
                }
                if self
                    .focus
                    .lease()
                    .is_none_or(|(active, _)| active != lease_id)
                {
                    return rejected(RejectReason::LeaseMismatch);
                }
                self.commit_remote_sequence(SequenceLane::Control, meta.sequence());
                self.release_focus(false)
            }
            Event::TimerElapsed { now } => {
                if self
                    .focus
                    .lease()
                    .is_some_and(|(_, expires_at)| now >= expires_at)
                {
                    self.recover(DisconnectReason::FocusLeaseExpired)
                } else {
                    Vec::new()
                }
            }
            Event::LocalEmergencyStop => self.recover(DisconnectReason::EmergencyStop),
            Event::LocalLocked => self.recover(DisconnectReason::LocalLocked),
            Event::LocalSleeping => self.recover(DisconnectReason::LocalSleeping),
            Event::ReconnectRequested => self.recover(DisconnectReason::RequestedReconnect),
            Event::LinkDisconnected => self.recover(DisconnectReason::LinkLost),
            Event::ConnectStarted
            | Event::TransportConnected
            | Event::AuthenticationSucceeded
            | Event::SessionEstablished { .. }
            | Event::LocalFocusRequested { .. }
            | Event::LocalFocusReleased => rejected(RejectReason::InvalidTransition),
        }
    }

    fn update_local_grant(
        &mut self,
        local_grant_epoch: GrantEpoch,
        local_grant_allows_peer_input: bool,
    ) -> Vec<Effect> {
        let Some(current) = self.local_grant_epoch else {
            return rejected(RejectReason::NoSession);
        };
        if !is_next_epoch(current, local_grant_epoch) {
            return rejected(RejectReason::GrantEpochDidNotIncrease);
        }

        self.local_grant_epoch = Some(local_grant_epoch);
        self.remote_sequences = SequenceWatermarks::default();
        self.local_grant_allows_peer_input = local_grant_allows_peer_input;
        self.published_topology_revision = None;
        self.acknowledged_topology_revision = None;
        self.local_topology_snapshot_pending = false;

        if self.focus != FocusState::Local
            || !self.injected_pressed.is_empty()
            || !self.routed_pressed.is_empty()
        {
            self.release_lease_for_grant_change()
        } else {
            self.clear_pointer_enter_state();
            Vec::new()
        }
    }

    fn update_peer_grant(
        &mut self,
        peer_grant_epoch: GrantEpoch,
        peer_grant_allows_local_input: bool,
    ) -> Vec<Effect> {
        let Some(current) = self.peer_grant_epoch else {
            return rejected(RejectReason::NoSession);
        };
        if !is_next_epoch(current, peer_grant_epoch) {
            return rejected(RejectReason::GrantEpochDidNotIncrease);
        }

        self.peer_grant_epoch = Some(peer_grant_epoch);
        self.peer_grant_allows_local_input = peer_grant_allows_local_input;
        self.remote_topology_revision = None;

        if self.focus != FocusState::Local
            || !self.injected_pressed.is_empty()
            || !self.routed_pressed.is_empty()
        {
            self.release_lease_for_grant_change()
        } else {
            self.clear_pointer_enter_state();
            Vec::new()
        }
    }

    fn release_lease_for_grant_change(&mut self) -> Vec<Effect> {
        let releases = self.injected_pressed.take_forced_releases();
        let _ = self.routed_pressed.take_forced_releases();
        self.focus = FocusState::Local;
        self.clear_pointer_enter_state();
        vec![
            Effect::ReleaseInjectedInput { releases },
            Effect::RestoreLocalOwnership,
            Effect::CancelFocusLease,
        ]
    }

    fn begin_local_topology_refresh(&mut self) -> Vec<Effect> {
        if self.link != LinkState::Ready {
            return rejected(RejectReason::InvalidTransition);
        }
        if self.local_topology_snapshot_pending {
            return Vec::new();
        }
        self.local_topology_snapshot_pending = true;
        if self.focus == FocusState::Local {
            Vec::new()
        } else {
            self.release_focus(true)
        }
    }

    fn finish_unchanged_local_topology_refresh(&mut self) -> Vec<Effect> {
        if self.link != LinkState::Ready || !self.local_topology_snapshot_pending {
            return rejected(RejectReason::InvalidTransition);
        }
        self.local_topology_snapshot_pending = false;
        Vec::new()
    }

    fn publish_local_topology(&mut self, revision: u64) -> Vec<Effect> {
        if self.link != LinkState::Ready {
            return rejected(RejectReason::InvalidTransition);
        }
        if !self.local_grant_allows_peer_input {
            return rejected(RejectReason::TopologyNotAuthorized);
        }
        if revision == 0 {
            return rejected(RejectReason::InvalidTopologyRevision);
        }
        if self
            .published_topology_revision
            .is_some_and(|published| revision <= published)
        {
            return rejected(RejectReason::StaleTopologyRevision);
        }
        self.published_topology_revision = Some(revision);
        self.acknowledged_topology_revision = None;
        self.local_topology_snapshot_pending = false;
        if self.focus == FocusState::Local {
            Vec::new()
        } else {
            self.release_focus(true)
        }
    }

    fn accept_remote_topology(&mut self, meta: EventMeta, revision: u64) -> Vec<Effect> {
        if let Err(reason) = self.validate_remote_meta(&meta, SequenceLane::Control) {
            return rejected(reason);
        }
        if !self.peer_grant_allows_local_input {
            return rejected(RejectReason::TopologyNotAuthorized);
        }
        if revision == 0 {
            return rejected(RejectReason::InvalidTopologyRevision);
        }
        if self
            .remote_topology_revision
            .is_some_and(|installed| revision <= installed)
        {
            return rejected(RejectReason::StaleTopologyRevision);
        }
        let mut effects = if self.focus == FocusState::Local {
            Vec::new()
        } else {
            self.release_focus(true)
        };
        self.commit_remote_sequence(SequenceLane::Control, meta.sequence());
        self.remote_topology_revision = Some(revision);
        effects.extend([
            Effect::AcceptRemoteTopology { revision },
            Effect::AcknowledgeRemoteTopology { revision },
        ]);
        effects
    }

    fn acknowledge_local_topology(&mut self, meta: EventMeta, revision: u64) -> Vec<Effect> {
        if let Err(reason) = self.validate_remote_meta(&meta, SequenceLane::Control) {
            return rejected(reason);
        }
        if !self.local_grant_allows_peer_input {
            return rejected(RejectReason::TopologyNotAuthorized);
        }
        if self.focus != FocusState::Local {
            return rejected(RejectReason::InvalidTransition);
        }
        if revision == 0 {
            return rejected(RejectReason::InvalidTopologyRevision);
        }
        if self.published_topology_revision != Some(revision) {
            return rejected(RejectReason::TopologyRevisionMismatch);
        }
        self.commit_remote_sequence(SequenceLane::Control, meta.sequence());
        if self.acknowledged_topology_revision == Some(revision) {
            return Vec::new();
        }
        self.acknowledged_topology_revision = Some(revision);
        vec![Effect::LocalTopologyReady { revision }]
    }

    fn handle_remote_input(
        &mut self,
        meta: EventMeta,
        lease_id: LeaseId,
        received_at: MonotonicMillis,
        input: InputEvent,
    ) -> Vec<Effect> {
        let lane = input_sequence_lane(input);
        if let Err(reason) = self.validate_remote_identity(&meta) {
            return rejected(reason);
        }
        if lease_id.is_zero() {
            return rejected(RejectReason::InvalidLease);
        }
        if !self.local_grant_allows_peer_input {
            return rejected(RejectReason::PeerInputNotAuthorized);
        }
        if !matches!(
            self.focus,
            FocusState::ControlledByRemote {
                lease_id: active,
                ..
            } if active == lease_id
        ) {
            return Vec::new();
        }
        if let Err(reason) = self.validate_remote_sequence(&meta, lane) {
            return rejected(reason);
        }
        if !self.inbound_pointer_enter.is_ready() {
            return rejected(RejectReason::InvalidTransition);
        }
        if self.acknowledged_topology_revision.is_none() {
            return rejected(RejectReason::TopologyUnavailable);
        }

        match self.focus {
            FocusState::ControlledByRemote { expires_at, .. } if received_at >= expires_at => {
                self.recover(DisconnectReason::FocusLeaseExpired)
            }
            FocusState::ControlledByRemote { .. } => {
                self.commit_remote_sequence(lane, meta.sequence());
                self.injected_pressed.apply(&input);
                vec![Effect::InjectInput(input)]
            }
            _ => Vec::new(),
        }
    }

    fn handle_remote_focus_request(
        &mut self,
        meta: EventMeta,
        lease_id: LeaseId,
        expires_at: MonotonicMillis,
        pointer_enter_required: bool,
    ) -> Vec<Effect> {
        if let Err(reason) = self.validate_remote_meta(&meta, SequenceLane::Control) {
            return rejected(reason);
        }
        if lease_id.is_zero() {
            return rejected(RejectReason::InvalidLease);
        }
        if !self.local_grant_allows_peer_input {
            return rejected(RejectReason::PeerInputNotAuthorized);
        }
        if self.link != LinkState::Ready {
            return rejected(RejectReason::InvalidTransition);
        }
        if self.local_topology_refresh_pending()
            || self.published_topology_revision.is_none()
            || self.acknowledged_topology_revision != self.published_topology_revision
        {
            self.commit_remote_sequence(SequenceLane::Control, meta.sequence());
            return vec![Effect::ReleaseRemoteFocus { lease_id }];
        }

        let renewal = match self.focus {
            FocusState::Local => false,
            FocusState::ControlledByRemote {
                lease_id: active,
                expires_at: current_expiry,
            } if active == lease_id => {
                if expires_at <= current_expiry {
                    return rejected(RejectReason::LeaseDidNotExtend);
                }
                if pointer_enter_required != self.inbound_pointer_enter.is_required() {
                    return rejected(RejectReason::InvalidTransition);
                }
                true
            }
            _ => return rejected(RejectReason::LeaseMismatch),
        };

        self.commit_remote_sequence(SequenceLane::Control, meta.sequence());
        if !renewal {
            self.inbound_pointer_enter = PointerEnterState::new(pointer_enter_required);
        }
        self.focus = FocusState::ControlledByRemote {
            lease_id,
            expires_at,
        };
        vec![
            Effect::GrantRemoteFocus {
                lease_id,
                expires_at,
                pointer_enter_required,
            },
            Effect::ArmFocusLease {
                lease_id,
                expires_at,
            },
        ]
    }

    fn handle_remote_pointer_enter(
        &mut self,
        meta: EventMeta,
        lease_id: LeaseId,
        received_at: MonotonicMillis,
        position: NormalizedPosition,
    ) -> Vec<Effect> {
        if let Err(reason) = self.validate_remote_identity(&meta) {
            return rejected(reason);
        }
        if !self.local_grant_allows_peer_input {
            return rejected(RejectReason::PeerInputNotAuthorized);
        }
        if lease_id.is_zero() {
            return rejected(RejectReason::InvalidLease);
        }
        if !matches!(
            self.focus,
            FocusState::ControlledByRemote {
                lease_id: active,
                ..
            } if active == lease_id
        ) {
            return Vec::new();
        }
        if let Err(reason) = self.validate_remote_sequence(&meta, SequenceLane::ReliableInput) {
            return rejected(reason);
        }
        if !matches!(self.inbound_pointer_enter, PointerEnterState::Awaiting) {
            return rejected(RejectReason::InvalidTransition);
        }
        match self.focus {
            FocusState::ControlledByRemote { expires_at, .. } if received_at >= expires_at => {
                self.recover(DisconnectReason::FocusLeaseExpired)
            }
            FocusState::ControlledByRemote { .. } => {
                self.commit_remote_sequence(SequenceLane::ReliableInput, meta.sequence());
                self.inbound_pointer_enter = PointerEnterState::Ready;
                vec![
                    Effect::InjectInput(InputEvent::PointerMotion { position }),
                    Effect::AcknowledgePointerEnter { lease_id },
                ]
            }
            _ => Vec::new(),
        }
    }

    fn handle_remote_pointer_enter_ack(
        &mut self,
        meta: EventMeta,
        lease_id: LeaseId,
    ) -> Vec<Effect> {
        if let Err(reason) = self.validate_remote_meta(&meta, SequenceLane::Control) {
            return rejected(reason);
        }
        if self.focus == FocusState::Local {
            self.commit_remote_sequence(SequenceLane::Control, meta.sequence());
            return Vec::new();
        }
        let FocusState::ControllingRemote {
            lease_id: active, ..
        } = self.focus
        else {
            return rejected(RejectReason::InvalidTransition);
        };
        if active != lease_id {
            return rejected(RejectReason::LeaseMismatch);
        }
        if !matches!(self.outbound_pointer_enter, PointerEnterState::Awaiting) {
            return rejected(RejectReason::InvalidTransition);
        }
        self.commit_remote_sequence(SequenceLane::Control, meta.sequence());
        self.outbound_pointer_enter = PointerEnterState::Ready;
        Vec::new()
    }

    fn request_lease_renewal(&self, lease_id: LeaseId, expires_at: MonotonicMillis) -> Vec<Effect> {
        if lease_id.is_zero() {
            return rejected(RejectReason::InvalidLease);
        }
        if !self.peer_grant_allows_local_input {
            return rejected(RejectReason::LocalInputNotAuthorized);
        }
        match self.focus {
            FocusState::ControllingRemote {
                lease_id: active,
                expires_at: current_expiry,
            } if active == lease_id && expires_at > current_expiry => {
                vec![Effect::RenewRemoteFocus {
                    lease_id,
                    expires_at,
                }]
            }
            FocusState::ControllingRemote {
                lease_id: active, ..
            } if active != lease_id => rejected(RejectReason::LeaseMismatch),
            FocusState::ControllingRemote { .. } => rejected(RejectReason::LeaseDidNotExtend),
            _ => rejected(RejectReason::InvalidTransition),
        }
    }

    fn handle_remote_lease_renewal(
        &mut self,
        meta: EventMeta,
        lease_id: LeaseId,
        expires_at: MonotonicMillis,
        pointer_enter_required: bool,
    ) -> Vec<Effect> {
        if let Err(reason) = self.validate_remote_meta(&meta, SequenceLane::Control) {
            return rejected(reason);
        }
        if lease_id.is_zero() {
            return rejected(RejectReason::InvalidLease);
        }
        if !self.peer_grant_allows_local_input {
            return rejected(RejectReason::LocalInputNotAuthorized);
        }
        if self.focus == FocusState::Local {
            self.commit_remote_sequence(SequenceLane::Control, meta.sequence());
            return Vec::new();
        }
        if pointer_enter_required != self.outbound_pointer_enter.is_required() {
            return rejected(RejectReason::InvalidTransition);
        }
        let FocusState::ControllingRemote {
            lease_id: active,
            expires_at: current_expiry,
        } = self.focus
        else {
            return rejected(RejectReason::InvalidTransition);
        };
        if active != lease_id {
            return rejected(RejectReason::LeaseMismatch);
        }
        if expires_at <= current_expiry {
            return rejected(RejectReason::LeaseDidNotExtend);
        }

        self.commit_remote_sequence(SequenceLane::Control, meta.sequence());
        self.focus = FocusState::ControllingRemote {
            lease_id,
            expires_at,
        };
        vec![Effect::ArmFocusLease {
            lease_id,
            expires_at,
        }]
    }

    fn release_all_routed_input(&mut self) -> Vec<Effect> {
        let FocusState::ControllingRemote { lease_id, .. } = self.focus else {
            return rejected(RejectReason::InvalidTransition);
        };
        let releases = self.routed_pressed.take_forced_releases();
        vec![
            Effect::ReleaseRoutedInput { lease_id, releases },
            Effect::SendReleaseAll { lease_id },
        ]
    }

    fn handle_remote_release_all(
        &mut self,
        meta: EventMeta,
        lease_id: LeaseId,
        received_at: MonotonicMillis,
    ) -> Vec<Effect> {
        if let Err(reason) = self.validate_remote_identity(&meta) {
            return rejected(reason);
        }
        if lease_id.is_zero() {
            return rejected(RejectReason::InvalidLease);
        }
        if !self.local_grant_allows_peer_input {
            return rejected(RejectReason::PeerInputNotAuthorized);
        }
        if !matches!(
            self.focus,
            FocusState::ControlledByRemote {
                lease_id: active,
                ..
            } if active == lease_id
        ) {
            return Vec::new();
        }
        if let Err(reason) = self.validate_remote_sequence(&meta, SequenceLane::ReliableInput) {
            return rejected(reason);
        }
        match self.focus {
            FocusState::ControlledByRemote { expires_at, .. } if received_at >= expires_at => {
                self.recover(DisconnectReason::FocusLeaseExpired)
            }
            FocusState::ControlledByRemote { .. } => {
                self.commit_remote_sequence(SequenceLane::ReliableInput, meta.sequence());
                vec![Effect::ReleaseInjectedInput {
                    releases: self.injected_pressed.take_forced_releases(),
                }]
            }
            _ => Vec::new(),
        }
    }

    fn validate_remote_meta(
        &self,
        meta: &EventMeta,
        lane: SequenceLane,
    ) -> Result<(), RejectReason> {
        self.validate_remote_identity(meta)?;
        self.validate_remote_sequence(meta, lane)
    }

    fn validate_remote_sequence(
        &self,
        meta: &EventMeta,
        lane: SequenceLane,
    ) -> Result<(), RejectReason> {
        if self
            .remote_sequences
            .get(lane)
            .is_some_and(|last| meta.sequence() <= last)
        {
            return Err(RejectReason::StaleSequence);
        }
        Ok(())
    }

    fn validate_remote_identity(&self, meta: &EventMeta) -> Result<(), RejectReason> {
        let Some(session_id) = self.session_id else {
            return Err(RejectReason::NoSession);
        };
        if meta.session_id() != session_id {
            return Err(RejectReason::WrongSession);
        }
        if Some(meta.origin()) != self.peer_id {
            return Err(RejectReason::WrongOrigin);
        }
        if Some(meta.grant_epoch()) != self.local_grant_epoch {
            return Err(RejectReason::WrongGrantEpoch);
        }
        if meta.capability() != Capability::REMOTE_INPUT {
            return Err(RejectReason::WrongCapability);
        }
        Ok(())
    }

    fn commit_remote_sequence(&mut self, lane: SequenceLane, sequence: Sequence) {
        self.remote_sequences.commit(lane, sequence);
    }

    fn release_focus(&mut self, notify_peer: bool) -> Vec<Effect> {
        let previous_focus = self.focus;
        let Some((lease_id, _)) = previous_focus.lease() else {
            return rejected(RejectReason::InvalidTransition);
        };
        let local_releases = self.injected_pressed.take_forced_releases();
        let remote_releases = self.routed_pressed.take_forced_releases();
        self.focus = FocusState::Local;
        self.clear_pointer_enter_state();

        let mut effects = vec![
            Effect::ReleaseInjectedInput {
                releases: local_releases,
            },
            Effect::ReleaseRoutedInput {
                lease_id,
                releases: remote_releases,
            },
        ];
        if notify_peer && matches!(previous_focus, FocusState::ControllingRemote { .. }) {
            effects.push(Effect::SendReleaseAll { lease_id });
        }
        effects.extend([Effect::RestoreLocalOwnership, Effect::CancelFocusLease]);
        if notify_peer {
            effects.push(Effect::ReleaseRemoteFocus { lease_id });
        }
        effects
    }

    fn recover(&mut self, reason: DisconnectReason) -> Vec<Effect> {
        // Clear safety-critical state before returning any command that can
        // involve the peer or an asynchronous runtime.
        let local_releases = self.injected_pressed.take_forced_releases();
        let remote_releases = self.routed_pressed.take_forced_releases();
        let lease_id = self.focus.lease().map(|(lease_id, _)| lease_id);
        self.focus = FocusState::Local;
        self.link = LinkState::Down;
        self.session_id = None;
        self.peer_id = None;
        self.local_grant_epoch = None;
        self.peer_grant_epoch = None;
        self.remote_sequences = SequenceWatermarks::default();
        self.local_grant_allows_peer_input = false;
        self.peer_grant_allows_local_input = false;
        self.published_topology_revision = None;
        self.acknowledged_topology_revision = None;
        self.local_topology_snapshot_pending = false;
        self.remote_topology_revision = None;
        self.clear_pointer_enter_state();

        let mut effects = vec![Effect::ReleaseInjectedInput {
            releases: local_releases,
        }];
        if let Some(lease_id) = lease_id {
            effects.push(Effect::ReleaseRoutedInput {
                lease_id,
                releases: remote_releases,
            });
        }
        effects.extend([Effect::RestoreLocalOwnership, Effect::CancelFocusLease]);
        effects.push(
            if matches!(
                reason,
                DisconnectReason::LinkLost | DisconnectReason::RequestedReconnect
            ) {
                Effect::SuspendContentOperations
            } else {
                Effect::AbortContentOperations
            },
        );
        effects.push(Effect::Disconnect { reason });
        effects
    }

    fn clear_pointer_enter_state(&mut self) {
        self.outbound_pointer_enter = PointerEnterState::NotRequired;
        self.inbound_pointer_enter = PointerEnterState::NotRequired;
    }
}

const fn input_sequence_lane(input: InputEvent) -> SequenceLane {
    match input {
        InputEvent::Key { .. } | InputEvent::PointerButton { .. } => SequenceLane::ReliableInput,
        InputEvent::PointerMotion { .. }
        | InputEvent::PointerDelta { .. }
        | InputEvent::Scroll { .. } => SequenceLane::ReplaceableInput,
    }
}

fn rejected(reason: RejectReason) -> Vec<Effect> {
    vec![Effect::Rejected { reason }]
}

const fn is_next_epoch(current: GrantEpoch, next: GrantEpoch) -> bool {
    match current.get().checked_add(1) {
        Some(expected) => next.get() == expected,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use nodavo_input::{
        DisplayId, HidUsage, KEYBOARD_PAGE, KeyState, Modifiers, NormalizedAxis,
        NormalizedPosition, PointerDelta,
    };
    use nodavo_protocol::{Capability, DeviceId};

    use super::*;

    fn ready_core(
        local_grant_allows_peer_input: bool,
        peer_grant_allows_local_input: bool,
    ) -> (SessionCore, SessionId, GrantEpoch) {
        let mut core = SessionCore::default();
        assert!(core.handle(Event::ConnectStarted).is_empty());
        assert!(core.handle(Event::TransportConnected).is_empty());
        assert!(core.handle(Event::AuthenticationSucceeded).is_empty());
        let session = SessionId::new([7; 16]);
        let epoch = GrantEpoch::new(3);
        assert!(
            core.handle(Event::SessionEstablished {
                session_id: session,
                peer_id: DeviceId::new([9; 32]),
                local_grant_epoch: epoch,
                peer_grant_epoch: GrantEpoch::new(8),
                local_grant_allows_peer_input,
                peer_grant_allows_local_input,
            })
            .is_empty()
        );
        // Most focus tests exercise lease/input behavior rather than topology
        // negotiation. Production sessions reach this state only after the
        // authenticated snapshot/ack exchange tested separately below.
        core.published_topology_revision = Some(1);
        core.acknowledged_topology_revision = Some(1);
        core.remote_topology_revision = Some(1);
        (core, session, epoch)
    }

    fn meta(session: SessionId, epoch: GrantEpoch, sequence: u64) -> EventMeta {
        EventMeta::new(
            session,
            DeviceId::new([9; 32]),
            Sequence::new(sequence),
            epoch,
            Capability::REMOTE_INPUT,
        )
    }

    fn key(usage_id: u16, state: KeyState) -> InputEvent {
        InputEvent::Key {
            usage: HidUsage::new(KEYBOARD_PAGE, usage_id),
            state,
            modifiers: Modifiers::empty(),
        }
    }

    fn key_down(usage_id: u16) -> InputEvent {
        key(usage_id, KeyState::Pressed)
    }

    fn pointer_motion() -> InputEvent {
        InputEvent::PointerMotion {
            position: NormalizedPosition::new(
                DisplayId::new(1),
                NormalizedAxis::from_bits(2),
                NormalizedAxis::from_bits(3),
            ),
        }
    }

    fn accept_peer_focus(
        core: &mut SessionCore,
        session: SessionId,
        epoch: GrantEpoch,
        sequence: u64,
        lease_id: LeaseId,
    ) {
        assert_eq!(
            core.handle(Event::RemoteFocusRequested {
                meta: meta(session, epoch, sequence),
                lease_id,
                expires_at: MonotonicMillis::new(100),
                pointer_enter_required: false,
            }),
            vec![
                Effect::GrantRemoteFocus {
                    lease_id,
                    expires_at: MonotonicMillis::new(100),
                    pointer_enter_required: false,
                },
                Effect::ArmFocusLease {
                    lease_id,
                    expires_at: MonotonicMillis::new(100),
                },
            ]
        );
    }

    #[test]
    fn sequence_lanes_are_independent_and_commit_only_after_validation() {
        let (mut core, session, epoch) = ready_core(true, true);
        let lease = LeaseId::new(11);
        accept_peer_focus(&mut core, session, epoch, 10, lease);

        assert_eq!(
            core.handle(Event::RemoteInput {
                meta: meta(session, epoch, 50),
                lease_id: LeaseId::new(99),
                received_at: MonotonicMillis::new(50),
                input: key_down(4),
            }),
            Vec::new()
        );
        assert_eq!(core.last_remote_sequence(SequenceLane::ReliableInput), None);

        assert_eq!(
            core.handle(Event::RemoteInput {
                meta: meta(session, epoch, 50),
                lease_id: lease,
                received_at: MonotonicMillis::new(50),
                input: key_down(4),
            }),
            vec![Effect::InjectInput(key_down(4))]
        );
        assert_eq!(
            core.handle(Event::RemoteInput {
                meta: meta(session, epoch, 1),
                lease_id: lease,
                received_at: MonotonicMillis::new(51),
                input: pointer_motion(),
            }),
            vec![Effect::InjectInput(pointer_motion())]
        );
        assert_eq!(
            core.last_remote_sequence(SequenceLane::Control),
            Some(Sequence::new(10))
        );
        assert_eq!(
            core.last_remote_sequence(SequenceLane::ReliableInput),
            Some(Sequence::new(50))
        );
        assert_eq!(
            core.last_remote_sequence(SequenceLane::ReplaceableInput),
            Some(Sequence::new(1))
        );
        assert_eq!(
            core.handle(Event::RemoteInput {
                meta: meta(session, epoch, 50),
                lease_id: lease,
                received_at: MonotonicMillis::new(52),
                input: key_down(4),
            }),
            rejected(RejectReason::StaleSequence)
        );
    }

    #[test]
    fn directional_grants_are_enforced_independently() {
        let (mut inbound_only, session, epoch) = ready_core(true, false);
        let lease = LeaseId::new(7);
        assert_eq!(
            inbound_only.handle(Event::LocalFocusRequested {
                lease_id: lease,
                expires_at: MonotonicMillis::new(100),
                pointer_enter_required: false,
            }),
            rejected(RejectReason::LocalInputNotAuthorized)
        );
        accept_peer_focus(&mut inbound_only, session, epoch, 1, lease);

        let (mut outbound_only, session, epoch) = ready_core(false, true);
        assert_eq!(
            outbound_only.handle(Event::RemoteFocusRequested {
                meta: meta(session, epoch, 1),
                lease_id: lease,
                expires_at: MonotonicMillis::new(100),
                pointer_enter_required: false,
            }),
            rejected(RejectReason::PeerInputNotAuthorized)
        );
        assert_eq!(
            outbound_only.last_remote_sequence(SequenceLane::Control),
            None
        );
        assert_eq!(
            outbound_only.handle(Event::LocalFocusRequested {
                lease_id: lease,
                expires_at: MonotonicMillis::new(100),
                pointer_enter_required: false,
            }),
            vec![
                Effect::RequestRemoteFocus {
                    lease_id: lease,
                    expires_at: MonotonicMillis::new(100),
                    pointer_enter_required: false,
                },
                Effect::ArmFocusLease {
                    lease_id: lease,
                    expires_at: MonotonicMillis::new(100),
                },
            ]
        );
    }

    #[test]
    fn topology_exchange_uses_authenticated_global_control_sequence() {
        let (mut core, session, epoch) = ready_core(true, true);
        assert!(
            core.handle(Event::LocalTopologyPublished { revision: 4 })
                .is_empty()
        );
        assert_eq!(core.published_topology_revision(), Some(4));

        assert_eq!(
            core.handle(Event::RemoteTopologyReceived {
                meta: meta(session, epoch, 5),
                revision: 7,
            }),
            vec![
                Effect::AcceptRemoteTopology { revision: 7 },
                Effect::AcknowledgeRemoteTopology { revision: 7 },
            ]
        );
        assert_eq!(core.remote_topology_revision(), Some(7));
        assert_eq!(
            core.last_remote_sequence(SequenceLane::Control),
            Some(Sequence::new(5))
        );

        assert_eq!(
            core.handle(Event::RemoteFocusRequested {
                meta: meta(session, epoch, 5),
                lease_id: LeaseId::new(1),
                expires_at: MonotonicMillis::new(100),
                pointer_enter_required: false,
            }),
            rejected(RejectReason::StaleSequence)
        );
        assert_eq!(
            core.handle(Event::RemoteTopologyAcknowledged {
                meta: meta(session, epoch, 6),
                revision: 4,
            }),
            vec![Effect::LocalTopologyReady { revision: 4 }]
        );
        assert_eq!(core.acknowledged_topology_revision(), Some(4));
    }

    #[test]
    fn topology_revisions_and_directional_authorization_fail_closed() {
        let (mut inbound_only, session, epoch) = ready_core(true, false);
        assert_eq!(
            inbound_only.handle(Event::RemoteTopologyReceived {
                meta: meta(session, epoch, 1),
                revision: 1,
            }),
            rejected(RejectReason::TopologyNotAuthorized)
        );
        assert_eq!(
            inbound_only.last_remote_sequence(SequenceLane::Control),
            None
        );

        let (mut outbound_only, session, epoch) = ready_core(false, true);
        assert_eq!(
            outbound_only.handle(Event::LocalTopologyPublished { revision: 1 }),
            rejected(RejectReason::TopologyNotAuthorized)
        );
        assert_eq!(
            outbound_only.handle(Event::RemoteTopologyReceived {
                meta: meta(session, epoch, 1),
                revision: 2,
            }),
            vec![
                Effect::AcceptRemoteTopology { revision: 2 },
                Effect::AcknowledgeRemoteTopology { revision: 2 },
            ]
        );
        assert_eq!(
            outbound_only.handle(Event::RemoteTopologyReceived {
                meta: meta(session, epoch, 2),
                revision: 2,
            }),
            rejected(RejectReason::StaleTopologyRevision)
        );
    }

    #[test]
    fn remote_topology_refresh_quiesces_an_active_focus_before_install() {
        let (mut core, session, epoch) = ready_core(true, true);
        let lease = LeaseId::new(7);
        accept_peer_focus(&mut core, session, epoch, 1, lease);
        assert_eq!(
            core.handle(Event::RemoteTopologyReceived {
                meta: meta(session, epoch, 2),
                revision: 1,
            }),
            rejected(RejectReason::StaleTopologyRevision)
        );
        assert_eq!(
            core.focus_state(),
            FocusState::ControlledByRemote {
                lease_id: lease,
                expires_at: MonotonicMillis::new(100),
            }
        );
        assert_eq!(
            core.last_remote_sequence(SequenceLane::Control),
            Some(Sequence::new(1))
        );
        assert_eq!(
            core.handle(Event::RemoteTopologyReceived {
                meta: meta(session, epoch, 2),
                revision: 2,
            }),
            vec![
                Effect::ReleaseInjectedInput {
                    releases: Vec::new()
                },
                Effect::ReleaseRoutedInput {
                    lease_id: lease,
                    releases: Vec::new(),
                },
                Effect::RestoreLocalOwnership,
                Effect::CancelFocusLease,
                Effect::ReleaseRemoteFocus { lease_id: lease },
                Effect::AcceptRemoteTopology { revision: 2 },
                Effect::AcknowledgeRemoteTopology { revision: 2 },
            ]
        );
        assert_eq!(core.focus_state(), FocusState::Local);
        assert_eq!(core.remote_topology_revision(), Some(2));
        assert_eq!(
            core.last_remote_sequence(SequenceLane::Control),
            Some(Sequence::new(2))
        );
    }

    #[test]
    fn local_topology_refresh_blocks_focus_until_the_exact_ack() {
        let (mut core, session, epoch) = ready_core(true, true);
        assert!(
            core.handle(Event::LocalTopologyPublished { revision: 2 })
                .is_empty()
        );
        assert!(core.local_topology_refresh_pending());
        assert_eq!(core.acknowledged_topology_revision(), None);

        let lease = LeaseId::new(8);
        assert_eq!(
            core.handle(Event::RemoteFocusRequested {
                meta: meta(session, epoch, 1),
                lease_id: lease,
                expires_at: MonotonicMillis::new(100),
                pointer_enter_required: false,
            }),
            vec![Effect::ReleaseRemoteFocus { lease_id: lease }]
        );
        assert_eq!(
            core.last_remote_sequence(SequenceLane::Control),
            Some(Sequence::new(1))
        );
        assert_eq!(
            core.handle(Event::RemoteTopologyAcknowledged {
                meta: meta(session, epoch, 2),
                revision: 1,
            }),
            rejected(RejectReason::TopologyRevisionMismatch)
        );
        assert_eq!(
            core.last_remote_sequence(SequenceLane::Control),
            Some(Sequence::new(1))
        );
        assert_eq!(
            core.handle(Event::RemoteTopologyAcknowledged {
                meta: meta(session, epoch, 2),
                revision: 2,
            }),
            vec![Effect::LocalTopologyReady { revision: 2 }]
        );
        assert!(!core.local_topology_refresh_pending());
        assert_eq!(core.acknowledged_topology_revision(), Some(2));
        assert_eq!(
            core.handle(Event::RemoteFocusRequested {
                meta: meta(session, epoch, 3),
                lease_id: lease,
                expires_at: MonotonicMillis::new(100),
                pointer_enter_required: false,
            }),
            vec![
                Effect::GrantRemoteFocus {
                    lease_id: lease,
                    expires_at: MonotonicMillis::new(100),
                    pointer_enter_required: false,
                },
                Effect::ArmFocusLease {
                    lease_id: lease,
                    expires_at: MonotonicMillis::new(100),
                },
            ]
        );
    }

    #[test]
    fn snapshot_acquisition_gates_focus_before_a_revision_exists() {
        let (mut core, session, epoch) = ready_core(true, true);
        assert!(core.handle(Event::LocalTopologyRefreshStarted).is_empty());
        assert!(core.local_topology_refresh_pending());

        let blocked = LeaseId::new(9);
        assert_eq!(
            core.handle(Event::RemoteFocusRequested {
                meta: meta(session, epoch, 1),
                lease_id: blocked,
                expires_at: MonotonicMillis::new(100),
                pointer_enter_required: false,
            }),
            vec![Effect::ReleaseRemoteFocus { lease_id: blocked }]
        );
        assert_eq!(
            core.last_remote_sequence(SequenceLane::Control),
            Some(Sequence::new(1))
        );
        assert!(core.handle(Event::LocalTopologyRefreshUnchanged).is_empty());
        assert!(!core.local_topology_refresh_pending());
        let admitted = LeaseId::new(10);
        assert_eq!(
            core.handle(Event::RemoteFocusRequested {
                meta: meta(session, epoch, 2),
                lease_id: admitted,
                expires_at: MonotonicMillis::new(100),
                pointer_enter_required: false,
            }),
            vec![
                Effect::GrantRemoteFocus {
                    lease_id: admitted,
                    expires_at: MonotonicMillis::new(100),
                    pointer_enter_required: false,
                },
                Effect::ArmFocusLease {
                    lease_id: admitted,
                    expires_at: MonotonicMillis::new(100),
                },
            ]
        );
    }

    #[test]
    fn local_refresh_orders_outbound_release_before_new_revision() {
        let (mut core, session, epoch) = ready_core(true, true);
        let lease = LeaseId::new(13);
        let _ = core.handle(Event::LocalFocusRequested {
            lease_id: lease,
            expires_at: MonotonicMillis::new(100),
            pointer_enter_required: false,
        });
        let _ = core.handle(Event::RemoteFocusGranted {
            meta: meta(session, epoch, 1),
            lease_id: lease,
            expires_at: MonotonicMillis::new(100),
            pointer_enter_required: false,
        });
        assert_eq!(
            core.handle(Event::LocalInput(key_down(4))),
            vec![Effect::SendInput {
                lease_id: lease,
                input: key_down(4),
            }]
        );

        assert_eq!(
            core.handle(Event::LocalTopologyPublished { revision: 2 }),
            vec![
                Effect::ReleaseInjectedInput {
                    releases: Vec::new()
                },
                Effect::ReleaseRoutedInput {
                    lease_id: lease,
                    releases: vec![key(4, KeyState::Released)],
                },
                Effect::SendReleaseAll { lease_id: lease },
                Effect::RestoreLocalOwnership,
                Effect::CancelFocusLease,
                Effect::ReleaseRemoteFocus { lease_id: lease },
            ]
        );
        assert_eq!(core.focus_state(), FocusState::Local);
        assert!(core.local_topology_refresh_pending());
        assert!(core.routed_input_is_clear());
    }

    #[test]
    fn drained_press_and_release_are_reduced_before_refresh_quiesce() {
        let (mut core, session, epoch) = ready_core(true, true);
        let lease = LeaseId::new(14);
        let _ = core.handle(Event::LocalFocusRequested {
            lease_id: lease,
            expires_at: MonotonicMillis::new(100),
            pointer_enter_required: false,
        });
        let _ = core.handle(Event::RemoteFocusGranted {
            meta: meta(session, epoch, 1),
            lease_id: lease,
            expires_at: MonotonicMillis::new(100),
            pointer_enter_required: false,
        });
        assert_eq!(
            core.handle(Event::LocalInput(key_down(4))),
            vec![Effect::SendInput {
                lease_id: lease,
                input: key_down(4),
            }]
        );
        let released = key(4, KeyState::Released);
        assert_eq!(
            core.handle(Event::LocalInput(released)),
            vec![Effect::SendInput {
                lease_id: lease,
                input: released,
            }]
        );

        assert_eq!(
            core.handle(Event::LocalTopologyRefreshStarted),
            vec![
                Effect::ReleaseInjectedInput {
                    releases: Vec::new()
                },
                Effect::ReleaseRoutedInput {
                    lease_id: lease,
                    releases: Vec::new(),
                },
                Effect::SendReleaseAll { lease_id: lease },
                Effect::RestoreLocalOwnership,
                Effect::CancelFocusLease,
                Effect::ReleaseRemoteFocus { lease_id: lease },
            ]
        );
        assert!(core.routed_input_is_clear());
    }

    #[test]
    fn every_noncurrent_input_lease_is_inert_across_multiple_lease_generations() {
        let (mut core, session, epoch) = ready_core(true, true);
        let first = LeaseId::new(7);
        accept_peer_focus(&mut core, session, epoch, 1, first);
        let _ = core.handle(Event::LocalTopologyPublished { revision: 2 });

        assert!(
            core.handle(Event::RemoteInput {
                meta: meta(session, epoch, 100),
                lease_id: first,
                received_at: MonotonicMillis::new(20),
                input: pointer_motion(),
            })
            .is_empty()
        );
        assert_eq!(
            core.last_remote_sequence(SequenceLane::ReplaceableInput),
            None
        );
        assert_eq!(
            core.handle(Event::RemoteTopologyAcknowledged {
                meta: meta(session, epoch, 2),
                revision: 2,
            }),
            vec![Effect::LocalTopologyReady { revision: 2 }]
        );

        let second = LeaseId::new(8);
        accept_peer_focus(&mut core, session, epoch, 3, second);
        assert_eq!(
            core.handle(Event::RemoteInput {
                meta: meta(session, epoch, 100),
                lease_id: second,
                received_at: MonotonicMillis::new(29),
                input: pointer_motion(),
            }),
            vec![Effect::InjectInput(pointer_motion())]
        );
        assert_eq!(
            core.handle(Event::RemoteFocusReleased {
                meta: meta(session, epoch, 4),
                lease_id: second,
            })
            .last(),
            Some(&Effect::CancelFocusLease)
        );

        let active = LeaseId::new(9);
        accept_peer_focus(&mut core, session, epoch, 5, active);
        for inactive in [first, second, LeaseId::new(99)] {
            assert!(
                core.handle(Event::RemoteInput {
                    // Even a sequence older than the current lane watermark is
                    // inert for a non-current lease and cannot poison the lane.
                    meta: meta(session, epoch, 1),
                    lease_id: inactive,
                    received_at: MonotonicMillis::new(30),
                    input: pointer_motion(),
                })
                .is_empty()
            );
        }
        assert!(
            core.handle(Event::RemoteInput {
                meta: meta(session, epoch, 101),
                lease_id: first,
                received_at: MonotonicMillis::new(30),
                input: pointer_motion(),
            })
            .is_empty()
        );
        assert_eq!(
            core.last_remote_sequence(SequenceLane::ReplaceableInput),
            Some(Sequence::new(100))
        );
        assert_eq!(
            core.handle(Event::RemoteInput {
                meta: meta(session, epoch, 101),
                lease_id: active,
                received_at: MonotonicMillis::new(32),
                input: pointer_motion(),
            }),
            vec![Effect::InjectInput(pointer_motion())]
        );
        assert_eq!(
            core.focus_state().lease().map(|(lease, _)| lease),
            Some(active)
        );
    }

    #[test]
    fn reliable_pointer_enter_ack_gates_outbound_relative_motion() {
        let (mut core, session, epoch) = ready_core(true, true);
        let lease = LeaseId::new(21);
        let position = NormalizedPosition::new(
            DisplayId::new(1),
            NormalizedAxis::MIN,
            NormalizedAxis::from_bits(7),
        );
        let _ = core.handle(Event::LocalFocusRequested {
            lease_id: lease,
            expires_at: MonotonicMillis::new(100),
            pointer_enter_required: true,
        });
        let _ = core.handle(Event::RemoteFocusGranted {
            meta: meta(session, epoch, 1),
            lease_id: lease,
            expires_at: MonotonicMillis::new(100),
            pointer_enter_required: true,
        });
        let delta = InputEvent::PointerDelta {
            delta: PointerDelta::new(4, -2).unwrap(),
        };
        assert!(!core.local_pointer_routing_ready());
        assert_eq!(
            core.handle(Event::LocalInput(delta)),
            rejected(RejectReason::InvalidTransition)
        );
        assert_eq!(
            core.handle(Event::LocalPointerEnter { position }),
            vec![Effect::SendPointerEnter {
                lease_id: lease,
                position,
            }]
        );
        assert!(
            core.handle(Event::RemotePointerEnterAcknowledged {
                meta: meta(session, epoch, 2),
                lease_id: lease,
            })
            .is_empty()
        );
        assert!(core.local_pointer_routing_ready());
        assert_eq!(
            core.handle(Event::LocalInput(delta)),
            vec![Effect::SendInput {
                lease_id: lease,
                input: delta,
            }]
        );
    }

    #[test]
    fn inbound_delta_waits_for_reliable_pointer_enter() {
        let (mut core, session, epoch) = ready_core(true, true);
        let lease = LeaseId::new(22);
        let position = NormalizedPosition::new(
            DisplayId::new(1),
            NormalizedAxis::MAX,
            NormalizedAxis::from_bits(9),
        );
        let _ = core.handle(Event::RemoteFocusRequested {
            meta: meta(session, epoch, 1),
            lease_id: lease,
            expires_at: MonotonicMillis::new(100),
            pointer_enter_required: true,
        });
        let delta = InputEvent::PointerDelta {
            delta: PointerDelta::new(6, 3).unwrap(),
        };
        assert_eq!(
            core.handle(Event::RemoteInput {
                meta: meta(session, epoch, 1),
                lease_id: lease,
                received_at: MonotonicMillis::new(20),
                input: delta,
            }),
            rejected(RejectReason::InvalidTransition)
        );
        assert_eq!(
            core.last_remote_sequence(SequenceLane::ReplaceableInput),
            None
        );
        assert_eq!(
            core.handle(Event::RemotePointerEnter {
                meta: meta(session, epoch, 1),
                lease_id: lease,
                received_at: MonotonicMillis::new(21),
                position,
            }),
            vec![
                Effect::InjectInput(InputEvent::PointerMotion { position }),
                Effect::AcknowledgePointerEnter { lease_id: lease },
            ]
        );
        assert_eq!(
            core.handle(Event::RemoteInput {
                meta: meta(session, epoch, 1),
                lease_id: lease,
                received_at: MonotonicMillis::new(22),
                input: delta,
            }),
            vec![Effect::InjectInput(delta)]
        );
    }

    #[test]
    fn normal_focus_release_keeps_ready_link_and_orders_forced_releases() {
        let (mut core, session, epoch) = ready_core(true, true);
        let lease = LeaseId::new(11);
        accept_peer_focus(&mut core, session, epoch, 1, lease);
        for (sequence, usage_id) in [(1, 8), (2, 4)] {
            let _ = core.handle(Event::RemoteInput {
                meta: meta(session, epoch, sequence),
                lease_id: lease,
                received_at: MonotonicMillis::new(50),
                input: key_down(usage_id),
            });
        }

        let effects = core.handle(Event::RemoteFocusReleased {
            meta: meta(session, epoch, 2),
            lease_id: lease,
        });
        assert_eq!(core.link_state(), LinkState::Ready);
        assert_eq!(core.focus_state(), FocusState::Local);
        assert_eq!(
            effects.first(),
            Some(&Effect::ReleaseInjectedInput {
                releases: vec![key(4, KeyState::Released), key(8, KeyState::Released),],
            })
        );
        assert_eq!(
            effects.get(1),
            Some(&Effect::ReleaseRoutedInput {
                lease_id: lease,
                releases: Vec::new(),
            })
        );
        assert!(!effects.iter().any(|effect| matches!(
            effect,
            Effect::SuspendContentOperations
                | Effect::AbortContentOperations
                | Effect::Disconnect { .. }
        )));
    }

    #[test]
    fn local_focus_release_routes_ordered_releases_with_the_active_lease() {
        let (mut core, session, epoch) = ready_core(true, true);
        let lease = LeaseId::new(12);
        let _ = core.handle(Event::LocalFocusRequested {
            lease_id: lease,
            expires_at: MonotonicMillis::new(100),
            pointer_enter_required: false,
        });
        let _ = core.handle(Event::RemoteFocusGranted {
            meta: meta(session, epoch, 1),
            lease_id: lease,
            expires_at: MonotonicMillis::new(100),
            pointer_enter_required: false,
        });
        let _ = core.handle(Event::LocalInput(key_down(8)));
        let _ = core.handle(Event::LocalInput(key_down(4)));

        assert_eq!(
            core.handle(Event::LocalFocusReleased),
            vec![
                Effect::ReleaseInjectedInput {
                    releases: Vec::new(),
                },
                Effect::ReleaseRoutedInput {
                    lease_id: lease,
                    releases: vec![key(4, KeyState::Released), key(8, KeyState::Released),],
                },
                Effect::SendReleaseAll { lease_id: lease },
                Effect::RestoreLocalOwnership,
                Effect::CancelFocusLease,
                Effect::ReleaseRemoteFocus { lease_id: lease },
            ]
        );
        assert_eq!(core.link_state(), LinkState::Ready);
        assert_eq!(core.focus_state(), FocusState::Local);
    }

    #[test]
    fn lease_renewal_and_release_all_have_explicit_effects() {
        let (mut core, session, epoch) = ready_core(true, true);
        let lease = LeaseId::new(13);
        let _ = core.handle(Event::LocalFocusRequested {
            lease_id: lease,
            expires_at: MonotonicMillis::new(100),
            pointer_enter_required: false,
        });
        let _ = core.handle(Event::RemoteFocusGranted {
            meta: meta(session, epoch, 1),
            lease_id: lease,
            expires_at: MonotonicMillis::new(100),
            pointer_enter_required: false,
        });
        let _ = core.handle(Event::LocalInput(key_down(4)));

        assert_eq!(
            core.handle(Event::LocalLeaseRenewalRequested {
                lease_id: lease,
                expires_at: MonotonicMillis::new(180),
            }),
            vec![Effect::RenewRemoteFocus {
                lease_id: lease,
                expires_at: MonotonicMillis::new(180),
            }]
        );
        assert_eq!(
            core.handle(Event::RemoteLeaseRenewed {
                meta: meta(session, epoch, 2),
                lease_id: lease,
                expires_at: MonotonicMillis::new(180),
                pointer_enter_required: false,
            }),
            vec![Effect::ArmFocusLease {
                lease_id: lease,
                expires_at: MonotonicMillis::new(180),
            }]
        );
        assert_eq!(
            core.handle(Event::LocalReleaseAll),
            vec![
                Effect::ReleaseRoutedInput {
                    lease_id: lease,
                    releases: vec![key(4, KeyState::Released)],
                },
                Effect::SendReleaseAll { lease_id: lease },
            ]
        );
        assert_eq!(core.link_state(), LinkState::Ready);
        assert_eq!(
            core.focus_state(),
            FocusState::ControllingRemote {
                lease_id: lease,
                expires_at: MonotonicMillis::new(180),
            }
        );
    }

    #[test]
    fn remote_release_all_releases_injected_state_without_releasing_focus() {
        let (mut core, session, epoch) = ready_core(true, true);
        let lease = LeaseId::new(14);
        accept_peer_focus(&mut core, session, epoch, 1, lease);
        let _ = core.handle(Event::RemoteInput {
            meta: meta(session, epoch, 1),
            lease_id: lease,
            received_at: MonotonicMillis::new(50),
            input: key_down(4),
        });

        assert_eq!(
            core.handle(Event::RemoteReleaseAll {
                meta: meta(session, epoch, 2),
                lease_id: lease,
                received_at: MonotonicMillis::new(60),
            }),
            vec![Effect::ReleaseInjectedInput {
                releases: vec![key(4, KeyState::Released)],
            }]
        );
        assert_eq!(core.link_state(), LinkState::Ready);
        assert!(matches!(
            core.focus_state(),
            FocusState::ControlledByRemote { .. }
        ));
    }

    #[test]
    fn terminal_events_explicitly_split_suspend_from_abort() {
        let cases = [
            (
                Event::LocalEmergencyStop,
                DisconnectReason::EmergencyStop,
                Effect::AbortContentOperations,
            ),
            (
                Event::LocalLocked,
                DisconnectReason::LocalLocked,
                Effect::AbortContentOperations,
            ),
            (
                Event::LocalSleeping,
                DisconnectReason::LocalSleeping,
                Effect::AbortContentOperations,
            ),
            (
                Event::ReconnectRequested,
                DisconnectReason::RequestedReconnect,
                Effect::SuspendContentOperations,
            ),
            (
                Event::LinkDisconnected,
                DisconnectReason::LinkLost,
                Effect::SuspendContentOperations,
            ),
            (
                Event::TimerElapsed {
                    now: MonotonicMillis::new(100),
                },
                DisconnectReason::FocusLeaseExpired,
                Effect::AbortContentOperations,
            ),
        ];

        for (terminal, expected_reason, expected_content_effect) in cases {
            let (mut core, session, epoch) = ready_core(true, true);
            let lease = LeaseId::new(11);
            accept_peer_focus(&mut core, session, epoch, 1, lease);
            let _ = core.handle(Event::RemoteInput {
                meta: meta(session, epoch, 1),
                lease_id: lease,
                received_at: MonotonicMillis::new(50),
                input: key_down(4),
            });

            let effects = core.handle(terminal);
            assert_eq!(core.link_state(), LinkState::Down);
            assert_eq!(core.focus_state(), FocusState::Local);
            assert!(core.injected_input_is_clear());
            assert_eq!(
                effects.first(),
                Some(&Effect::ReleaseInjectedInput {
                    releases: vec![key(4, KeyState::Released)],
                })
            );
            assert_eq!(
                effects.get(1),
                Some(&Effect::ReleaseRoutedInput {
                    lease_id: lease,
                    releases: Vec::new(),
                })
            );
            assert_eq!(
                effects.last(),
                Some(&Effect::Disconnect {
                    reason: expected_reason,
                })
            );
            assert!(effects.contains(&expected_content_effect));
        }
    }

    #[test]
    fn local_grant_epoch_replay_is_rejected_and_inbound_focus_is_released() {
        let (mut core, session, epoch) = ready_core(true, true);
        accept_peer_focus(&mut core, session, epoch, 1, LeaseId::new(12));

        let effects = core.handle(Event::LocalGrantUpdated {
            local_grant_epoch: GrantEpoch::new(4),
            local_grant_allows_peer_input: false,
        });

        assert_eq!(core.link_state(), LinkState::Ready);
        assert_eq!(core.focus_state(), FocusState::Local);
        assert_eq!(
            effects,
            vec![
                Effect::ReleaseInjectedInput {
                    releases: Vec::new(),
                },
                Effect::RestoreLocalOwnership,
                Effect::CancelFocusLease,
            ]
        );
        assert_eq!(core.local_grant_epoch(), Some(GrantEpoch::new(4)));
        assert_eq!(core.peer_grant_epoch(), Some(GrantEpoch::new(8)));
        assert_eq!(
            core.handle(Event::LocalGrantUpdated {
                local_grant_epoch: GrantEpoch::new(4),
                local_grant_allows_peer_input: true,
            }),
            rejected(RejectReason::GrantEpochDidNotIncrease)
        );
        assert_eq!(
            core.handle(Event::LocalGrantUpdated {
                local_grant_epoch: GrantEpoch::new(6),
                local_grant_allows_peer_input: true,
            }),
            rejected(RejectReason::GrantEpochDidNotIncrease)
        );
    }

    #[test]
    fn peer_grant_update_changes_only_outbound_authority_and_releases_routing() {
        let (mut core, _session, _epoch) = ready_core(true, true);
        core.focus = FocusState::ControllingRemote {
            lease_id: LeaseId::new(42),
            expires_at: MonotonicMillis::new(100),
        };
        core.routed_pressed.apply(&key_down(4));

        assert_eq!(
            core.handle(Event::PeerGrantUpdated {
                peer_grant_epoch: GrantEpoch::new(9),
                peer_grant_allows_local_input: false,
            }),
            vec![
                Effect::ReleaseInjectedInput {
                    releases: Vec::new(),
                },
                Effect::RestoreLocalOwnership,
                Effect::CancelFocusLease,
            ]
        );
        assert_eq!(core.focus_state(), FocusState::Local);
        assert!(core.routed_input_is_clear());
        assert!(core.local_grant_allows_peer_input());
        assert!(!core.peer_grant_allows_local_input());
        assert_eq!(core.local_grant_epoch(), Some(GrantEpoch::new(3)));
        assert_eq!(core.peer_grant_epoch(), Some(GrantEpoch::new(9)));
        assert_eq!(
            core.handle(Event::PeerGrantUpdated {
                peer_grant_epoch: GrantEpoch::new(9),
                peer_grant_allows_local_input: true,
            }),
            rejected(RejectReason::GrantEpochDidNotIncrease)
        );
    }
}
