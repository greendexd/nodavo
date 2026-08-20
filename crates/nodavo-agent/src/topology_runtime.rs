//! Session-local native/display topology boundary and per-peer placement policy.
//!
//! Native identifiers stay in [`LocalDisplayMap`]. Only fresh session-scoped
//! identifiers enter topology messages or pointer payloads.

use nodavo_input::{DisplayId, InputEvent, NormalizedAxis, NormalizedPosition};
use nodavo_local_ipc::PeerPlacement;
use nodavo_protocol::{
    DisplayDescriptor, DisplayRotation, DisplayTopology, MAX_TOPOLOGY_DISPLAYS, SessionDisplayId,
};
use nodavo_session::{
    DisplayEdge, EdgeAlignment, EdgeRoute, EdgeSwitchConfig, EdgeSwitchController, FocusState,
    MonotonicMillis, PointerSample, TargetPointerPosition, map_pointer_across_route,
};
use thiserror::Error;

const DEFAULT_ACTIVATION_BAND_MILLI: u32 = 8_000;
const DEFAULT_HYSTERESIS_MILLI: u32 = 12_000;
const DEFAULT_ENTRY_INSET_MILLI: u32 = 4_000;
const DEFAULT_DEBOUNCE_MS: u32 = 80;
const DEFAULT_COOLDOWN_MS: u32 = 300;
const MAX_DERIVED_EDGE_ROUTES: usize = 32;

/// Platform-owned geometry converted to bounded integer units before it enters
/// session policy. `native_id` never leaves this process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeDisplaySnapshot {
    pub(crate) native_id: DisplayId,
    pub(crate) origin_x_milli: i32,
    pub(crate) origin_y_milli: i32,
    pub(crate) pixel_width: u32,
    pub(crate) pixel_height: u32,
    pub(crate) scale_x_milli: u16,
    pub(crate) scale_y_milli: u16,
    pub(crate) rotation: DisplayRotation,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum TopologyRuntimeError {
    #[error("topology revision does not match the authorized session transition")]
    RevisionMismatch,
    #[error("topology acknowledgement does not match a published revision")]
    UnexpectedAcknowledgement,
    #[error("native display snapshot is invalid or ambiguous")]
    InvalidNativeSnapshot,
    #[error("session display mapping is unavailable")]
    DisplayMappingUnavailable,
    #[error("explicit edge route configuration is invalid")]
    InvalidEdgeConfiguration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DisplayMapping {
    native: DisplayId,
    session: SessionDisplayId,
}

#[derive(Clone, Debug, Default)]
struct LocalDisplayMap {
    mappings: Vec<DisplayMapping>,
    next_session_id: u32,
    revision: u64,
    topology: Option<DisplayTopology>,
}

#[derive(Clone, Debug)]
pub(crate) struct LocalTopologyCandidate {
    base_revision: u64,
    mappings: Vec<DisplayMapping>,
    next_session_id: u32,
    topology: DisplayTopology,
}

impl LocalTopologyCandidate {
    #[must_use]
    pub(crate) const fn revision(&self) -> u64 {
        self.topology.revision()
    }
}

impl LocalDisplayMap {
    fn prepare_reconcile(
        &self,
        snapshots: &[NativeDisplaySnapshot],
    ) -> Result<Option<LocalTopologyCandidate>, TopologyRuntimeError> {
        if snapshots.is_empty() || snapshots.len() > MAX_TOPOLOGY_DISPLAYS {
            return Err(TopologyRuntimeError::InvalidNativeSnapshot);
        }
        for (index, snapshot) in snapshots.iter().enumerate() {
            if snapshots[..index]
                .iter()
                .any(|seen| seen.native_id == snapshot.native_id)
            {
                return Err(TopologyRuntimeError::InvalidNativeSnapshot);
            }
        }

        let mut next_session_id = self.next_session_id;
        let mut candidate_mappings = Vec::with_capacity(snapshots.len());
        let mut descriptors = Vec::with_capacity(snapshots.len());
        for snapshot in snapshots {
            let session = if let Some(mapping) = self
                .mappings
                .iter()
                .find(|mapping| mapping.native == snapshot.native_id)
            {
                mapping.session
            } else {
                next_session_id = next_session_id
                    .checked_add(1)
                    .ok_or(TopologyRuntimeError::InvalidNativeSnapshot)?;
                SessionDisplayId::new(next_session_id)
            };
            candidate_mappings.push(DisplayMapping {
                native: snapshot.native_id,
                session,
            });
            descriptors.push(
                DisplayDescriptor::new(
                    session,
                    snapshot.origin_x_milli,
                    snapshot.origin_y_milli,
                    snapshot.pixel_width,
                    snapshot.pixel_height,
                    snapshot.scale_x_milli,
                    snapshot.scale_y_milli,
                    snapshot.rotation,
                )
                .map_err(|_| TopologyRuntimeError::InvalidNativeSnapshot)?,
            );
        }
        let mut ordered = candidate_mappings
            .into_iter()
            .zip(descriptors)
            .collect::<Vec<_>>();
        ordered.sort_unstable_by_key(|(mapping, _)| mapping.session.get());
        let (candidate_mappings, descriptors): (Vec<_>, Vec<_>) = ordered.into_iter().unzip();

        if self
            .topology
            .as_ref()
            .is_some_and(|current| current.displays() == descriptors.as_slice())
        {
            return Ok(None);
        }
        let revision = self
            .revision
            .checked_add(1)
            .ok_or(TopologyRuntimeError::InvalidNativeSnapshot)?;
        let topology = DisplayTopology::new(revision, descriptors)
            .map_err(|_| TopologyRuntimeError::InvalidNativeSnapshot)?;
        Ok(Some(LocalTopologyCandidate {
            base_revision: self.revision,
            mappings: candidate_mappings,
            next_session_id,
            topology,
        }))
    }

    fn commit(
        &mut self,
        candidate: LocalTopologyCandidate,
    ) -> Result<DisplayTopology, TopologyRuntimeError> {
        if self.revision != candidate.base_revision
            || candidate.topology.revision() != candidate.base_revision.saturating_add(1)
        {
            return Err(TopologyRuntimeError::RevisionMismatch);
        }
        self.mappings = candidate.mappings;
        self.next_session_id = candidate.next_session_id;
        self.revision = candidate.topology.revision();
        self.topology = Some(candidate.topology.clone());
        Ok(candidate.topology)
    }

    fn topology(&self) -> Option<&DisplayTopology> {
        self.topology.as_ref()
    }

    fn session_id(&self, native: DisplayId) -> Option<SessionDisplayId> {
        self.mappings
            .iter()
            .find(|mapping| mapping.native == native)
            .map(|mapping| mapping.session)
    }

    fn native_id(&self, session: SessionDisplayId) -> Option<DisplayId> {
        self.mappings
            .iter()
            .find(|mapping| mapping.session == session)
            .map(|mapping| mapping.native)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LocalPointerAction {
    /// Keep the event local; no route is armed.
    Local,
    /// Ask the normal session reducer for a lease, then seed this target after
    /// the authenticated grant arrives.
    RequestFocus,
    /// A lease request is in flight, so the physical sample is not sent.
    Suppressed,
}

#[derive(Clone, Debug)]
pub(crate) struct PeerTopologyState {
    local: LocalDisplayMap,
    staged_remote: Option<DisplayTopology>,
    remote: Option<DisplayTopology>,
    published_local_revision: Option<u64>,
    ready_local_revision: Option<u64>,
    local_transition_pending: bool,
    edge: EdgeSwitchController,
    routes: Vec<EdgeRoute>,
    placement: PeerPlacement,
    peer_input_granted: bool,
    activation_band_milli: u32,
    hysteresis_milli: u32,
    entry_inset_milli: u32,
    debounce_ms: u32,
    cooldown_ms: u32,
    active_route: Option<EdgeRoute>,
    pending_target: Option<InputEvent>,
}

impl PeerTopologyState {
    pub(crate) fn from_environment(
        placement: PeerPlacement,
        peer_input_granted: bool,
    ) -> Result<Self, TopologyRuntimeError> {
        let routes = Vec::new();
        let activation = env_u32(
            "NODAVO_EDGE_ACTIVATION_MILLI",
            DEFAULT_ACTIVATION_BAND_MILLI,
        )?;
        let hysteresis = env_u32("NODAVO_EDGE_HYSTERESIS_MILLI", DEFAULT_HYSTERESIS_MILLI)?;
        let entry_inset = env_u32("NODAVO_EDGE_ENTRY_INSET_MILLI", DEFAULT_ENTRY_INSET_MILLI)?;
        let debounce = env_u32("NODAVO_EDGE_DEBOUNCE_MS", DEFAULT_DEBOUNCE_MS)?;
        let cooldown = env_u32("NODAVO_EDGE_COOLDOWN_MS", DEFAULT_COOLDOWN_MS)?;
        let config = EdgeSwitchConfig::new(
            routes.clone(),
            activation,
            hysteresis,
            entry_inset,
            debounce,
            cooldown,
        )
        .map_err(|_| TopologyRuntimeError::InvalidEdgeConfiguration)?;
        Ok(Self {
            local: LocalDisplayMap::default(),
            staged_remote: None,
            remote: None,
            published_local_revision: None,
            ready_local_revision: None,
            local_transition_pending: false,
            edge: EdgeSwitchController::new(config),
            routes,
            placement,
            peer_input_granted,
            activation_band_milli: activation,
            hysteresis_milli: hysteresis,
            entry_inset_milli: entry_inset,
            debounce_ms: debounce,
            cooldown_ms: cooldown,
            active_route: None,
            pending_target: None,
        })
    }

    #[cfg(test)]
    fn with_routes(routes: Vec<EdgeRoute>) -> Self {
        let config = EdgeSwitchConfig::new(
            routes.clone(),
            DEFAULT_ACTIVATION_BAND_MILLI,
            DEFAULT_HYSTERESIS_MILLI,
            DEFAULT_ENTRY_INSET_MILLI,
            0,
            0,
        )
        .unwrap();
        Self {
            local: LocalDisplayMap::default(),
            staged_remote: None,
            remote: None,
            published_local_revision: None,
            ready_local_revision: None,
            local_transition_pending: false,
            edge: EdgeSwitchController::new(config),
            routes,
            placement: PeerPlacement::Right,
            peer_input_granted: true,
            activation_band_milli: DEFAULT_ACTIVATION_BAND_MILLI,
            hysteresis_milli: DEFAULT_HYSTERESIS_MILLI,
            entry_inset_milli: DEFAULT_ENTRY_INSET_MILLI,
            debounce_ms: 0,
            cooldown_ms: 0,
            active_route: None,
            pending_target: None,
        }
    }

    pub(crate) fn prepare_local_candidate(
        &mut self,
        snapshots: &[NativeDisplaySnapshot],
    ) -> Result<Option<LocalTopologyCandidate>, TopologyRuntimeError> {
        let candidate = match self.local.prepare_reconcile(snapshots) {
            Ok(candidate) => candidate,
            Err(error) => {
                self.local_transition_pending = true;
                let _ = self.clear_derived_routes();
                return Err(error);
            }
        };
        if candidate.is_some() {
            self.local_transition_pending = true;
            self.clear_derived_routes()?;
        }
        Ok(candidate)
    }

    pub(crate) fn begin_local_transition(&mut self) -> Result<(), TopologyRuntimeError> {
        self.local_transition_pending = true;
        self.clear_derived_routes()
    }

    pub(crate) fn finish_unchanged_local_transition(&mut self) -> Result<(), TopologyRuntimeError> {
        if self.local.topology().is_none() {
            return Err(TopologyRuntimeError::DisplayMappingUnavailable);
        }
        self.local_transition_pending = false;
        self.rebuild_routes()
    }

    pub(crate) fn commit_local_candidate(
        &mut self,
        candidate: LocalTopologyCandidate,
    ) -> Result<DisplayTopology, TopologyRuntimeError> {
        let topology = self.local.commit(candidate)?;
        Ok(topology)
    }

    pub(crate) fn mark_unpublished_local_ready(&mut self) -> Result<(), TopologyRuntimeError> {
        if self.local.topology().is_none() || self.published_local_revision.is_some() {
            return Err(TopologyRuntimeError::UnexpectedAcknowledgement);
        }
        self.local_transition_pending = false;
        self.rebuild_routes()
    }

    pub(crate) fn invalidate_local_authorization(&mut self) {
        self.published_local_revision = None;
        self.ready_local_revision = None;
        self.local_transition_pending = true;
        let _ = self.clear_derived_routes();
    }

    pub(crate) fn invalidate_remote_authorization(&mut self) {
        self.staged_remote = None;
        self.remote = None;
        self.active_route = None;
        self.pending_target = None;
        let _ = self.clear_derived_routes();
    }

    pub(crate) fn stage_remote(
        &mut self,
        topology: DisplayTopology,
        authorized_revision: u64,
    ) -> Result<(), TopologyRuntimeError> {
        if topology.revision() != authorized_revision {
            return Err(TopologyRuntimeError::RevisionMismatch);
        }
        self.clear_derived_routes()?;
        self.staged_remote = Some(topology);
        Ok(())
    }

    pub(crate) fn commit_remote(
        &mut self,
        authorized_revision: u64,
    ) -> Result<(), TopologyRuntimeError> {
        let staged = self
            .staged_remote
            .take()
            .ok_or(TopologyRuntimeError::RevisionMismatch)?;
        if staged.revision() != authorized_revision {
            return Err(TopologyRuntimeError::RevisionMismatch);
        }
        self.remote = Some(staged);
        self.rebuild_routes()?;
        Ok(())
    }

    pub(crate) fn set_peer_placement(
        &mut self,
        placement: PeerPlacement,
    ) -> Result<(), TopologyRuntimeError> {
        self.placement = placement;
        self.rebuild_routes()
    }

    pub(crate) fn record_local_publish(&mut self, revision: u64) {
        self.published_local_revision = Some(revision);
        self.ready_local_revision = None;
        self.local_transition_pending = true;
        let _ = self.clear_derived_routes();
    }

    #[must_use]
    pub(crate) fn local_ack_pending(&self) -> bool {
        self.published_local_revision != self.ready_local_revision
    }

    #[must_use]
    pub(crate) fn local_is_ready(&self) -> bool {
        !self.local_transition_pending
            && self.local.topology().is_some()
            && self
                .published_local_revision
                .is_none_or(|published| self.ready_local_revision == Some(published))
    }

    pub(crate) fn mark_local_ready(&mut self, revision: u64) -> Result<(), TopologyRuntimeError> {
        if self.published_local_revision != Some(revision) {
            return Err(TopologyRuntimeError::UnexpectedAcknowledgement);
        }
        self.ready_local_revision = Some(revision);
        self.local_transition_pending = false;
        self.rebuild_routes()
    }

    pub(crate) fn prepare_manual_focus(&mut self) -> Result<(), TopologyRuntimeError> {
        let local = self
            .local
            .topology()
            .ok_or(TopologyRuntimeError::DisplayMappingUnavailable)?;
        let remote = self
            .remote
            .as_ref()
            .ok_or(TopologyRuntimeError::DisplayMappingUnavailable)?;
        let Some(route) = self.routes.iter().copied().find(|route| route.enabled()) else {
            // Manual focus remains useful for keyboard/buttons/scroll even when
            // automatic edge switching is explicitly disabled. Without a route
            // no absolute pointer seed is sent, preserving the remote cursor.
            self.active_route = None;
            self.pending_target = None;
            return Ok(());
        };
        let sample = boundary_center_sample(route, MonotonicMillis::new(0));
        let target = map_pointer_across_route(sample, local, remote, route, self.entry_inset_milli)
            .ok_or(TopologyRuntimeError::DisplayMappingUnavailable)?;
        self.active_route = Some(route);
        self.pending_target = Some(target_event(target));
        Ok(())
    }

    pub(crate) fn local_pointer(
        &mut self,
        position: NormalizedPosition,
        focus: FocusState,
        now: MonotonicMillis,
    ) -> Result<LocalPointerAction, TopologyRuntimeError> {
        if self.routes.is_empty() {
            return Ok(match focus {
                FocusState::RequestingRemote { .. } | FocusState::ControllingRemote { .. } => {
                    LocalPointerAction::Suppressed
                }
                FocusState::Local | FocusState::ControlledByRemote { .. } => {
                    LocalPointerAction::Local
                }
            });
        }
        let session = self
            .local
            .session_id(position.display())
            .ok_or(TopologyRuntimeError::DisplayMappingUnavailable)?;
        let sample = PointerSample {
            display: session,
            x: expand_axis(position.x()),
            y: expand_axis(position.y()),
            observed_at: now,
        };
        let local = self
            .local
            .topology()
            .ok_or(TopologyRuntimeError::DisplayMappingUnavailable)?;
        let remote = self
            .remote
            .as_ref()
            .ok_or(TopologyRuntimeError::DisplayMappingUnavailable)?;
        match focus {
            FocusState::Local => {
                let Some(decision) = self.edge.observe(focus, sample, local, remote) else {
                    return Ok(LocalPointerAction::Local);
                };
                self.active_route = Some(decision.route);
                self.pending_target = Some(target_event(decision.target));
                Ok(LocalPointerAction::RequestFocus)
            }
            FocusState::RequestingRemote { .. } | FocusState::ControllingRemote { .. } => {
                Ok(LocalPointerAction::Suppressed)
            }
            FocusState::ControlledByRemote { .. } => Ok(LocalPointerAction::Local),
        }
    }

    pub(crate) fn resolve_incoming(
        &self,
        event: InputEvent,
    ) -> Result<InputEvent, TopologyRuntimeError> {
        let InputEvent::PointerMotion { position } = event else {
            return Ok(event);
        };
        let session_value = u32::try_from(position.display().get())
            .map_err(|_| TopologyRuntimeError::DisplayMappingUnavailable)?;
        let native = self
            .local
            .native_id(SessionDisplayId::new(session_value))
            .ok_or(TopologyRuntimeError::DisplayMappingUnavailable)?;
        Ok(InputEvent::PointerMotion {
            position: NormalizedPosition::new(native, position.x(), position.y()),
        })
    }

    pub(crate) fn take_pending_target(&mut self) -> Option<InputEvent> {
        self.pending_target.take()
    }

    #[must_use]
    pub(crate) const fn pointer_enter_required(&self) -> bool {
        self.pending_target.is_some()
    }

    pub(crate) fn clear_focus_route(&mut self) {
        self.active_route = None;
        self.pending_target = None;
    }

    fn clear_derived_routes(&mut self) -> Result<(), TopologyRuntimeError> {
        self.routes.clear();
        self.active_route = None;
        self.pending_target = None;
        self.edge.replace_config(edge_config(
            Vec::new(),
            self.activation_band_milli,
            self.hysteresis_milli,
            self.entry_inset_milli,
            self.debounce_ms,
            self.cooldown_ms,
        )?);
        Ok(())
    }

    fn rebuild_routes(&mut self) -> Result<(), TopologyRuntimeError> {
        self.active_route = None;
        self.pending_target = None;
        let routes =
            if self.peer_input_granted && self.local_is_ready() && self.staged_remote.is_none() {
                self.local
                    .topology()
                    .zip(self.remote.as_ref())
                    .map_or_else(Vec::new, |(local, remote)| {
                        derive_exterior_routes(self.placement, local, remote)
                    })
            } else {
                Vec::new()
            };
        let config = edge_config(
            routes.clone(),
            self.activation_band_milli,
            self.hysteresis_milli,
            self.entry_inset_milli,
            self.debounce_ms,
            self.cooldown_ms,
        )?;
        self.routes = routes;
        self.edge.replace_config(config);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn remote(&self) -> Option<&DisplayTopology> {
        self.remote.as_ref()
    }
}

fn edge_config(
    routes: Vec<EdgeRoute>,
    activation_band_milli: u32,
    hysteresis_milli: u32,
    entry_inset_milli: u32,
    debounce_ms: u32,
    cooldown_ms: u32,
) -> Result<EdgeSwitchConfig, TopologyRuntimeError> {
    EdgeSwitchConfig::new(
        routes,
        activation_band_milli,
        hysteresis_milli,
        entry_inset_milli,
        debounce_ms,
        cooldown_ms,
    )
    .map_err(|_| TopologyRuntimeError::InvalidEdgeConfiguration)
}

fn derive_exterior_routes(
    placement: PeerPlacement,
    local: &DisplayTopology,
    remote: &DisplayTopology,
) -> Vec<EdgeRoute> {
    let Some((source_edge, destination_edge)) = placement_edges(placement) else {
        return Vec::new();
    };
    let sources = exterior_displays(local, source_edge);
    let destinations = exterior_displays(remote, destination_edge);
    if sources.is_empty() || destinations.is_empty() {
        return Vec::new();
    }
    let source_count = sources.len();
    let destination_count = destinations.len();
    sources
        .into_iter()
        .take(MAX_DERIVED_EDGE_ROUTES)
        .enumerate()
        .map(|(index, source)| {
            // Pair the centers of the ordered exterior spans. This stays
            // deterministic when the two workstations expose different counts.
            let destination_index = ((2 * index + 1) * destination_count) / (2 * source_count);
            let destination = destinations[destination_index.min(destination_count - 1)];
            EdgeRoute::new(
                source.id(),
                source_edge,
                destination.id(),
                destination_edge,
                EdgeAlignment::Stretch,
                true,
            )
        })
        .collect()
}

const fn placement_edges(placement: PeerPlacement) -> Option<(DisplayEdge, DisplayEdge)> {
    match placement {
        PeerPlacement::Disabled => None,
        PeerPlacement::Left => Some((DisplayEdge::Left, DisplayEdge::Right)),
        PeerPlacement::Right => Some((DisplayEdge::Right, DisplayEdge::Left)),
        PeerPlacement::Above => Some((DisplayEdge::Top, DisplayEdge::Bottom)),
        PeerPlacement::Below => Some((DisplayEdge::Bottom, DisplayEdge::Top)),
    }
}

fn exterior_displays(topology: &DisplayTopology, edge: DisplayEdge) -> Vec<&DisplayDescriptor> {
    let exterior = topology
        .displays()
        .iter()
        .map(|display| edge_coordinate(display, edge))
        .reduce(|left, right| match edge {
            DisplayEdge::Left | DisplayEdge::Top => left.min(right),
            DisplayEdge::Right | DisplayEdge::Bottom => left.max(right),
        });
    let Some(exterior) = exterior else {
        return Vec::new();
    };
    let mut displays = topology
        .displays()
        .iter()
        .filter(|display| edge_coordinate(display, edge) == exterior)
        .collect::<Vec<_>>();
    displays.sort_unstable_by_key(|display| match edge {
        DisplayEdge::Left | DisplayEdge::Right => {
            (i64::from(display.origin_y_milli()), display.id().get())
        }
        DisplayEdge::Top | DisplayEdge::Bottom => {
            (i64::from(display.origin_x_milli()), display.id().get())
        }
    });
    displays
}

fn edge_coordinate(display: &DisplayDescriptor, edge: DisplayEdge) -> i64 {
    match edge {
        DisplayEdge::Left => i64::from(display.origin_x_milli()),
        DisplayEdge::Right => {
            i64::from(display.origin_x_milli())
                + i64::try_from(display.logical_width_milli()).unwrap_or(i64::MAX)
        }
        DisplayEdge::Top => i64::from(display.origin_y_milli()),
        DisplayEdge::Bottom => {
            i64::from(display.origin_y_milli())
                + i64::try_from(display.logical_height_milli()).unwrap_or(i64::MAX)
        }
    }
}

fn boundary_center_sample(route: EdgeRoute, observed_at: MonotonicMillis) -> PointerSample {
    let (x, y) = match route.source_edge() {
        DisplayEdge::Left => (0, u32::MAX / 2),
        DisplayEdge::Right => (u32::MAX, u32::MAX / 2),
        DisplayEdge::Top => (u32::MAX / 2, 0),
        DisplayEdge::Bottom => (u32::MAX / 2, u32::MAX),
    };
    PointerSample {
        display: route.source_display(),
        x,
        y,
        observed_at,
    }
}

fn target_event(target: TargetPointerPosition) -> InputEvent {
    InputEvent::PointerMotion {
        position: NormalizedPosition::new(
            DisplayId::new(u64::from(target.display.get())),
            collapse_axis(target.x),
            collapse_axis(target.y),
        ),
    }
}

fn expand_axis(axis: NormalizedAxis) -> u32 {
    u32::from(axis.bits()) * 65_537
}

const fn collapse_axis(axis: u32) -> NormalizedAxis {
    NormalizedAxis::from_bits((axis / 65_537) as u16)
}

fn env_u32(name: &str, default: u32) -> Result<u32, TopologyRuntimeError> {
    std::env::var(name).map_or(Ok(default), |value| {
        value
            .parse()
            .map_err(|_| TopologyRuntimeError::InvalidEdgeConfiguration)
    })
}

#[cfg(test)]
mod tests {
    use nodavo_protocol::TopologyValidationError;

    use super::*;

    fn descriptor(id: u32) -> Result<DisplayDescriptor, TopologyValidationError> {
        DisplayDescriptor::new(
            SessionDisplayId::new(id),
            0,
            0,
            1_920,
            1_080,
            1_000,
            1_000,
            DisplayRotation::Degrees0,
        )
    }

    fn positioned_descriptor(
        id: u32,
        horizontal_origin: i32,
        vertical_origin: i32,
    ) -> DisplayDescriptor {
        DisplayDescriptor::new(
            SessionDisplayId::new(id),
            horizontal_origin,
            vertical_origin,
            1_920,
            1_080,
            1_000,
            1_000,
            DisplayRotation::Degrees0,
        )
        .unwrap()
    }

    fn topology(revision: u64) -> Result<DisplayTopology, TopologyValidationError> {
        DisplayTopology::new(revision, vec![descriptor(1)?])
    }

    fn snapshot(native: u64) -> NativeDisplaySnapshot {
        NativeDisplaySnapshot {
            native_id: DisplayId::new(native),
            origin_x_milli: 0,
            origin_y_milli: 0,
            pixel_width: 1_920,
            pixel_height: 1_080,
            scale_x_milli: 1_000,
            scale_y_milli: 1_000,
            rotation: DisplayRotation::Degrees0,
        }
    }

    fn route() -> EdgeRoute {
        EdgeRoute::new(
            SessionDisplayId::new(1),
            DisplayEdge::Right,
            SessionDisplayId::new(1),
            DisplayEdge::Left,
            EdgeAlignment::Stretch,
            true,
        )
    }

    #[test]
    fn native_ids_never_become_session_ids_and_remain_stable() {
        let mut map = LocalDisplayMap::default();
        let first = map
            .commit(
                map.prepare_reconcile(&[snapshot(0xDEAD_BEEF)])
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(first.displays()[0].id(), SessionDisplayId::new(1));
        assert!(
            map.prepare_reconcile(&[snapshot(0xDEAD_BEEF)])
                .unwrap()
                .is_none()
        );
        let candidate = map
            .prepare_reconcile(&[snapshot(0xDEAD_BEEF), snapshot(9)])
            .unwrap()
            .unwrap();
        let second = map.commit(candidate).unwrap();
        assert_eq!(second.displays()[0].id(), SessionDisplayId::new(1));
        assert_eq!(second.displays()[1].id(), SessionDisplayId::new(2));
    }

    #[test]
    fn candidate_is_transactional_and_removed_ids_never_resolve() {
        let mut map = LocalDisplayMap::default();
        let initial = map
            .prepare_reconcile(&[snapshot(100), snapshot(200)])
            .unwrap()
            .unwrap();
        assert_eq!(map.revision, 0, "prepare mutated the active revision");
        assert!(map.session_id(DisplayId::new(100)).is_none());
        map.commit(initial).unwrap();
        let removed_session = map.session_id(DisplayId::new(100)).unwrap();
        let retained_session = map.session_id(DisplayId::new(200)).unwrap();

        let removal = map.prepare_reconcile(&[snapshot(200)]).unwrap().unwrap();
        assert_eq!(map.native_id(removed_session), Some(DisplayId::new(100)));
        map.commit(removal).unwrap();
        assert_eq!(map.session_id(DisplayId::new(100)), None);
        assert_eq!(map.native_id(removed_session), None);
        assert_eq!(map.session_id(DisplayId::new(200)), Some(retained_session));

        let readded = map
            .prepare_reconcile(&[snapshot(100), snapshot(200)])
            .unwrap()
            .unwrap();
        map.commit(readded).unwrap();
        assert_ne!(map.session_id(DisplayId::new(100)), Some(removed_session));
        assert_eq!(map.session_id(DisplayId::new(200)), Some(retained_session));
    }

    #[test]
    fn invalid_or_stale_candidate_never_partially_mutates_active_map() {
        let mut map = LocalDisplayMap::default();
        let initial = map.prepare_reconcile(&[snapshot(1)]).unwrap().unwrap();
        map.commit(initial).unwrap();
        let before = map.clone();
        let mut invalid = snapshot(2);
        invalid.pixel_width = 0;
        assert!(matches!(
            map.prepare_reconcile(&[snapshot(1), invalid]),
            Err(TopologyRuntimeError::InvalidNativeSnapshot)
        ));
        assert_eq!(map.mappings, before.mappings);
        assert_eq!(map.next_session_id, before.next_session_id);
        assert_eq!(map.revision, before.revision);
        assert_eq!(map.topology, before.topology);

        let stale = map
            .prepare_reconcile(&[snapshot(1), snapshot(2)])
            .unwrap()
            .unwrap();
        let newer = map
            .prepare_reconcile(&[snapshot(1), snapshot(3)])
            .unwrap()
            .unwrap();
        map.commit(newer).unwrap();
        assert_eq!(
            map.commit(stale),
            Err(TopologyRuntimeError::RevisionMismatch)
        );
    }

    #[test]
    fn remote_topology_requires_matching_authorize_then_commit_revision() {
        let mut state = PeerTopologyState::with_routes(vec![route()]);
        assert_eq!(
            state.stage_remote(topology(2).unwrap(), 1),
            Err(TopologyRuntimeError::RevisionMismatch)
        );
        state.stage_remote(topology(2).unwrap(), 2).unwrap();
        assert_eq!(
            state.commit_remote(1),
            Err(TopologyRuntimeError::RevisionMismatch)
        );
        state.stage_remote(topology(2).unwrap(), 2).unwrap();
        state.commit_remote(2).unwrap();
        assert_eq!(state.remote().map(DisplayTopology::revision), Some(2));
    }

    #[test]
    fn incoming_session_token_resolves_only_through_local_map() {
        let mut state = PeerTopologyState::with_routes(vec![route()]);
        let candidate = state
            .prepare_local_candidate(&[snapshot(777)])
            .unwrap()
            .unwrap();
        let _ = state.commit_local_candidate(candidate).unwrap();
        let incoming = InputEvent::PointerMotion {
            position: NormalizedPosition::new(
                DisplayId::new(1),
                NormalizedAxis::MIN,
                NormalizedAxis::MAX,
            ),
        };
        let InputEvent::PointerMotion { position } = state.resolve_incoming(incoming).unwrap()
        else {
            unreachable!()
        };
        assert_eq!(position.display(), DisplayId::new(777));
    }

    #[test]
    fn local_ready_requires_the_exact_published_revision() {
        let mut state = PeerTopologyState::with_routes(vec![route()]);
        state.record_local_publish(3);
        assert_eq!(
            state.mark_local_ready(2),
            Err(TopologyRuntimeError::UnexpectedAcknowledgement)
        );
        assert_eq!(state.mark_local_ready(3), Ok(()));
    }

    #[test]
    fn manual_focus_without_routes_preserves_remote_cursor() {
        let mut state = PeerTopologyState::with_routes(Vec::new());
        let candidate = state
            .prepare_local_candidate(&[snapshot(777)])
            .unwrap()
            .unwrap();
        let _ = state.commit_local_candidate(candidate).unwrap();
        state.remote = Some(topology(1).unwrap());
        assert_eq!(state.prepare_manual_focus(), Ok(()));
        assert_eq!(state.take_pending_target(), None);
        assert_eq!(
            state
                .local_pointer(
                    NormalizedPosition::new(
                        DisplayId::new(777),
                        NormalizedAxis::MAX,
                        NormalizedAxis::MAX,
                    ),
                    FocusState::ControllingRemote {
                        lease_id: nodavo_session::LeaseId::new(9),
                        expires_at: MonotonicMillis::new(100),
                    },
                    MonotonicMillis::new(1),
                )
                .unwrap(),
            LocalPointerAction::Suppressed
        );
    }

    #[test]
    fn placement_derives_only_deterministic_exterior_stretch_routes() {
        let local = DisplayTopology::new(
            1,
            vec![
                positioned_descriptor(1, 0, 0),
                positioned_descriptor(2, 1_920_000, 0),
                positioned_descriptor(3, 1_920_000, 1_080_000),
            ],
        )
        .unwrap();
        let remote = DisplayTopology::new(
            1,
            vec![
                positioned_descriptor(10, 0, 0),
                positioned_descriptor(11, 0, 1_080_000),
                positioned_descriptor(12, 1_920_000, 0),
            ],
        )
        .unwrap();

        let routes = derive_exterior_routes(PeerPlacement::Right, &local, &remote);
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].source_display(), SessionDisplayId::new(2));
        assert_eq!(routes[1].source_display(), SessionDisplayId::new(3));
        assert_eq!(routes[0].destination_display(), SessionDisplayId::new(10));
        assert_eq!(routes[1].destination_display(), SessionDisplayId::new(11));
        assert!(routes.iter().all(|route| {
            route.source_edge() == DisplayEdge::Right
                && route.destination_edge() == DisplayEdge::Left
                && route.alignment() == EdgeAlignment::Stretch
        }));
        assert!(routes.len() <= MAX_DERIVED_EDGE_ROUTES);
        assert!(derive_exterior_routes(PeerPlacement::Disabled, &local, &remote).is_empty());
    }

    #[test]
    fn route_activation_requires_grant_and_committed_topologies_and_changes_clear_state() {
        let mut state = PeerTopologyState::with_routes(Vec::new());
        state.placement = PeerPlacement::Right;
        state.peer_input_granted = false;
        let candidate = state
            .prepare_local_candidate(&[snapshot(7)])
            .unwrap()
            .unwrap();
        state.commit_local_candidate(candidate).unwrap();
        state.mark_unpublished_local_ready().unwrap();
        state.stage_remote(topology(1).unwrap(), 1).unwrap();
        state.commit_remote(1).unwrap();
        assert!(
            state.routes.is_empty(),
            "a missing input grant armed routes"
        );

        state.peer_input_granted = true;
        state.rebuild_routes().unwrap();
        assert_eq!(state.routes.len(), 1);
        let pending_local = state
            .prepare_local_candidate(&[snapshot(7), snapshot(8)])
            .unwrap()
            .unwrap();
        state.set_peer_placement(PeerPlacement::Left).unwrap();
        assert!(
            state.routes.is_empty(),
            "placement rearmed a route across a pending local topology"
        );
        state.commit_local_candidate(pending_local).unwrap();
        state.mark_unpublished_local_ready().unwrap();
        assert!(!state.routes.is_empty());
        state.stage_remote(topology(2).unwrap(), 2).unwrap();
        state.set_peer_placement(PeerPlacement::Right).unwrap();
        assert!(
            state.routes.is_empty(),
            "placement rearmed a route across a staged remote topology"
        );
        state.commit_remote(2).unwrap();
        assert!(!state.routes.is_empty());
        state.active_route = state.routes.first().copied();
        state.pending_target = Some(InputEvent::PointerMotion {
            position: NormalizedPosition::new(
                DisplayId::new(1),
                NormalizedAxis::MAX,
                NormalizedAxis::MIN,
            ),
        });
        let mut invalid = snapshot(9);
        invalid.pixel_width = 0;
        assert!(state.prepare_local_candidate(&[invalid]).is_err());
        assert!(state.routes.is_empty());
        assert!(state.active_route.is_none());
        assert!(state.pending_target.is_none());
        state.set_peer_placement(PeerPlacement::Disabled).unwrap();
        assert!(state.routes.is_empty());
        assert!(state.active_route.is_none());
        assert!(state.pending_target.is_none());
    }

    #[test]
    fn published_local_topology_ack_is_the_exact_route_activation_gate() {
        let mut state = PeerTopologyState::with_routes(Vec::new());
        state.placement = PeerPlacement::Right;
        let candidate = state
            .prepare_local_candidate(&[snapshot(70)])
            .unwrap()
            .unwrap();
        let local_topology = state.commit_local_candidate(candidate).unwrap();
        state.stage_remote(topology(9).unwrap(), 9).unwrap();
        state.commit_remote(9).unwrap();
        assert!(state.routes.is_empty());

        state.record_local_publish(local_topology.revision());
        assert!(!state.local_is_ready());
        assert!(state.routes.is_empty());
        assert_eq!(
            state.mark_local_ready(local_topology.revision() + 1),
            Err(TopologyRuntimeError::UnexpectedAcknowledgement)
        );
        assert!(state.routes.is_empty());
        state.mark_local_ready(local_topology.revision()).unwrap();
        assert!(state.local_is_ready());
        assert_eq!(state.routes.len(), 1);
    }
}
