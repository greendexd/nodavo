//! Session-local native/display topology boundary and edge policy.
//!
//! Native identifiers stay in [`LocalDisplayMap`]. Only fresh session-scoped
//! identifiers enter topology messages or pointer payloads.

use nodavo_input::{DisplayId, InputEvent, NormalizedAxis, NormalizedPosition};
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

impl LocalDisplayMap {
    fn reconcile(
        &mut self,
        snapshots: &[NativeDisplaySnapshot],
    ) -> Result<Option<DisplayTopology>, TopologyRuntimeError> {
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

        let mut descriptors = Vec::with_capacity(snapshots.len());
        for snapshot in snapshots {
            let session = if let Some(mapping) = self
                .mappings
                .iter()
                .find(|mapping| mapping.native == snapshot.native_id)
            {
                mapping.session
            } else {
                self.next_session_id = self
                    .next_session_id
                    .checked_add(1)
                    .ok_or(TopologyRuntimeError::InvalidNativeSnapshot)?;
                let session = SessionDisplayId::new(self.next_session_id);
                self.mappings.push(DisplayMapping {
                    native: snapshot.native_id,
                    session,
                });
                session
            };
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

        if self
            .topology
            .as_ref()
            .is_some_and(|current| current.displays() == descriptors.as_slice())
        {
            return Ok(None);
        }
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(TopologyRuntimeError::InvalidNativeSnapshot)?;
        let topology = DisplayTopology::new(self.revision, descriptors)
            .map_err(|_| TopologyRuntimeError::InvalidNativeSnapshot)?;
        self.topology = Some(topology.clone());
        Ok(Some(topology))
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
    edge: EdgeSwitchController,
    routes: Vec<EdgeRoute>,
    entry_inset_milli: u32,
    active_route: Option<EdgeRoute>,
    pending_target: Option<InputEvent>,
}

impl PeerTopologyState {
    pub(crate) fn from_environment() -> Result<Self, TopologyRuntimeError> {
        let routes = parse_routes(std::env::var("NODAVO_EDGE_ROUTES").ok().as_deref())?;
        #[cfg(test)]
        let routes = if routes.is_empty() {
            vec![EdgeRoute::new(
                SessionDisplayId::new(1),
                DisplayEdge::Right,
                SessionDisplayId::new(1),
                DisplayEdge::Left,
                EdgeAlignment::Stretch,
                true,
            )]
        } else {
            routes
        };
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
            edge: EdgeSwitchController::new(config),
            routes,
            entry_inset_milli: entry_inset,
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
            edge: EdgeSwitchController::new(config),
            routes,
            entry_inset_milli: DEFAULT_ENTRY_INSET_MILLI,
            active_route: None,
            pending_target: None,
        }
    }

    pub(crate) fn reconcile_local(
        &mut self,
        snapshots: &[NativeDisplaySnapshot],
    ) -> Result<Option<DisplayTopology>, TopologyRuntimeError> {
        self.local.reconcile(snapshots)
    }

    pub(crate) fn stage_remote(
        &mut self,
        topology: DisplayTopology,
        authorized_revision: u64,
    ) -> Result<(), TopologyRuntimeError> {
        if topology.revision() != authorized_revision {
            return Err(TopologyRuntimeError::RevisionMismatch);
        }
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
        Ok(())
    }

    pub(crate) fn record_local_publish(&mut self, revision: u64) {
        self.published_local_revision = Some(revision);
        self.ready_local_revision = None;
    }

    pub(crate) fn mark_local_ready(&mut self, revision: u64) -> Result<(), TopologyRuntimeError> {
        if self.published_local_revision != Some(revision) {
            return Err(TopologyRuntimeError::UnexpectedAcknowledgement);
        }
        self.ready_local_revision = Some(revision);
        Ok(())
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

    pub(crate) fn resolve_incoming_position(
        &self,
        position: NormalizedPosition,
    ) -> Result<NormalizedPosition, TopologyRuntimeError> {
        let session_value = u32::try_from(position.display().get())
            .map_err(|_| TopologyRuntimeError::DisplayMappingUnavailable)?;
        let native = self
            .local
            .native_id(SessionDisplayId::new(session_value))
            .ok_or(TopologyRuntimeError::DisplayMappingUnavailable)?;
        Ok(NormalizedPosition::new(native, position.x(), position.y()))
    }

    pub(crate) fn clear_focus_route(&mut self) {
        self.active_route = None;
        self.pending_target = None;
    }

    #[cfg(test)]
    pub(crate) fn remote(&self) -> Option<&DisplayTopology> {
        self.remote.as_ref()
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

fn parse_routes(value: Option<&str>) -> Result<Vec<EdgeRoute>, TopologyRuntimeError> {
    let Some(value) = value.filter(|value| !value.is_empty()) else {
        return Ok(Vec::new());
    };
    value
        .split(',')
        .map(|route| {
            let (source, destination) = route
                .split_once('>')
                .ok_or(TopologyRuntimeError::InvalidEdgeConfiguration)?;
            let (destination, alignment) = destination
                .rsplit_once(':')
                .ok_or(TopologyRuntimeError::InvalidEdgeConfiguration)?;
            let (source_display, source_edge) = parse_endpoint(source)?;
            let (destination_display, destination_edge) = parse_endpoint(destination)?;
            Ok(EdgeRoute::new(
                source_display,
                source_edge,
                destination_display,
                destination_edge,
                parse_alignment(alignment)?,
                true,
            ))
        })
        .collect()
}

fn parse_endpoint(value: &str) -> Result<(SessionDisplayId, DisplayEdge), TopologyRuntimeError> {
    let (display, edge) = value
        .split_once(':')
        .ok_or(TopologyRuntimeError::InvalidEdgeConfiguration)?;
    let display = display
        .parse()
        .map(SessionDisplayId::new)
        .map_err(|_| TopologyRuntimeError::InvalidEdgeConfiguration)?;
    let edge = match edge {
        "left" => DisplayEdge::Left,
        "right" => DisplayEdge::Right,
        "top" => DisplayEdge::Top,
        "bottom" => DisplayEdge::Bottom,
        _ => return Err(TopologyRuntimeError::InvalidEdgeConfiguration),
    };
    Ok((display, edge))
}

fn parse_alignment(value: &str) -> Result<EdgeAlignment, TopologyRuntimeError> {
    match value {
        "start" => Ok(EdgeAlignment::Start),
        "center" => Ok(EdgeAlignment::Center),
        "end" => Ok(EdgeAlignment::End),
        "stretch" => Ok(EdgeAlignment::Stretch),
        _ => Err(TopologyRuntimeError::InvalidEdgeConfiguration),
    }
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
        let first = map.reconcile(&[snapshot(0xDEAD_BEEF)]).unwrap().unwrap();
        assert_eq!(first.displays()[0].id(), SessionDisplayId::new(1));
        assert_eq!(map.reconcile(&[snapshot(0xDEAD_BEEF)]).unwrap(), None);
        let second = map
            .reconcile(&[snapshot(0xDEAD_BEEF), snapshot(9)])
            .unwrap()
            .unwrap();
        assert_eq!(second.displays()[0].id(), SessionDisplayId::new(1));
        assert_eq!(second.displays()[1].id(), SessionDisplayId::new(2));
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
        let _ = state.reconcile_local(&[snapshot(777)]).unwrap();
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
    fn route_parser_requires_fully_explicit_adjacency() {
        assert_eq!(parse_routes(None), Ok(Vec::new()));
        let routes = parse_routes(Some("1:right>2:left:center")).unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].source_display(), SessionDisplayId::new(1));
        assert_eq!(routes[0].destination_display(), SessionDisplayId::new(2));
        assert_eq!(routes[0].alignment(), EdgeAlignment::Center);
        assert_eq!(
            parse_routes(Some("right>left")),
            Err(TopologyRuntimeError::InvalidEdgeConfiguration)
        );
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
        let _ = state.reconcile_local(&[snapshot(777)]).unwrap();
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
}
