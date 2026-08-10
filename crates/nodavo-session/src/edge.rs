//! Deterministic, explicitly configured display-edge switching.
//!
//! This reducer never changes focus itself. It emits a decision only while the
//! session focus is local; the caller must still request and receive a normal
//! focus lease before routing input. Empty routes disable switching.

use nodavo_protocol::{DisplayDescriptor, DisplayTopology, SessionDisplayId};
use thiserror::Error;

use crate::{FocusState, MonotonicMillis};

pub const MAX_EDGE_ROUTES: usize = 128;
pub const MAX_EDGE_BAND_MILLI: u32 = 250_000;
pub const MAX_EDGE_DEBOUNCE_MS: u32 = 2_000;
pub const MAX_EDGE_COOLDOWN_MS: u32 = 10_000;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DisplayEdge {
    Left,
    Right,
    Top,
    Bottom,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EdgeAlignment {
    /// Preserve logical distance from the top or left endpoint.
    Start,
    /// Center the shorter logical edge on the longer edge.
    Center,
    /// Preserve logical distance from the bottom or right endpoint.
    End,
    /// Scale the full source edge onto the full destination edge.
    Stretch,
}

/// One user-configured, directional adjacency.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EdgeRoute {
    source_display: SessionDisplayId,
    source_edge: DisplayEdge,
    destination_display: SessionDisplayId,
    destination_edge: DisplayEdge,
    alignment: EdgeAlignment,
    enabled: bool,
}

impl EdgeRoute {
    #[must_use]
    pub const fn new(
        source_display: SessionDisplayId,
        source_edge: DisplayEdge,
        destination_display: SessionDisplayId,
        destination_edge: DisplayEdge,
        alignment: EdgeAlignment,
        enabled: bool,
    ) -> Self {
        Self {
            source_display,
            source_edge,
            destination_display,
            destination_edge,
            alignment,
            enabled,
        }
    }

    #[must_use]
    pub const fn source_display(self) -> SessionDisplayId {
        self.source_display
    }

    #[must_use]
    pub const fn source_edge(self) -> DisplayEdge {
        self.source_edge
    }

    #[must_use]
    pub const fn destination_display(self) -> SessionDisplayId {
        self.destination_display
    }

    #[must_use]
    pub const fn destination_edge(self) -> DisplayEdge {
        self.destination_edge
    }

    #[must_use]
    pub const fn alignment(self) -> EdgeAlignment {
        self.alignment
    }

    #[must_use]
    pub const fn enabled(self) -> bool {
        self.enabled
    }
}

/// Edge activation policy in logical millipoints and monotonic milliseconds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EdgeSwitchConfig {
    routes: Vec<EdgeRoute>,
    activation_band_milli: u32,
    hysteresis_milli: u32,
    entry_inset_milli: u32,
    debounce_ms: u32,
    cooldown_ms: u32,
}

impl EdgeSwitchConfig {
    /// Builds a bounded explicit policy. An empty route list is valid and keeps
    /// automatic edge switching disabled.
    ///
    /// # Errors
    ///
    /// Returns an error for duplicate source edges, zero identifiers, or
    /// out-of-range timing/geometry policy.
    pub fn new(
        routes: Vec<EdgeRoute>,
        activation_band_milli: u32,
        hysteresis_milli: u32,
        entry_inset_milli: u32,
        debounce_ms: u32,
        cooldown_ms: u32,
    ) -> Result<Self, EdgeConfigError> {
        if routes.len() > MAX_EDGE_ROUTES {
            return Err(EdgeConfigError::TooManyRoutes);
        }
        if activation_band_milli == 0
            || activation_band_milli > MAX_EDGE_BAND_MILLI
            || hysteresis_milli > MAX_EDGE_BAND_MILLI
            || entry_inset_milli > MAX_EDGE_BAND_MILLI
        {
            return Err(EdgeConfigError::InvalidGeometryPolicy);
        }
        if debounce_ms > MAX_EDGE_DEBOUNCE_MS || cooldown_ms > MAX_EDGE_COOLDOWN_MS {
            return Err(EdgeConfigError::InvalidTimingPolicy);
        }
        for (index, route) in routes.iter().enumerate() {
            if route.source_display.is_zero() || route.destination_display.is_zero() {
                return Err(EdgeConfigError::ZeroDisplayId);
            }
            if routes[..index].iter().any(|seen| {
                seen.source_display == route.source_display && seen.source_edge == route.source_edge
            }) {
                return Err(EdgeConfigError::DuplicateSourceEdge);
            }
        }
        Ok(Self {
            routes,
            activation_band_milli,
            hysteresis_milli,
            entry_inset_milli,
            debounce_ms,
            cooldown_ms,
        })
    }

    #[must_use]
    pub fn disabled() -> Self {
        Self {
            routes: Vec::new(),
            activation_band_milli: 8_000,
            hysteresis_milli: 12_000,
            entry_inset_milli: 4_000,
            debounce_ms: 80,
            cooldown_ms: 300,
        }
    }

    #[must_use]
    pub fn routes(&self) -> &[EdgeRoute] {
        &self.routes
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum EdgeConfigError {
    #[error("edge route count exceeds the supported maximum")]
    TooManyRoutes,
    #[error("edge route contains a zero display identifier")]
    ZeroDisplayId,
    #[error("more than one route uses the same local display edge")]
    DuplicateSourceEdge,
    #[error("edge geometry policy is outside the supported range")]
    InvalidGeometryPolicy,
    #[error("edge timing policy is outside the supported range")]
    InvalidTimingPolicy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PointerSample {
    pub display: SessionDisplayId,
    pub x: u32,
    pub y: u32,
    pub observed_at: MonotonicMillis,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TargetPointerPosition {
    pub display: SessionDisplayId,
    pub x: u32,
    pub y: u32,
}

/// A policy decision that still requires the normal authenticated focus lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EdgeSwitchDecision {
    pub route: EdgeRoute,
    pub target: TargetPointerPosition,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PreviousSample {
    display: SessionDisplayId,
    x: u32,
    y: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Candidate {
    route: EdgeRoute,
    entered_at: MonotonicMillis,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LatchedEdge {
    display: SessionDisplayId,
    edge: DisplayEdge,
}

/// Pure edge-policy state. It owns no transport, clock, or native display ID.
#[derive(Clone, Debug)]
pub struct EdgeSwitchController {
    config: EdgeSwitchConfig,
    previous: Option<PreviousSample>,
    candidate: Option<Candidate>,
    latched: Option<LatchedEdge>,
    last_switch_at: Option<MonotonicMillis>,
    topology_revisions: Option<(u64, u64)>,
}

impl EdgeSwitchController {
    #[must_use]
    pub const fn new(config: EdgeSwitchConfig) -> Self {
        Self {
            config,
            previous: None,
            candidate: None,
            latched: None,
            last_switch_at: None,
            topology_revisions: None,
        }
    }

    pub fn replace_config(&mut self, config: EdgeSwitchConfig) {
        self.config = config;
        self.reset_transient();
        self.latched = None;
        self.last_switch_at = None;
    }

    /// Observes one local pointer sample.
    ///
    /// A decision is possible only with local focus, a validated explicit route,
    /// a movement toward the configured edge, continuous dwell in the activation
    /// band, and an expired cooldown. The caller must request a focus lease and
    /// wait for its grant before sending `target` to the peer.
    #[must_use]
    pub fn observe(
        &mut self,
        focus: FocusState,
        sample: PointerSample,
        local_topology: &DisplayTopology,
        remote_topology: &DisplayTopology,
    ) -> Option<EdgeSwitchDecision> {
        let revisions = (local_topology.revision(), remote_topology.revision());
        if self.topology_revisions != Some(revisions) {
            self.reset_transient();
            self.latched = None;
            self.topology_revisions = Some(revisions);
        }

        if focus != FocusState::Local || self.config.routes.is_empty() {
            self.candidate = None;
            return None;
        }

        let Some(source) = local_topology.display(sample.display) else {
            self.reset_transient();
            return None;
        };

        if let Some(latched) = self.latched {
            if latched.display == sample.display
                && within_release_band(
                    source,
                    latched.edge,
                    sample,
                    self.config.activation_band_milli,
                    self.config.hysteresis_milli,
                )
            {
                self.remember(sample);
                return None;
            }
            self.latched = None;
        }

        if self.last_switch_at.is_some_and(|last| {
            sample.observed_at < last
                || sample.observed_at.get().saturating_sub(last.get())
                    < u64::from(self.config.cooldown_ms)
        }) {
            self.candidate = None;
            self.remember(sample);
            return None;
        }

        let selected = self.select_route(sample, source);
        let Some(route) = selected else {
            self.candidate = None;
            self.remember(sample);
            return None;
        };
        let Some(destination) = remote_topology.display(route.destination_display) else {
            self.candidate = None;
            self.remember(sample);
            return None;
        };

        let decision = match self.candidate {
            Some(candidate)
                if candidate.route == route
                    && sample.observed_at >= candidate.entered_at
                    && sample
                        .observed_at
                        .get()
                        .saturating_sub(candidate.entered_at.get())
                        >= u64::from(self.config.debounce_ms) =>
            {
                Some(EdgeSwitchDecision {
                    route,
                    target: map_target(
                        sample,
                        source,
                        destination,
                        route,
                        self.config.entry_inset_milli,
                    ),
                })
            }
            Some(candidate) if candidate.route == route => None,
            _ if self.moving_outward(sample, route.source_edge) => {
                self.candidate = Some(Candidate {
                    route,
                    entered_at: sample.observed_at,
                });
                None
            }
            _ => {
                self.candidate = None;
                None
            }
        };

        if decision.is_some() {
            self.candidate = None;
            self.latched = Some(LatchedEdge {
                display: route.source_display,
                edge: route.source_edge,
            });
            self.last_switch_at = Some(sample.observed_at);
        }
        self.remember(sample);
        decision
    }

    fn select_route(&self, sample: PointerSample, source: &DisplayDescriptor) -> Option<EdgeRoute> {
        self.config
            .routes
            .iter()
            .copied()
            .filter(|route| route.enabled && route.source_display == sample.display)
            .filter_map(|route| {
                edge_distance_milli(source, route.source_edge, sample)
                    .filter(|distance| *distance <= u64::from(self.config.activation_band_milli))
                    .map(|distance| (distance, route.source_edge, route))
            })
            .min_by_key(|(distance, edge, _)| (*distance, *edge))
            .map(|(_, _, route)| route)
    }

    fn moving_outward(&self, sample: PointerSample, edge: DisplayEdge) -> bool {
        let Some(previous) = self.previous else {
            return false;
        };
        if previous.display != sample.display {
            return false;
        }
        match edge {
            DisplayEdge::Left => sample.x < previous.x,
            DisplayEdge::Right => sample.x > previous.x,
            DisplayEdge::Top => sample.y < previous.y,
            DisplayEdge::Bottom => sample.y > previous.y,
        }
    }

    fn remember(&mut self, sample: PointerSample) {
        self.previous = Some(PreviousSample {
            display: sample.display,
            x: sample.x,
            y: sample.y,
        });
    }

    fn reset_transient(&mut self) {
        self.previous = None;
        self.candidate = None;
    }
}

fn within_release_band(
    display: &DisplayDescriptor,
    edge: DisplayEdge,
    sample: PointerSample,
    activation_band_milli: u32,
    hysteresis_milli: u32,
) -> bool {
    edge_distance_milli(display, edge, sample).is_some_and(|distance| {
        distance <= u64::from(activation_band_milli.saturating_add(hysteresis_milli))
    })
}

fn edge_distance_milli(
    display: &DisplayDescriptor,
    edge: DisplayEdge,
    sample: PointerSample,
) -> Option<u64> {
    if display.id() != sample.display {
        return None;
    }
    let (axis, length) = match edge {
        DisplayEdge::Left => (sample.x, display.logical_width_milli()),
        DisplayEdge::Right => (u32::MAX - sample.x, display.logical_width_milli()),
        DisplayEdge::Top => (sample.y, display.logical_height_milli()),
        DisplayEdge::Bottom => (u32::MAX - sample.y, display.logical_height_milli()),
    };
    Some(normalized_to_logical(axis, length))
}

fn map_target(
    sample: PointerSample,
    source: &DisplayDescriptor,
    destination: &DisplayDescriptor,
    route: EdgeRoute,
    entry_inset_milli: u32,
) -> TargetPointerPosition {
    let (source_along, source_length) = match route.source_edge {
        DisplayEdge::Left | DisplayEdge::Right => (sample.y, source.logical_height_milli()),
        DisplayEdge::Top | DisplayEdge::Bottom => (sample.x, source.logical_width_milli()),
    };
    let destination_length = match route.destination_edge {
        DisplayEdge::Left | DisplayEdge::Right => destination.logical_height_milli(),
        DisplayEdge::Top | DisplayEdge::Bottom => destination.logical_width_milli(),
    };
    let along = map_along_edge(
        source_along,
        source_length,
        destination_length,
        route.alignment,
    );
    let perpendicular_length = match route.destination_edge {
        DisplayEdge::Left | DisplayEdge::Right => destination.logical_width_milli(),
        DisplayEdge::Top | DisplayEdge::Bottom => destination.logical_height_milli(),
    };
    let inset = logical_to_normalized(
        u64::from(entry_inset_milli).min(perpendicular_length / 2),
        perpendicular_length,
    );
    let (x, y) = match route.destination_edge {
        DisplayEdge::Left => (inset, along),
        DisplayEdge::Right => (u32::MAX - inset, along),
        DisplayEdge::Top => (along, inset),
        DisplayEdge::Bottom => (along, u32::MAX - inset),
    };
    TargetPointerPosition {
        display: destination.id(),
        x,
        y,
    }
}

/// Maps a source sample through one explicit route using mixed-DPI logical
/// geometry. This does not authorize focus or input delivery.
#[must_use]
pub fn map_pointer_across_route(
    sample: PointerSample,
    local_topology: &DisplayTopology,
    remote_topology: &DisplayTopology,
    route: EdgeRoute,
    entry_inset_milli: u32,
) -> Option<TargetPointerPosition> {
    let source = local_topology.display(route.source_display)?;
    let destination = remote_topology.display(route.destination_display)?;
    if sample.display != route.source_display || entry_inset_milli > MAX_EDGE_BAND_MILLI {
        return None;
    }
    Some(map_target(
        sample,
        source,
        destination,
        route,
        entry_inset_milli,
    ))
}

fn map_along_edge(
    source_axis: u32,
    source_length: u64,
    destination_length: u64,
    alignment: EdgeAlignment,
) -> u32 {
    if alignment == EdgeAlignment::Stretch {
        return source_axis;
    }
    let source_position = normalized_to_logical(source_axis, source_length);
    let mapped = match alignment {
        EdgeAlignment::Start => i128::from(source_position),
        EdgeAlignment::Center => {
            i128::from(source_position)
                + (i128::from(destination_length) - i128::from(source_length)) / 2
        }
        EdgeAlignment::End => {
            i128::from(source_position) + i128::from(destination_length) - i128::from(source_length)
        }
        EdgeAlignment::Stretch => unreachable!("stretch returned above"),
    }
    .clamp(0, i128::from(destination_length));
    let mapped = u64::try_from(mapped).expect("clamped logical coordinate is nonnegative");
    logical_to_normalized(mapped, destination_length)
}

fn normalized_to_logical(axis: u32, logical_length: u64) -> u64 {
    let value = u128::from(axis) * u128::from(logical_length) / u128::from(u32::MAX);
    u64::try_from(value).expect("bounded display dimensions fit in u64")
}

fn logical_to_normalized(position: u64, logical_length: u64) -> u32 {
    if logical_length == 0 {
        return 0;
    }
    let value = u128::from(position.min(logical_length)) * u128::from(u32::MAX)
        / u128::from(logical_length);
    u32::try_from(value).expect("normalized coordinate fits in u32")
}

#[cfg(test)]
mod tests {
    use nodavo_protocol::{DisplayRotation, DisplayTopology};

    use super::*;

    fn topology(revision: u64, id: u32, width: u32, height: u32, scale: u16) -> DisplayTopology {
        DisplayTopology::new(
            revision,
            vec![
                DisplayDescriptor::new(
                    SessionDisplayId::new(id),
                    0,
                    0,
                    width,
                    height,
                    scale,
                    scale,
                    DisplayRotation::Degrees0,
                )
                .unwrap(),
            ],
        )
        .unwrap()
    }

    fn config(alignment: EdgeAlignment) -> EdgeSwitchConfig {
        EdgeSwitchConfig::new(
            vec![EdgeRoute::new(
                SessionDisplayId::new(1),
                DisplayEdge::Right,
                SessionDisplayId::new(2),
                DisplayEdge::Left,
                alignment,
                true,
            )],
            20_000,
            10_000,
            4_000,
            50,
            100,
        )
        .unwrap()
    }

    fn sample(x: u32, y: u32, at: u64) -> PointerSample {
        PointerSample {
            display: SessionDisplayId::new(1),
            x,
            y,
            observed_at: MonotonicMillis::new(at),
        }
    }

    #[test]
    fn empty_config_and_nonlocal_focus_never_switch() {
        let local = topology(1, 1, 1_920, 1_080, 1_000);
        let remote = topology(1, 2, 1_920, 1_080, 1_000);
        let mut disabled = EdgeSwitchController::new(EdgeSwitchConfig::disabled());
        assert_eq!(
            disabled.observe(FocusState::Local, sample(u32::MAX, 1, 1), &local, &remote),
            None
        );

        let mut enabled = EdgeSwitchController::new(config(EdgeAlignment::Stretch));
        assert_eq!(
            enabled.observe(
                FocusState::ControllingRemote {
                    lease_id: crate::LeaseId::new(1),
                    expires_at: MonotonicMillis::new(100),
                },
                sample(u32::MAX, 1, 1),
                &local,
                &remote,
            ),
            None
        );
    }

    #[test]
    fn requires_outward_motion_and_continuous_debounce() {
        let local = topology(1, 1, 1_920, 1_080, 1_000);
        let remote = topology(1, 2, 1_920, 1_080, 1_000);
        let mut controller = EdgeSwitchController::new(config(EdgeAlignment::Stretch));

        assert_eq!(
            controller.observe(
                FocusState::Local,
                sample(u32::MAX - 100_000_000, u32::MAX / 2, 0),
                &local,
                &remote,
            ),
            None
        );
        assert_eq!(
            controller.observe(
                FocusState::Local,
                sample(u32::MAX - 10_000_000, u32::MAX / 2, 10),
                &local,
                &remote,
            ),
            None
        );
        let decision = controller
            .observe(
                FocusState::Local,
                sample(u32::MAX, u32::MAX / 2, 60),
                &local,
                &remote,
            )
            .expect("debounced edge crossing");
        assert_eq!(decision.target.display, SessionDisplayId::new(2));
        assert!(decision.target.x > 0);
        assert_eq!(decision.target.y, u32::MAX / 2);
    }

    #[test]
    fn latch_requires_hysteresis_exit_before_rearming() {
        let local = topology(1, 1, 1_920, 1_080, 1_000);
        let remote = topology(1, 2, 1_920, 1_080, 1_000);
        let mut controller = EdgeSwitchController::new(config(EdgeAlignment::Stretch));
        for (x, at) in [
            (u32::MAX - 100_000_000, 0),
            (u32::MAX - 10_000_000, 10),
            (u32::MAX, 60),
        ] {
            let _ = controller.observe(
                FocusState::Local,
                sample(x, u32::MAX / 2, at),
                &local,
                &remote,
            );
        }
        assert_eq!(
            controller.observe(
                FocusState::Local,
                sample(u32::MAX, u32::MAX / 2, 500),
                &local,
                &remote,
            ),
            None
        );
        let _ = controller.observe(
            FocusState::Local,
            sample(u32::MAX / 2, u32::MAX / 2, 510),
            &local,
            &remote,
        );
        let _ = controller.observe(
            FocusState::Local,
            sample(u32::MAX - 10_000_000, u32::MAX / 2, 520),
            &local,
            &remote,
        );
        assert!(
            controller
                .observe(
                    FocusState::Local,
                    sample(u32::MAX, u32::MAX / 2, 580),
                    &local,
                    &remote,
                )
                .is_some()
        );
    }

    #[test]
    fn center_alignment_preserves_logical_distance_across_mixed_dpi() {
        let local = topology(1, 1, 3_840, 2_160, 2_000); // 1920x1080 logical.
        let remote = topology(1, 2, 2_560, 1_440, 2_000); // 1280x720 logical.
        let source = local.display(SessionDisplayId::new(1)).unwrap();
        let destination = remote.display(SessionDisplayId::new(2)).unwrap();
        let route = config(EdgeAlignment::Center).routes()[0];
        let top = map_target(sample(u32::MAX, 0, 0), source, destination, route, 4_000);
        let middle = map_target(
            sample(u32::MAX, u32::MAX / 2, 0),
            source,
            destination,
            route,
            4_000,
        );
        assert_eq!(top.y, 0); // Centered source overhang clamps safely.
        assert!(
            normalized_to_logical(middle.y, destination.logical_height_milli())
                .abs_diff(destination.logical_height_milli() / 2)
                <= 2
        );
    }

    #[test]
    fn config_rejects_ambiguous_source_edges() {
        let route = EdgeRoute::new(
            SessionDisplayId::new(1),
            DisplayEdge::Left,
            SessionDisplayId::new(2),
            DisplayEdge::Right,
            EdgeAlignment::Stretch,
            true,
        );
        assert_eq!(
            EdgeSwitchConfig::new(vec![route, route], 1, 0, 0, 0, 0),
            Err(EdgeConfigError::DuplicateSourceEdge)
        );
    }
}
