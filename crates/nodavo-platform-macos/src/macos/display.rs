//! Stable, bounded ownership of the current CoreGraphics display graph.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::thread;
use std::time::Duration;

use core_graphics::display::{CGDirectDisplayID, CGDisplay};
use nodavo_input::DisplayId;
use nodavo_protocol::{
    DisplayRotation, MAX_DISPLAY_ORIGIN_MILLI, MAX_DISPLAY_PIXEL_DIMENSION,
    MAX_DISPLAY_SCALE_MILLI, MAX_TOPOLOGY_DISPLAYS, MIN_DISPLAY_SCALE_MILLI,
};

use super::ffi;
use crate::{DisplayGeometry, MacPlatformError};

const SNAPSHOT_ATTEMPTS: usize = 8;
const PRE_SAMPLE_SETTLE: Duration = Duration::from_millis(30);
const POST_SAMPLE_SETTLE: Duration = Duration::from_millis(10);
const IDENTITY_RESET_FLAGS: u32 =
    ffi::DISPLAY_BEGIN_CONFIGURATION_FLAG | ffi::DISPLAY_IDENTITY_CHANGE_FLAGS;

#[derive(Clone, Debug, PartialEq)]
pub struct MacDisplaySnapshot {
    revision: u64,
    displays: Arc<[DisplayGeometry]>,
}

impl MacDisplaySnapshot {
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub fn displays(&self) -> &[DisplayGeometry] {
        &self.displays
    }
}

#[derive(Default)]
struct DisplayIdentities {
    next_id: u64,
    by_native: BTreeMap<CGDirectDisplayID, DisplayId>,
    revision: u64,
}

struct SharedDisplayState {
    identities: Mutex<DisplayIdentities>,
    refresh: Mutex<()>,
    snapshot: RwLock<Option<Arc<MacDisplaySnapshot>>>,
}

impl Default for SharedDisplayState {
    fn default() -> Self {
        Self {
            identities: Mutex::new(DisplayIdentities::default()),
            refresh: Mutex::new(()),
            snapshot: RwLock::new(None),
        }
    }
}

fn shared_state() -> Arc<SharedDisplayState> {
    static STATE: OnceLock<Arc<SharedDisplayState>> = OnceLock::new();
    Arc::clone(STATE.get_or_init(|| Arc::new(SharedDisplayState::default())))
}

/// Explicit ownership of CoreGraphics display-change observation.
///
/// The native callback performs only atomic bookkeeping and a nonblocking
/// capacity-one notification. Call [`Self::current_snapshot`] outside the
/// callback to consume a change and atomically publish fresh geometry shared
/// by capture and injection.
pub struct MacDisplayMonitor {
    native: Option<ffi::NativeDisplayMonitor>,
    state: Arc<SharedDisplayState>,
}

impl MacDisplayMonitor {
    /// Starts display observation and publishes one stable initial snapshot.
    ///
    /// # Errors
    ///
    /// Fails if callback registration or stable bounded enumeration fails.
    pub fn start() -> Result<Self, MacPlatformError> {
        let native = ffi::NativeDisplayMonitor::start()
            .map_err(|()| MacPlatformError::DisplayMonitorUnavailable)?;
        let monitor = Self {
            native: Some(native),
            state: shared_state(),
        };
        monitor.current_snapshot()?;
        Ok(monitor)
    }

    /// Returns true while a display reconfiguration is in progress or a
    /// completed change has not yet been incorporated into a stable snapshot.
    #[must_use]
    pub fn display_change_pending(&self) -> bool {
        ffi::display_change_pending()
    }

    /// Enumerates until two complete samples match under one callback
    /// generation, reconciles opaque identities, and publishes the result.
    ///
    /// # Errors
    ///
    /// Fails closed for a changing, oversized, empty, or invalid display graph.
    pub fn current_snapshot(&self) -> Result<Arc<MacDisplaySnapshot>, MacPlatformError> {
        refresh_snapshot(&self.state, 0)
    }

    /// Removes this monitor's callback registration reference. The shared
    /// geometry and retired opaque identifiers remain process-local so a later
    /// restart cannot reuse an identifier.
    ///
    /// # Errors
    ///
    /// Returns an error if CoreGraphics rejects callback removal.
    pub fn stop(&mut self) -> Result<(), MacPlatformError> {
        let Some(mut native) = self.native.take() else {
            return Ok(());
        };
        native
            .stop()
            .map_err(|()| MacPlatformError::DisplayMonitorUnavailable)
    }

    /// Reinstalls observation after a successful stop and refreshes geometry.
    ///
    /// # Errors
    ///
    /// Fails if this monitor is already running or registration/refresh fails.
    pub fn restart(&mut self) -> Result<(), MacPlatformError> {
        if self.native.is_some() {
            return Err(MacPlatformError::DisplayMonitorAlreadyRunning);
        }
        let native = ffi::NativeDisplayMonitor::start()
            .map_err(|()| MacPlatformError::DisplayMonitorUnavailable)?;
        self.native = Some(native);
        if let Err(error) = self.current_snapshot() {
            let _ = self.stop();
            return Err(error);
        }
        Ok(())
    }
}

impl Drop for MacDisplayMonitor {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

#[derive(Clone, Debug, PartialEq)]
struct RawDisplayGeometry {
    native_id: CGDirectDisplayID,
    origin_x: f64,
    origin_y: f64,
    width_points: f64,
    height_points: f64,
    width_pixels: u64,
    height_pixels: u64,
    rotation: DisplayRotation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct GenerationObservation {
    generation: u64,
    configuring: bool,
}

trait DisplayChangeSource {
    fn pending(&self) -> bool;
    fn configuring(&self) -> bool;
    fn generation(&self) -> u64;
    fn take_flags(&self, generation: u64) -> Option<u32>;
    fn mark_clean(&self, generation: u64) -> bool;
}

struct NativeDisplayChanges;

impl DisplayChangeSource for NativeDisplayChanges {
    fn pending(&self) -> bool {
        ffi::display_change_pending()
    }

    fn configuring(&self) -> bool {
        ffi::display_configuration_in_progress()
    }

    fn generation(&self) -> u64 {
        ffi::display_change_generation()
    }

    fn take_flags(&self, generation: u64) -> Option<u32> {
        ffi::take_display_change_flags(generation)
    }

    fn mark_clean(&self, generation: u64) -> bool {
        ffi::mark_display_change_clean(generation)
    }
}

pub(super) fn current_process_snapshot() -> Result<Arc<MacDisplaySnapshot>, MacPlatformError> {
    let forced_flags = if ffi::display_monitor_active() {
        0
    } else {
        // Without an active callback registration, CoreGraphics native IDs
        // may have been removed and reused between samples without any
        // observable generation. Treat every such enumeration as a standalone
        // snapshot and retire all prior opaque identities.
        IDENTITY_RESET_FLAGS
    };
    refresh_snapshot(&shared_state(), forced_flags)
}

pub(super) fn passive_process_snapshot() -> Result<Arc<MacDisplaySnapshot>, MacPlatformError> {
    if ffi::display_monitor_active() {
        clean_process_snapshot()
    } else {
        current_process_snapshot()
    }
}

pub(super) fn clean_process_snapshot() -> Result<Arc<MacDisplaySnapshot>, MacPlatformError> {
    let generation = ffi::display_change_generation();
    if ffi::display_change_pending() {
        return Err(MacPlatformError::DisplayConfigurationChanged);
    }
    let snapshot = shared_state()
        .snapshot
        .read()
        .map_err(|_| MacPlatformError::DisplayMonitorUnavailable)?
        .clone()
        .ok_or(MacPlatformError::DisplayConfigurationChanged)?;
    if ffi::display_change_pending() || ffi::display_change_generation() != generation {
        Err(MacPlatformError::DisplayConfigurationChanged)
    } else {
        Ok(snapshot)
    }
}

pub(super) fn clean_display_generation() -> Result<u64, MacPlatformError> {
    let generation = ffi::display_change_generation();
    if ffi::display_change_pending() {
        return Err(MacPlatformError::DisplayConfigurationChanged);
    }
    if ffi::display_change_generation() == generation {
        Ok(generation)
    } else {
        Err(MacPlatformError::DisplayConfigurationChanged)
    }
}

pub(super) fn display_generation_is_current(generation: u64) -> bool {
    if !generation_matches(
        generation,
        ffi::display_change_generation(),
        ffi::display_change_pending(),
    ) {
        return false;
    }
    generation_matches(
        generation,
        ffi::display_change_generation(),
        ffi::display_change_pending(),
    )
}

fn generation_matches(expected: u64, current: u64, pending: bool) -> bool {
    expected != 0 && !pending && current == expected
}

pub(super) fn mark_wake_dirty() {
    ffi::force_display_change(IDENTITY_RESET_FLAGS);
}

fn refresh_snapshot(
    state: &SharedDisplayState,
    forced_flags: u32,
) -> Result<Arc<MacDisplaySnapshot>, MacPlatformError> {
    refresh_snapshot_with(
        state,
        &NativeDisplayChanges,
        forced_flags,
        sample_once,
        thread::sleep,
    )
}

fn refresh_snapshot_with<S, F, W>(
    state: &SharedDisplayState,
    changes: &S,
    forced_flags: u32,
    mut sample: F,
    mut wait: W,
) -> Result<Arc<MacDisplaySnapshot>, MacPlatformError>
where
    S: DisplayChangeSource,
    F: FnMut() -> Result<Vec<RawDisplayGeometry>, MacPlatformError>,
    W: FnMut(Duration),
{
    let _refresh = state
        .refresh
        .lock()
        .map_err(|_| MacPlatformError::DisplayMonitorUnavailable)?;
    let mut last_error = MacPlatformError::DisplayTopologyUnstable;
    for _ in 0..SNAPSHOT_ATTEMPTS {
        if changes.configuring() {
            thread::yield_now();
            continue;
        }
        let generation = changes.generation();
        if changes.pending() {
            wait(PRE_SAMPLE_SETTLE);
        }
        let before_samples = generation_observation(changes);
        if !observation_matches(generation, before_samples) {
            last_error = MacPlatformError::DisplayTopologyUnstable;
            continue;
        }
        let first = match sample() {
            Ok(sample) => sample,
            Err(MacPlatformError::TooManyDisplays) => {
                return Err(MacPlatformError::TooManyDisplays);
            }
            Err(error) => {
                last_error = error;
                thread::yield_now();
                continue;
            }
        };
        let second = match sample() {
            Ok(sample) => sample,
            Err(MacPlatformError::TooManyDisplays) => {
                return Err(MacPlatformError::TooManyDisplays);
            }
            Err(error) => {
                last_error = error;
                thread::yield_now();
                continue;
            }
        };
        let after_samples = generation_observation(changes);
        if first != second || !observation_matches(generation, after_samples) {
            last_error = MacPlatformError::DisplayTopologyUnstable;
            thread::yield_now();
            continue;
        }
        if changes.pending() {
            wait(POST_SAMPLE_SETTLE);
        }
        let after_settle = generation_observation(changes);
        if !snapshot_candidate_is_stable(
            generation,
            [before_samples, after_samples, after_settle],
            first == second,
        ) {
            last_error = MacPlatformError::DisplayTopologyUnstable;
            continue;
        }
        let Some(flags) = changes.take_flags(generation) else {
            thread::yield_now();
            continue;
        };
        let snapshot = publish_sample(state, first, flags | forced_flags)?;
        if changes.mark_clean(generation) {
            return Ok(snapshot);
        }
        last_error = MacPlatformError::DisplayTopologyUnstable;
        thread::yield_now();
    }
    Err(last_error)
}

fn generation_observation(changes: &impl DisplayChangeSource) -> GenerationObservation {
    GenerationObservation {
        generation: changes.generation(),
        configuring: changes.configuring(),
    }
}

fn observation_matches(expected: u64, observation: GenerationObservation) -> bool {
    !observation.configuring && observation.generation == expected
}

fn snapshot_candidate_is_stable(
    expected: u64,
    observations: [GenerationObservation; 3],
    identical_samples: bool,
) -> bool {
    identical_samples
        && observations
            .into_iter()
            .all(|observation| observation_matches(expected, observation))
}

fn sample_once() -> Result<Vec<RawDisplayGeometry>, MacPlatformError> {
    let identifiers =
        ffi::active_display_ids_bounded(MAX_TOPOLOGY_DISPLAYS).map_err(|error| match error {
            ffi::NativeDisplayListError::CoreGraphics => MacPlatformError::CoreGraphics,
            ffi::NativeDisplayListError::TooMany => MacPlatformError::TooManyDisplays,
        })?;
    if identifiers.is_empty() {
        return Err(MacPlatformError::InvalidNativeEvent);
    }
    let mut displays = Vec::with_capacity(identifiers.len());
    for native_id in identifiers {
        let display = CGDisplay::new(native_id);
        let bounds = display.bounds();
        let width_pixels = display.pixels_wide();
        let height_pixels = display.pixels_high();
        let rotation = rotation(display.rotation())?;
        displays.push(RawDisplayGeometry {
            native_id,
            origin_x: bounds.origin.x,
            origin_y: bounds.origin.y,
            width_points: bounds.size.width,
            height_points: bounds.size.height,
            width_pixels,
            height_pixels,
            rotation,
        });
    }
    canonicalize_sample(displays)
}

fn canonicalize_sample(
    mut displays: Vec<RawDisplayGeometry>,
) -> Result<Vec<RawDisplayGeometry>, MacPlatformError> {
    if displays.is_empty() || displays.len() > MAX_TOPOLOGY_DISPLAYS {
        return Err(MacPlatformError::InvalidNativeEvent);
    }
    let mut seen = BTreeSet::new();
    for display in &displays {
        if display.native_id == 0 || !seen.insert(display.native_id) {
            return Err(MacPlatformError::InvalidNativeEvent);
        }
        validate_geometry(
            display.origin_x,
            display.origin_y,
            display.width_points,
            display.height_points,
            display.width_pixels,
            display.height_pixels,
        )?;
    }
    displays.sort_unstable_by_key(|display| display.native_id);
    Ok(displays)
}

fn validate_geometry(
    origin_x: f64,
    origin_y: f64,
    width_points: f64,
    height_points: f64,
    width_pixels: u64,
    height_pixels: u64,
) -> Result<(), MacPlatformError> {
    if !origin_x.is_finite()
        || !origin_y.is_finite()
        || !width_points.is_finite()
        || !height_points.is_finite()
        || width_points <= 0.0
        || height_points <= 0.0
        || origin_x.abs() > f64::from(MAX_DISPLAY_ORIGIN_MILLI) / 1_000.0
        || origin_y.abs() > f64::from(MAX_DISPLAY_ORIGIN_MILLI) / 1_000.0
        || width_pixels == 0
        || height_pixels == 0
        || width_pixels > u64::from(MAX_DISPLAY_PIXEL_DIMENSION)
        || height_pixels > u64::from(MAX_DISPLAY_PIXEL_DIMENSION)
    {
        return Err(MacPlatformError::InvalidNativeEvent);
    }
    let width_pixels =
        u32::try_from(width_pixels).map_err(|_| MacPlatformError::InvalidNativeEvent)?;
    let height_pixels =
        u32::try_from(height_pixels).map_err(|_| MacPlatformError::InvalidNativeEvent)?;
    let scale_x = f64::from(width_pixels) / width_points;
    let scale_y = f64::from(height_pixels) / height_points;
    let minimum = f64::from(MIN_DISPLAY_SCALE_MILLI) / 1_000.0;
    let maximum = f64::from(MAX_DISPLAY_SCALE_MILLI) / 1_000.0;
    if !scale_x.is_finite()
        || !scale_y.is_finite()
        || !(minimum..=maximum).contains(&scale_x)
        || !(minimum..=maximum).contains(&scale_y)
    {
        return Err(MacPlatformError::InvalidNativeEvent);
    }
    Ok(())
}

fn rotation(value: f64) -> Result<DisplayRotation, MacPlatformError> {
    const TOLERANCE: f64 = 0.001;

    if !value.is_finite() {
        return Err(MacPlatformError::InvalidNativeEvent);
    }
    let normalized = value.rem_euclid(360.0);
    if normalized <= TOLERANCE || (360.0 - normalized) <= TOLERANCE {
        Ok(DisplayRotation::Degrees0)
    } else if (normalized - 90.0).abs() <= TOLERANCE {
        Ok(DisplayRotation::Degrees90)
    } else if (normalized - 180.0).abs() <= TOLERANCE {
        Ok(DisplayRotation::Degrees180)
    } else if (normalized - 270.0).abs() <= TOLERANCE {
        Ok(DisplayRotation::Degrees270)
    } else {
        Err(MacPlatformError::InvalidNativeEvent)
    }
}

fn publish_sample(
    state: &SharedDisplayState,
    raw: Vec<RawDisplayGeometry>,
    flags: u32,
) -> Result<Arc<MacDisplaySnapshot>, MacPlatformError> {
    let mut identities = state
        .identities
        .lock()
        .map_err(|_| MacPlatformError::DisplayMonitorUnavailable)?;
    if flags & IDENTITY_RESET_FLAGS != 0 {
        identities.by_native.clear();
    }
    let active = raw
        .iter()
        .map(|display| display.native_id)
        .collect::<BTreeSet<_>>();
    identities
        .by_native
        .retain(|native_id, _| active.contains(native_id));

    let mut displays = Vec::with_capacity(raw.len());
    for display in raw {
        let id = if let Some(id) = identities.by_native.get(&display.native_id).copied() {
            id
        } else {
            identities.next_id = identities
                .next_id
                .checked_add(1)
                .filter(|id| *id != 0)
                .ok_or(MacPlatformError::DisplayIdentityExhausted)?;
            let id = DisplayId::new(identities.next_id);
            identities.by_native.insert(display.native_id, id);
            id
        };
        displays.push(DisplayGeometry {
            id,
            origin_x: display.origin_x,
            origin_y: display.origin_y,
            width_points: display.width_points,
            height_points: display.height_points,
            width_pixels: display.width_pixels,
            height_pixels: display.height_pixels,
            rotation: display.rotation,
        });
    }

    let current = state
        .snapshot
        .read()
        .map_err(|_| MacPlatformError::DisplayMonitorUnavailable)?
        .clone();
    if let Some(current) = current
        && current.displays() == displays.as_slice()
    {
        return Ok(current);
    }
    identities.revision = identities
        .revision
        .checked_add(1)
        .filter(|revision| *revision != 0)
        .ok_or(MacPlatformError::DisplayIdentityExhausted)?;
    let snapshot = Arc::new(MacDisplaySnapshot {
        revision: identities.revision,
        displays: displays.into(),
    });
    *state
        .snapshot
        .write()
        .map_err(|_| MacPlatformError::DisplayMonitorUnavailable)? = Some(Arc::clone(&snapshot));
    Ok(snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

    struct FakeChanges {
        pending: AtomicBool,
        configuring: AtomicBool,
        generation: AtomicU64,
        flags: AtomicU32,
    }

    impl DisplayChangeSource for FakeChanges {
        fn pending(&self) -> bool {
            self.pending.load(Ordering::Acquire)
        }

        fn configuring(&self) -> bool {
            self.configuring.load(Ordering::Acquire)
        }

        fn generation(&self) -> u64 {
            self.generation.load(Ordering::Acquire)
        }

        fn take_flags(&self, generation: u64) -> Option<u32> {
            (self.generation() == generation && !self.configuring())
                .then(|| self.flags.swap(0, Ordering::AcqRel))
        }

        fn mark_clean(&self, generation: u64) -> bool {
            if self.generation() != generation || self.configuring() {
                return false;
            }
            self.pending.store(false, Ordering::Release);
            self.generation() == generation && !self.configuring()
        }
    }

    fn raw(native_id: u32, origin_x: f64) -> RawDisplayGeometry {
        RawDisplayGeometry {
            native_id,
            origin_x,
            origin_y: 0.0,
            width_points: 1_920.0,
            height_points: 1_080.0,
            width_pixels: 3_840,
            height_pixels: 2_160,
            rotation: DisplayRotation::Degrees0,
        }
    }

    #[test]
    fn rotation_accepts_only_supported_quadrants() {
        assert_eq!(rotation(0.0), Ok(DisplayRotation::Degrees0));
        assert_eq!(rotation(90.0), Ok(DisplayRotation::Degrees90));
        assert_eq!(rotation(-90.0), Ok(DisplayRotation::Degrees270));
        assert_eq!(rotation(360.0), Ok(DisplayRotation::Degrees0));
        assert_eq!(rotation(45.0), Err(MacPlatformError::InvalidNativeEvent));
        assert_eq!(
            rotation(f64::NAN),
            Err(MacPlatformError::InvalidNativeEvent)
        );
    }

    #[test]
    fn canonical_sample_sorts_ids_and_rejects_duplicates_or_excess() {
        let sorted = canonicalize_sample(vec![raw(9, 1_920.0), raw(7, 0.0)]).unwrap();
        assert_eq!(
            sorted
                .iter()
                .map(|display| display.native_id)
                .collect::<Vec<_>>(),
            [7, 9]
        );
        assert_eq!(
            canonicalize_sample(vec![raw(7, 0.0), raw(7, 1_920.0)]),
            Err(MacPlatformError::InvalidNativeEvent)
        );
        assert_eq!(
            canonicalize_sample(
                (0..=MAX_TOPOLOGY_DISPLAYS)
                    .map(|index| {
                        let index = u32::try_from(index).unwrap();
                        raw(index + 1, f64::from(index))
                    })
                    .collect(),
            ),
            Err(MacPlatformError::InvalidNativeEvent)
        );
    }

    #[test]
    fn geometry_validation_is_finite_nonzero_and_protocol_bounded() {
        assert!(validate_geometry(-1_920.0, 0.0, 1_920.0, 1_080.0, 3_840, 2_160).is_ok());
        assert_eq!(
            validate_geometry(f64::NAN, 0.0, 1.0, 1.0, 1, 1),
            Err(MacPlatformError::InvalidNativeEvent)
        );
        assert_eq!(
            validate_geometry(0.0, 0.0, 1.0, 1.0, 0, 1),
            Err(MacPlatformError::InvalidNativeEvent)
        );
        assert_eq!(
            validate_geometry(
                0.0,
                0.0,
                1.0,
                1.0,
                u64::from(MAX_DISPLAY_PIXEL_DIMENSION) + 1,
                1,
            ),
            Err(MacPlatformError::InvalidNativeEvent)
        );
    }

    #[test]
    fn opaque_id_is_monotonic_and_never_reused_after_removal() {
        let state = SharedDisplayState::default();
        let first = publish_sample(&state, vec![raw(7, 0.0)], 0).unwrap();
        let first_id = first.displays()[0].id;
        publish_sample(&state, vec![raw(8, 0.0)], 0).unwrap();
        let returned = publish_sample(&state, vec![raw(7, 0.0)], 0).unwrap();
        assert_ne!(returned.displays()[0].id, first_id);
        assert!(returned.displays()[0].id.get() > first_id.get());
    }

    #[test]
    fn identity_change_flags_retire_even_still_present_native_ids() {
        let state = SharedDisplayState::default();
        let first = publish_sample(&state, vec![raw(7, 0.0), raw(8, 1_920.0)], 0).unwrap();
        let first_ids = first
            .displays()
            .iter()
            .map(|display| display.id)
            .collect::<Vec<_>>();
        let second = publish_sample(
            &state,
            vec![raw(7, 0.0), raw(8, 1_920.0)],
            IDENTITY_RESET_FLAGS,
        )
        .unwrap();
        assert!(
            second
                .displays()
                .iter()
                .zip(first_ids)
                .all(|(display, old)| display.id != old)
        );
    }

    #[test]
    fn geometry_change_keeps_identity_and_advances_snapshot_revision() {
        let state = SharedDisplayState::default();
        let first = publish_sample(&state, vec![raw(7, 0.0)], 0).unwrap();
        let second = publish_sample(&state, vec![raw(7, 10.0)], 0).unwrap();
        assert_eq!(first.displays()[0].id, second.displays()[0].id);
        assert!(second.revision() > first.revision());
    }

    #[test]
    fn routing_generation_fails_closed_on_begin_or_any_later_generation() {
        assert!(generation_matches(7, 7, false));
        assert!(!generation_matches(7, 7, true));
        assert!(!generation_matches(7, 8, false));
        assert!(!generation_matches(0, 0, false));
    }

    #[test]
    fn dirty_state_can_be_refreshed_externally_without_the_monitor_handle() {
        let state = SharedDisplayState::default();
        let initial = publish_sample(&state, vec![raw(7, 0.0)], 0).unwrap();
        let changes = FakeChanges {
            pending: AtomicBool::new(true),
            configuring: AtomicBool::new(false),
            generation: AtomicU64::new(9),
            flags: AtomicU32::new(IDENTITY_RESET_FLAGS),
        };
        let refreshed =
            refresh_snapshot_with(&state, &changes, 0, || Ok(vec![raw(7, 10.0)]), |_| {}).unwrap();
        assert!(!changes.pending());
        assert!(refreshed.revision() > initial.revision());
        assert_ne!(refreshed.displays()[0].id, initial.displays()[0].id);
        assert_eq!(
            state.snapshot.read().unwrap().as_deref(),
            Some(refreshed.as_ref())
        );
    }

    #[test]
    fn multi_begin_and_interleaved_post_never_publish_an_intermediate_graph() {
        let begin = GenerationObservation {
            generation: 11,
            configuring: true,
        };
        let first_post = GenerationObservation {
            generation: 12,
            configuring: false,
        };
        let later_post = GenerationObservation {
            generation: 13,
            configuring: false,
        };
        assert!(!snapshot_candidate_is_stable(
            11,
            [begin, first_post, later_post],
            true,
        ));
        assert!(!snapshot_candidate_is_stable(
            12,
            [first_post, first_post, later_post],
            true,
        ));
        assert!(snapshot_candidate_is_stable(
            13,
            [later_post, later_post, later_post],
            true,
        ));
        assert!(!snapshot_candidate_is_stable(
            13,
            [later_post, later_post, later_post],
            false,
        ));
    }

    #[test]
    fn multi_begin_summary_retires_ids_on_first_post_before_later_identity_post() {
        let state = SharedDisplayState::default();
        let initial = publish_sample(&state, vec![raw(7, 0.0), raw(8, 1_920.0)], 0).unwrap();
        let initial_ids = initial
            .displays()
            .iter()
            .map(|display| display.id)
            .collect::<Vec<_>>();

        // The first stable post-configuration graph can arrive before a later
        // per-display add/remove callback. Begin alone must already retire all
        // identities, including unchanged/reused native display numbers.
        let first_post = publish_sample(
            &state,
            vec![raw(7, 0.0), raw(8, 1_920.0)],
            ffi::DISPLAY_BEGIN_CONFIGURATION_FLAG,
        )
        .unwrap();
        assert!(
            first_post
                .displays()
                .iter()
                .zip(&initial_ids)
                .all(|(display, old)| display.id != *old)
        );

        let first_post_ids = first_post
            .displays()
            .iter()
            .map(|display| display.id)
            .collect::<Vec<_>>();
        let later_identity_post = publish_sample(
            &state,
            vec![raw(7, 0.0), raw(8, 1_920.0)],
            ffi::DISPLAY_IDENTITY_CHANGE_FLAGS,
        )
        .unwrap();
        assert!(
            later_identity_post
                .displays()
                .iter()
                .zip(first_post_ids)
                .all(|(display, old)| display.id != old)
        );
    }

    #[test]
    fn standalone_refresh_forces_snapshot_scoped_identities() {
        let state = SharedDisplayState::default();
        let initial = publish_sample(&state, vec![raw(7, 0.0)], 0).unwrap();
        let changes = FakeChanges {
            pending: AtomicBool::new(false),
            configuring: AtomicBool::new(false),
            generation: AtomicU64::new(9),
            flags: AtomicU32::new(0),
        };
        let refreshed = refresh_snapshot_with(
            &state,
            &changes,
            IDENTITY_RESET_FLAGS,
            || Ok(vec![raw(7, 0.0)]),
            |_| {},
        )
        .unwrap();
        assert_ne!(refreshed.displays()[0].id, initial.displays()[0].id);
        assert!(refreshed.revision() > initial.revision());
    }
}
