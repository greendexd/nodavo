//! Pure display-snapshot validation and stability tracking.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use nodavo_input::DisplayId;
use nodavo_protocol::{
    DisplayRotation, MAX_DISPLAY_ORIGIN_MILLI, MAX_DISPLAY_PIXEL_DIMENSION,
    MAX_DISPLAY_SCALE_MILLI, MIN_DISPLAY_SCALE_MILLI,
};

use crate::{DisplayGeometry, MAX_DISPLAYS, WindowsPlatformError};

/// One complete, stable display graph observed by the Windows platform worker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplaySnapshot {
    revision: u64,
    displays: Arc<[DisplayGeometry]>,
}

impl DisplaySnapshot {
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub fn displays(&self) -> &[DisplayGeometry] {
        &self.displays
    }
}

/// Availability of the authoritative, full display snapshot.
///
/// `Pending` and `Unavailable` deliberately do not expose the last good graph:
/// stale geometry must never remain usable for capture or injection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DisplaySnapshotState {
    Pending,
    Available(DisplaySnapshot),
    Unavailable,
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct NativeDisplayKey(Vec<u16>);

impl NativeDisplayKey {
    pub(crate) fn new(units: &[u16]) -> Result<Self, WindowsPlatformError> {
        let Some(nul) = units.iter().position(|unit| *unit == 0) else {
            return Err(WindowsPlatformError::InvalidDisplay);
        };
        if nul == 0 {
            return Err(WindowsPlatformError::InvalidDisplay);
        }
        let normalized = units[..nul]
            .iter()
            .map(|unit| match *unit {
                0x41..=0x5a => unit + 0x20,
                value => value,
            })
            .collect();
        Ok(Self(normalized))
    }

    pub(crate) fn from_display_config_target(
        adapter_low: u32,
        adapter_high: i32,
        target_id: u32,
        device_path: &[u16],
    ) -> Result<Self, WindowsPlatformError> {
        let path = Self::new(device_path)?;
        let mut key = Vec::with_capacity(path.0.len() + 8);
        key.extend_from_slice(&[0xffff, 1]);
        for value in [adapter_low, adapter_high.cast_unsigned(), target_id] {
            let bytes = value.to_le_bytes();
            key.push(u16::from_le_bytes([bytes[0], bytes[1]]));
            key.push(u16::from_le_bytes([bytes[2], bytes[3]]));
        }
        key.extend(path.0);
        Ok(Self(key))
    }
}

pub(crate) fn unique_native_display_key(
    keys: Vec<NativeDisplayKey>,
) -> Result<NativeDisplayKey, WindowsPlatformError> {
    let mut keys = keys.into_iter();
    let key = keys.next().ok_or(WindowsPlatformError::InvalidDisplay)?;
    if keys.next().is_some() {
        return Err(WindowsPlatformError::InvalidDisplay);
    }
    Ok(key)
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct NativeDisplayGeometry {
    pub(crate) key: NativeDisplayKey,
    pub(crate) left: i32,
    pub(crate) top: i32,
    pub(crate) width_pixels: u32,
    pub(crate) height_pixels: u32,
    pub(crate) dpi_x: u32,
    pub(crate) dpi_y: u32,
    pub(crate) rotation: DisplayRotation,
    pub(crate) primary: bool,
}

pub(crate) const fn display_rotation(native: u32) -> Result<DisplayRotation, WindowsPlatformError> {
    match native {
        0 => Ok(DisplayRotation::Degrees0),
        1 => Ok(DisplayRotation::Degrees90),
        2 => Ok(DisplayRotation::Degrees180),
        3 => Ok(DisplayRotation::Degrees270),
        _ => Err(WindowsPlatformError::InvalidDisplay),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum DisplayTrackerUpdate {
    Unchanged,
    Pending,
    Available(DisplaySnapshot),
    Unavailable,
}

pub(crate) struct DisplayTracker {
    next_id: u64,
    revision: u64,
    active_ids: BTreeMap<NativeDisplayKey, DisplayId>,
    published: Option<Vec<NativeDisplayGeometry>>,
    pending: Option<Vec<NativeDisplayGeometry>>,
    available: bool,
}

pub(crate) struct DisplayWorkerLifecycle {
    gate: Mutex<()>,
    next_generation: AtomicU64,
}

impl Default for DisplayWorkerLifecycle {
    fn default() -> Self {
        Self {
            gate: Mutex::new(()),
            next_generation: AtomicU64::new(0),
        }
    }
}

impl DisplayWorkerLifecycle {
    pub(crate) fn lock(&self) -> Result<MutexGuard<'_, ()>, WindowsPlatformError> {
        self.gate
            .lock()
            .map_err(|_| WindowsPlatformError::DisplayUnavailable)
    }

    pub(crate) fn next_generation(&self) -> Result<u64, WindowsPlatformError> {
        let previous = self
            .next_generation
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |generation| {
                generation.checked_add(1).filter(|next| *next != 0)
            })
            .map_err(|_| WindowsPlatformError::DisplayUnavailable)?;
        previous
            .checked_add(1)
            .ok_or(WindowsPlatformError::DisplayUnavailable)
    }
}

impl Default for DisplayTracker {
    fn default() -> Self {
        Self {
            next_id: 1,
            revision: 0,
            active_ids: BTreeMap::new(),
            published: None,
            pending: None,
            available: false,
        }
    }
}

impl DisplayTracker {
    pub(crate) fn observe(
        &mut self,
        observation: Result<Vec<NativeDisplayGeometry>, WindowsPlatformError>,
    ) -> DisplayTrackerUpdate {
        let Ok(mut displays) = observation.and_then(validate_observation) else {
            self.pending = None;
            self.available = false;
            return DisplayTrackerUpdate::Unavailable;
        };
        displays.sort_by(|left, right| left.key.cmp(&right.key));

        if self.available && self.published.as_ref() == Some(&displays) {
            self.pending = None;
            return DisplayTrackerUpdate::Unchanged;
        }

        let was_available = self.available;
        self.available = false;
        if self.pending.as_ref() != Some(&displays) {
            self.pending = Some(displays);
            return if was_available {
                DisplayTrackerUpdate::Unavailable
            } else {
                DisplayTrackerUpdate::Pending
            };
        }

        self.pending = None;
        match self.publish(displays) {
            Ok(snapshot) => DisplayTrackerUpdate::Available(snapshot),
            Err(_) => DisplayTrackerUpdate::Unavailable,
        }
    }

    fn publish(
        &mut self,
        displays: Vec<NativeDisplayGeometry>,
    ) -> Result<DisplaySnapshot, WindowsPlatformError> {
        let observed_keys = displays
            .iter()
            .map(|display| display.key.clone())
            .collect::<BTreeSet<_>>();
        self.active_ids.retain(|key, _| observed_keys.contains(key));

        for key in &observed_keys {
            if self.active_ids.contains_key(key) {
                continue;
            }
            let id = DisplayId::new(self.next_id);
            self.next_id = self
                .next_id
                .checked_add(1)
                .ok_or(WindowsPlatformError::InvalidDisplay)?;
            self.active_ids.insert(key.clone(), id);
        }

        let mut canonical = displays
            .iter()
            .map(|display| {
                let id = self
                    .active_ids
                    .get(&display.key)
                    .copied()
                    .ok_or(WindowsPlatformError::InvalidDisplay)?;
                Ok(DisplayGeometry {
                    id,
                    left: display.left,
                    top: display.top,
                    width_pixels: display.width_pixels,
                    height_pixels: display.height_pixels,
                    dpi_x: display.dpi_x,
                    dpi_y: display.dpi_y,
                    rotation: display.rotation,
                    primary: display.primary,
                })
            })
            .collect::<Result<Vec<_>, WindowsPlatformError>>()?;
        canonical.sort_by_key(|display| display.id);
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(WindowsPlatformError::InvalidDisplay)?;
        let snapshot = DisplaySnapshot {
            revision: self.revision,
            displays: canonical.into(),
        };
        self.published = Some(displays);
        self.available = true;
        Ok(snapshot)
    }
}

fn validate_observation(
    displays: Vec<NativeDisplayGeometry>,
) -> Result<Vec<NativeDisplayGeometry>, WindowsPlatformError> {
    if displays.is_empty() || displays.len() > MAX_DISPLAYS {
        return Err(WindowsPlatformError::InvalidDisplay);
    }
    let mut keys = BTreeSet::new();
    let mut primary_count = 0_usize;
    for display in &displays {
        if !keys.insert(&display.key)
            || display.width_pixels == 0
            || display.height_pixels == 0
            || display.width_pixels > MAX_DISPLAY_PIXEL_DIMENSION
            || display.height_pixels > MAX_DISPLAY_PIXEL_DIMENSION
            || display.dpi_x == 0
            || display.dpi_y == 0
            || !valid_scale(display.dpi_x)
            || !valid_scale(display.dpi_y)
            || !valid_origin(display.left, display.dpi_x)
            || !valid_origin(display.top, display.dpi_y)
            || i64::from(display.left) + i64::from(display.width_pixels) > i64::from(i32::MAX)
            || i64::from(display.top) + i64::from(display.height_pixels) > i64::from(i32::MAX)
        {
            return Err(WindowsPlatformError::InvalidDisplay);
        }
        primary_count += usize::from(display.primary);
    }
    if primary_count != 1 {
        return Err(WindowsPlatformError::InvalidDisplay);
    }
    Ok(displays)
}

fn valid_scale(dpi: u32) -> bool {
    let scale = u64::from(dpi) * 1_000 / 96;
    (u64::from(MIN_DISPLAY_SCALE_MILLI)..=u64::from(MAX_DISPLAY_SCALE_MILLI)).contains(&scale)
}

fn valid_origin(position: i32, dpi: u32) -> bool {
    let logical_milli = i64::from(position) * 96_000 / i64::from(dpi);
    logical_milli.unsigned_abs() <= u64::from(MAX_DISPLAY_ORIGIN_MILLI.unsigned_abs())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn native(key: u16, left: i32, dpi: u32, primary: bool) -> NativeDisplayGeometry {
        NativeDisplayGeometry {
            key: NativeDisplayKey::new(&[key, 0]).expect("valid fixture key"),
            left,
            top: 0,
            width_pixels: 1_920,
            height_pixels: 1_080,
            dpi_x: dpi,
            dpi_y: dpi,
            rotation: DisplayRotation::Degrees0,
            primary,
        }
    }

    #[test]
    fn native_device_keys_are_ascii_case_canonical() {
        let upper =
            NativeDisplayKey::new(&[u16::from(b'D'), u16::from(b'I'), u16::from(b'S'), 0]).unwrap();
        let lower =
            NativeDisplayKey::new(&[u16::from(b'd'), u16::from(b'i'), u16::from(b's'), 0]).unwrap();
        assert!(upper == lower);
        assert!(NativeDisplayKey::new(&[0]).is_err());
        assert!(NativeDisplayKey::new(&[u16::from(b'x')]).is_err());
    }

    #[test]
    fn native_identity_requires_one_unique_active_interface() {
        let first = NativeDisplayKey::new(&[1, 0]).unwrap();
        let second = NativeDisplayKey::new(&[2, 0]).unwrap();
        assert!(unique_native_display_key(Vec::new()).is_err());
        assert!(unique_native_display_key(vec![first.clone(), second]).is_err());
        assert!(unique_native_display_key(vec![first.clone(), first.clone()]).is_err());
        assert!(unique_native_display_key(vec![first]).is_ok());
    }

    #[test]
    fn display_config_identity_includes_non_recyclable_target_selector() {
        let path = [u16::from(b'M'), u16::from(b'O'), u16::from(b'N'), 0];
        let first = NativeDisplayKey::from_display_config_target(7, -2, 10, &path).unwrap();
        let same_canonical_path = [u16::from(b'm'), u16::from(b'o'), u16::from(b'n'), 0];
        let same =
            NativeDisplayKey::from_display_config_target(7, -2, 10, &same_canonical_path).unwrap();
        let replacement =
            NativeDisplayKey::from_display_config_target(7, -2, 11, &same_canonical_path).unwrap();

        assert!(first == same);
        assert!(first != replacement);
    }

    #[test]
    fn native_rotation_is_strictly_bounded() {
        assert_eq!(display_rotation(0), Ok(DisplayRotation::Degrees0));
        assert_eq!(display_rotation(1), Ok(DisplayRotation::Degrees90));
        assert_eq!(display_rotation(2), Ok(DisplayRotation::Degrees180));
        assert_eq!(display_rotation(3), Ok(DisplayRotation::Degrees270));
        assert_eq!(
            display_rotation(4),
            Err(WindowsPlatformError::InvalidDisplay)
        );
        assert_eq!(
            display_rotation(u32::MAX),
            Err(WindowsPlatformError::InvalidDisplay)
        );
    }

    #[test]
    fn concurrent_restart_sequences_never_interleave_generations() {
        let lifecycle = Arc::new(DisplayWorkerLifecycle::default());
        let events = Arc::new(Mutex::new(Vec::new()));
        let start = Arc::new(std::sync::Barrier::new(3));
        let mut workers = Vec::new();
        for label in [1_u8, 2_u8] {
            let lifecycle = Arc::clone(&lifecycle);
            let events = Arc::clone(&events);
            let start = Arc::clone(&start);
            workers.push(std::thread::spawn(move || {
                start.wait();
                let _gate = lifecycle.lock().unwrap();
                events.lock().unwrap().push((label, "stop", 0));
                std::thread::yield_now();
                events.lock().unwrap().push((label, "join", 0));
                let generation = lifecycle.next_generation().unwrap();
                events.lock().unwrap().push((label, "start", generation));
            }));
        }
        start.wait();
        for worker in workers {
            worker.join().unwrap();
        }

        let events = events.lock().unwrap();
        assert_eq!(events.len(), 6);
        assert!(events.chunks_exact(3).all(|sequence| {
            sequence[0].0 == sequence[1].0
                && sequence[1].0 == sequence[2].0
                && sequence[0].1 == "stop"
                && sequence[1].1 == "join"
                && sequence[2].1 == "start"
        }));
        let mut generations = events
            .chunks_exact(3)
            .map(|sequence| sequence[2].2)
            .collect::<Vec<_>>();
        generations.sort_unstable();
        assert_eq!(generations, vec![1, 2]);
    }

    fn confirm(
        tracker: &mut DisplayTracker,
        displays: Vec<NativeDisplayGeometry>,
    ) -> DisplaySnapshot {
        assert!(matches!(
            tracker.observe(Ok(displays.clone())),
            DisplayTrackerUpdate::Pending | DisplayTrackerUpdate::Unavailable
        ));
        match tracker.observe(Ok(displays)) {
            DisplayTrackerUpdate::Available(snapshot) => snapshot,
            update => panic!("expected available snapshot, got {update:?}"),
        }
    }

    #[test]
    fn requires_two_identical_canonical_samples() {
        let mut tracker = DisplayTracker::default();
        let displays = vec![native(2, 1_920, 144, false), native(1, 0, 96, true)];
        assert_eq!(
            tracker.observe(Ok(displays.clone())),
            DisplayTrackerUpdate::Pending
        );
        let mut reordered = displays;
        reordered.reverse();
        let DisplayTrackerUpdate::Available(snapshot) = tracker.observe(Ok(reordered)) else {
            panic!("canonical reorder must confirm the pending graph");
        };
        assert_eq!(snapshot.revision(), 1);
        assert_eq!(snapshot.displays()[0].id, DisplayId::new(1));
        assert_eq!(snapshot.displays()[1].id, DisplayId::new(2));
    }

    #[test]
    fn divergence_is_unavailable_until_confirmed() {
        let mut tracker = DisplayTracker::default();
        let initial = vec![native(1, 0, 96, true)];
        let first = confirm(&mut tracker, initial.clone());
        assert_eq!(first.revision(), 1);
        let changed = vec![native(1, 0, 120, true)];
        assert_eq!(
            tracker.observe(Ok(changed.clone())),
            DisplayTrackerUpdate::Unavailable
        );
        let DisplayTrackerUpdate::Available(second) = tracker.observe(Ok(changed)) else {
            panic!("second equal sample must publish");
        };
        assert_eq!(second.revision(), 2);
    }

    #[test]
    fn observation_error_preserves_ids_but_requires_stable_recovery() {
        let mut tracker = DisplayTracker::default();
        let initial = vec![native(1, 0, 96, true)];
        let first = confirm(&mut tracker, initial.clone());
        assert_eq!(
            tracker.observe(Err(WindowsPlatformError::NativeApi)),
            DisplayTrackerUpdate::Unavailable
        );
        assert_eq!(
            tracker.observe(Ok(initial.clone())),
            DisplayTrackerUpdate::Pending
        );
        let DisplayTrackerUpdate::Available(recovered) = tracker.observe(Ok(initial)) else {
            panic!("recovery must require a second sample");
        };
        assert_eq!(recovered.displays()[0].id, first.displays()[0].id);
        assert_eq!(recovered.revision(), 2);
    }

    #[test]
    fn removed_display_ids_are_never_reused() {
        let mut tracker = DisplayTracker::default();
        let initial = vec![native(1, 0, 96, true), native(2, 1_920, 96, false)];
        let first = confirm(&mut tracker, initial);
        assert_eq!(first.displays()[1].id, DisplayId::new(2));
        let removed = vec![native(1, 0, 96, true)];
        let _ = confirm(&mut tracker, removed);
        let reappeared = vec![native(1, 0, 96, true), native(2, 1_920, 96, false)];
        let third = confirm(&mut tracker, reappeared);
        assert_eq!(third.displays()[1].id, DisplayId::new(3));
    }

    #[test]
    fn worker_restart_keeps_process_ledger_and_retires_old_keys() {
        let mut tracker = DisplayTracker::default();
        let first = confirm(&mut tracker, vec![native(1, 0, 96, true)]);
        assert_eq!(first.displays()[0].id, DisplayId::new(1));

        assert_eq!(
            tracker.observe(Err(WindowsPlatformError::DisplayUnavailable)),
            DisplayTrackerUpdate::Unavailable
        );
        let second = confirm(&mut tracker, vec![native(2, 0, 96, true)]);
        assert_eq!(second.displays()[0].id, DisplayId::new(2));

        assert_eq!(
            tracker.observe(Err(WindowsPlatformError::DisplayUnavailable)),
            DisplayTrackerUpdate::Unavailable
        );
        let returned = confirm(&mut tracker, vec![native(1, 0, 96, true)]);
        assert_eq!(returned.displays()[0].id, DisplayId::new(3));
        assert!(returned.revision() > second.revision());
    }

    #[test]
    fn missing_identity_then_replacement_never_reuses_display_id() {
        let mut tracker = DisplayTracker::default();
        let first = confirm(&mut tracker, vec![native(1, 0, 96, true)]);
        assert_eq!(first.displays()[0].id, DisplayId::new(1));

        assert_eq!(
            tracker.observe(Err(WindowsPlatformError::InvalidDisplay)),
            DisplayTrackerUpdate::Unavailable
        );
        let replacement = confirm(&mut tracker, vec![native(2, 0, 96, true)]);
        assert_eq!(replacement.displays()[0].id, DisplayId::new(2));
        assert_ne!(replacement.displays()[0].id, first.displays()[0].id);
    }

    #[test]
    fn invalid_or_duplicate_graphs_fail_closed() {
        let mut tracker = DisplayTracker::default();
        let duplicate = vec![native(1, 0, 96, true), native(1, 1_920, 96, false)];
        assert_eq!(
            tracker.observe(Ok(duplicate)),
            DisplayTrackerUpdate::Unavailable
        );
        let no_primary = vec![native(1, 0, 96, false)];
        assert_eq!(
            tracker.observe(Ok(no_primary)),
            DisplayTrackerUpdate::Unavailable
        );

        let mut oversized = native(1, 0, 96, true);
        oversized.width_pixels = MAX_DISPLAY_PIXEL_DIMENSION + 1;
        assert_eq!(
            tracker.observe(Ok(vec![oversized])),
            DisplayTrackerUpdate::Unavailable
        );

        let too_small_scale = vec![native(1, 0, 1, true)];
        assert_eq!(
            tracker.observe(Ok(too_small_scale)),
            DisplayTrackerUpdate::Unavailable
        );
    }
}
