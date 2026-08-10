//! Host-testable translation for the Windows input runtime.

#![cfg_attr(not(target_os = "windows"), allow(dead_code))]

use std::collections::BTreeSet;
use std::sync::{Condvar, Mutex};
use std::time::Duration;

use nodavo_input::{
    ButtonState, CONSUMER_PAGE, HidUsage, InputEvent, KEYBOARD_PAGE, KeyState, Modifiers,
    NormalizedAxis, NormalizedPosition, PointerButton, PointerDelta, ScrollUnit,
};

use crate::{DisplayGeometry, WindowsPlatformError};

const WHEEL_DELTA: i32 = 120;
#[cfg(not(test))]
const ROUTING_DISABLE_TIMEOUT: Duration = Duration::from_secs(2);
#[cfg(test)]
const ROUTING_DISABLE_TIMEOUT: Duration = Duration::from_millis(50);

/// Synchronous confirmation that every tracked release was injected.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ForceReleaseAcknowledgement {
    pub released_keys: usize,
    pub released_buttons: usize,
}

/// Observable lifecycle conditions for the current Windows input session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsInputLifecycleEvent {
    CaptureStarted,
    CaptureStopped,
    SessionLocked,
    SessionUnlocked,
    SessionDisconnected,
    SessionConnected,
    SystemSuspending,
    SystemResumed,
    DefaultDesktopUnavailable,
    DefaultDesktopAvailable,
    InputDeviceChanged,
}

/// A semantic input event or lifecycle condition from the capture runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsInputCaptureEvent {
    Input(InputEvent),
    Lifecycle(WindowsInputLifecycleEvent),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct NativeModifierState {
    pub left_control: bool,
    pub left_shift: bool,
    pub left_alt: bool,
    pub left_meta: bool,
    pub right_control: bool,
    pub right_shift: bool,
    pub right_alt: bool,
    pub right_meta: bool,
    pub caps_lock: bool,
    pub num_lock: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeInputEvent {
    Keyboard {
        scan_code: u16,
        virtual_key: u16,
        extended: bool,
        e1: bool,
        pressed: bool,
    },
    PointerMotion {
        x: i32,
        y: i32,
        delta_x: i32,
        delta_y: i32,
    },
    PointerButton {
        button: u8,
        pressed: bool,
    },
    Scroll {
        horizontal: i32,
        vertical: i32,
    },
    Lifecycle(NativeLifecycleEvent),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeLifecycleEvent {
    SessionLocked,
    SessionUnlocked,
    SessionDisconnected,
    SessionConnected,
    SystemSuspending,
    SystemResumed,
    DefaultDesktopUnavailable,
    DefaultDesktopAvailable,
    InputDeviceChanged,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeRoutingObservation {
    pub(crate) hook_suppressed: bool,
    pub(crate) routed_at_hook: bool,
    pub(crate) reliable_suppressed: bool,
    pub(crate) epoch: u64,
}

/// Serializes routing decisions with disable acknowledgement.
///
/// A hook increments the active-admission count until it has recorded whether
/// its event was suppressed. Disabling first closes admission and then waits a
/// bounded interval for the old enabled admissions and every reliable
/// suppressed key/button/scroll observation to reach the bridge. A timeout
/// leaves admission disabled; re-enabling is refused until both counts drain.
pub(crate) struct RoutingAdmission {
    state: Mutex<RoutingAdmissionState>,
    drained: Condvar,
}

#[derive(Default)]
struct RoutingAdmissionState {
    enabled: bool,
    epoch: u64,
    active_enabled_admissions: usize,
    outstanding_reliable_suppressions: usize,
}

impl Default for RoutingAdmission {
    fn default() -> Self {
        Self {
            state: Mutex::new(RoutingAdmissionState::default()),
            drained: Condvar::new(),
        }
    }
}

impl RoutingAdmission {
    pub(crate) fn begin(&self) -> RoutingAdmissionGuard<'_> {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => {
                let mut state = poisoned.into_inner();
                state.enabled = false;
                return RoutingAdmissionGuard {
                    admission: self,
                    enabled: false,
                    epoch: state.epoch,
                };
            }
        };
        let mut enabled = state.enabled;
        if enabled {
            if let Some(next) = state.active_enabled_admissions.checked_add(1) {
                state.active_enabled_admissions = next;
            } else {
                let _ = close_routing_epoch(&mut state);
                enabled = false;
            }
        }
        RoutingAdmissionGuard {
            admission: self,
            enabled,
            epoch: state.epoch,
        }
    }

    pub(crate) fn enable(&self) -> Result<(), WindowsPlatformError> {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => {
                poisoned.into_inner().enabled = false;
                return Err(WindowsPlatformError::CaptureBarrierTimeout);
            }
        };
        if state.enabled {
            return Ok(());
        }
        if !routing_is_drained(&state) {
            state.enabled = false;
            return Err(WindowsPlatformError::CaptureBarrierTimeout);
        }
        state.epoch = state
            .epoch
            .checked_add(1)
            .ok_or(WindowsPlatformError::CaptureBarrierTimeout)?;
        state.enabled = true;
        Ok(())
    }

    pub(crate) fn disable(&self) -> Result<(), WindowsPlatformError> {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => {
                poisoned.into_inner().enabled = false;
                return Err(WindowsPlatformError::CaptureBarrierTimeout);
            }
        };
        close_routing_epoch(&mut state)?;
        let waited = self
            .drained
            .wait_timeout_while(state, ROUTING_DISABLE_TIMEOUT, |state| {
                !routing_is_drained(state)
            });
        let (mut state, timeout) = match waited {
            Ok(waited) => waited,
            Err(poisoned) => {
                let (mut state, _) = poisoned.into_inner();
                state.enabled = false;
                return Err(WindowsPlatformError::CaptureBarrierTimeout);
            }
        };
        state.enabled = false;
        if timeout.timed_out() && !routing_is_drained(&state) {
            Err(WindowsPlatformError::CaptureBarrierTimeout)
        } else {
            Ok(())
        }
    }

    pub(crate) fn close_admission(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _ = close_routing_epoch(&mut state);
    }

    pub(crate) fn complete_reliable_suppressions(&self, count: usize) -> bool {
        if count == 0 {
            return true;
        }
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(remaining) = state.outstanding_reliable_suppressions.checked_sub(count) else {
            let _ = close_routing_epoch(&mut state);
            return false;
        };
        state.outstanding_reliable_suppressions = remaining;
        if routing_is_drained(&state) {
            self.drained.notify_all();
        }
        true
    }

    pub(crate) fn disable_fail_closed(&self) {
        let _ = self.disable();
    }

    pub(crate) fn is_enabled(&self) -> bool {
        self.state.lock().is_ok_and(|state| state.enabled)
    }

    pub(crate) fn epoch_is_current(&self, epoch: u64) -> bool {
        self.state.lock().is_ok_and(|state| state.epoch == epoch)
    }

    pub(crate) fn has_outstanding_reliable_suppressions(&self) -> bool {
        let Ok(state) = self.state.lock() else {
            return true;
        };
        state.outstanding_reliable_suppressions != 0
    }
}

pub(crate) struct RoutingAdmissionGuard<'a> {
    admission: &'a RoutingAdmission,
    enabled: bool,
    epoch: u64,
}

impl RoutingAdmissionGuard<'_> {
    pub(crate) const fn enabled(&self) -> bool {
        self.enabled
    }

    pub(crate) const fn epoch(&self) -> u64 {
        self.epoch
    }

    pub(crate) fn commit_reliable_suppression(&self) -> Result<(), WindowsPlatformError> {
        if !self.enabled {
            return Err(WindowsPlatformError::CaptureBarrierTimeout);
        }
        let mut state = self
            .admission
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(next) = state.outstanding_reliable_suppressions.checked_add(1) else {
            let _ = close_routing_epoch(&mut state);
            return Err(WindowsPlatformError::CaptureBarrierTimeout);
        };
        state.outstanding_reliable_suppressions = next;
        Ok(())
    }
}

impl Drop for RoutingAdmissionGuard<'_> {
    fn drop(&mut self) {
        if !self.enabled {
            return;
        }
        let mut state = self
            .admission
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.active_enabled_admissions = state.active_enabled_admissions.saturating_sub(1);
        if routing_is_drained(&state) {
            self.admission.drained.notify_all();
        }
    }
}

const fn routing_is_drained(state: &RoutingAdmissionState) -> bool {
    state.active_enabled_admissions == 0 && state.outstanding_reliable_suppressions == 0
}

fn close_routing_epoch(state: &mut RoutingAdmissionState) -> Result<(), WindowsPlatformError> {
    if !state.enabled {
        return Ok(());
    }
    state.enabled = false;
    state.epoch = state
        .epoch
        .checked_add(1)
        .ok_or(WindowsPlatformError::CaptureBarrierTimeout)?;
    Ok(())
}

pub(crate) struct CaptureTranslator {
    modifiers: Modifiers,
    pressed_keys: BTreeSet<HidUsage>,
}

impl CaptureTranslator {
    pub(crate) fn new(initial: NativeModifierState) -> Self {
        let mut modifiers = Modifiers::empty();
        set_modifier(
            &mut modifiers,
            Modifiers::LEFT_CONTROL,
            initial.left_control,
        );
        set_modifier(&mut modifiers, Modifiers::LEFT_SHIFT, initial.left_shift);
        set_modifier(&mut modifiers, Modifiers::LEFT_ALT, initial.left_alt);
        set_modifier(&mut modifiers, Modifiers::LEFT_META, initial.left_meta);
        set_modifier(
            &mut modifiers,
            Modifiers::RIGHT_CONTROL,
            initial.right_control,
        );
        set_modifier(&mut modifiers, Modifiers::RIGHT_SHIFT, initial.right_shift);
        set_modifier(&mut modifiers, Modifiers::RIGHT_ALT, initial.right_alt);
        set_modifier(&mut modifiers, Modifiers::RIGHT_META, initial.right_meta);
        set_modifier(&mut modifiers, Modifiers::ALT_GRAPH, initial.right_alt);
        set_modifier(&mut modifiers, Modifiers::CAPS_LOCK, initial.caps_lock);
        set_modifier(&mut modifiers, Modifiers::NUM_LOCK, initial.num_lock);
        Self {
            modifiers,
            pressed_keys: BTreeSet::new(),
        }
    }

    pub(crate) fn convert(
        &mut self,
        native: NativeInputEvent,
        displays: &[DisplayGeometry],
        relative_pointer: bool,
    ) -> Option<WindowsInputCaptureEvent> {
        let event = match native {
            NativeInputEvent::Keyboard {
                scan_code,
                virtual_key,
                extended,
                e1,
                pressed,
            } => {
                let usage = consumer_usage(virtual_key).unwrap_or_else(|| {
                    HidUsage::new(
                        KEYBOARD_PAGE,
                        scan_code_to_hid(scan_code, extended, e1, virtual_key).unwrap_or(0),
                    )
                });
                if usage.id() == 0 {
                    return None;
                }
                self.update_modifiers(usage, pressed);
                InputEvent::Key {
                    usage,
                    state: key_state(pressed),
                    modifiers: self.modifiers,
                }
            }
            NativeInputEvent::PointerMotion {
                delta_x, delta_y, ..
            } if relative_pointer => InputEvent::PointerDelta {
                delta: PointerDelta::new(delta_x, delta_y).ok()?,
            },
            NativeInputEvent::PointerMotion { x, y, .. } => InputEvent::PointerMotion {
                position: normalize_position(x, y, displays)?,
            },
            NativeInputEvent::PointerButton { button, pressed } => InputEvent::PointerButton {
                button: PointerButton::new(button).ok()?,
                state: if pressed {
                    ButtonState::Pressed
                } else {
                    ButtonState::Released
                },
            },
            NativeInputEvent::Scroll {
                horizontal,
                vertical,
            } => {
                let line_aligned = horizontal % WHEEL_DELTA == 0 && vertical % WHEEL_DELTA == 0;
                InputEvent::Scroll {
                    horizontal: if line_aligned {
                        horizontal / WHEEL_DELTA
                    } else {
                        horizontal
                    },
                    vertical: if line_aligned {
                        vertical / WHEEL_DELTA
                    } else {
                        vertical
                    },
                    unit: if line_aligned {
                        ScrollUnit::Lines
                    } else {
                        ScrollUnit::Precise
                    },
                }
            }
            NativeInputEvent::Lifecycle(event) => {
                return Some(WindowsInputCaptureEvent::Lifecycle(lifecycle_event(event)));
            }
        };
        Some(WindowsInputCaptureEvent::Input(event))
    }

    fn update_modifiers(&mut self, usage: HidUsage, pressed: bool) {
        let repeated = pressed && self.pressed_keys.contains(&usage);
        if pressed {
            self.pressed_keys.insert(usage);
        } else {
            self.pressed_keys.remove(&usage);
        }
        match usage.id() {
            0xe0 => set_modifier(&mut self.modifiers, Modifiers::LEFT_CONTROL, pressed),
            0xe1 => set_modifier(&mut self.modifiers, Modifiers::LEFT_SHIFT, pressed),
            0xe2 => set_modifier(&mut self.modifiers, Modifiers::LEFT_ALT, pressed),
            0xe3 => set_modifier(&mut self.modifiers, Modifiers::LEFT_META, pressed),
            0xe4 => set_modifier(&mut self.modifiers, Modifiers::RIGHT_CONTROL, pressed),
            0xe5 => set_modifier(&mut self.modifiers, Modifiers::RIGHT_SHIFT, pressed),
            0xe6 => {
                set_modifier(&mut self.modifiers, Modifiers::RIGHT_ALT, pressed);
                set_modifier(&mut self.modifiers, Modifiers::ALT_GRAPH, pressed);
            }
            0xe7 => set_modifier(&mut self.modifiers, Modifiers::RIGHT_META, pressed),
            0x39 if pressed && !repeated => self.modifiers.toggle(Modifiers::CAPS_LOCK),
            0x53 if pressed && !repeated => self.modifiers.toggle(Modifiers::NUM_LOCK),
            _ => {}
        }
    }
}

pub(crate) const fn lifecycle_requires_local_recovery(event: WindowsInputLifecycleEvent) -> bool {
    matches!(
        event,
        WindowsInputLifecycleEvent::SessionLocked
            | WindowsInputLifecycleEvent::SessionDisconnected
            | WindowsInputLifecycleEvent::SystemSuspending
            | WindowsInputLifecycleEvent::DefaultDesktopUnavailable
    )
}

const fn lifecycle_event(event: NativeLifecycleEvent) -> WindowsInputLifecycleEvent {
    match event {
        NativeLifecycleEvent::SessionLocked => WindowsInputLifecycleEvent::SessionLocked,
        NativeLifecycleEvent::SessionUnlocked => WindowsInputLifecycleEvent::SessionUnlocked,
        NativeLifecycleEvent::SessionDisconnected => {
            WindowsInputLifecycleEvent::SessionDisconnected
        }
        NativeLifecycleEvent::SessionConnected => WindowsInputLifecycleEvent::SessionConnected,
        NativeLifecycleEvent::SystemSuspending => WindowsInputLifecycleEvent::SystemSuspending,
        NativeLifecycleEvent::SystemResumed => WindowsInputLifecycleEvent::SystemResumed,
        NativeLifecycleEvent::DefaultDesktopUnavailable => {
            WindowsInputLifecycleEvent::DefaultDesktopUnavailable
        }
        NativeLifecycleEvent::DefaultDesktopAvailable => {
            WindowsInputLifecycleEvent::DefaultDesktopAvailable
        }
        NativeLifecycleEvent::InputDeviceChanged => WindowsInputLifecycleEvent::InputDeviceChanged,
    }
}

fn normalize_position(x: i32, y: i32, displays: &[DisplayGeometry]) -> Option<NormalizedPosition> {
    let display = displays.iter().find(|display| {
        let right = i64::from(display.left) + i64::from(display.width_pixels);
        let bottom = i64::from(display.top) + i64::from(display.height_pixels);
        i64::from(x) >= i64::from(display.left)
            && i64::from(x) < right
            && i64::from(y) >= i64::from(display.top)
            && i64::from(y) < bottom
    })?;
    Some(NormalizedPosition::new(
        display.id,
        normalize_axis(x, display.left, display.width_pixels)?,
        normalize_axis(y, display.top, display.height_pixels)?,
    ))
}

fn normalize_axis(value: i32, origin: i32, extent: u32) -> Option<NormalizedAxis> {
    let maximum = extent.checked_sub(1)?;
    let offset = u64::try_from(i64::from(value) - i64::from(origin)).ok()?;
    if offset > u64::from(maximum) {
        return None;
    }
    if maximum == 0 {
        return Some(NormalizedAxis::MIN);
    }
    let bits = (offset * u64::from(u16::MAX) + u64::from(maximum) / 2) / u64::from(maximum);
    Some(NormalizedAxis::from_bits(u16::try_from(bits).ok()?))
}

const fn key_state(pressed: bool) -> KeyState {
    if pressed {
        KeyState::Pressed
    } else {
        KeyState::Released
    }
}

fn set_modifier(modifiers: &mut Modifiers, flag: Modifiers, enabled: bool) {
    if enabled {
        modifiers.insert(flag);
    } else {
        modifiers.remove(flag);
    }
}

fn consumer_usage(virtual_key: u16) -> Option<HidUsage> {
    let id = match virtual_key {
        0xb0 => 0x00b5,
        0xb1 => 0x00b6,
        0xb2 => 0x00b7,
        0xb3 => 0x00cd,
        0xad => 0x00e2,
        0xaf => 0x00e9,
        0xae => 0x00ea,
        _ => return None,
    };
    Some(HidUsage::new(CONSUMER_PAGE, id))
}

pub(crate) fn native_keyboard_is_supported(
    scan_code: u16,
    virtual_key: u16,
    extended: bool,
    e1: bool,
) -> bool {
    consumer_usage(virtual_key).is_some()
        || scan_code_to_hid(scan_code, extended, e1, virtual_key).is_some()
}

#[allow(clippy::too_many_lines)]
const fn scan_code_to_hid(
    scan_code: u16,
    extended: bool,
    e1: bool,
    virtual_key: u16,
) -> Option<u16> {
    if e1 || virtual_key == 0x13 {
        return Some(0x48);
    }
    if extended && scan_code == 0x37 {
        return Some(0x46);
    }
    let usage = match (scan_code, extended) {
        (0x1e, false) => 0x04,
        (0x30, false) => 0x05,
        (0x2e, false) => 0x06,
        (0x20, false) => 0x07,
        (0x12, false) => 0x08,
        (0x21, false) => 0x09,
        (0x22, false) => 0x0a,
        (0x23, false) => 0x0b,
        (0x17, false) => 0x0c,
        (0x24, false) => 0x0d,
        (0x25, false) => 0x0e,
        (0x26, false) => 0x0f,
        (0x32, false) => 0x10,
        (0x31, false) => 0x11,
        (0x18, false) => 0x12,
        (0x19, false) => 0x13,
        (0x10, false) => 0x14,
        (0x13, false) => 0x15,
        (0x1f, false) => 0x16,
        (0x14, false) => 0x17,
        (0x16, false) => 0x18,
        (0x2f, false) => 0x19,
        (0x11, false) => 0x1a,
        (0x2d, false) => 0x1b,
        (0x15, false) => 0x1c,
        (0x2c, false) => 0x1d,
        (0x02, false) => 0x1e,
        (0x03, false) => 0x1f,
        (0x04, false) => 0x20,
        (0x05, false) => 0x21,
        (0x06, false) => 0x22,
        (0x07, false) => 0x23,
        (0x08, false) => 0x24,
        (0x09, false) => 0x25,
        (0x0a, false) => 0x26,
        (0x0b, false) => 0x27,
        (0x1c, false) => 0x28,
        (0x01, false) => 0x29,
        (0x0e, false) => 0x2a,
        (0x0f, false) => 0x2b,
        (0x39, false) => 0x2c,
        (0x0c, false) => 0x2d,
        (0x0d, false) => 0x2e,
        (0x1a, false) => 0x2f,
        (0x1b, false) => 0x30,
        (0x2b, false) => 0x31,
        (0x27, false) => 0x33,
        (0x28, false) => 0x34,
        (0x29, false) => 0x35,
        (0x33, false) => 0x36,
        (0x34, false) => 0x37,
        (0x35, false) => 0x38,
        (0x3a, false) => 0x39,
        (0x3b..=0x44, false) => 0x3a + scan_code - 0x3b,
        (0x57, false) => 0x44,
        (0x58, false) => 0x45,
        (0x46, false) => 0x47,
        (0x52, true) => 0x49,
        (0x47, true) => 0x4a,
        (0x49, true) => 0x4b,
        (0x53, true) => 0x4c,
        (0x4f, true) => 0x4d,
        (0x51, true) => 0x4e,
        (0x4d, true) => 0x4f,
        (0x4b, true) => 0x50,
        (0x50, true) => 0x51,
        (0x48, true) => 0x52,
        (0x45, true) => 0x53,
        (0x35, true) => 0x54,
        (0x37, false) => 0x55,
        (0x4a, false) => 0x56,
        (0x4e, false) => 0x57,
        (0x1c, true) => 0x58,
        (0x4f, false) => 0x59,
        (0x50, false) => 0x5a,
        (0x51, false) => 0x5b,
        (0x4b, false) => 0x5c,
        (0x4c, false) => 0x5d,
        (0x4d, false) => 0x5e,
        (0x47, false) => 0x5f,
        (0x48, false) => 0x60,
        (0x49, false) => 0x61,
        (0x52, false) => 0x62,
        (0x53, false) => 0x63,
        (0x1d, false) => 0xe0,
        (0x2a, false) => 0xe1,
        (0x38, false) => 0xe2,
        (0x5b, true) => 0xe3,
        (0x1d, true) => 0xe4,
        (0x36, false) => 0xe5,
        (0x38, true) => 0xe6,
        (0x5c, true) => 0xe7,
        _ => return None,
    };
    Some(usage)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier, mpsc};
    use std::thread;
    use std::time::{Duration, Instant};

    use nodavo_input::DisplayId;

    use super::*;

    fn display() -> DisplayGeometry {
        DisplayGeometry {
            id: DisplayId::new(4),
            left: -1_920,
            top: 0,
            width_pixels: 1_920,
            height_pixels: 1_080,
            dpi_x: 96,
            dpi_y: 96,
            rotation: nodavo_protocol::DisplayRotation::Degrees0,
            primary: true,
        }
    }

    #[test]
    fn routing_disable_waits_for_old_admission_to_finish() {
        let routing = Arc::new(RoutingAdmission::default());
        routing.enable().unwrap();
        let admission = routing.begin();
        assert!(admission.enabled());

        let started = Arc::new(Barrier::new(2));
        let worker_routing = Arc::clone(&routing);
        let worker_started = Arc::clone(&started);
        let (done, completed) = mpsc::sync_channel(1);
        let worker = thread::spawn(move || {
            worker_started.wait();
            worker_routing.disable().unwrap();
            done.send(()).unwrap();
        });
        started.wait();
        let deadline = Instant::now() + Duration::from_secs(1);
        while routing.is_enabled() && Instant::now() < deadline {
            thread::yield_now();
        }
        assert!(!routing.is_enabled());
        assert!(matches!(
            completed.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));

        drop(admission);
        completed.recv_timeout(Duration::from_secs(1)).unwrap();
        worker.join().unwrap();
        assert!(!routing.is_enabled());
    }

    #[test]
    fn routing_disable_timeout_stays_closed_until_old_admission_drains() {
        let routing = RoutingAdmission::default();
        routing.enable().unwrap();
        let admission = routing.begin();
        assert!(admission.enabled());

        assert_eq!(
            routing.disable(),
            Err(WindowsPlatformError::CaptureBarrierTimeout)
        );
        assert!(!routing.is_enabled());
        assert_eq!(
            routing.enable(),
            Err(WindowsPlatformError::CaptureBarrierTimeout)
        );

        drop(admission);
        routing.enable().unwrap();
        assert!(routing.is_enabled());
    }

    #[test]
    fn disable_waits_until_suppressed_reliable_input_reaches_fake_bridge() {
        let routing = Arc::new(RoutingAdmission::default());
        routing.enable().unwrap();
        let hook = routing.begin();
        assert!(hook.enabled());
        hook.commit_reliable_suppression().unwrap();
        drop(hook);

        let worker_routing = Arc::clone(&routing);
        let (barrier_done, barrier_result) = mpsc::sync_channel(1);
        let worker = thread::spawn(move || {
            barrier_done.send(worker_routing.disable()).unwrap();
        });
        let deadline = Instant::now() + Duration::from_secs(1);
        while routing.is_enabled() && Instant::now() < deadline {
            thread::yield_now();
        }
        assert!(!routing.is_enabled());
        assert!(matches!(
            barrier_result.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));

        let (bridge, drained) = mpsc::sync_channel(1);
        bridge.send("released").unwrap();
        assert!(routing.complete_reliable_suppressions(1));
        assert_eq!(
            barrier_result.recv_timeout(Duration::from_secs(1)),
            Ok(Ok(()))
        );
        assert_eq!(drained.recv().unwrap(), "released");
        worker.join().unwrap();
    }

    #[test]
    fn missing_reliable_raw_input_times_out_and_blocks_reenable() {
        let routing = RoutingAdmission::default();
        routing.enable().unwrap();
        let hook = routing.begin();
        hook.commit_reliable_suppression().unwrap();
        drop(hook);

        assert_eq!(
            routing.disable(),
            Err(WindowsPlatformError::CaptureBarrierTimeout)
        );
        assert!(!routing.is_enabled());
        assert_eq!(
            routing.enable(),
            Err(WindowsPlatformError::CaptureBarrierTimeout)
        );

        assert!(routing.complete_reliable_suppressions(1));
        routing.enable().unwrap();
        assert!(routing.is_enabled());
    }

    #[test]
    fn routing_epochs_fence_both_enable_and_disable_boundaries() {
        let routing = RoutingAdmission::default();
        let disabled = routing.begin();
        let disabled_epoch = disabled.epoch();
        assert!(!disabled.enabled());
        drop(disabled);

        routing.enable().unwrap();
        assert!(!routing.epoch_is_current(disabled_epoch));
        let enabled = routing.begin();
        let enabled_epoch = enabled.epoch();
        assert!(enabled.enabled());
        drop(enabled);

        routing.disable().unwrap();
        assert!(!routing.epoch_is_current(enabled_epoch));
    }

    #[test]
    fn keyboard_translation_tracks_modifiers_and_media() {
        let mut translator = CaptureTranslator::new(NativeModifierState::default());
        let shift = translator
            .convert(
                NativeInputEvent::Keyboard {
                    scan_code: 0x2a,
                    virtual_key: 0xa0,
                    extended: false,
                    e1: false,
                    pressed: true,
                },
                &[],
                false,
            )
            .unwrap();
        assert!(matches!(
            shift,
            WindowsInputCaptureEvent::Input(InputEvent::Key {
                usage,
                modifiers,
                ..
            }) if usage == HidUsage::new(KEYBOARD_PAGE, 0xe1)
                && modifiers == Modifiers::LEFT_SHIFT
        ));

        let media = translator
            .convert(
                NativeInputEvent::Keyboard {
                    scan_code: 0,
                    virtual_key: 0xb3,
                    extended: true,
                    e1: false,
                    pressed: true,
                },
                &[],
                false,
            )
            .unwrap();
        assert!(matches!(
            media,
            WindowsInputCaptureEvent::Input(InputEvent::Key {
                usage,
                modifiers,
                ..
            }) if usage == HidUsage::new(CONSUMER_PAGE, 0x00cd)
                && modifiers == Modifiers::LEFT_SHIFT
        ));
    }

    #[test]
    fn pointer_and_scroll_translation_is_bounded_and_unit_aware() {
        let mut translator = CaptureTranslator::new(NativeModifierState::default());
        let motion = translator
            .convert(
                NativeInputEvent::PointerMotion {
                    x: -1,
                    y: 1_079,
                    delta_x: 5,
                    delta_y: -3,
                },
                &[display()],
                false,
            )
            .unwrap();
        assert!(matches!(
            motion,
            WindowsInputCaptureEvent::Input(InputEvent::PointerMotion { position })
                if position.x() == NormalizedAxis::MAX && position.y() == NormalizedAxis::MAX
        ));
        assert!(
            translator
                .convert(
                    NativeInputEvent::PointerMotion {
                        x: 0,
                        y: 1_080,
                        delta_x: 5,
                        delta_y: -3,
                    },
                    &[display()],
                    false,
                )
                .is_none()
        );

        for (delta, unit, semantic) in [(120, ScrollUnit::Lines, 1), (30, ScrollUnit::Precise, 30)]
        {
            let event = translator
                .convert(
                    NativeInputEvent::Scroll {
                        horizontal: 0,
                        vertical: delta,
                    },
                    &[],
                    false,
                )
                .unwrap();
            assert!(matches!(
                event,
                WindowsInputCaptureEvent::Input(InputEvent::Scroll {
                    vertical,
                    unit: actual,
                    ..
                }) if vertical == semantic && actual == unit
            ));
        }
    }

    #[test]
    fn routed_pointer_uses_relative_raw_input_without_display_identity() {
        let mut translator = CaptureTranslator::new(NativeModifierState::default());
        assert_eq!(
            translator.convert(
                NativeInputEvent::PointerMotion {
                    x: -1_000,
                    y: 500,
                    delta_x: 17,
                    delta_y: -9,
                },
                &[display()],
                true,
            ),
            Some(WindowsInputCaptureEvent::Input(InputEvent::PointerDelta {
                delta: PointerDelta::new(17, -9).unwrap(),
            }))
        );
    }

    #[test]
    fn lifecycle_recovery_is_fail_closed() {
        for event in [
            WindowsInputLifecycleEvent::SessionLocked,
            WindowsInputLifecycleEvent::SessionDisconnected,
            WindowsInputLifecycleEvent::SystemSuspending,
            WindowsInputLifecycleEvent::DefaultDesktopUnavailable,
        ] {
            assert!(lifecycle_requires_local_recovery(event));
        }
        assert!(!lifecycle_requires_local_recovery(
            WindowsInputLifecycleEvent::SessionUnlocked
        ));
    }
}
