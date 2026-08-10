//! Host-testable translation for the Windows input runtime.

#![cfg_attr(not(target_os = "windows"), allow(dead_code))]

use std::collections::BTreeSet;

use nodavo_input::{
    ButtonState, CONSUMER_PAGE, HidUsage, InputEvent, KEYBOARD_PAGE, KeyState, Modifiers,
    NormalizedAxis, NormalizedPosition, PointerButton, PointerDelta, ScrollUnit,
};

use crate::DisplayGeometry;

const WHEEL_DELTA: i32 = 120;

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
            primary: true,
        }
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
