//! Platform-neutral input semantics.
//!
//! This crate deliberately models input without native key codes, window handles,
//! or operating-system coordinate types. Platform adapters are responsible for
//! translating these values at the trust boundary.

use std::{collections::BTreeSet, fmt};

use bitflags::bitflags;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The HID Generic Desktop usage page.
pub const GENERIC_DESKTOP_PAGE: u16 = 0x01;
/// The HID Keyboard/Keypad usage page.
pub const KEYBOARD_PAGE: u16 = 0x07;
/// The HID Button usage page.
pub const BUTTON_PAGE: u16 = 0x09;
/// The HID Consumer usage page.
pub const CONSUMER_PAGE: u16 = 0x0c;

/// A physical control identified by its HID usage page and usage identifier.
///
/// This is intentionally not a native scan code or virtual-key value.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct HidUsage {
    page: u16,
    id: u16,
}

impl fmt::Debug for HidUsage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HidUsage([redacted])")
    }
}

impl HidUsage {
    /// Creates a usage from its HID page and identifier.
    #[must_use]
    pub const fn new(page: u16, id: u16) -> Self {
        Self { page, id }
    }

    /// Returns the HID usage page.
    #[must_use]
    pub const fn page(self) -> u16 {
        self.page
    }

    /// Returns the usage identifier within the page.
    #[must_use]
    pub const fn id(self) -> u16 {
        self.id
    }
}

bitflags! {
    /// Logical modifier state accompanying a keyboard event.
    ///
    /// `ALT_GRAPH` is distinct from `RIGHT_ALT` because layouts can assign
    /// different semantics even when a platform reports the same physical key.
    #[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
    pub struct Modifiers: u16 {
        const LEFT_CONTROL  = 1 << 0;
        const LEFT_SHIFT    = 1 << 1;
        const LEFT_ALT      = 1 << 2;
        const LEFT_META     = 1 << 3;
        const RIGHT_CONTROL = 1 << 4;
        const RIGHT_SHIFT   = 1 << 5;
        const RIGHT_ALT     = 1 << 6;
        const RIGHT_META    = 1 << 7;
        const ALT_GRAPH     = 1 << 8;
        const CAPS_LOCK     = 1 << 9;
        const NUM_LOCK      = 1 << 10;
    }
}

/// Whether a key is physically pressed or released.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum KeyState {
    Pressed,
    Released,
}

/// A one-based HID pointer button number.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct PointerButton(u8);

impl PointerButton {
    /// Highest button number accepted by the canonical model.
    pub const MAX: u8 = 32;

    /// Creates a pointer button when `number` is in `1..=32`.
    ///
    /// # Errors
    ///
    /// Returns [`InputValueError::InvalidPointerButton`] for zero or values
    /// greater than [`Self::MAX`].
    pub fn new(number: u8) -> Result<Self, InputValueError> {
        if (1..=Self::MAX).contains(&number) {
            Ok(Self(number))
        } else {
            Err(InputValueError::InvalidPointerButton(number))
        }
    }

    /// Returns the one-based HID button number.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

/// Whether a pointer button is physically pressed or released.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum ButtonState {
    Pressed,
    Released,
}

/// An opaque display identifier scoped to the current display graph.
///
/// Display identifiers are adapter-provided, ephemeral values. They must not be
/// persisted as device identity or included in telemetry.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct DisplayId(u64);

impl DisplayId {
    /// Creates a display identifier.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the adapter-provided value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A deterministic fixed-point coordinate on one display axis.
///
/// `0` is the leading edge and [`u16::MAX`] is the trailing edge. Fixed-point
/// storage avoids architecture-dependent floating-point behavior in reducers
/// and on the wire.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct NormalizedAxis(u16);

impl NormalizedAxis {
    pub const MIN: Self = Self(0);
    pub const MAX: Self = Self(u16::MAX);

    /// Creates a coordinate from its canonical fixed-point representation.
    #[must_use]
    pub const fn from_bits(value: u16) -> Self {
        Self(value)
    }

    /// Converts a finite unit coordinate into the canonical representation.
    ///
    /// Values outside the inclusive `0.0..=1.0` range are rejected rather than
    /// clamped so display-routing bugs cannot be silently hidden.
    ///
    /// # Errors
    ///
    /// Returns [`InputValueError::InvalidNormalizedCoordinate`] when `value` is
    /// non-finite or outside the inclusive unit interval.
    pub fn from_unit_f64(value: f64) -> Result<Self, InputValueError> {
        if !value.is_finite() || !(0.0..=1.0).contains(&value) {
            return Err(InputValueError::InvalidNormalizedCoordinate);
        }

        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let bits = (value * f64::from(u16::MAX)).round() as u16;
        Ok(Self(bits))
    }

    /// Returns the canonical fixed-point representation.
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Returns this coordinate in the inclusive unit interval.
    #[must_use]
    pub fn to_unit_f64(self) -> f64 {
        f64::from(self.0) / f64::from(u16::MAX)
    }
}

/// An absolute pointer position normalized within one display.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct NormalizedPosition {
    display: DisplayId,
    x: NormalizedAxis,
    y: NormalizedAxis,
}

impl NormalizedPosition {
    #[must_use]
    pub const fn new(display: DisplayId, x: NormalizedAxis, y: NormalizedAxis) -> Self {
        Self { display, x, y }
    }

    #[must_use]
    pub const fn display(self) -> DisplayId {
        self.display
    }

    #[must_use]
    pub const fn x(self) -> NormalizedAxis {
        self.x
    }

    #[must_use]
    pub const fn y(self) -> NormalizedAxis {
        self.y
    }
}

/// Units used for semantic scroll deltas.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum ScrollUnit {
    /// Discrete detents from a wheel or equivalent control.
    Lines,
    /// High-resolution device-independent units from a touch surface.
    Precise,
}

/// A platform-neutral input action.
#[derive(Clone, Copy, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum InputEvent {
    Key {
        usage: HidUsage,
        state: KeyState,
        modifiers: Modifiers,
    },
    PointerMotion {
        position: NormalizedPosition,
    },
    PointerButton {
        button: PointerButton,
        state: ButtonState,
    },
    Scroll {
        horizontal: i32,
        vertical: i32,
        unit: ScrollUnit,
    },
}

impl fmt::Debug for InputEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Input payloads must not accidentally enter structured or panic logs.
        let kind = match self {
            Self::Key { .. } => "Key",
            Self::PointerMotion { .. } => "PointerMotion",
            Self::PointerButton { .. } => "PointerButton",
            Self::Scroll { .. } => "Scroll",
        };
        formatter
            .debug_struct("InputEvent")
            .field("kind", &kind)
            .field("payload", &"[redacted]")
            .finish()
    }
}

/// Validation failures for canonical input values.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum InputValueError {
    #[error("pointer button {0} is outside the supported range 1..=32")]
    InvalidPointerButton(u8),
    #[error("normalized coordinate must be finite and in the inclusive range 0.0..=1.0")]
    InvalidNormalizedCoordinate,
}

/// Keys and pointer buttons currently considered pressed by a session.
///
/// A `BTreeSet` gives forced release a stable, platform-independent order.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct PressedState {
    keys: BTreeSet<HidUsage>,
    buttons: BTreeSet<PointerButton>,
}

impl fmt::Debug for PressedState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PressedState")
            .field("pressed_keys", &self.keys.len())
            .field("pressed_buttons", &self.buttons.len())
            .finish()
    }
}

impl PressedState {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty() && self.buttons.is_empty()
    }

    #[must_use]
    pub fn pressed_key_count(&self) -> usize {
        self.keys.len()
    }

    #[must_use]
    pub fn pressed_button_count(&self) -> usize {
        self.buttons.len()
    }

    /// Applies the press/release portion of an input event.
    pub fn apply(&mut self, event: &InputEvent) {
        match *event {
            InputEvent::Key { usage, state, .. } => match state {
                KeyState::Pressed => {
                    self.keys.insert(usage);
                }
                KeyState::Released => {
                    self.keys.remove(&usage);
                }
            },
            InputEvent::PointerButton { button, state } => match state {
                ButtonState::Pressed => {
                    self.buttons.insert(button);
                }
                ButtonState::Released => {
                    self.buttons.remove(&button);
                }
            },
            InputEvent::PointerMotion { .. } | InputEvent::Scroll { .. } => {}
        }
    }

    /// Clears all tracked presses and returns deterministic release actions.
    ///
    /// Keyboard usages are released in ascending `(page, id)` order, followed
    /// by pointer buttons in ascending HID button order. The empty modifier
    /// snapshot prevents a stale modifier state from being carried into local
    /// recovery; each physical modifier usage is still released explicitly if
    /// it was tracked as a key.
    #[must_use]
    pub fn take_forced_releases(&mut self) -> Vec<InputEvent> {
        let mut releases = Vec::with_capacity(self.keys.len() + self.buttons.len());
        releases.extend(self.keys.iter().copied().map(|usage| InputEvent::Key {
            usage,
            state: KeyState::Released,
            modifiers: Modifiers::empty(),
        }));
        releases.extend(
            self.buttons
                .iter()
                .copied()
                .map(|button| InputEvent::PointerButton {
                    button,
                    state: ButtonState::Released,
                }),
        );
        self.keys.clear();
        self.buttons.clear();
        releases
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalized_axis_rejects_non_finite_and_out_of_range_values() {
        for invalid in [f64::NAN, f64::INFINITY, -0.001, 1.001] {
            assert_eq!(
                NormalizedAxis::from_unit_f64(invalid),
                Err(InputValueError::InvalidNormalizedCoordinate)
            );
        }

        assert_eq!(NormalizedAxis::from_unit_f64(0.0), Ok(NormalizedAxis::MIN));
        assert_eq!(NormalizedAxis::from_unit_f64(1.0), Ok(NormalizedAxis::MAX));
    }

    #[test]
    fn forced_releases_are_stable_and_clear_state() {
        let mut state = PressedState::default();
        let key_b = HidUsage::new(KEYBOARD_PAGE, 5);
        let key_a = HidUsage::new(KEYBOARD_PAGE, 4);
        let button_two = PointerButton::new(2).unwrap();
        let button_one = PointerButton::new(1).unwrap();

        for event in [
            InputEvent::PointerButton {
                button: button_two,
                state: ButtonState::Pressed,
            },
            InputEvent::Key {
                usage: key_b,
                state: KeyState::Pressed,
                modifiers: Modifiers::LEFT_SHIFT,
            },
            InputEvent::PointerButton {
                button: button_one,
                state: ButtonState::Pressed,
            },
            InputEvent::Key {
                usage: key_a,
                state: KeyState::Pressed,
                modifiers: Modifiers::empty(),
            },
        ] {
            state.apply(&event);
        }

        assert_eq!(
            state.take_forced_releases(),
            vec![
                InputEvent::Key {
                    usage: key_a,
                    state: KeyState::Released,
                    modifiers: Modifiers::empty(),
                },
                InputEvent::Key {
                    usage: key_b,
                    state: KeyState::Released,
                    modifiers: Modifiers::empty(),
                },
                InputEvent::PointerButton {
                    button: button_one,
                    state: ButtonState::Released,
                },
                InputEvent::PointerButton {
                    button: button_two,
                    state: ButtonState::Released,
                },
            ]
        );
        assert!(state.is_empty());
        assert!(state.take_forced_releases().is_empty());
    }
}
