//! Auditable conversion between protocol input payloads and platform-neutral input.

use nodavo_input::{
    ButtonState, DisplayId, HidUsage, InputEvent, KeyState, Modifiers, NormalizedAxis,
    NormalizedPosition, PointerButton, PointerDelta, ScrollUnit,
};
use nodavo_protocol::{
    ButtonState as WireButtonState, EventMeta, InputMessage, KeyEvent, KeyState as WireKeyState,
    PointerButtonEvent, PointerDeltaEvent, PointerEnterEvent, PointerMotionEvent, ReleaseAllEvent,
    ScrollEvent, ScrollUnit as WireScrollUnit,
};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DecodedInput {
    Event(InputEvent),
    PointerEnter(NormalizedPosition),
    ReleaseAll,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum InputWireError {
    #[error("input payload contains an unsupported value")]
    UnsupportedValue,
}

pub(crate) fn encode_event(
    event: InputEvent,
    meta: EventMeta,
    lease_id: u64,
) -> Result<InputMessage, InputWireError> {
    let message = match event {
        InputEvent::Key {
            usage,
            state,
            modifiers,
        } => InputMessage::Key(KeyEvent {
            meta,
            usage_page: usage.page(),
            usage_id: usage.id(),
            state: match state {
                KeyState::Pressed => WireKeyState::Down,
                KeyState::Released => WireKeyState::Up,
            },
            modifiers: modifiers.bits(),
            lease_id,
        }),
        InputEvent::PointerButton { button, state } => {
            InputMessage::PointerButton(PointerButtonEvent {
                meta,
                button: button.get(),
                state: match state {
                    ButtonState::Pressed => WireButtonState::Down,
                    ButtonState::Released => WireButtonState::Up,
                },
                lease_id,
            })
        }
        InputEvent::PointerMotion { position } => {
            let display_id = u32::try_from(position.display().get())
                .map_err(|_| InputWireError::UnsupportedValue)?;
            InputMessage::PointerMotion(PointerMotionEvent {
                meta,
                display_id,
                x: expand_axis(position.x()),
                y: expand_axis(position.y()),
                lease_id,
            })
        }
        InputEvent::PointerDelta { delta } => InputMessage::PointerDelta(PointerDeltaEvent {
            meta,
            delta_x: delta.horizontal(),
            delta_y: delta.vertical(),
            lease_id,
        }),
        InputEvent::Scroll {
            horizontal,
            vertical,
            unit,
        } => InputMessage::Scroll(ScrollEvent {
            meta,
            delta_x: horizontal,
            delta_y: vertical,
            unit: match unit {
                ScrollUnit::Lines => WireScrollUnit::Lines,
                ScrollUnit::Precise => WireScrollUnit::Precise,
            },
            lease_id,
        }),
    };
    Ok(message)
}

pub(crate) const fn encode_release_all(meta: EventMeta, lease_id: u64) -> InputMessage {
    InputMessage::ReleaseAll(ReleaseAllEvent { meta, lease_id })
}

pub(crate) fn encode_pointer_enter(
    position: NormalizedPosition,
    meta: EventMeta,
    lease_id: u64,
) -> Result<InputMessage, InputWireError> {
    let display_id =
        u32::try_from(position.display().get()).map_err(|_| InputWireError::UnsupportedValue)?;
    Ok(InputMessage::PointerEnter(PointerEnterEvent {
        meta,
        display_id,
        x: expand_axis(position.x()),
        y: expand_axis(position.y()),
        lease_id,
    }))
}

pub(crate) fn decode_event(message: &InputMessage) -> Result<DecodedInput, InputWireError> {
    let decoded = match message {
        InputMessage::Key(event) => DecodedInput::Event(InputEvent::Key {
            usage: HidUsage::new(event.usage_page, event.usage_id),
            state: match event.state {
                WireKeyState::Down => KeyState::Pressed,
                WireKeyState::Up => KeyState::Released,
            },
            modifiers: Modifiers::from_bits(event.modifiers)
                .ok_or(InputWireError::UnsupportedValue)?,
        }),
        InputMessage::PointerButton(event) => DecodedInput::Event(InputEvent::PointerButton {
            button: PointerButton::new(event.button)
                .map_err(|_| InputWireError::UnsupportedValue)?,
            state: match event.state {
                WireButtonState::Down => ButtonState::Pressed,
                WireButtonState::Up => ButtonState::Released,
            },
        }),
        InputMessage::PointerMotion(event) => DecodedInput::Event(InputEvent::PointerMotion {
            position: NormalizedPosition::new(
                DisplayId::new(u64::from(event.display_id)),
                collapse_axis(event.x),
                collapse_axis(event.y),
            ),
        }),
        InputMessage::PointerDelta(event) => DecodedInput::Event(InputEvent::PointerDelta {
            delta: PointerDelta::new(event.delta_x, event.delta_y)
                .map_err(|_| InputWireError::UnsupportedValue)?,
        }),
        InputMessage::PointerEnter(event) => DecodedInput::PointerEnter(NormalizedPosition::new(
            DisplayId::new(u64::from(event.display_id)),
            collapse_axis(event.x),
            collapse_axis(event.y),
        )),
        InputMessage::Scroll(event) => DecodedInput::Event(InputEvent::Scroll {
            horizontal: event.delta_x,
            vertical: event.delta_y,
            unit: match event.unit {
                WireScrollUnit::Lines => ScrollUnit::Lines,
                WireScrollUnit::Precise => ScrollUnit::Precise,
            },
        }),
        InputMessage::ReleaseAll(_) => DecodedInput::ReleaseAll,
    };
    Ok(decoded)
}

fn expand_axis(axis: NormalizedAxis) -> u32 {
    u32::from(axis.bits()) * 65_537
}

const fn collapse_axis(axis: u32) -> NormalizedAxis {
    NormalizedAxis::from_bits((axis / 65_537) as u16)
}

#[cfg(test)]
mod tests {
    use nodavo_input::{KEYBOARD_PAGE, Modifiers};
    use nodavo_protocol::{Capability, DeviceId, GrantEpoch, Sequence, SessionId};

    use super::*;

    fn meta() -> EventMeta {
        EventMeta::new(
            SessionId::new([1; 16]),
            DeviceId::new([2; 32]),
            Sequence::new(1),
            GrantEpoch::new(1),
            Capability::REMOTE_INPUT,
        )
    }

    #[test]
    fn semantic_input_round_trips_without_native_codes() {
        let events = [
            InputEvent::Key {
                usage: HidUsage::new(KEYBOARD_PAGE, 4),
                state: KeyState::Pressed,
                modifiers: Modifiers::LEFT_SHIFT,
            },
            InputEvent::PointerMotion {
                position: NormalizedPosition::new(
                    DisplayId::new(7),
                    NormalizedAxis::from_bits(123),
                    NormalizedAxis::MAX,
                ),
            },
            InputEvent::PointerDelta {
                delta: PointerDelta::new(-17, 23).unwrap(),
            },
            InputEvent::Scroll {
                horizontal: -2,
                vertical: 3,
                unit: ScrollUnit::Precise,
            },
        ];
        for event in events {
            let encoded = encode_event(event, meta(), 9).unwrap();
            assert_eq!(decode_event(&encoded), Ok(DecodedInput::Event(event)));
        }
    }
}
