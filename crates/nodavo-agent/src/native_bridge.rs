//! Bounded handoff from native callback threads to the async session owner.

#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use nodavo_input::InputEvent;
use tokio::sync::watch;

const INPUT_CAPACITY: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PlatformSafetyEvent {
    LocalLocked,
    LocalSleeping,
    CaptureFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeInputBridgeError {
    ReliableCapacityExhausted,
    Poisoned,
}

#[derive(Default)]
struct InputBuffer {
    events: VecDeque<InputEvent>,
}

#[derive(Clone)]
pub(crate) struct NativeInputSender {
    buffer: Arc<Mutex<InputBuffer>>,
    revision: watch::Sender<u64>,
}

pub(crate) struct NativeInputReceiver {
    buffer: Arc<Mutex<InputBuffer>>,
    revision: watch::Receiver<u64>,
}

pub(crate) fn native_input_channel() -> (NativeInputSender, NativeInputReceiver) {
    let buffer = Arc::new(Mutex::new(InputBuffer::default()));
    let (revision, observed_revision) = watch::channel(0_u64);
    (
        NativeInputSender {
            buffer: Arc::clone(&buffer),
            revision,
        },
        NativeInputReceiver {
            buffer,
            revision: observed_revision,
        },
    )
}

impl NativeInputSender {
    /// Enqueues a physical event without ever evicting a key or button event.
    ///
    /// Motion and scroll are replaceable. Their newest value displaces an
    /// older value of the same kind, and either kind may be evicted to admit a
    /// reliable event when the fixed-size queue is full. Exhausting the queue
    /// with reliable events is an explicit failure so the adapter can restore
    /// local ownership instead of silently losing a release.
    pub(crate) fn send(&self, event: InputEvent) -> Result<(), NativeInputBridgeError> {
        let mut buffer = self
            .buffer
            .lock()
            .map_err(|_| NativeInputBridgeError::Poisoned)?;

        if is_replaceable(event) {
            if let Some(index) = buffer
                .events
                .iter()
                .rposition(|queued| same_replaceable_kind(*queued, event))
            {
                let _ = buffer.events.remove(index);
            } else if buffer.events.len() == INPUT_CAPACITY {
                let Some(index) = buffer
                    .events
                    .iter()
                    .position(|queued| is_replaceable(*queued))
                else {
                    return Err(NativeInputBridgeError::ReliableCapacityExhausted);
                };
                let _ = buffer.events.remove(index);
            }
        } else if buffer.events.len() == INPUT_CAPACITY {
            let Some(index) = buffer
                .events
                .iter()
                .position(|queued| is_replaceable(*queued))
            else {
                return Err(NativeInputBridgeError::ReliableCapacityExhausted);
            };
            let _ = buffer.events.remove(index);
        }

        buffer.events.push_back(event);
        drop(buffer);
        let next = self.revision.borrow().wrapping_add(1);
        self.revision.send_replace(next);
        Ok(())
    }
}

impl NativeInputReceiver {
    pub(crate) async fn recv(&mut self) -> Result<InputEvent, NativeInputBridgeError> {
        loop {
            if let Some(event) = self
                .buffer
                .lock()
                .map_err(|_| NativeInputBridgeError::Poisoned)?
                .events
                .pop_front()
            {
                return Ok(event);
            }
            if self.revision.changed().await.is_err() {
                std::future::pending::<()>().await;
            }
        }
    }
}

#[derive(Clone)]
pub(crate) struct PlatformSafetySender {
    event: watch::Sender<Option<PlatformSafetyEvent>>,
}

pub(crate) struct PlatformSafetyReceiver {
    event: watch::Receiver<Option<PlatformSafetyEvent>>,
}

pub(crate) fn platform_safety_channel() -> (PlatformSafetySender, PlatformSafetyReceiver) {
    let (event, observed_event) = watch::channel(None);
    (
        PlatformSafetySender { event },
        PlatformSafetyReceiver {
            event: observed_event,
        },
    )
}

impl PlatformSafetySender {
    pub(crate) fn send(&self, event: PlatformSafetyEvent) {
        self.event.send_replace(Some(event));
    }
}

impl PlatformSafetyReceiver {
    pub(crate) fn pending(&mut self) -> Option<PlatformSafetyEvent> {
        *self.event.borrow_and_update()
    }

    pub(crate) async fn changed(&mut self) -> Option<PlatformSafetyEvent> {
        loop {
            if self.event.changed().await.is_err() {
                std::future::pending::<()>().await;
            }
            if let Some(event) = self.pending() {
                return Some(event);
            }
        }
    }
}

const fn is_replaceable(event: InputEvent) -> bool {
    matches!(
        event,
        InputEvent::PointerMotion { .. } | InputEvent::Scroll { .. }
    )
}

const fn same_replaceable_kind(left: InputEvent, right: InputEvent) -> bool {
    matches!(
        (left, right),
        (
            InputEvent::PointerMotion { .. },
            InputEvent::PointerMotion { .. }
        ) | (InputEvent::Scroll { .. }, InputEvent::Scroll { .. })
    )
}

#[cfg(test)]
mod tests {
    use nodavo_input::{
        ButtonState, DisplayId, HidUsage, InputEvent, KEYBOARD_PAGE, KeyState, Modifiers,
        NormalizedAxis, NormalizedPosition, PointerButton, ScrollUnit,
    };

    use super::*;

    fn key(id: u16) -> InputEvent {
        InputEvent::Key {
            usage: HidUsage::new(KEYBOARD_PAGE, id),
            state: KeyState::Pressed,
            modifiers: Modifiers::empty(),
        }
    }

    fn motion(axis: u32) -> InputEvent {
        InputEvent::PointerMotion {
            position: NormalizedPosition::new(
                DisplayId::new(1),
                NormalizedAxis::from_bits(u16::try_from(axis).unwrap()),
                NormalizedAxis::from_bits(u16::try_from(axis).unwrap()),
            ),
        }
    }

    #[tokio::test]
    async fn coalesces_replaceable_events_without_evicting_reliable_events() {
        let (sender, mut receiver) = native_input_channel();
        sender.send(motion(1)).unwrap();
        sender.send(key(4)).unwrap();
        sender.send(motion(2)).unwrap();
        sender
            .send(InputEvent::Scroll {
                horizontal: 1,
                vertical: -1,
                unit: ScrollUnit::Lines,
            })
            .unwrap();
        sender
            .send(InputEvent::PointerButton {
                button: PointerButton::new(1).unwrap(),
                state: ButtonState::Pressed,
            })
            .unwrap();

        assert_eq!(receiver.recv().await.unwrap(), key(4));
        assert_eq!(receiver.recv().await.unwrap(), motion(2));
        assert!(matches!(
            receiver.recv().await.unwrap(),
            InputEvent::Scroll { .. }
        ));
        assert!(matches!(
            receiver.recv().await.unwrap(),
            InputEvent::PointerButton { .. }
        ));
    }

    #[test]
    fn reliable_only_overflow_is_explicit() {
        let (sender, _receiver) = native_input_channel();
        for id in 0..INPUT_CAPACITY {
            sender.send(key(u16::try_from(id).unwrap())).unwrap();
        }
        assert_eq!(
            sender.send(key(0x0100)),
            Err(NativeInputBridgeError::ReliableCapacityExhausted)
        );
    }

    #[tokio::test]
    async fn priority_safety_signal_is_independent_of_the_input_queue() {
        let (input, _receiver) = native_input_channel();
        for id in 0..INPUT_CAPACITY {
            input.send(key(u16::try_from(id).unwrap())).unwrap();
        }
        let (safety, mut observed) = platform_safety_channel();
        safety.send(PlatformSafetyEvent::LocalSleeping);
        assert_eq!(
            observed.changed().await,
            Some(PlatformSafetyEvent::LocalSleeping)
        );
    }
}
