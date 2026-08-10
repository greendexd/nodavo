//! Bounded handoff from native callback threads to the async session owner.

#![cfg_attr(not(any(target_os = "macos", target_os = "windows")), allow(dead_code))]

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use nodavo_input::{InputEvent, PointerDelta};
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
    ReplaceableCapacityExhausted,
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
    /// Absolute motion and scroll are replaceable. Relative motion coalesces by
    /// bounded summation so callback backpressure does not turn queued physical
    /// movement into an unrelated absolute position. Replaceable input may be
    /// evicted to admit a reliable event. Exhausting the queue with reliable
    /// events is an explicit failure so the adapter can restore local ownership
    /// instead of silently losing a release.
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
                match merge_relative_delta(buffer.events[index], event) {
                    RelativeMerge::Merged(merged) => {
                        buffer.events[index] = merged;
                        notify_revision(buffer, &self.revision);
                        return Ok(());
                    }
                    RelativeMerge::Cancelled => {
                        let _ = buffer.events.remove(index);
                        notify_revision(buffer, &self.revision);
                        return Ok(());
                    }
                    RelativeMerge::Overflow => {
                        if buffer.events.len() == INPUT_CAPACITY {
                            let Some(eviction) = buffer
                                .events
                                .iter()
                                .position(|queued| is_lossy_replaceable(*queued))
                            else {
                                return Err(NativeInputBridgeError::ReplaceableCapacityExhausted);
                            };
                            let _ = buffer.events.remove(eviction);
                        }
                    }
                    RelativeMerge::NotRelative => {
                        let _ = buffer.events.remove(index);
                    }
                }
            } else if buffer.events.len() == INPUT_CAPACITY {
                let Some(index) = buffer
                    .events
                    .iter()
                    .position(|queued| is_lossy_replaceable(*queued))
                else {
                    return Err(NativeInputBridgeError::ReplaceableCapacityExhausted);
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

fn notify_revision(buffer: std::sync::MutexGuard<'_, InputBuffer>, revision: &watch::Sender<u64>) {
    drop(buffer);
    let next = revision.borrow().wrapping_add(1);
    revision.send_replace(next);
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
        InputEvent::PointerMotion { .. }
            | InputEvent::PointerDelta { .. }
            | InputEvent::Scroll { .. }
    )
}

const fn is_lossy_replaceable(event: InputEvent) -> bool {
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
        ) | (
            InputEvent::PointerDelta { .. },
            InputEvent::PointerDelta { .. }
        ) | (InputEvent::Scroll { .. }, InputEvent::Scroll { .. })
    )
}

enum RelativeMerge {
    NotRelative,
    Merged(InputEvent),
    Cancelled,
    Overflow,
}

fn merge_relative_delta(left: InputEvent, right: InputEvent) -> RelativeMerge {
    let (InputEvent::PointerDelta { delta: left }, InputEvent::PointerDelta { delta: right }) =
        (left, right)
    else {
        return RelativeMerge::NotRelative;
    };
    let Some(horizontal) = left.horizontal().checked_add(right.horizontal()) else {
        return RelativeMerge::Overflow;
    };
    let Some(vertical) = left.vertical().checked_add(right.vertical()) else {
        return RelativeMerge::Overflow;
    };
    if horizontal == 0 && vertical == 0 {
        return RelativeMerge::Cancelled;
    }
    PointerDelta::new(horizontal, vertical).map_or(RelativeMerge::Overflow, |delta| {
        RelativeMerge::Merged(InputEvent::PointerDelta { delta })
    })
}

#[cfg(test)]
mod tests {
    use nodavo_input::{
        ButtonState, DisplayId, HidUsage, InputEvent, KEYBOARD_PAGE, KeyState, Modifiers,
        NormalizedAxis, NormalizedPosition, PointerButton, PointerDelta, ScrollUnit,
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

    fn delta(horizontal: i32, vertical: i32) -> InputEvent {
        InputEvent::PointerDelta {
            delta: PointerDelta::new(horizontal, vertical).unwrap(),
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

    #[tokio::test]
    async fn coalesces_relative_motion_without_truncating_overflow() {
        let (sender, mut receiver) = native_input_channel();
        sender.send(delta(3, -4)).unwrap();
        sender.send(delta(7, 2)).unwrap();
        assert_eq!(receiver.recv().await.unwrap(), delta(10, -2));

        sender.send(delta(32_000, 1)).unwrap();
        sender.send(delta(2_000, 1)).unwrap();
        assert_eq!(receiver.recv().await.unwrap(), delta(32_000, 1));
        assert_eq!(receiver.recv().await.unwrap(), delta(2_000, 1));
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
