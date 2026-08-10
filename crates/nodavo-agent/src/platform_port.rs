//! Small platform boundary owned by the authenticated session runtime.
//!
//! Native capture and injection remain owned by their platform crates. This
//! module binds them to the session effect executor without exposing native
//! handles to transport or protocol code.

#[cfg(test)]
use std::sync::{Arc, Mutex};

use nodavo_input::InputEvent;
#[cfg(any(target_os = "macos", test))]
use nodavo_protocol::DisplayRotation;
use thiserror::Error;

use crate::topology_runtime::NativeDisplaySnapshot;

#[cfg(target_os = "macos")]
use std::sync::mpsc as std_mpsc;
#[cfg(target_os = "macos")]
use std::thread::{self, JoinHandle};
#[cfg(target_os = "macos")]
use std::time::Duration;

#[cfg(target_os = "macos")]
use nodavo_platform_macos::{
    MacInputCapture, MacInputCaptureEvent, MacInputInjector, MacInputLifecycleEvent,
    MacPlatformError, accessibility_trusted, active_displays,
};

#[cfg(target_os = "macos")]
use crate::native_bridge::{NativeInputSender, PlatformSafetyEvent, PlatformSafetySender};

#[cfg(target_os = "macos")]
const NATIVE_ACK_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum PlatformPortError {
    #[error("native input integration is unavailable")]
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    Unavailable,
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    #[error("native input integration failed")]
    Native,
}

pub(crate) trait PlatformPort: Send {
    fn display_snapshot(&self) -> Result<Vec<NativeDisplaySnapshot>, PlatformPortError>;
    fn start_capture(&mut self) -> Result<(), PlatformPortError>;
    fn set_routing_to_peer(&mut self, enabled: bool) -> Result<(), PlatformPortError>;
    fn inject(&mut self, event: InputEvent) -> Result<(), PlatformPortError>;
    fn release_injected(&mut self, releases: &[InputEvent]) -> Result<(), PlatformPortError>;
    fn restore_local_ownership(&mut self) -> Result<(), PlatformPortError>;
    fn ensure_healthy(&self) -> Result<(), PlatformPortError>;
}

/// Honest production placeholder until a reviewed native adapter is wired in.
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
#[derive(Debug, Default)]
pub(crate) struct UnavailablePlatformPort;

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
impl PlatformPort for UnavailablePlatformPort {
    fn display_snapshot(&self) -> Result<Vec<NativeDisplaySnapshot>, PlatformPortError> {
        Err(PlatformPortError::Unavailable)
    }

    fn start_capture(&mut self) -> Result<(), PlatformPortError> {
        Ok(())
    }

    fn set_routing_to_peer(&mut self, enabled: bool) -> Result<(), PlatformPortError> {
        if enabled {
            Err(PlatformPortError::Unavailable)
        } else {
            Ok(())
        }
    }

    fn inject(&mut self, _event: InputEvent) -> Result<(), PlatformPortError> {
        Err(PlatformPortError::Unavailable)
    }

    fn release_injected(&mut self, _releases: &[InputEvent]) -> Result<(), PlatformPortError> {
        Ok(())
    }

    fn restore_local_ownership(&mut self) -> Result<(), PlatformPortError> {
        Ok(())
    }

    fn ensure_healthy(&self) -> Result<(), PlatformPortError> {
        Ok(())
    }
}

#[cfg(target_os = "macos")]
pub(crate) struct MacPlatformPort {
    capture: MacInputCapture,
    injector: Option<MacInjectorWorker>,
}

#[cfg(target_os = "macos")]
enum MacInjectorCommand {
    Inject(
        InputEvent,
        std_mpsc::SyncSender<Result<(), MacPlatformError>>,
    ),
    Release(std_mpsc::SyncSender<Result<(), MacPlatformError>>),
    Stop,
}

#[cfg(target_os = "macos")]
struct MacInjectorWorker {
    commands: std_mpsc::SyncSender<MacInjectorCommand>,
    worker: Option<JoinHandle<()>>,
}

#[cfg(target_os = "macos")]
impl MacInjectorWorker {
    fn start() -> Result<Self, PlatformPortError> {
        let (commands, receiver) = std_mpsc::sync_channel(1);
        let (ready, started) = std_mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("nodavo-macos-injector".into())
            .spawn(move || {
                let Ok(mut injector) = MacInputInjector::new() else {
                    let _ = ready.send(false);
                    return;
                };
                if ready.send(true).is_err() {
                    return;
                }
                while let Ok(command) = receiver.recv() {
                    match command {
                        MacInjectorCommand::Inject(event, acknowledgement) => {
                            let _ = acknowledgement.send(injector.inject(event));
                        }
                        MacInjectorCommand::Release(acknowledgement) => {
                            let result = injector.force_release_all().map(|_| ());
                            let _ = acknowledgement.send(result);
                        }
                        MacInjectorCommand::Stop => break,
                    }
                }
                let _ = injector.force_release_all();
            })
            .map_err(|_| PlatformPortError::Native)?;
        if let Ok(true) = started.recv_timeout(NATIVE_ACK_TIMEOUT) {
            Ok(Self {
                commands,
                worker: Some(worker),
            })
        } else {
            let _ = worker.join();
            Err(PlatformPortError::Native)
        }
    }

    fn inject(&self, event: InputEvent) -> Result<(), PlatformPortError> {
        let (acknowledgement, received) = std_mpsc::sync_channel(1);
        self.commands
            .send(MacInjectorCommand::Inject(event, acknowledgement))
            .map_err(|_| PlatformPortError::Native)?;
        received
            .recv_timeout(NATIVE_ACK_TIMEOUT)
            .map_err(|_| PlatformPortError::Native)?
            .map_err(|_| PlatformPortError::Native)
    }

    fn force_release_all(&self) -> Result<(), PlatformPortError> {
        let (acknowledgement, received) = std_mpsc::sync_channel(1);
        self.commands
            .send(MacInjectorCommand::Release(acknowledgement))
            .map_err(|_| PlatformPortError::Native)?;
        received
            .recv_timeout(NATIVE_ACK_TIMEOUT)
            .map_err(|_| PlatformPortError::Native)?
            .map_err(|_| PlatformPortError::Native)
    }

    fn is_running(&self) -> bool {
        self.worker
            .as_ref()
            .is_some_and(|worker| !worker.is_finished())
    }

    fn stop(&mut self) {
        let _ = self.commands.send(MacInjectorCommand::Stop);
        if let Some(worker) = self.worker.take()
            && worker.is_finished()
        {
            let _ = worker.join();
        }
    }
}

#[cfg(target_os = "macos")]
impl Drop for MacInjectorWorker {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(target_os = "macos")]
impl MacPlatformPort {
    pub(crate) fn new(input: NativeInputSender, safety: &PlatformSafetySender) -> Self {
        let callback_safety = safety.clone();
        let capture = MacInputCapture::new_edge_routed_fallible(move |event| match event {
            MacInputCaptureEvent::Input(event) => input.send(event).map_err(|_| {
                callback_safety.send(PlatformSafetyEvent::CaptureFailed);
                MacPlatformError::CaptureCallbackFailed
            }),
            MacInputCaptureEvent::Lifecycle(lifecycle) => {
                let event = safety_event_for_lifecycle(lifecycle);
                if let Some(event) = event {
                    callback_safety.send(event);
                }
                Ok(())
            }
        });
        Self {
            capture,
            injector: None,
        }
    }

    fn injector(&self) -> Result<&MacInjectorWorker, PlatformPortError> {
        self.injector.as_ref().ok_or(PlatformPortError::Native)
    }
}

#[cfg(target_os = "macos")]
const fn safety_event_for_lifecycle(
    lifecycle: MacInputLifecycleEvent,
) -> Option<PlatformSafetyEvent> {
    match lifecycle {
        MacInputLifecycleEvent::SystemWillSleep => Some(PlatformSafetyEvent::LocalSleeping),
        MacInputLifecycleEvent::ScreensDidSleep
        | MacInputLifecycleEvent::SessionDidResignActive => Some(PlatformSafetyEvent::LocalLocked),
        MacInputLifecycleEvent::TapDisabledByTimeout
        | MacInputLifecycleEvent::TapDisabledByUserInput => {
            Some(PlatformSafetyEvent::CaptureFailed)
        }
        MacInputLifecycleEvent::CaptureStarted
        | MacInputLifecycleEvent::CaptureStopped
        | MacInputLifecycleEvent::SystemDidWake
        | MacInputLifecycleEvent::ScreensDidWake
        | MacInputLifecycleEvent::SessionDidBecomeActive => None,
    }
}

#[cfg(target_os = "macos")]
impl PlatformPort for MacPlatformPort {
    fn display_snapshot(&self) -> Result<Vec<NativeDisplaySnapshot>, PlatformPortError> {
        active_displays()
            .map_err(|_| PlatformPortError::Native)?
            .into_iter()
            .map(|display| {
                let pixel_width =
                    u32::try_from(display.width_pixels).map_err(|_| PlatformPortError::Native)?;
                let pixel_height =
                    u32::try_from(display.height_pixels).map_err(|_| PlatformPortError::Native)?;
                Ok(NativeDisplaySnapshot {
                    native_id: display.id,
                    origin_x_milli: logical_milli_i32(display.origin_x)?,
                    origin_y_milli: logical_milli_i32(display.origin_y)?,
                    pixel_width,
                    pixel_height,
                    scale_x_milli: scale_milli(display.width_pixels, display.width_points)?,
                    scale_y_milli: scale_milli(display.height_pixels, display.height_points)?,
                    rotation: DisplayRotation::Degrees0,
                })
            })
            .collect()
    }

    fn start_capture(&mut self) -> Result<(), PlatformPortError> {
        if self.injector.is_some() {
            return Err(PlatformPortError::Native);
        }
        let injector = MacInjectorWorker::start()?;
        self.capture
            .start()
            .map_err(|_| PlatformPortError::Native)?;
        self.injector = Some(injector);
        Ok(())
    }

    fn set_routing_to_peer(&mut self, enabled: bool) -> Result<(), PlatformPortError> {
        self.capture
            .set_routing_to_peer(enabled)
            .map_err(|_| PlatformPortError::Native)
    }

    fn inject(&mut self, event: InputEvent) -> Result<(), PlatformPortError> {
        self.injector()?.inject(event)
    }

    fn release_injected(&mut self, releases: &[InputEvent]) -> Result<(), PlatformPortError> {
        match &self.injector {
            Some(injector) => injector.force_release_all(),
            None if releases.is_empty() => Ok(()),
            None => Err(PlatformPortError::Native),
        }
    }

    fn restore_local_ownership(&mut self) -> Result<(), PlatformPortError> {
        let routing = self.capture.set_routing_to_peer(false);
        let releases = self
            .injector
            .as_ref()
            .map(MacInjectorWorker::force_release_all)
            .transpose();
        if routing.is_err() || releases.is_err() {
            Err(PlatformPortError::Native)
        } else {
            Ok(())
        }
    }

    fn ensure_healthy(&self) -> Result<(), PlatformPortError> {
        if self.capture.is_running()
            && self
                .injector
                .as_ref()
                .is_some_and(MacInjectorWorker::is_running)
            && accessibility_trusted()
        {
            Ok(())
        } else {
            Err(PlatformPortError::Native)
        }
    }
}

#[cfg(test)]
#[derive(Clone, Debug, Default)]
pub(crate) struct VirtualPlatformPort {
    state: Arc<Mutex<VirtualPlatformState>>,
}

#[cfg(test)]
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct VirtualPlatformState {
    pub(crate) injected: Vec<InputEvent>,
    pub(crate) forced_releases: Vec<InputEvent>,
    pub(crate) restore_count: usize,
    pub(crate) routing_to_peer: bool,
    pub(crate) routing_transitions: Vec<bool>,
}

#[cfg(test)]
impl VirtualPlatformPort {
    pub(crate) fn snapshot(&self) -> VirtualPlatformState {
        self.state.lock().expect("virtual platform lock").clone()
    }
}

#[cfg(test)]
impl PlatformPort for VirtualPlatformPort {
    fn display_snapshot(&self) -> Result<Vec<NativeDisplaySnapshot>, PlatformPortError> {
        Ok(vec![NativeDisplaySnapshot {
            native_id: nodavo_input::DisplayId::new(101),
            origin_x_milli: 0,
            origin_y_milli: 0,
            pixel_width: 1_920,
            pixel_height: 1_080,
            scale_x_milli: 1_000,
            scale_y_milli: 1_000,
            rotation: DisplayRotation::Degrees0,
        }])
    }

    fn start_capture(&mut self) -> Result<(), PlatformPortError> {
        Ok(())
    }

    fn set_routing_to_peer(&mut self, enabled: bool) -> Result<(), PlatformPortError> {
        let mut state = self.state.lock().expect("virtual platform lock");
        state.routing_to_peer = enabled;
        state.routing_transitions.push(enabled);
        Ok(())
    }

    fn inject(&mut self, event: InputEvent) -> Result<(), PlatformPortError> {
        self.state
            .lock()
            .expect("virtual platform lock")
            .injected
            .push(event);
        Ok(())
    }

    fn release_injected(&mut self, releases: &[InputEvent]) -> Result<(), PlatformPortError> {
        self.state
            .lock()
            .expect("virtual platform lock")
            .forced_releases
            .extend_from_slice(releases);
        Ok(())
    }

    fn restore_local_ownership(&mut self) -> Result<(), PlatformPortError> {
        let mut state = self.state.lock().expect("virtual platform lock");
        state.routing_to_peer = false;
        state.restore_count = state.restore_count.saturating_add(1);
        Ok(())
    }

    fn ensure_healthy(&self) -> Result<(), PlatformPortError> {
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn logical_milli_i32(value: f64) -> Result<i32, PlatformPortError> {
    let value = value * 1_000.0;
    if !value.is_finite() || value < f64::from(i32::MIN) || value > f64::from(i32::MAX) {
        return Err(PlatformPortError::Native);
    }
    #[allow(clippy::cast_possible_truncation)]
    Ok(value.round() as i32)
}

#[cfg(target_os = "macos")]
fn scale_milli(pixels: u64, points: f64) -> Result<u16, PlatformPortError> {
    let pixels = u32::try_from(pixels).map_err(|_| PlatformPortError::Native)?;
    let scale = f64::from(pixels) * 1_000.0 / points;
    if !scale.is_finite() || scale <= 0.0 || scale > f64::from(u16::MAX) {
        return Err(PlatformPortError::Native);
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    Ok(scale.round() as u16)
}

#[cfg(all(test, target_os = "macos"))]
mod mac_tests {
    use super::*;
    use crate::native_bridge::{native_input_channel, platform_safety_channel};

    #[test]
    fn native_adapter_is_inert_until_start_and_maps_terminal_lifecycle() {
        let (input, _observed_input) = native_input_channel();
        let (safety, _observed_safety) = platform_safety_channel();
        let mut platform = MacPlatformPort::new(input, &safety);

        assert!(platform.set_routing_to_peer(false).is_ok());
        assert_eq!(platform.ensure_healthy(), Err(PlatformPortError::Native));
        assert_eq!(
            safety_event_for_lifecycle(MacInputLifecycleEvent::SystemWillSleep),
            Some(PlatformSafetyEvent::LocalSleeping)
        );
        assert_eq!(
            safety_event_for_lifecycle(MacInputLifecycleEvent::SessionDidResignActive),
            Some(PlatformSafetyEvent::LocalLocked)
        );
        assert_eq!(
            safety_event_for_lifecycle(MacInputLifecycleEvent::TapDisabledByTimeout),
            Some(PlatformSafetyEvent::CaptureFailed)
        );
        assert_eq!(
            safety_event_for_lifecycle(MacInputLifecycleEvent::SystemDidWake),
            None
        );
    }
}
