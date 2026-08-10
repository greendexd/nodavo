//! Windows native input adapter owned by one authenticated peer session.

use std::sync::mpsc as std_mpsc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use nodavo_input::InputEvent;
use nodavo_platform_windows::{
    WindowsInputCapture, WindowsInputCaptureEvent, WindowsInputInjector,
    WindowsInputLifecycleEvent, WindowsPlatformError, probe_environment,
};
use nodavo_protocol::DisplayRotation;

use crate::native_bridge::{NativeInputSender, PlatformSafetyEvent, PlatformSafetySender};
use crate::platform_port::{PlatformPort, PlatformPortError};
use crate::topology_runtime::NativeDisplaySnapshot;

const NATIVE_ACK_TIMEOUT: Duration = Duration::from_secs(2);

pub(crate) struct WindowsPlatformPort {
    // Capture drops first, so suppression is cleared before injector teardown.
    capture: WindowsInputCapture,
    injector: Option<WindowsInjectorWorker>,
}

enum WindowsInjectorCommand {
    Inject(
        InputEvent,
        std_mpsc::SyncSender<Result<(), WindowsPlatformError>>,
    ),
    Release(std_mpsc::SyncSender<Result<(), WindowsPlatformError>>),
    Stop(std_mpsc::SyncSender<Result<(), WindowsPlatformError>>),
}

struct WindowsInjectorWorker {
    commands: std_mpsc::SyncSender<WindowsInjectorCommand>,
    worker: Option<JoinHandle<()>>,
}

impl WindowsInjectorWorker {
    fn start() -> Result<Self, PlatformPortError> {
        let (commands, receiver) = std_mpsc::sync_channel(1);
        let (ready, started) = std_mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("nodavo-windows-injector".into())
            .spawn(move || {
                let Ok(mut injector) = WindowsInputInjector::new() else {
                    let _ = ready.send(false);
                    return;
                };
                if ready.send(true).is_err() {
                    return;
                }
                while let Ok(command) = receiver.recv() {
                    match command {
                        WindowsInjectorCommand::Inject(event, acknowledgement) => {
                            let _ = acknowledgement.send(injector.inject(event));
                        }
                        WindowsInjectorCommand::Release(acknowledgement) => {
                            let result = injector.force_release_all().map(|_| ());
                            let _ = acknowledgement.send(result);
                        }
                        WindowsInjectorCommand::Stop(acknowledgement) => {
                            let result = injector.force_release_all().map(|_| ());
                            let _ = acknowledgement.send(result);
                            break;
                        }
                    }
                }
                // A disconnected command owner still gets a best-effort release.
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
            .send(WindowsInjectorCommand::Inject(event, acknowledgement))
            .map_err(|_| PlatformPortError::Native)?;
        received
            .recv_timeout(NATIVE_ACK_TIMEOUT)
            .map_err(|_| PlatformPortError::Native)?
            .map_err(|_| PlatformPortError::Native)
    }

    fn force_release_all(&self) -> Result<(), PlatformPortError> {
        let (acknowledgement, received) = std_mpsc::sync_channel(1);
        self.commands
            .send(WindowsInjectorCommand::Release(acknowledgement))
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
        let (acknowledgement, received) = std_mpsc::sync_channel(1);
        if self
            .commands
            .send(WindowsInjectorCommand::Stop(acknowledgement))
            .is_ok()
        {
            let _ = received.recv_timeout(NATIVE_ACK_TIMEOUT);
        }
        if let Some(worker) = self.worker.take() {
            if worker.is_finished() {
                let _ = worker.join();
            }
        }
    }
}

impl Drop for WindowsInjectorWorker {
    fn drop(&mut self) {
        self.stop();
    }
}

impl WindowsPlatformPort {
    pub(crate) fn new(input: NativeInputSender, safety: &PlatformSafetySender) -> Self {
        let callback_safety = safety.clone();
        let capture = WindowsInputCapture::new_routed_fallible(move |event| match event {
            WindowsInputCaptureEvent::Input(event) => input.send(event).map_err(|_| {
                callback_safety.send(PlatformSafetyEvent::CaptureFailed);
                WindowsPlatformError::CaptureCallbackFailed
            }),
            WindowsInputCaptureEvent::Lifecycle(lifecycle) => {
                if let Some(event) = safety_event_for_lifecycle(lifecycle) {
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

    fn injector(&self) -> Result<&WindowsInjectorWorker, PlatformPortError> {
        self.injector.as_ref().ok_or(PlatformPortError::Native)
    }
}

const fn safety_event_for_lifecycle(
    lifecycle: WindowsInputLifecycleEvent,
) -> Option<PlatformSafetyEvent> {
    match lifecycle {
        WindowsInputLifecycleEvent::SystemSuspending => Some(PlatformSafetyEvent::LocalSleeping),
        WindowsInputLifecycleEvent::SessionLocked
        | WindowsInputLifecycleEvent::SessionDisconnected
        | WindowsInputLifecycleEvent::DefaultDesktopUnavailable => {
            Some(PlatformSafetyEvent::LocalLocked)
        }
        WindowsInputLifecycleEvent::CaptureStarted
        | WindowsInputLifecycleEvent::CaptureStopped
        | WindowsInputLifecycleEvent::SessionUnlocked
        | WindowsInputLifecycleEvent::SessionConnected
        | WindowsInputLifecycleEvent::SystemResumed
        | WindowsInputLifecycleEvent::DefaultDesktopAvailable
        | WindowsInputLifecycleEvent::InputDeviceChanged => None,
    }
}

impl PlatformPort for WindowsPlatformPort {
    fn display_snapshot(&self) -> Result<Vec<NativeDisplaySnapshot>, PlatformPortError> {
        nodavo_platform_windows::active_displays()
            .map_err(|_| PlatformPortError::Native)?
            .into_iter()
            .map(|display| {
                let origin_x_milli = logical_origin_milli(display.left, display.dpi_x)?;
                let origin_y_milli = logical_origin_milli(display.top, display.dpi_y)?;
                let scale_x_milli = scale_milli(display.dpi_x)?;
                let scale_y_milli = scale_milli(display.dpi_y)?;
                Ok(NativeDisplaySnapshot {
                    native_id: display.id,
                    origin_x_milli,
                    origin_y_milli,
                    pixel_width: display.width_pixels,
                    pixel_height: display.height_pixels,
                    scale_x_milli,
                    scale_y_milli,
                    rotation: DisplayRotation::Degrees0,
                })
            })
            .collect()
    }

    fn start_capture(&mut self) -> Result<(), PlatformPortError> {
        if self.injector.is_some() {
            return Err(PlatformPortError::Native);
        }
        let injector = WindowsInjectorWorker::start()?;
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
            .map(WindowsInjectorWorker::force_release_all)
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
                .is_some_and(WindowsInjectorWorker::is_running)
            && probe_environment().is_ok()
        {
            Ok(())
        } else {
            Err(PlatformPortError::Native)
        }
    }
}

fn logical_origin_milli(value: i32, dpi: u32) -> Result<i32, PlatformPortError> {
    if dpi == 0 {
        return Err(PlatformPortError::Native);
    }
    let scaled = i64::from(value)
        .checked_mul(96_000)
        .ok_or(PlatformPortError::Native)?
        / i64::from(dpi);
    i32::try_from(scaled).map_err(|_| PlatformPortError::Native)
}

fn scale_milli(dpi: u32) -> Result<u16, PlatformPortError> {
    let scaled = u64::from(dpi)
        .checked_mul(1_000)
        .ok_or(PlatformPortError::Native)?
        / 96;
    u16::try_from(scaled).map_err(|_| PlatformPortError::Native)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_sleep_and_desktop_loss_request_priority_recovery() {
        assert_eq!(
            safety_event_for_lifecycle(WindowsInputLifecycleEvent::SessionLocked),
            Some(PlatformSafetyEvent::LocalLocked)
        );
        assert_eq!(
            safety_event_for_lifecycle(WindowsInputLifecycleEvent::SessionDisconnected),
            Some(PlatformSafetyEvent::LocalLocked)
        );
        assert_eq!(
            safety_event_for_lifecycle(WindowsInputLifecycleEvent::DefaultDesktopUnavailable),
            Some(PlatformSafetyEvent::LocalLocked)
        );
        assert_eq!(
            safety_event_for_lifecycle(WindowsInputLifecycleEvent::SystemSuspending),
            Some(PlatformSafetyEvent::LocalSleeping)
        );
        assert_eq!(
            safety_event_for_lifecycle(WindowsInputLifecycleEvent::SystemResumed),
            None
        );
    }
}
