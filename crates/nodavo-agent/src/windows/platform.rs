//! Windows native input adapter owned by one authenticated peer session.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc as std_mpsc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use nodavo_input::InputEvent;
use nodavo_platform_windows::{
    WindowsDisplayMonitor, WindowsInputCapture, WindowsInputCaptureEvent, WindowsInputInjector,
    WindowsInputLifecycleEvent, WindowsPlatformError, probe_environment,
    resolve_downloads_nodavo_directory as resolve_native_downloads_nodavo_directory,
};
use nodavo_transfer::ReceiveRoot;

use crate::native_bridge::{NativeInputSender, PlatformSafetyEvent, PlatformSafetySender};
use crate::platform_port::{
    PlatformPort, PlatformPortError, absolute_pointer_transition_is_retryable,
    acknowledge_inject_result, finish_worker_before_deadline, injector_worker_start_allowed,
    receive_worker_stop_before_deadline, submit_worker_command_before_deadline,
};
use crate::topology_runtime::NativeDisplaySnapshot;

const NATIVE_ACK_TIMEOUT: Duration = Duration::from_secs(2);
static WINDOWS_INJECTOR_POISONED: AtomicBool = AtomicBool::new(false);

/// Converts the retained Windows known-folder handle directly into the generic
/// receive-root capability without exposing or reopening a pathname.
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn resolve_downloads_nodavo_directory() -> Result<ReceiveRoot, ()> {
    let handle = resolve_native_downloads_nodavo_directory().map_err(|_| ())?;
    ReceiveRoot::from_retained_directory_handle(handle).map_err(|_| ())
}

pub(crate) struct WindowsPlatformPort {
    // Capture drops first, so suppression is cleared before injector teardown.
    capture: WindowsInputCapture,
    display_monitor: Option<WindowsDisplayMonitor>,
    injector: Option<WindowsInjectorWorker>,
    input_admission: NativeInputSender,
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
        if !injector_worker_start_allowed(&WINDOWS_INJECTOR_POISONED) {
            return Err(PlatformPortError::Native);
        }
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
                            let result = injector.inject(event);
                            let retryable_transition = absolute_pointer_transition_is_retryable(
                                event,
                                matches!(&result, Err(WindowsPlatformError::DisplayUnavailable)),
                            );
                            acknowledge_inject_result(
                                result,
                                &acknowledgement,
                                &WINDOWS_INJECTOR_POISONED,
                                retryable_transition,
                            );
                        }
                        WindowsInjectorCommand::Release(acknowledgement) => {
                            let result = injector.force_release_all().map(|_| ());
                            if result.is_err() {
                                WINDOWS_INJECTOR_POISONED.store(true, Ordering::Release);
                            }
                            if acknowledgement.send(result).is_err() {
                                WINDOWS_INJECTOR_POISONED.store(true, Ordering::Release);
                            }
                        }
                        WindowsInjectorCommand::Stop(acknowledgement) => {
                            let result = injector.force_release_all().map(|_| ());
                            let release_failed = result.is_err();
                            let acknowledgement_failed = acknowledgement.send(result).is_err();
                            if release_failed || acknowledgement_failed {
                                WINDOWS_INJECTOR_POISONED.store(true, Ordering::Release);
                            }
                            return;
                        }
                    }
                }
                // A disconnected command owner still gets a best-effort release.
                if injector.force_release_all().is_err() {
                    WINDOWS_INJECTOR_POISONED.store(true, Ordering::Release);
                }
            })
            .map_err(|_| PlatformPortError::Native)?;
        match started.recv_timeout(NATIVE_ACK_TIMEOUT) {
            Ok(true) => Ok(Self {
                commands,
                worker: Some(worker),
            }),
            outcome => {
                let mut worker = Some(worker);
                if matches!(outcome, Err(std_mpsc::RecvTimeoutError::Timeout)) {
                    WINDOWS_INJECTOR_POISONED.store(true, Ordering::Release);
                    drop(worker.take());
                } else {
                    let _ = finish_worker_before_deadline(
                        &mut worker,
                        &WINDOWS_INJECTOR_POISONED,
                        Instant::now() + NATIVE_ACK_TIMEOUT,
                    );
                }
                Err(PlatformPortError::Native)
            }
        }
    }

    fn inject(&self, event: InputEvent) -> Result<(), PlatformPortError> {
        let (acknowledgement, received) = std_mpsc::sync_channel(1);
        submit_worker_command_before_deadline(
            &self.commands,
            WindowsInjectorCommand::Inject(event, acknowledgement),
            &received,
            &WINDOWS_INJECTOR_POISONED,
            Instant::now() + NATIVE_ACK_TIMEOUT,
        )
        .map_err(|()| PlatformPortError::Native)?
        .map_err(|error| match error {
            WindowsPlatformError::DisplayUnavailable => PlatformPortError::DisplaySnapshotPending,
            _ => PlatformPortError::Native,
        })
    }

    fn force_release_all(&self) -> Result<(), PlatformPortError> {
        let (acknowledgement, received) = std_mpsc::sync_channel(1);
        submit_worker_command_before_deadline(
            &self.commands,
            WindowsInjectorCommand::Release(acknowledgement),
            &received,
            &WINDOWS_INJECTOR_POISONED,
            Instant::now() + NATIVE_ACK_TIMEOUT,
        )
        .map_err(|()| PlatformPortError::Native)?
        .map_err(|_| PlatformPortError::Native)
    }

    fn is_running(&self) -> bool {
        self.worker
            .as_ref()
            .is_some_and(|worker| !worker.is_finished())
    }

    fn stop(&mut self) {
        let (acknowledgement, received) = std_mpsc::sync_channel(1);
        let deadline = Instant::now() + NATIVE_ACK_TIMEOUT;
        let mut command = WindowsInjectorCommand::Stop(acknowledgement);
        let mut submitted = false;
        loop {
            match self.commands.try_send(command) {
                Ok(()) => {
                    submitted = true;
                    break;
                }
                Err(std_mpsc::TrySendError::Disconnected(_)) => {
                    WINDOWS_INJECTOR_POISONED.store(true, Ordering::Release);
                    break;
                }
                Err(std_mpsc::TrySendError::Full(returned)) => {
                    command = returned;
                    if Instant::now() >= deadline {
                        WINDOWS_INJECTOR_POISONED.store(true, Ordering::Release);
                        drop(self.worker.take());
                        return;
                    }
                    thread::sleep(Duration::from_millis(1));
                }
            }
        }
        if submitted {
            let _ = receive_worker_stop_before_deadline(
                &received,
                &WINDOWS_INJECTOR_POISONED,
                deadline,
            );
        }
        let _ =
            finish_worker_before_deadline(&mut self.worker, &WINDOWS_INJECTOR_POISONED, deadline);
    }
}

impl Drop for WindowsInjectorWorker {
    fn drop(&mut self) {
        self.stop();
    }
}

impl WindowsPlatformPort {
    pub(crate) fn new(input: NativeInputSender, safety: &PlatformSafetySender) -> Self {
        let input_admission = input.clone();
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
            display_monitor: None,
            injector: None,
            input_admission,
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
        self.display_monitor
            .as_ref()
            .ok_or(PlatformPortError::Native)?
            .snapshot()
            .map_err(|error| match error {
                WindowsPlatformError::DisplayUnavailable => {
                    PlatformPortError::DisplaySnapshotPending
                }
                _ => PlatformPortError::Native,
            })?
            .displays()
            .iter()
            .map(|display| {
                Ok(NativeDisplaySnapshot {
                    native_id: display.id,
                    origin_x_milli: logical_origin_milli(display.left, display.dpi_x)?,
                    origin_y_milli: logical_origin_milli(display.top, display.dpi_y)?,
                    pixel_width: display.width_pixels,
                    pixel_height: display.height_pixels,
                    scale_x_milli: scale_milli(display.dpi_x)?,
                    scale_y_milli: scale_milli(display.dpi_y)?,
                    rotation: display.rotation,
                })
            })
            .collect()
    }

    fn display_change_pending(&mut self) -> Result<bool, PlatformPortError> {
        self.display_monitor
            .as_ref()
            .map(WindowsDisplayMonitor::display_change_pending)
            .ok_or(PlatformPortError::Native)
    }

    fn pause_input_admission(&mut self) -> Result<(), PlatformPortError> {
        self.input_admission
            .pause_admission()
            .map_err(|_| PlatformPortError::Native)
    }

    fn resume_input_admission(&mut self) {
        self.input_admission.resume_admission();
    }

    fn start_capture(&mut self) -> Result<(), PlatformPortError> {
        if self.injector.is_some() || self.display_monitor.is_some() {
            return Err(PlatformPortError::Native);
        }
        let display_monitor =
            WindowsDisplayMonitor::start().map_err(|_| PlatformPortError::Native)?;
        let injector = WindowsInjectorWorker::start()?;
        self.capture
            .start()
            .map_err(|_| PlatformPortError::Native)?;
        self.display_monitor = Some(display_monitor);
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
            && self
                .display_monitor
                .as_ref()
                .is_some_and(WindowsDisplayMonitor::is_running)
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
