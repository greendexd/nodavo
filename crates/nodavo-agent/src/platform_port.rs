//! Small platform boundary owned by the authenticated session runtime.
//!
//! Native capture and injection remain owned by their platform crates. This
//! module binds them to the session effect executor without exposing native
//! handles to transport or protocol code.

#[cfg(test)]
use std::sync::{Arc, Mutex};

#[cfg(any(target_os = "macos", target_os = "windows"))]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(any(target_os = "macos", target_os = "windows"))]
use std::time::Instant;

use nodavo_input::InputEvent;
#[cfg(test)]
use nodavo_protocol::DisplayRotation;
use thiserror::Error;

use crate::topology_runtime::NativeDisplaySnapshot;

#[cfg(target_os = "macos")]
use std::sync::mpsc as std_mpsc;
#[cfg(any(target_os = "macos", target_os = "windows"))]
use std::thread::{self, JoinHandle};
#[cfg(any(target_os = "macos", target_os = "windows"))]
use std::time::Duration;

#[cfg(target_os = "macos")]
use nodavo_platform_macos::{
    MacDisplayMonitor, MacInputCapture, MacInputCaptureEvent, MacInputInjector,
    MacInputLifecycleEvent, MacPlatformError, accessibility_trusted,
};

#[cfg(target_os = "macos")]
use crate::native_bridge::{NativeInputSender, PlatformSafetyEvent, PlatformSafetySender};

#[cfg(target_os = "macos")]
const NATIVE_ACK_TIMEOUT: Duration = Duration::from_secs(2);

#[cfg(target_os = "macos")]
static MAC_INJECTOR_POISONED: AtomicBool = AtomicBool::new(false);

#[cfg(any(target_os = "macos", target_os = "windows"))]
pub(crate) fn injector_worker_start_allowed(poison: &AtomicBool) -> bool {
    !poison.load(Ordering::Acquire)
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
pub(crate) const fn absolute_pointer_transition_is_retryable(
    event: InputEvent,
    topology_transition: bool,
) -> bool {
    topology_transition && matches!(event, InputEvent::PointerMotion { .. })
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
pub(crate) fn acknowledge_inject_result<Error>(
    result: Result<(), Error>,
    acknowledgement: &std::sync::mpsc::SyncSender<Result<(), Error>>,
    poison: &AtomicBool,
    retryable_transition: bool,
) {
    if result.is_err() && !retryable_transition {
        // The replacement fence must be visible before the caller can observe
        // the fatal ACK and begin recovery.
        poison.store(true, Ordering::Release);
    }
    if acknowledgement.send(result).is_err() {
        poison.store(true, Ordering::Release);
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
pub(crate) fn finish_worker_before_deadline(
    worker: &mut Option<JoinHandle<()>>,
    poison: &AtomicBool,
    deadline: Instant,
) -> bool {
    let Some(handle) = worker.take() else {
        return true;
    };
    while !handle.is_finished() {
        if Instant::now() >= deadline {
            poison.store(true, Ordering::Release);
            // Detaching is safe only because poison permanently prevents a
            // replacement injector from starting in this process.
            drop(handle);
            return false;
        }
        thread::sleep(Duration::from_millis(1));
    }
    if handle.join().is_err() {
        poison.store(true, Ordering::Release);
        false
    } else {
        true
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
pub(crate) fn submit_worker_command_before_deadline<Command, Reply>(
    commands: &std::sync::mpsc::SyncSender<Command>,
    command: Command,
    received: &std::sync::mpsc::Receiver<Reply>,
    poison: &AtomicBool,
    deadline: Instant,
) -> Result<Reply, ()> {
    if poison.load(Ordering::Acquire) {
        return Err(());
    }
    let mut command = command;
    loop {
        match commands.try_send(command) {
            Ok(()) => break,
            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                poison.store(true, Ordering::Release);
                return Err(());
            }
            Err(std::sync::mpsc::TrySendError::Full(returned)) => {
                command = returned;
                if Instant::now() >= deadline {
                    poison.store(true, Ordering::Release);
                    return Err(());
                }
                thread::sleep(Duration::from_millis(1));
            }
        }
    }
    let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
        poison.store(true, Ordering::Release);
        return Err(());
    };
    received.recv_timeout(remaining).map_err(|_| {
        poison.store(true, Ordering::Release);
    })
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
pub(crate) fn receive_worker_stop_before_deadline<Error>(
    received: &std::sync::mpsc::Receiver<Result<(), Error>>,
    poison: &AtomicBool,
    deadline: Instant,
) -> bool {
    let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
        poison.store(true, Ordering::Release);
        return false;
    };
    if matches!(received.recv_timeout(remaining), Ok(Ok(()))) {
        true
    } else {
        poison.store(true, Ordering::Release);
        false
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum PlatformPortError {
    #[cfg_attr(
        not(target_os = "windows"),
        allow(dead_code, reason = "Windows exposes an asynchronous stable snapshot")
    )]
    #[error("a changed display graph is not stable yet")]
    DisplaySnapshotPending,
    #[error("native input integration is unavailable")]
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    Unavailable,
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    #[error("native input integration failed")]
    Native,
}

pub(crate) trait PlatformPort: Send {
    fn display_snapshot(&self) -> Result<Vec<NativeDisplaySnapshot>, PlatformPortError>;
    /// Coalesced edge-trigger for a fresh full snapshot. Platform adapters may
    /// keep the default until their native display watcher is wired.
    fn display_change_pending(&mut self) -> Result<bool, PlatformPortError> {
        Ok(false)
    }
    fn pause_input_admission(&mut self) -> Result<(), PlatformPortError> {
        Ok(())
    }
    fn resume_input_admission(&mut self) {}
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
    display_monitor: Option<MacDisplayMonitor>,
    injector: Option<MacInjectorWorker>,
    input_admission: NativeInputSender,
}

#[cfg(target_os = "macos")]
enum MacInjectorCommand {
    Inject(
        InputEvent,
        std_mpsc::SyncSender<Result<(), MacPlatformError>>,
    ),
    Release(std_mpsc::SyncSender<Result<(), MacPlatformError>>),
    Stop(std_mpsc::SyncSender<Result<(), MacPlatformError>>),
}

#[cfg(target_os = "macos")]
struct MacInjectorWorker {
    commands: std_mpsc::SyncSender<MacInjectorCommand>,
    worker: Option<JoinHandle<()>>,
}

#[cfg(target_os = "macos")]
impl MacInjectorWorker {
    fn start() -> Result<Self, PlatformPortError> {
        if !injector_worker_start_allowed(&MAC_INJECTOR_POISONED) {
            return Err(PlatformPortError::Native);
        }
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
                            let result = injector.inject(event);
                            let retryable_transition = absolute_pointer_transition_is_retryable(
                                event,
                                matches!(
                                    &result,
                                    Err(MacPlatformError::DisplayConfigurationChanged
                                        | MacPlatformError::DisplayTopologyUnstable)
                                ),
                            );
                            acknowledge_inject_result(
                                result,
                                &acknowledgement,
                                &MAC_INJECTOR_POISONED,
                                retryable_transition,
                            );
                        }
                        MacInjectorCommand::Release(acknowledgement) => {
                            let result = injector.force_release_all().map(|_| ());
                            if result.is_err() {
                                MAC_INJECTOR_POISONED.store(true, Ordering::Release);
                            }
                            if acknowledgement.send(result).is_err() {
                                MAC_INJECTOR_POISONED.store(true, Ordering::Release);
                            }
                        }
                        MacInjectorCommand::Stop(acknowledgement) => {
                            let result = injector.force_release_all().map(|_| ());
                            let release_failed = result.is_err();
                            let acknowledgement_failed = acknowledgement.send(result).is_err();
                            if release_failed || acknowledgement_failed {
                                MAC_INJECTOR_POISONED.store(true, Ordering::Release);
                            }
                            return;
                        }
                    }
                }
                if injector.force_release_all().is_err() {
                    MAC_INJECTOR_POISONED.store(true, Ordering::Release);
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
                    MAC_INJECTOR_POISONED.store(true, Ordering::Release);
                    // The constructor may still be inside native code. Never
                    // wait beyond the startup bound and never replace it.
                    drop(worker.take());
                } else {
                    let _ = finish_worker_before_deadline(
                        &mut worker,
                        &MAC_INJECTOR_POISONED,
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
            MacInjectorCommand::Inject(event, acknowledgement),
            &received,
            &MAC_INJECTOR_POISONED,
            Instant::now() + NATIVE_ACK_TIMEOUT,
        )
        .map_err(|()| PlatformPortError::Native)?
        .map_err(|error| mac_display_snapshot_error(&error))
    }

    fn force_release_all(&self) -> Result<(), PlatformPortError> {
        let (acknowledgement, received) = std_mpsc::sync_channel(1);
        submit_worker_command_before_deadline(
            &self.commands,
            MacInjectorCommand::Release(acknowledgement),
            &received,
            &MAC_INJECTOR_POISONED,
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
        let deadline = Instant::now() + NATIVE_ACK_TIMEOUT;
        let (acknowledgement, received) = std_mpsc::sync_channel(1);
        let mut command = MacInjectorCommand::Stop(acknowledgement);
        let mut submitted = false;
        loop {
            match self.commands.try_send(command) {
                Ok(()) => {
                    submitted = true;
                    break;
                }
                Err(std_mpsc::TrySendError::Disconnected(_)) => {
                    MAC_INJECTOR_POISONED.store(true, Ordering::Release);
                    break;
                }
                Err(std_mpsc::TrySendError::Full(returned)) => {
                    command = returned;
                    if Instant::now() >= deadline {
                        MAC_INJECTOR_POISONED.store(true, Ordering::Release);
                        drop(self.worker.take());
                        return;
                    }
                    thread::sleep(Duration::from_millis(1));
                }
            }
        }
        if submitted {
            let _ =
                receive_worker_stop_before_deadline(&received, &MAC_INJECTOR_POISONED, deadline);
        }
        let _ = finish_worker_before_deadline(&mut self.worker, &MAC_INJECTOR_POISONED, deadline);
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
        let input_admission = input.clone();
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
            display_monitor: None,
            injector: None,
            input_admission,
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
        self.display_monitor
            .as_ref()
            .ok_or(PlatformPortError::Native)?
            .current_snapshot()
            .map_err(|error| mac_display_snapshot_error(&error))?
            .displays()
            .iter()
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
                    rotation: display.rotation,
                })
            })
            .collect()
    }

    fn display_change_pending(&mut self) -> Result<bool, PlatformPortError> {
        self.display_monitor
            .as_ref()
            .map(MacDisplayMonitor::display_change_pending)
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
        let injector = MacInjectorWorker::start()?;
        let display_monitor = MacDisplayMonitor::start().map_err(|_| PlatformPortError::Native)?;
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
            && self.display_monitor.is_some()
            && accessibility_trusted()
        {
            Ok(())
        } else {
            Err(PlatformPortError::Native)
        }
    }
}

#[cfg(target_os = "macos")]
const fn mac_display_snapshot_error(error: &MacPlatformError) -> PlatformPortError {
    match error {
        MacPlatformError::DisplayConfigurationChanged
        | MacPlatformError::DisplayTopologyUnstable => PlatformPortError::DisplaySnapshotPending,
        _ => PlatformPortError::Native,
    }
}

#[cfg(test)]
#[derive(Clone, Debug, Default)]
pub(crate) struct VirtualPlatformPort {
    state: Arc<Mutex<VirtualPlatformState>>,
}

#[cfg(test)]
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent virtual watcher and one-shot fault controls model platform races"
)]
pub(crate) struct VirtualPlatformState {
    pub(crate) injected: Vec<InputEvent>,
    pub(crate) injection_attempts: usize,
    pub(crate) forced_releases: Vec<InputEvent>,
    pub(crate) restore_count: usize,
    pub(crate) routing_to_peer: bool,
    pub(crate) routing_transitions: Vec<bool>,
    pub(crate) display_snapshot: Option<Vec<NativeDisplaySnapshot>>,
    pub(crate) display_snapshot_attempts: usize,
    pub(crate) display_change_pending: bool,
    pub(crate) display_snapshot_pending: bool,
    pub(crate) display_revision: u64,
    pub(crate) observed_display_revision: u64,
    fail_next_pointer_injection: bool,
    fail_restore_local_ownership: bool,
}

#[cfg(test)]
impl VirtualPlatformPort {
    pub(crate) fn snapshot(&self) -> VirtualPlatformState {
        self.state.lock().expect("virtual platform lock").clone()
    }

    pub(crate) fn signal_display_change(&self, snapshot: Vec<NativeDisplaySnapshot>) {
        let mut state = self.state.lock().expect("virtual platform lock");
        state.display_snapshot = Some(snapshot);
        state.display_revision = state.display_revision.saturating_add(1);
        state.display_change_pending = false;
        state.display_snapshot_pending = false;
    }

    pub(crate) fn signal_unstable_display_change(&self) {
        let mut state = self.state.lock().expect("virtual platform lock");
        state.display_change_pending = true;
        state.display_snapshot_pending = true;
    }

    pub(crate) fn stabilize_display_change(&self, snapshot: Vec<NativeDisplaySnapshot>) {
        let mut state = self.state.lock().expect("virtual platform lock");
        state.display_snapshot = Some(snapshot);
        state.display_revision = state.display_revision.saturating_add(1);
        state.display_change_pending = false;
        state.display_snapshot_pending = false;
    }

    pub(crate) fn fail_next_pointer_injection_for_topology(&self) {
        self.state
            .lock()
            .expect("virtual platform lock")
            .fail_next_pointer_injection = true;
    }

    pub(crate) fn fail_restore_local_ownership(&self) {
        self.state
            .lock()
            .expect("virtual platform lock")
            .fail_restore_local_ownership = true;
    }
}

#[cfg(test)]
impl PlatformPort for VirtualPlatformPort {
    fn display_snapshot(&self) -> Result<Vec<NativeDisplaySnapshot>, PlatformPortError> {
        let mut state = self.state.lock().expect("virtual platform lock");
        state.display_snapshot_attempts = state.display_snapshot_attempts.saturating_add(1);
        if state.display_snapshot_pending {
            return Err(PlatformPortError::DisplaySnapshotPending);
        }
        if let Some(snapshot) = state.display_snapshot.clone() {
            state.observed_display_revision = state.display_revision;
            state.display_change_pending = false;
            return Ok(snapshot);
        }
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

    fn display_change_pending(&mut self) -> Result<bool, PlatformPortError> {
        let state = self.state.lock().expect("virtual platform lock");
        Ok(state.display_change_pending
            || state.display_snapshot_pending
            || state.display_revision != state.observed_display_revision)
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
        let mut state = self.state.lock().expect("virtual platform lock");
        state.injection_attempts = state.injection_attempts.saturating_add(1);
        if matches!(event, InputEvent::PointerMotion { .. }) && state.fail_next_pointer_injection {
            state.fail_next_pointer_injection = false;
            return Err(PlatformPortError::DisplaySnapshotPending);
        }
        state.injected.push(event);
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
        if state.fail_restore_local_ownership {
            Err(PlatformPortError::Native)
        } else {
            Ok(())
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn display(native_id: u64, pixel_width: u32) -> NativeDisplaySnapshot {
        NativeDisplaySnapshot {
            native_id: nodavo_input::DisplayId::new(native_id),
            origin_x_milli: 0,
            origin_y_milli: 0,
            pixel_width,
            pixel_height: 1_080,
            scale_x_milli: 1_000,
            scale_y_milli: 1_000,
            rotation: DisplayRotation::Degrees0,
        }
    }

    #[test]
    fn virtual_display_change_signal_is_bounded_and_latest_snapshot_wins() {
        let mut platform = VirtualPlatformPort::default();
        let observer = platform.clone();
        observer.signal_display_change(vec![display(1, 1_280)]);
        observer.signal_display_change(vec![display(2, 1_920)]);

        assert_eq!(platform.display_change_pending(), Ok(true));
        assert_eq!(platform.display_change_pending(), Ok(true));
        assert_eq!(platform.display_snapshot(), Ok(vec![display(2, 1_920)]));
        assert_eq!(platform.display_change_pending(), Ok(false));

        observer.signal_unstable_display_change();
        assert_eq!(platform.display_change_pending(), Ok(true));
        assert_eq!(platform.display_change_pending(), Ok(true));
        assert_eq!(
            platform.display_snapshot(),
            Err(PlatformPortError::DisplaySnapshotPending)
        );
        observer.signal_display_change(vec![display(3, 2_560)]);
        assert_eq!(platform.display_change_pending(), Ok(true));
        assert_eq!(platform.display_snapshot(), Ok(vec![display(3, 2_560)]));
        assert_eq!(platform.display_change_pending(), Ok(false));
    }
}

#[cfg(all(test, target_os = "macos"))]
mod mac_tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use nodavo_input::{
        DisplayId, HidUsage, KEYBOARD_PAGE, KeyState, Modifiers, NormalizedAxis, NormalizedPosition,
    };

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
        assert_eq!(
            mac_display_snapshot_error(&MacPlatformError::DisplayConfigurationChanged),
            PlatformPortError::DisplaySnapshotPending
        );
        assert_eq!(
            mac_display_snapshot_error(&MacPlatformError::DisplayTopologyUnstable),
            PlatformPortError::DisplaySnapshotPending
        );
        assert_eq!(
            mac_display_snapshot_error(&MacPlatformError::TooManyDisplays),
            PlatformPortError::Native
        );
    }

    #[test]
    fn bounded_worker_finish_joins_clean_exit_without_poison() {
        let exited = Arc::new(AtomicBool::new(false));
        let worker_exited = Arc::clone(&exited);
        let (release, released) = std_mpsc::sync_channel(1);
        let mut worker = Some(thread::spawn(move || {
            let _ = released.recv();
            worker_exited.store(true, Ordering::Release);
        }));
        release.send(()).unwrap();
        let poison = AtomicBool::new(false);

        assert!(finish_worker_before_deadline(
            &mut worker,
            &poison,
            Instant::now() + Duration::from_secs(1),
        ));

        assert!(worker.is_none());
        assert!(exited.load(Ordering::Acquire));
        assert!(!poison.load(Ordering::Acquire));
    }

    #[test]
    fn bounded_worker_finish_poisons_before_detaching_a_stuck_worker() {
        let (release, released) = std_mpsc::sync_channel(1);
        let mut worker = Some(thread::spawn(move || {
            let _ = released.recv();
        }));
        let poison = AtomicBool::new(false);

        assert!(!finish_worker_before_deadline(
            &mut worker,
            &poison,
            Instant::now() + Duration::from_millis(10),
        ));
        assert!(worker.is_none());
        assert!(poison.load(Ordering::Acquire));

        // Let the deliberately detached test worker exit; production never
        // clears poison and therefore can never overlap it with a replacement.
        release.send(()).unwrap();
    }

    #[test]
    fn stuck_inject_poisons_and_makes_recovery_submission_nonblocking() {
        enum FakeCommand {
            Inject(std_mpsc::SyncSender<()>),
            Release(std_mpsc::SyncSender<()>),
        }

        let (commands, received_commands) = std_mpsc::sync_channel(1);
        let (unblock, blocked) = std_mpsc::sync_channel(1);
        let worker = thread::spawn(move || {
            while let Ok(command) = received_commands.recv() {
                match command {
                    FakeCommand::Inject(acknowledgement) => {
                        let _ = blocked.recv();
                        let _ = acknowledgement.send(());
                    }
                    FakeCommand::Release(acknowledgement) => {
                        let _ = acknowledgement.send(());
                    }
                }
            }
        });
        let poison = AtomicBool::new(false);
        let (acknowledgement, received) = std_mpsc::sync_channel(1);
        let started = Instant::now();

        assert!(
            submit_worker_command_before_deadline(
                &commands,
                FakeCommand::Inject(acknowledgement),
                &received,
                &poison,
                started + Duration::from_millis(10),
            )
            .is_err()
        );
        assert!(poison.load(Ordering::Acquire));
        assert!(started.elapsed() < Duration::from_secs(1));

        let (release_acknowledgement, release_received) = std_mpsc::sync_channel(1);
        let recovery_started = Instant::now();
        assert!(
            submit_worker_command_before_deadline(
                &commands,
                FakeCommand::Release(release_acknowledgement),
                &release_received,
                &poison,
                recovery_started + Duration::from_secs(1),
            )
            .is_err()
        );
        assert!(recovery_started.elapsed() < Duration::from_millis(50));

        unblock.send(()).unwrap();
        drop(commands);
        worker.join().unwrap();
    }

    #[test]
    fn disconnected_worker_command_poisons_before_returning() {
        let (commands, received_commands) = std_mpsc::sync_channel::<()>(1);
        drop(received_commands);
        let (_acknowledgement, received) = std_mpsc::sync_channel::<()>(1);
        let poison = AtomicBool::new(false);

        assert!(
            submit_worker_command_before_deadline(
                &commands,
                (),
                &received,
                &poison,
                Instant::now() + Duration::from_secs(1),
            )
            .is_err()
        );
        assert!(poison.load(Ordering::Acquire));
    }

    #[test]
    fn missing_or_failed_stop_ack_and_worker_panic_poison_replacement() {
        let (failed, failed_result) = std_mpsc::sync_channel(1);
        failed.send(Err::<(), ()>(())).unwrap();
        let failed_poison = AtomicBool::new(false);
        assert!(!receive_worker_stop_before_deadline(
            &failed_result,
            &failed_poison,
            Instant::now() + Duration::from_secs(1),
        ));
        assert!(failed_poison.load(Ordering::Acquire));

        let (missing, missing_result) = std_mpsc::sync_channel::<Result<(), ()>>(1);
        let held_sender = thread::spawn(move || {
            thread::sleep(Duration::from_millis(20));
            drop(missing);
        });
        let missing_poison = AtomicBool::new(false);
        assert!(!receive_worker_stop_before_deadline(
            &missing_result,
            &missing_poison,
            Instant::now() + Duration::from_millis(10),
        ));
        assert!(missing_poison.load(Ordering::Acquire));
        held_sender.join().unwrap();

        let mut panicked = Some(thread::spawn(|| panic!("deterministic worker panic")));
        let panic_poison = AtomicBool::new(false);
        assert!(!finish_worker_before_deadline(
            &mut panicked,
            &panic_poison,
            Instant::now() + Duration::from_secs(1),
        ));
        assert!(panic_poison.load(Ordering::Acquire));
    }

    #[test]
    fn fatal_inject_ack_is_poisoned_before_observation_but_pointer_transition_retries() {
        #[derive(Debug, Eq, PartialEq)]
        enum FakeInjectError {
            Fatal,
            TopologyTransition,
        }

        let fatal_poison = Arc::new(AtomicBool::new(false));
        let observed_poison = Arc::clone(&fatal_poison);
        let (fatal_acknowledgement, fatal_received) = std_mpsc::sync_channel(1);
        let fatal_observer = thread::spawn(move || {
            assert_eq!(fatal_received.recv(), Ok(Err(FakeInjectError::Fatal)));
            assert!(!injector_worker_start_allowed(observed_poison.as_ref()));
        });
        acknowledge_inject_result(
            Err(FakeInjectError::Fatal),
            &fatal_acknowledgement,
            fatal_poison.as_ref(),
            false,
        );
        fatal_observer.join().unwrap();

        let pointer = InputEvent::PointerMotion {
            position: NormalizedPosition::new(
                DisplayId::new(1),
                NormalizedAxis::MIN,
                NormalizedAxis::MAX,
            ),
        };
        let transition_poison = AtomicBool::new(false);
        let (transition_acknowledgement, transition_received) = std_mpsc::sync_channel(1);
        acknowledge_inject_result(
            Err(FakeInjectError::TopologyTransition),
            &transition_acknowledgement,
            &transition_poison,
            absolute_pointer_transition_is_retryable(pointer, true),
        );
        assert_eq!(
            transition_received.recv(),
            Ok(Err(FakeInjectError::TopologyTransition))
        );
        assert!(injector_worker_start_allowed(&transition_poison));

        let key = InputEvent::Key {
            usage: HidUsage::new(KEYBOARD_PAGE, 4),
            state: KeyState::Pressed,
            modifiers: Modifiers::empty(),
        };
        assert!(!absolute_pointer_transition_is_retryable(key, true));
    }
}
