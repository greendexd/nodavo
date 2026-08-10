use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread::{self, JoinHandle};

use core_graphics::display::CGDisplay;
use core_graphics::event::{
    CGEvent, CGEventFlags, CGEventTapLocation, CGEventType, CGMouseButton, EventField, KeyCode,
    ScrollEventUnit,
};
use core_graphics::event_source::{CGEventSource, CGEventSourceStateID};
use core_graphics::geometry::CGPoint;
use macos_accessibility_client::accessibility::{
    application_is_trusted, application_is_trusted_with_prompt,
};
use nodavo_input::{
    ButtonState, CONSUMER_PAGE, DisplayId, HidUsage, InputEvent, KEYBOARD_PAGE, KeyState,
    Modifiers, NormalizedAxis, NormalizedPosition, PointerButton, PointerDelta, PressedState,
    ScrollUnit,
};

use super::{DisplayGeometry, MacPlatformError, MacReadinessProbe, NODAVO_SYNTHETIC_EVENT_TAG};

#[path = "macos/ffi.rs"]
mod ffi;
#[path = "macos/ipc_auth.rs"]
mod ipc_auth;
#[path = "macos/xpc_ipc.rs"]
mod xpc_ipc;

pub use ipc_auth::{MacIpcAuthError, MacIpcPeerGuard};
pub use xpc_ipc::{
    MAX_XPC_GLOBAL_OUTSTANDING, MAX_XPC_MESSAGE_BYTES, MAX_XPC_PEER_OUTSTANDING, MAX_XPC_PEERS,
    MacLocalIpcAuthMode, MacXpcError, MacXpcEvent, MacXpcListener, MacXpcPeerIdentity, MacXpcReply,
    MacXpcRequest, NODAVO_AGENT_MACH_SERVICE, XPC_REPLY_DEADLINE_MILLISECONDS, local_ipc_auth_mode,
    mac_xpc_peer_requirement,
};

#[cfg(test)]
pub(crate) use ffi::clipboard_release_named;
pub(crate) use ffi::{
    clipboard_change_count, clipboard_clear, clipboard_snapshot, clipboard_write, keychain_delete,
    keychain_load, keychain_store,
};

#[must_use]
pub fn accessibility_trusted() -> bool {
    application_is_trusted()
}

#[must_use]
pub fn request_accessibility() -> bool {
    application_is_trusted_with_prompt()
}

/// Returns geometry for every active display.
///
/// # Errors
///
/// Returns [`MacPlatformError::CoreGraphics`] when display enumeration fails,
/// or [`MacPlatformError::InvalidNativeEvent`] for invalid native geometry.
pub fn active_displays() -> Result<Vec<DisplayGeometry>, MacPlatformError> {
    CGDisplay::active_displays()
        .map_err(|_| MacPlatformError::CoreGraphics)?
        .into_iter()
        .map(|id| {
            let display = CGDisplay::new(id);
            let bounds = display.bounds();
            if bounds.size.width <= 0.0 || bounds.size.height <= 0.0 {
                return Err(MacPlatformError::InvalidNativeEvent);
            }
            Ok(DisplayGeometry {
                id: DisplayId::new(u64::from(id)),
                origin_x: bounds.origin.x,
                origin_y: bounds.origin.y,
                width_points: bounds.size.width,
                height_points: bounds.size.height,
                width_pixels: display.pixels_wide(),
                height_pixels: display.pixels_high(),
            })
        })
        .collect()
}

/// Probes current-user prerequisites without registering capture, routing,
/// suppressing or injecting input, and without showing a permission prompt.
#[must_use]
pub fn probe_readiness() -> MacReadinessProbe {
    let initially_trusted = accessibility_trusted();
    let local_topology_available = active_displays().is_ok_and(|displays| !displays.is_empty());
    // Construction creates an event source and validates displays but never
    // posts an event or installs a process-wide event tap.
    let input_prerequisites_available = initially_trusted && MacInputInjector::new().is_ok();
    // Permission may be revoked while prerequisites are checked. The final
    // observation is authoritative so a missing permission never leaks through
    // as a generic input failure.
    let accessibility_trusted = accessibility_trusted();
    MacReadinessProbe {
        accessibility_trusted,
        input_prerequisites_available,
        local_topology_available,
    }
}

pub struct MacInputInjector {
    source: CGEventSource,
    displays: Vec<DisplayGeometry>,
    pressed: PressedState,
}

impl MacInputInjector {
    /// Creates an injector for the current user session.
    ///
    /// # Errors
    ///
    /// Returns an error when Accessibility permission is absent, the event
    /// source cannot be created, or active displays cannot be enumerated.
    pub fn new() -> Result<Self, MacPlatformError> {
        if !accessibility_trusted() {
            return Err(MacPlatformError::AccessibilityDenied);
        }
        Ok(Self {
            source: CGEventSource::new(CGEventSourceStateID::Private)
                .map_err(|()| MacPlatformError::CoreGraphics)?,
            displays: active_displays()?,
            pressed: PressedState::default(),
        })
    }

    /// Refreshes the cached active-display geometry.
    ///
    /// # Errors
    ///
    /// Returns an error when CoreGraphics cannot enumerate valid displays.
    pub fn refresh_displays(&mut self) -> Result<(), MacPlatformError> {
        self.displays = active_displays()?;
        Ok(())
    }

    /// Injects one semantic input event into the current session.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported keys, unknown displays, or a rejected
    /// CoreGraphics event operation.
    pub fn inject(&mut self, input: InputEvent) -> Result<(), MacPlatformError> {
        if !accessibility_trusted() {
            return Err(MacPlatformError::AccessibilityDenied);
        }
        self.send_event(input)?;
        self.pressed.apply(&input);
        Ok(())
    }

    /// Releases all tracked keys and buttons before acknowledging completion.
    ///
    /// Releases use the deterministic order defined by
    /// [`PressedState::take_forced_releases`]. A failed release remains tracked
    /// so the caller may retry after Accessibility or session recovery.
    ///
    /// # Errors
    ///
    /// Returns [`MacPlatformError::ReleaseIncomplete`] when one or more native
    /// release events could not be posted synchronously.
    pub fn force_release_all(&mut self) -> Result<ForceReleaseAcknowledgement, MacPlatformError> {
        if !accessibility_trusted() {
            return Err(MacPlatformError::AccessibilityDenied);
        }
        let releases = self.pressed.take_forced_releases();
        let mut failed = PressedState::default();
        let mut released_keys = 0_usize;
        let mut released_buttons = 0_usize;
        for release in releases {
            if self.send_event(release).is_err() {
                failed.apply(&pressed_equivalent(release));
            } else {
                match release {
                    InputEvent::Key { .. } => released_keys += 1,
                    InputEvent::PointerButton { .. } => released_buttons += 1,
                    InputEvent::PointerMotion { .. }
                    | InputEvent::PointerDelta { .. }
                    | InputEvent::Scroll { .. } => {}
                }
            }
        }
        self.pressed = failed;
        if self.pressed.is_empty() {
            Ok(ForceReleaseAcknowledgement {
                released_keys,
                released_buttons,
            })
        } else {
            Err(MacPlatformError::ReleaseIncomplete)
        }
    }

    #[must_use]
    pub fn pressed_input_is_clear(&self) -> bool {
        self.pressed.is_empty()
    }

    #[must_use]
    pub fn displays(&self) -> &[DisplayGeometry] {
        &self.displays
    }

    fn send_event(&self, input: InputEvent) -> Result<(), MacPlatformError> {
        match input {
            InputEvent::Key {
                usage,
                state,
                modifiers,
            } => self.inject_key(usage, state, modifiers),
            InputEvent::PointerMotion { position } => self.inject_motion(position),
            InputEvent::PointerDelta { delta } => self.inject_delta(delta),
            InputEvent::PointerButton { button, state } => self.inject_button(button, state),
            InputEvent::Scroll {
                horizontal,
                vertical,
                unit,
            } => self.inject_scroll(horizontal, vertical, unit),
        }
    }

    fn inject_key(
        &self,
        usage: HidUsage,
        state: KeyState,
        modifiers: Modifiers,
    ) -> Result<(), MacPlatformError> {
        if usage.page() == CONSUMER_PAGE {
            return ffi::post_media_key(
                usage.id(),
                state == KeyState::Pressed,
                NODAVO_SYNTHETIC_EVENT_TAG,
            )
            .map_err(|()| MacPlatformError::UnsupportedKey);
        }
        let keycode = hid_to_keycode(usage).ok_or(MacPlatformError::UnsupportedKey)?;
        let event =
            CGEvent::new_keyboard_event(self.source.clone(), keycode, state == KeyState::Pressed)
                .map_err(|()| MacPlatformError::CoreGraphics)?;
        event.set_flags(modifiers_to_flags(modifiers));
        post_tagged(&event);
        Ok(())
    }

    fn inject_motion(&self, position: NormalizedPosition) -> Result<(), MacPlatformError> {
        let display = self
            .displays
            .iter()
            .find(|display| display.id == position.display())
            .ok_or(MacPlatformError::UnknownDisplay)?;
        let point = CGPoint::new(
            display.origin_x + position.x().to_unit_f64() * display.width_points,
            display.origin_y + position.y().to_unit_f64() * display.height_points,
        );
        let event = CGEvent::new_mouse_event(
            self.source.clone(),
            CGEventType::MouseMoved,
            point,
            CGMouseButton::Left,
        )
        .map_err(|()| MacPlatformError::CoreGraphics)?;
        post_tagged(&event);
        Ok(())
    }

    fn inject_delta(&self, delta: PointerDelta) -> Result<(), MacPlatformError> {
        let current = CGEvent::new(self.source.clone())
            .map_err(|()| MacPlatformError::CoreGraphics)?
            .location();
        let point = CGPoint::new(
            current.x + f64::from(delta.horizontal()),
            current.y + f64::from(delta.vertical()),
        );
        let event = CGEvent::new_mouse_event(
            self.source.clone(),
            CGEventType::MouseMoved,
            point,
            CGMouseButton::Left,
        )
        .map_err(|()| MacPlatformError::CoreGraphics)?;
        post_tagged(&event);
        Ok(())
    }

    fn inject_button(
        &self,
        button: PointerButton,
        state: ButtonState,
    ) -> Result<(), MacPlatformError> {
        let current = CGEvent::new(self.source.clone())
            .map_err(|()| MacPlatformError::CoreGraphics)?
            .location();
        let number = button.get();
        let (event_type, mouse_button) = match (number, state) {
            (1, ButtonState::Pressed) => (CGEventType::LeftMouseDown, CGMouseButton::Left),
            (1, ButtonState::Released) => (CGEventType::LeftMouseUp, CGMouseButton::Left),
            (2, ButtonState::Pressed) => (CGEventType::RightMouseDown, CGMouseButton::Right),
            (2, ButtonState::Released) => (CGEventType::RightMouseUp, CGMouseButton::Right),
            (_, ButtonState::Pressed) => (CGEventType::OtherMouseDown, CGMouseButton::Center),
            (_, ButtonState::Released) => (CGEventType::OtherMouseUp, CGMouseButton::Center),
        };
        let event =
            CGEvent::new_mouse_event(self.source.clone(), event_type, current, mouse_button)
                .map_err(|()| MacPlatformError::CoreGraphics)?;
        event.set_integer_value_field(EventField::MOUSE_EVENT_BUTTON_NUMBER, i64::from(number - 1));
        post_tagged(&event);
        Ok(())
    }

    fn inject_scroll(
        &self,
        horizontal: i32,
        vertical: i32,
        unit: ScrollUnit,
    ) -> Result<(), MacPlatformError> {
        let units = match unit {
            ScrollUnit::Lines => ScrollEventUnit::LINE,
            ScrollUnit::Precise => ScrollEventUnit::PIXEL,
        };
        let event =
            CGEvent::new_scroll_event(self.source.clone(), units, 2, vertical, horizontal, 0)
                .map_err(|()| MacPlatformError::CoreGraphics)?;
        post_tagged(&event);
        Ok(())
    }
}

fn post_tagged(event: &CGEvent) {
    event.set_integer_value_field(
        EventField::EVENT_SOURCE_USER_DATA,
        NODAVO_SYNTHETIC_EVENT_TAG,
    );
    event.post(CGEventTapLocation::Session);
}

/// Synchronous confirmation that every tracked release was posted.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ForceReleaseAcknowledgement {
    pub released_keys: usize,
    pub released_buttons: usize,
}

fn pressed_equivalent(release: InputEvent) -> InputEvent {
    match release {
        InputEvent::Key {
            usage, modifiers, ..
        } => InputEvent::Key {
            usage,
            state: KeyState::Pressed,
            modifiers,
        },
        InputEvent::PointerButton { button, .. } => InputEvent::PointerButton {
            button,
            state: ButtonState::Pressed,
        },
        InputEvent::PointerMotion { .. }
        | InputEvent::PointerDelta { .. }
        | InputEvent::Scroll { .. } => release,
    }
}

/// Observable lifecycle conditions for the current macOS input session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacInputLifecycleEvent {
    CaptureStarted,
    CaptureStopped,
    SystemWillSleep,
    SystemDidWake,
    ScreensDidSleep,
    ScreensDidWake,
    SessionDidResignActive,
    SessionDidBecomeActive,
    TapDisabledByTimeout,
    TapDisabledByUserInput,
}

/// A semantic input event or a lifecycle condition from the capture runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacInputCaptureEvent {
    Input(InputEvent),
    Lifecycle(MacInputLifecycleEvent),
}

type CaptureCallback =
    dyn Fn(MacInputCaptureEvent) -> Result<(), MacPlatformError> + Send + Sync + 'static;

struct CaptureRuntime {
    stop: ffi::NativeInputCaptureStopHandle,
    worker: JoinHandle<Result<(), MacPlatformError>>,
}

/// Owned, restartable current-session `CGEventTap` runtime.
///
/// Input suppression is disabled by default. It becomes active only after
/// [`Self::set_routing_to_peer`] is explicitly set to `true`, and it is always
/// cleared before stop, sleep/session-inactive notifications, tap disablement,
/// or callback failure.
pub struct MacInputCapture {
    callback: Arc<CaptureCallback>,
    routing_to_peer: Arc<AtomicBool>,
    delivery: CaptureDelivery,
    runtime: Option<CaptureRuntime>,
}

#[derive(Clone, Copy)]
enum CaptureDelivery {
    AllAbsolute,
    RoutedRelative,
    LocalAbsolutePointerAndRoutedRelative,
}

impl fmt::Debug for MacInputCapture {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacInputCapture")
            .field("running", &self.is_running())
            .field("routing_to_peer", &self.routing_to_peer())
            .finish_non_exhaustive()
    }
}

impl MacInputCapture {
    #[must_use]
    pub fn new(callback: impl Fn(MacInputCaptureEvent) + Send + Sync + 'static) -> Self {
        Self::new_fallible(move |event| {
            callback(event);
            Ok(())
        })
    }

    /// Creates a capture whose callback may fail closed.
    ///
    /// A callback error synchronously disables routing and terminates the
    /// event tap. This is intended for bounded callback-to-runtime bridges
    /// which must not silently lose reliable physical events.
    #[must_use]
    pub fn new_fallible(
        callback: impl Fn(MacInputCaptureEvent) -> Result<(), MacPlatformError> + Send + Sync + 'static,
    ) -> Self {
        Self::with_callback(callback, CaptureDelivery::AllAbsolute)
    }

    /// Creates a fail-closed callback which receives physical input only while
    /// routing is enabled. Lifecycle events are always delivered.
    #[must_use]
    pub fn new_routed_fallible(
        callback: impl Fn(MacInputCaptureEvent) -> Result<(), MacPlatformError> + Send + Sync + 'static,
    ) -> Self {
        Self::with_callback(callback, CaptureDelivery::RoutedRelative)
    }

    /// Creates a fail-closed capture which emits absolute pointer positions
    /// without suppression while focus is local, then all physical input with
    /// relative pointer deltas while authenticated routing is active.
    #[must_use]
    pub fn new_edge_routed_fallible(
        callback: impl Fn(MacInputCaptureEvent) -> Result<(), MacPlatformError> + Send + Sync + 'static,
    ) -> Self {
        Self::with_callback(
            callback,
            CaptureDelivery::LocalAbsolutePointerAndRoutedRelative,
        )
    }

    fn with_callback(
        callback: impl Fn(MacInputCaptureEvent) -> Result<(), MacPlatformError> + Send + Sync + 'static,
        delivery: CaptureDelivery,
    ) -> Self {
        Self {
            callback: Arc::new(callback),
            routing_to_peer: Arc::new(AtomicBool::new(false)),
            delivery,
            runtime: None,
        }
    }

    /// Starts a fresh tap on a dedicated run-loop thread.
    ///
    /// # Errors
    ///
    /// Fails closed when Accessibility is absent, display discovery fails, a
    /// tap cannot be installed/enabled, or this handle already owns a runtime.
    #[allow(clippy::too_many_lines)]
    pub fn start(&mut self) -> Result<(), MacPlatformError> {
        if self.runtime.is_some() {
            return Err(MacPlatformError::CaptureAlreadyRunning);
        }
        if !accessibility_trusted() {
            return Err(MacPlatformError::AccessibilityDenied);
        }
        let displays = active_displays()?;
        let callback = Arc::clone(&self.callback);
        let routing_to_peer = Arc::clone(&self.routing_to_peer);
        let delivery = self.delivery;
        routing_to_peer.store(false, Ordering::Release);
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("nodavo-macos-input".into())
            .spawn(move || {
                let event_callback = Arc::clone(&callback);
                let event_routing = Arc::clone(&routing_to_peer);
                let Ok(capture) = ffi::NativeInputCapture::new(move |native| match native {
                    ffi::NativeInputEvent::Lifecycle(native) => {
                        let lifecycle = lifecycle_event(native);
                        if lifecycle_requires_local_recovery(lifecycle) {
                            event_routing.store(false, Ordering::Release);
                        }
                        if event_callback(MacInputCaptureEvent::Lifecycle(lifecycle)).is_err() {
                            event_routing.store(false, Ordering::Release);
                            ffi::NativeCaptureDisposition::Abort
                        } else {
                            ffi::NativeCaptureDisposition::Keep
                        }
                    }
                    native => {
                        let routing = event_routing.load(Ordering::Acquire);
                        let deliver = match delivery {
                            CaptureDelivery::AllAbsolute => true,
                            CaptureDelivery::RoutedRelative => routing,
                            CaptureDelivery::LocalAbsolutePointerAndRoutedRelative => {
                                routing
                                    || matches!(native, ffi::NativeInputEvent::PointerMotion { .. })
                            }
                        };
                        if !deliver {
                            return ffi::NativeCaptureDisposition::Keep;
                        }
                        let relative_pointer =
                            routing && !matches!(delivery, CaptureDelivery::AllAbsolute);
                        if relative_pointer
                            && let ffi::NativeInputEvent::PointerMotion {
                                delta_x, delta_y, ..
                            } = native
                        {
                            if delta_x == 0 && delta_y == 0 {
                                return ffi::NativeCaptureDisposition::Suppress;
                            }
                            if PointerDelta::new(delta_x, delta_y).is_err() {
                                event_routing.store(false, Ordering::Release);
                                return ffi::NativeCaptureDisposition::Abort;
                            }
                        }
                        let Some(input) = convert_native_input(native, &displays, relative_pointer)
                        else {
                            return ffi::NativeCaptureDisposition::Keep;
                        };
                        if event_callback(MacInputCaptureEvent::Input(input)).is_err() {
                            event_routing.store(false, Ordering::Release);
                            ffi::NativeCaptureDisposition::Abort
                        } else if event_routing.load(Ordering::Acquire) {
                            ffi::NativeCaptureDisposition::Suppress
                        } else {
                            ffi::NativeCaptureDisposition::Keep
                        }
                    }
                }) else {
                    let error = if accessibility_trusted() {
                        MacPlatformError::EventTapUnavailable
                    } else {
                        MacPlatformError::AccessibilityDenied
                    };
                    let _ = ready_tx.send(Err(error.clone()));
                    return Err(error);
                };
                let stop = capture
                    .stop_handle()
                    .map_err(|()| MacPlatformError::EventTapUnavailable)?;
                if let Err(error) =
                    emit_callback(callback.as_ref(), MacInputLifecycleEvent::CaptureStarted)
                {
                    let _ = ready_tx.send(Err(error.clone()));
                    return Err(error);
                }
                if ready_tx.send(Ok(stop)).is_err() {
                    return Err(MacPlatformError::CaptureThread);
                }
                let result = match capture.run() {
                    ffi::NativeCaptureExit::StopRequested => Ok(()),
                    ffi::NativeCaptureExit::TapDisabledByTimeout => {
                        Err(MacPlatformError::EventTapTimedOut)
                    }
                    ffi::NativeCaptureExit::TapDisabledByUserInput => {
                        Err(MacPlatformError::EventTapDisabled)
                    }
                    ffi::NativeCaptureExit::CallbackFailed => {
                        Err(MacPlatformError::CaptureCallbackFailed)
                    }
                    ffi::NativeCaptureExit::NativeFailure => {
                        Err(MacPlatformError::EventTapUnavailable)
                    }
                };
                routing_to_peer.store(false, Ordering::Release);
                if result.is_ok() {
                    emit_callback(callback.as_ref(), MacInputLifecycleEvent::CaptureStopped)?;
                }
                result
            })
            .map_err(|_| MacPlatformError::CaptureThread)?;

        match ready_rx.recv() {
            Ok(Ok(stop)) => {
                self.runtime = Some(CaptureRuntime { stop, worker });
                Ok(())
            }
            Ok(Err(error)) => {
                let _ = worker.join();
                Err(error)
            }
            Err(_) => {
                let _ = worker.join();
                Err(MacPlatformError::CaptureThread)
            }
        }
    }

    /// Enables or disables suppression for successfully decoded local input.
    ///
    /// # Errors
    ///
    /// Refuses to enable routing without a live tap or current Accessibility.
    pub fn set_routing_to_peer(&self, enabled: bool) -> Result<(), MacPlatformError> {
        if enabled {
            if !self.is_running() {
                return Err(MacPlatformError::CaptureNotRunning);
            }
            if !accessibility_trusted() {
                return Err(MacPlatformError::AccessibilityDenied);
            }
        }
        self.routing_to_peer.store(enabled, Ordering::Release);
        Ok(())
    }

    #[must_use]
    pub fn routing_to_peer(&self) -> bool {
        self.routing_to_peer.load(Ordering::Acquire)
    }

    #[must_use]
    pub fn is_running(&self) -> bool {
        self.runtime
            .as_ref()
            .is_some_and(|runtime| !runtime.worker.is_finished())
    }

    /// Stops the native run loop and waits for its terminal acknowledgement.
    ///
    /// # Errors
    ///
    /// Returns the terminal tap/callback failure if the runtime had already
    /// failed, or a thread error if the worker panicked.
    pub fn stop(&mut self) -> Result<(), MacPlatformError> {
        self.routing_to_peer.store(false, Ordering::Release);
        let Some(runtime) = self.runtime.take() else {
            return Ok(());
        };
        runtime.stop.stop();
        runtime
            .worker
            .join()
            .map_err(|_| MacPlatformError::CaptureThread)?
    }

    /// Stops any owned runtime and installs a fresh event tap.
    ///
    /// A prior terminal tap error does not prevent a restart, but the new start
    /// still performs fresh Accessibility and native enablement checks.
    ///
    /// # Errors
    ///
    /// Returns a non-recoverable stop failure or any fresh startup failure.
    pub fn restart(&mut self) -> Result<(), MacPlatformError> {
        if let Err(error) = self.stop()
            && !matches!(
                error,
                MacPlatformError::EventTapTimedOut
                    | MacPlatformError::EventTapDisabled
                    | MacPlatformError::CaptureCallbackFailed
            )
        {
            return Err(error);
        }
        self.start()
    }

    /// Waits for a naturally terminating runtime without requesting stop.
    ///
    /// # Errors
    ///
    /// Returns [`MacPlatformError::CaptureNotRunning`] when no runtime is
    /// owned, or the tap's terminal failure reason.
    pub fn wait(&mut self) -> Result<(), MacPlatformError> {
        let Some(runtime) = self.runtime.take() else {
            return Err(MacPlatformError::CaptureNotRunning);
        };
        runtime
            .worker
            .join()
            .map_err(|_| MacPlatformError::CaptureThread)?
    }
}

impl Drop for MacInputCapture {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

/// Runs non-suppressing input capture until the tap terminates.
///
/// Prefer [`MacInputCapture`] when the caller needs stop/restart or explicitly
/// controlled peer routing.
///
/// # Errors
///
/// Returns an error for Accessibility, tap startup, timeout, or callback
/// failures.
pub fn run_input_capture(
    on_input: impl Fn(InputEvent) + Send + Sync + 'static,
) -> Result<(), MacPlatformError> {
    let mut capture = MacInputCapture::new(move |event| {
        if let MacInputCaptureEvent::Input(input) = event {
            on_input(input);
        }
    });
    capture.start()?;
    capture.wait()
}

fn emit_callback(
    callback: &CaptureCallback,
    lifecycle: MacInputLifecycleEvent,
) -> Result<(), MacPlatformError> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        callback(MacInputCaptureEvent::Lifecycle(lifecycle))
    }))
    .map_err(|_| MacPlatformError::CaptureCallbackFailed)?
}

fn lifecycle_event(native: ffi::NativeLifecycleEvent) -> MacInputLifecycleEvent {
    match native {
        ffi::NativeLifecycleEvent::SystemWillSleep => MacInputLifecycleEvent::SystemWillSleep,
        ffi::NativeLifecycleEvent::SystemDidWake => MacInputLifecycleEvent::SystemDidWake,
        ffi::NativeLifecycleEvent::ScreensDidSleep => MacInputLifecycleEvent::ScreensDidSleep,
        ffi::NativeLifecycleEvent::ScreensDidWake => MacInputLifecycleEvent::ScreensDidWake,
        ffi::NativeLifecycleEvent::SessionDidResignActive => {
            MacInputLifecycleEvent::SessionDidResignActive
        }
        ffi::NativeLifecycleEvent::SessionDidBecomeActive => {
            MacInputLifecycleEvent::SessionDidBecomeActive
        }
        ffi::NativeLifecycleEvent::TapDisabledByTimeout => {
            MacInputLifecycleEvent::TapDisabledByTimeout
        }
        ffi::NativeLifecycleEvent::TapDisabledByUserInput => {
            MacInputLifecycleEvent::TapDisabledByUserInput
        }
    }
}

fn lifecycle_requires_local_recovery(event: MacInputLifecycleEvent) -> bool {
    matches!(
        event,
        MacInputLifecycleEvent::SystemWillSleep
            | MacInputLifecycleEvent::ScreensDidSleep
            | MacInputLifecycleEvent::SessionDidResignActive
            | MacInputLifecycleEvent::TapDisabledByTimeout
            | MacInputLifecycleEvent::TapDisabledByUserInput
    )
}

fn convert_native_input(
    native: ffi::NativeInputEvent,
    displays: &[DisplayGeometry],
    relative_pointer: bool,
) -> Option<InputEvent> {
    match native {
        ffi::NativeInputEvent::Keyboard {
            keycode,
            pressed,
            modifier_bits,
        } => Some(InputEvent::Key {
            usage: keycode_to_hid(keycode)?,
            state: key_state(pressed),
            modifiers: Modifiers::from_bits(modifier_bits)?,
        }),
        ffi::NativeInputEvent::Consumer {
            usage,
            pressed,
            modifier_bits,
        } => Some(InputEvent::Key {
            usage: HidUsage::new(CONSUMER_PAGE, usage),
            state: key_state(pressed),
            modifiers: Modifiers::from_bits(modifier_bits)?,
        }),
        ffi::NativeInputEvent::PointerMotion {
            x: _,
            y: _,
            delta_x,
            delta_y,
        } if relative_pointer => Some(InputEvent::PointerDelta {
            delta: PointerDelta::new(delta_x, delta_y).ok()?,
        }),
        ffi::NativeInputEvent::PointerMotion { x, y, .. } => Some(InputEvent::PointerMotion {
            position: normalize_position(CGPoint::new(x, y), displays)?,
        }),
        ffi::NativeInputEvent::PointerButton { button, pressed } => {
            Some(InputEvent::PointerButton {
                button: PointerButton::new(button).ok()?,
                state: if pressed {
                    ButtonState::Pressed
                } else {
                    ButtonState::Released
                },
            })
        }
        ffi::NativeInputEvent::Scroll {
            horizontal,
            vertical,
            precise,
        } => Some(InputEvent::Scroll {
            horizontal,
            vertical,
            unit: if precise {
                ScrollUnit::Precise
            } else {
                ScrollUnit::Lines
            },
        }),
        ffi::NativeInputEvent::Lifecycle(_) => None,
    }
}

const fn key_state(pressed: bool) -> KeyState {
    if pressed {
        KeyState::Pressed
    } else {
        KeyState::Released
    }
}

fn normalize_position(point: CGPoint, displays: &[DisplayGeometry]) -> Option<NormalizedPosition> {
    let display = displays.iter().find(|display| {
        point.x >= display.origin_x
            && point.x <= display.origin_x + display.width_points
            && point.y >= display.origin_y
            && point.y <= display.origin_y + display.height_points
    })?;
    let x = (point.x - display.origin_x) / display.width_points;
    let y = (point.y - display.origin_y) / display.height_points;
    Some(NormalizedPosition::new(
        display.id,
        NormalizedAxis::from_unit_f64(x).ok()?,
        NormalizedAxis::from_unit_f64(y).ok()?,
    ))
}

fn modifiers_to_flags(modifiers: Modifiers) -> CGEventFlags {
    let mut flags = CGEventFlags::empty();
    if modifiers.intersects(Modifiers::LEFT_SHIFT | Modifiers::RIGHT_SHIFT) {
        flags |= CGEventFlags::CGEventFlagShift;
    }
    if modifiers.intersects(Modifiers::LEFT_CONTROL | Modifiers::RIGHT_CONTROL) {
        flags |= CGEventFlags::CGEventFlagControl;
    }
    if modifiers.intersects(Modifiers::LEFT_ALT | Modifiers::RIGHT_ALT | Modifiers::ALT_GRAPH) {
        flags |= CGEventFlags::CGEventFlagAlternate;
    }
    if modifiers.intersects(Modifiers::LEFT_META | Modifiers::RIGHT_META) {
        flags |= CGEventFlags::CGEventFlagCommand;
    }
    if modifiers.contains(Modifiers::CAPS_LOCK) {
        flags |= CGEventFlags::CGEventFlagAlphaShift;
    }
    flags
}

#[allow(clippy::too_many_lines)]
fn hid_to_keycode(usage: HidUsage) -> Option<u16> {
    if usage.page() != KEYBOARD_PAGE {
        return None;
    }
    Some(match usage.id() {
        0x04 => KeyCode::ANSI_A,
        0x05 => KeyCode::ANSI_B,
        0x06 => KeyCode::ANSI_C,
        0x07 => KeyCode::ANSI_D,
        0x08 => KeyCode::ANSI_E,
        0x09 => KeyCode::ANSI_F,
        0x0A => KeyCode::ANSI_G,
        0x0B => KeyCode::ANSI_H,
        0x0C => KeyCode::ANSI_I,
        0x0D => KeyCode::ANSI_J,
        0x0E => KeyCode::ANSI_K,
        0x0F => KeyCode::ANSI_L,
        0x10 => KeyCode::ANSI_M,
        0x11 => KeyCode::ANSI_N,
        0x12 => KeyCode::ANSI_O,
        0x13 => KeyCode::ANSI_P,
        0x14 => KeyCode::ANSI_Q,
        0x15 => KeyCode::ANSI_R,
        0x16 => KeyCode::ANSI_S,
        0x17 => KeyCode::ANSI_T,
        0x18 => KeyCode::ANSI_U,
        0x19 => KeyCode::ANSI_V,
        0x1A => KeyCode::ANSI_W,
        0x1B => KeyCode::ANSI_X,
        0x1C => KeyCode::ANSI_Y,
        0x1D => KeyCode::ANSI_Z,
        0x1E => KeyCode::ANSI_1,
        0x1F => KeyCode::ANSI_2,
        0x20 => KeyCode::ANSI_3,
        0x21 => KeyCode::ANSI_4,
        0x22 => KeyCode::ANSI_5,
        0x23 => KeyCode::ANSI_6,
        0x24 => KeyCode::ANSI_7,
        0x25 => KeyCode::ANSI_8,
        0x26 => KeyCode::ANSI_9,
        0x27 => KeyCode::ANSI_0,
        0x28 => KeyCode::RETURN,
        0x29 => KeyCode::ESCAPE,
        0x2A => KeyCode::DELETE,
        0x2B => KeyCode::TAB,
        0x2C => KeyCode::SPACE,
        0x2D => KeyCode::ANSI_MINUS,
        0x2E => KeyCode::ANSI_EQUAL,
        0x2F => KeyCode::ANSI_LEFT_BRACKET,
        0x30 => KeyCode::ANSI_RIGHT_BRACKET,
        0x31 => KeyCode::ANSI_BACKSLASH,
        0x33 => KeyCode::ANSI_SEMICOLON,
        0x34 => KeyCode::ANSI_QUOTE,
        0x35 => KeyCode::ANSI_GRAVE,
        0x36 => KeyCode::ANSI_COMMA,
        0x37 => KeyCode::ANSI_PERIOD,
        0x38 => KeyCode::ANSI_SLASH,
        0x39 => KeyCode::CAPS_LOCK,
        0x3A => KeyCode::F1,
        0x3B => KeyCode::F2,
        0x3C => KeyCode::F3,
        0x3D => KeyCode::F4,
        0x3E => KeyCode::F5,
        0x3F => KeyCode::F6,
        0x40 => KeyCode::F7,
        0x41 => KeyCode::F8,
        0x42 => KeyCode::F9,
        0x43 => KeyCode::F10,
        0x44 => KeyCode::F11,
        0x45 => KeyCode::F12,
        0x49 | 0x75 => KeyCode::HELP,
        0x4A => KeyCode::HOME,
        0x4B => KeyCode::PAGE_UP,
        0x4C => KeyCode::FORWARD_DELETE,
        0x4D => KeyCode::END,
        0x4E => KeyCode::PAGE_DOWN,
        0x4F => KeyCode::RIGHT_ARROW,
        0x50 => KeyCode::LEFT_ARROW,
        0x51 => KeyCode::DOWN_ARROW,
        0x52 => KeyCode::UP_ARROW,
        0x53 => KeyCode::ANSI_KEYPAD_CLEAR,
        0x54 => KeyCode::ANSI_KEYPAD_DIVIDE,
        0x55 => KeyCode::ANSI_KEYPAD_MULTIPLY,
        0x56 => KeyCode::ANSI_KEYPAD_MINUS,
        0x57 => KeyCode::ANSI_KEYPAD_PLUS,
        0x58 => KeyCode::ANSI_KEYPAD_ENTER,
        0x59 => KeyCode::ANSI_KEYPAD_1,
        0x5A => KeyCode::ANSI_KEYPAD_2,
        0x5B => KeyCode::ANSI_KEYPAD_3,
        0x5C => KeyCode::ANSI_KEYPAD_4,
        0x5D => KeyCode::ANSI_KEYPAD_5,
        0x5E => KeyCode::ANSI_KEYPAD_6,
        0x5F => KeyCode::ANSI_KEYPAD_7,
        0x60 => KeyCode::ANSI_KEYPAD_8,
        0x61 => KeyCode::ANSI_KEYPAD_9,
        0x62 => KeyCode::ANSI_KEYPAD_0,
        0x63 => KeyCode::ANSI_KEYPAD_DECIMAL,
        0x64 => KeyCode::ISO_SECTION,
        0x67 => KeyCode::ANSI_KEYPAD_EQUAL,
        0x68 => KeyCode::F13,
        0x69 => KeyCode::F14,
        0x6A => KeyCode::F15,
        0x6B => KeyCode::F16,
        0x6C => KeyCode::F17,
        0x6D => KeyCode::F18,
        0x6E => KeyCode::F19,
        0x6F => KeyCode::F20,
        0xE0 => KeyCode::CONTROL,
        0xE1 => KeyCode::SHIFT,
        0xE2 => KeyCode::OPTION,
        0xE3 => KeyCode::COMMAND,
        0xE4 => KeyCode::RIGHT_CONTROL,
        0xE5 => KeyCode::RIGHT_SHIFT,
        0xE6 => KeyCode::RIGHT_OPTION,
        0xE7 => KeyCode::RIGHT_COMMAND,
        _ => return None,
    })
}

fn keycode_to_hid(keycode: u16) -> Option<HidUsage> {
    const IDS: &[u16] = &[
        0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12,
        0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21,
        0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
        0x31, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40,
        0x41, 0x42, 0x43, 0x44, 0x45, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52,
        0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61,
        0x62, 0x63, 0x64, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0xE0, 0xE1, 0xE2,
        0xE3, 0xE4, 0xE5, 0xE6, 0xE7,
    ];
    IDS.iter()
        .copied()
        .find(|id| hid_to_keycode(HidUsage::new(KEYBOARD_PAGE, *id)) == Some(keycode))
        .map(|id| HidUsage::new(KEYBOARD_PAGE, id))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn display() -> DisplayGeometry {
        DisplayGeometry {
            id: DisplayId::new(17),
            origin_x: -1_920.0,
            origin_y: 0.0,
            width_points: 1_920.0,
            height_points: 1_080.0,
            width_pixels: 3_840,
            height_pixels: 2_160,
        }
    }

    #[test]
    fn keyboard_mapping_round_trips_modifiers_keypad_and_function_keys() {
        for id in [0x04, 0x28, 0x53, 0x58, 0x63, 0x64, 0x68, 0x6f, 0xe0, 0xe7] {
            let usage = HidUsage::new(KEYBOARD_PAGE, id);
            let keycode = hid_to_keycode(usage).expect("representative usage is mapped");
            assert_eq!(keycode_to_hid(keycode), Some(usage));
        }
        assert_eq!(hid_to_keycode(HidUsage::new(CONSUMER_PAGE, 0x00cd)), None);
    }

    #[test]
    fn native_events_preserve_directional_modifiers_scroll_and_buttons() {
        let modifiers = Modifiers::LEFT_SHIFT | Modifiers::RIGHT_ALT;
        assert_eq!(
            convert_native_input(
                ffi::NativeInputEvent::Keyboard {
                    keycode: KeyCode::ANSI_A,
                    pressed: true,
                    modifier_bits: modifiers.bits(),
                },
                &[display()],
                false,
            ),
            Some(InputEvent::Key {
                usage: HidUsage::new(KEYBOARD_PAGE, 0x04),
                state: KeyState::Pressed,
                modifiers,
            })
        );
        assert_eq!(
            convert_native_input(
                ffi::NativeInputEvent::Scroll {
                    horizontal: -7,
                    vertical: 13,
                    precise: true,
                },
                &[display()],
                false,
            ),
            Some(InputEvent::Scroll {
                horizontal: -7,
                vertical: 13,
                unit: ScrollUnit::Precise,
            })
        );
        assert_eq!(
            convert_native_input(
                ffi::NativeInputEvent::PointerButton {
                    button: 32,
                    pressed: false,
                },
                &[display()],
                false,
            ),
            Some(InputEvent::PointerButton {
                button: PointerButton::new(32).unwrap(),
                state: ButtonState::Released,
            })
        );
    }

    #[test]
    fn absolute_pointer_normalization_keeps_display_edges() {
        let display = display();
        assert_eq!(
            normalize_position(CGPoint::new(display.origin_x, display.origin_y), &[display]),
            Some(NormalizedPosition::new(
                display.id,
                NormalizedAxis::MIN,
                NormalizedAxis::MIN,
            ))
        );
        assert_eq!(
            normalize_position(
                CGPoint::new(
                    display.origin_x + display.width_points,
                    display.origin_y + display.height_points,
                ),
                &[display],
            ),
            Some(NormalizedPosition::new(
                display.id,
                NormalizedAxis::MAX,
                NormalizedAxis::MAX,
            ))
        );
    }

    #[test]
    fn routed_pointer_conversion_uses_relative_delta_without_display_identity() {
        assert_eq!(
            convert_native_input(
                ffi::NativeInputEvent::PointerMotion {
                    x: -10_000.0,
                    y: 8_000.0,
                    delta_x: 15,
                    delta_y: -6,
                },
                &[display()],
                true,
            ),
            Some(InputEvent::PointerDelta {
                delta: PointerDelta::new(15, -6).unwrap(),
            })
        );
    }

    #[test]
    fn only_terminal_lifecycle_events_require_local_recovery() {
        for event in [
            MacInputLifecycleEvent::SystemWillSleep,
            MacInputLifecycleEvent::ScreensDidSleep,
            MacInputLifecycleEvent::SessionDidResignActive,
            MacInputLifecycleEvent::TapDisabledByTimeout,
            MacInputLifecycleEvent::TapDisabledByUserInput,
        ] {
            assert!(lifecycle_requires_local_recovery(event));
        }
        for event in [
            MacInputLifecycleEvent::CaptureStarted,
            MacInputLifecycleEvent::CaptureStopped,
            MacInputLifecycleEvent::SystemDidWake,
            MacInputLifecycleEvent::ScreensDidWake,
            MacInputLifecycleEvent::SessionDidBecomeActive,
        ] {
            assert!(!lifecycle_requires_local_recovery(event));
        }
    }

    #[test]
    fn capture_handle_never_routes_before_explicit_enable() {
        let capture = MacInputCapture::new(|_| {});
        assert!(!capture.routing_to_peer());
        assert_eq!(
            capture.set_routing_to_peer(true),
            Err(MacPlatformError::CaptureNotRunning)
        );
        assert!(!capture.routing_to_peer());
    }
}
