use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

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
    ButtonState, CONSUMER_PAGE, HidUsage, InputEvent, KEYBOARD_PAGE, KeyState, Modifiers,
    NormalizedAxis, NormalizedPosition, PointerButton, PointerDelta, PressedState, ScrollUnit,
};

use super::{DisplayGeometry, MacPlatformError, MacReadinessProbe, NODAVO_SYNTHETIC_EVENT_TAG};

#[path = "macos/display.rs"]
mod display;
#[path = "macos/ffi.rs"]
pub(crate) mod ffi;
#[path = "macos/ipc_auth.rs"]
mod ipc_auth;
#[path = "macos/xpc_ipc.rs"]
mod xpc_ipc;

pub use display::{MacDisplayMonitor, MacDisplaySnapshot};
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

/// Returns one stable geometry snapshot for every active display.
///
/// Without an active [`MacDisplayMonitor`], identifiers are scoped to this
/// snapshot and every identifier from an earlier standalone call is retired.
///
/// # Errors
///
/// Fails closed when enumeration fails or the graph is changing, oversized,
/// empty, or invalid.
pub fn active_displays() -> Result<Vec<DisplayGeometry>, MacPlatformError> {
    Ok(refresh_display_snapshot()?.displays().to_vec())
}

/// Publishes and returns one stable process-global display snapshot.
///
/// This is the explicit refresh point for an async bridge after
/// [`MacDisplayMonitor::display_change_pending`] becomes true. Capture and
/// injection hot paths never call it implicitly.
///
/// Without any active [`MacDisplayMonitor`], the returned geometry is a
/// standalone snapshot: all previously issued opaque display identifiers are
/// retired because native identifier reuse could not have been observed.
///
/// # Errors
///
/// Fails closed for a changing, oversized, empty, or invalid display graph.
pub fn refresh_display_snapshot() -> Result<Arc<MacDisplaySnapshot>, MacPlatformError> {
    display::current_process_snapshot()
}

/// Probes current-user prerequisites without registering capture, routing,
/// suppressing or injecting input, and without showing a permission prompt.
#[must_use]
pub fn probe_readiness() -> MacReadinessProbe {
    let initially_trusted = accessibility_trusted();
    let local_topology_available =
        display::passive_process_snapshot().is_ok_and(|snapshot| !snapshot.displays().is_empty());
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
        display::passive_process_snapshot()?;
        Ok(Self {
            source: CGEventSource::new(CGEventSourceStateID::Private)
                .map_err(|()| MacPlatformError::CoreGraphics)?,
            pressed: PressedState::default(),
        })
    }

    /// Refreshes the cached active-display geometry.
    ///
    /// # Errors
    ///
    /// Returns an error when CoreGraphics cannot enumerate valid displays.
    pub fn refresh_displays(&mut self) -> Result<(), MacPlatformError> {
        display::current_process_snapshot()?;
        Ok(())
    }

    /// Injects one semantic input event into the current session.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported keys, unknown displays, or a rejected
    /// CoreGraphics event operation. Absolute pointer motion also fails while
    /// display geometry is dirty; semantic topology-independent events do not.
    pub fn inject(&mut self, input: InputEvent) -> Result<(), MacPlatformError> {
        if !accessibility_trusted() {
            return Err(MacPlatformError::AccessibilityDenied);
        }
        let topology = topology_snapshot_for_input(&input, display::clean_process_snapshot)?;
        self.send_event(input, topology.as_deref())?;
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
            if self.send_event(release, None).is_err() {
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

    /// Returns the exact clean display snapshot currently shared with capture.
    ///
    /// # Errors
    ///
    /// Fails while display reconfiguration is pending or if monitor state is
    /// unavailable.
    pub fn display_snapshot(&self) -> Result<Arc<MacDisplaySnapshot>, MacPlatformError> {
        display::clean_process_snapshot()
    }

    fn send_event(
        &self,
        input: InputEvent,
        topology: Option<&MacDisplaySnapshot>,
    ) -> Result<(), MacPlatformError> {
        match input {
            InputEvent::Key {
                usage,
                state,
                modifiers,
            } => self.inject_key(usage, state, modifiers),
            InputEvent::PointerMotion { position } => self.inject_motion(
                position,
                topology
                    .ok_or(MacPlatformError::DisplayConfigurationChanged)?
                    .displays(),
            ),
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

    fn inject_motion(
        &self,
        position: NormalizedPosition,
        displays: &[DisplayGeometry],
    ) -> Result<(), MacPlatformError> {
        let point = point_for_position(position, displays)?;
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

fn topology_snapshot_for_input<T, E>(
    input: &InputEvent,
    clean_snapshot: impl FnOnce() -> Result<T, E>,
) -> Result<Option<T>, E> {
    match input {
        InputEvent::PointerMotion { .. } => clean_snapshot().map(Some),
        InputEvent::Key { .. }
        | InputEvent::PointerDelta { .. }
        | InputEvent::PointerButton { .. }
        | InputEvent::Scroll { .. } => Ok(None),
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
    stop: Arc<ffi::NativeInputCaptureStopHandle>,
    worker: JoinHandle<Result<(), MacPlatformError>>,
}

const ROUTING_DISABLE_DEADLINE: Duration = Duration::from_secs(2);
const CAPTURE_OWNERSHIP_DEADLINE: Duration = Duration::from_secs(2);
const CAPTURE_WORKER_POLL_INTERVAL: Duration = Duration::from_millis(1);
static MAC_INPUT_CAPTURE_POISONED: AtomicBool = AtomicBool::new(false);

fn ensure_capture_process_available(poison: &AtomicBool) -> Result<(), MacPlatformError> {
    if poison.load(Ordering::Acquire) {
        Err(MacPlatformError::CaptureProcessPoisoned)
    } else {
        Ok(())
    }
}

fn finish_capture_worker_before_deadline(
    worker: JoinHandle<Result<(), MacPlatformError>>,
    poison: &AtomicBool,
    deadline: Instant,
) -> Result<(), MacPlatformError> {
    while !worker.is_finished() {
        let now = Instant::now();
        if now >= deadline {
            poison.store(true, Ordering::Release);
            // Detaching is safe only because process-global poison permanently
            // prevents a replacement capture from starting in this process.
            drop(worker);
            return Err(MacPlatformError::CaptureProcessPoisoned);
        }
        thread::sleep(CAPTURE_WORKER_POLL_INTERVAL.min(deadline.saturating_duration_since(now)));
    }
    worker.join().map_err(|_| MacPlatformError::CaptureThread)?
}

fn request_startup_stop(startup_stop: &Mutex<Option<Arc<ffi::NativeInputCaptureStopHandle>>>) {
    let stop = startup_stop
        .try_lock()
        .ok()
        .and_then(|slot| slot.as_ref().map(Arc::clone));
    if let Some(stop) = stop {
        stop.stop();
    }
}

struct RoutingGate {
    enabled: AtomicBool,
    display_generation: AtomicU64,
    active_callbacks: AtomicUsize,
    drain_lock: Mutex<()>,
    drained: Condvar,
}

impl Default for RoutingGate {
    fn default() -> Self {
        Self {
            enabled: AtomicBool::new(false),
            display_generation: AtomicU64::new(0),
            active_callbacks: AtomicUsize::new(0),
            drain_lock: Mutex::new(()),
            drained: Condvar::new(),
        }
    }
}

impl RoutingGate {
    fn enable(&self, display_generation: u64) -> Result<(), MacPlatformError> {
        if display_generation == 0 || self.active_callbacks.load(Ordering::SeqCst) != 0 {
            self.invalidate();
            return Err(MacPlatformError::CaptureCallbackDrainTimedOut);
        }
        self.display_generation
            .store(display_generation, Ordering::SeqCst);
        self.enabled.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn invalidate(&self) {
        self.enabled.store(false, Ordering::SeqCst);
        self.display_generation.store(0, Ordering::SeqCst);
    }

    fn disable_and_drain(&self, timeout: Duration) -> Result<(), MacPlatformError> {
        self.invalidate();
        let deadline = Instant::now() + timeout;
        let mut lock = self
            .drain_lock
            .lock()
            .map_err(|_| MacPlatformError::CaptureCallbackDrainTimedOut)?;
        while self.active_callbacks.load(Ordering::SeqCst) != 0 {
            let now = Instant::now();
            if now >= deadline {
                return Err(MacPlatformError::CaptureCallbackDrainTimedOut);
            }
            let remaining = deadline.saturating_duration_since(now);
            let (next, wait) = self
                .drained
                .wait_timeout(lock, remaining)
                .map_err(|_| MacPlatformError::CaptureCallbackDrainTimedOut)?;
            lock = next;
            if wait.timed_out() && self.active_callbacks.load(Ordering::SeqCst) != 0 {
                return Err(MacPlatformError::CaptureCallbackDrainTimedOut);
            }
        }
        Ok(())
    }

    fn enter_if(
        &self,
        generation_is_current: impl FnOnce(u64) -> bool,
    ) -> Option<RoutedCallback<'_>> {
        if !self.enabled.load(Ordering::SeqCst) {
            return None;
        }
        if self
            .active_callbacks
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |active| {
                active.checked_add(1)
            })
            .is_err()
        {
            self.invalidate();
            return None;
        }
        if !self.enabled.load(Ordering::SeqCst) {
            self.leave_callback();
            return None;
        }
        let generation = self.display_generation.load(Ordering::SeqCst);
        if generation == 0 || !generation_is_current(generation) {
            self.invalidate();
            self.leave_callback();
            return None;
        }
        Some(RoutedCallback {
            gate: self,
            display_generation: generation,
        })
    }

    fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::SeqCst)
            && display::display_generation_is_current(
                self.display_generation.load(Ordering::SeqCst),
            )
    }

    fn leave_callback(&self) {
        let previous = self.active_callbacks.fetch_sub(1, Ordering::SeqCst);
        debug_assert!(previous != 0, "routed callback accounting underflow");
        if previous == 1 {
            if let Ok(_lock) = self.drain_lock.lock() {
                self.drained.notify_all();
            } else {
                self.invalidate();
            }
        }
    }
}

struct RoutedCallback<'a> {
    gate: &'a RoutingGate,
    display_generation: u64,
}

impl RoutedCallback<'_> {
    fn remains_current(&self) -> bool {
        self.remains_current_with(display::display_generation_is_current)
    }

    fn remains_current_with(&self, generation_is_current: impl FnOnce(u64) -> bool) -> bool {
        self.gate.enabled.load(Ordering::SeqCst)
            && self.gate.display_generation.load(Ordering::SeqCst) == self.display_generation
            && generation_is_current(self.display_generation)
    }
}

impl Drop for RoutedCallback<'_> {
    fn drop(&mut self) {
        self.gate.leave_callback();
    }
}

const fn committed_input_disposition(
    routed: bool,
    enqueue_succeeded: bool,
) -> ffi::NativeCaptureDisposition {
    if !enqueue_succeeded {
        ffi::NativeCaptureDisposition::Abort
    } else if routed {
        // Routed delivery is transactional at this boundary. Once the
        // reliable bridge accepted an event while its admission guard is
        // active, the same physical event must not fall through locally even
        // if display/routing state becomes dirty before this callback returns.
        ffi::NativeCaptureDisposition::Suppress
    } else {
        ffi::NativeCaptureDisposition::Keep
    }
}

/// Owned, restartable current-session `CGEventTap` runtime.
///
/// Input suppression is disabled by default. It becomes active only after
/// [`Self::set_routing_to_peer`] is explicitly set to `true`, and it is always
/// cleared before stop, sleep/session-inactive notifications, tap disablement,
/// or callback failure.
pub struct MacInputCapture {
    callback: Arc<CaptureCallback>,
    routing: Arc<RoutingGate>,
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
            routing: Arc::new(RoutingGate::default()),
            delivery,
            runtime: None,
        }
    }

    /// Starts a fresh tap on a dedicated run-loop thread.
    ///
    /// # Errors
    ///
    /// Fails closed when Accessibility is absent, display discovery fails, a
    /// tap cannot be installed/enabled, this handle already owns a runtime, or
    /// any earlier capture could not relinquish process ownership by deadline.
    #[allow(clippy::too_many_lines)]
    pub fn start(&mut self) -> Result<(), MacPlatformError> {
        if self.runtime.is_some() {
            return Err(MacPlatformError::CaptureAlreadyRunning);
        }
        ensure_capture_process_available(&MAC_INPUT_CAPTURE_POISONED)?;
        if !accessibility_trusted() {
            return Err(MacPlatformError::AccessibilityDenied);
        }
        let deadline = Instant::now() + CAPTURE_OWNERSHIP_DEADLINE;
        let callback = Arc::clone(&self.callback);
        let routing = Arc::clone(&self.routing);
        let delivery = self.delivery;
        routing.invalidate();
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let (ownership_tx, ownership_rx) = mpsc::sync_channel(1);
        let startup_cancelled = Arc::new(AtomicBool::new(false));
        let worker_cancelled = Arc::clone(&startup_cancelled);
        let startup_stop = Arc::new(Mutex::new(None));
        let worker_startup_stop = Arc::clone(&startup_stop);
        let worker = thread::Builder::new()
            .name("nodavo-macos-input".into())
            .spawn(move || {
                if worker_cancelled.load(Ordering::Acquire)
                    || ensure_capture_process_available(&MAC_INPUT_CAPTURE_POISONED).is_err()
                {
                    let error = MacPlatformError::CaptureProcessPoisoned;
                    let _ = ready_tx.send(Err(error.clone()));
                    return Err(error);
                }
                let mut display_monitor = match MacDisplayMonitor::start() {
                    Ok(monitor) => monitor,
                    Err(error) => {
                        let _ = ready_tx.send(Err(error.clone()));
                        return Err(error);
                    }
                };
                let event_callback = Arc::clone(&callback);
                let event_routing = Arc::clone(&routing);
                let Ok(capture) = ffi::NativeInputCapture::new(move |native| match native {
                    ffi::NativeInputEvent::Lifecycle(native) => {
                        let lifecycle = lifecycle_event(native);
                        if matches!(
                            lifecycle,
                            MacInputLifecycleEvent::SystemDidWake
                                | MacInputLifecycleEvent::ScreensDidWake
                        ) {
                            display::mark_wake_dirty();
                        }
                        if lifecycle_requires_local_recovery(lifecycle) {
                            event_routing.invalidate();
                        }
                        if event_callback(MacInputCaptureEvent::Lifecycle(lifecycle)).is_err() {
                            event_routing.invalidate();
                            ffi::NativeCaptureDisposition::Abort
                        } else {
                            ffi::NativeCaptureDisposition::Keep
                        }
                    }
                    native => {
                        let routed = event_routing.enter_if(display::display_generation_is_current);
                        let routing = routed.is_some();
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
                                event_routing.invalidate();
                                return ffi::NativeCaptureDisposition::Abort;
                            }
                        }
                        let snapshot = if !relative_pointer
                            && matches!(native, ffi::NativeInputEvent::PointerMotion { .. })
                        {
                            let Ok(snapshot) = display::clean_process_snapshot() else {
                                return ffi::NativeCaptureDisposition::Keep;
                            };
                            Some(snapshot)
                        } else {
                            None
                        };
                        let Some(input) = convert_native_input(
                            native,
                            snapshot
                                .as_deref()
                                .map_or(&[], MacDisplaySnapshot::displays),
                            relative_pointer,
                        ) else {
                            return ffi::NativeCaptureDisposition::Keep;
                        };
                        if routed
                            .as_ref()
                            .is_some_and(|admission| !admission.remains_current())
                        {
                            event_routing.invalidate();
                            return ffi::NativeCaptureDisposition::Keep;
                        }
                        let enqueue_succeeded =
                            event_callback(MacInputCaptureEvent::Input(input)).is_ok();
                        if !enqueue_succeeded {
                            event_routing.invalidate();
                        }
                        committed_input_disposition(routing, enqueue_succeeded)
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
                let stop = if let Ok(stop) = capture.stop_handle() {
                    Arc::new(stop)
                } else {
                    let error = MacPlatformError::EventTapUnavailable;
                    let _ = ready_tx.send(Err(error.clone()));
                    return Err(error);
                };
                let startup_slot_ready = worker_startup_stop
                    .lock()
                    .map(|mut slot| *slot = Some(Arc::clone(&stop)))
                    .is_ok();
                if !startup_slot_ready {
                    stop.stop();
                    let error = MacPlatformError::CaptureThread;
                    let _ = ready_tx.send(Err(error.clone()));
                    return Err(error);
                }
                if worker_cancelled.load(Ordering::Acquire)
                    || ensure_capture_process_available(&MAC_INPUT_CAPTURE_POISONED).is_err()
                {
                    stop.stop();
                    return Err(MacPlatformError::CaptureProcessPoisoned);
                }
                if let Err(error) =
                    emit_callback(callback.as_ref(), MacInputLifecycleEvent::CaptureStarted)
                {
                    let _ = ready_tx.send(Err(error.clone()));
                    return Err(error);
                }
                if worker_cancelled.load(Ordering::Acquire)
                    || ensure_capture_process_available(&MAC_INPUT_CAPTURE_POISONED).is_err()
                {
                    stop.stop();
                    return Err(MacPlatformError::CaptureProcessPoisoned);
                }
                if ready_tx.send(Ok(Arc::clone(&stop))).is_err() {
                    stop.stop();
                    return Err(MacPlatformError::CaptureThread);
                }
                if ownership_rx
                    .recv_timeout(CAPTURE_OWNERSHIP_DEADLINE)
                    .is_err()
                {
                    stop.stop();
                    return Err(if MAC_INPUT_CAPTURE_POISONED.load(Ordering::Acquire) {
                        MacPlatformError::CaptureProcessPoisoned
                    } else {
                        MacPlatformError::CaptureThread
                    });
                }
                if let Ok(mut slot) = worker_startup_stop.lock() {
                    slot.take();
                } else {
                    stop.stop();
                    return Err(MacPlatformError::CaptureThread);
                }
                if worker_cancelled.load(Ordering::Acquire)
                    || ensure_capture_process_available(&MAC_INPUT_CAPTURE_POISONED).is_err()
                {
                    stop.stop();
                    return Err(MacPlatformError::CaptureProcessPoisoned);
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
                routing.invalidate();
                if result.is_ok() {
                    emit_callback(callback.as_ref(), MacInputLifecycleEvent::CaptureStopped)?;
                }
                drop(capture);
                let monitor_result = display_monitor.stop();
                result.and(monitor_result)
            })
            .map_err(|_| MacPlatformError::CaptureThread)?;

        let ready = ready_rx.recv_timeout(deadline.saturating_duration_since(Instant::now()));
        match ready {
            Ok(Ok(stop)) if !MAC_INPUT_CAPTURE_POISONED.load(Ordering::Acquire) => {
                if ownership_tx.send(()).is_err() {
                    startup_cancelled.store(true, Ordering::Release);
                    stop.stop();
                    let stopped = finish_capture_worker_before_deadline(
                        worker,
                        &MAC_INPUT_CAPTURE_POISONED,
                        deadline,
                    );
                    return match stopped {
                        Err(MacPlatformError::CaptureProcessPoisoned) => stopped,
                        _ => Err(MacPlatformError::CaptureThread),
                    };
                }
                self.runtime = Some(CaptureRuntime { stop, worker });
                Ok(())
            }
            Ok(Ok(stop)) => {
                drop(ownership_tx);
                startup_cancelled.store(true, Ordering::Release);
                stop.stop();
                let _ = finish_capture_worker_before_deadline(
                    worker,
                    &MAC_INPUT_CAPTURE_POISONED,
                    deadline,
                );
                Err(MacPlatformError::CaptureProcessPoisoned)
            }
            Ok(Err(error)) => {
                drop(ownership_tx);
                startup_cancelled.store(true, Ordering::Release);
                request_startup_stop(&startup_stop);
                match finish_capture_worker_before_deadline(
                    worker,
                    &MAC_INPUT_CAPTURE_POISONED,
                    deadline,
                ) {
                    Err(MacPlatformError::CaptureProcessPoisoned) => {
                        Err(MacPlatformError::CaptureProcessPoisoned)
                    }
                    Err(MacPlatformError::CaptureThread) => Err(MacPlatformError::CaptureThread),
                    Ok(()) | Err(_) => Err(error),
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                drop(ownership_tx);
                startup_cancelled.store(true, Ordering::Release);
                request_startup_stop(&startup_stop);
                match finish_capture_worker_before_deadline(
                    worker,
                    &MAC_INPUT_CAPTURE_POISONED,
                    deadline,
                ) {
                    Ok(()) => Err(MacPlatformError::CaptureThread),
                    Err(error) => Err(error),
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                drop(ownership_tx);
                startup_cancelled.store(true, Ordering::Release);
                MAC_INPUT_CAPTURE_POISONED.store(true, Ordering::Release);
                request_startup_stop(&startup_stop);
                drop(worker);
                Err(MacPlatformError::CaptureProcessPoisoned)
            }
        }
    }

    /// Enables or disables suppression for successfully decoded local input.
    ///
    /// Disabling first closes routed admission, then waits for every callback
    /// which could have observed the prior enabled state to finish its
    /// enqueue/suppression decision. The wait is bounded and remains fail
    /// closed if an in-flight callback does not drain before the deadline.
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
            display::clean_process_snapshot()?;
            let generation = display::clean_display_generation()?;
            self.routing.enable(generation)?;
            if !display::display_generation_is_current(generation) {
                self.routing.invalidate();
                return Err(MacPlatformError::DisplayConfigurationChanged);
            }
            return Ok(());
        }
        self.routing.disable_and_drain(ROUTING_DISABLE_DEADLINE)
    }

    #[must_use]
    pub fn routing_to_peer(&self) -> bool {
        self.routing.is_enabled()
    }

    #[must_use]
    pub fn is_running(&self) -> bool {
        self.runtime
            .as_ref()
            .is_some_and(|runtime| !runtime.worker.is_finished())
    }

    /// Stops the native run loop and waits up to two seconds for its terminal
    /// acknowledgement, including routed-callback drain time.
    ///
    /// # Errors
    ///
    /// Returns the terminal tap/callback failure if the runtime had already
    /// failed, or permanently poisons capture startup for this process if the
    /// worker cannot relinquish ownership by the deadline.
    pub fn stop(&mut self) -> Result<(), MacPlatformError> {
        let deadline = Instant::now() + CAPTURE_OWNERSHIP_DEADLINE;
        let routing = self
            .routing
            .disable_and_drain(deadline.saturating_duration_since(Instant::now()));
        let Some(runtime) = self.runtime.take() else {
            return routing;
        };
        runtime.stop.stop();
        let stopped = finish_capture_worker_before_deadline(
            runtime.worker,
            &MAC_INPUT_CAPTURE_POISONED,
            deadline,
        );
        if matches!(stopped, Err(MacPlatformError::CaptureProcessPoisoned)) {
            stopped
        } else {
            routing.and(stopped)
        }
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
    /// Unlike [`Self::stop`], this is an explicitly unbounded wait. Callers
    /// choose it only when they intend to remain blocked until the native tap
    /// or callback exits naturally.
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

fn point_for_position(
    position: NormalizedPosition,
    displays: &[DisplayGeometry],
) -> Result<CGPoint, MacPlatformError> {
    let display = displays
        .iter()
        .find(|display| display.id == position.display())
        .ok_or(MacPlatformError::UnknownDisplay)?;
    Ok(CGPoint::new(
        display.origin_x + position.x().to_unit_f64() * display.width_points,
        display.origin_y + position.y().to_unit_f64() * display.height_points,
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
    use nodavo_input::DisplayId;

    fn display() -> DisplayGeometry {
        DisplayGeometry {
            id: DisplayId::new(17),
            origin_x: -1_920.0,
            origin_y: 0.0,
            width_points: 1_920.0,
            height_points: 1_080.0,
            width_pixels: 3_840,
            height_pixels: 2_160,
            rotation: nodavo_protocol::DisplayRotation::Degrees0,
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
    fn stale_display_identity_never_targets_current_geometry() {
        let current = display();
        let stale = NormalizedPosition::new(
            DisplayId::new(current.id.get() + 1),
            NormalizedAxis::MIN,
            NormalizedAxis::MIN,
        );
        assert!(matches!(
            point_for_position(stale, &[current]),
            Err(MacPlatformError::UnknownDisplay)
        ));
    }

    #[test]
    fn dirty_topology_blocks_only_absolute_pointer_in_pure_admission() {
        let absolute = InputEvent::PointerMotion {
            position: NormalizedPosition::new(
                display().id,
                NormalizedAxis::MIN,
                NormalizedAxis::MIN,
            ),
        };
        let blocked: Result<Option<()>, MacPlatformError> =
            topology_snapshot_for_input(&absolute, || {
                Err(MacPlatformError::DisplayConfigurationChanged)
            });
        assert_eq!(blocked, Err(MacPlatformError::DisplayConfigurationChanged));
        assert_eq!(
            topology_snapshot_for_input(&absolute, || Ok::<_, MacPlatformError>(())),
            Ok(Some(()))
        );

        let independent = [
            InputEvent::Key {
                usage: HidUsage::new(KEYBOARD_PAGE, 0x04),
                state: KeyState::Pressed,
                modifiers: Modifiers::empty(),
            },
            InputEvent::PointerDelta {
                delta: PointerDelta::new(1, -1).unwrap(),
            },
            InputEvent::PointerButton {
                button: PointerButton::new(1).unwrap(),
                state: ButtonState::Pressed,
            },
            InputEvent::Scroll {
                horizontal: 1,
                vertical: -1,
                unit: ScrollUnit::Lines,
            },
        ];
        for input in independent {
            let accepted: Result<Option<()>, MacPlatformError> =
                topology_snapshot_for_input(&input, || {
                    Err(MacPlatformError::DisplayConfigurationChanged)
                });
            assert_eq!(accepted, Ok(None));
        }
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

    #[test]
    fn routing_disable_waits_for_in_flight_callback_and_closes_future_admission() {
        use std::sync::mpsc::TryRecvError;

        let gate = Arc::new(RoutingGate::default());
        gate.enable(7).unwrap();
        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let callback_gate = Arc::clone(&gate);
        let callback = thread::spawn(move || {
            let admission = callback_gate
                .enter_if(|generation| generation == 7)
                .expect("routing was enabled");
            entered_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            drop(admission);
        });
        entered_rx.recv().unwrap();

        let (started_tx, started_rx) = mpsc::sync_channel(1);
        let (disabled_tx, disabled_rx) = mpsc::sync_channel(1);
        let disable_gate = Arc::clone(&gate);
        let disable = thread::spawn(move || {
            started_tx.send(()).unwrap();
            let result = disable_gate.disable_and_drain(Duration::from_secs(1));
            disabled_tx.send(result).unwrap();
        });
        started_rx.recv().unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        while gate.enabled.load(Ordering::SeqCst) && Instant::now() < deadline {
            thread::yield_now();
        }
        assert!(!gate.enabled.load(Ordering::SeqCst));
        assert_eq!(disabled_rx.try_recv(), Err(TryRecvError::Empty));

        release_tx.send(()).unwrap();
        assert_eq!(disabled_rx.recv().unwrap(), Ok(()));
        callback.join().unwrap();
        disable.join().unwrap();
        assert!(gate.enter_if(|_| true).is_none());
    }

    #[test]
    fn routing_disable_timeout_is_bounded_and_stays_closed() {
        let gate = RoutingGate::default();
        gate.enable(7).unwrap();
        let admission = gate
            .enter_if(|generation| generation == 7)
            .expect("routing was enabled");

        assert_eq!(
            gate.disable_and_drain(Duration::ZERO),
            Err(MacPlatformError::CaptureCallbackDrainTimedOut)
        );
        assert!(!gate.enabled.load(Ordering::SeqCst));
        assert!(gate.enter_if(|_| true).is_none());

        drop(admission);
        assert_eq!(gate.disable_and_drain(Duration::from_secs(1)), Ok(()));
        assert_eq!(gate.enable(7), Ok(()));
    }

    #[test]
    fn routing_cannot_reenable_while_timed_out_callback_is_still_active() {
        let gate = RoutingGate::default();
        gate.enable(7).unwrap();
        let admission = gate
            .enter_if(|generation| generation == 7)
            .expect("routing was enabled");
        assert_eq!(
            gate.disable_and_drain(Duration::ZERO),
            Err(MacPlatformError::CaptureCallbackDrainTimedOut)
        );
        assert_eq!(
            gate.enable(7),
            Err(MacPlatformError::CaptureCallbackDrainTimedOut)
        );
        assert!(!gate.enabled.load(Ordering::SeqCst));
        drop(admission);
    }

    #[test]
    fn routed_enqueue_commits_one_destination_across_generation_change() {
        let gate = RoutingGate::default();
        let generation = AtomicU64::new(7);
        gate.enable(7).unwrap();
        let admission = gate
            .enter_if(|expected| generation.load(Ordering::SeqCst) == expected)
            .expect("routing was current at admission");

        let reliable_queue = vec!["physical-key-down"];
        assert_eq!(gate.active_callbacks.load(Ordering::SeqCst), 1);
        generation.store(8, Ordering::SeqCst);
        assert!(
            !admission
                .remains_current_with(|expected| { generation.load(Ordering::SeqCst) == expected })
        );

        let disposition = committed_input_disposition(true, true);
        assert_eq!(disposition, ffi::NativeCaptureDisposition::Suppress);
        assert_eq!(reliable_queue, ["physical-key-down"]);
        let local_delivery_count = usize::from(disposition == ffi::NativeCaptureDisposition::Keep);
        assert_eq!(reliable_queue.len() + local_delivery_count, 1);
        drop(admission);
        assert_eq!(gate.active_callbacks.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn routed_enqueue_failure_aborts_without_suppression() {
        assert_eq!(
            committed_input_disposition(true, false),
            ffi::NativeCaptureDisposition::Abort
        );
    }

    #[test]
    fn bounded_capture_finish_joins_clean_worker_without_poison() {
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let worker = thread::spawn(move || {
            release_rx.recv().unwrap();
            Ok(())
        });
        release_tx.send(()).unwrap();
        let poison = AtomicBool::new(false);

        assert_eq!(
            finish_capture_worker_before_deadline(
                worker,
                &poison,
                Instant::now() + Duration::from_secs(1),
            ),
            Ok(())
        );
        assert!(!poison.load(Ordering::Acquire));
        assert_eq!(ensure_capture_process_available(&poison), Ok(()));
    }

    #[test]
    fn bounded_capture_finish_poisons_before_detaching_stuck_worker() {
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let worker = thread::spawn(move || {
            release_rx.recv().unwrap();
            Ok(())
        });
        let poison = AtomicBool::new(false);

        assert_eq!(
            finish_capture_worker_before_deadline(
                worker,
                &poison,
                Instant::now() + Duration::from_millis(10),
            ),
            Err(MacPlatformError::CaptureProcessPoisoned)
        );
        assert!(poison.load(Ordering::Acquire));
        assert_eq!(
            ensure_capture_process_available(&poison),
            Err(MacPlatformError::CaptureProcessPoisoned)
        );

        // Let the deliberately detached fixture exit. Production poison is
        // permanent, so a timed-out callback cannot overlap a replacement.
        release_tx.send(()).unwrap();
    }
}
