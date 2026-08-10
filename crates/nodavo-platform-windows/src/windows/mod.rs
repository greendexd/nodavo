//! Safe Windows-specific orchestration over the isolated FFI wrappers.

mod ffi;

use std::fmt;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread::{self, JoinHandle};

use nodavo_input::{
    ButtonState, CONSUMER_PAGE, HidUsage, InputEvent, KEYBOARD_PAGE, KeyState, PointerDelta,
    PressedState, ScrollUnit,
};

use crate::input_runtime::{
    CaptureTranslator, ForceReleaseAcknowledgement, NativeInputEvent,
    lifecycle_requires_local_recovery,
};
use crate::windows_ipc_policy::{
    ObservedWindowsUi, WindowsUiPolicy, authorizes_windows_ui, compiled_windows_ui_identity,
    compiled_windows_ui_policy,
};
use crate::{
    ClipboardFormat, ClipboardMetadata, DisplayGeometry, EnvironmentCapabilities, MAX_DISPLAYS,
    MAX_PROTECTED_SECRET_BLOB_BYTES, MAX_PROTECTED_SECRET_BYTES, ProtectedSecretBlob,
    WindowsInputCaptureEvent, WindowsInputLifecycleEvent, WindowsInputReadiness,
    WindowsPlatformError, WindowsReadinessProbe,
};

pub use crate::windows_ipc_policy::compiled_windows_ui_auth_mode;

const MAX_PIPE_NAME_UNITS: usize = 240;
const REQUIRED_PIPE_PREFIX: &str = r"\\.\pipe\nodavo-";

/// Returns the private agent pipe name expected by the Windows shell.
///
/// The current-user SID keeps independently logged-in users in separate pipe
/// namespaces. The server still validates both user SID and process session on
/// every accepted connection before decoding any bytes.
///
/// # Errors
///
/// Fails closed when Windows cannot read or stringify the current-user SID.
pub fn current_user_agent_pipe_name() -> Result<String, WindowsPlatformError> {
    let pipe_name = format!(
        "{REQUIRED_PIPE_PREFIX}agent-{}",
        ffi::current_user_sid_string()?
    );
    if pipe_name.encode_utf16().count() > MAX_PIPE_NAME_UNITS {
        return Err(WindowsPlatformError::UnauthorizedLocalIpc);
    }
    Ok(pipe_name)
}

/// Atomically replaces a persistent file with a closed temporary file.
///
/// Both paths must have the same parent directory. The native operation uses
/// replace-existing and write-through semantics without cross-volume copying.
/// The caller remains responsible for validating both paths against reparse
/// points before invoking this boundary.
///
/// # Errors
///
/// Rejects paths in different directories, missing filenames, embedded NULs,
/// oversized paths, and any native replacement failure.
pub fn replace_file_atomic(source: &Path, destination: &Path) -> Result<(), WindowsPlatformError> {
    if source == destination
        || source.file_name().is_none()
        || destination.file_name().is_none()
        || source.parent() != destination.parent()
    {
        return Err(WindowsPlatformError::NativeApi);
    }
    ffi::replace_file_atomic(source, destination)
}

/// Creates one byte-mode named-pipe server instance with a protected DACL.
///
/// The pipe rejects remote clients. `first_instance` must be true only for the
/// listener's first instance; subsequent accept slots use false.
///
/// # Errors
///
/// Rejects names outside the private Nodavo namespace, embedded NULs, names
/// above the hard limit, unavailable Tokio I/O, or Windows security failures.
pub fn create_private_named_pipe(
    pipe_name: &str,
    first_instance: bool,
) -> Result<tokio::net::windows::named_pipe::NamedPipeServer, WindowsPlatformError> {
    if !pipe_name.starts_with(REQUIRED_PIPE_PREFIX)
        || pipe_name.encode_utf16().count() > MAX_PIPE_NAME_UNITS
        || pipe_name.contains('\0')
    {
        return Err(WindowsPlatformError::UnauthorizedLocalIpc);
    }
    ffi::create_private_named_pipe(pipe_name, first_instance)
}

/// Connection-bound authorization for the exact packaged Nodavo Windows UI.
///
/// The guard retains native process and token handles for the accepted pipe
/// client's lifetime. Its debug representation never exposes native identity
/// values, and callers cannot access the underlying handles.
pub struct AuthorizedWindowsUi {
    native: ffi::NativeNamedPipeClient,
    policy: WindowsUiPolicy,
    observed: ObservedWindowsUi,
}

impl std::fmt::Debug for AuthorizedWindowsUi {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AuthorizedWindowsUi([redacted])")
    }
}

impl AuthorizedWindowsUi {
    /// Revalidates the retained process/token and its exact package identity.
    ///
    /// Call this immediately before a blocking frame read and again after a
    /// successful decode, immediately before dispatching the command.
    ///
    /// # Errors
    ///
    /// Fails closed if the pipe endpoint, process lifetime, token statistics,
    /// package identity, AUMID, or package-relative executable changed.
    pub fn revalidate(&self) -> Result<(), WindowsPlatformError> {
        self.native.revalidate()?;
        if !authorizes_windows_ui(&self.policy, &self.observed) {
            return Err(WindowsPlatformError::UnauthorizedLocalIpc);
        }
        Ok(())
    }
}

/// Authorizes an accepted named-pipe client as the exact packaged Nodavo UI.
///
/// Ordinary and unpackaged builds have no embedded policy and always fail
/// closed. Development and release policy can only be selected at compile
/// time; no environment variable is consulted at runtime.
///
/// # Errors
///
/// Fails closed on an unconfigured build, missing package identity, any native
/// inspection failure, or any exact policy mismatch.
pub fn authorize_named_pipe_client(
    pipe: &tokio::net::windows::named_pipe::NamedPipeServer,
) -> Result<AuthorizedWindowsUi, WindowsPlatformError> {
    let (package_name, publisher) =
        compiled_windows_ui_identity().ok_or(WindowsPlatformError::UnauthorizedLocalIpc)?;
    let package_family_name = ffi::derive_package_family_name(package_name, publisher)?;
    let policy = compiled_windows_ui_policy(&package_family_name)
        .ok_or(WindowsPlatformError::UnauthorizedLocalIpc)?;
    let native = ffi::authenticate_named_pipe_client(pipe)?;
    let identity = native.package_identity();
    let observed = ObservedWindowsUi {
        package_full_name: identity.package_full_name.clone(),
        package_name: identity.package_name.clone(),
        publisher: identity.publisher.clone(),
        package_family_name: identity.package_family_name.clone(),
        application_user_model_id: identity.application_user_model_id.clone(),
        package_relative_executable: identity.package_relative_executable.clone(),
        processor_architecture: identity.processor_architecture,
        resource_id: identity.resource_id.clone(),
        publisher_id: identity.publisher_id.clone(),
    };
    if !authorizes_windows_ui(&policy, &observed) {
        return Err(WindowsPlatformError::UnauthorizedLocalIpc);
    }
    native.verify_signer(
        &policy.signer_certificate_sha256,
        policy.requires_trusted_timestamp,
    )?;
    native.revalidate()?;
    Ok(AuthorizedWindowsUi {
        native,
        policy,
        observed,
    })
}

/// Validates the complete compile-time Windows UI authorization policy.
///
/// This performs no client authorization and is intended for package build
/// self-checks before an artifact is assembled.
///
/// # Errors
///
/// Fails when the build is unconfigured or the embedded package identity,
/// PFN, signer certificate hash, application ID, or executable is inconsistent.
pub fn validate_compiled_windows_ui_auth_policy()
-> Result<crate::WindowsUiAuthMode, WindowsPlatformError> {
    let (package_name, publisher) =
        compiled_windows_ui_identity().ok_or(WindowsPlatformError::UnauthorizedLocalIpc)?;
    let package_family_name = ffi::derive_package_family_name(package_name, publisher)?;
    compiled_windows_ui_policy(&package_family_name)
        .ok_or(WindowsPlatformError::UnauthorizedLocalIpc)?;
    Ok(compiled_windows_ui_auth_mode())
}

/// Protects secret bytes with Windows DPAPI for the current user only.
///
/// No machine-wide flag or UI prompt is used. The returned opaque blob may be
/// persisted by the agent, but is not plaintext key material.
///
/// # Errors
///
/// Rejects empty/oversized input and any DPAPI or allocation failure.
pub fn protect_current_user_secret(
    secret: &[u8],
) -> Result<ProtectedSecretBlob, WindowsPlatformError> {
    if secret.is_empty() || secret.len() > MAX_PROTECTED_SECRET_BYTES {
        return Err(WindowsPlatformError::SecretTooLarge);
    }
    ProtectedSecretBlob::from_bytes(ffi::protect_current_user_secret(secret)?)
}

/// Decrypts an opaque blob with current-user DPAPI and returns zeroizing memory.
///
/// # Errors
///
/// Rejects oversized ciphertext/plaintext and blobs not protected for this user
/// with Nodavo's application entropy.
pub fn unprotect_current_user_secret(
    protected: &ProtectedSecretBlob,
) -> Result<zeroize::Zeroizing<Vec<u8>>, WindowsPlatformError> {
    if protected.as_bytes().len() > MAX_PROTECTED_SECRET_BLOB_BYTES {
        return Err(WindowsPlatformError::SecretTooLarge);
    }
    ffi::unprotect_current_user_secret(protected.as_bytes())
}

const MAX_TEXT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_IMAGE_BYTES: u64 = 100 * 1024 * 1024;

/// Probes the current unprivileged interactive session and input desktop.
///
/// # Errors
///
/// Fails closed when the process session or default input desktop is unavailable.
pub fn probe_environment() -> Result<EnvironmentCapabilities, WindowsPlatformError> {
    ffi::probe_environment()
}

/// Enumerates a bounded, mixed-DPI virtual display graph.
///
/// # Errors
///
/// Fails closed on session, desktop, enumeration, DPI, or geometry errors.
pub fn active_displays() -> Result<Vec<DisplayGeometry>, WindowsPlatformError> {
    probe_environment()?;
    let displays = ffi::enumerate_displays()?;
    if displays.is_empty() || displays.len() > MAX_DISPLAYS {
        return Err(WindowsPlatformError::InvalidDisplay);
    }
    Ok(displays)
}

/// Probes current-user input prerequisites without registering Raw Input,
/// enabling routing, suppressing or injecting input, requesting elevation, or
/// using a service.
#[must_use]
pub fn probe_readiness() -> WindowsReadinessProbe {
    let environment = match probe_environment() {
        Ok(environment) if environment.input_desktop_is_default => environment,
        Ok(_) | Err(WindowsPlatformError::SecureDesktop) => {
            return WindowsReadinessProbe {
                input: WindowsInputReadiness::BlockedByDesktop,
                local_topology_available: false,
            };
        }
        Err(_) => {
            return WindowsReadinessProbe {
                input: WindowsInputReadiness::Unavailable,
                local_topology_available: false,
            };
        }
    };
    let local_topology_available = active_displays().is_ok_and(|displays| !displays.is_empty());
    let input = if environment.send_input && environment.raw_input_capture {
        // Construction validates the default desktop and display graph but
        // never calls SendInput or registers a process-wide capture runtime.
        match WindowsInputInjector::new() {
            Ok(_injector) => WindowsInputReadiness::Ready,
            Err(WindowsPlatformError::SecureDesktop) => WindowsInputReadiness::BlockedByDesktop,
            Err(_) => WindowsInputReadiness::Unavailable,
        }
    } else {
        WindowsInputReadiness::Unavailable
    };
    WindowsReadinessProbe {
        input,
        local_topology_available,
    }
}

/// Unprivileged `SendInput` adapter with pressed-state recovery.
pub struct WindowsInputInjector {
    displays: Vec<DisplayGeometry>,
    pressed: PressedState,
}

impl WindowsInputInjector {
    /// Opens an injector only for the current default interactive desktop.
    ///
    /// # Errors
    ///
    /// Fails closed when session/desktop probing or display enumeration fails.
    pub fn new() -> Result<Self, WindowsPlatformError> {
        Ok(Self {
            displays: active_displays()?,
            pressed: PressedState::default(),
        })
    }

    /// Re-enumerates the mixed-DPI display graph.
    ///
    /// # Errors
    ///
    /// Fails closed if Windows reports an invalid or inaccessible display set.
    pub fn refresh_displays(&mut self) -> Result<(), WindowsPlatformError> {
        self.displays = active_displays()?;
        Ok(())
    }

    #[must_use]
    pub fn displays(&self) -> &[DisplayGeometry] {
        &self.displays
    }

    /// Injects one semantic event after re-checking the interactive desktop.
    ///
    /// # Errors
    ///
    /// Rejects unsupported HID usages, invalid display geometry, secure-desktop
    /// transitions, and partial or blocked `SendInput` calls.
    pub fn inject(&mut self, event: InputEvent) -> Result<(), WindowsPlatformError> {
        probe_environment()?;
        self.send_event(event)?;
        self.pressed.apply(&event);
        Ok(())
    }

    /// Releases every tracked key/button in deterministic core-model order.
    ///
    /// This is the integration point for disconnect, lock, sleep, timeout, and
    /// emergency-stop recovery. Failed releases remain tracked for retry.
    ///
    /// # Errors
    ///
    /// Returns [`WindowsPlatformError::ReleaseIncomplete`] if any release could
    /// not be injected, or the session is no longer on the default desktop.
    pub fn force_release_all(
        &mut self,
    ) -> Result<ForceReleaseAcknowledgement, WindowsPlatformError> {
        probe_environment()?;
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
            Err(WindowsPlatformError::ReleaseIncomplete)
        }
    }

    #[must_use]
    pub fn pressed_input_is_clear(&self) -> bool {
        self.pressed.is_empty()
    }

    fn send_event(&self, event: InputEvent) -> Result<(), WindowsPlatformError> {
        let native = match event {
            InputEvent::Key { usage, state, .. } => keyboard_input(usage, state)?,
            InputEvent::PointerMotion { position } => {
                let display = self
                    .displays
                    .iter()
                    .copied()
                    .find(|display| display.id == position.display())
                    .ok_or(WindowsPlatformError::UnknownDisplay)?;
                let (x, y) = display.map_position(position)?;
                let bounds = virtual_desktop_bounds(&self.displays)?;
                let absolute_x = normalize_virtual_axis(x, bounds.0, bounds.2)?;
                let absolute_y = normalize_virtual_axis(y, bounds.1, bounds.3)?;
                ffi::NativeInput::AbsoluteMotion {
                    x: absolute_x,
                    y: absolute_y,
                }
            }
            InputEvent::PointerDelta { delta } => ffi::NativeInput::RelativeMotion {
                delta_x: delta.horizontal(),
                delta_y: delta.vertical(),
            },
            InputEvent::PointerButton { button, state } => pointer_button(button.get(), state)?,
            InputEvent::Scroll {
                horizontal,
                vertical,
                unit,
            } => {
                let multiplier = match unit {
                    ScrollUnit::Lines => 120,
                    ScrollUnit::Precise => 1,
                };
                ffi::NativeInput::Scroll {
                    horizontal: horizontal
                        .checked_mul(multiplier)
                        .ok_or(WindowsPlatformError::InputBlocked)?,
                    vertical: vertical
                        .checked_mul(multiplier)
                        .ok_or(WindowsPlatformError::InputBlocked)?,
                }
            }
        };
        ffi::send_input(native)
    }
}

type CaptureCallback =
    dyn Fn(WindowsInputCaptureEvent) -> Result<(), WindowsPlatformError> + Send + Sync + 'static;

struct CaptureRuntime {
    stop: ffi::NativeInputCaptureStopHandle,
    worker: JoinHandle<Result<(), WindowsPlatformError>>,
}

/// Owned, restartable Raw Input runtime for the current interactive session.
///
/// A dedicated message-only window owns Raw Input registration, WTS/power
/// lifecycle notifications, and low-level hooks. Hooks classify origin and
/// optionally suppress already-supported physical events; only Raw Input is
/// translated to semantic events. Suppression is disabled by default and is
/// cleared on stop, lock, disconnect, suspend, or default-desktop loss.
pub struct WindowsInputCapture {
    callback: Arc<CaptureCallback>,
    routing_to_peer: Arc<AtomicBool>,
    runtime: Option<CaptureRuntime>,
}

impl fmt::Debug for WindowsInputCapture {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsInputCapture")
            .field("running", &self.is_running())
            .field("routing_to_peer", &self.routing_to_peer())
            .finish_non_exhaustive()
    }
}

impl WindowsInputCapture {
    #[must_use]
    pub fn new(callback: impl Fn(WindowsInputCaptureEvent) + Send + Sync + 'static) -> Self {
        Self::new_routed_fallible(move |event| {
            callback(event);
            Ok(())
        })
    }

    /// Creates a capture boundary whose callback may request fail-closed stop.
    ///
    /// A callback error immediately clears routing and terminates the native
    /// capture loop. This lets bounded consumers refuse reliable input rather
    /// than suppressing an event that could not be delivered to the session.
    #[must_use]
    pub fn new_routed_fallible(
        callback: impl Fn(WindowsInputCaptureEvent) -> Result<(), WindowsPlatformError>
        + Send
        + Sync
        + 'static,
    ) -> Self {
        Self {
            callback: Arc::new(callback),
            routing_to_peer: Arc::new(AtomicBool::new(false)),
            runtime: None,
        }
    }

    /// Starts a fresh message-only Raw Input runtime on a dedicated thread.
    ///
    /// # Errors
    ///
    /// Fails closed outside the default interactive desktop, when a window,
    /// registration, hook, or worker cannot be created, or when already running.
    pub fn start(&mut self) -> Result<(), WindowsPlatformError> {
        if self.runtime.is_some() {
            return Err(WindowsPlatformError::CaptureAlreadyRunning);
        }
        probe_environment()?;
        let displays = active_displays()?;
        let callback = Arc::clone(&self.callback);
        let routing_to_peer = Arc::clone(&self.routing_to_peer);
        routing_to_peer.store(false, Ordering::Release);
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("nodavo-windows-input".into())
            .spawn(move || {
                let event_callback = Arc::clone(&callback);
                let event_routing = Arc::clone(&routing_to_peer);
                let mut translator = CaptureTranslator::new(ffi::current_modifier_state());
                let capture = ffi::NativeInputCapture::new(
                    Arc::clone(&routing_to_peer),
                    move |native: NativeInputEvent| {
                        let relative_pointer = event_routing.load(Ordering::Acquire);
                        if relative_pointer
                            && let NativeInputEvent::PointerMotion {
                                delta_x, delta_y, ..
                            } = native
                            && (delta_x != 0 || delta_y != 0)
                            && PointerDelta::new(delta_x, delta_y).is_err()
                        {
                            return Err(WindowsPlatformError::RawInputUnavailable);
                        }
                        let Some(event) = translator.convert(native, &displays, relative_pointer)
                        else {
                            return Ok(());
                        };
                        if let WindowsInputCaptureEvent::Lifecycle(lifecycle) = event
                            && lifecycle_requires_local_recovery(lifecycle)
                        {
                            event_routing.store(false, Ordering::Release);
                        }
                        event_callback(event)
                    },
                );
                let mut capture = match capture {
                    Ok(capture) => capture,
                    Err(error) => {
                        let _ = ready_tx.send(Err(error));
                        return Err(error);
                    }
                };
                let stop = capture.stop_handle();
                if ready_tx.send(Ok(stop)).is_err() {
                    return Err(WindowsPlatformError::CaptureThread);
                }
                emit_callback(
                    callback.as_ref(),
                    WindowsInputLifecycleEvent::CaptureStarted,
                )?;
                let result = capture.run();
                routing_to_peer.store(false, Ordering::Release);
                if result.is_ok() {
                    emit_callback(
                        callback.as_ref(),
                        WindowsInputLifecycleEvent::CaptureStopped,
                    )?;
                }
                result
            })
            .map_err(|_| WindowsPlatformError::CaptureThread)?;

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
                Err(WindowsPlatformError::CaptureThread)
            }
        }
    }

    /// Enables or disables suppression of supported physical input.
    ///
    /// # Errors
    ///
    /// Enabling is refused without a live capture or outside the current default
    /// interactive desktop. Disabling is always allowed and immediate.
    pub fn set_routing_to_peer(&self, enabled: bool) -> Result<(), WindowsPlatformError> {
        if enabled {
            if !self.is_running() {
                return Err(WindowsPlatformError::CaptureNotRunning);
            }
            probe_environment()?;
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

    /// Stops the capture thread and waits for terminal acknowledgement.
    ///
    /// # Errors
    ///
    /// Returns the terminal capture/callback failure or a worker panic.
    pub fn stop(&mut self) -> Result<(), WindowsPlatformError> {
        self.routing_to_peer.store(false, Ordering::Release);
        let Some(runtime) = self.runtime.take() else {
            return Ok(());
        };
        if !runtime.worker.is_finished() {
            runtime.stop.stop()?;
        }
        runtime
            .worker
            .join()
            .map_err(|_| WindowsPlatformError::CaptureThread)?
    }

    /// Stops any owned runtime and starts a fresh capture boundary.
    ///
    /// # Errors
    ///
    /// Returns any terminal stop failure or fresh startup failure.
    pub fn restart(&mut self) -> Result<(), WindowsPlatformError> {
        self.stop()?;
        self.start()
    }

    /// Waits for a naturally terminating runtime without requesting stop.
    ///
    /// # Errors
    ///
    /// Returns [`WindowsPlatformError::CaptureNotRunning`] if no runtime is
    /// owned, or the terminal native/callback failure.
    pub fn wait(&mut self) -> Result<(), WindowsPlatformError> {
        let Some(runtime) = self.runtime.take() else {
            return Err(WindowsPlatformError::CaptureNotRunning);
        };
        runtime
            .worker
            .join()
            .map_err(|_| WindowsPlatformError::CaptureThread)?
    }
}

impl Drop for WindowsInputCapture {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

/// Runs non-suppressing input capture until the native loop terminates.
///
/// # Errors
///
/// Returns an error for session, desktop, Raw Input, hook, worker, or callback
/// failures.
pub fn run_input_capture(
    on_input: impl Fn(InputEvent) + Send + Sync + 'static,
) -> Result<(), WindowsPlatformError> {
    let mut capture = WindowsInputCapture::new(move |event| {
        if let WindowsInputCaptureEvent::Input(input) = event {
            on_input(input);
        }
    });
    capture.start()?;
    capture.wait()
}

fn emit_callback(
    callback: &CaptureCallback,
    lifecycle: WindowsInputLifecycleEvent,
) -> Result<(), WindowsPlatformError> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        callback(WindowsInputCaptureEvent::Lifecycle(lifecycle))
    }))
    .map_err(|_| WindowsPlatformError::CaptureCallbackFailed)?
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

fn keyboard_input(
    usage: HidUsage,
    state: KeyState,
) -> Result<ffi::NativeInput, WindowsPlatformError> {
    let released = state == KeyState::Released;
    match usage.page() {
        KEYBOARD_PAGE => {
            let (scan_code, extended) =
                hid_keyboard_scan_code(usage.id()).ok_or(WindowsPlatformError::UnsupportedKey)?;
            Ok(ffi::NativeInput::ScanCodeKey {
                scan_code,
                extended,
                released,
            })
        }
        CONSUMER_PAGE => {
            let virtual_key = match usage.id() {
                0x00b5 => 0xb0, // next track
                0x00b6 => 0xb1, // previous track
                0x00b7 => 0xb2, // stop
                0x00cd => 0xb3, // play/pause
                0x00e2 => 0xad, // mute
                0x00e9 => 0xaf, // volume up
                0x00ea => 0xae, // volume down
                _ => return Err(WindowsPlatformError::UnsupportedKey),
            };
            Ok(ffi::NativeInput::VirtualKey {
                virtual_key,
                released,
            })
        }
        _ => Err(WindowsPlatformError::UnsupportedKey),
    }
}

#[allow(clippy::too_many_lines)]
const fn hid_keyboard_scan_code(usage: u16) -> Option<(u16, bool)> {
    let mapping = match usage {
        0x04 => (0x1e, false),
        0x05 => (0x30, false),
        0x06 => (0x2e, false),
        0x07 => (0x20, false),
        0x08 => (0x12, false),
        0x09 => (0x21, false),
        0x0a => (0x22, false),
        0x0b => (0x23, false),
        0x0c => (0x17, false),
        0x0d => (0x24, false),
        0x0e => (0x25, false),
        0x0f => (0x26, false),
        0x10 => (0x32, false),
        0x11 => (0x31, false),
        0x12 => (0x18, false),
        0x13 => (0x19, false),
        0x14 => (0x10, false),
        0x15 => (0x13, false),
        0x16 => (0x1f, false),
        0x17 => (0x14, false),
        0x18 => (0x16, false),
        0x19 => (0x2f, false),
        0x1a => (0x11, false),
        0x1b => (0x2d, false),
        0x1c => (0x15, false),
        0x1d => (0x2c, false),
        0x1e => (0x02, false),
        0x1f => (0x03, false),
        0x20 => (0x04, false),
        0x21 => (0x05, false),
        0x22 => (0x06, false),
        0x23 => (0x07, false),
        0x24 => (0x08, false),
        0x25 => (0x09, false),
        0x26 => (0x0a, false),
        0x27 => (0x0b, false),
        0x28 => (0x1c, false),
        0x29 => (0x01, false),
        0x2a => (0x0e, false),
        0x2b => (0x0f, false),
        0x2c => (0x39, false),
        0x2d => (0x0c, false),
        0x2e => (0x0d, false),
        0x2f => (0x1a, false),
        0x30 => (0x1b, false),
        0x31 => (0x2b, false),
        0x33 => (0x27, false),
        0x34 => (0x28, false),
        0x35 => (0x29, false),
        0x36 => (0x33, false),
        0x37 => (0x34, false),
        0x38 => (0x35, false),
        0x39 => (0x3a, false),
        0x3a..=0x43 => (0x3b + usage - 0x3a, false),
        0x44 => (0x57, false),
        0x45 => (0x58, false),
        0x49 => (0x52, true),
        0x4a => (0x47, true),
        0x4b => (0x49, true),
        0x4c => (0x53, true),
        0x4d => (0x4f, true),
        0x4e => (0x51, true),
        0x4f => (0x4d, true),
        0x50 => (0x4b, true),
        0x51 => (0x50, true),
        0x52 => (0x48, true),
        0x53 => (0x45, true),
        0x54 => (0x35, true),
        0x55 => (0x37, false),
        0x56 => (0x4a, false),
        0x57 => (0x4e, false),
        0x58 => (0x1c, true),
        0x59 => (0x4f, false),
        0x5a => (0x50, false),
        0x5b => (0x51, false),
        0x5c => (0x4b, false),
        0x5d => (0x4c, false),
        0x5e => (0x4d, false),
        0x5f => (0x47, false),
        0x60 => (0x48, false),
        0x61 => (0x49, false),
        0x62 => (0x52, false),
        0x63 => (0x53, false),
        0xe0 => (0x1d, false),
        0xe1 => (0x2a, false),
        0xe2 => (0x38, false),
        0xe3 => (0x5b, true),
        0xe4 => (0x1d, true),
        0xe5 => (0x36, false),
        0xe6 => (0x38, true),
        0xe7 => (0x5c, true),
        _ => return None,
    };
    Some(mapping)
}

fn pointer_button(
    number: u8,
    state: ButtonState,
) -> Result<ffi::NativeInput, WindowsPlatformError> {
    if !(1..=5).contains(&number) {
        return Err(WindowsPlatformError::UnsupportedButton);
    }
    Ok(ffi::NativeInput::Button {
        number,
        released: state == ButtonState::Released,
    })
}

fn virtual_desktop_bounds(
    displays: &[DisplayGeometry],
) -> Result<(i32, i32, u32, u32), WindowsPlatformError> {
    let left = displays
        .iter()
        .map(|display| display.left)
        .min()
        .ok_or(WindowsPlatformError::InvalidDisplay)?;
    let top = displays
        .iter()
        .map(|display| display.top)
        .min()
        .ok_or(WindowsPlatformError::InvalidDisplay)?;
    let right = displays
        .iter()
        .map(|display| i64::from(display.left) + i64::from(display.width_pixels))
        .max()
        .ok_or(WindowsPlatformError::InvalidDisplay)?;
    let bottom = displays
        .iter()
        .map(|display| i64::from(display.top) + i64::from(display.height_pixels))
        .max()
        .ok_or(WindowsPlatformError::InvalidDisplay)?;
    let width =
        u32::try_from(right - i64::from(left)).map_err(|_| WindowsPlatformError::InvalidDisplay)?;
    let height =
        u32::try_from(bottom - i64::from(top)).map_err(|_| WindowsPlatformError::InvalidDisplay)?;
    if width == 0 || height == 0 {
        return Err(WindowsPlatformError::InvalidDisplay);
    }
    Ok((left, top, width, height))
}

fn normalize_virtual_axis(
    coordinate: i32,
    origin: i32,
    extent: u32,
) -> Result<i32, WindowsPlatformError> {
    let maximum = extent
        .checked_sub(1)
        .ok_or(WindowsPlatformError::InvalidDisplay)?;
    let offset = i64::from(coordinate) - i64::from(origin);
    if offset < 0 || offset > i64::from(maximum) {
        return Err(WindowsPlatformError::InvalidDisplay);
    }
    let normalized = (u64::try_from(offset).map_err(|_| WindowsPlatformError::InvalidDisplay)?
        * u64::from(u16::MAX)
        + u64::from(maximum) / 2)
        / u64::from(maximum.max(1));
    i32::try_from(normalized).map_err(|_| WindowsPlatformError::InvalidDisplay)
}

/// Clipboard boundary tied to the current interactive desktop.
#[derive(Clone, Copy, Debug, Default)]
pub struct WindowsClipboard;

impl WindowsClipboard {
    /// Creates a clipboard boundary after probing the current desktop.
    ///
    /// # Errors
    ///
    /// Fails closed outside the default interactive desktop.
    pub fn new() -> Result<Self, WindowsPlatformError> {
        probe_environment()?;
        Ok(Self)
    }

    /// Returns the native clipboard change sequence.
    ///
    /// # Errors
    ///
    /// Returns an error when Windows cannot provide a usable sequence value.
    pub fn sequence_number(self) -> Result<u32, WindowsPlatformError> {
        probe_environment()?;
        ffi::clipboard_sequence_number()
    }

    /// Reads bounded metadata for UTF-16 text, `CF_HTML`, registered PNG, and
    /// canonical BMP representations.
    ///
    /// # Errors
    ///
    /// Fails if the clipboard changes during the observation, is busy, or any
    /// advertised supported representation exceeds its hard bound.
    pub fn metadata(self) -> Result<ClipboardMetadata, WindowsPlatformError> {
        probe_environment()?;
        ffi::clipboard_metadata()
    }

    /// Reads `CF_UNICODETEXT` only if `expected_sequence` is still current.
    ///
    /// # Errors
    ///
    /// Rejects stale, missing, oversized, unterminated, or malformed text.
    pub fn read_text(self, expected_sequence: u32) -> Result<String, WindowsPlatformError> {
        probe_environment()?;
        ffi::read_clipboard_text(expected_sequence, MAX_TEXT_BYTES)
    }

    /// Replaces the clipboard with bounded `CF_UNICODETEXT`.
    ///
    /// # Errors
    ///
    /// Rejects embedded NULs, oversized content, busy clipboard state, and
    /// native ownership-transfer failures.
    pub fn write_text(self, text: &str) -> Result<u32, WindowsPlatformError> {
        probe_environment()?;
        ffi::write_clipboard_text(text, MAX_TEXT_BYTES)
    }

    /// Reads the bounded UTF-8 fragment from registered `HTML Format` data.
    ///
    /// # Errors
    ///
    /// Rejects stale sequences, malformed `CF_HTML` offsets, embedded NULs,
    /// invalid UTF-8, and content outside the text limit.
    pub fn read_html(self, expected_sequence: u32) -> Result<String, WindowsPlatformError> {
        probe_environment()?;
        ffi::read_clipboard_html(expected_sequence, MAX_TEXT_BYTES)
    }

    /// Replaces the clipboard with a bounded UTF-8 `CF_HTML` fragment.
    ///
    /// # Errors
    ///
    /// Rejects embedded NULs, oversized fragments, a busy clipboard, and
    /// native ownership-transfer failures.
    pub fn write_html(self, fragment: &str) -> Result<u32, WindowsPlatformError> {
        probe_environment()?;
        ffi::write_clipboard_html(fragment, MAX_TEXT_BYTES)
    }

    /// Reads validated PNG file bytes from the registered `PNG` format.
    ///
    /// # Errors
    ///
    /// Rejects stale sequences, absent data, malformed chunks or CRCs, and
    /// content outside the image limit.
    pub fn read_png(self, expected_sequence: u32) -> Result<Vec<u8>, WindowsPlatformError> {
        probe_environment()?;
        ffi::read_clipboard_png(expected_sequence, MAX_IMAGE_BYTES)
    }

    /// Replaces the clipboard with validated PNG file bytes.
    ///
    /// # Errors
    ///
    /// Rejects malformed or oversized PNG data, a busy clipboard, and native
    /// ownership-transfer failures.
    pub fn write_png(self, png: &[u8]) -> Result<u32, WindowsPlatformError> {
        probe_environment()?;
        ffi::write_clipboard_png(png, MAX_IMAGE_BYTES)
    }

    /// Reads a strict DIB/DIBV5 representation as canonical BMP file bytes.
    ///
    /// # Errors
    ///
    /// Rejects stale sequences, unsupported DIB compression/profile layouts,
    /// inconsistent offsets, and content outside the image limit.
    pub fn read_bmp(self, expected_sequence: u32) -> Result<Vec<u8>, WindowsPlatformError> {
        probe_environment()?;
        ffi::read_clipboard_bmp(expected_sequence, MAX_IMAGE_BYTES)
    }

    /// Replaces the clipboard with a DIB derived from canonical BMP bytes.
    ///
    /// # Errors
    ///
    /// Rejects malformed headers, unsupported compression/profile layouts,
    /// inconsistent offsets, oversized content, and native write failures.
    pub fn write_bmp(self, bmp: &[u8]) -> Result<u32, WindowsPlatformError> {
        probe_environment()?;
        ffi::write_clipboard_bmp(bmp, MAX_IMAGE_BYTES)
    }

    /// Empties the native clipboard.
    ///
    /// # Errors
    ///
    /// Fails if the default interactive desktop is unavailable or Windows
    /// cannot open and empty the clipboard.
    pub fn clear(self) -> Result<u32, WindowsPlatformError> {
        probe_environment()?;
        ffi::clear_clipboard()
    }

    /// Reads one bounded `CF_DIB` or `CF_DIBV5` memory block.
    ///
    /// # Errors
    ///
    /// Rejects text format requests, stale sequence values, absent data, and
    /// image blocks outside the clipboard image limit.
    pub fn read_image(
        self,
        format: ClipboardFormat,
        expected_sequence: u32,
    ) -> Result<Vec<u8>, WindowsPlatformError> {
        probe_environment()?;
        if !matches!(format, ClipboardFormat::Dib | ClipboardFormat::DibV5) {
            return Err(WindowsPlatformError::InvalidClipboardImage);
        }
        ffi::read_clipboard_image(format, expected_sequence, MAX_IMAGE_BYTES)
    }

    /// Replaces the clipboard with one bounded DIB memory block.
    ///
    /// # Errors
    ///
    /// Rejects text format requests, empty/oversized data, busy clipboard state,
    /// and native ownership-transfer failures. This boundary does not parse or
    /// render the image.
    pub fn write_image(
        self,
        format: ClipboardFormat,
        dib: &[u8],
    ) -> Result<u32, WindowsPlatformError> {
        probe_environment()?;
        if !matches!(format, ClipboardFormat::Dib | ClipboardFormat::DibV5) || dib.is_empty() {
            return Err(WindowsPlatformError::InvalidClipboardImage);
        }
        ffi::write_clipboard_image(format, dib, MAX_IMAGE_BYTES)
    }
}

#[cfg(test)]
mod tests {
    use tokio::net::windows::named_pipe::ClientOptions;

    use super::*;

    #[tokio::test]
    async fn private_pipe_rejects_an_unpackaged_current_process() {
        let pipe_name = format!(r"\\.\pipe\nodavo-test-{}", std::process::id());
        let server = create_private_named_pipe(&pipe_name, true).unwrap();
        let _client = ClientOptions::new().open(&pipe_name).unwrap();
        server.connect().await.unwrap();
        assert_eq!(
            authorize_named_pipe_client(&server).unwrap_err(),
            WindowsPlatformError::UnauthorizedLocalIpc
        );
    }

    #[test]
    #[ignore = "requires a real interactive Windows default desktop"]
    fn input_capture_starts_and_stops_without_enabling_suppression() {
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let received = Arc::clone(&events);
        let mut capture = WindowsInputCapture::new(move |event| {
            received.lock().unwrap().push(event);
        });
        capture.start().unwrap();
        assert!(capture.is_running());
        assert!(!capture.routing_to_peer());
        capture.stop().unwrap();
        let events = events.lock().unwrap();
        assert!(events.contains(&WindowsInputCaptureEvent::Lifecycle(
            WindowsInputLifecycleEvent::CaptureStarted
        )));
        assert!(events.contains(&WindowsInputCaptureEvent::Lifecycle(
            WindowsInputLifecycleEvent::CaptureStopped
        )));
    }
}
