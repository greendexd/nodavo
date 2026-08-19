//! Safe Windows-specific orchestration over the isolated FFI wrappers.

pub(crate) mod ffi;

use std::fmt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex, OnceLock, RwLock, Weak};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use nodavo_input::{
    ButtonState, CONSUMER_PAGE, HidUsage, InputEvent, KEYBOARD_PAGE, KeyState, PointerDelta,
    PressedState, ScrollUnit,
};

use crate::display_runtime::{DisplayTracker, DisplayTrackerUpdate, DisplayWorkerLifecycle};
use crate::input_runtime::{
    CaptureTranslator, ForceReleaseAcknowledgement, NativeInputEvent, NativeRoutingObservation,
    RoutingAdmission, lifecycle_requires_local_recovery,
};
use crate::windows_ipc_policy::{
    ObservedWindowsUi, WindowsUiPolicy, authorizes_windows_ui, compiled_windows_ui_identity,
    compiled_windows_ui_policy,
};
use crate::{
    ClipboardFormat, ClipboardMetadata, DisplayGeometry, DisplaySnapshot, DisplaySnapshotState,
    EnvironmentCapabilities, MAX_PROTECTED_SECRET_BLOB_BYTES, MAX_PROTECTED_SECRET_BYTES,
    ProtectedSecretBlob, WindowsInputCaptureEvent, WindowsInputLifecycleEvent,
    WindowsInputReadiness, WindowsPlatformError, WindowsReadinessProbe,
};

pub use crate::windows_ipc_policy::compiled_windows_ui_auth_mode;

const MAX_PIPE_NAME_UNITS: usize = 240;
const REQUIRED_PIPE_PREFIX: &str = r"\\.\pipe\nodavo-";
const INITIAL_DISPLAY_SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(3);
#[cfg(not(test))]
const DISPLAY_JOIN_TIMEOUT: Duration = Duration::from_secs(2);
#[cfg(test)]
const DISPLAY_JOIN_TIMEOUT: Duration = Duration::from_millis(50);
#[cfg(not(test))]
const CAPTURE_JOIN_TIMEOUT: Duration = Duration::from_secs(2);
#[cfg(test)]
const CAPTURE_JOIN_TIMEOUT: Duration = Duration::from_millis(50);

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
    ffi::ensure_process_dpi_awareness()?;
    ffi::probe_environment()
}

struct SharedDisplayState {
    snapshot: RwLock<DisplaySnapshotState>,
    routing_flags: Mutex<Vec<Weak<RoutingAdmission>>>,
    active_generation: AtomicU64,
    worker_running: AtomicBool,
    changed: Condvar,
    wait_state: Mutex<bool>,
}

impl Default for SharedDisplayState {
    fn default() -> Self {
        Self {
            snapshot: RwLock::new(DisplaySnapshotState::Pending),
            routing_flags: Mutex::new(Vec::new()),
            active_generation: AtomicU64::new(0),
            worker_running: AtomicBool::new(false),
            changed: Condvar::new(),
            wait_state: Mutex::new(false),
        }
    }
}

impl SharedDisplayState {
    fn snapshot_state(&self) -> DisplaySnapshotState {
        self.snapshot
            .read()
            .map_or(DisplaySnapshotState::Unavailable, |state| state.clone())
    }

    fn snapshot(&self) -> Result<DisplaySnapshot, WindowsPlatformError> {
        match self.snapshot_state() {
            DisplaySnapshotState::Available(snapshot) => Ok(snapshot),
            DisplaySnapshotState::Pending | DisplaySnapshotState::Unavailable => {
                Err(WindowsPlatformError::DisplayUnavailable)
            }
        }
    }

    fn consume_snapshot(
        &self,
        observed_revision: &AtomicU64,
    ) -> Result<DisplaySnapshot, WindowsPlatformError> {
        let state = self
            .snapshot
            .read()
            .map_err(|_| WindowsPlatformError::DisplayUnavailable)?;
        let DisplaySnapshotState::Available(snapshot) = &*state else {
            return Err(WindowsPlatformError::DisplayUnavailable);
        };
        observed_revision.store(snapshot.revision(), Ordering::Release);
        Ok(snapshot.clone())
    }

    fn pending_for(&self, observed_revision: &AtomicU64) -> bool {
        let Ok(state) = self.snapshot.read() else {
            return true;
        };
        match &*state {
            DisplaySnapshotState::Available(snapshot) => {
                snapshot.revision() != observed_revision.load(Ordering::Acquire)
            }
            DisplaySnapshotState::Pending | DisplaySnapshotState::Unavailable => true,
        }
    }

    fn revision_is_current(&self, revision: u64) -> bool {
        matches!(
            self.snapshot_state(),
            DisplaySnapshotState::Available(snapshot) if snapshot.revision() == revision
        )
    }

    fn with_available_snapshot<T>(
        &self,
        operation: impl FnOnce(&DisplaySnapshot) -> Result<T, WindowsPlatformError>,
    ) -> Result<T, WindowsPlatformError> {
        let state = self
            .snapshot
            .read()
            .map_err(|_| WindowsPlatformError::DisplayUnavailable)?;
        let DisplaySnapshotState::Available(snapshot) = &*state else {
            return Err(WindowsPlatformError::DisplayUnavailable);
        };
        if !self.worker_running.load(Ordering::Acquire) {
            return Err(WindowsPlatformError::DisplayUnavailable);
        }
        operation(snapshot)
    }

    fn enable_routing(&self, routing: &RoutingAdmission) -> Result<(), WindowsPlatformError> {
        self.enable_routing_after(routing, || {})
    }

    fn enable_routing_after(
        &self,
        routing: &RoutingAdmission,
        before_enable: impl FnOnce(),
    ) -> Result<(), WindowsPlatformError> {
        let result = self.with_available_snapshot(|_| {
            // The display worker must acquire the snapshot write lock before it
            // can publish Pending/Unavailable and clear routing. Keeping the
            // read lock through enable makes those operations one ordered
            // authority transition instead of a check-then-enable race.
            before_enable();
            routing.enable()
        });
        if matches!(result, Err(WindowsPlatformError::DisplayUnavailable)) {
            routing.disable_fail_closed();
        }
        result
    }

    fn register_routing_flag(
        &self,
        routing: &Arc<RoutingAdmission>,
    ) -> Result<(), WindowsPlatformError> {
        let Ok(mut flags) = self.routing_flags.lock() else {
            routing.disable_fail_closed();
            return Err(WindowsPlatformError::DisplayUnavailable);
        };
        flags.retain(|flag| flag.strong_count() > 0);
        let routing = Arc::downgrade(routing);
        if !flags.iter().any(|registered| registered.ptr_eq(&routing)) {
            flags.push(routing);
        }
        Ok(())
    }

    fn clear_routing(&self) {
        if let Ok(mut flags) = self.routing_flags.lock() {
            flags.retain(|flag| {
                let Some(flag) = flag.upgrade() else {
                    return false;
                };
                flag.disable_fail_closed();
                true
            });
        }
    }

    #[cfg(test)]
    fn apply(&self, update: DisplayTrackerUpdate) {
        let next = match update {
            DisplayTrackerUpdate::Unchanged => return,
            DisplayTrackerUpdate::Pending => DisplaySnapshotState::Pending,
            DisplayTrackerUpdate::Available(snapshot) => DisplaySnapshotState::Available(snapshot),
            DisplayTrackerUpdate::Unavailable => DisplaySnapshotState::Unavailable,
        };
        if !matches!(next, DisplaySnapshotState::Available(_)) {
            self.clear_routing();
        }
        if let Ok(mut snapshot) = self.snapshot.write() {
            *snapshot = next;
        } else {
            self.clear_routing();
        }
        self.notify_waiters();
    }

    fn begin_worker(&self, generation: u64) -> Result<(), WindowsPlatformError> {
        let mut snapshot = self
            .snapshot
            .write()
            .map_err(|_| WindowsPlatformError::DisplayUnavailable)?;
        self.active_generation.store(generation, Ordering::Release);
        self.worker_running.store(false, Ordering::Release);
        *snapshot = DisplaySnapshotState::Pending;
        drop(snapshot);
        self.clear_routing();
        self.notify_waiters();
        Ok(())
    }

    fn apply_worker(&self, generation: u64, update: DisplayTrackerUpdate) {
        if matches!(update, DisplayTrackerUpdate::Unchanged) {
            return;
        }
        let Ok(mut snapshot) = self.snapshot.write() else {
            self.clear_routing();
            return;
        };
        if self.active_generation.load(Ordering::Acquire) != generation {
            return;
        }
        let next = match update {
            DisplayTrackerUpdate::Unchanged => return,
            DisplayTrackerUpdate::Pending => DisplaySnapshotState::Pending,
            DisplayTrackerUpdate::Available(snapshot) => DisplaySnapshotState::Available(snapshot),
            DisplayTrackerUpdate::Unavailable => DisplaySnapshotState::Unavailable,
        };
        if !matches!(next, DisplaySnapshotState::Available(_)) {
            self.clear_routing();
        }
        *snapshot = next;
        drop(snapshot);
        self.notify_waiters();
    }

    fn set_worker_running(&self, generation: u64, running: bool) {
        let Ok(snapshot) = self.snapshot.write() else {
            self.clear_routing();
            return;
        };
        if self.active_generation.load(Ordering::Acquire) != generation {
            return;
        }
        self.worker_running.store(running, Ordering::Release);
        drop(snapshot);
        self.notify_waiters();
    }

    fn finish_worker(&self, generation: u64) {
        let Ok(mut snapshot) = self.snapshot.write() else {
            self.clear_routing();
            return;
        };
        if self.active_generation.load(Ordering::Acquire) != generation {
            return;
        }
        self.worker_running.store(false, Ordering::Release);
        *snapshot = DisplaySnapshotState::Unavailable;
        drop(snapshot);
        self.clear_routing();
        self.notify_waiters();
    }

    fn retire_worker(&self, generation: u64) {
        let Ok(mut snapshot) = self.snapshot.write() else {
            self.clear_routing();
            return;
        };
        if self.active_generation.load(Ordering::Acquire) != generation {
            return;
        }
        self.active_generation.store(0, Ordering::Release);
        self.worker_running.store(false, Ordering::Release);
        *snapshot = DisplaySnapshotState::Unavailable;
        drop(snapshot);
        self.clear_routing();
        self.notify_waiters();
    }

    fn notify_waiters(&self) {
        if let Ok(mut changed) = self.wait_state.lock() {
            *changed = !*changed;
            self.changed.notify_all();
        }
    }

    fn wait_for_snapshot(
        &self,
        timeout: Duration,
    ) -> Result<DisplaySnapshot, WindowsPlatformError> {
        let deadline = Instant::now() + timeout;
        let mut wait_state = self
            .wait_state
            .lock()
            .map_err(|_| WindowsPlatformError::DisplayUnavailable)?;
        loop {
            if let Ok(snapshot) = self.snapshot() {
                return Ok(snapshot);
            }
            if !self.worker_running.load(Ordering::Acquire) {
                return Err(WindowsPlatformError::DisplayUnavailable);
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(WindowsPlatformError::DisplayUnavailable);
            }
            let duration = deadline.saturating_duration_since(now);
            let observed = *wait_state;
            let (next, timed_out) = self
                .changed
                .wait_timeout_while(wait_state, duration, |state| *state == observed)
                .map_err(|_| WindowsPlatformError::DisplayUnavailable)?;
            wait_state = next;
            if timed_out.timed_out() && self.snapshot().is_err() {
                return Err(WindowsPlatformError::DisplayUnavailable);
            }
        }
    }
}

struct DisplayWorker {
    generation: u64,
    stop: ffi::NativeDisplayMonitorStopHandle,
    worker: JoinHandle<Result<(), WindowsPlatformError>>,
}

struct DisplayService {
    state: Arc<SharedDisplayState>,
    runtime: Mutex<Option<DisplayWorker>>,
    process: Arc<DisplayProcessState>,
}

fn process_display_tracker() -> Arc<Mutex<DisplayTracker>> {
    static TRACKER: OnceLock<Arc<Mutex<DisplayTracker>>> = OnceLock::new();
    Arc::clone(TRACKER.get_or_init(|| Arc::new(Mutex::new(DisplayTracker::default()))))
}

struct DisplayProcessState {
    lifecycle: DisplayWorkerLifecycle,
    status: Mutex<DisplayProcessStatus>,
}

#[derive(Default)]
struct DisplayProcessStatus {
    active: bool,
    poisoned: bool,
}

impl Default for DisplayProcessState {
    fn default() -> Self {
        Self {
            lifecycle: DisplayWorkerLifecycle::default(),
            status: Mutex::new(DisplayProcessStatus::default()),
        }
    }
}

impl DisplayProcessState {
    fn reserve(&self) -> Result<(), WindowsPlatformError> {
        let mut status = self
            .status
            .lock()
            .map_err(|_| WindowsPlatformError::DisplayUnavailable)?;
        if status.active || status.poisoned {
            return Err(WindowsPlatformError::DisplayUnavailable);
        }
        status.active = true;
        Ok(())
    }

    fn release(&self) {
        if let Ok(mut status) = self.status.lock() {
            status.active = false;
        }
    }

    fn poison(&self) {
        if let Ok(mut status) = self.status.lock() {
            status.active = false;
            status.poisoned = true;
        }
    }

    fn unavailable(&self) -> bool {
        let Ok(status) = self.status.lock() else {
            return true;
        };
        status.poisoned
    }
}

fn process_display_state() -> Arc<DisplayProcessState> {
    static PROCESS: OnceLock<Arc<DisplayProcessState>> = OnceLock::new();
    Arc::clone(PROCESS.get_or_init(|| Arc::new(DisplayProcessState::default())))
}

fn join_display_worker_bounded(
    worker: JoinHandle<Result<(), WindowsPlatformError>>,
    process: &DisplayProcessState,
) -> Result<(), WindowsPlatformError> {
    let deadline = Instant::now() + DISPLAY_JOIN_TIMEOUT;
    while !worker.is_finished() {
        if Instant::now() >= deadline {
            process.poison();
            drop(worker);
            return Err(WindowsPlatformError::DisplayUnavailable);
        }
        thread::sleep(Duration::from_millis(1));
    }
    match worker.join() {
        Ok(result) => result,
        Err(_) => Err(WindowsPlatformError::DisplayUnavailable),
    }
}

impl DisplayService {
    fn start() -> Result<Arc<Self>, WindowsPlatformError> {
        Self::start_with_process_state(process_display_state())
    }

    #[cfg(test)]
    fn start_with_test_process(
        process: Arc<DisplayProcessState>,
    ) -> Result<Arc<Self>, WindowsPlatformError> {
        Self::start_with_process_state(process)
    }

    fn start_with_process_state(
        process: Arc<DisplayProcessState>,
    ) -> Result<Arc<Self>, WindowsPlatformError> {
        if process.unavailable() {
            return Err(WindowsPlatformError::DisplayUnavailable);
        }
        ffi::ensure_process_dpi_awareness()?;
        let service = Arc::new(Self {
            state: Arc::new(SharedDisplayState::default()),
            runtime: Mutex::new(None),
            process,
        });
        {
            let _lifecycle = service.process.lifecycle.lock()?;
            service.start_worker_locked()?;
        }
        Ok(service)
    }

    fn start_worker_locked(&self) -> Result<(), WindowsPlatformError> {
        self.process.reserve()?;
        let result = self.start_reserved_worker_locked();
        if result.is_err() {
            self.process.release();
        }
        result
    }

    fn start_reserved_worker_locked(&self) -> Result<(), WindowsPlatformError> {
        let mut runtime = self
            .runtime
            .lock()
            .map_err(|_| WindowsPlatformError::DisplayUnavailable)?;
        if runtime.is_some() {
            return Err(WindowsPlatformError::DisplayUnavailable);
        }
        let generation = self.process.lifecycle.next_generation()?;
        self.state.begin_worker(generation)?;
        let worker_state = Arc::clone(&self.state);
        let worker_tracker = process_display_tracker();
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("nodavo-windows-displays".into())
            .spawn(move || {
                let mut native = match ffi::NativeDisplayMonitor::new() {
                    Ok(native) => native,
                    Err(error) => {
                        let _ = ready_tx.send(Err(error));
                        if let Ok(mut tracker) = worker_tracker.lock() {
                            let _ = tracker.observe(Err(error));
                        }
                        worker_state.finish_worker(generation);
                        return Err(error);
                    }
                };
                let stop = native.stop_handle();
                worker_state.set_worker_running(generation, true);
                if ready_tx.send(Ok(stop)).is_err() {
                    worker_state.finish_worker(generation);
                    return Err(WindowsPlatformError::DisplayUnavailable);
                }
                let result = native.run(|native_available| {
                    let observation = if native_available {
                        probe_environment().and_then(|_| ffi::enumerate_displays())
                    } else {
                        Err(WindowsPlatformError::SessionUnavailable)
                    };
                    let update = worker_tracker
                        .lock()
                        .map_or(DisplayTrackerUpdate::Unavailable, |mut tracker| {
                            tracker.observe(observation)
                        });
                    worker_state.apply_worker(generation, update);
                });
                if let Ok(mut tracker) = worker_tracker.lock() {
                    let _ = tracker.observe(Err(WindowsPlatformError::DisplayUnavailable));
                }
                worker_state.finish_worker(generation);
                result
            })
            .map_err(|_| {
                self.state.finish_worker(generation);
                WindowsPlatformError::DisplayUnavailable
            })?;
        let stop = match ready_rx.recv() {
            Ok(Ok(stop)) => stop,
            Ok(Err(error)) => {
                let _ = worker.join();
                return Err(error);
            }
            Err(_) => {
                let _ = worker.join();
                return Err(WindowsPlatformError::DisplayUnavailable);
            }
        };
        *runtime = Some(DisplayWorker {
            generation,
            stop,
            worker,
        });
        Ok(())
    }

    fn is_running(&self) -> bool {
        !self.process.unavailable()
            && self.state.worker_running.load(Ordering::Acquire)
            && self.runtime.lock().is_ok_and(|runtime| {
                runtime
                    .as_ref()
                    .is_some_and(|runtime| !runtime.worker.is_finished())
            })
    }

    fn stop_locked(&self) -> Result<(), WindowsPlatformError> {
        let Some(runtime) = self
            .runtime
            .lock()
            .map_err(|_| WindowsPlatformError::DisplayUnavailable)?
            .take()
        else {
            return Ok(());
        };
        self.state.retire_worker(runtime.generation);
        let stop_result = if runtime.worker.is_finished() {
            Ok(())
        } else {
            runtime.stop.stop()
        };
        let join_result = join_display_worker_bounded(runtime.worker, &self.process);
        self.process.release();
        stop_result?;
        join_result
    }

    fn stop(&self) -> Result<(), WindowsPlatformError> {
        let _lifecycle = self.process.lifecycle.lock()?;
        self.stop_locked()
    }

    fn restart(&self) -> Result<(), WindowsPlatformError> {
        let _lifecycle = self.process.lifecycle.lock()?;
        if self.process.unavailable() {
            return Err(WindowsPlatformError::DisplayUnavailable);
        }
        self.stop_locked()?;
        self.start_worker_locked()
    }
}

impl Drop for DisplayService {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

fn shared_display_service() -> Result<Arc<DisplayService>, WindowsPlatformError> {
    static SERVICE: OnceLock<Mutex<Weak<DisplayService>>> = OnceLock::new();
    let slot = SERVICE.get_or_init(|| Mutex::new(Weak::new()));
    let mut service = slot
        .lock()
        .map_err(|_| WindowsPlatformError::DisplayUnavailable)?;
    if let Some(current) = service.upgrade() {
        if !current.is_running() {
            current.restart()?;
        }
        return Ok(current);
    }
    let current = DisplayService::start()?;
    *service = Arc::downgrade(&current);
    Ok(current)
}

/// Lease over the process-local authoritative Windows display worker.
///
/// The worker polls a full graph every second on its owned thread. Its hidden
/// top-level window only shortens reaction time for `WM_DISPLAYCHANGE`; it is
/// never the authority for snapshot contents.
pub struct WindowsDisplayMonitor {
    service: Arc<DisplayService>,
    observed_revision: AtomicU64,
}

impl fmt::Debug for WindowsDisplayMonitor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsDisplayMonitor")
            .field("running", &self.service.is_running())
            .field("state", &self.snapshot_state())
            .finish_non_exhaustive()
    }
}

impl WindowsDisplayMonitor {
    /// Starts or shares the process-local display worker.
    ///
    /// # Errors
    ///
    /// Fails if `PMv2` DPI awareness or the worker window cannot be established.
    pub fn start() -> Result<Self, WindowsPlatformError> {
        let service = shared_display_service()?;
        let initial = service
            .state
            .wait_for_snapshot(INITIAL_DISPLAY_SNAPSHOT_TIMEOUT)?;
        Ok(Self {
            service,
            observed_revision: AtomicU64::new(initial.revision()),
        })
    }

    /// Returns true unless a complete, twice-confirmed graph is available.
    ///
    /// Callers must restore local ownership before consuming the later stable
    /// snapshot. `Unavailable` is intentionally treated as pending work.
    #[must_use]
    pub fn display_change_pending(&self) -> bool {
        self.service.state.pending_for(&self.observed_revision)
    }

    /// Returns whether the owned display worker is alive.
    ///
    /// Snapshot `Pending` or `Unavailable` does not by itself make the worker
    /// unhealthy; callers may continue their bounded refresh deadline.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.service.is_running()
    }

    /// Returns the current full-snapshot availability without blocking.
    ///
    /// This diagnostic read does not consume an unseen stable revision; only
    /// [`Self::snapshot`] acknowledges it for this monitor handle.
    #[must_use]
    pub fn snapshot_state(&self) -> DisplaySnapshotState {
        self.service.state.snapshot_state()
    }

    /// Returns the current stable full snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`WindowsPlatformError::DisplayUnavailable`] while an initial or
    /// changed graph is awaiting its second identical sample.
    pub fn snapshot(&self) -> Result<DisplaySnapshot, WindowsPlatformError> {
        self.service.state.consume_snapshot(&self.observed_revision)
    }

    /// Stops and joins the shared worker, invalidating all outstanding leases.
    ///
    /// # Errors
    ///
    /// Returns a native post, lock, or worker-join failure.
    pub fn stop(&mut self) -> Result<(), WindowsPlatformError> {
        self.service.stop()
    }

    /// Restarts the worker in the same shared service so existing input users
    /// observe the fresh snapshot instead of retaining a stopped source.
    ///
    /// # Errors
    ///
    /// Returns a stop or startup failure.
    pub fn restart(&mut self) -> Result<(), WindowsPlatformError> {
        self.service.restart()
    }
}

/// Enumerates a bounded, mixed-DPI virtual display graph.
///
/// # Errors
///
/// Fails closed on session, desktop, enumeration, DPI, or geometry errors.
pub fn active_displays() -> Result<Vec<DisplayGeometry>, WindowsPlatformError> {
    let service = shared_display_service()?;
    Ok(service
        .state
        .wait_for_snapshot(INITIAL_DISPLAY_SNAPSHOT_TIMEOUT)?
        .displays()
        .to_vec())
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
    let display_service = shared_display_service().ok();
    let local_topology_available = display_service.as_ref().is_some_and(|service| {
        service
            .state
            .wait_for_snapshot(INITIAL_DISPLAY_SNAPSHOT_TIMEOUT)
            .is_ok_and(|snapshot| !snapshot.displays().is_empty())
    });
    let input = if environment.send_input && environment.raw_input_capture {
        // Construction validates the default desktop and display graph but
        // never calls SendInput or registers a process-wide capture runtime.
        match display_service
            .clone()
            .ok_or(WindowsPlatformError::DisplayUnavailable)
            .and_then(WindowsInputInjector::with_display_service)
        {
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
    display_service: Arc<DisplayService>,
    pressed: PressedState,
}

impl WindowsInputInjector {
    /// Opens an injector only for the current default interactive desktop.
    ///
    /// # Errors
    ///
    /// Fails closed when session/desktop probing or display enumeration fails.
    pub fn new() -> Result<Self, WindowsPlatformError> {
        let display_service = shared_display_service()?;
        Self::with_display_service(display_service)
    }

    fn with_display_service(
        display_service: Arc<DisplayService>,
    ) -> Result<Self, WindowsPlatformError> {
        display_service
            .state
            .wait_for_snapshot(INITIAL_DISPLAY_SNAPSHOT_TIMEOUT)?;
        Ok(Self {
            display_service,
            pressed: PressedState::default(),
        })
    }

    /// Re-enumerates the mixed-DPI display graph.
    ///
    /// # Errors
    ///
    /// Fails closed if Windows reports an invalid or inaccessible display set.
    pub fn refresh_displays(&mut self) -> Result<(), WindowsPlatformError> {
        self.display_service
            .state
            .wait_for_snapshot(INITIAL_DISPLAY_SNAPSHOT_TIMEOUT)?;
        Ok(())
    }

    /// Returns one atomically published full display snapshot.
    ///
    /// # Errors
    ///
    /// Fails while a topology change is unconfirmed or the desktop is unavailable.
    pub fn display_snapshot(&self) -> Result<DisplaySnapshot, WindowsPlatformError> {
        self.display_service.state.snapshot()
    }

    /// Injects one semantic event after re-checking the interactive desktop.
    ///
    /// # Errors
    ///
    /// Rejects unsupported HID usages, invalid display geometry, secure-desktop
    /// transitions, and partial or blocked `SendInput` calls.
    pub fn inject(&mut self, event: InputEvent) -> Result<(), WindowsPlatformError> {
        probe_environment()?;
        send_with_display_authority(&self.display_service.state, event, Self::send_event)?;
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
            if Self::send_event(release, &[]).is_err() {
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

    fn send_event(
        event: InputEvent,
        displays: &[DisplayGeometry],
    ) -> Result<(), WindowsPlatformError> {
        let native = match event {
            InputEvent::Key { usage, state, .. } => keyboard_input(usage, state)?,
            InputEvent::PointerMotion { position } => {
                let display = displays
                    .iter()
                    .copied()
                    .find(|display| display.id == position.display())
                    .ok_or(WindowsPlatformError::UnknownDisplay)?;
                let (x, y) = display.map_position(position)?;
                let bounds = virtual_desktop_bounds(displays)?;
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

fn send_with_display_authority(
    displays: &SharedDisplayState,
    event: InputEvent,
    send: impl FnOnce(InputEvent, &[DisplayGeometry]) -> Result<(), WindowsPlatformError>,
) -> Result<(), WindowsPlatformError> {
    if matches!(event, InputEvent::PointerMotion { .. }) {
        displays.with_available_snapshot(|snapshot| send(event, snapshot.displays()))
    } else {
        // Keys, buttons, scroll, and relative pointer input do not consume
        // topology. In particular, releases remain possible after a graph was
        // invalidated.
        send(event, &[])
    }
}

type CaptureCallback =
    dyn Fn(WindowsInputCaptureEvent) -> Result<(), WindowsPlatformError> + Send + Sync + 'static;

fn translate_native_capture(
    translator: &mut CaptureTranslator,
    displays: &SharedDisplayState,
    routing: &RoutingAdmission,
    native: NativeInputEvent,
    observation: Option<NativeRoutingObservation>,
) -> Result<Option<WindowsInputCaptureEvent>, WindowsPlatformError> {
    let lifecycle = matches!(native, NativeInputEvent::Lifecycle(_));
    if !lifecycle {
        let Some(observation) = observation else {
            return Err(WindowsPlatformError::RawInputUnavailable);
        };
        if !observation.reliable_suppressed && !routing.epoch_is_current(observation.epoch) {
            return Ok(None);
        }
    }
    let relative_pointer = observation
        .is_some_and(|observation| observation.routed_at_hook && observation.hook_suppressed);
    let needs_snapshot =
        matches!(native, NativeInputEvent::PointerMotion { .. }) && !relative_pointer;
    let snapshot = if lifecycle || !needs_snapshot {
        None
    } else {
        let Ok(snapshot) = displays.snapshot() else {
            routing.disable()?;
            return Ok(None);
        };
        Some(snapshot)
    };
    if relative_pointer
        && let NativeInputEvent::PointerMotion {
            delta_x, delta_y, ..
        } = native
        && (delta_x != 0 || delta_y != 0)
        && PointerDelta::new(delta_x, delta_y).is_err()
    {
        return Err(WindowsPlatformError::RawInputUnavailable);
    }
    let Some(event) = translator.convert(
        native,
        snapshot.as_ref().map_or(&[], DisplaySnapshot::displays),
        relative_pointer,
    ) else {
        return Ok(None);
    };
    if let Some(snapshot) = &snapshot
        && !displays.revision_is_current(snapshot.revision())
    {
        routing.disable()?;
        return Ok(None);
    }
    Ok(Some(event))
}

struct CaptureRuntime {
    stop: ffi::NativeInputCaptureStopHandle,
    worker: JoinHandle<Result<(), WindowsPlatformError>>,
    display_service: Arc<DisplayService>,
}

struct CaptureRoutingLifecycle {
    state: Mutex<CaptureRoutingLifecycleState>,
    process: Arc<CaptureProcessState>,
}

#[derive(Default)]
struct CaptureRoutingLifecycleState {
    active: bool,
}

#[derive(Default)]
struct CaptureProcessState {
    state: Mutex<CaptureProcessStatus>,
}

#[derive(Default)]
struct CaptureProcessStatus {
    active: bool,
    poisoned: bool,
}

fn process_capture_state() -> Arc<CaptureProcessState> {
    static PROCESS: OnceLock<Arc<CaptureProcessState>> = OnceLock::new();
    Arc::clone(PROCESS.get_or_init(|| Arc::new(CaptureProcessState::default())))
}

impl Default for CaptureRoutingLifecycle {
    fn default() -> Self {
        Self::with_process_state(process_capture_state())
    }
}

impl CaptureRoutingLifecycle {
    fn with_process_state(process: Arc<CaptureProcessState>) -> Self {
        Self {
            state: Mutex::new(CaptureRoutingLifecycleState::default()),
            process,
        }
    }

    fn activate(
        self: &Arc<Self>,
        routing: Arc<RoutingAdmission>,
    ) -> Result<CaptureRoutingLease, WindowsPlatformError> {
        let mut process = self
            .process
            .state
            .lock()
            .map_err(|_| WindowsPlatformError::CaptureThread)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| WindowsPlatformError::CaptureThread)?;
        if process.poisoned {
            routing.close_admission();
            return Err(WindowsPlatformError::CaptureThread);
        }
        if state.active || process.active {
            return Err(WindowsPlatformError::CaptureAlreadyRunning);
        }
        process.active = true;
        state.active = true;
        drop(state);
        Ok(CaptureRoutingLease {
            lifecycle: Arc::clone(self),
            routing,
            active: true,
        })
    }

    fn with_active<T>(
        &self,
        routing: &RoutingAdmission,
        operation: impl FnOnce() -> Result<T, WindowsPlatformError>,
    ) -> Result<T, WindowsPlatformError> {
        let Ok(process) = self.process.state.lock() else {
            routing.close_admission();
            return Err(WindowsPlatformError::CaptureThread);
        };
        let Ok(state) = self.state.lock() else {
            routing.close_admission();
            return Err(WindowsPlatformError::CaptureThread);
        };
        if process.poisoned {
            routing.close_admission();
            return Err(WindowsPlatformError::CaptureThread);
        }
        if !state.active {
            routing.close_admission();
            return Err(WindowsPlatformError::CaptureNotRunning);
        }
        operation()
    }

    fn deactivate(&self, routing: &RoutingAdmission) -> Result<(), WindowsPlatformError> {
        let Ok(mut process) = self.process.state.lock() else {
            routing.close_admission();
            routing.disable()?;
            return Err(WindowsPlatformError::CaptureThread);
        };
        let Ok(mut state) = self.state.lock() else {
            routing.close_admission();
            routing.disable()?;
            return Err(WindowsPlatformError::CaptureThread);
        };
        state.active = false;
        process.active = false;
        routing.disable()
    }

    fn close_for_stop(&self, routing: &RoutingAdmission) -> Result<(), WindowsPlatformError> {
        let Ok(mut state) = self.state.lock() else {
            routing.close_admission();
            routing.disable()?;
            return Err(WindowsPlatformError::CaptureThread);
        };
        state.active = false;
        routing.disable()
    }

    fn is_active(&self) -> bool {
        let Ok(process) = self.process.state.lock() else {
            return false;
        };
        self.state
            .lock()
            .is_ok_and(|state| state.active && process.active && !process.poisoned)
    }

    fn is_poisoned(&self) -> bool {
        let Ok(process) = self.process.state.lock() else {
            return true;
        };
        process.poisoned
    }

    fn poison(&self, routing: &RoutingAdmission) {
        if let Ok(mut process) = self.process.state.lock() {
            process.active = false;
            process.poisoned = true;
        }
        if let Ok(mut state) = self.state.lock() {
            state.active = false;
        }
        routing.close_admission();
    }
}

struct CaptureRoutingLease {
    lifecycle: Arc<CaptureRoutingLifecycle>,
    routing: Arc<RoutingAdmission>,
    active: bool,
}

impl CaptureRoutingLease {
    fn finish(&mut self) -> Result<(), WindowsPlatformError> {
        if !self.active {
            return Ok(());
        }
        self.active = false;
        self.lifecycle.deactivate(&self.routing)
    }
}

impl Drop for CaptureRoutingLease {
    fn drop(&mut self) {
        if self.active {
            self.active = false;
            let _ = self.lifecycle.deactivate(&self.routing);
        }
    }
}

fn join_capture_worker_bounded(
    worker: JoinHandle<Result<(), WindowsPlatformError>>,
    before_detach: impl FnOnce(),
) -> (Result<(), WindowsPlatformError>, bool) {
    let deadline = Instant::now() + CAPTURE_JOIN_TIMEOUT;
    while !worker.is_finished() {
        if Instant::now() >= deadline {
            before_detach();
            drop(worker);
            return (Err(WindowsPlatformError::CaptureThread), true);
        }
        thread::sleep(Duration::from_millis(1));
    }
    let result = match worker.join() {
        Ok(result) => result,
        Err(_) => Err(WindowsPlatformError::CaptureThread),
    };
    (result, false)
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
    routing_to_peer: Arc<RoutingAdmission>,
    routing_lifecycle: Arc<CaptureRoutingLifecycle>,
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
            routing_to_peer: Arc::new(RoutingAdmission::default()),
            routing_lifecycle: Arc::new(CaptureRoutingLifecycle::default()),
            runtime: None,
        }
    }

    /// Starts a fresh message-only Raw Input runtime on a dedicated thread.
    ///
    /// # Errors
    ///
    /// Fails closed outside the default interactive desktop, when a window,
    /// registration, hook, or worker cannot be created, or when already running.
    #[allow(clippy::too_many_lines)]
    pub fn start(&mut self) -> Result<(), WindowsPlatformError> {
        if self.runtime.is_some() {
            return Err(WindowsPlatformError::CaptureAlreadyRunning);
        }
        if self.routing_lifecycle.is_poisoned() {
            return Err(WindowsPlatformError::CaptureThread);
        }
        probe_environment()?;
        let display_service = shared_display_service()?;
        display_service
            .state
            .wait_for_snapshot(INITIAL_DISPLAY_SNAPSHOT_TIMEOUT)?;
        let callback = Arc::clone(&self.callback);
        let routing_to_peer = Arc::clone(&self.routing_to_peer);
        let routing_lifecycle = Arc::clone(&self.routing_lifecycle);
        display_service
            .state
            .register_routing_flag(&routing_to_peer)?;
        let runtime_display_service = Arc::clone(&display_service);
        routing_to_peer.disable()?;
        let routing_lease = self
            .routing_lifecycle
            .activate(Arc::clone(&routing_to_peer))?;
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("nodavo-windows-input".into())
            .spawn(move || {
                let mut routing_lease = routing_lease;
                let event_callback = Arc::clone(&callback);
                let event_routing = Arc::clone(&routing_to_peer);
                let event_displays = Arc::clone(&display_service);
                let mut translator = CaptureTranslator::new(ffi::current_modifier_state());
                let capture = ffi::NativeInputCapture::new(
                    Arc::clone(&routing_to_peer),
                    move |native: NativeInputEvent,
                          observation: Option<NativeRoutingObservation>| {
                        let Some(event) = translate_native_capture(
                            &mut translator,
                            &event_displays.state,
                            &event_routing,
                            native,
                            observation,
                        )?
                        else {
                            return Ok(());
                        };
                        if let WindowsInputCaptureEvent::Lifecycle(lifecycle) = event
                            && lifecycle_requires_local_recovery(lifecycle)
                        {
                            event_routing.disable()?;
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
                    let _ = routing_lifecycle.close_for_stop(&routing_to_peer);
                    drop(capture);
                    let _ = routing_lease.finish();
                    return Err(WindowsPlatformError::CaptureThread);
                }
                let result = emit_callback(
                    callback.as_ref(),
                    WindowsInputLifecycleEvent::CaptureStarted,
                )
                .and_then(|()| {
                    let result = capture.run();
                    if result.is_ok() {
                        emit_callback(
                            callback.as_ref(),
                            WindowsInputLifecycleEvent::CaptureStopped,
                        )?;
                    }
                    result
                });
                if matches!(result, Err(WindowsPlatformError::CaptureBarrierTimeout)) {
                    routing_lifecycle.poison(&routing_to_peer);
                }
                let close_result = routing_lifecycle.close_for_stop(&routing_to_peer);
                drop(capture);
                routing_lease.finish()?;
                close_result?;
                result
            })
            .map_err(|_| WindowsPlatformError::CaptureThread)?;

        match ready_rx.recv() {
            Ok(Ok(stop)) => {
                if !self.routing_lifecycle.is_active() {
                    return worker
                        .join()
                        .map_err(|_| WindowsPlatformError::CaptureThread)?
                        .and(Err(WindowsPlatformError::CaptureThread));
                }
                self.runtime = Some(CaptureRuntime {
                    stop,
                    worker,
                    display_service: runtime_display_service,
                });
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
    /// interactive desktop. Disabling closes admission immediately, then waits
    /// up to two seconds for old hook admissions and suppressed reliable
    /// key/button/scroll observations to reach the bridge. A timeout remains
    /// fail-closed and prevents re-enable until both counts drain.
    pub fn set_routing_to_peer(&self, enabled: bool) -> Result<(), WindowsPlatformError> {
        if enabled {
            if !self.is_running() {
                return Err(WindowsPlatformError::CaptureNotRunning);
            }
            probe_environment()?;
            let runtime = self
                .runtime
                .as_ref()
                .ok_or(WindowsPlatformError::CaptureNotRunning)?;
            self.routing_lifecycle
                .with_active(&self.routing_to_peer, || {
                    runtime
                        .display_service
                        .state
                        .enable_routing(&self.routing_to_peer)
                })?;
        } else {
            self.routing_to_peer.disable()?;
        }
        Ok(())
    }

    #[must_use]
    pub fn routing_to_peer(&self) -> bool {
        self.routing_to_peer.is_enabled()
    }

    #[must_use]
    pub fn is_running(&self) -> bool {
        self.routing_lifecycle.is_active()
            && self
                .runtime
                .as_ref()
                .is_some_and(|runtime| !runtime.worker.is_finished())
    }

    /// Stops the capture thread and waits for terminal acknowledgement.
    ///
    /// # Errors
    ///
    /// Returns the terminal capture/callback failure or a worker panic.
    pub fn stop(&mut self) -> Result<(), WindowsPlatformError> {
        let barrier = self.routing_lifecycle.close_for_stop(&self.routing_to_peer);
        let Some(runtime) = self.runtime.take() else {
            return barrier;
        };
        let stop_result = if runtime.worker.is_finished() {
            Ok(())
        } else {
            runtime.stop.stop()
        };
        let (join_result, _detached) = join_capture_worker_bounded(runtime.worker, || {
            self.routing_lifecycle.poison(&self.routing_to_peer);
        });
        barrier?;
        stop_result?;
        join_result
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
    use nodavo_input::{DisplayId, NormalizedAxis, NormalizedPosition};
    use tokio::net::windows::named_pipe::ClientOptions;

    use super::*;
    use crate::display_runtime::{NativeDisplayGeometry, NativeDisplayKey};

    fn observed_display(key: u16, dpi: u32) -> NativeDisplayGeometry {
        NativeDisplayGeometry {
            key: NativeDisplayKey::new(&[key, 0]).unwrap(),
            left: 0,
            top: 0,
            width_pixels: 1_920,
            height_pixels: 1_080,
            dpi_x: dpi,
            dpi_y: dpi,
            rotation: nodavo_protocol::DisplayRotation::Degrees0,
            primary: true,
        }
    }

    #[test]
    fn shared_snapshot_change_clears_every_routing_lease_and_recovers() {
        let state = SharedDisplayState::default();
        let first_route = Arc::new(RoutingAdmission::default());
        let second_route = Arc::new(RoutingAdmission::default());
        first_route.enable().unwrap();
        second_route.enable().unwrap();
        state.register_routing_flag(&first_route).unwrap();
        state.register_routing_flag(&second_route).unwrap();

        let mut tracker = DisplayTracker::default();
        let first = vec![observed_display(1, 96)];
        state.apply(tracker.observe(Ok(first.clone())));
        assert!(!first_route.is_enabled());
        assert!(!second_route.is_enabled());
        state.apply(tracker.observe(Ok(first)));
        let revision = state.snapshot().unwrap().revision();

        first_route.enable().unwrap();
        second_route.enable().unwrap();
        let changed = vec![observed_display(1, 144)];
        state.apply(tracker.observe(Ok(changed.clone())));
        assert_eq!(
            state.snapshot(),
            Err(WindowsPlatformError::DisplayUnavailable)
        );
        assert!(!first_route.is_enabled());
        assert!(!second_route.is_enabled());
        state.apply(tracker.observe(Ok(changed)));
        assert!(state.snapshot().unwrap().revision() > revision);
    }

    #[test]
    fn repeated_routing_registration_keeps_one_bounded_invalidation_barrier() {
        let state = SharedDisplayState::default();
        let routing = Arc::new(RoutingAdmission::default());
        for _ in 0..8 {
            state.register_routing_flag(&routing).unwrap();
        }
        assert_eq!(state.routing_flags.lock().unwrap().len(), 1);

        routing.enable().unwrap();
        let hook = routing.begin();
        hook.commit_reliable_suppression().unwrap();
        drop(hook);
        let started = Instant::now();
        state.clear_routing();
        assert!(started.elapsed() < Duration::from_millis(250));
        assert!(!routing.is_enabled());
        assert!(routing.complete_reliable_suppressions(1));
    }

    #[test]
    fn stable_revision_remains_pending_until_that_monitor_consumes_it() {
        let state = Arc::new(SharedDisplayState::default());
        let mut tracker = DisplayTracker::default();
        let first = vec![observed_display(1, 96)];
        state.apply(tracker.observe(Ok(first.clone())));
        state.apply(tracker.observe(Ok(first)));
        let initial_revision = state.snapshot().unwrap().revision();
        let service = Arc::new(DisplayService {
            state: Arc::clone(&state),
            runtime: Mutex::new(None),
            process: Arc::new(DisplayProcessState::default()),
        });
        let monitor = WindowsDisplayMonitor {
            service,
            observed_revision: AtomicU64::new(initial_revision),
        };
        assert!(!monitor.display_change_pending());

        let changed = vec![observed_display(1, 144)];
        state.apply(tracker.observe(Ok(changed.clone())));
        state.apply(tracker.observe(Ok(changed)));

        // The entire unavailable-to-available transition happened without a
        // consumer poll, but the unseen stable revision retains the edge.
        assert!(monitor.display_change_pending());
        let consumed = monitor.snapshot().unwrap();
        assert!(consumed.revision() > initial_revision);
        assert!(!monitor.display_change_pending());
    }

    #[test]
    fn hook_suppressed_release_survives_unavailable_display_snapshot() {
        let displays = SharedDisplayState::default();
        assert_eq!(
            displays.snapshot(),
            Err(WindowsPlatformError::DisplayUnavailable)
        );
        let routing = RoutingAdmission::default();
        routing.enable().unwrap();
        let admission = routing.begin();
        assert!(admission.enabled());
        let epoch = admission.epoch();
        drop(admission);
        routing.disable().unwrap();

        let mut translator =
            CaptureTranslator::new(crate::input_runtime::NativeModifierState::default());
        let event = translate_native_capture(
            &mut translator,
            &displays,
            &routing,
            NativeInputEvent::Keyboard {
                scan_code: 0x1e,
                virtual_key: 0x41,
                extended: false,
                e1: false,
                pressed: false,
            },
            Some(NativeRoutingObservation {
                hook_suppressed: true,
                routed_at_hook: true,
                reliable_suppressed: true,
                epoch,
            }),
        )
        .unwrap();
        assert!(matches!(
            event,
            Some(WindowsInputCaptureEvent::Input(InputEvent::Key {
                usage,
                state: KeyState::Released,
                ..
            })) if usage == HidUsage::new(KEYBOARD_PAGE, 0x04)
        ));
    }

    #[test]
    fn delayed_pre_enable_motion_cannot_cross_routing_epoch() {
        let displays = SharedDisplayState::default();
        let routing = RoutingAdmission::default();
        let pre_enable = routing.begin();
        assert!(!pre_enable.enabled());
        let old_epoch = pre_enable.epoch();
        drop(pre_enable);
        routing.enable().unwrap();
        assert!(!routing.epoch_is_current(old_epoch));

        let mut translator =
            CaptureTranslator::new(crate::input_runtime::NativeModifierState::default());
        let event = translate_native_capture(
            &mut translator,
            &displays,
            &routing,
            NativeInputEvent::PointerMotion {
                x: 100,
                y: 100,
                delta_x: 5,
                delta_y: 5,
            },
            Some(NativeRoutingObservation {
                hook_suppressed: false,
                routed_at_hook: false,
                reliable_suppressed: false,
                epoch: old_epoch,
            }),
        )
        .unwrap();
        assert!(event.is_none());
    }

    #[test]
    fn capture_final_close_rejects_reenable_before_worker_thread_exits() {
        let process = Arc::new(CaptureProcessState::default());
        let lifecycle = Arc::new(CaptureRoutingLifecycle::with_process_state(Arc::clone(
            &process,
        )));
        let replacement = Arc::new(CaptureRoutingLifecycle::with_process_state(Arc::clone(
            &process,
        )));
        let routing = Arc::new(RoutingAdmission::default());
        let mut lease = lifecycle.activate(Arc::clone(&routing)).unwrap();
        routing.enable().unwrap();

        let (closed, close_observed) = std::sync::mpsc::sync_channel(1);
        let (native_dropped, may_drop_native) = std::sync::mpsc::sync_channel(1);
        let worker_lifecycle = Arc::clone(&lifecycle);
        let worker_routing = Arc::clone(&routing);
        let worker = std::thread::spawn(move || {
            worker_lifecycle.close_for_stop(&worker_routing).unwrap();
            closed.send(()).unwrap();
            may_drop_native.recv().unwrap();
            lease.finish().unwrap();
        });
        close_observed.recv().unwrap();

        assert_eq!(
            lifecycle.with_active(&routing, || routing.enable()),
            Err(WindowsPlatformError::CaptureNotRunning)
        );
        assert!(!routing.is_enabled());
        assert!(matches!(
            replacement.activate(Arc::new(RoutingAdmission::default())),
            Err(WindowsPlatformError::CaptureAlreadyRunning)
        ));
        native_dropped.send(()).unwrap();
        worker.join().unwrap();
        assert!(
            replacement
                .activate(Arc::new(RoutingAdmission::default()))
                .is_ok()
        );
    }

    #[test]
    fn process_capture_owner_rejects_a_second_fresh_handle() {
        let process = Arc::new(CaptureProcessState::default());
        let first = Arc::new(CaptureRoutingLifecycle::with_process_state(Arc::clone(
            &process,
        )));
        let second = Arc::new(CaptureRoutingLifecycle::with_process_state(Arc::clone(
            &process,
        )));
        let first_routing = Arc::new(RoutingAdmission::default());
        let second_routing = Arc::new(RoutingAdmission::default());
        let mut lease = first.activate(first_routing).unwrap();

        assert!(matches!(
            second.activate(Arc::clone(&second_routing)),
            Err(WindowsPlatformError::CaptureAlreadyRunning)
        ));
        lease.finish().unwrap();
        assert!(second.activate(second_routing).is_ok());
    }

    #[test]
    fn stalled_capture_join_is_bounded_and_permanently_poisoned() {
        let process = Arc::new(CaptureProcessState::default());
        let lifecycle = Arc::new(CaptureRoutingLifecycle::with_process_state(Arc::clone(
            &process,
        )));
        let routing = Arc::new(RoutingAdmission::default());
        let mut lease = lifecycle.activate(Arc::clone(&routing)).unwrap();
        routing.enable().unwrap();
        let (release, blocked) = std::sync::mpsc::sync_channel(1);
        let (exited, exit_observed) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            blocked.recv().unwrap();
            lease.finish()?;
            exited.send(()).unwrap();
            Ok(())
        });

        lifecycle.close_for_stop(&routing).unwrap();
        let started = Instant::now();
        let poison_lifecycle = Arc::clone(&lifecycle);
        let poison_routing = Arc::clone(&routing);
        let (join_result, detached) = join_capture_worker_bounded(worker, move || {
            poison_lifecycle.poison(&poison_routing);
        });
        assert_eq!(join_result, Err(WindowsPlatformError::CaptureThread));
        assert!(detached);
        assert!(started.elapsed() < Duration::from_millis(250));
        assert!(process.state.lock().unwrap().poisoned);
        assert!(matches!(
            lifecycle.activate(Arc::clone(&routing)),
            Err(WindowsPlatformError::CaptureThread)
        ));
        let fresh_lifecycle = Arc::new(CaptureRoutingLifecycle::with_process_state(Arc::clone(
            &process,
        )));
        let fresh_routing = Arc::new(RoutingAdmission::default());
        assert!(matches!(
            fresh_lifecycle.activate(fresh_routing),
            Err(WindowsPlatformError::CaptureThread)
        ));
        assert!(!routing.is_enabled());

        release.send(()).unwrap();
        exit_observed.recv_timeout(Duration::from_secs(1)).unwrap();
    }

    #[test]
    fn stalled_display_join_poison_blocks_every_fresh_service() {
        let process = Arc::new(DisplayProcessState::default());
        process.reserve().unwrap();
        let (release, blocked) = std::sync::mpsc::sync_channel(1);
        let (exited, exit_observed) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            blocked.recv().unwrap();
            exited.send(()).unwrap();
            Ok(())
        });

        let started = Instant::now();
        assert_eq!(
            join_display_worker_bounded(worker, &process),
            Err(WindowsPlatformError::DisplayUnavailable)
        );
        assert!(started.elapsed() < Duration::from_millis(250));
        assert!(process.status.lock().unwrap().poisoned);
        assert!(matches!(
            DisplayService::start_with_test_process(Arc::clone(&process)),
            Err(WindowsPlatformError::DisplayUnavailable)
        ));

        release.send(()).unwrap();
        exit_observed.recv_timeout(Duration::from_secs(1)).unwrap();
    }

    #[test]
    fn display_process_owner_fences_last_lease_drop_from_new_start() {
        let process = Arc::new(DisplayProcessState::default());
        process.reserve().unwrap();

        // A replacement that reaches the process gate before old Drop starts
        // must fail rather than overlap the still-owned worker.
        {
            let _gate = process.lifecycle.lock().unwrap();
            assert_eq!(
                process.reserve(),
                Err(WindowsPlatformError::DisplayUnavailable)
            );
        }

        let (dropping, drop_entered) = std::sync::mpsc::sync_channel(1);
        let (finish_drop, may_finish_drop) = std::sync::mpsc::sync_channel(1);
        let dropping_process = Arc::clone(&process);
        let old_drop = std::thread::spawn(move || {
            let _gate = dropping_process.lifecycle.lock().unwrap();
            dropping.send(()).unwrap();
            may_finish_drop.recv().unwrap();
            dropping_process.release();
        });
        drop_entered.recv().unwrap();

        let (started, start_result) = std::sync::mpsc::sync_channel(1);
        let starting_process = Arc::clone(&process);
        let replacement = std::thread::spawn(move || {
            let _gate = starting_process.lifecycle.lock().unwrap();
            started.send(starting_process.reserve()).unwrap();
        });
        assert!(matches!(
            start_result.recv_timeout(Duration::from_millis(20)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));

        finish_drop.send(()).unwrap();
        old_drop.join().unwrap();
        assert_eq!(start_result.recv().unwrap(), Ok(()));
        replacement.join().unwrap();
        process.release();
    }

    #[test]
    fn display_invalidation_cannot_leave_routing_enabled_against_pending() {
        let state = Arc::new(SharedDisplayState::default());
        let routing = Arc::new(RoutingAdmission::default());
        state.register_routing_flag(&routing).unwrap();

        let mut tracker = DisplayTracker::default();
        state.begin_worker(1).unwrap();
        state.set_worker_running(1, true);
        let display = vec![observed_display(1, 96)];
        state.apply_worker(1, tracker.observe(Ok(display.clone())));
        state.apply_worker(1, tracker.observe(Ok(display)));

        let (entered, enable_entered) = std::sync::mpsc::sync_channel(1);
        let (resume, enable_resumed) = std::sync::mpsc::sync_channel(1);
        let enabling_state = Arc::clone(&state);
        let enabling_routing = Arc::clone(&routing);
        let enabling = std::thread::spawn(move || {
            enabling_state.enable_routing_after(&enabling_routing, || {
                entered.send(()).unwrap();
                enable_resumed.recv().unwrap();
            })
        });
        enable_entered.recv().unwrap();

        let (attempting, invalidation_attempted) = std::sync::mpsc::sync_channel(1);
        let (invalidated, invalidation_done) = std::sync::mpsc::sync_channel(1);
        let invalidating_state = Arc::clone(&state);
        let invalidating = std::thread::spawn(move || {
            attempting.send(()).unwrap();
            invalidating_state.apply_worker(1, DisplayTrackerUpdate::Pending);
            invalidated.send(()).unwrap();
        });
        invalidation_attempted.recv().unwrap();
        assert!(matches!(
            invalidation_done.recv_timeout(Duration::from_millis(20)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));

        resume.send(()).unwrap();
        assert_eq!(enabling.join().unwrap(), Ok(()));
        invalidating.join().unwrap();
        invalidation_done.recv().unwrap();

        assert_eq!(state.snapshot_state(), DisplaySnapshotState::Pending);
        assert!(!routing.is_enabled());
    }

    #[test]
    fn absolute_send_holds_display_authority_until_send_returns() {
        let state = Arc::new(SharedDisplayState::default());
        let mut tracker = DisplayTracker::default();
        state.begin_worker(1).unwrap();
        state.set_worker_running(1, true);
        let display = vec![observed_display(1, 96)];
        state.apply_worker(1, tracker.observe(Ok(display.clone())));
        state.apply_worker(1, tracker.observe(Ok(display)));

        let event = InputEvent::PointerMotion {
            position: NormalizedPosition::new(
                DisplayId::new(1),
                NormalizedAxis::MIN,
                NormalizedAxis::MIN,
            ),
        };
        let (entered, send_entered) = std::sync::mpsc::sync_channel(1);
        let (resume, send_resumed) = std::sync::mpsc::sync_channel(1);
        let sending_state = Arc::clone(&state);
        let sending = std::thread::spawn(move || {
            send_with_display_authority(&sending_state, event, |sent, displays| {
                assert_eq!(sent, event);
                assert_eq!(displays.len(), 1);
                entered.send(()).unwrap();
                send_resumed.recv().unwrap();
                Ok(())
            })
        });
        send_entered.recv().unwrap();

        let (attempting, invalidation_attempted) = std::sync::mpsc::sync_channel(1);
        let (invalidated, invalidation_done) = std::sync::mpsc::sync_channel(1);
        let invalidating_state = Arc::clone(&state);
        let invalidating = std::thread::spawn(move || {
            attempting.send(()).unwrap();
            invalidating_state.apply_worker(1, DisplayTrackerUpdate::Pending);
            invalidated.send(()).unwrap();
        });
        invalidation_attempted.recv().unwrap();
        assert!(matches!(
            invalidation_done.recv_timeout(Duration::from_millis(20)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));

        resume.send(()).unwrap();
        assert_eq!(sending.join().unwrap(), Ok(()));
        invalidating.join().unwrap();
        invalidation_done.recv().unwrap();
        assert_eq!(state.snapshot_state(), DisplaySnapshotState::Pending);
    }

    #[test]
    fn retired_worker_teardown_cannot_overwrite_new_generation() {
        let state = SharedDisplayState::default();
        let mut tracker = DisplayTracker::default();

        state.begin_worker(1).unwrap();
        state.set_worker_running(1, true);
        let first = vec![observed_display(1, 96)];
        state.apply_worker(1, tracker.observe(Ok(first.clone())));
        state.apply_worker(1, tracker.observe(Ok(first)));
        state.retire_worker(1);
        let _ = tracker.observe(Err(WindowsPlatformError::DisplayUnavailable));

        state.begin_worker(2).unwrap();
        state.set_worker_running(2, true);
        let second = vec![observed_display(2, 144)];
        state.apply_worker(2, tracker.observe(Ok(second.clone())));
        state.apply_worker(2, tracker.observe(Ok(second)));
        let revision = state.snapshot().unwrap().revision();

        state.finish_worker(1);
        state.apply_worker(1, DisplayTrackerUpdate::Unavailable);
        state.set_worker_running(1, false);

        assert_eq!(state.snapshot().unwrap().revision(), revision);
        assert!(state.worker_running.load(Ordering::Acquire));
        assert_eq!(state.active_generation.load(Ordering::Acquire), 2);
    }

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
    fn display_monitor_restart_preserves_shared_consumers() {
        let mut monitor = WindowsDisplayMonitor::start().unwrap();
        let shared = Arc::clone(&monitor.service);
        shared
            .state
            .wait_for_snapshot(INITIAL_DISPLAY_SNAPSHOT_TIMEOUT)
            .unwrap();
        monitor.restart().unwrap();
        assert!(Arc::ptr_eq(&monitor.service, &shared));
        shared
            .state
            .wait_for_snapshot(INITIAL_DISPLAY_SNAPSHOT_TIMEOUT)
            .unwrap();
        monitor.stop().unwrap();
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
