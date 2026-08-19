//! macOS platform adapter.
//!
//! Native details remain behind semantic clipboard, input, display, and secret
//! storage values. The input adapter tags every injected event so its capture
//! callback can reject recapture.

// ADR-0002 permits native FFI only in this platform crate and only in modules
// named `ffi`. All direct Security.framework calls live in `macos/ffi.rs`.
#![allow(unsafe_code)]

use thiserror::Error;

mod clipboard;
mod keychain;
#[cfg(target_os = "macos")]
mod update;

pub use clipboard::{
    MacClipboard, MacClipboardEffectExecutor, MacClipboardEffectOutcome, MacClipboardError,
    MacClipboardSink, MacClipboardSnapshot, MacClipboardSource,
};
pub use keychain::{
    DEVICE_SIGNING_SEED_ACCOUNT, KeychainError, KeychainSecret, MAX_KEYCHAIN_SECRET_BYTES,
    MacKeychain, NODAVO_AGENT_KEYCHAIN_SERVICE, StoreDisposition, TLS_PRIVATE_KEY_ACCOUNT,
    TRUST_DATABASE_ACCOUNT,
};
#[cfg(target_os = "macos")]
pub use update::{
    MacUpdateBundleIdentity, MacUpdateBundlePolicy, MacUpdateError, MacUpdateInstallRoot,
    MacUpdatePrivateRoot, MacValidatedCandidateBundle, MacValidatedInstalledBundle,
    NODAVO_AGENT_BUNDLE_IDENTIFIER, NODAVO_AGENT_BUNDLE_RELATIVE_PATH, NODAVO_AGENT_EXECUTABLE,
    NODAVO_AGENT_LAUNCH_PLIST, NODAVO_APP_BUNDLE_IDENTIFIER, NODAVO_APP_EXECUTABLE,
};

pub const NODAVO_SYNTHETIC_EVENT_TAG: i64 = 0x4E_4F_44_41_56_4F;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MacPlatformError {
    #[error("macOS Accessibility permission is not granted")]
    AccessibilityDenied,
    #[error("CoreGraphics rejected the input operation")]
    CoreGraphics,
    #[error("the requested HID usage is not mapped on macOS")]
    UnsupportedKey,
    #[error("the requested display is not active")]
    UnknownDisplay,
    #[error("the active display configuration changed")]
    DisplayConfigurationChanged,
    #[error("the active display graph did not stabilize")]
    DisplayTopologyUnstable,
    #[error("the active display graph exceeds the supported bound")]
    TooManyDisplays,
    #[error("the CoreGraphics display observer is unavailable")]
    DisplayMonitorUnavailable,
    #[error("the CoreGraphics display observer is already running")]
    DisplayMonitorAlreadyRunning,
    #[error("the process-local display identity space is exhausted")]
    DisplayIdentityExhausted,
    #[error("the native event contains an invalid value")]
    InvalidNativeEvent,
    #[error("the macOS input event tap could not be installed or enabled")]
    EventTapUnavailable,
    #[error("the macOS input event tap was disabled after timing out")]
    EventTapTimedOut,
    #[error("the macOS input event tap was disabled by user or system input")]
    EventTapDisabled,
    #[error("an input capture runtime is already owned by this handle")]
    CaptureAlreadyRunning,
    #[error("no live input capture runtime is owned by this handle")]
    CaptureNotRunning,
    #[error("the input capture callback failed")]
    CaptureCallbackFailed,
    #[error("an in-flight routed input callback did not drain before the deadline")]
    CaptureCallbackDrainTimedOut,
    #[error("capture runtime ownership is poisoned until process restart")]
    CaptureProcessPoisoned,
    #[error("the input capture worker could not start or terminated unexpectedly")]
    CaptureThread,
    #[error("one or more tracked keys or buttons could not be released")]
    ReleaseIncomplete,
    #[error("the macOS adapter is unavailable on this platform")]
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct DisplayGeometry {
    pub id: nodavo_input::DisplayId,
    pub origin_x: f64,
    pub origin_y: f64,
    pub width_points: f64,
    pub height_points: f64,
    pub width_pixels: u64,
    pub height_pixels: u64,
    pub rotation: nodavo_protocol::DisplayRotation,
}

/// Content-free readiness observations for the current agent identity.
///
/// No native process, display, path, or permission-prompt identifiers cross
/// this boundary.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MacReadinessProbe {
    pub accessibility_trusted: bool,
    /// Required permission, display discovery, and event-source construction
    /// succeeded. Live capture is verified only by an authenticated session.
    pub input_prerequisites_available: bool,
    pub local_topology_available: bool,
}

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "macos")]
pub use macos::{
    ForceReleaseAcknowledgement, MAX_XPC_GLOBAL_OUTSTANDING, MAX_XPC_MESSAGE_BYTES,
    MAX_XPC_PEER_OUTSTANDING, MAX_XPC_PEERS, MacDisplayMonitor, MacDisplaySnapshot,
    MacInputCapture, MacInputCaptureEvent, MacInputInjector, MacInputLifecycleEvent,
    MacIpcAuthError, MacIpcPeerGuard, MacLocalIpcAuthMode, MacXpcError, MacXpcEvent,
    MacXpcListener, MacXpcPeerIdentity, MacXpcReply, MacXpcRequest, NODAVO_AGENT_MACH_SERVICE,
    XPC_REPLY_DEADLINE_MILLISECONDS, accessibility_trusted, active_displays, local_ipc_auth_mode,
    mac_xpc_peer_requirement, probe_readiness, refresh_display_snapshot, request_accessibility,
    run_input_capture,
};

#[cfg(not(target_os = "macos"))]
pub fn accessibility_trusted() -> bool {
    false
}

#[cfg(not(target_os = "macos"))]
pub fn request_accessibility() -> bool {
    false
}

#[cfg(not(target_os = "macos"))]
pub fn active_displays() -> Result<Vec<DisplayGeometry>, MacPlatformError> {
    Err(MacPlatformError::Unavailable)
}

/// Returns an honest unavailable probe off macOS.
#[must_use]
#[cfg(not(target_os = "macos"))]
pub const fn probe_readiness() -> MacReadinessProbe {
    MacReadinessProbe {
        accessibility_trusted: false,
        input_prerequisites_available: false,
        local_topology_available: false,
    }
}
