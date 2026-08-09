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

pub use clipboard::{
    MacClipboard, MacClipboardEffectExecutor, MacClipboardEffectOutcome, MacClipboardError,
    MacClipboardSink, MacClipboardSnapshot, MacClipboardSource,
};
pub use keychain::{
    DEVICE_SIGNING_SEED_ACCOUNT, KeychainError, KeychainSecret, MAX_KEYCHAIN_SECRET_BYTES,
    MacKeychain, NODAVO_AGENT_KEYCHAIN_SERVICE, StoreDisposition, TLS_PRIVATE_KEY_ACCOUNT,
    TRUST_DATABASE_ACCOUNT,
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
}

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "macos")]
pub use macos::{
    ForceReleaseAcknowledgement, MacInputCapture, MacInputCaptureEvent, MacInputInjector,
    MacInputLifecycleEvent, accessibility_trusted, active_displays, request_accessibility,
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
