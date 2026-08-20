#![allow(unsafe_code)]
//! Windows platform boundary for input, displays, sessions, and clipboard data.
//!
//! Native calls and pointer ownership are isolated in `windows::ffi`. The
//! public API exposes semantic values, never HWND/HANDLE/HGLOBAL values. This
//! crate does not provide privileged-service, UAC, login-screen, or secure-
//! desktop control.

use nodavo_input::{DisplayId, NormalizedPosition};
use nodavo_protocol::DisplayRotation;
use thiserror::Error;

#[cfg_attr(not(any(target_os = "windows", test)), allow(dead_code))]
mod clipboard;

#[cfg_attr(not(any(target_os = "windows", test)), allow(dead_code))]
mod display_runtime;
mod input_runtime;
mod update;

#[cfg(any(target_os = "windows", test))]
mod windows_ipc_policy;

#[cfg(any(target_os = "windows", test))]
pub use windows_ipc_policy::WindowsUiAuthMode;

pub use display_runtime::{DisplaySnapshot, DisplaySnapshotState};
pub use input_runtime::{
    ForceReleaseAcknowledgement, WindowsInputCaptureEvent, WindowsInputLifecycleEvent,
};
pub use update::{
    InspectedWindowsBundle, InspectedWindowsPackage, WindowsDirectoryDurability,
    WindowsDistribution, WindowsPackageArchitecture, WindowsPackageIdentityPolicy,
    WindowsPackageVersion, WindowsUpdateError,
};

#[cfg(target_os = "windows")]
pub use update::{WindowsArtifactStaging, inspect_windows_package_bundle};

/// `dwExtraInfo` value attached to every Nodavo `SendInput` event.
///
/// Capture hooks must reject this tag, and should reject every event Windows
/// marks as injected, before converting it to [`nodavo_input::InputEvent`].
pub const NODAVO_INPUT_TAG: usize = 0x4E4F_4441_564F_5749;

/// Hard ceiling for display records returned by native enumeration.
pub const MAX_DISPLAYS: usize = nodavo_protocol::MAX_TOPOLOGY_DISPLAYS;
/// Largest plaintext accepted by the current-user DPAPI boundary.
pub const MAX_PROTECTED_SECRET_BYTES: usize = 1024 * 1024;
/// Largest serialized DPAPI blob accepted from local persistent storage.
pub const MAX_PROTECTED_SECRET_BLOB_BYTES: usize = 2 * 1024 * 1024;

/// Opaque current-user DPAPI ciphertext suitable for bounded local persistence.
#[derive(Clone, Eq, PartialEq)]
pub struct ProtectedSecretBlob(Vec<u8>);

impl ProtectedSecretBlob {
    /// Validates a serialized DPAPI blob read from storage.
    ///
    /// # Errors
    ///
    /// Rejects empty values and ciphertext over the hard storage limit.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, WindowsPlatformError> {
        if bytes.is_empty() || bytes.len() > MAX_PROTECTED_SECRET_BLOB_BYTES {
            return Err(WindowsPlatformError::SecretTooLarge);
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl std::fmt::Debug for ProtectedSecretBlob {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ProtectedSecretBlob([redacted])")
    }
}

/// Required handling for low-level capture metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureDisposition {
    /// A Raw Input event from a physical keyboard or pointer may be decoded.
    AcceptPhysical,
    /// A Nodavo-injected event must not be routed back to a peer.
    RejectNodavoInjected,
    /// Input injected by another local process is not treated as physical.
    RejectOtherInjected,
}

/// Classifies capture-hook metadata before payload decoding.
///
/// The capture adapter must call this at the low-level hook boundary and use
/// Raw Input only for events classified as physical. `lower_integrity` is kept
/// explicit because lower-integrity injection is never a physical source.
#[must_use]
pub const fn classify_captured_origin(
    windows_reports_injected: bool,
    lower_integrity: bool,
    extra_info: usize,
) -> CaptureDisposition {
    if extra_info == NODAVO_INPUT_TAG {
        CaptureDisposition::RejectNodavoInjected
    } else if windows_reports_injected || lower_integrity {
        CaptureDisposition::RejectOtherInjected
    } else {
        CaptureDisposition::AcceptPhysical
    }
}

/// Registration and filtering requirements for a future message-loop owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InputCaptureContract {
    pub raw_keyboard_usage_page: u16,
    pub raw_keyboard_usage: u16,
    pub raw_pointer_usage_page: u16,
    pub raw_pointer_usage: u16,
    pub reject_all_injected_events: bool,
    pub suppression_requires_explicit_routing: bool,
    pub lifecycle_fail_closed: bool,
    pub nodavo_extra_info_tag: usize,
}

/// Returns the platform-neutral contract the Windows capture loop enforces.
#[must_use]
pub const fn input_capture_contract() -> InputCaptureContract {
    InputCaptureContract {
        raw_keyboard_usage_page: 0x01,
        raw_keyboard_usage: 0x06,
        raw_pointer_usage_page: 0x01,
        raw_pointer_usage: 0x02,
        reject_all_injected_events: true,
        suppression_requires_explicit_routing: true,
        lifecycle_fail_closed: true,
        nodavo_extra_info_tag: NODAVO_INPUT_TAG,
    }
}

/// Capabilities observed for the current unprivileged interactive process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(clippy::struct_excessive_bools)]
pub struct EnvironmentCapabilities {
    pub process_session_id: u32,
    pub active_console_session_id: Option<u32>,
    pub input_desktop_is_default: bool,
    pub send_input: bool,
    pub raw_input_capture: bool,
    pub clipboard: bool,
}

/// Content-free readiness of current unprivileged Windows input prerequisites.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsInputReadiness {
    /// Default-desktop prerequisites and unprivileged injector construction
    /// succeeded. Live Raw Input capture is verified only by a peer session.
    Ready,
    BlockedByDesktop,
    Unavailable,
}

/// Public platform readiness observations without session, process, desktop,
/// display, or filesystem identifiers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowsReadinessProbe {
    pub input: WindowsInputReadiness,
    pub local_topology_available: bool,
}

/// A monitor in Windows virtual-desktop pixel coordinates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DisplayGeometry {
    pub id: DisplayId,
    pub left: i32,
    pub top: i32,
    pub width_pixels: u32,
    pub height_pixels: u32,
    pub dpi_x: u32,
    pub dpi_y: u32,
    pub rotation: DisplayRotation,
    pub primary: bool,
}

impl DisplayGeometry {
    /// Maps a normalized semantic position to this display's inclusive pixel
    /// coordinate range.
    ///
    /// # Errors
    ///
    /// Returns [`WindowsPlatformError::UnknownDisplay`] when the position is
    /// scoped to another display, or [`WindowsPlatformError::InvalidDisplay`]
    /// for zero-sized or overflowing native geometry.
    pub fn map_position(
        self,
        position: NormalizedPosition,
    ) -> Result<(i32, i32), WindowsPlatformError> {
        if position.display() != self.id {
            return Err(WindowsPlatformError::UnknownDisplay);
        }
        if self.width_pixels == 0 || self.height_pixels == 0 {
            return Err(WindowsPlatformError::InvalidDisplay);
        }
        let x_offset = scale_axis(position.x().bits(), self.width_pixels)?;
        let y_offset = scale_axis(position.y().bits(), self.height_pixels)?;
        let x = self
            .left
            .checked_add(x_offset)
            .ok_or(WindowsPlatformError::InvalidDisplay)?;
        let y = self
            .top
            .checked_add(y_offset)
            .ok_or(WindowsPlatformError::InvalidDisplay)?;
        Ok((x, y))
    }
}

fn scale_axis(bits: u16, extent: u32) -> Result<i32, WindowsPlatformError> {
    let maximum = extent
        .checked_sub(1)
        .ok_or(WindowsPlatformError::InvalidDisplay)?;
    let scaled =
        (u64::from(bits) * u64::from(maximum) + u64::from(u16::MAX) / 2) / u64::from(u16::MAX);
    i32::try_from(scaled).map_err(|_| WindowsPlatformError::InvalidDisplay)
}

/// Native clipboard formats supported at this initial boundary.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ClipboardFormat {
    UnicodeText,
    Html,
    Png,
    /// Canonical BMP file bytes, including `BITMAPFILEHEADER`.
    Bmp,
    /// Raw `CF_DIB`, retained only for low-level platform probes.
    Dib,
    /// Raw `CF_DIBV5`, retained only for low-level platform probes.
    DibV5,
}

/// Bounded clipboard representation metadata. No content is logged or stored.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClipboardFormatMetadata {
    pub format: ClipboardFormat,
    pub byte_len: u64,
}

/// One consistent clipboard change-sequence observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClipboardMetadata {
    pub sequence_number: u32,
    pub native_types_empty: bool,
    pub formats: Vec<ClipboardFormatMetadata>,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum WindowsPlatformError {
    #[error("the Windows platform adapter is unavailable on this target")]
    Unavailable,
    #[error("the current process is not in a usable interactive session")]
    SessionUnavailable,
    #[error("the default interactive input desktop is unavailable")]
    SecureDesktop,
    #[error("a required Win32 API operation failed")]
    NativeApi,
    #[error("the requested HID usage is not mapped on Windows")]
    UnsupportedKey,
    #[error("the requested pointer button is not supported by SendInput")]
    UnsupportedButton,
    #[error("the requested display is not active")]
    UnknownDisplay,
    #[error("Windows returned invalid or overflowing display geometry")]
    InvalidDisplay,
    #[error("the authoritative Windows display snapshot is not available")]
    DisplayUnavailable,
    #[error("Windows rejected or partially completed input injection")]
    InputBlocked,
    #[error("the Windows Raw Input capture boundary could not be created")]
    RawInputUnavailable,
    #[error("the Windows low-level input hooks could not be installed")]
    InputHookUnavailable,
    #[error("an input capture runtime is already owned by this handle")]
    CaptureAlreadyRunning,
    #[error("no live input capture runtime is owned by this handle")]
    CaptureNotRunning,
    #[error("the input capture callback failed")]
    CaptureCallbackFailed,
    #[error("the input capture routing barrier did not drain in time")]
    CaptureBarrierTimeout,
    #[error("the input capture worker could not start or terminated unexpectedly")]
    CaptureThread,
    #[error("one or more tracked keys or buttons could not be released")]
    ReleaseIncomplete,
    #[error("the clipboard could not be opened consistently")]
    ClipboardBusy,
    #[error("the requested clipboard format is unavailable")]
    ClipboardFormatUnavailable,
    #[error("clipboard content exceeds its hard size limit")]
    ClipboardTooLarge,
    #[error("clipboard text is malformed")]
    InvalidClipboardText,
    #[error("clipboard HTML framing or UTF-8 content is malformed")]
    InvalidClipboardHtml,
    #[error("clipboard image data is empty or uses an unsupported format")]
    InvalidClipboardImage,
    #[error("the local Windows IPC client is not the authorized packaged UI")]
    UnauthorizedLocalIpc,
    #[error("the secret or protected blob exceeds its hard size limit")]
    SecretTooLarge,
    #[error("Windows current-user secret protection failed")]
    SecretProtection,
}

/// Returns whether this build contains the Windows implementation.
#[must_use]
pub const fn is_available() -> bool {
    cfg!(target_os = "windows")
}

#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "windows")]
pub use self::windows::{
    AuthorizedWindowsUi, WindowsClipboard, WindowsDisplayMonitor, WindowsInputCapture,
    WindowsInputInjector, active_displays, authorize_named_pipe_client,
    compiled_windows_ui_auth_mode, create_private_named_pipe, current_user_agent_pipe_name,
    probe_environment, probe_readiness, protect_current_user_secret, replace_file_atomic,
    resolve_downloads_nodavo_directory, run_input_capture, unprotect_current_user_secret,
    validate_compiled_windows_ui_auth_policy,
};

/// Non-Windows probe stub used by workspace tooling and portable callers.
///
/// # Errors
///
/// Always returns [`WindowsPlatformError::Unavailable`] off Windows.
#[cfg(not(target_os = "windows"))]
pub const fn probe_environment() -> Result<EnvironmentCapabilities, WindowsPlatformError> {
    Err(WindowsPlatformError::Unavailable)
}

/// Non-Windows display-enumeration stub.
///
/// # Errors
///
/// Always returns [`WindowsPlatformError::Unavailable`] off Windows.
#[cfg(not(target_os = "windows"))]
pub const fn active_displays() -> Result<Vec<DisplayGeometry>, WindowsPlatformError> {
    Err(WindowsPlatformError::Unavailable)
}

/// Returns an honest unavailable probe off Windows.
#[must_use]
#[cfg(not(target_os = "windows"))]
pub const fn probe_readiness() -> WindowsReadinessProbe {
    WindowsReadinessProbe {
        input: WindowsInputReadiness::Unavailable,
        local_topology_available: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nodavo_input::{NormalizedAxis, NormalizedPosition};

    #[test]
    fn injected_origin_filter_is_fail_closed() {
        assert_eq!(
            classify_captured_origin(false, false, NODAVO_INPUT_TAG),
            CaptureDisposition::RejectNodavoInjected
        );
        assert_eq!(
            classify_captured_origin(true, false, 0),
            CaptureDisposition::RejectOtherInjected
        );
        assert_eq!(
            classify_captured_origin(false, false, 0),
            CaptureDisposition::AcceptPhysical
        );
        let contract = input_capture_contract();
        assert!(contract.reject_all_injected_events);
        assert!(contract.suppression_requires_explicit_routing);
        assert!(contract.lifecycle_fail_closed);
    }

    #[test]
    fn display_mapping_keeps_inclusive_edges() {
        let display = DisplayGeometry {
            id: DisplayId::new(4),
            left: -1_920,
            top: 0,
            width_pixels: 1_920,
            height_pixels: 1_080,
            dpi_x: 144,
            dpi_y: 144,
            rotation: DisplayRotation::Degrees0,
            primary: false,
        };
        assert_eq!(
            display
                .map_position(NormalizedPosition::new(
                    display.id,
                    NormalizedAxis::MIN,
                    NormalizedAxis::MIN,
                ))
                .unwrap(),
            (-1_920, 0)
        );
        assert_eq!(
            display
                .map_position(NormalizedPosition::new(
                    display.id,
                    NormalizedAxis::MAX,
                    NormalizedAxis::MAX,
                ))
                .unwrap(),
            (-1, 1_079)
        );
    }

    #[test]
    fn protected_secret_blob_is_bounded_and_redacted() {
        assert!(ProtectedSecretBlob::from_bytes(Vec::new()).is_err());
        assert!(
            ProtectedSecretBlob::from_bytes(vec![0; MAX_PROTECTED_SECRET_BLOB_BYTES + 1]).is_err()
        );
        let blob = ProtectedSecretBlob::from_bytes(vec![1, 2, 3]).unwrap();
        assert_eq!(format!("{blob:?}"), "ProtectedSecretBlob([redacted])");
        assert!(!format!("{blob:?}").contains('1'));
    }
}
