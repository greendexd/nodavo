//! Audited Win32 FFI wrappers. Unsafe code must remain in this module.

// windows-rs `#[implement]` emits always-inline pointer adapter thunks. These
// two lints cannot be attached to only the macro expansion.
#![allow(clippy::inline_always, clippy::ref_as_ptr)]

use std::cell::Cell;
use std::collections::VecDeque;
use std::ffi::{OsString, c_void};
use std::io::{Read as _, Seek as _, SeekFrom};
use std::mem::{offset_of, size_of, size_of_val};
use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::windows::fs::MetadataExt as _;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows::Win32::Devices::Display::{
    DISPLAYCONFIG_DEVICE_INFO_GET_SOURCE_NAME, DISPLAYCONFIG_DEVICE_INFO_GET_TARGET_NAME,
    DISPLAYCONFIG_DEVICE_INFO_HEADER, DISPLAYCONFIG_MODE_INFO, DISPLAYCONFIG_PATH_INFO,
    DISPLAYCONFIG_SOURCE_DEVICE_NAME, DISPLAYCONFIG_TARGET_DEVICE_NAME, DisplayConfigGetDeviceInfo,
    GetDisplayConfigBufferSizes, QDC_ONLY_ACTIVE_PATHS, QueryDisplayConfig,
};
use windows::Win32::Foundation::{
    DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND,
    ERROR_INSUFFICIENT_BUFFER, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS, FILETIME, GlobalFree, HANDLE,
    HGLOBAL, HINSTANCE, HLOCAL, HWND, LPARAM, LRESULT, LocalFree, POINT, RECT, RPC_E_CHANGED_MODE,
    S_FALSE, S_OK, STG_E_ACCESSDENIED, STG_E_INVALIDFUNCTION, STG_E_INVALIDPOINTER,
    STG_E_READFAULT, STG_E_REVERTED, STG_E_SEEKERROR, STG_E_WRITEFAULT, WAIT_TIMEOUT, WPARAM,
};
use windows::Win32::Graphics::Gdi::{
    DEVMODEW, DM_DISPLAYORIENTATION, ENUM_CURRENT_SETTINGS, EnumDisplayMonitors,
    EnumDisplaySettingsW, GetMonitorInfoW, HDC, HMONITOR, MONITORINFOEXW,
};
use windows::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
    SE_FILE_OBJECT,
};
use windows::Win32::Security::Cryptography::{
    BCRYPT_SHA256_ALGORITHM, CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptHashCertificate2,
    CryptProtectData, CryptUnprotectData,
};
use windows::Win32::Security::WinTrust::{
    SGNR_TYPE_TIMESTAMP, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_FILE_INFO,
    WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE, WTD_DISABLE_MD2_MD4, WTD_REVOCATION_CHECK_NONE,
    WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
    WTD_UICONTEXT_EXECUTE, WTHelperGetProvCertFromChain, WTHelperGetProvSignerFromChain,
    WTHelperProvDataFromStateData, WinVerifyTrustEx,
};
use windows::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
    CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation,
    GetSecurityDescriptorControl, GetTokenInformation, IsValidSid, OBJECT_INHERIT_ACE,
    OBJECT_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SE_DACL_PROTECTED, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_STATISTICS, TOKEN_USER,
    TokenSessionId, TokenStatistics, TokenUser,
};
use windows::Win32::Storage::FileSystem::{
    CREATE_NEW, CreateDirectoryW, CreateFileW, FILE_ALL_ACCESS, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_FLAGS_AND_ATTRIBUTES, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_LIST_DIRECTORY,
    FILE_READ_ATTRIBUTES, FILE_SHARE_NONE, FILE_SHARE_READ, FILE_SHARE_WRITE, GetDriveTypeW,
    GetFinalPathNameByHandleW, MOVE_FILE_FLAGS, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    MoveFileExW, OPEN_EXISTING, READ_CONTROL, ReOpenFile, VOLUME_NAME_GUID, WRITE_DAC,
};
use windows::Win32::Storage::Packaging::Appx::{
    APPLICATION_USER_MODEL_ID_MAX_LENGTH, APPX_PACKAGE_ARCHITECTURE_ARM64,
    APPX_PACKAGE_ARCHITECTURE_X64, AppxBundleFactory, AppxFactory, GetApplicationUserModelId,
    GetApplicationUserModelIdFromToken, GetPackageFamilyName, GetPackageFamilyNameFromToken,
    GetPackageFullName, GetPackageFullNameFromToken, GetPackagePathByFullName2, IAppxBundleFactory,
    IAppxFactory, IAppxManifestPackageId, PACKAGE_FAMILY_NAME_MAX_LENGTH,
    PACKAGE_FULL_NAME_MAX_LENGTH, PACKAGE_ID, PACKAGE_INFORMATION_FULL, PackageFamilyNameFromId,
    PackageIdFromFullName, PackagePathType_Install,
};
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoTaskMemFree,
    CoUninitialize, ISequentialStream_Impl, IStream, IStream_Impl, LOCKTYPE, STATFLAG, STATSTG,
    STGC, STGM_READ, STGTY_STREAM, STREAM_SEEK, STREAM_SEEK_CUR, STREAM_SEEK_END, STREAM_SEEK_SET,
};
use windows::Win32::System::DataExchange::{
    CloseClipboard, CountClipboardFormats, EmptyClipboard, GetClipboardData,
    GetClipboardSequenceNumber, IsClipboardFormatAvailable, OpenClipboard,
    RegisterClipboardFormatW, SetClipboardData,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Memory::{
    GMEM_MOVEABLE, GMEM_ZEROINIT, GlobalAlloc, GlobalLock, GlobalSize, GlobalUnlock,
};
use windows::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows::Win32::System::Power::{
    HPOWERNOTIFY, RegisterSuspendResumeNotification, UnregisterSuspendResumeNotification,
};
use windows::Win32::System::RemoteDesktop::{
    NOTIFY_FOR_THIS_SESSION, ProcessIdToSessionId, WTSGetActiveConsoleSessionId,
    WTSRegisterSessionNotification, WTSUnRegisterSessionNotification,
};
use windows::Win32::System::StationsAndDesktops::{
    CloseDesktop, DESKTOP_CONTROL_FLAGS, DESKTOP_READOBJECTS, GetUserObjectInformationW, HDESK,
    OpenInputDesktop, UOI_NAME,
};
use windows::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, GetCurrentThreadId, GetProcessId, GetProcessTimes,
    OpenProcess, OpenProcessToken, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SYNCHRONIZE, QueryFullProcessImageNameW, WaitForSingleObject,
};
use windows::Win32::System::WindowsProgramming::DRIVE_FIXED;
use windows::Win32::UI::HiDpi::{
    AreDpiAwarenessContextsEqual, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2,
    GetDpiAwarenessContextForProcess, GetDpiForMonitor, MDT_EFFECTIVE_DPI,
    SetProcessDpiAwarenessContext,
};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    GetAsyncKeyState, GetKeyState, INPUT, INPUT_0, INPUT_KEYBOARD, INPUT_MOUSE, KEYBD_EVENT_FLAGS,
    KEYBDINPUT, KEYEVENTF_EXTENDEDKEY, KEYEVENTF_KEYUP, KEYEVENTF_SCANCODE, MOUSE_EVENT_FLAGS,
    MOUSEEVENTF_ABSOLUTE, MOUSEEVENTF_HWHEEL, MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP,
    MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP, MOUSEEVENTF_MOVE, MOUSEEVENTF_RIGHTDOWN,
    MOUSEEVENTF_RIGHTUP, MOUSEEVENTF_VIRTUALDESK, MOUSEEVENTF_WHEEL, MOUSEEVENTF_XDOWN,
    MOUSEEVENTF_XUP, MOUSEINPUT, SendInput, VIRTUAL_KEY, VK_CAPITAL, VK_LCONTROL, VK_LMENU,
    VK_LSHIFT, VK_LWIN, VK_NUMLOCK, VK_RCONTROL, VK_RMENU, VK_RSHIFT, VK_RWIN,
};
use windows::Win32::UI::Input::{
    GetRawInputData, HRAWINPUT, RAWINPUT, RAWINPUTDEVICE, RAWINPUTHEADER, RID_INPUT,
    RIDEV_DEVNOTIFY, RIDEV_INPUTSINK, RIDEV_REMOVE, RIM_TYPEKEYBOARD, RIM_TYPEMOUSE,
    RegisterRawInputDevices,
};
use windows::Win32::UI::Shell::{FOLDERID_Downloads, KF_FLAG_DEFAULT, SHGetKnownFolderPath};
use windows::Win32::UI::WindowsAndMessaging::{
    CW_USEDEFAULT, CallNextHookEx, CreateWindowExW, DEVICE_NOTIFY_WINDOW_HANDLE, DefWindowProcW,
    DestroyWindow, DispatchMessageW, GIDC_ARRIVAL, GIDC_REMOVAL, GetCursorPos, GetMessageTime,
    GetMessageW, HHOOK, HWND_MESSAGE, KBDLLHOOKSTRUCT, KillTimer, LLKHF_EXTENDED, LLKHF_INJECTED,
    LLKHF_LOWER_IL_INJECTED, LLMHF_INJECTED, LLMHF_LOWER_IL_INJECTED, MSG, MSLLHOOKSTRUCT,
    PBT_APMRESUMEAUTOMATIC, PBT_APMRESUMECRITICAL, PBT_APMRESUMESUSPEND, PBT_APMSUSPEND,
    PostMessageW, PostQuitMessage, PostThreadMessageW, RI_KEY_BREAK, RI_KEY_E0, RI_KEY_E1,
    RI_MOUSE_BUTTON_1_DOWN, RI_MOUSE_BUTTON_1_UP, RI_MOUSE_BUTTON_2_DOWN, RI_MOUSE_BUTTON_2_UP,
    RI_MOUSE_BUTTON_3_DOWN, RI_MOUSE_BUTTON_3_UP, RI_MOUSE_BUTTON_4_DOWN, RI_MOUSE_BUTTON_4_UP,
    RI_MOUSE_BUTTON_5_DOWN, RI_MOUSE_BUTTON_5_UP, RI_MOUSE_HWHEEL, RI_MOUSE_WHEEL, RegisterClassW,
    SetTimer, SetWindowsHookExW, TranslateMessage, UnhookWindowsHookEx, UnregisterClassW,
    WH_KEYBOARD_LL, WH_MOUSE_LL, WINDOW_EX_STYLE, WINDOW_STYLE, WM_APP, WM_DISPLAYCHANGE, WM_INPUT,
    WM_INPUT_DEVICE_CHANGE, WM_KEYDOWN, WM_KEYUP, WM_LBUTTONDOWN, WM_LBUTTONUP, WM_MBUTTONDOWN,
    WM_MBUTTONUP, WM_MOUSEHWHEEL, WM_MOUSEMOVE, WM_MOUSEWHEEL, WM_POWERBROADCAST, WM_QUIT,
    WM_RBUTTONDOWN, WM_RBUTTONUP, WM_SYSKEYDOWN, WM_SYSKEYUP, WM_TIMER, WM_WTSSESSION_CHANGE,
    WM_XBUTTONDOWN, WM_XBUTTONUP, WNDCLASSW, WTS_CONSOLE_CONNECT, WTS_CONSOLE_DISCONNECT,
    WTS_REMOTE_CONNECT, WTS_REMOTE_DISCONNECT, WTS_SESSION_LOCK, WTS_SESSION_UNLOCK,
};
use windows::core::{BOOL, HRESULT, PCWSTR, PWSTR, implement, w};
use zeroize::Zeroizing;

use crate::clipboard::{
    bmp_to_dib, decode_cf_html, dib_to_bmp, encode_cf_html, maximum_cf_html_bytes, validate_png,
};
use crate::display_runtime::{
    NativeDisplayGeometry, NativeDisplayKey, display_rotation, unique_native_display_key,
};
use crate::input_runtime::{
    NativeInputEvent, NativeLifecycleEvent, NativeModifierState, NativeRoutingObservation,
    RoutingAdmission, native_keyboard_is_supported,
};
use crate::{
    ClipboardFormat, ClipboardFormatMetadata, ClipboardMetadata, EnvironmentCapabilities,
    MAX_DISPLAYS, MAX_PROTECTED_SECRET_BLOB_BYTES, MAX_PROTECTED_SECRET_BYTES, NODAVO_INPUT_TAG,
    WindowsPlatformError,
};

const CF_DIB: u32 = 8;
const CF_UNICODETEXT: u32 = 13;
const CF_DIBV5: u32 = 17;
const MONITORINFOF_PRIMARY: u32 = 1;
const NO_ACTIVE_SESSION: u32 = u32::MAX;
const MAX_DESKTOP_NAME_UNITS: usize = 64;
const MAX_KNOWN_FOLDER_PATH_UNITS: usize = 32_767;
const MAX_TEXT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_IMAGE_BYTES: u64 = 100 * 1024 * 1024;
const PIPE_BUFFER_BYTES: u32 = 64 * 1024;
const OWNER_ONLY_PIPE_SDDL: &[u16] = &[
    b'D' as u16,
    b':' as u16,
    b'P' as u16,
    b'(' as u16,
    b'A' as u16,
    b';' as u16,
    b';' as u16,
    b'G' as u16,
    b'A' as u16,
    b';' as u16,
    b';' as u16,
    b';' as u16,
    b'O' as u16,
    b'W' as u16,
    b')' as u16,
    0,
];
const DPAPI_ENTROPY: &[u8] = b"Nodavo/current-user-secret/v1";
const MAX_WINDOWS_PATH_UNITS: usize = 32_767;
const MAX_RAW_INPUT_BYTES: u32 = 64 * 1024;
const MAX_HOOK_OBSERVATIONS: usize = 256;
const MAX_AUTHENTICODE_CHAIN_CERTIFICATES: u32 = 32;
const HOOK_OBSERVATION_MAX_AGE_MS: u32 = 250;
const CAPTURE_TIMER_ID: usize = 1;
const CAPTURE_TIMER_INTERVAL_MS: u32 = 500;
const WM_NODAVO_CAPTURE_STOP: u32 = WM_APP + 0x4e;
const DISPLAY_TIMER_ID: usize = 1;
const DISPLAY_TIMER_INTERVAL_MS: u32 = 1_000;
const WM_NODAVO_DISPLAY_STOP: u32 = WM_APP + 0x4f;
const NODAVO_INPUT_TAG_LOW32: u32 = 0x564f_5749;
const MAX_APPMODEL_STRING_UNITS: usize = 32_768;
const MAX_TOKEN_INFORMATION_BYTES: usize = 64 * 1024;
const MAX_DISPLAY_CONFIG_MODES: usize = MAX_DISPLAYS * 2;
const DISPLAY_CONFIG_QUERY_ATTEMPTS: usize = 4;
#[cfg(not(test))]
const RELIABLE_LIFECYCLE_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
#[cfg(test)]
const RELIABLE_LIFECYCLE_DRAIN_TIMEOUT: Duration = Duration::from_millis(50);

static PROCESS_DPI_AWARENESS: OnceLock<Result<(), WindowsPlatformError>> = OnceLock::new();

thread_local! {
    static CAPTURE_CONTEXT: Cell<*mut InputCaptureContext> = const { Cell::new(ptr::null_mut()) };
}

type NativeInputCallback = dyn FnMut(NativeInputEvent, Option<NativeRoutingObservation>) -> Result<(), WindowsPlatformError>
    + Send
    + 'static;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HookObservationKey {
    Keyboard {
        scan_code: u16,
        virtual_key: u16,
        pressed: bool,
    },
    Mouse {
        message: u32,
    },
}

#[derive(Clone, Copy)]
struct HookObservation {
    key: HookObservationKey,
    disposition: crate::CaptureDisposition,
    timestamp: u32,
    suppressed: bool,
    reliable_suppressed: bool,
    routed_at_hook: bool,
    routing_epoch: u64,
}

#[derive(Clone, Copy)]
struct HookAdmission {
    disposition: crate::CaptureDisposition,
    suppressed: bool,
    reliable_suppressions: usize,
    routed_at_hook: bool,
    routing_epoch: u64,
}

#[derive(Clone, Copy)]
struct PendingReliableLifecycle {
    event: NativeLifecycleEvent,
    deadline: Instant,
}

#[allow(clippy::struct_excessive_bools)]
struct InputCaptureContext {
    callback: Box<NativeInputCallback>,
    routing_to_peer: Arc<RoutingAdmission>,
    observations: VecDeque<HookObservation>,
    session_active: bool,
    desktop_available: bool,
    callback_failed: bool,
    native_failed: bool,
    reliable_delivery_failed: bool,
    pending_lifecycle: Option<PendingReliableLifecycle>,
}

impl InputCaptureContext {
    fn record_hook(&mut self, mut observation: HookObservation) -> bool {
        if self.observations.len() == MAX_HOOK_OBSERVATIONS {
            let mut reliable_delivery_failed = observation.reliable_suppressed;
            if let Some(retired) = self.observations.pop_front()
                && retired.reliable_suppressed
            {
                reliable_delivery_failed = true;
                let _ = self.routing_to_peer.complete_reliable_suppressions(1);
            }
            if observation.reliable_suppressed {
                let _ = self.routing_to_peer.complete_reliable_suppressions(1);
            }
            observation.suppressed = false;
            observation.reliable_suppressed = false;
            self.native_failed = true;
            self.reliable_delivery_failed |= reliable_delivery_failed;
            self.routing_to_peer.close_admission();
            // SAFETY: hook callbacks execute on this capture thread; queue
            // overflow terminates its own message loop after allowing the
            // current physical event through locally.
            unsafe { PostQuitMessage(1) };
        }
        let suppressed = observation.suppressed;
        self.observations.push_back(observation);
        suppressed
    }

    fn take_origin(&mut self, key: HookObservationKey, timestamp: u32) -> Option<HookAdmission> {
        while self.observations.front().is_some_and(|observation| {
            timestamp.wrapping_sub(observation.timestamp) > HOOK_OBSERVATION_MAX_AGE_MS
        }) {
            if let Some(expired) = self.observations.pop_front()
                && expired.reliable_suppressed
            {
                let _ = self.routing_to_peer.complete_reliable_suppressions(1);
                self.native_failed = true;
                self.reliable_delivery_failed = true;
                self.routing_to_peer.close_admission();
                // SAFETY: this runs on the capture thread and terminates its
                // own loop after a reliable suppressed observation expired.
                unsafe { PostQuitMessage(1) };
            }
        }
        let first_index = self
            .observations
            .iter()
            .position(|observation| observation.key == key && observation.timestamp == timestamp)?;
        let first_disposition = self.observations[first_index].disposition;
        let conflicting_origin = self.observations.iter().any(|observation| {
            observation.key == key
                && observation.timestamp == timestamp
                && observation.disposition != first_disposition
        });
        if !conflicting_origin {
            let observation = self.observations.remove(first_index)?;
            return Some(HookAdmission {
                disposition: observation.disposition,
                suppressed: observation.suppressed,
                reliable_suppressions: usize::from(observation.reliable_suppressed),
                routed_at_hook: observation.routed_at_hook,
                routing_epoch: observation.routing_epoch,
            });
        }

        let mut disposition = first_disposition;
        let mut reliable_suppressions = 0_usize;
        let mut index = 0;
        while index < self.observations.len() {
            if self.observations[index].key != key
                || self.observations[index].timestamp != timestamp
            {
                index += 1;
                continue;
            }
            let observation = self.observations.remove(index)?;
            reliable_suppressions += usize::from(observation.reliable_suppressed);
            if observation.disposition != crate::CaptureDisposition::AcceptPhysical {
                disposition = observation.disposition;
            }
        }
        self.native_failed = true;
        self.reliable_delivery_failed |= reliable_suppressions != 0;
        self.routing_to_peer.close_admission();
        // SAFETY: an injected/physical origin collision is terminal for this
        // capture thread; its reliable token is completed only as abort by the
        // raw-input caller before this loop exits.
        unsafe { PostQuitMessage(1) };
        Some(HookAdmission {
            disposition,
            suppressed: false,
            reliable_suppressions,
            routed_at_hook: false,
            routing_epoch: 0,
        })
    }

    fn emit(
        &mut self,
        event: NativeInputEvent,
        routing: Option<NativeRoutingObservation>,
        reliable_suppressions: usize,
    ) {
        if self.callback_failed {
            self.reliable_delivery_failed |= reliable_suppressions != 0;
            let _ = self
                .routing_to_peer
                .complete_reliable_suppressions(reliable_suppressions);
            return;
        }
        let delivered = matches!(
            catch_unwind(AssertUnwindSafe(|| (self.callback)(event, routing))),
            Ok(Ok(()))
        );
        let completed = self
            .routing_to_peer
            .complete_reliable_suppressions(reliable_suppressions);
        if !delivered || !completed {
            self.callback_failed = true;
            if (!delivered || !completed) && reliable_suppressions != 0 {
                self.reliable_delivery_failed = true;
            }
            self.abort_pending_observations();
            self.routing_to_peer.disable_fail_closed();
            // SAFETY: this callback runs only on the capture thread and requests
            // termination of that thread's own message loop.
            unsafe { PostQuitMessage(1) };
        }
    }

    fn emit_lifecycle(&mut self, event: NativeLifecycleEvent) {
        if self.pending_lifecycle.is_some() {
            self.fail_native();
            return;
        }
        if matches!(
            event,
            NativeLifecycleEvent::SessionLocked
                | NativeLifecycleEvent::SessionDisconnected
                | NativeLifecycleEvent::SystemSuspending
                | NativeLifecycleEvent::DefaultDesktopUnavailable
        ) {
            self.routing_to_peer.close_admission();
            if self.routing_to_peer.has_outstanding_reliable_suppressions() {
                self.pending_lifecycle = Some(PendingReliableLifecycle {
                    event,
                    deadline: Instant::now() + RELIABLE_LIFECYCLE_DRAIN_TIMEOUT,
                });
                return;
            }
            if self.routing_to_peer.disable().is_err() {
                self.fail_native();
                return;
            }
        }
        self.emit(NativeInputEvent::Lifecycle(event), None, 0);
    }

    fn finish_pending_lifecycle_if_drained(&mut self) {
        let Some(pending) = self.pending_lifecycle else {
            return;
        };
        if self.reliable_delivery_failed || self.callback_failed || self.native_failed {
            self.pending_lifecycle = None;
            return;
        }
        if self.routing_to_peer.has_outstanding_reliable_suppressions() {
            return;
        }
        self.pending_lifecycle = None;
        if self.routing_to_peer.disable().is_err() {
            self.fail_native();
            return;
        }
        self.emit(NativeInputEvent::Lifecycle(pending.event), None, 0);
    }

    fn poll_pending_lifecycle(&mut self) {
        let Some(pending) = self.pending_lifecycle else {
            return;
        };
        if self.reliable_delivery_failed || self.callback_failed || self.native_failed {
            self.pending_lifecycle = None;
            return;
        }
        if !self.routing_to_peer.has_outstanding_reliable_suppressions() {
            self.finish_pending_lifecycle_if_drained();
        } else if Instant::now() >= pending.deadline {
            self.pending_lifecycle = None;
            self.fail_reliable_delivery();
        }
    }

    fn fail_reliable_delivery(&mut self) {
        self.reliable_delivery_failed = true;
        self.fail_native();
    }

    fn fail_native(&mut self) {
        self.native_failed = true;
        self.abort_pending_observations();
        self.routing_to_peer.disable_fail_closed();
        // SAFETY: this method is called only while dispatching on the capture
        // thread and terminates that thread's own message loop.
        unsafe { PostQuitMessage(1) };
    }

    fn abort_pending_observations(&mut self) {
        self.pending_lifecycle = None;
        let reliable = self
            .observations
            .drain(..)
            .filter(|observation| observation.reliable_suppressed)
            .count();
        self.reliable_delivery_failed |= reliable != 0;
        let _ = self
            .routing_to_peer
            .complete_reliable_suppressions(reliable);
    }
}

struct CaptureStopState {
    window: Mutex<Option<isize>>,
}

pub(super) struct NativeInputCaptureStopHandle {
    state: Arc<CaptureStopState>,
}

impl NativeInputCaptureStopHandle {
    pub(super) fn stop(&self) -> Result<(), WindowsPlatformError> {
        let window = self
            .state
            .window
            .lock()
            .map_err(|_| WindowsPlatformError::CaptureThread)?;
        let Some(raw) = *window else {
            return Ok(());
        };
        // SAFETY: the mutex synchronizes this post with teardown. While it is
        // held, `raw` is the live message-only window owned by the capture.
        unsafe {
            PostMessageW(
                Some(windows::Win32::Foundation::HWND(raw as *mut c_void)),
                WM_NODAVO_CAPTURE_STOP,
                WPARAM(0),
                LPARAM(0),
            )
        }
        .map_err(|_| WindowsPlatformError::CaptureThread)
    }
}

pub(super) struct NativeInputCapture {
    context: Box<InputCaptureContext>,
    stop_state: Arc<CaptureStopState>,
    window: windows::Win32::Foundation::HWND,
    module: HINSTANCE,
    class_name: Vec<u16>,
    keyboard_hook: Option<HHOOK>,
    mouse_hook: Option<HHOOK>,
    timer_registered: bool,
    session_registered: bool,
    power_notification: Option<HPOWERNOTIFY>,
    raw_input_registered: bool,
}

impl NativeInputCapture {
    #[allow(clippy::too_many_lines)]
    pub(super) fn new(
        routing_to_peer: Arc<RoutingAdmission>,
        callback: impl FnMut(
            NativeInputEvent,
            Option<NativeRoutingObservation>,
        ) -> Result<(), WindowsPlatformError>
        + Send
        + 'static,
    ) -> Result<Self, WindowsPlatformError> {
        ensure_process_dpi_awareness()?;
        probe_environment()?;
        let mut context = Box::new(InputCaptureContext {
            callback: Box::new(callback),
            routing_to_peer,
            observations: VecDeque::with_capacity(MAX_HOOK_OBSERVATIONS),
            session_active: true,
            desktop_available: true,
            callback_failed: false,
            native_failed: false,
            reliable_delivery_failed: false,
            pending_lifecycle: None,
        });
        let already_active = CAPTURE_CONTEXT.with(|slot| {
            if slot.get().is_null() {
                slot.set(&raw mut *context);
                false
            } else {
                true
            }
        });
        if already_active {
            return Err(WindowsPlatformError::CaptureAlreadyRunning);
        }

        // SAFETY: a null module name requests the module containing this code.
        let module = HINSTANCE(
            unsafe { GetModuleHandleW(None) }
                .map_err(|_| WindowsPlatformError::RawInputUnavailable)?
                .0,
        );
        let class_name = format!(
            "NodavoRawInput-{}-{}",
            // SAFETY: scalar process/thread identifiers have no ownership.
            unsafe { GetCurrentProcessId() },
            unsafe { GetCurrentThreadId() }
        )
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
        let class = WNDCLASSW {
            lpfnWndProc: Some(input_window_proc),
            hInstance: module,
            lpszClassName: PCWSTR(class_name.as_ptr()),
            ..Default::default()
        };
        // SAFETY: `class` and its NUL-terminated class-name buffer remain live;
        // the registered callback has process lifetime.
        if unsafe { RegisterClassW(&raw const class) } == 0 {
            CAPTURE_CONTEXT.with(|slot| slot.set(ptr::null_mut()));
            return Err(WindowsPlatformError::RawInputUnavailable);
        }

        // SAFETY: the registered class and module remain live for the owned
        // message-only window lifetime. No external creation parameter is used.
        let Ok(window) = (unsafe {
            CreateWindowExW(
                WINDOW_EX_STYLE::default(),
                PCWSTR(class_name.as_ptr()),
                w!("Nodavo Raw Input"),
                WINDOW_STYLE::default(),
                CW_USEDEFAULT,
                CW_USEDEFAULT,
                0,
                0,
                Some(HWND_MESSAGE),
                None,
                Some(module),
                None,
            )
        }) else {
            // SAFETY: this unregisters the class registered immediately above.
            let _ = unsafe { UnregisterClassW(PCWSTR(class_name.as_ptr()), Some(module)) };
            CAPTURE_CONTEXT.with(|slot| slot.set(ptr::null_mut()));
            return Err(WindowsPlatformError::RawInputUnavailable);
        };
        let stop_state = Arc::new(CaptureStopState {
            window: Mutex::new(Some(window.0.addr().cast_signed())),
        });
        let mut capture = Self {
            context,
            stop_state,
            window,
            module,
            class_name,
            keyboard_hook: None,
            mouse_hook: None,
            timer_registered: false,
            session_registered: false,
            power_notification: None,
            raw_input_registered: false,
        };

        register_raw_input(window, false)?;
        capture.raw_input_registered = true;
        // SAFETY: window is a live top-level message-only window and remains so
        // until capture Drop unregisters this notification.
        unsafe { WTSRegisterSessionNotification(window, NOTIFY_FOR_THIS_SESSION) }
            .map_err(|_| WindowsPlatformError::RawInputUnavailable)?;
        capture.session_registered = true;
        // SAFETY: the recipient handle is this live message-only window. The
        // registration is unregistered before window destruction.
        capture.power_notification = Some(
            unsafe {
                RegisterSuspendResumeNotification(HANDLE(window.0), DEVICE_NOTIFY_WINDOW_HANDLE)
            }
            .map_err(|_| WindowsPlatformError::RawInputUnavailable)?,
        );
        // SAFETY: window remains live; timer callbacks are delivered as WM_TIMER
        // to this same thread and are killed during teardown.
        if unsafe {
            SetTimer(
                Some(window),
                CAPTURE_TIMER_ID,
                CAPTURE_TIMER_INTERVAL_MS,
                None,
            )
        } == 0
        {
            return Err(WindowsPlatformError::RawInputUnavailable);
        }
        capture.timer_registered = true;

        // SAFETY: both callback functions have process lifetime, module contains
        // them, and the hooks are uninstalled before context teardown.
        capture.keyboard_hook = Some(
            unsafe { SetWindowsHookExW(WH_KEYBOARD_LL, Some(keyboard_hook_proc), Some(module), 0) }
                .map_err(|_| WindowsPlatformError::InputHookUnavailable)?,
        );
        capture.mouse_hook = Some(
            unsafe { SetWindowsHookExW(WH_MOUSE_LL, Some(mouse_hook_proc), Some(module), 0) }
                .map_err(|_| WindowsPlatformError::InputHookUnavailable)?,
        );
        Ok(capture)
    }

    pub(super) fn stop_handle(&self) -> NativeInputCaptureStopHandle {
        NativeInputCaptureStopHandle {
            state: Arc::clone(&self.stop_state),
        }
    }

    pub(super) fn run(&mut self) -> Result<(), WindowsPlatformError> {
        let mut message = MSG::default();
        loop {
            // SAFETY: `message` is a live output location. This owned thread
            // pumps all messages required by its window and low-level hooks.
            let result = unsafe { GetMessageW(&raw mut message, None, 0, 0) };
            if result.0 == -1 {
                return Err(WindowsPlatformError::RawInputUnavailable);
            }
            if result.0 == 0 {
                break;
            }
            // SAFETY: GetMessageW initialized this MSG; neither call retains it.
            unsafe {
                let _ = TranslateMessage(&raw const message);
                DispatchMessageW(&raw const message);
            }
        }
        if self.context.reliable_delivery_failed {
            Err(WindowsPlatformError::CaptureBarrierTimeout)
        } else if self.context.callback_failed {
            Err(WindowsPlatformError::CaptureCallbackFailed)
        } else if self.context.native_failed {
            Err(WindowsPlatformError::RawInputUnavailable)
        } else {
            Ok(())
        }
    }
}

impl Drop for NativeInputCapture {
    fn drop(&mut self) {
        self.context.abort_pending_observations();
        self.context.routing_to_peer.disable_fail_closed();
        if let Some(hook) = self.mouse_hook.take() {
            // SAFETY: this is the uniquely owned live hook returned at creation.
            let _ = unsafe { UnhookWindowsHookEx(hook) };
        }
        if let Some(hook) = self.keyboard_hook.take() {
            // SAFETY: this is the uniquely owned live hook returned at creation.
            let _ = unsafe { UnhookWindowsHookEx(hook) };
        }
        if self.raw_input_registered {
            let _ = register_raw_input(self.window, true);
        }
        if self.session_registered {
            // SAFETY: registration belongs to this still-live window.
            let _ = unsafe { WTSUnRegisterSessionNotification(self.window) };
        }
        if let Some(notification) = self.power_notification.take() {
            // SAFETY: this is the uniquely owned registration returned during
            // capture creation and is released exactly once.
            let _ = unsafe { UnregisterSuspendResumeNotification(notification) };
        }
        if self.timer_registered {
            // SAFETY: timer belongs to this still-live window.
            let _ = unsafe { KillTimer(Some(self.window), CAPTURE_TIMER_ID) };
        }
        if let Ok(mut window) = self.stop_state.window.lock() {
            *window = None;
        }
        // SAFETY: the window and class were created by this capture on this
        // thread and are destroyed/unregistered exactly once.
        let _ = unsafe { DestroyWindow(self.window) };
        let _ = unsafe { UnregisterClassW(PCWSTR(self.class_name.as_ptr()), Some(self.module)) };
        CAPTURE_CONTEXT.with(|slot| slot.set(ptr::null_mut()));
    }
}

struct DisplayStopState {
    window: Mutex<Option<isize>>,
    thread_id: u32,
}

pub(super) struct NativeDisplayMonitorStopHandle {
    state: Arc<DisplayStopState>,
}

impl NativeDisplayMonitorStopHandle {
    pub(super) fn stop(&self) -> Result<(), WindowsPlatformError> {
        let window = self
            .state
            .window
            .lock()
            .map_err(|_| WindowsPlatformError::DisplayUnavailable)?;
        let Some(raw) = *window else {
            return Ok(());
        };
        // SAFETY: the mutex serializes this post with display-window teardown.
        let posted = unsafe {
            PostMessageW(
                Some(HWND(raw as *mut c_void)),
                WM_NODAVO_DISPLAY_STOP,
                WPARAM(0),
                LPARAM(0),
            )
        };
        if posted.is_ok() {
            return Ok(());
        }
        // SAFETY: thread_id belongs to this owned message-loop thread and
        // WM_QUIT carries no pointer-bearing payload.
        unsafe { PostThreadMessageW(self.state.thread_id, WM_QUIT, WPARAM(0), LPARAM(0)) }
            .map_err(|_| WindowsPlatformError::DisplayUnavailable)
    }
}

/// Dedicated hidden top-level window used only as an early display-change wake.
/// The one-second timer remains the authoritative full-snapshot source.
pub(super) struct NativeDisplayMonitor {
    stop_state: Arc<DisplayStopState>,
    window: HWND,
    module: HINSTANCE,
    class_name: Vec<u16>,
    timer_registered: bool,
    session_registered: bool,
    power_notification: Option<HPOWERNOTIFY>,
}

impl NativeDisplayMonitor {
    pub(super) fn new() -> Result<Self, WindowsPlatformError> {
        ensure_process_dpi_awareness()?;
        // SAFETY: a null module name requests the module containing this code.
        let module = HINSTANCE(
            unsafe { GetModuleHandleW(None) }
                .map_err(|_| WindowsPlatformError::DisplayUnavailable)?
                .0,
        );
        let class_name = format!(
            "NodavoDisplayMonitor-{}-{}",
            // SAFETY: scalar process/thread identifiers have no ownership.
            unsafe { GetCurrentProcessId() },
            unsafe { GetCurrentThreadId() }
        )
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
        let class = WNDCLASSW {
            lpfnWndProc: Some(display_window_proc),
            hInstance: module,
            lpszClassName: PCWSTR(class_name.as_ptr()),
            ..Default::default()
        };
        // SAFETY: the class and its name remain live until this owner drops.
        if unsafe { RegisterClassW(&raw const class) } == 0 {
            return Err(WindowsPlatformError::DisplayUnavailable);
        }
        // No HWND_MESSAGE parent is used: this is an unowned, never-shown
        // top-level window so broadcast WM_DISPLAYCHANGE can wake polling.
        let Ok(window) = (unsafe {
            CreateWindowExW(
                WINDOW_EX_STYLE::default(),
                PCWSTR(class_name.as_ptr()),
                w!("Nodavo Display Monitor"),
                WINDOW_STYLE::default(),
                CW_USEDEFAULT,
                CW_USEDEFAULT,
                0,
                0,
                None,
                None,
                Some(module),
                None,
            )
        }) else {
            // SAFETY: this unregisters the class registered immediately above.
            let _ = unsafe { UnregisterClassW(PCWSTR(class_name.as_ptr()), Some(module)) };
            return Err(WindowsPlatformError::DisplayUnavailable);
        };
        let stop_state = Arc::new(DisplayStopState {
            window: Mutex::new(Some(window.0.addr().cast_signed())),
            // SAFETY: creation and the message loop run on this owned thread.
            thread_id: unsafe { GetCurrentThreadId() },
        });
        let mut monitor = Self {
            stop_state,
            window,
            module,
            class_name,
            timer_registered: false,
            session_registered: false,
            power_notification: None,
        };
        // SAFETY: this live top-level window remains registered until Drop.
        unsafe { WTSRegisterSessionNotification(window, NOTIFY_FOR_THIS_SESSION) }
            .map_err(|_| WindowsPlatformError::DisplayUnavailable)?;
        monitor.session_registered = true;
        // SAFETY: the registration is owned by this still-live window.
        monitor.power_notification = Some(
            unsafe {
                RegisterSuspendResumeNotification(HANDLE(window.0), DEVICE_NOTIFY_WINDOW_HANDLE)
            }
            .map_err(|_| WindowsPlatformError::DisplayUnavailable)?,
        );
        // SAFETY: the window remains live until Drop and owns this timer.
        if unsafe {
            SetTimer(
                Some(window),
                DISPLAY_TIMER_ID,
                DISPLAY_TIMER_INTERVAL_MS,
                None,
            )
        } == 0
        {
            return Err(WindowsPlatformError::DisplayUnavailable);
        }
        monitor.timer_registered = true;
        Ok(monitor)
    }

    pub(super) fn stop_handle(&self) -> NativeDisplayMonitorStopHandle {
        NativeDisplayMonitorStopHandle {
            state: Arc::clone(&self.stop_state),
        }
    }

    pub(super) fn run(
        &mut self,
        mut poll_full_snapshot: impl FnMut(bool),
    ) -> Result<(), WindowsPlatformError> {
        if self.window.0.is_null() {
            return Err(WindowsPlatformError::DisplayUnavailable);
        }
        let mut session_active = true;
        let mut power_active = true;
        // Two complete back-to-back samples establish initial stability without
        // forcing callers to wait for the first timer tick. Later changes still
        // require a second observation, with the one-second timer authoritative.
        poll_full_snapshot(true);
        poll_full_snapshot(true);
        let mut message = MSG::default();
        loop {
            // SAFETY: this owned thread pumps all messages for its hidden window.
            let result = unsafe { GetMessageW(&raw mut message, None, 0, 0) };
            if result.0 == -1 {
                return Err(WindowsPlatformError::DisplayUnavailable);
            }
            if result.0 == 0 {
                return Ok(());
            }
            match message.message {
                WM_WTSSESSION_CHANGE => {
                    match u32::try_from(message.wParam.0).unwrap_or(u32::MAX) {
                        WTS_SESSION_LOCK | WTS_CONSOLE_DISCONNECT | WTS_REMOTE_DISCONNECT => {
                            session_active = false;
                        }
                        WTS_SESSION_UNLOCK | WTS_CONSOLE_CONNECT | WTS_REMOTE_CONNECT => {
                            session_active = true;
                        }
                        _ => {}
                    }
                    poll_full_snapshot(session_active && power_active);
                }
                WM_POWERBROADCAST => {
                    match u32::try_from(message.wParam.0).unwrap_or(u32::MAX) {
                        PBT_APMSUSPEND => power_active = false,
                        PBT_APMRESUMEAUTOMATIC | PBT_APMRESUMECRITICAL | PBT_APMRESUMESUSPEND => {
                            power_active = true;
                        }
                        _ => {}
                    }
                    poll_full_snapshot(session_active && power_active);
                }
                WM_DISPLAYCHANGE | WM_TIMER
                    if message.message != WM_TIMER || message.wParam.0 == DISPLAY_TIMER_ID =>
                {
                    poll_full_snapshot(session_active && power_active);
                }
                _ => {}
            }
            // SAFETY: GetMessageW initialized this MSG; neither call retains it.
            unsafe {
                let _ = TranslateMessage(&raw const message);
                DispatchMessageW(&raw const message);
            }
        }
    }
}

impl Drop for NativeDisplayMonitor {
    fn drop(&mut self) {
        if self.timer_registered {
            // SAFETY: the timer belongs to this still-live window.
            let _ = unsafe { KillTimer(Some(self.window), DISPLAY_TIMER_ID) };
        }
        if self.session_registered {
            // SAFETY: registration belongs to this still-live window.
            let _ = unsafe { WTSUnRegisterSessionNotification(self.window) };
        }
        if let Some(notification) = self.power_notification.take() {
            // SAFETY: this registration is released exactly once.
            let _ = unsafe { UnregisterSuspendResumeNotification(notification) };
        }
        if let Ok(mut window) = self.stop_state.window.lock() {
            *window = None;
        }
        // SAFETY: the window and class are owned by this monitor thread.
        let _ = unsafe { DestroyWindow(self.window) };
        let _ = unsafe { UnregisterClassW(PCWSTR(self.class_name.as_ptr()), Some(self.module)) };
    }
}

unsafe extern "system" fn display_window_proc(
    window: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if message == WM_NODAVO_DISPLAY_STOP {
        // SAFETY: this runs on the display-monitor thread and stops its loop.
        unsafe { PostQuitMessage(0) };
        return LRESULT(0);
    }
    // SAFETY: Nodavo has no custom pointer-bearing state for this window.
    unsafe { DefWindowProcW(window, message, wparam, lparam) }
}

fn register_raw_input(
    window: windows::Win32::Foundation::HWND,
    remove: bool,
) -> Result<(), WindowsPlatformError> {
    let flags = if remove {
        RIDEV_REMOVE
    } else {
        RIDEV_INPUTSINK | RIDEV_DEVNOTIFY
    };
    let target = if remove {
        windows::Win32::Foundation::HWND::default()
    } else {
        window
    };
    let devices = [
        RAWINPUTDEVICE {
            usUsagePage: 0x01,
            usUsage: 0x06,
            dwFlags: flags,
            hwndTarget: target,
        },
        RAWINPUTDEVICE {
            usUsagePage: 0x01,
            usUsage: 0x02,
            dwFlags: flags,
            hwndTarget: target,
        },
    ];
    let size = u32::try_from(size_of::<RAWINPUTDEVICE>())
        .map_err(|_| WindowsPlatformError::RawInputUnavailable)?;
    // SAFETY: both descriptors are fully initialized and the slice remains live
    // for this synchronous registration/removal call.
    unsafe { RegisterRawInputDevices(&devices, size) }
        .map_err(|_| WindowsPlatformError::RawInputUnavailable)
}

pub(super) fn current_modifier_state() -> NativeModifierState {
    NativeModifierState {
        left_control: key_is_down(VK_LCONTROL),
        left_shift: key_is_down(VK_LSHIFT),
        left_alt: key_is_down(VK_LMENU),
        left_meta: key_is_down(VK_LWIN),
        right_control: key_is_down(VK_RCONTROL),
        right_shift: key_is_down(VK_RSHIFT),
        right_alt: key_is_down(VK_RMENU),
        right_meta: key_is_down(VK_RWIN),
        caps_lock: key_is_toggled(VK_CAPITAL),
        num_lock: key_is_toggled(VK_NUMLOCK),
    }
}

fn key_is_down(key: VIRTUAL_KEY) -> bool {
    // SAFETY: GetAsyncKeyState accepts every virtual-key scalar and retains nothing.
    (unsafe { GetAsyncKeyState(i32::from(key.0)) }) < 0
}

fn key_is_toggled(key: VIRTUAL_KEY) -> bool {
    // SAFETY: GetKeyState accepts every virtual-key scalar and retains nothing.
    (unsafe { GetKeyState(i32::from(key.0)) }) & 1 != 0
}

unsafe extern "system" fn input_window_proc(
    window: windows::Win32::Foundation::HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if message == WM_NODAVO_CAPTURE_STOP {
        // SAFETY: this window procedure runs on the capture thread and requests
        // termination of its own message loop.
        unsafe { PostQuitMessage(0) };
        return LRESULT(0);
    }

    let context = CAPTURE_CONTEXT.with(Cell::get);
    if context.is_null() {
        // SAFETY: no Nodavo context is available, so default processing owns the
        // message and no pointer derived from lparam is dereferenced here.
        return unsafe { DefWindowProcW(window, message, wparam, lparam) };
    }
    // SAFETY: NativeInputCapture pins this context in a Box, sets this thread-
    // local pointer before window creation, and clears it only after teardown.
    let context = unsafe { &mut *context };
    match message {
        WM_INPUT => {
            // SAFETY: WM_INPUT lparam is the HRAWINPUT owned by Windows for the
            // duration of this window-procedure call.
            if unsafe { process_raw_input(context, HRAWINPUT(lparam.0 as *mut c_void)) }.is_err() {
                context.fail_native();
            } else {
                context.finish_pending_lifecycle_if_drained();
            }
        }
        WM_INPUT_DEVICE_CHANGE
            if matches!(
                u32::try_from(wparam.0).unwrap_or(u32::MAX),
                GIDC_ARRIVAL | GIDC_REMOVAL
            ) =>
        {
            context.emit_lifecycle(NativeLifecycleEvent::InputDeviceChanged);
        }
        WM_WTSSESSION_CHANGE => {
            handle_session_change(context, u32::try_from(wparam.0).unwrap_or(u32::MAX));
        }
        WM_POWERBROADCAST => {
            handle_power_change(context, u32::try_from(wparam.0).unwrap_or(u32::MAX));
        }
        WM_TIMER if wparam.0 == CAPTURE_TIMER_ID => {
            refresh_desktop_state(context);
            context.poll_pending_lifecycle();
        }
        _ => {}
    }
    // SAFETY: default processing is required for WM_INPUT cleanup and is valid
    // for every message delivered to this owned window.
    unsafe { DefWindowProcW(window, message, wparam, lparam) }
}

fn handle_session_change(context: &mut InputCaptureContext, code: u32) {
    match code {
        WTS_SESSION_LOCK => {
            context.session_active = false;
            context.emit_lifecycle(NativeLifecycleEvent::SessionLocked);
        }
        WTS_SESSION_UNLOCK => {
            context.session_active = true;
            context.emit_lifecycle(NativeLifecycleEvent::SessionUnlocked);
            refresh_desktop_state(context);
        }
        WTS_CONSOLE_DISCONNECT | WTS_REMOTE_DISCONNECT => {
            context.session_active = false;
            context.emit_lifecycle(NativeLifecycleEvent::SessionDisconnected);
        }
        WTS_CONSOLE_CONNECT | WTS_REMOTE_CONNECT => {
            context.session_active = true;
            context.emit_lifecycle(NativeLifecycleEvent::SessionConnected);
            refresh_desktop_state(context);
        }
        _ => {}
    }
}

fn handle_power_change(context: &mut InputCaptureContext, code: u32) {
    match code {
        PBT_APMSUSPEND => {
            context.emit_lifecycle(NativeLifecycleEvent::SystemSuspending);
        }
        PBT_APMRESUMEAUTOMATIC | PBT_APMRESUMECRITICAL | PBT_APMRESUMESUSPEND => {
            context.emit_lifecycle(NativeLifecycleEvent::SystemResumed);
            refresh_desktop_state(context);
        }
        _ => {}
    }
}

fn refresh_desktop_state(context: &mut InputCaptureContext) {
    let available = verify_default_input_desktop().is_ok();
    if available == context.desktop_available {
        return;
    }
    context.desktop_available = available;
    context.emit_lifecycle(if available {
        NativeLifecycleEvent::DefaultDesktopAvailable
    } else {
        NativeLifecycleEvent::DefaultDesktopUnavailable
    });
}

unsafe extern "system" fn keyboard_hook_proc(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    if code < 0 {
        // SAFETY: required hook chaining for unhandled negative hook codes.
        return unsafe { CallNextHookEx(None, code, wparam, lparam) };
    }
    let message = u32::try_from(wparam.0).unwrap_or(u32::MAX);
    let Some(pressed) = keyboard_message_state(message) else {
        // SAFETY: unsupported messages are passed through unchanged.
        return unsafe { CallNextHookEx(None, code, wparam, lparam) };
    };
    if lparam.0 == 0 {
        // SAFETY: a malformed callback payload is never dereferenced.
        return unsafe { CallNextHookEx(None, code, wparam, lparam) };
    }
    // SAFETY: Windows supplies a live KBDLLHOOKSTRUCT for HC_ACTION callbacks.
    let data = unsafe { &*(lparam.0 as *const KBDLLHOOKSTRUCT) };
    let scan_code = u16::try_from(data.scanCode).unwrap_or(0);
    let virtual_key = u16::try_from(data.vkCode).unwrap_or(0);
    let extended = data.flags.contains(LLKHF_EXTENDED);
    let disposition = crate::classify_captured_origin(
        data.flags.contains(LLKHF_INJECTED),
        data.flags.contains(LLKHF_LOWER_IL_INJECTED),
        data.dwExtraInfo,
    );
    let context = CAPTURE_CONTEXT.with(Cell::get);
    if !context.is_null() {
        // SAFETY: the TLS invariant is documented in input_window_proc.
        let context = unsafe { &mut *context };
        let routing = Arc::clone(&context.routing_to_peer);
        let admission = routing.begin();
        let routed_at_hook = disposition == crate::CaptureDisposition::AcceptPhysical
            && context.session_active
            && context.desktop_available
            && admission.enabled();
        let mut suppressed = routed_at_hook
            && native_keyboard_is_supported(scan_code, virtual_key, extended, virtual_key == 0x13);
        let mut reliable_suppressed = false;
        if suppressed {
            if admission.commit_reliable_suppression().is_ok() {
                reliable_suppressed = true;
            } else {
                suppressed = false;
                context.native_failed = true;
                context.routing_to_peer.close_admission();
                // SAFETY: hook callbacks execute on the owned capture thread.
                unsafe { PostQuitMessage(1) };
            }
        }
        suppressed = context.record_hook(HookObservation {
            key: HookObservationKey::Keyboard {
                scan_code,
                virtual_key,
                pressed,
            },
            disposition,
            timestamp: data.time,
            suppressed,
            reliable_suppressed,
            routed_at_hook,
            routing_epoch: admission.epoch(),
        });
        if suppressed {
            return LRESULT(1);
        }
    }
    // SAFETY: every non-suppressed event must continue through the hook chain.
    unsafe { CallNextHookEx(None, code, wparam, lparam) }
}

unsafe extern "system" fn mouse_hook_proc(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    if code < 0 || lparam.0 == 0 {
        // SAFETY: required hook chaining for unhandled or malformed callbacks.
        return unsafe { CallNextHookEx(None, code, wparam, lparam) };
    }
    let message = u32::try_from(wparam.0).unwrap_or(u32::MAX);
    if !mouse_message_is_supported(message) {
        // SAFETY: unsupported messages are passed through unchanged.
        return unsafe { CallNextHookEx(None, code, wparam, lparam) };
    }
    // SAFETY: Windows supplies a live MSLLHOOKSTRUCT for HC_ACTION callbacks.
    let data = unsafe { &*(lparam.0 as *const MSLLHOOKSTRUCT) };
    let disposition = crate::classify_captured_origin(
        data.flags & LLMHF_INJECTED != 0,
        data.flags & LLMHF_LOWER_IL_INJECTED != 0,
        data.dwExtraInfo,
    );
    let context = CAPTURE_CONTEXT.with(Cell::get);
    if !context.is_null() {
        // SAFETY: the TLS invariant is documented in input_window_proc.
        let context = unsafe { &mut *context };
        let routing = Arc::clone(&context.routing_to_peer);
        let admission = routing.begin();
        let routed_at_hook = disposition == crate::CaptureDisposition::AcceptPhysical
            && context.session_active
            && context.desktop_available
            && admission.enabled();
        let mut suppressed = routed_at_hook;
        let mut reliable_suppressed = false;
        if suppressed && mouse_message_is_reliable(message) {
            if admission.commit_reliable_suppression().is_ok() {
                reliable_suppressed = true;
            } else {
                suppressed = false;
                context.native_failed = true;
                context.routing_to_peer.close_admission();
                // SAFETY: hook callbacks execute on the owned capture thread.
                unsafe { PostQuitMessage(1) };
            }
        }
        suppressed = context.record_hook(HookObservation {
            key: HookObservationKey::Mouse { message },
            disposition,
            timestamp: data.time,
            suppressed,
            reliable_suppressed,
            routed_at_hook,
            routing_epoch: admission.epoch(),
        });
        if suppressed {
            return LRESULT(1);
        }
    }
    // SAFETY: every non-suppressed event must continue through the hook chain.
    unsafe { CallNextHookEx(None, code, wparam, lparam) }
}

const fn keyboard_message_state(message: u32) -> Option<bool> {
    match message {
        WM_KEYDOWN | WM_SYSKEYDOWN => Some(true),
        WM_KEYUP | WM_SYSKEYUP => Some(false),
        _ => None,
    }
}

const fn mouse_message_is_supported(message: u32) -> bool {
    matches!(
        message,
        WM_MOUSEMOVE
            | WM_LBUTTONDOWN
            | WM_LBUTTONUP
            | WM_RBUTTONDOWN
            | WM_RBUTTONUP
            | WM_MBUTTONDOWN
            | WM_MBUTTONUP
            | WM_XBUTTONDOWN
            | WM_XBUTTONUP
            | WM_MOUSEWHEEL
            | WM_MOUSEHWHEEL
    )
}

const fn mouse_message_is_reliable(message: u32) -> bool {
    matches!(
        message,
        WM_LBUTTONDOWN
            | WM_LBUTTONUP
            | WM_RBUTTONDOWN
            | WM_RBUTTONUP
            | WM_MBUTTONDOWN
            | WM_MBUTTONUP
            | WM_XBUTTONDOWN
            | WM_XBUTTONUP
            | WM_MOUSEWHEEL
            | WM_MOUSEHWHEEL
    )
}

#[allow(clippy::too_many_lines)]
unsafe fn process_raw_input(
    context: &mut InputCaptureContext,
    handle: HRAWINPUT,
) -> Result<(), WindowsPlatformError> {
    let header_size = u32::try_from(size_of::<RAWINPUTHEADER>())
        .map_err(|_| WindowsPlatformError::RawInputUnavailable)?;
    let mut byte_len = 0_u32;
    // SAFETY: this is the documented sizing query for the live WM_INPUT handle.
    let queried =
        unsafe { GetRawInputData(handle, RID_INPUT, None, &raw mut byte_len, header_size) };
    let minimum = u32::try_from(size_of::<RAWINPUT>())
        .map_err(|_| WindowsPlatformError::RawInputUnavailable)?;
    if queried != 0 || byte_len < minimum || byte_len > MAX_RAW_INPUT_BYTES {
        return Err(WindowsPlatformError::RawInputUnavailable);
    }
    let units = usize::try_from(byte_len)
        .map_err(|_| WindowsPlatformError::RawInputUnavailable)?
        .div_ceil(size_of::<usize>());
    let mut storage = vec![0_usize; units];
    let mut received = byte_len;
    // SAFETY: usize storage provides RAWINPUT alignment and at least byte_len
    // writable bytes. The native call does not retain this buffer.
    let copied = unsafe {
        GetRawInputData(
            handle,
            RID_INPUT,
            Some(storage.as_mut_ptr().cast::<c_void>()),
            &raw mut received,
            header_size,
        )
    };
    if copied == u32::MAX || copied != byte_len || received != byte_len {
        return Err(WindowsPlatformError::RawInputUnavailable);
    }
    // SAFETY: GetRawInputData initialized a complete RAWINPUT at the aligned
    // start of storage, and its header size was bounded above.
    let raw = unsafe { &*(storage.as_ptr().cast::<RAWINPUT>()) };
    if raw.header.dwSize > byte_len {
        return Err(WindowsPlatformError::RawInputUnavailable);
    }
    // SAFETY: GetMessageTime reads scalar state for the message currently being
    // dispatched on this capture thread.
    let timestamp = unsafe { GetMessageTime() }.cast_unsigned();
    match raw.header.dwType {
        value if value == RIM_TYPEKEYBOARD.0 => {
            // SAFETY: dwType selects the initialized keyboard union member.
            let keyboard = unsafe { raw.data.keyboard };
            let pressed = u32::from(keyboard.Flags) & RI_KEY_BREAK == 0;
            let key = HookObservationKey::Keyboard {
                scan_code: keyboard.MakeCode,
                virtual_key: keyboard.VKey,
                pressed,
            };
            if keyboard.ExtraInformation == NODAVO_INPUT_TAG_LOW32 {
                discard_origin(context, key, timestamp);
                return Ok(());
            }
            emit_if_physical(
                context,
                key,
                timestamp,
                NativeInputEvent::Keyboard {
                    scan_code: keyboard.MakeCode,
                    virtual_key: keyboard.VKey,
                    extended: u32::from(keyboard.Flags) & RI_KEY_E0 != 0,
                    e1: u32::from(keyboard.Flags) & RI_KEY_E1 != 0,
                    pressed,
                },
            );
        }
        value if value == RIM_TYPEMOUSE.0 => {
            // SAFETY: dwType selects the initialized mouse union member.
            let mouse = unsafe { raw.data.mouse };
            // SAFETY: RAWMOUSE always initializes its button-flags/data view.
            let buttons = unsafe { mouse.Anonymous.Anonymous };
            if mouse.ulExtraInformation == NODAVO_INPUT_TAG_LOW32 {
                discard_raw_mouse_origins(
                    context,
                    mouse.lLastX != 0 || mouse.lLastY != 0,
                    buttons.usButtonFlags,
                    timestamp,
                );
                return Ok(());
            }
            if mouse.lLastX != 0 || mouse.lLastY != 0 {
                let mut point = POINT::default();
                // SAFETY: point is a live output location.
                if unsafe { GetCursorPos(&raw mut point) }.is_ok() {
                    emit_if_physical(
                        context,
                        HookObservationKey::Mouse {
                            message: WM_MOUSEMOVE,
                        },
                        timestamp,
                        NativeInputEvent::PointerMotion {
                            x: point.x,
                            y: point.y,
                            delta_x: mouse.lLastX,
                            delta_y: mouse.lLastY,
                        },
                    );
                }
            }
            emit_raw_mouse_buttons(context, buttons.usButtonFlags, timestamp);
            let delta = i32::from(i16::from_ne_bytes(buttons.usButtonData.to_ne_bytes()));
            if u32::from(buttons.usButtonFlags) & RI_MOUSE_WHEEL != 0 {
                emit_if_physical(
                    context,
                    HookObservationKey::Mouse {
                        message: WM_MOUSEWHEEL,
                    },
                    timestamp,
                    NativeInputEvent::Scroll {
                        horizontal: 0,
                        vertical: delta,
                    },
                );
            }
            if u32::from(buttons.usButtonFlags) & RI_MOUSE_HWHEEL != 0 {
                emit_if_physical(
                    context,
                    HookObservationKey::Mouse {
                        message: WM_MOUSEHWHEEL,
                    },
                    timestamp,
                    NativeInputEvent::Scroll {
                        horizontal: delta,
                        vertical: 0,
                    },
                );
            }
        }
        _ => {}
    }
    Ok(())
}

fn emit_raw_mouse_buttons(context: &mut InputCaptureContext, flags: u16, timestamp: u32) {
    let flags = u32::from(flags);
    for (mask, message, button, pressed) in raw_mouse_button_messages() {
        if flags & mask != 0 {
            emit_if_physical(
                context,
                HookObservationKey::Mouse { message },
                timestamp,
                NativeInputEvent::PointerButton { button, pressed },
            );
        }
    }
}

fn discard_raw_mouse_origins(
    context: &mut InputCaptureContext,
    moved: bool,
    flags: u16,
    timestamp: u32,
) {
    if moved {
        discard_origin(
            context,
            HookObservationKey::Mouse {
                message: WM_MOUSEMOVE,
            },
            timestamp,
        );
    }
    let flags = u32::from(flags);
    for (mask, message, _, _) in raw_mouse_button_messages() {
        if flags & mask != 0 {
            discard_origin(context, HookObservationKey::Mouse { message }, timestamp);
        }
    }
    if flags & RI_MOUSE_WHEEL != 0 {
        discard_origin(
            context,
            HookObservationKey::Mouse {
                message: WM_MOUSEWHEEL,
            },
            timestamp,
        );
    }
    if flags & RI_MOUSE_HWHEEL != 0 {
        discard_origin(
            context,
            HookObservationKey::Mouse {
                message: WM_MOUSEHWHEEL,
            },
            timestamp,
        );
    }
}

const fn raw_mouse_button_messages() -> [(u32, u32, u8, bool); 10] {
    [
        (RI_MOUSE_BUTTON_1_DOWN, WM_LBUTTONDOWN, 1, true),
        (RI_MOUSE_BUTTON_1_UP, WM_LBUTTONUP, 1, false),
        (RI_MOUSE_BUTTON_2_DOWN, WM_RBUTTONDOWN, 2, true),
        (RI_MOUSE_BUTTON_2_UP, WM_RBUTTONUP, 2, false),
        (RI_MOUSE_BUTTON_3_DOWN, WM_MBUTTONDOWN, 3, true),
        (RI_MOUSE_BUTTON_3_UP, WM_MBUTTONUP, 3, false),
        (RI_MOUSE_BUTTON_4_DOWN, WM_XBUTTONDOWN, 4, true),
        (RI_MOUSE_BUTTON_4_UP, WM_XBUTTONUP, 4, false),
        (RI_MOUSE_BUTTON_5_DOWN, WM_XBUTTONDOWN, 5, true),
        (RI_MOUSE_BUTTON_5_UP, WM_XBUTTONUP, 5, false),
    ]
}

fn discard_origin(context: &mut InputCaptureContext, key: HookObservationKey, timestamp: u32) {
    if let Some(admission) = context.take_origin(key, timestamp) {
        let _ = context
            .routing_to_peer
            .complete_reliable_suppressions(admission.reliable_suppressions);
    }
}

fn emit_if_physical(
    context: &mut InputCaptureContext,
    key: HookObservationKey,
    timestamp: u32,
    event: NativeInputEvent,
) {
    let Some(admission) = context.take_origin(key, timestamp) else {
        if native_event_is_reliable(event) && context.routing_to_peer.is_enabled() {
            context.fail_reliable_delivery();
        }
        return;
    };
    let reliable_suppressed = admission.reliable_suppressions != 0;
    if admission.disposition == crate::CaptureDisposition::AcceptPhysical
        && ((context.session_active && context.desktop_available) || reliable_suppressed)
    {
        context.emit(
            event,
            Some(NativeRoutingObservation {
                hook_suppressed: admission.suppressed,
                routed_at_hook: admission.routed_at_hook,
                reliable_suppressed,
                epoch: admission.routing_epoch,
            }),
            admission.reliable_suppressions,
        );
    } else {
        let _ = context
            .routing_to_peer
            .complete_reliable_suppressions(admission.reliable_suppressions);
    }
}

const fn native_event_is_reliable(event: NativeInputEvent) -> bool {
    matches!(
        event,
        NativeInputEvent::Keyboard { .. }
            | NativeInputEvent::PointerButton { .. }
            | NativeInputEvent::Scroll { .. }
    )
}

#[cfg(test)]
mod capture_tests {
    use super::*;

    fn context() -> InputCaptureContext {
        InputCaptureContext {
            callback: Box::new(|_, _| Ok(())),
            routing_to_peer: Arc::new(RoutingAdmission::default()),
            observations: VecDeque::new(),
            session_active: true,
            desktop_available: true,
            callback_failed: false,
            native_failed: false,
            reliable_delivery_failed: false,
            pending_lifecycle: None,
        }
    }

    #[test]
    fn ambiguous_hook_origins_fail_closed() {
        let mut context = context();
        context.routing_to_peer.enable().unwrap();
        let key = HookObservationKey::Keyboard {
            scan_code: 0x1e,
            virtual_key: 0x41,
            pressed: true,
        };
        let routing = Arc::clone(&context.routing_to_peer);
        let physical = routing.begin();
        physical.commit_reliable_suppression().unwrap();
        let epoch = physical.epoch();
        assert!(context.record_hook(HookObservation {
            key,
            disposition: crate::CaptureDisposition::AcceptPhysical,
            timestamp: 10,
            suppressed: true,
            reliable_suppressed: true,
            routed_at_hook: true,
            routing_epoch: epoch,
        }));
        drop(physical);
        context.record_hook(HookObservation {
            key,
            disposition: crate::CaptureDisposition::RejectOtherInjected,
            timestamp: 10,
            suppressed: false,
            reliable_suppressed: false,
            routed_at_hook: false,
            routing_epoch: epoch,
        });
        let conflict = context.take_origin(key, 10).unwrap();
        assert_eq!(
            conflict.disposition,
            crate::CaptureDisposition::RejectOtherInjected
        );
        assert_eq!(conflict.reliable_suppressions, 1);
        assert!(context.native_failed);
        assert!(context.reliable_delivery_failed);
        assert!(!context.routing_to_peer.is_enabled());
        assert!(
            context
                .routing_to_peer
                .complete_reliable_suppressions(conflict.reliable_suppressions)
        );
        assert!(context.take_origin(key, 10).is_none());
    }

    #[test]
    fn duplicate_physical_origins_complete_one_reliable_event_each() {
        let mut context = context();
        context.routing_to_peer.enable().unwrap();
        let key = HookObservationKey::Keyboard {
            scan_code: 0x1e,
            virtual_key: 0x41,
            pressed: true,
        };
        for _ in 0..2 {
            let routing = Arc::clone(&context.routing_to_peer);
            let hook = routing.begin();
            hook.commit_reliable_suppression().unwrap();
            let epoch = hook.epoch();
            assert!(context.record_hook(HookObservation {
                key,
                disposition: crate::CaptureDisposition::AcceptPhysical,
                timestamp: 10,
                suppressed: true,
                reliable_suppressed: true,
                routed_at_hook: true,
                routing_epoch: epoch,
            }));
            drop(hook);
        }

        let first = context.take_origin(key, 10).unwrap();
        let second = context.take_origin(key, 10).unwrap();
        assert_eq!(first.reliable_suppressions, 1);
        assert_eq!(second.reliable_suppressions, 1);
        assert!(
            context
                .routing_to_peer
                .complete_reliable_suppressions(first.reliable_suppressions)
        );
        assert!(
            context
                .routing_to_peer
                .complete_reliable_suppressions(second.reliable_suppressions)
        );
        assert!(context.routing_to_peer.disable().is_ok());
    }

    #[test]
    fn callback_error_immediately_disables_routing() {
        let mut context = context();
        context.routing_to_peer.enable().unwrap();
        context.callback = Box::new(|_, _| Err(WindowsPlatformError::CaptureCallbackFailed));

        context.emit(
            NativeInputEvent::Lifecycle(NativeLifecycleEvent::InputDeviceChanged),
            None,
            0,
        );

        assert!(context.callback_failed);
        assert!(!context.routing_to_peer.is_enabled());
    }

    #[test]
    fn suppressed_reliable_callback_error_requires_process_poison_result() {
        let mut context = context();
        context.routing_to_peer.enable().unwrap();
        context.callback = Box::new(|_, _| Err(WindowsPlatformError::CaptureCallbackFailed));
        let key = HookObservationKey::Keyboard {
            scan_code: 0x1e,
            virtual_key: 0x41,
            pressed: true,
        };
        let routing = Arc::clone(&context.routing_to_peer);
        let hook = routing.begin();
        hook.commit_reliable_suppression().unwrap();
        assert!(context.record_hook(HookObservation {
            key,
            disposition: crate::CaptureDisposition::AcceptPhysical,
            timestamp: 15,
            suppressed: true,
            reliable_suppressed: true,
            routed_at_hook: true,
            routing_epoch: hook.epoch(),
        }));
        drop(hook);

        emit_if_physical(
            &mut context,
            key,
            15,
            NativeInputEvent::Keyboard {
                scan_code: 0x1e,
                virtual_key: 0x41,
                extended: false,
                e1: false,
                pressed: true,
            },
        );

        assert!(context.callback_failed);
        assert!(context.reliable_delivery_failed);
        assert!(!context.routing_to_peer.is_enabled());
    }

    #[test]
    fn reliable_suppression_barrier_waits_for_raw_bridge_delivery() {
        let (bridge, delivered) = std::sync::mpsc::sync_channel(1);
        let mut context = context();
        context.callback = Box::new(move |event, suppressed| {
            bridge.send((event, suppressed)).unwrap();
            Ok(())
        });
        context.routing_to_peer.enable().unwrap();
        let key = HookObservationKey::Keyboard {
            scan_code: 0x1e,
            virtual_key: 0x41,
            pressed: false,
        };
        let hook_routing = Arc::clone(&context.routing_to_peer);
        let hook = hook_routing.begin();
        hook.commit_reliable_suppression().unwrap();
        let epoch = hook.epoch();
        assert!(context.record_hook(HookObservation {
            key,
            disposition: crate::CaptureDisposition::AcceptPhysical,
            timestamp: 10,
            suppressed: true,
            reliable_suppressed: true,
            routed_at_hook: true,
            routing_epoch: epoch,
        }));
        drop(hook);

        let routing = Arc::clone(&context.routing_to_peer);
        let (barrier, barrier_result) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || barrier.send(routing.disable()).unwrap());
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        while context.routing_to_peer.is_enabled() && std::time::Instant::now() < deadline {
            std::thread::yield_now();
        }
        assert!(!context.routing_to_peer.is_enabled());
        assert!(matches!(
            barrier_result.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));

        emit_if_physical(
            &mut context,
            key,
            10,
            NativeInputEvent::Keyboard {
                scan_code: 0x1e,
                virtual_key: 0x41,
                extended: false,
                e1: false,
                pressed: false,
            },
        );
        assert_eq!(barrier_result.recv().unwrap(), Ok(()));
        assert_eq!(
            delivered.recv().unwrap(),
            (
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
        );
        worker.join().unwrap();
    }

    #[test]
    fn lifecycle_loss_delivers_suppressed_reliable_input_before_callback() {
        let delivered = Arc::new(Mutex::new(Vec::new()));
        let callback_delivered = Arc::clone(&delivered);
        let mut context = context();
        context.callback = Box::new(move |event, routing| {
            callback_delivered.lock().unwrap().push((event, routing));
            Ok(())
        });
        context.routing_to_peer.enable().unwrap();
        let key = HookObservationKey::Keyboard {
            scan_code: 0x1e,
            virtual_key: 0x41,
            pressed: false,
        };
        let hook_routing = Arc::clone(&context.routing_to_peer);
        let hook = hook_routing.begin();
        hook.commit_reliable_suppression().unwrap();
        let epoch = hook.epoch();
        assert!(context.record_hook(HookObservation {
            key,
            disposition: crate::CaptureDisposition::AcceptPhysical,
            timestamp: 20,
            suppressed: true,
            reliable_suppressed: true,
            routed_at_hook: true,
            routing_epoch: epoch,
        }));
        drop(hook);

        context.session_active = false;
        context.emit_lifecycle(NativeLifecycleEvent::SessionLocked);
        assert!(context.pending_lifecycle.is_some());
        assert!(!context.routing_to_peer.is_enabled());
        assert!(delivered.lock().unwrap().is_empty());

        emit_if_physical(
            &mut context,
            key,
            20,
            NativeInputEvent::Keyboard {
                scan_code: 0x1e,
                virtual_key: 0x41,
                extended: false,
                e1: false,
                pressed: false,
            },
        );
        context.finish_pending_lifecycle_if_drained();

        let delivered = delivered.lock().unwrap();
        assert_eq!(delivered.len(), 2);
        assert!(matches!(
            delivered[0],
            (
                NativeInputEvent::Keyboard { pressed: false, .. },
                Some(NativeRoutingObservation {
                    reliable_suppressed: true,
                    ..
                })
            )
        ));
        assert_eq!(
            delivered[1],
            (
                NativeInputEvent::Lifecycle(NativeLifecycleEvent::SessionLocked),
                None
            )
        );
        assert!(context.pending_lifecycle.is_none());
        assert!(!context.native_failed);
    }

    #[test]
    fn lifecycle_missing_reliable_raw_input_is_terminal_not_clean() {
        let delivered = Arc::new(Mutex::new(Vec::new()));
        let callback_delivered = Arc::clone(&delivered);
        let mut context = context();
        context.callback = Box::new(move |event, routing| {
            callback_delivered.lock().unwrap().push((event, routing));
            Ok(())
        });
        context.routing_to_peer.enable().unwrap();
        let routing = Arc::clone(&context.routing_to_peer);
        let hook = routing.begin();
        hook.commit_reliable_suppression().unwrap();
        assert!(context.record_hook(HookObservation {
            key: HookObservationKey::Keyboard {
                scan_code: 0x1e,
                virtual_key: 0x41,
                pressed: false,
            },
            disposition: crate::CaptureDisposition::AcceptPhysical,
            timestamp: 30,
            suppressed: true,
            reliable_suppressed: true,
            routed_at_hook: true,
            routing_epoch: hook.epoch(),
        }));
        drop(hook);

        context.session_active = false;
        context.emit_lifecycle(NativeLifecycleEvent::SessionLocked);
        std::thread::sleep(RELIABLE_LIFECYCLE_DRAIN_TIMEOUT + Duration::from_millis(10));
        context.poll_pending_lifecycle();

        assert!(context.native_failed);
        assert!(context.reliable_delivery_failed);
        assert!(context.pending_lifecycle.is_none());
        assert!(!context.routing_to_peer.is_enabled());
        assert!(delivered.lock().unwrap().is_empty());
    }

    #[test]
    fn second_lifecycle_while_reliable_delivery_pending_is_terminal() {
        let mut context = context();
        context.routing_to_peer.enable().unwrap();
        let routing = Arc::clone(&context.routing_to_peer);
        let hook = routing.begin();
        hook.commit_reliable_suppression().unwrap();
        assert!(context.record_hook(HookObservation {
            key: HookObservationKey::Keyboard {
                scan_code: 0x1e,
                virtual_key: 0x41,
                pressed: false,
            },
            disposition: crate::CaptureDisposition::AcceptPhysical,
            timestamp: 35,
            suppressed: true,
            reliable_suppressed: true,
            routed_at_hook: true,
            routing_epoch: hook.epoch(),
        }));
        drop(hook);

        context.session_active = false;
        context.emit_lifecycle(NativeLifecycleEvent::SessionLocked);
        assert!(context.pending_lifecycle.is_some());
        context.emit_lifecycle(NativeLifecycleEvent::InputDeviceChanged);

        assert!(context.native_failed);
        assert!(context.reliable_delivery_failed);
        assert!(context.pending_lifecycle.is_none());
        assert!(!context.routing_to_peer.is_enabled());
    }

    #[test]
    fn expired_reliable_observation_never_emits_pending_lifecycle() {
        let delivered = Arc::new(Mutex::new(Vec::new()));
        let callback_delivered = Arc::clone(&delivered);
        let mut context = context();
        context.callback = Box::new(move |event, routing| {
            callback_delivered.lock().unwrap().push((event, routing));
            Ok(())
        });
        context.routing_to_peer.enable().unwrap();
        let routing = Arc::clone(&context.routing_to_peer);
        let hook = routing.begin();
        hook.commit_reliable_suppression().unwrap();
        assert!(context.record_hook(HookObservation {
            key: HookObservationKey::Keyboard {
                scan_code: 0x1e,
                virtual_key: 0x41,
                pressed: false,
            },
            disposition: crate::CaptureDisposition::AcceptPhysical,
            timestamp: 10,
            suppressed: true,
            reliable_suppressed: true,
            routed_at_hook: true,
            routing_epoch: hook.epoch(),
        }));
        drop(hook);
        context.session_active = false;
        context.emit_lifecycle(NativeLifecycleEvent::SessionLocked);
        assert!(context.pending_lifecycle.is_some());

        emit_if_physical(
            &mut context,
            HookObservationKey::Mouse {
                message: WM_MOUSEMOVE,
            },
            10 + HOOK_OBSERVATION_MAX_AGE_MS + 1,
            NativeInputEvent::PointerMotion {
                x: 0,
                y: 0,
                delta_x: 1,
                delta_y: 1,
            },
        );
        context.finish_pending_lifecycle_if_drained();

        assert!(context.native_failed);
        assert!(context.reliable_delivery_failed);
        assert!(context.pending_lifecycle.is_none());
        assert!(delivered.lock().unwrap().is_empty());
    }

    #[test]
    fn missing_reliable_hook_observation_terminates_enabled_capture() {
        let delivered = Arc::new(Mutex::new(Vec::new()));
        let callback_delivered = Arc::clone(&delivered);
        let mut context = context();
        context.callback = Box::new(move |event, routing| {
            callback_delivered.lock().unwrap().push((event, routing));
            Ok(())
        });
        context.routing_to_peer.enable().unwrap();

        emit_if_physical(
            &mut context,
            HookObservationKey::Keyboard {
                scan_code: 0x1e,
                virtual_key: 0x41,
                pressed: true,
            },
            40,
            NativeInputEvent::Keyboard {
                scan_code: 0x1e,
                virtual_key: 0x41,
                extended: false,
                e1: false,
                pressed: true,
            },
        );

        assert!(context.native_failed);
        assert!(context.reliable_delivery_failed);
        assert!(!context.routing_to_peer.is_enabled());
        assert!(delivered.lock().unwrap().is_empty());
    }
}

pub(super) fn replace_file_atomic(
    source: &Path,
    destination: &Path,
) -> Result<(), WindowsPlatformError> {
    let source = nul_terminated_path(source)?;
    let destination = nul_terminated_path(destination)?;
    let flags = MOVE_FILE_FLAGS(MOVEFILE_REPLACE_EXISTING.0 | MOVEFILE_WRITE_THROUGH.0);
    // SAFETY: both path buffers are live, NUL-terminated UTF-16 strings for
    // the duration of this synchronous call. COPY_ALLOWED is intentionally
    // absent, so a cross-volume operation fails instead of degrading to copy.
    unsafe {
        MoveFileExW(PCWSTR(source.as_ptr()), PCWSTR(destination.as_ptr()), flags)
            .map_err(|_| WindowsPlatformError::NativeApi)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeUpdateFileOpenError {
    NotFound,
    Failed,
}

impl NativeUpdateFileOpenError {
    pub(crate) const fn is_not_found(self) -> bool {
        matches!(self, Self::NotFound)
    }
}

pub(crate) fn create_private_update_directory(path: &Path) -> Result<(), WindowsPlatformError> {
    let path = nul_terminated_path(path)?;
    with_owner_only_security_attributes(|attributes| {
        // SAFETY: the path and owner-only security descriptor are live for the
        // synchronous call. The protected DACL is applied at directory birth.
        unsafe { CreateDirectoryW(PCWSTR(path.as_ptr()), Some(attributes)) }
            .map_err(|_| WindowsPlatformError::NativeApi)
    })
}

/// Creates the visible receive root with the transfer core's exact directory
/// security policy present at namespace publication.
pub(crate) fn create_private_receive_directory(path: &Path) -> Result<(), WindowsPlatformError> {
    let path = nul_terminated_path(path)?;
    with_receive_owner_only_security_attributes(|attributes| {
        // SAFETY: the path and dynamic current-user security descriptor remain
        // live for the synchronous call. OICI inheritance and the protected
        // DACL are therefore present at the instant the leaf is published.
        unsafe { CreateDirectoryW(PCWSTR(path.as_ptr()), Some(attributes)) }
            .map_err(|_| WindowsPlatformError::NativeApi)
    })
}

/// Resolves the current interactive user's Downloads known folder.
///
/// The shell allocation is always released with `CoTaskMemFree`. Environment
/// variables are intentionally not part of this boundary.
pub(crate) fn current_user_downloads_directory() -> Result<PathBuf, WindowsPlatformError> {
    let folder_id = FOLDERID_Downloads;
    // SAFETY: the documented Downloads folder identifier is static, default
    // flags request the current configured path, and a null token means the
    // current interactive user. The returned COM allocation is guarded below.
    let value = unsafe {
        SHGetKnownFolderPath(&raw const folder_id, KF_FLAG_DEFAULT, None)
            .map_err(|_| WindowsPlatformError::NativeApi)?
    };
    if value.is_null() {
        return Err(WindowsPlatformError::NativeApi);
    }
    let owned = CoTaskWideString(value);
    let mut length = None;
    for index in 0..=MAX_KNOWN_FOLDER_PATH_UNITS {
        // SAFETY: SHGetKnownFolderPath returns a valid NUL-terminated COM
        // allocation. The local policy bounds the accepted path length.
        if unsafe { *owned.0.0.add(index) } == 0 {
            length = Some(index);
            break;
        }
    }
    let length = length.ok_or(WindowsPlatformError::NativeApi)?;
    if length == 0 {
        return Err(WindowsPlatformError::NativeApi);
    }
    // SAFETY: the bounded scan above found the terminator in this allocation.
    let units = unsafe { std::slice::from_raw_parts(owned.0.0, length) };
    Ok(PathBuf::from(OsString::from_wide(units)))
}

pub(crate) fn open_retained_update_directory(
    path: &Path,
) -> Result<std::fs::File, WindowsPlatformError> {
    let path = nul_terminated_path(path)?;
    let flags = FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT;
    // SAFETY: the path is a live NUL-terminated string. Read/write sharing lets
    // this process enumerate the retained directory; absent delete sharing
    // prevents replacement or rename of the root. READ_CONTROL is required by
    // the immediate owner/DACL validation through GetSecurityInfo.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(path.as_ptr()),
            FILE_LIST_DIRECTORY.0 | FILE_READ_ATTRIBUTES.0 | READ_CONTROL.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            flags,
            None,
        )
    }
    .map_err(|_| WindowsPlatformError::NativeApi)?;
    owned_handle(handle).map(std::fs::File::from)
}

/// Opens the final private receive root for handle-relative mutation.
///
/// Unlike namespace-observation handles, this final capability carries the
/// current user's read/write directory rights and `WRITE_DAC`, which the
/// transfer boundary needs to create and verify owner-only children. Delete
/// sharing remains absent so the exact root cannot be renamed or replaced.
pub(crate) fn open_retained_receive_directory(
    path: &Path,
) -> Result<std::fs::File, WindowsPlatformError> {
    let path = nul_terminated_path(path)?;
    let flags = FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT;
    // SAFETY: the path is a live NUL-terminated string. The protected leaf is
    // opened for handle-relative current-user transfer mutations. Read/write
    // sharing permits bounded child work; absent delete sharing retains the
    // exact directory object. OPEN_REPARSE_POINT suppresses final traversal.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(path.as_ptr()),
            FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0 | READ_CONTROL.0 | WRITE_DAC.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            flags,
            None,
        )
    }
    .map_err(|_| WindowsPlatformError::NativeApi)?;
    owned_handle(handle).map(std::fs::File::from)
}

pub(crate) fn canonical_fixed_volume_root(
    drive_root: &std::fs::File,
) -> Result<PathBuf, WindowsPlatformError> {
    let canonical = canonical_volume_path(drive_root)?;
    let canonical_units = nul_terminated_path(&canonical)?;
    // SAFETY: the canonical volume-GUID root is live and NUL-terminated. A
    // network, removable, optical, RAM, or unknown volume is not accepted for
    // update durability.
    if unsafe { GetDriveTypeW(PCWSTR(canonical_units.as_ptr())) } != DRIVE_FIXED {
        return Err(WindowsPlatformError::NativeApi);
    }
    Ok(canonical)
}

pub(crate) fn canonical_volume_path(
    handle: &std::fs::File,
) -> Result<PathBuf, WindowsPlatformError> {
    let mut encoded = vec![0_u16; MAX_WINDOWS_PATH_UNITS];
    let flags = VOLUME_NAME_GUID;
    // SAFETY: the retained handle and complete mutable output buffer are live
    // for this call. The fixed bound exceeds every accepted path.
    let length =
        unsafe { GetFinalPathNameByHandleW(HANDLE(handle.as_raw_handle()), &mut encoded, flags) };
    let length = usize::try_from(length).map_err(|_| WindowsPlatformError::NativeApi)?;
    if length == 0 || length >= encoded.len() {
        return Err(WindowsPlatformError::NativeApi);
    }
    encoded.truncate(length);
    Ok(PathBuf::from(OsString::from_wide(&encoded)))
}

pub(crate) fn open_or_create_private_update_lease(
    path: &Path,
) -> Result<std::fs::File, WindowsPlatformError> {
    match open_update_file(path, true, OPEN_EXISTING, None) {
        Ok(file) => Ok(file),
        Err(NativeUpdateFileOpenError::NotFound) => {
            let mut created = None;
            with_owner_only_security_attributes(|attributes| {
                created = Some(
                    open_update_file(path, true, CREATE_NEW, Some(attributes))
                        .map_err(|_| WindowsPlatformError::NativeApi)?,
                );
                Ok(())
            })
            .map_err(|_| WindowsPlatformError::NativeApi)?;
            created.ok_or(WindowsPlatformError::NativeApi)
        }
        Err(NativeUpdateFileOpenError::Failed) => Err(WindowsPlatformError::NativeApi),
    }
}

pub(crate) fn create_private_update_file(
    path: &Path,
) -> Result<std::fs::File, WindowsPlatformError> {
    let mut created = None;
    with_owner_only_security_attributes(|attributes| {
        created = Some(
            open_update_file(path, true, CREATE_NEW, Some(attributes))
                .map_err(|_| WindowsPlatformError::NativeApi)?,
        );
        Ok(())
    })
    .map_err(|_| WindowsPlatformError::NativeApi)?;
    created.ok_or(WindowsPlatformError::NativeApi)
}

pub(crate) fn open_existing_update_file(
    path: &Path,
    writable: bool,
) -> Result<std::fs::File, NativeUpdateFileOpenError> {
    open_update_file(path, writable, OPEN_EXISTING, None)
}

fn open_update_file(
    path: &Path,
    writable: bool,
    disposition: windows::Win32::Storage::FileSystem::FILE_CREATION_DISPOSITION,
    security: Option<*const SECURITY_ATTRIBUTES>,
) -> Result<std::fs::File, NativeUpdateFileOpenError> {
    let path = nul_terminated_path(path).map_err(|_| NativeUpdateFileOpenError::Failed)?;
    let desired_access = if writable {
        FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0
    } else {
        FILE_GENERIC_READ.0
    };
    let flags = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT;
    // SAFETY: the path and optional security descriptor are live for this call.
    // No sharing is granted and reparse traversal is explicitly suppressed.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(path.as_ptr()),
            desired_access,
            FILE_SHARE_NONE,
            security,
            disposition,
            flags,
            None,
        )
    };
    match handle {
        Ok(handle) => owned_handle(handle)
            .map(std::fs::File::from)
            .map_err(|_| NativeUpdateFileOpenError::Failed),
        Err(error)
            if error.code() == ERROR_FILE_NOT_FOUND.to_hresult()
                || error.code() == ERROR_PATH_NOT_FOUND.to_hresult() =>
        {
            Err(NativeUpdateFileOpenError::NotFound)
        }
        Err(_) => Err(NativeUpdateFileOpenError::Failed),
    }
}

pub(crate) fn move_update_file_write_through(
    source: &Path,
    destination: &Path,
    replace: bool,
) -> Result<(), WindowsPlatformError> {
    if source == destination
        || source.parent() != destination.parent()
        || source.file_name().is_none()
        || destination.file_name().is_none()
    {
        return Err(WindowsPlatformError::NativeApi);
    }
    let source = nul_terminated_path(source)?;
    let destination = nul_terminated_path(destination)?;
    let mut flags = MOVEFILE_WRITE_THROUGH;
    if replace {
        flags = MOVE_FILE_FLAGS(flags.0 | MOVEFILE_REPLACE_EXISTING.0);
    }
    // SAFETY: both path buffers are live NUL-terminated UTF-16. COPY_ALLOWED
    // is absent, so the namespace mutation cannot silently cross volumes.
    unsafe { MoveFileExW(PCWSTR(source.as_ptr()), PCWSTR(destination.as_ptr()), flags) }
        .map_err(|_| WindowsPlatformError::NativeApi)
}

pub(crate) fn validate_private_update_handle(
    file: &std::fs::File,
) -> Result<(), WindowsPlatformError> {
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    let information =
        OBJECT_SECURITY_INFORMATION(OWNER_SECURITY_INFORMATION.0 | DACL_SECURITY_INFORMATION.0);
    // SAFETY: the retained file handle is valid; only the self-relative
    // descriptor output is requested and it is released with LocalFree below.
    let status = unsafe {
        GetSecurityInfo(
            HANDLE(file.as_raw_handle()),
            SE_FILE_OBJECT,
            information,
            None,
            None,
            None,
            None,
            Some(&raw mut descriptor),
        )
    };
    if status != ERROR_SUCCESS || descriptor.0.is_null() {
        return Err(WindowsPlatformError::NativeApi);
    }
    let descriptor = LocalSecurityDescriptor(descriptor);
    let mut encoded = PWSTR::null();
    let mut encoded_length = 0_u32;
    // SAFETY: the descriptor is live and the output is LocalAlloc memory which
    // remains owned by the guard until after the bounded conversion.
    unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor.0,
            SDDL_REVISION_1,
            information,
            &raw mut encoded,
            Some(&raw mut encoded_length),
        )
        .map_err(|_| WindowsPlatformError::NativeApi)?;
    }
    if encoded.is_null() || encoded_length == 0 || encoded_length > 8 * 1024 {
        if !encoded.is_null() {
            let _ = unsafe { LocalFree(Some(HLOCAL(encoded.0.cast::<c_void>()))) };
        }
        return Err(WindowsPlatformError::NativeApi);
    }
    let encoded = LocalWideString(encoded);
    // SAFETY: the API reported the exact NUL-inclusive character count for the
    // retained allocation.
    let units = unsafe {
        std::slice::from_raw_parts(
            encoded.0.0,
            usize::try_from(encoded_length).map_err(|_| WindowsPlatformError::NativeApi)?,
        )
    };
    let terminator = units
        .iter()
        .position(|unit| *unit == 0)
        .ok_or(WindowsPlatformError::NativeApi)?;
    let actual =
        String::from_utf16(&units[..terminator]).map_err(|_| WindowsPlatformError::NativeApi)?;
    let expected = format!("O:{}D:P(A;;FA;;;OW)", current_user_sid_string()?);
    if actual != expected {
        return Err(WindowsPlatformError::NativeApi);
    }
    Ok(())
}

/// Validates the transfer core's exact receive-directory security invariant.
///
/// The current user must own the object. Its DACL must be protected and contain
/// exactly one allow ACE for that same SID, with only OI+CI inheritance flags
/// and exactly `FILE_ALL_ACCESS`.
#[allow(clippy::too_many_lines)]
pub(crate) fn validate_private_receive_handle(
    file: &std::fs::File,
) -> Result<(), WindowsPlatformError> {
    // SAFETY: GetCurrentProcess returns a process pseudo-handle that remains
    // valid for the process lifetime and must not be closed.
    let current_token = open_query_token(unsafe { GetCurrentProcess() })?;
    let current_user = read_token_user(as_windows_handle(&current_token))?;
    let current_sid = current_user.sid;

    let mut owner = PSID::default();
    let mut dacl = ptr::null_mut::<ACL>();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    let information =
        OBJECT_SECURITY_INFORMATION(OWNER_SECURITY_INFORMATION.0 | DACL_SECURITY_INFORMATION.0);
    // SAFETY: the retained file handle and all output pointers remain live;
    // the returned descriptor is transferred immediately to its guard.
    let status = unsafe {
        GetSecurityInfo(
            HANDLE(file.as_raw_handle()),
            SE_FILE_OBJECT,
            information,
            Some(&raw mut owner),
            None,
            Some(&raw mut dacl),
            None,
            Some(&raw mut descriptor),
        )
    };
    if status != ERROR_SUCCESS
        || descriptor.0.is_null()
        || owner.0.is_null()
        || dacl.is_null()
        || !unsafe { IsValidSid(owner) }.as_bool()
    {
        return Err(WindowsPlatformError::NativeApi);
    }
    let descriptor = LocalSecurityDescriptor(descriptor);
    // SAFETY: owner, current_sid, and the descriptor backing owner remain live.
    unsafe { EqualSid(owner, current_sid) }.map_err(|_| WindowsPlatformError::NativeApi)?;

    let mut control = 0_u16;
    let mut revision = 0_u32;
    // SAFETY: the guarded descriptor and scalar outputs remain live.
    unsafe {
        GetSecurityDescriptorControl(descriptor.0, &raw mut control, &raw mut revision)
            .map_err(|_| WindowsPlatformError::NativeApi)?;
    }
    if control & SE_DACL_PROTECTED.0 == 0 {
        return Err(WindowsPlatformError::NativeApi);
    }

    let mut acl_information = ACL_SIZE_INFORMATION::default();
    // SAFETY: the DACL belongs to the guarded descriptor and the output has
    // exactly the documented size and alignment.
    unsafe {
        GetAclInformation(
            dacl,
            ptr::from_mut(&mut acl_information).cast::<c_void>(),
            u32::try_from(size_of::<ACL_SIZE_INFORMATION>())
                .map_err(|_| WindowsPlatformError::NativeApi)?,
            AclSizeInformation,
        )
        .map_err(|_| WindowsPlatformError::NativeApi)?;
    }
    if acl_information.AceCount != 1 {
        return Err(WindowsPlatformError::NativeApi);
    }

    let mut raw_ace = ptr::null_mut::<c_void>();
    // SAFETY: the validated ACL reports exactly one entry and the output is live.
    unsafe { GetAce(dacl, 0, &raw mut raw_ace) }.map_err(|_| WindowsPlatformError::NativeApi)?;
    if raw_ace.is_null() {
        return Err(WindowsPlatformError::NativeApi);
    }
    let list_base = dacl.cast::<u8>() as usize;
    let list_limit = list_base
        .checked_add(
            usize::try_from(acl_information.AclBytesInUse)
                .map_err(|_| WindowsPlatformError::NativeApi)?,
        )
        .ok_or(WindowsPlatformError::NativeApi)?;
    let entry_base = raw_ace.cast::<u8>() as usize;
    let minimum_entry_base = list_base
        .checked_add(size_of::<ACL>())
        .ok_or(WindowsPlatformError::NativeApi)?;
    if entry_base != minimum_entry_base || entry_base >= list_limit {
        return Err(WindowsPlatformError::NativeApi);
    }
    let header_limit = entry_base
        .checked_add(size_of::<ACE_HEADER>())
        .ok_or(WindowsPlatformError::NativeApi)?;
    if header_limit > list_limit {
        return Err(WindowsPlatformError::NativeApi);
    }
    // SAFETY: the fixed ACE header is fully bounded by the live ACL.
    let header = unsafe { &*raw_ace.cast::<ACE_HEADER>() };
    let ace_size = usize::from(header.AceSize);
    let entry_limit = entry_base
        .checked_add(ace_size)
        .ok_or(WindowsPlatformError::NativeApi)?;
    let sid_offset = offset_of!(ACCESS_ALLOWED_ACE, SidStart);
    let minimum_ace_size = sid_offset
        .checked_add(8)
        .ok_or(WindowsPlatformError::NativeApi)?;
    if ace_size < minimum_ace_size || entry_limit > list_limit {
        return Err(WindowsPlatformError::NativeApi);
    }
    // SAFETY: all fixed ACCESS_ALLOWED_ACE fields and the fixed SID header are
    // bounded by AceSize and the containing live ACL.
    let ace = unsafe { &*raw_ace.cast::<ACCESS_ALLOWED_ACE>() };
    let expected_flags = u8::try_from((OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE).0)
        .map_err(|_| WindowsPlatformError::NativeApi)?;
    if u32::from(header.AceType) != ACCESS_ALLOWED_ACE_TYPE
        || header.AceFlags != expected_flags
        || ace.Mask != FILE_ALL_ACCESS.0
    {
        return Err(WindowsPlatformError::NativeApi);
    }

    let ace_sid_start = raw_ace.cast::<u8>().wrapping_add(sid_offset);
    // SAFETY: the complete fixed SID header lies within the bounded ACE.
    let sub_authority_count = usize::from(unsafe { *ace_sid_start.add(1) });
    let sid_size = 8_usize
        .checked_add(
            sub_authority_count
                .checked_mul(4)
                .ok_or(WindowsPlatformError::NativeApi)?,
        )
        .ok_or(WindowsPlatformError::NativeApi)?;
    if sid_offset
        .checked_add(sid_size)
        .is_none_or(|end| end != ace_size)
        || entry_limit != list_limit
    {
        return Err(WindowsPlatformError::NativeApi);
    }
    let ace_sid = PSID(ace_sid_start.cast::<c_void>());
    // SAFETY: the variable-length SID is bounded by the ACE and live ACL.
    if ace_sid.0.is_null() || !unsafe { IsValidSid(ace_sid) }.as_bool() {
        return Err(WindowsPlatformError::NativeApi);
    }
    // SAFETY: both SIDs are valid and backed by live storage.
    unsafe { EqualSid(ace_sid, current_sid) }.map_err(|_| WindowsPlatformError::NativeApi)
}

fn with_owner_only_security_attributes<T>(
    operation: impl FnOnce(*const SECURITY_ATTRIBUTES) -> Result<T, WindowsPlatformError>,
) -> Result<T, WindowsPlatformError> {
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: the static SDDL and output pointer are valid for this call.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(OWNER_ONLY_PIPE_SDDL.as_ptr()),
            SDDL_REVISION_1,
            &raw mut descriptor,
            None,
        )
        .map_err(|_| WindowsPlatformError::NativeApi)?;
    }
    let descriptor = LocalSecurityDescriptor(descriptor);
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>())
            .map_err(|_| WindowsPlatformError::NativeApi)?,
        lpSecurityDescriptor: descriptor.0.0,
        bInheritHandle: false.into(),
    };
    operation(&raw const attributes)
}

fn with_receive_owner_only_security_attributes<T>(
    operation: impl FnOnce(*const SECURITY_ATTRIBUTES) -> Result<T, WindowsPlatformError>,
) -> Result<T, WindowsPlatformError> {
    let sid = current_user_sid_string()?;
    let sddl = format!("O:{sid}D:P(A;OICI;FA;;;{sid})");
    let encoded = sddl
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: the bounded dynamic SDDL and output pointer remain live. The SID
    // was obtained from and validated against the current process token.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(encoded.as_ptr()),
            SDDL_REVISION_1,
            &raw mut descriptor,
            None,
        )
        .map_err(|_| WindowsPlatformError::NativeApi)?;
    }
    let descriptor = LocalSecurityDescriptor(descriptor);
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>())
            .map_err(|_| WindowsPlatformError::NativeApi)?,
        lpSecurityDescriptor: descriptor.0.0,
        bInheritHandle: false.into(),
    };
    operation(&raw const attributes)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeUpdateArchitecture {
    X64,
    Arm64,
}

pub(crate) struct NativeInspectedUpdatePackage {
    pub(crate) package_full_name: String,
    pub(crate) architecture: NativeUpdateArchitecture,
    pub(crate) resource_id: String,
    pub(crate) application_user_model_id: String,
}

pub(crate) struct NativeInspectedUpdateBundle {
    pub(crate) package_name: String,
    pub(crate) publisher: String,
    pub(crate) package_family_name: String,
    pub(crate) version: u64,
    pub(crate) packages: Vec<NativeInspectedUpdatePackage>,
}

#[allow(clippy::too_many_lines)]
pub(crate) fn inspect_update_bundle(
    bundle_guard: std::fs::File,
) -> Result<NativeInspectedUpdateBundle, WindowsPlatformError> {
    let metadata = bundle_guard
        .metadata()
        .map_err(|_| WindowsPlatformError::NativeApi)?;
    if !metadata.file_type().is_file()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
        || metadata.len() == 0
        || metadata.len() > 16 * 1024 * 1024 * 1024
    {
        return Err(WindowsPlatformError::NativeApi);
    }
    validate_private_update_handle(&bundle_guard)?;
    let _com = ComApartment::initialize()?;
    let stream = read_only_file_stream(bundle_guard, metadata.len())?;
    // SAFETY: COM is initialized on this thread and the class/interface IDs are
    // the official inbox Appx packaging factory.
    let bundle_factory: IAppxBundleFactory =
        unsafe { CoCreateInstance(&AppxBundleFactory, None, CLSCTX_INPROC_SERVER) }
            .map_err(|_| WindowsPlatformError::NativeApi)?;
    // SAFETY: the retained read-only stream remains live for the reader.
    let bundle_reader = unsafe { bundle_factory.CreateBundleReader(&stream) }
        .map_err(|_| WindowsPlatformError::NativeApi)?;
    // SAFETY: the reader owns validated bundle state for the returned manifest.
    let bundle_manifest =
        unsafe { bundle_reader.GetManifest() }.map_err(|_| WindowsPlatformError::NativeApi)?;
    // SAFETY: the manifest reader retains the identity object.
    let bundle_id =
        unsafe { bundle_manifest.GetPackageId() }.map_err(|_| WindowsPlatformError::NativeApi)?;
    let package_name = appx_package_id_text(&bundle_id, AppxIdentityText::Name, 50)?;
    let publisher = appx_package_id_text(&bundle_id, AppxIdentityText::Publisher, 8 * 1024)?;
    let package_family_name = appx_package_id_text(&bundle_id, AppxIdentityText::FamilyName, 64)?;
    // SAFETY: simple value getter on the retained identity.
    let version = unsafe { bundle_id.GetVersion() }.map_err(|_| WindowsPlatformError::NativeApi)?;

    // SAFETY: the official package factory consumes each payload IStream.
    let package_factory: IAppxFactory =
        unsafe { CoCreateInstance(&AppxFactory, None, CLSCTX_INPROC_SERVER) }
            .map_err(|_| WindowsPlatformError::NativeApi)?;
    // SAFETY: enumerator is retained by the bundle reader.
    let payloads = unsafe { bundle_reader.GetPayloadPackages() }
        .map_err(|_| WindowsPlatformError::NativeApi)?;
    let mut packages = Vec::new();
    // SAFETY: boolean/current/move-next calls follow the COM enumerator contract.
    while unsafe { payloads.GetHasCurrent() }
        .map_err(|_| WindowsPlatformError::NativeApi)?
        .as_bool()
    {
        if packages.len() >= 4 {
            return Err(WindowsPlatformError::NativeApi);
        }
        // SAFETY: GetHasCurrent returned true.
        let payload =
            unsafe { payloads.GetCurrent() }.map_err(|_| WindowsPlatformError::NativeApi)?;
        // SAFETY: the payload owns the returned read-only stream.
        let payload_stream =
            unsafe { payload.GetStream() }.map_err(|_| WindowsPlatformError::NativeApi)?;
        // SAFETY: factory and stream remain live through reader construction.
        let package_reader = unsafe { package_factory.CreatePackageReader(&payload_stream) }
            .map_err(|_| WindowsPlatformError::NativeApi)?;
        // SAFETY: the package reader retains the returned manifest.
        let manifest =
            unsafe { package_reader.GetManifest() }.map_err(|_| WindowsPlatformError::NativeApi)?;
        // SAFETY: identity is retained by the manifest reader.
        let package_id =
            unsafe { manifest.GetPackageId() }.map_err(|_| WindowsPlatformError::NativeApi)?;
        let payload_name = appx_package_id_text(&package_id, AppxIdentityText::Name, 50)?;
        let payload_publisher =
            appx_package_id_text(&package_id, AppxIdentityText::Publisher, 8 * 1024)?;
        // SAFETY: simple integer value getter.
        let payload_version =
            unsafe { package_id.GetVersion() }.map_err(|_| WindowsPlatformError::NativeApi)?;
        if payload_name != package_name
            || payload_publisher != publisher
            || payload_version != version
        {
            return Err(WindowsPlatformError::NativeApi);
        }
        // SAFETY: simple value getter.
        let architecture = match unsafe { package_id.GetArchitecture() }
            .map_err(|_| WindowsPlatformError::NativeApi)?
        {
            APPX_PACKAGE_ARCHITECTURE_X64 => NativeUpdateArchitecture::X64,
            APPX_PACKAGE_ARCHITECTURE_ARM64 => NativeUpdateArchitecture::Arm64,
            _ => return Err(WindowsPlatformError::NativeApi),
        };
        let resource_id = appx_package_id_text(&package_id, AppxIdentityText::ResourceId, 64)?;
        let package_full_name = appx_package_id_text(&package_id, AppxIdentityText::FullName, 255)?;

        // Exactly one application is required in every architecture payload.
        // SAFETY: the manifest retains the application enumerator.
        let applications =
            unsafe { manifest.GetApplications() }.map_err(|_| WindowsPlatformError::NativeApi)?;
        if !unsafe { applications.GetHasCurrent() }
            .map_err(|_| WindowsPlatformError::NativeApi)?
            .as_bool()
        {
            return Err(WindowsPlatformError::NativeApi);
        }
        // SAFETY: GetHasCurrent returned true.
        let application =
            unsafe { applications.GetCurrent() }.map_err(|_| WindowsPlatformError::NativeApi)?;
        // SAFETY: returned COM-owned string is copied and freed below.
        let application_user_model_id = take_appx_text(
            unsafe { application.GetAppUserModelId() }
                .map_err(|_| WindowsPlatformError::NativeApi)?,
            130,
            false,
        )?;
        if unsafe { applications.MoveNext() }
            .map_err(|_| WindowsPlatformError::NativeApi)?
            .as_bool()
        {
            return Err(WindowsPlatformError::NativeApi);
        }
        packages.push(NativeInspectedUpdatePackage {
            package_full_name,
            architecture,
            resource_id,
            application_user_model_id,
        });
        // SAFETY: advances the enumerator after consuming the current payload.
        let _ = unsafe { payloads.MoveNext() }.map_err(|_| WindowsPlatformError::NativeApi)?;
    }
    if packages.is_empty() {
        return Err(WindowsPlatformError::NativeApi);
    }
    Ok(NativeInspectedUpdateBundle {
        package_name,
        publisher,
        package_family_name,
        version,
        packages,
    })
}

pub(crate) fn open_update_bundle_guard(path: &Path) -> Result<std::fs::File, WindowsPlatformError> {
    let path = nul_terminated_path(path)?;
    let flags = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT;
    // SAFETY: the path is live and NUL-terminated. Read sharing permits only
    // handle-based IStream clones; absent write/delete sharing prevents
    // mutation or pathname replacement for the entire inspection.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(path.as_ptr()),
            FILE_GENERIC_READ.0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            flags,
            None,
        )
    }
    .map_err(|_| WindowsPlatformError::NativeApi)?;
    owned_handle(handle).map(std::fs::File::from)
}

#[implement(IStream)]
struct ReadOnlyFileStream {
    file: Mutex<std::fs::File>,
    length: u64,
}

fn read_only_file_stream(
    mut file: std::fs::File,
    length: u64,
) -> Result<IStream, WindowsPlatformError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| WindowsPlatformError::NativeApi)?;
    Ok(ReadOnlyFileStream {
        file: Mutex::new(file),
        length,
    }
    .into())
}

#[allow(non_snake_case)]
impl ISequentialStream_Impl for ReadOnlyFileStream_Impl {
    fn Read(&self, output: *mut c_void, requested: u32, read: *mut u32) -> HRESULT {
        if !read.is_null() {
            // SAFETY: COM requires a non-null output pointer to reference a live
            // u32 for this synchronous call.
            unsafe { read.write(0) };
        }
        if requested == 0 {
            return S_OK;
        }
        if output.is_null() {
            return STG_E_INVALIDPOINTER;
        }
        let Ok(length) = usize::try_from(requested) else {
            return STG_E_READFAULT;
        };
        // SAFETY: ISequentialStream::Read requires `output` to reference at
        // least `requested` writable bytes for the duration of the call.
        let output = unsafe { std::slice::from_raw_parts_mut(output.cast::<u8>(), length) };
        let Ok(mut file) = self.file.lock() else {
            return STG_E_REVERTED;
        };
        let Ok(observed) = file.read(output) else {
            return STG_E_READFAULT;
        };
        let Ok(observed_u32) = u32::try_from(observed) else {
            return STG_E_READFAULT;
        };
        if !read.is_null() {
            // SAFETY: validated by the COM caller contract above.
            unsafe { read.write(observed_u32) };
        }
        if observed_u32 == requested {
            S_OK
        } else {
            S_FALSE
        }
    }

    fn Write(&self, _input: *const c_void, _length: u32, written: *mut u32) -> HRESULT {
        if !written.is_null() {
            // SAFETY: COM requires a non-null output pointer to reference a live
            // u32 for this synchronous call.
            unsafe { written.write(0) };
        }
        STG_E_ACCESSDENIED
    }
}

#[allow(non_snake_case)]
impl IStream_Impl for ReadOnlyFileStream_Impl {
    fn Seek(
        &self,
        displacement: i64,
        origin: STREAM_SEEK,
        new_position: *mut u64,
    ) -> windows::core::Result<()> {
        let position = match origin {
            STREAM_SEEK_SET => SeekFrom::Start(
                u64::try_from(displacement)
                    .map_err(|_| windows::core::Error::from_hresult(STG_E_SEEKERROR))?,
            ),
            STREAM_SEEK_CUR => SeekFrom::Current(displacement),
            STREAM_SEEK_END => SeekFrom::End(displacement),
            _ => return Err(windows::core::Error::from_hresult(STG_E_INVALIDFUNCTION)),
        };
        let mut file = self
            .file
            .lock()
            .map_err(|_| windows::core::Error::from_hresult(STG_E_REVERTED))?;
        let observed = file
            .seek(position)
            .map_err(|_| windows::core::Error::from_hresult(STG_E_SEEKERROR))?;
        if !new_position.is_null() {
            // SAFETY: COM requires this optional non-null output to reference a
            // live u64 for the duration of the call.
            unsafe { new_position.write(observed) };
        }
        Ok(())
    }

    fn SetSize(&self, _new_size: u64) -> windows::core::Result<()> {
        Err(windows::core::Error::from_hresult(STG_E_ACCESSDENIED))
    }

    fn CopyTo(
        &self,
        target: windows::core::Ref<IStream>,
        requested: u64,
        read: *mut u64,
        written: *mut u64,
    ) -> windows::core::Result<()> {
        if !read.is_null() {
            // SAFETY: COM requires optional non-null outputs to be live.
            unsafe { read.write(0) };
        }
        if !written.is_null() {
            // SAFETY: COM requires optional non-null outputs to be live.
            unsafe { written.write(0) };
        }
        if target.is_null() {
            return Err(windows::core::Error::from_hresult(STG_E_INVALIDPOINTER));
        }
        let target = target.ok()?;
        let mut total_read = 0_u64;
        let mut total_written = 0_u64;
        let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
        while total_read < requested {
            let request = usize::try_from((requested - total_read).min(buffer.len() as u64))
                .map_err(|_| windows::core::Error::from_hresult(STG_E_READFAULT))?;
            let observed = {
                let mut file = self
                    .file
                    .lock()
                    .map_err(|_| windows::core::Error::from_hresult(STG_E_REVERTED))?;
                file.read(&mut buffer[..request])
                    .map_err(|_| windows::core::Error::from_hresult(STG_E_READFAULT))?
            };
            if observed == 0 {
                break;
            }
            let mut chunk_written = 0_u32;
            // SAFETY: the target interface is retained, and the input slice and
            // output count remain live for this synchronous COM call.
            unsafe {
                target.Write(
                    buffer.as_ptr().cast::<c_void>(),
                    u32::try_from(observed)
                        .map_err(|_| windows::core::Error::from_hresult(STG_E_WRITEFAULT))?,
                    Some(&raw mut chunk_written),
                )
            }
            .ok()?;
            if usize::try_from(chunk_written).ok() != Some(observed) {
                return Err(windows::core::Error::from_hresult(STG_E_WRITEFAULT));
            }
            let observed_u64 = u64::try_from(observed)
                .map_err(|_| windows::core::Error::from_hresult(STG_E_READFAULT))?;
            total_read = total_read
                .checked_add(observed_u64)
                .ok_or_else(|| windows::core::Error::from_hresult(STG_E_READFAULT))?;
            total_written = total_written
                .checked_add(u64::from(chunk_written))
                .ok_or_else(|| windows::core::Error::from_hresult(STG_E_WRITEFAULT))?;
        }
        if !read.is_null() {
            // SAFETY: validated by the COM caller contract above.
            unsafe { read.write(total_read) };
        }
        if !written.is_null() {
            // SAFETY: validated by the COM caller contract above.
            unsafe { written.write(total_written) };
        }
        Ok(())
    }

    fn Commit(&self, _flags: &STGC) -> windows::core::Result<()> {
        Ok(())
    }

    fn Revert(&self) -> windows::core::Result<()> {
        Err(windows::core::Error::from_hresult(STG_E_INVALIDFUNCTION))
    }

    fn LockRegion(
        &self,
        _offset: u64,
        _length: u64,
        _lock_type: &LOCKTYPE,
    ) -> windows::core::Result<()> {
        Err(windows::core::Error::from_hresult(STG_E_INVALIDFUNCTION))
    }

    fn UnlockRegion(
        &self,
        _offset: u64,
        _length: u64,
        _lock_type: u32,
    ) -> windows::core::Result<()> {
        Err(windows::core::Error::from_hresult(STG_E_INVALIDFUNCTION))
    }

    fn Stat(&self, output: *mut STATSTG, _flags: &STATFLAG) -> windows::core::Result<()> {
        if output.is_null() {
            return Err(windows::core::Error::from_hresult(STG_E_INVALIDPOINTER));
        }
        let value = STATSTG {
            r#type: u32::try_from(STGTY_STREAM.0)
                .map_err(|_| windows::core::Error::from_hresult(STG_E_INVALIDFUNCTION))?,
            cbSize: self.length,
            grfMode: STGM_READ,
            ..STATSTG::default()
        };
        // SAFETY: COM requires `output` to reference one live STATSTG.
        unsafe { output.write(value) };
        Ok(())
    }

    fn Clone(&self) -> windows::core::Result<IStream> {
        let mut file = self
            .file
            .lock()
            .map_err(|_| windows::core::Error::from_hresult(STG_E_REVERTED))?;
        let position = file
            .stream_position()
            .map_err(|_| windows::core::Error::from_hresult(STG_E_SEEKERROR))?;
        // SAFETY: the original file handle is live and retained under the
        // mutex. ReOpenFile binds the clone to the same file object without a
        // pathname lookup and gives it an independent seek pointer.
        let handle = unsafe {
            ReOpenFile(
                HANDLE(file.as_raw_handle()),
                FILE_GENERIC_READ.0,
                FILE_SHARE_READ,
                FILE_FLAGS_AND_ATTRIBUTES(0),
            )
        }
        .map_err(|_| windows::core::Error::from_hresult(STG_E_READFAULT))?;
        let owned = owned_handle(handle)
            .map_err(|_| windows::core::Error::from_hresult(STG_E_READFAULT))?;
        let mut cloned = std::fs::File::from(owned);
        cloned
            .seek(SeekFrom::Start(position))
            .map_err(|_| windows::core::Error::from_hresult(STG_E_SEEKERROR))?;
        drop(file);
        Ok(ReadOnlyFileStream {
            file: Mutex::new(cloned),
            length: self.length,
        }
        .into())
    }
}

#[cfg(test)]
mod update_stream_tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    static NEXT_STREAM_ROOT: AtomicU64 = AtomicU64::new(0);

    fn temporary_root() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "nodavo-windows-handle-stream-{}-{nonce}-{}",
            std::process::id(),
            NEXT_STREAM_ROOT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn appx_stream_reads_and_clones_the_retained_file_handle() {
        let root = temporary_root();
        create_private_update_directory(&root).unwrap();
        let path = root.join("bundle.bin");
        let mut file = create_private_update_file(&path).unwrap();
        std::io::Write::write_all(&mut file, b"abc").unwrap();
        file.sync_all().unwrap();
        drop(file);

        let guard = open_update_bundle_guard(&path).unwrap();
        let stream = read_only_file_stream(guard, 3).unwrap();
        assert!(std::fs::rename(&path, root.join("pivot.bin")).is_err());
        let mut null_read = 0_u64;
        let mut null_written = 0_u64;
        let error = unsafe {
            stream.CopyTo(
                None::<&IStream>,
                1,
                Some(&raw mut null_read),
                Some(&raw mut null_written),
            )
        }
        .unwrap_err();
        assert_eq!(error.code(), STG_E_INVALIDPOINTER);
        assert_eq!((null_read, null_written), (0, 0));
        unsafe { stream.Seek(1, STREAM_SEEK_SET, None) }.unwrap();
        let clone = unsafe { stream.Clone() }.unwrap();

        let mut clone_byte = [0_u8; 1];
        let mut clone_read = 0_u32;
        assert_eq!(
            unsafe {
                clone.Read(
                    clone_byte.as_mut_ptr().cast::<c_void>(),
                    1,
                    Some(&raw mut clone_read),
                )
            },
            S_OK
        );
        assert_eq!((clone_byte, clone_read), ([b'b'], 1));

        let mut original_byte = [0_u8; 1];
        let mut original_read = 0_u32;
        assert_eq!(
            unsafe {
                stream.Read(
                    original_byte.as_mut_ptr().cast::<c_void>(),
                    1,
                    Some(&raw mut original_read),
                )
            },
            S_OK
        );
        assert_eq!((original_byte, original_read), ([b'b'], 1));

        drop(clone);
        drop(stream);
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(root).unwrap();
    }
}

#[derive(Clone, Copy)]
enum AppxIdentityText {
    Name,
    Publisher,
    FamilyName,
    ResourceId,
    FullName,
}

fn appx_package_id_text(
    identity: &IAppxManifestPackageId,
    field: AppxIdentityText,
    maximum_units: usize,
) -> Result<String, WindowsPlatformError> {
    // SAFETY: each getter belongs to the retained identity. Every returned
    // COM-owned string is copied with a fixed bound and released exactly once.
    let value = unsafe {
        match field {
            AppxIdentityText::Name => identity.GetName(),
            AppxIdentityText::Publisher => identity.GetPublisher(),
            AppxIdentityText::FamilyName => identity.GetPackageFamilyName(),
            AppxIdentityText::ResourceId => identity.GetResourceId(),
            AppxIdentityText::FullName => identity.GetPackageFullName(),
        }
    }
    .map_err(|_| WindowsPlatformError::NativeApi)?;
    take_appx_text(
        value,
        maximum_units,
        matches!(field, AppxIdentityText::ResourceId),
    )
}

fn take_appx_text(
    value: PWSTR,
    maximum_units: usize,
    allow_empty: bool,
) -> Result<String, WindowsPlatformError> {
    if value.is_null() || maximum_units == 0 {
        return Err(WindowsPlatformError::NativeApi);
    }
    let owned = CoTaskWideString(value);
    let mut length = None;
    for index in 0..=maximum_units {
        // SAFETY: Appx APIs return a valid NUL-terminated COM allocation. Reads
        // are bounded to one unit past the documented local policy maximum.
        if unsafe { *owned.0.0.add(index) } == 0 {
            length = Some(index);
            break;
        }
    }
    let length = length.ok_or(WindowsPlatformError::NativeApi)?;
    if length == 0 && !allow_empty {
        return Err(WindowsPlatformError::NativeApi);
    }
    // SAFETY: the preceding bounded scan found the terminator in this allocation.
    let units = unsafe { std::slice::from_raw_parts(owned.0.0, length) };
    String::from_utf16(units).map_err(|_| WindowsPlatformError::NativeApi)
}

struct CoTaskWideString(PWSTR);

impl Drop for CoTaskWideString {
    fn drop(&mut self) {
        // SAFETY: the originating COM or Shell API returned this exact string
        // with the COM task allocator.
        unsafe { CoTaskMemFree(Some(self.0.0.cast::<c_void>())) };
    }
}

struct ComApartment {
    uninitialize: bool,
}

impl ComApartment {
    fn initialize() -> Result<Self, WindowsPlatformError> {
        // SAFETY: no reserved pointer is supplied; apartment lifetime is held by
        // the returned guard on this same thread.
        let status = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        if status.is_ok() {
            Ok(Self { uninitialize: true })
        } else if status == RPC_E_CHANGED_MODE {
            // An existing STA is also sufficient for the synchronous Appx APIs;
            // this call did not acquire an initialization reference.
            Ok(Self {
                uninitialize: false,
            })
        } else {
            Err(WindowsPlatformError::NativeApi)
        }
    }
}

impl Drop for ComApartment {
    fn drop(&mut self) {
        if self.uninitialize {
            // SAFETY: paired with the successful CoInitializeEx on this thread.
            unsafe { CoUninitialize() };
        }
    }
}

fn nul_terminated_path(path: &Path) -> Result<Vec<u16>, WindowsPlatformError> {
    let mut encoded: Vec<u16> = path.as_os_str().encode_wide().collect();
    if encoded.is_empty() || encoded.len() >= MAX_WINDOWS_PATH_UNITS || encoded.contains(&0) {
        return Err(WindowsPlatformError::NativeApi);
    }
    encoded.push(0);
    Ok(encoded)
}

pub(super) fn protect_current_user_secret(secret: &[u8]) -> Result<Vec<u8>, WindowsPlatformError> {
    let input = input_blob(secret)?;
    let entropy = input_blob(DPAPI_ENTROPY)?;
    let mut output = CRYPT_INTEGER_BLOB::default();
    // SAFETY: input and entropy point to live immutable slices for the call;
    // output is a live descriptor populated with LocalAlloc memory by DPAPI.
    unsafe {
        CryptProtectData(
            &raw const input,
            w!("Nodavo protected secret"),
            Some(&raw const entropy),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &raw mut output,
        )
        .map_err(|_| WindowsPlatformError::SecretProtection)?;
    }
    copy_local_blob(output, MAX_PROTECTED_SECRET_BLOB_BYTES, false)
}

pub(super) fn unprotect_current_user_secret(
    protected: &[u8],
) -> Result<Zeroizing<Vec<u8>>, WindowsPlatformError> {
    let input = input_blob(protected)?;
    let entropy = input_blob(DPAPI_ENTROPY)?;
    let mut output = CRYPT_INTEGER_BLOB::default();
    // SAFETY: input and entropy point to live immutable slices for the call;
    // no description is requested, UI is forbidden, and output is LocalAlloc memory.
    unsafe {
        CryptUnprotectData(
            &raw const input,
            None,
            Some(&raw const entropy),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &raw mut output,
        )
        .map_err(|_| WindowsPlatformError::SecretProtection)?;
    }
    copy_local_blob(output, MAX_PROTECTED_SECRET_BYTES, true).map(Zeroizing::new)
}

fn input_blob(bytes: &[u8]) -> Result<CRYPT_INTEGER_BLOB, WindowsPlatformError> {
    Ok(CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(bytes.len()).map_err(|_| WindowsPlatformError::SecretTooLarge)?,
        pbData: bytes.as_ptr().cast_mut(),
    })
}

fn copy_local_blob(
    blob: CRYPT_INTEGER_BLOB,
    maximum: usize,
    sensitive: bool,
) -> Result<Vec<u8>, WindowsPlatformError> {
    let mut guard = LocalBlob { blob, sensitive };
    let length =
        usize::try_from(guard.blob.cbData).map_err(|_| WindowsPlatformError::SecretTooLarge)?;
    if length == 0 || length > maximum || guard.blob.pbData.is_null() {
        return Err(WindowsPlatformError::SecretTooLarge);
    }
    // SAFETY: DPAPI returned a non-null LocalAlloc buffer of exactly cbData
    // initialized bytes. The guard retains ownership until after the copy.
    let bytes = unsafe { std::slice::from_raw_parts(guard.blob.pbData, length) }.to_vec();
    if sensitive {
        // The returned Vec becomes Zeroizing at the safe wrapper boundary. Mark
        // native memory for wiping now even if later conversion fails.
        guard.sensitive = true;
    }
    Ok(bytes)
}

struct LocalBlob {
    blob: CRYPT_INTEGER_BLOB,
    sensitive: bool,
}

impl Drop for LocalBlob {
    fn drop(&mut self) {
        if self.blob.pbData.is_null() {
            return;
        }
        if self.sensitive {
            // SAFETY: the DPAPI LocalAlloc buffer remains exclusively owned and
            // writable for cbData bytes until LocalFree below.
            unsafe {
                ptr::write_bytes(
                    self.blob.pbData,
                    0,
                    usize::try_from(self.blob.cbData).unwrap_or(0),
                );
            }
        }
        // SAFETY: DPAPI allocated this exact buffer with LocalAlloc. It is freed once.
        let _ = unsafe { LocalFree(Some(HLOCAL(self.blob.pbData.cast::<c_void>()))) };
    }
}

pub(super) fn create_private_named_pipe(
    pipe_name: &str,
    first_instance: bool,
) -> Result<NamedPipeServer, WindowsPlatformError> {
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: OWNER_ONLY_PIPE_SDDL is a static, NUL-terminated UTF-16 string;
    // `descriptor` is a live output pointer and is released with LocalFree.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(OWNER_ONLY_PIPE_SDDL.as_ptr()),
            SDDL_REVISION_1,
            &raw mut descriptor,
            None,
        )
        .map_err(|_| WindowsPlatformError::UnauthorizedLocalIpc)?;
    }
    let descriptor = LocalSecurityDescriptor(descriptor);
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>())
            .map_err(|_| WindowsPlatformError::NativeApi)?,
        lpSecurityDescriptor: descriptor.0.0,
        bInheritHandle: false.into(),
    };
    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(first_instance)
        .reject_remote_clients(true)
        .max_instances(8)
        .in_buffer_size(PIPE_BUFFER_BYTES)
        .out_buffer_size(PIPE_BUFFER_BYTES);
    // SAFETY: `attributes` and its security descriptor remain live throughout
    // the synchronous CreateNamedPipe call. The descriptor is not retained.
    unsafe {
        options.create_with_security_attributes_raw(
            pipe_name,
            ptr::from_mut(&mut attributes).cast::<c_void>(),
        )
    }
    .map_err(|_| WindowsPlatformError::UnauthorizedLocalIpc)
}

pub(super) fn authenticate_named_pipe_client(
    pipe: &NamedPipeServer,
) -> Result<NativeNamedPipeClient, WindowsPlatformError> {
    let pipe_process_id = named_pipe_client_process_id(pipe)?;
    let pipe_handle = duplicate_handle(HANDLE(pipe.as_raw_handle()))?;

    // SAFETY: the PID came directly from the connected pipe. The returned
    // process handle is uniquely owned and includes synchronization access so
    // its liveness can be checked without trusting PID reuse.
    let process = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            false,
            pipe_process_id,
        )
    }
    .map_err(|_| WindowsPlatformError::UnauthorizedLocalIpc)?;
    let process = owned_handle(process)?;
    let process_id = process_id_from_handle(as_windows_handle(&process))?;
    if process_id != pipe_process_id {
        return Err(WindowsPlatformError::UnauthorizedLocalIpc);
    }
    let creation_time = process_creation_time(as_windows_handle(&process))?;
    let token = open_query_token(as_windows_handle(&process))?;
    let token_identity = read_token_identity(as_windows_handle(&token))?;
    validate_client_against_agent(process_id, &token_identity)?;
    let package_identity =
        read_package_identity(as_windows_handle(&process), as_windows_handle(&token))?;
    let image_file = open_image_file(&package_identity.image_path)?;

    if named_pipe_client_process_id_from_handle(as_windows_handle(&pipe_handle))? != pipe_process_id
        || !process_is_live(as_windows_handle(&process))
    {
        return Err(WindowsPlatformError::UnauthorizedLocalIpc);
    }

    Ok(NativeNamedPipeClient {
        process_id,
        pipe: pipe_handle,
        process,
        token,
        image_file,
        creation_time,
        token_identity,
        package_identity,
    })
}

pub(super) fn derive_package_family_name(
    package_name: &str,
    publisher: &str,
) -> Result<String, WindowsPlatformError> {
    if package_name.is_empty()
        || publisher.is_empty()
        || package_name.contains('\0')
        || publisher.contains('\0')
    {
        return Err(WindowsPlatformError::UnauthorizedLocalIpc);
    }
    let mut package_name_wide = wide_null(package_name)?;
    let mut publisher_wide = wide_null(publisher)?;
    let package_id = PACKAGE_ID {
        name: PWSTR(package_name_wide.as_mut_ptr()),
        publisher: PWSTR(publisher_wide.as_mut_ptr()),
        resourceId: PWSTR::null(),
        publisherId: PWSTR::null(),
        ..PACKAGE_ID::default()
    };
    package_family_name_from_id(&raw const package_id)
}

pub(super) struct NativeNamedPipeClient {
    process_id: u32,
    pipe: OwnedHandle,
    process: OwnedHandle,
    token: OwnedHandle,
    image_file: OwnedHandle,
    creation_time: u64,
    token_identity: NativeTokenIdentity,
    package_identity: NativePackageIdentity,
}

impl NativeNamedPipeClient {
    pub(super) fn package_identity(&self) -> &NativePackageIdentity {
        &self.package_identity
    }

    pub(super) fn verify_signer(
        &self,
        expected_certificate_sha256: &[u8; 32],
        requires_trusted_timestamp: bool,
    ) -> Result<(), WindowsPlatformError> {
        verify_authenticode_signer(
            as_windows_handle(&self.image_file),
            &self.package_identity.image_path,
            expected_certificate_sha256,
            requires_trusted_timestamp,
        )
    }

    pub(super) fn revalidate(&self) -> Result<(), WindowsPlatformError> {
        if named_pipe_client_process_id_from_handle(as_windows_handle(&self.pipe))?
            != self.process_id
            || process_id_from_handle(as_windows_handle(&self.process))? != self.process_id
            || process_creation_time(as_windows_handle(&self.process))? != self.creation_time
            || !process_is_live(as_windows_handle(&self.process))
        {
            return Err(WindowsPlatformError::UnauthorizedLocalIpc);
        }

        // The retained token proves the initially inspected object is still
        // live. Reopening the process token additionally rejects a process that
        // replaced its primary token after the connection was authorized.
        if read_token_identity(as_windows_handle(&self.token))? != self.token_identity {
            return Err(WindowsPlatformError::UnauthorizedLocalIpc);
        }
        let current_token = open_query_token(as_windows_handle(&self.process))?;
        let current_token_identity = read_token_identity(as_windows_handle(&current_token))?;
        if current_token_identity != self.token_identity {
            return Err(WindowsPlatformError::UnauthorizedLocalIpc);
        }
        validate_client_against_agent(self.process_id, &current_token_identity)?;

        let current_package_identity = read_package_identity(
            as_windows_handle(&self.process),
            as_windows_handle(&current_token),
        )?;
        if current_package_identity != self.package_identity
            || named_pipe_client_process_id_from_handle(as_windows_handle(&self.pipe))?
                != self.process_id
            || !process_is_live(as_windows_handle(&self.process))
        {
            return Err(WindowsPlatformError::UnauthorizedLocalIpc);
        }
        Ok(())
    }
}

pub(super) struct NativePackageIdentity {
    pub(super) package_full_name: String,
    pub(super) package_name: String,
    pub(super) publisher: String,
    pub(super) package_family_name: String,
    pub(super) application_user_model_id: String,
    pub(super) package_relative_executable: String,
    pub(super) processor_architecture: u32,
    pub(super) resource_id: String,
    pub(super) publisher_id: String,
    image_path: String,
    package_path: String,
}

impl PartialEq for NativePackageIdentity {
    fn eq(&self, other: &Self) -> bool {
        self.package_full_name == other.package_full_name
            && self.package_name == other.package_name
            && self.publisher == other.publisher
            && self.package_family_name == other.package_family_name
            && self.application_user_model_id == other.application_user_model_id
            && self.package_relative_executable == other.package_relative_executable
            && self.processor_architecture == other.processor_architecture
            && self.resource_id == other.resource_id
            && self.publisher_id == other.publisher_id
            && self.image_path == other.image_path
            && self.package_path == other.package_path
    }
}

impl Eq for NativePackageIdentity {}

#[derive(Clone, Eq, PartialEq)]
struct NativeTokenIdentity {
    user_sid: String,
    session_id: u32,
    token_id: NativeLuid,
    authentication_id: NativeLuid,
    modified_id: NativeLuid,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct NativeLuid {
    low: u32,
    high: i32,
}

fn named_pipe_client_process_id(pipe: &NamedPipeServer) -> Result<u32, WindowsPlatformError> {
    named_pipe_client_process_id_from_handle(HANDLE(pipe.as_raw_handle()))
}

fn named_pipe_client_process_id_from_handle(handle: HANDLE) -> Result<u32, WindowsPlatformError> {
    let mut process_id = 0_u32;
    // SAFETY: the Tokio server owns a connected pipe HANDLE for the duration
    // of this call and the PID output points to a live `u32`.
    unsafe {
        GetNamedPipeClientProcessId(handle, &raw mut process_id)
            .map_err(|_| WindowsPlatformError::UnauthorizedLocalIpc)?;
    }
    if process_id == 0 {
        Err(WindowsPlatformError::UnauthorizedLocalIpc)
    } else {
        Ok(process_id)
    }
}

fn duplicate_handle(source: HANDLE) -> Result<OwnedHandle, WindowsPlatformError> {
    let mut duplicate = HANDLE::default();
    // SAFETY: both process arguments are the live current-process
    // pseudo-handle, `source` is live, and the output is uniquely adopted by
    // std's OwnedHandle on success.
    unsafe {
        let process = GetCurrentProcess();
        DuplicateHandle(
            process,
            source,
            process,
            &raw mut duplicate,
            0,
            false,
            DUPLICATE_SAME_ACCESS,
        )
        .map_err(|_| WindowsPlatformError::UnauthorizedLocalIpc)?;
    }
    owned_handle(duplicate)
}

fn owned_handle(handle: HANDLE) -> Result<OwnedHandle, WindowsPlatformError> {
    if handle.is_invalid() {
        return Err(WindowsPlatformError::UnauthorizedLocalIpc);
    }
    // SAFETY: the caller transfers unique ownership of a successful Win32
    // handle, which std closes exactly once.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle.0) })
}

fn as_windows_handle(handle: &OwnedHandle) -> HANDLE {
    HANDLE(handle.as_raw_handle())
}

fn process_id_from_handle(process: HANDLE) -> Result<u32, WindowsPlatformError> {
    // SAFETY: `process` is a live process handle retained by the caller.
    let process_id = unsafe { GetProcessId(process) };
    if process_id == 0 {
        Err(WindowsPlatformError::UnauthorizedLocalIpc)
    } else {
        Ok(process_id)
    }
}

fn process_creation_time(process: HANDLE) -> Result<u64, WindowsPlatformError> {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: all four outputs are live and `process` is queryable for the
    // duration of this call.
    unsafe {
        GetProcessTimes(
            process,
            &raw mut creation,
            &raw mut exit,
            &raw mut kernel,
            &raw mut user,
        )
        .map_err(|_| WindowsPlatformError::UnauthorizedLocalIpc)?;
    }
    Ok((u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime))
}

fn process_is_live(process: HANDLE) -> bool {
    // SAFETY: synchronization access was requested when the retained process
    // handle was opened; a zero timeout only observes the signaled state.
    unsafe { WaitForSingleObject(process, 0) == WAIT_TIMEOUT }
}

fn validate_client_against_agent(
    process_id: u32,
    client: &NativeTokenIdentity,
) -> Result<(), WindowsPlatformError> {
    // SAFETY: the current-process pseudo-handle is live and must not be closed.
    let agent_token = open_query_token(unsafe { GetCurrentProcess() })?;
    let agent = read_token_identity(as_windows_handle(&agent_token))?;
    let process_session = process_session_id(process_id)?;
    let agent_process_session = process_session_id(
        // SAFETY: no parameters and no ownership transfer.
        unsafe { GetCurrentProcessId() },
    )?;
    if client.user_sid != agent.user_sid
        || client.session_id == 0
        || client.session_id != agent.session_id
        || client.session_id != process_session
        || agent.session_id != agent_process_session
        || client.authentication_id != agent.authentication_id
    {
        return Err(WindowsPlatformError::UnauthorizedLocalIpc);
    }
    Ok(())
}

fn read_token_identity(token: HANDLE) -> Result<NativeTokenIdentity, WindowsPlatformError> {
    let token_user = read_token_user(token)?;
    let user_sid = sid_to_string(token_user.sid)?;
    let session_id = read_token_session_id(token)?;
    let statistics = read_token_statistics(token)?;
    Ok(NativeTokenIdentity {
        user_sid,
        session_id,
        token_id: luid(statistics.TokenId),
        authentication_id: luid(statistics.AuthenticationId),
        modified_id: luid(statistics.ModifiedId),
    })
}

const fn luid(value: windows::Win32::Foundation::LUID) -> NativeLuid {
    NativeLuid {
        low: value.LowPart,
        high: value.HighPart,
    }
}

fn read_token_session_id(token: HANDLE) -> Result<u32, WindowsPlatformError> {
    let mut value = 0_u32;
    let mut returned = 0_u32;
    // SAFETY: the output is correctly sized/aligned for TokenSessionId and all
    // pointers remain live for the synchronous call.
    unsafe {
        GetTokenInformation(
            token,
            TokenSessionId,
            Some(ptr::from_mut(&mut value).cast::<c_void>()),
            u32::try_from(size_of::<u32>())
                .map_err(|_| WindowsPlatformError::UnauthorizedLocalIpc)?,
            &raw mut returned,
        )
        .map_err(|_| WindowsPlatformError::UnauthorizedLocalIpc)?;
    }
    if returned != u32::try_from(size_of::<u32>()).unwrap_or(0) {
        return Err(WindowsPlatformError::UnauthorizedLocalIpc);
    }
    Ok(value)
}

fn read_token_statistics(token: HANDLE) -> Result<TOKEN_STATISTICS, WindowsPlatformError> {
    let mut value = TOKEN_STATISTICS::default();
    let mut returned = 0_u32;
    // SAFETY: the output is correctly sized/aligned for TokenStatistics and
    // all pointers remain live for the synchronous call.
    unsafe {
        GetTokenInformation(
            token,
            TokenStatistics,
            Some(ptr::from_mut(&mut value).cast::<c_void>()),
            u32::try_from(size_of::<TOKEN_STATISTICS>())
                .map_err(|_| WindowsPlatformError::UnauthorizedLocalIpc)?,
            &raw mut returned,
        )
        .map_err(|_| WindowsPlatformError::UnauthorizedLocalIpc)?;
    }
    if returned != u32::try_from(size_of::<TOKEN_STATISTICS>()).unwrap_or(0) {
        return Err(WindowsPlatformError::UnauthorizedLocalIpc);
    }
    Ok(value)
}

fn read_package_identity(
    process: HANDLE,
    token: HANDLE,
) -> Result<NativePackageIdentity, WindowsPlatformError> {
    let package_full_name =
        query_appmodel_string(PACKAGE_FULL_NAME_MAX_LENGTH + 1, |length, output| {
            // SAFETY: process is live and queryable, while the helper owns the
            // sizing/output buffers for this synchronous call.
            unsafe { GetPackageFullName(process, length, output) }
        })?;
    let token_package_full_name =
        query_appmodel_string(PACKAGE_FULL_NAME_MAX_LENGTH + 1, |length, output| {
            // SAFETY: token is live with TOKEN_QUERY access and buffers are valid.
            unsafe { GetPackageFullNameFromToken(token, length, output) }
        })?;
    if token_package_full_name != package_full_name {
        return Err(WindowsPlatformError::UnauthorizedLocalIpc);
    }

    let process_family_name =
        query_appmodel_string(PACKAGE_FAMILY_NAME_MAX_LENGTH + 1, |length, output| {
            // SAFETY: same handle/buffer invariants as above.
            unsafe { GetPackageFamilyName(process, length, output) }
        })?;
    let token_family_name =
        query_appmodel_string(PACKAGE_FAMILY_NAME_MAX_LENGTH + 1, |length, output| {
            // SAFETY: same handle/buffer invariants as above.
            unsafe { GetPackageFamilyNameFromToken(token, length, output) }
        })?;
    if token_family_name != process_family_name {
        return Err(WindowsPlatformError::UnauthorizedLocalIpc);
    }

    let process_aumid =
        query_appmodel_string(APPLICATION_USER_MODEL_ID_MAX_LENGTH, |length, output| {
            // SAFETY: same handle/buffer invariants as above.
            unsafe { GetApplicationUserModelId(process, length, output) }
        })?;
    let token_aumid =
        query_appmodel_string(APPLICATION_USER_MODEL_ID_MAX_LENGTH, |length, output| {
            // SAFETY: same handle/buffer invariants as above.
            unsafe { GetApplicationUserModelIdFromToken(token, length, output) }
        })?;
    if token_aumid != process_aumid {
        return Err(WindowsPlatformError::UnauthorizedLocalIpc);
    }

    let parsed = parse_package_full_name(&package_full_name)?;
    if parsed.family_name != process_family_name {
        return Err(WindowsPlatformError::UnauthorizedLocalIpc);
    }
    let package_path = package_install_path(&package_full_name)?;
    let image_path = process_image_path(process)?;
    let relative = PathBuf::from(&image_path)
        .strip_prefix(Path::new(&package_path))
        .map_err(|_| WindowsPlatformError::UnauthorizedLocalIpc)?
        .to_path_buf();
    if relative.components().count() != 1 {
        return Err(WindowsPlatformError::UnauthorizedLocalIpc);
    }
    let package_relative_executable = relative
        .to_str()
        .filter(|value| !value.is_empty())
        .ok_or(WindowsPlatformError::UnauthorizedLocalIpc)?
        .to_owned();

    Ok(NativePackageIdentity {
        package_full_name,
        package_name: parsed.name,
        publisher: parsed.publisher,
        package_family_name: parsed.family_name,
        application_user_model_id: process_aumid,
        package_relative_executable,
        processor_architecture: parsed.processor_architecture,
        resource_id: parsed.resource_id,
        publisher_id: parsed.publisher_id,
        image_path,
        package_path,
    })
}

struct ParsedPackageIdentity {
    name: String,
    publisher: String,
    family_name: String,
    processor_architecture: u32,
    resource_id: String,
    publisher_id: String,
}

fn parse_package_full_name(value: &str) -> Result<ParsedPackageIdentity, WindowsPlatformError> {
    let wide = wide_null(value)?;
    let mut required = 0_u32;
    // SAFETY: sizing call has a live length output and deliberately omits the
    // destination buffer.
    let status = unsafe {
        PackageIdFromFullName(
            PCWSTR(wide.as_ptr()),
            PACKAGE_INFORMATION_FULL,
            &raw mut required,
            None,
        )
    };
    if status != ERROR_INSUFFICIENT_BUFFER {
        return Err(WindowsPlatformError::UnauthorizedLocalIpc);
    }
    let required_usize =
        usize::try_from(required).map_err(|_| WindowsPlatformError::UnauthorizedLocalIpc)?;
    if required_usize < size_of::<PACKAGE_ID>() || required_usize > MAX_TOKEN_INFORMATION_BYTES {
        return Err(WindowsPlatformError::UnauthorizedLocalIpc);
    }
    let mut storage = vec![0_usize; required_usize.div_ceil(size_of::<usize>())];
    let storage_bytes = size_of_val(storage.as_slice());
    let mut supplied =
        u32::try_from(storage_bytes).map_err(|_| WindowsPlatformError::UnauthorizedLocalIpc)?;
    // SAFETY: usize storage is sufficiently large/aligned, the input is
    // NUL-terminated, and the package parser initializes one PACKAGE_ID whose
    // string pointers refer into the retained storage.
    let status = unsafe {
        PackageIdFromFullName(
            PCWSTR(wide.as_ptr()),
            PACKAGE_INFORMATION_FULL,
            &raw mut supplied,
            Some(storage.as_mut_ptr().cast::<u8>()),
        )
    };
    if status != ERROR_SUCCESS || usize::try_from(supplied).ok() != Some(required_usize) {
        return Err(WindowsPlatformError::UnauthorizedLocalIpc);
    }
    let package_id_pointer = storage.as_ptr().cast::<PACKAGE_ID>();
    // SAFETY: the parser initialized a PACKAGE_ID at the aligned buffer start.
    // `read_unaligned` also accommodates the SDK's packed 64-bit definition.
    let package_id = unsafe { ptr::read_unaligned(package_id_pointer) };
    let name = package_id_string(&storage, package_id.name)?;
    let publisher = package_id_string(&storage, package_id.publisher)?;
    let resource_id = package_id_string(&storage, package_id.resourceId)?;
    let publisher_id = package_id_string(&storage, package_id.publisherId)?;
    let family_name = package_family_name_from_id(package_id_pointer)?;
    Ok(ParsedPackageIdentity {
        name,
        publisher,
        family_name,
        processor_architecture: package_id.processorArchitecture,
        resource_id,
        publisher_id,
    })
}

fn package_id_string(storage: &[usize], value: PWSTR) -> Result<String, WindowsPlatformError> {
    if value.is_null() {
        return Err(WindowsPlatformError::UnauthorizedLocalIpc);
    }
    let start = storage.as_ptr().cast::<u8>() as usize;
    let end = start
        .checked_add(size_of_val(storage))
        .ok_or(WindowsPlatformError::UnauthorizedLocalIpc)?;
    let pointer = value.0 as usize;
    if pointer < start || pointer >= end || !(pointer - start).is_multiple_of(2) {
        return Err(WindowsPlatformError::UnauthorizedLocalIpc);
    }
    let remaining_units = (end - pointer) / size_of::<u16>();
    // SAFETY: the pointer was range/alignment checked against the retained
    // allocation and the slice cannot extend beyond it.
    let units = unsafe { std::slice::from_raw_parts(value.0, remaining_units) };
    let terminator = units
        .iter()
        .position(|unit| *unit == 0)
        .ok_or(WindowsPlatformError::UnauthorizedLocalIpc)?;
    String::from_utf16(&units[..terminator]).map_err(|_| WindowsPlatformError::UnauthorizedLocalIpc)
}

fn package_family_name_from_id(
    package_id: *const PACKAGE_ID,
) -> Result<String, WindowsPlatformError> {
    query_appmodel_string(PACKAGE_FAMILY_NAME_MAX_LENGTH + 1, |length, output| {
        // SAFETY: the caller retains the PACKAGE_ID and all of its referenced
        // strings; the helper owns valid sizing/output buffers.
        unsafe { PackageFamilyNameFromId(package_id, length, output) }
    })
}

fn package_install_path(package_full_name: &str) -> Result<String, WindowsPlatformError> {
    let wide = wide_null(package_full_name)?;
    query_appmodel_string(
        u32::try_from(MAX_WINDOWS_PATH_UNITS + 1)
            .map_err(|_| WindowsPlatformError::UnauthorizedLocalIpc)?,
        |length, output| {
            // SAFETY: the package name is NUL-terminated and the helper owns valid
            // sizing/output buffers.
            unsafe {
                GetPackagePathByFullName2(
                    PCWSTR(wide.as_ptr()),
                    PackagePathType_Install,
                    length,
                    output,
                )
            }
        },
    )
}

fn process_image_path(process: HANDLE) -> Result<String, WindowsPlatformError> {
    let mut storage = vec![0_u16; MAX_WINDOWS_PATH_UNITS + 1];
    let mut length =
        u32::try_from(storage.len()).map_err(|_| WindowsPlatformError::UnauthorizedLocalIpc)?;
    // SAFETY: the process is queryable and the output buffer/length remain live.
    unsafe {
        QueryFullProcessImageNameW(
            process,
            PROCESS_NAME_WIN32,
            PWSTR(storage.as_mut_ptr()),
            &raw mut length,
        )
        .map_err(|_| WindowsPlatformError::UnauthorizedLocalIpc)?;
    }
    let used = usize::try_from(length).map_err(|_| WindowsPlatformError::UnauthorizedLocalIpc)?;
    if used == 0 || used >= storage.len() || storage[..used].contains(&0) {
        return Err(WindowsPlatformError::UnauthorizedLocalIpc);
    }
    String::from_utf16(&storage[..used]).map_err(|_| WindowsPlatformError::UnauthorizedLocalIpc)
}

fn query_appmodel_string(
    maximum_units_including_nul: u32,
    mut call: impl FnMut(*mut u32, Option<PWSTR>) -> windows::Win32::Foundation::WIN32_ERROR,
) -> Result<String, WindowsPlatformError> {
    let mut required = 0_u32;
    if call(&raw mut required, None) != ERROR_INSUFFICIENT_BUFFER {
        return Err(WindowsPlatformError::UnauthorizedLocalIpc);
    }
    let required_usize =
        usize::try_from(required).map_err(|_| WindowsPlatformError::UnauthorizedLocalIpc)?;
    let maximum = usize::try_from(maximum_units_including_nul)
        .map_err(|_| WindowsPlatformError::UnauthorizedLocalIpc)?;
    if !(2..=maximum.min(MAX_APPMODEL_STRING_UNITS)).contains(&required_usize) {
        return Err(WindowsPlatformError::UnauthorizedLocalIpc);
    }
    let mut storage = vec![0_u16; required_usize];
    let mut supplied = required;
    if call(&raw mut supplied, Some(PWSTR(storage.as_mut_ptr()))) != ERROR_SUCCESS {
        return Err(WindowsPlatformError::UnauthorizedLocalIpc);
    }
    let used = usize::try_from(supplied).map_err(|_| WindowsPlatformError::UnauthorizedLocalIpc)?;
    if used < 2 || used > storage.len() || storage[used - 1] != 0 {
        return Err(WindowsPlatformError::UnauthorizedLocalIpc);
    }
    storage.truncate(used - 1);
    if storage.contains(&0) {
        return Err(WindowsPlatformError::UnauthorizedLocalIpc);
    }
    String::from_utf16(&storage).map_err(|_| WindowsPlatformError::UnauthorizedLocalIpc)
}

fn wide_null(value: &str) -> Result<Vec<u16>, WindowsPlatformError> {
    let mut wide: Vec<u16> = value.encode_utf16().collect();
    if wide.is_empty() || wide.len() >= MAX_APPMODEL_STRING_UNITS || wide.contains(&0) {
        return Err(WindowsPlatformError::UnauthorizedLocalIpc);
    }
    wide.push(0);
    Ok(wide)
}

fn open_image_file(path: &str) -> Result<OwnedHandle, WindowsPlatformError> {
    let path = wide_null(path)?;
    // SAFETY: the path is NUL-terminated. The returned handle is adopted by
    // std ownership and retained for the complete authorized connection. Only
    // FILE_SHARE_READ is granted, preventing replacement/deletion while live.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(path.as_ptr()),
            FILE_GENERIC_READ.0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    }
    .map_err(|_| WindowsPlatformError::UnauthorizedLocalIpc)?;
    owned_handle(handle)
}

fn verify_authenticode_signer(
    image_file: HANDLE,
    image_path: &str,
    expected_certificate_sha256: &[u8; 32],
    requires_trusted_timestamp: bool,
) -> Result<(), WindowsPlatformError> {
    if requires_trusted_timestamp {
        let evidence = run_wintrust(
            image_file,
            image_path,
            WTD_REVOKE_NONE,
            WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_DISABLE_MD2_MD4,
            0,
            true,
        )?;
        if !constant_time_eq(&evidence.certificate_sha256, expected_certificate_sha256)
            || !evidence.has_timestamp
        {
            return Err(WindowsPlatformError::UnauthorizedLocalIpc);
        }
        return Ok(());
    }

    let evidence = run_wintrust(
        image_file,
        image_path,
        WTD_REVOKE_NONE,
        WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_DISABLE_MD2_MD4,
        0,
        true,
    )?;
    if !constant_time_eq(&evidence.certificate_sha256, expected_certificate_sha256) {
        return Err(WindowsPlatformError::UnauthorizedLocalIpc);
    }
    Ok(())
}

struct AuthenticodeEvidence {
    certificate_sha256: [u8; 32],
    has_timestamp: bool,
}

fn run_wintrust(
    image_file: HANDLE,
    image_path: &str,
    revocation_checks: windows::Win32::Security::WinTrust::WINTRUST_DATA_REVOCATION_CHECKS,
    provider_flags: windows::Win32::Security::WinTrust::WINTRUST_DATA_PROVIDER_FLAGS,
    expected_status: i32,
    collect_evidence: bool,
) -> Result<AuthenticodeEvidence, WindowsPlatformError> {
    let image_path = wide_null(image_path)?;
    let mut file = WINTRUST_FILE_INFO {
        cbStruct: u32::try_from(size_of::<WINTRUST_FILE_INFO>())
            .map_err(|_| WindowsPlatformError::UnauthorizedLocalIpc)?,
        pcwszFilePath: PCWSTR(image_path.as_ptr()),
        hFile: image_file,
        pgKnownSubject: ptr::null_mut(),
    };
    let mut data = WINTRUST_DATA {
        cbStruct: u32::try_from(size_of::<WINTRUST_DATA>())
            .map_err(|_| WindowsPlatformError::UnauthorizedLocalIpc)?,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: revocation_checks,
        dwUnionChoice: WTD_CHOICE_FILE,
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: provider_flags,
        dwUIContext: WTD_UICONTEXT_EXECUTE,
        ..WINTRUST_DATA::default()
    };
    data.Anonymous.pFile = &raw mut file;
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    // SAFETY: all WinTrust structures and the retained file handle remain live
    // through verification, evidence extraction, and mandatory state close.
    let status = unsafe { WinVerifyTrustEx(HWND::default(), &raw mut action, &raw mut data) };
    let result = if status != expected_status {
        Err(WindowsPlatformError::UnauthorizedLocalIpc)
    } else if collect_evidence {
        // SAFETY: a successful VERIFY action populated hWVTStateData and keeps
        // provider-owned signer/certificate pointers live until CLOSE below.
        unsafe { authenticode_evidence(data.hWVTStateData) }
    } else {
        Ok(AuthenticodeEvidence {
            certificate_sha256: [0_u8; 32],
            has_timestamp: false,
        })
    };

    data.dwStateAction = WTD_STATEACTION_CLOSE;
    // SAFETY: this closes exactly the state established by the call above;
    // the same action GUID/data storage remains live.
    let close_status = unsafe { WinVerifyTrustEx(HWND::default(), &raw mut action, &raw mut data) };
    if close_status != 0 {
        return Err(WindowsPlatformError::UnauthorizedLocalIpc);
    }
    result
}

unsafe fn authenticode_evidence(
    state: HANDLE,
) -> Result<AuthenticodeEvidence, WindowsPlatformError> {
    if state.is_invalid() {
        return Err(WindowsPlatformError::UnauthorizedLocalIpc);
    }
    // SAFETY: WinVerifyTrust VERIFY produced the state and it remains open.
    let provider = unsafe { WTHelperProvDataFromStateData(state) };
    if provider.is_null() || unsafe { (*provider).csSigners } != 1 {
        return Err(WindowsPlatformError::UnauthorizedLocalIpc);
    }
    // SAFETY: provider is live and reports exactly one primary signer.
    let signer = unsafe { WTHelperGetProvSignerFromChain(provider, 0, false, 0) };
    if signer.is_null()
        || unsafe { (*signer).dwError } != 0
        || unsafe { (*signer).csCertChain } == 0
        || unsafe { (*signer).csCertChain } > MAX_AUTHENTICODE_CHAIN_CERTIFICATES
        || unsafe { (*signer).pasCertChain }.is_null()
    {
        return Err(WindowsPlatformError::UnauthorizedLocalIpc);
    }
    // SAFETY: signer reports a nonempty provider-owned certificate chain.
    let provider_certificate = unsafe { WTHelperGetProvCertFromChain(signer, 0) };
    if provider_certificate.is_null()
        || unsafe { (*provider_certificate).dwError } != 0
        || unsafe { (*provider_certificate).pCert }.is_null()
    {
        return Err(WindowsPlatformError::UnauthorizedLocalIpc);
    }
    // SAFETY: the certificate context belongs to the open provider state.
    let certificate = unsafe { &*(*provider_certificate).pCert };
    let encoded_len = usize::try_from(certificate.cbCertEncoded)
        .map_err(|_| WindowsPlatformError::UnauthorizedLocalIpc)?;
    if certificate.pbCertEncoded.is_null() || encoded_len == 0 || encoded_len > 1024 * 1024 {
        return Err(WindowsPlatformError::UnauthorizedLocalIpc);
    }
    // SAFETY: CERT_CONTEXT exposes cbCertEncoded readable bytes until CLOSE.
    let encoded = unsafe { std::slice::from_raw_parts(certificate.pbCertEncoded, encoded_len) };
    let mut certificate_sha256 = [0_u8; 32];
    let mut hash_len = u32::try_from(certificate_sha256.len())
        .map_err(|_| WindowsPlatformError::UnauthorizedLocalIpc)?;
    // SAFETY: encoded certificate bytes and fixed hash output are live and
    // correctly bounded for the synchronous Crypt32 call.
    unsafe {
        CryptHashCertificate2(
            BCRYPT_SHA256_ALGORITHM,
            0,
            None,
            Some(encoded),
            Some(certificate_sha256.as_mut_ptr()),
            &raw mut hash_len,
        )
        .map_err(|_| WindowsPlatformError::UnauthorizedLocalIpc)?;
    }
    if hash_len != u32::try_from(certificate_sha256.len()).unwrap_or(0) {
        return Err(WindowsPlatformError::UnauthorizedLocalIpc);
    }

    let has_timestamp = unsafe { (*signer).csCounterSigners } == 1
        && !unsafe { (*signer).pasCounterSigners }.is_null()
        && {
            // SAFETY: the signer reports at least one live countersigner.
            let timestamp = unsafe { WTHelperGetProvSignerFromChain(provider, 0, true, 0) };
            if timestamp.is_null() {
                false
            } else {
                let timestamp_certificates = unsafe { (*timestamp).csCertChain };
                let timestamp_certificate = if timestamp_certificates > 0
                    && timestamp_certificates <= MAX_AUTHENTICODE_CHAIN_CERTIFICATES
                    && !unsafe { (*timestamp).pasCertChain }.is_null()
                {
                    // SAFETY: the countersigner reports a bounded nonempty chain.
                    unsafe { WTHelperGetProvCertFromChain(timestamp, 0) }
                } else {
                    ptr::null_mut()
                };
                (unsafe { (*timestamp).dwError }) == 0
                    && (unsafe { (*timestamp).dwSignerType }) == SGNR_TYPE_TIMESTAMP
                    && (unsafe { (*timestamp).sftVerifyAsOf.dwLowDateTime } != 0
                        || unsafe { (*timestamp).sftVerifyAsOf.dwHighDateTime } != 0)
                    && !timestamp_certificate.is_null()
                    && (unsafe { (*timestamp_certificate).dwError }) == 0
                    && !unsafe { (*timestamp_certificate).pCert }.is_null()
            }
        };
    Ok(AuthenticodeEvidence {
        certificate_sha256,
        has_timestamp,
    })
}

fn constant_time_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

pub(super) fn current_user_sid_string() -> Result<String, WindowsPlatformError> {
    // SAFETY: GetCurrentProcess returns a process pseudo-handle that must not
    // be closed and remains valid for the current process lifetime.
    let current_token = open_query_token(unsafe { GetCurrentProcess() })?;
    let current_user = read_token_user(as_windows_handle(&current_token))?;
    let value = sid_to_string(current_user.sid)?;
    if value.is_empty()
        || value.len() > 184
        || !value.is_ascii()
        || !value.starts_with("S-")
        || value
            .chars()
            .any(|character| !(character.is_ascii_digit() || matches!(character, 'S' | '-')))
    {
        return Err(WindowsPlatformError::UnauthorizedLocalIpc);
    }
    Ok(value)
}

fn open_query_token(process: HANDLE) -> Result<OwnedHandle, WindowsPlatformError> {
    let mut token = HANDLE::default();
    // SAFETY: `process` is either a live owned process handle or the current
    // process pseudo-handle; `token` is a live output location.
    unsafe {
        OpenProcessToken(process, TOKEN_QUERY, &raw mut token)
            .map_err(|_| WindowsPlatformError::UnauthorizedLocalIpc)?;
    }
    owned_handle(token)
}

fn read_token_user(token: HANDLE) -> Result<TokenUserBuffer, WindowsPlatformError> {
    let mut reported_required = 0_u32;
    // SAFETY: this documented sizing query passes no destination buffer and a
    // live size output. Failure is expected; a nonzero required size is used.
    let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &raw mut reported_required) };
    let required = usize::try_from(reported_required)
        .map_err(|_| WindowsPlatformError::UnauthorizedLocalIpc)?;
    if required < size_of::<TOKEN_USER>() || required > MAX_TOKEN_INFORMATION_BYTES {
        return Err(WindowsPlatformError::UnauthorizedLocalIpc);
    }
    let units = required.div_ceil(size_of::<usize>());
    let mut storage = vec![0_usize; units];
    let byte_len = u32::try_from(size_of_val(storage.as_slice()))
        .map_err(|_| WindowsPlatformError::UnauthorizedLocalIpc)?;
    // SAFETY: the usize-backed allocation has sufficient size and alignment
    // for TOKEN_USER, remains writable for `byte_len`, and the size output is live.
    unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(storage.as_mut_ptr().cast::<c_void>()),
            byte_len,
            &raw mut reported_required,
        )
        .map_err(|_| WindowsPlatformError::UnauthorizedLocalIpc)?;
    }
    // SAFETY: GetTokenInformation initialized a TOKEN_USER at the aligned start
    // of `storage`; the buffer remains owned by the returned wrapper.
    let sid = unsafe { (*(storage.as_ptr().cast::<TOKEN_USER>())).User.Sid };
    // SAFETY: `sid` was returned by GetTokenInformation and its backing buffer
    // remains live. Invalid or null SIDs fail closed.
    if sid.is_invalid() || !unsafe { IsValidSid(sid) }.as_bool() {
        return Err(WindowsPlatformError::UnauthorizedLocalIpc);
    }
    Ok(TokenUserBuffer {
        _storage: storage,
        sid,
    })
}

fn sid_to_string(sid: PSID) -> Result<String, WindowsPlatformError> {
    let mut sid_text = PWSTR::null();
    // SAFETY: the caller retains the validated SID backing buffer for this
    // call. Windows returns a NUL-terminated LocalAlloc string on success.
    unsafe {
        ConvertSidToStringSidW(sid, &raw mut sid_text)
            .map_err(|_| WindowsPlatformError::UnauthorizedLocalIpc)?;
    }
    if sid_text.is_null() {
        return Err(WindowsPlatformError::UnauthorizedLocalIpc);
    }
    let sid_text = LocalWideString(sid_text);
    // SAFETY: ConvertSidToStringSidW returned a live NUL-terminated string
    // retained by sid_text until after this copy.
    unsafe { sid_text.0.to_string() }.map_err(|_| WindowsPlatformError::UnauthorizedLocalIpc)
}

fn process_session_id(process_id: u32) -> Result<u32, WindowsPlatformError> {
    let mut session_id = 0_u32;
    // SAFETY: the output pointer is live and the PID is supplied by Windows or
    // GetCurrentProcessId.
    unsafe {
        ProcessIdToSessionId(process_id, &raw mut session_id)
            .map_err(|_| WindowsPlatformError::UnauthorizedLocalIpc)?;
    }
    Ok(session_id)
}

struct LocalSecurityDescriptor(PSECURITY_DESCRIPTOR);

impl Drop for LocalSecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: ConvertStringSecurityDescriptor allocated this exact pointer
        // with LocalAlloc; it is released once after CreateNamedPipe returns.
        let _ = unsafe { LocalFree(Some(HLOCAL(self.0.0))) };
    }
}

struct LocalWideString(PWSTR);

impl Drop for LocalWideString {
    fn drop(&mut self) {
        // SAFETY: ConvertSidToStringSidW allocated this exact pointer with
        // LocalAlloc; it is released once after conversion.
        let _ = unsafe { LocalFree(Some(HLOCAL(self.0.0.cast::<c_void>()))) };
    }
}

struct TokenUserBuffer {
    _storage: Vec<usize>,
    sid: PSID,
}

#[derive(Clone, Copy)]
pub(super) enum NativeInput {
    ScanCodeKey {
        scan_code: u16,
        extended: bool,
        released: bool,
    },
    VirtualKey {
        virtual_key: u16,
        released: bool,
    },
    AbsoluteMotion {
        x: i32,
        y: i32,
    },
    RelativeMotion {
        delta_x: i32,
        delta_y: i32,
    },
    Button {
        number: u8,
        released: bool,
    },
    Scroll {
        horizontal: i32,
        vertical: i32,
    },
}

/// Establishes the process-wide per-monitor-v2 contract before any Nodavo
/// display enumeration or window creation.
pub(super) fn ensure_process_dpi_awareness() -> Result<(), WindowsPlatformError> {
    *PROCESS_DPI_AWARENESS.get_or_init(|| {
        // SAFETY: this process-wide call has no pointer parameters. Nodavo calls
        // it before its first display or window boundary.
        let result =
            unsafe { SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) };
        let Err(error) = result else { return Ok(()) };
        // A manifest or earlier Nodavo boundary may already have established
        // the process default. Accept only the exact PMv2 context; an unrelated
        // shell process cannot affect this process-local query.
        // SAFETY: both calls only inspect process/thread DPI state.
        let denied = error.code() == HRESULT::from_win32(ERROR_ACCESS_DENIED.0);
        let current = unsafe { GetDpiAwarenessContextForProcess(GetCurrentProcess()) };
        if denied
            && unsafe {
                AreDpiAwarenessContextsEqual(current, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2)
            }
            .as_bool()
        {
            Ok(())
        } else {
            Err(WindowsPlatformError::NativeApi)
        }
    })
}

pub(super) fn probe_environment() -> Result<EnvironmentCapabilities, WindowsPlatformError> {
    let mut process_session_id = 0_u32;
    // SAFETY: the output pointer refers to a live `u32`, and the current PID is
    // obtained from the same process immediately before the query.
    unsafe {
        ProcessIdToSessionId(GetCurrentProcessId(), &raw mut process_session_id)
            .map_err(|_| WindowsPlatformError::SessionUnavailable)?;
    }
    if process_session_id == 0 {
        return Err(WindowsPlatformError::SessionUnavailable);
    }

    // SAFETY: this query has no pointer parameters or ownership transfer.
    let active = unsafe { WTSGetActiveConsoleSessionId() };
    let active_console_session_id = (active != NO_ACTIVE_SESSION).then_some(active);
    verify_default_input_desktop()?;
    Ok(EnvironmentCapabilities {
        process_session_id,
        active_console_session_id,
        input_desktop_is_default: true,
        send_input: true,
        raw_input_capture: true,
        clipboard: true,
    })
}

fn verify_default_input_desktop() -> Result<(), WindowsPlatformError> {
    // SAFETY: no native handle is supplied by Rust. The returned owned HDESK is
    // closed by `DesktopGuard` before this function returns.
    let desktop =
        unsafe { OpenInputDesktop(DESKTOP_CONTROL_FLAGS::default(), false, DESKTOP_READOBJECTS) }
            .map_err(|_| WindowsPlatformError::SecureDesktop)?;
    let guard = DesktopGuard(desktop);
    let mut name = [0_u16; MAX_DESKTOP_NAME_UNITS];
    let byte_len = u32::try_from(size_of::<u16>() * name.len())
        .map_err(|_| WindowsPlatformError::NativeApi)?;
    let mut needed = 0_u32;
    // SAFETY: `name` is writable for `byte_len` bytes, `needed` is a live output
    // value, and `guard.0` remains open for the duration of the call.
    unsafe {
        GetUserObjectInformationW(
            HANDLE(guard.0.0),
            UOI_NAME,
            Some(name.as_mut_ptr().cast::<c_void>()),
            byte_len,
            Some(&raw mut needed),
        )
        .map_err(|_| WindowsPlatformError::SecureDesktop)?;
    }
    let nul = name
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(name.len());
    let desktop_name =
        String::from_utf16(&name[..nul]).map_err(|_| WindowsPlatformError::SecureDesktop)?;
    if !desktop_name.eq_ignore_ascii_case("default") {
        return Err(WindowsPlatformError::SecureDesktop);
    }
    Ok(())
}

struct DesktopGuard(HDESK);

impl Drop for DesktopGuard {
    fn drop(&mut self) {
        // SAFETY: this guard uniquely owns the HDESK returned by
        // `OpenInputDesktop`; no operation uses it after this drop begins.
        let _ = unsafe { CloseDesktop(self.0) };
    }
}

pub(super) fn enumerate_displays() -> Result<Vec<NativeDisplayGeometry>, WindowsPlatformError> {
    ensure_process_dpi_awareness()?;
    let mut context = MonitorContext {
        displays: Vec::new(),
        error: None,
    };
    let parameter = LPARAM(ptr::from_mut(&mut context).addr().cast_signed());
    // SAFETY: `parameter` points to `context` for the synchronous duration of
    // EnumDisplayMonitors. The callback never retains the pointer.
    let completed = unsafe { EnumDisplayMonitors(None, None, Some(monitor_callback), parameter) };
    if !completed.as_bool() {
        return Err(context.error.unwrap_or(WindowsPlatformError::NativeApi));
    }
    if let Some(error) = context.error {
        return Err(error);
    }
    Ok(context.displays)
}

struct MonitorContext {
    displays: Vec<NativeDisplayGeometry>,
    error: Option<WindowsPlatformError>,
}

unsafe extern "system" fn monitor_callback(
    monitor: HMONITOR,
    _device_context: HDC,
    _bounds: *mut RECT,
    parameter: LPARAM,
) -> BOOL {
    // SAFETY: `enumerate_displays` passes a non-null, aligned pointer to a live
    // `MonitorContext`; EnumDisplayMonitors invokes callbacks synchronously.
    let context = unsafe { &mut *(parameter.0 as *mut MonitorContext) };
    if context.displays.len() >= MAX_DISPLAYS {
        context.error = Some(WindowsPlatformError::InvalidDisplay);
        return false.into();
    }
    match unsafe { describe_monitor(monitor) } {
        Ok(display) => context.displays.push(display),
        Err(error) => {
            context.error = Some(error);
            return false.into();
        }
    }
    true.into()
}

unsafe fn describe_monitor(
    monitor: HMONITOR,
) -> Result<NativeDisplayGeometry, WindowsPlatformError> {
    let mut info = MONITORINFOEXW {
        monitorInfo: windows::Win32::Graphics::Gdi::MONITORINFO {
            cbSize: u32::try_from(size_of::<MONITORINFOEXW>())
                .map_err(|_| WindowsPlatformError::NativeApi)?,
            ..Default::default()
        },
        ..Default::default()
    };
    // SAFETY: `info` has the required cbSize and remains writable for the call.
    if !unsafe { GetMonitorInfoW(monitor, (&raw mut info).cast()) }.as_bool() {
        return Err(WindowsPlatformError::NativeApi);
    }
    let width = u32::try_from(info.monitorInfo.rcMonitor.right - info.monitorInfo.rcMonitor.left)
        .map_err(|_| WindowsPlatformError::InvalidDisplay)?;
    let height = u32::try_from(info.monitorInfo.rcMonitor.bottom - info.monitorInfo.rcMonitor.top)
        .map_err(|_| WindowsPlatformError::InvalidDisplay)?;
    if width == 0 || height == 0 {
        return Err(WindowsPlatformError::InvalidDisplay);
    }
    let mut dpi_x = 0_u32;
    let mut dpi_y = 0_u32;
    // SAFETY: both DPI output pointers are live, and `monitor` was supplied by
    // the active EnumDisplayMonitors callback.
    unsafe { GetDpiForMonitor(monitor, MDT_EFFECTIVE_DPI, &raw mut dpi_x, &raw mut dpi_y) }
        .map_err(|_| WindowsPlatformError::NativeApi)?;
    if dpi_x == 0 || dpi_y == 0 {
        return Err(WindowsPlatformError::InvalidDisplay);
    }
    Ok(NativeDisplayGeometry {
        key: monitor_identity_key(&info.szDevice)?,
        left: info.monitorInfo.rcMonitor.left,
        top: info.monitorInfo.rcMonitor.top,
        width_pixels: width,
        height_pixels: height,
        dpi_x,
        dpi_y,
        rotation: monitor_rotation(&info.szDevice)?,
        primary: info.monitorInfo.dwFlags & MONITORINFOF_PRIMARY != 0,
    })
}

fn monitor_rotation(
    adapter_name: &[u16; 32],
) -> Result<nodavo_protocol::DisplayRotation, WindowsPlatformError> {
    let mut mode = DEVMODEW {
        dmSize: u16::try_from(size_of::<DEVMODEW>())
            .map_err(|_| WindowsPlatformError::NativeApi)?,
        ..Default::default()
    };
    // SAFETY: adapter_name is the NUL-terminated MONITORINFOEXW source name;
    // `mode` has the required dmSize and remains writable during the call.
    if !unsafe {
        EnumDisplaySettingsW(
            PCWSTR(adapter_name.as_ptr()),
            ENUM_CURRENT_SETTINGS,
            &raw mut mode,
        )
    }
    .as_bool()
        || mode.dmFields & DM_DISPLAYORIENTATION != DM_DISPLAYORIENTATION
    {
        return Err(WindowsPlatformError::InvalidDisplay);
    }
    // SAFETY: EnumDisplaySettingsW succeeded and explicitly marked the display
    // orientation member as valid in dmFields.
    display_rotation(unsafe { mode.Anonymous1.Anonymous2.dmDisplayOrientation }.0)
}

fn monitor_identity_key(
    adapter_name: &[u16; 32],
) -> Result<NativeDisplayKey, WindowsPlatformError> {
    let source_key = NativeDisplayKey::new(adapter_name)?;
    let mut active_interfaces = Vec::new();
    for path in active_display_config_paths()? {
        let mut source = DISPLAYCONFIG_SOURCE_DEVICE_NAME {
            header: DISPLAYCONFIG_DEVICE_INFO_HEADER {
                r#type: DISPLAYCONFIG_DEVICE_INFO_GET_SOURCE_NAME,
                size: u32::try_from(size_of::<DISPLAYCONFIG_SOURCE_DEVICE_NAME>())
                    .map_err(|_| WindowsPlatformError::NativeApi)?,
                adapterId: path.sourceInfo.adapterId,
                id: path.sourceInfo.id,
            },
            ..Default::default()
        };
        // SAFETY: the request header has the exact source structure size and
        // an adapter/source pair returned by QueryDisplayConfig.
        if unsafe { DisplayConfigGetDeviceInfo(&raw mut source.header) } != 0 {
            return Err(WindowsPlatformError::NativeApi);
        }
        if NativeDisplayKey::new(&source.viewGdiDeviceName)? != source_key {
            continue;
        }

        let mut target = DISPLAYCONFIG_TARGET_DEVICE_NAME {
            header: DISPLAYCONFIG_DEVICE_INFO_HEADER {
                r#type: DISPLAYCONFIG_DEVICE_INFO_GET_TARGET_NAME,
                size: u32::try_from(size_of::<DISPLAYCONFIG_TARGET_DEVICE_NAME>())
                    .map_err(|_| WindowsPlatformError::NativeApi)?,
                adapterId: path.targetInfo.adapterId,
                id: path.targetInfo.id,
            },
            ..Default::default()
        };
        // SAFETY: the request header has the exact target structure size and
        // an adapter/target pair returned by QueryDisplayConfig.
        if unsafe { DisplayConfigGetDeviceInfo(&raw mut target.header) } != 0 {
            return Err(WindowsPlatformError::NativeApi);
        }
        active_interfaces.push(NativeDisplayKey::from_display_config_target(
            path.targetInfo.adapterId.LowPart,
            path.targetInfo.adapterId.HighPart,
            path.targetInfo.id,
            &target.monitorDevicePath,
        )?);
    }
    // The GDI source name is used only to join two observations made during the
    // same sample. It is never persisted as identity. Mirroring or a missing
    // target interface fails closed instead of inheriting a retired identifier.
    unique_native_display_key(active_interfaces)
}

fn active_display_config_paths() -> Result<Vec<DISPLAYCONFIG_PATH_INFO>, WindowsPlatformError> {
    for _ in 0..DISPLAY_CONFIG_QUERY_ATTEMPTS {
        let mut path_count = 0_u32;
        let mut mode_count = 0_u32;
        // SAFETY: both count outputs are live and no buffers are supplied.
        if unsafe {
            GetDisplayConfigBufferSizes(
                QDC_ONLY_ACTIVE_PATHS,
                &raw mut path_count,
                &raw mut mode_count,
            )
        } != ERROR_SUCCESS
        {
            return Err(WindowsPlatformError::NativeApi);
        }
        let path_capacity =
            usize::try_from(path_count).map_err(|_| WindowsPlatformError::InvalidDisplay)?;
        let mode_capacity =
            usize::try_from(mode_count).map_err(|_| WindowsPlatformError::InvalidDisplay)?;
        if path_capacity == 0
            || path_capacity > MAX_DISPLAYS
            || mode_capacity == 0
            || mode_capacity > MAX_DISPLAY_CONFIG_MODES
        {
            return Err(WindowsPlatformError::InvalidDisplay);
        }
        let mut paths = vec![DISPLAYCONFIG_PATH_INFO::default(); path_capacity];
        let mut modes = vec![DISPLAYCONFIG_MODE_INFO::default(); mode_capacity];
        // SAFETY: both vectors have the capacities advertised immediately above;
        // the call updates counts to the initialized prefix lengths.
        let status = unsafe {
            QueryDisplayConfig(
                QDC_ONLY_ACTIVE_PATHS,
                &raw mut path_count,
                paths.as_mut_ptr(),
                &raw mut mode_count,
                modes.as_mut_ptr(),
                None,
            )
        };
        if status == ERROR_INSUFFICIENT_BUFFER {
            continue;
        }
        if status != ERROR_SUCCESS {
            return Err(WindowsPlatformError::NativeApi);
        }
        let path_count =
            usize::try_from(path_count).map_err(|_| WindowsPlatformError::InvalidDisplay)?;
        let mode_count =
            usize::try_from(mode_count).map_err(|_| WindowsPlatformError::InvalidDisplay)?;
        if path_count == 0
            || path_count > paths.len()
            || mode_count == 0
            || mode_count > modes.len()
        {
            return Err(WindowsPlatformError::InvalidDisplay);
        }
        paths.truncate(path_count);
        return Ok(paths);
    }
    Err(WindowsPlatformError::DisplayUnavailable)
}

pub(super) fn send_input(input: NativeInput) -> Result<(), WindowsPlatformError> {
    let mut native = Vec::with_capacity(2);
    match input {
        NativeInput::ScanCodeKey {
            scan_code,
            extended,
            released,
        } => native.push(keyboard_scan_input(scan_code, extended, released)),
        NativeInput::VirtualKey {
            virtual_key,
            released,
        } => native.push(keyboard_virtual_input(virtual_key, released)),
        NativeInput::AbsoluteMotion { x, y } => native.push(mouse_input(
            x,
            y,
            0,
            MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK,
        )),
        NativeInput::RelativeMotion { delta_x, delta_y } => {
            native.push(mouse_input(delta_x, delta_y, 0, MOUSEEVENTF_MOVE));
        }
        NativeInput::Button { number, released } => {
            let (data, flags) = mouse_button(number, released)?;
            native.push(mouse_input(0, 0, data, flags));
        }
        NativeInput::Scroll {
            horizontal,
            vertical,
        } => {
            if horizontal != 0 {
                native.push(mouse_input(
                    0,
                    0,
                    u32::from_ne_bytes(horizontal.to_ne_bytes()),
                    MOUSEEVENTF_HWHEEL,
                ));
            }
            if vertical != 0 {
                native.push(mouse_input(
                    0,
                    0,
                    u32::from_ne_bytes(vertical.to_ne_bytes()),
                    MOUSEEVENTF_WHEEL,
                ));
            }
        }
    }
    if native.is_empty() {
        return Ok(());
    }
    let input_size =
        i32::try_from(size_of::<INPUT>()).map_err(|_| WindowsPlatformError::NativeApi)?;
    // SAFETY: every INPUT union is initialized for its declared input type;
    // the slice remains alive and immutable for the duration of SendInput.
    let sent = unsafe { SendInput(&native, input_size) };
    if usize::try_from(sent).ok() == Some(native.len()) {
        Ok(())
    } else {
        Err(WindowsPlatformError::InputBlocked)
    }
}

fn keyboard_scan_input(scan_code: u16, extended: bool, released: bool) -> INPUT {
    let mut flags = KEYEVENTF_SCANCODE;
    if extended {
        flags |= KEYEVENTF_EXTENDEDKEY;
    }
    if released {
        flags |= KEYEVENTF_KEYUP;
    }
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: VIRTUAL_KEY(0),
                wScan: scan_code,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: NODAVO_INPUT_TAG,
            },
        },
    }
}

fn keyboard_virtual_input(virtual_key: u16, released: bool) -> INPUT {
    let flags = if released {
        KEYEVENTF_KEYUP
    } else {
        KEYBD_EVENT_FLAGS(0)
    };
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: VIRTUAL_KEY(virtual_key),
                wScan: 0,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: NODAVO_INPUT_TAG,
            },
        },
    }
}

fn mouse_input(dx: i32, dy: i32, data: u32, flags: MOUSE_EVENT_FLAGS) -> INPUT {
    INPUT {
        r#type: INPUT_MOUSE,
        Anonymous: INPUT_0 {
            mi: MOUSEINPUT {
                dx,
                dy,
                mouseData: data,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: NODAVO_INPUT_TAG,
            },
        },
    }
}

fn mouse_button(
    number: u8,
    released: bool,
) -> Result<(u32, MOUSE_EVENT_FLAGS), WindowsPlatformError> {
    let value = match (number, released) {
        (1, false) => (0, MOUSEEVENTF_LEFTDOWN),
        (1, true) => (0, MOUSEEVENTF_LEFTUP),
        (2, false) => (0, MOUSEEVENTF_RIGHTDOWN),
        (2, true) => (0, MOUSEEVENTF_RIGHTUP),
        (3, false) => (0, MOUSEEVENTF_MIDDLEDOWN),
        (3, true) => (0, MOUSEEVENTF_MIDDLEUP),
        (4, false) => (1, MOUSEEVENTF_XDOWN),
        (4, true) => (1, MOUSEEVENTF_XUP),
        (5, false) => (2, MOUSEEVENTF_XDOWN),
        (5, true) => (2, MOUSEEVENTF_XUP),
        _ => return Err(WindowsPlatformError::UnsupportedButton),
    };
    Ok(value)
}

pub(super) fn clipboard_sequence_number() -> Result<u32, WindowsPlatformError> {
    // SAFETY: this query has no pointer parameters or ownership transfer.
    let sequence = unsafe { GetClipboardSequenceNumber() };
    if sequence == 0 {
        Err(WindowsPlatformError::NativeApi)
    } else {
        Ok(sequence)
    }
}

pub(super) fn clipboard_metadata() -> Result<ClipboardMetadata, WindowsPlatformError> {
    let html_format = registered_html_format()?;
    let png_format = registered_png_format()?;
    let before = clipboard_sequence_number()?;
    let clipboard = ClipboardGuard::open()?;
    // SAFETY: the clipboard is open on this thread and the call has no pointer
    // parameters. Zero means that the native clipboard currently has no data.
    let native_types_empty = unsafe { CountClipboardFormats() } == 0;
    let mut formats = Vec::with_capacity(4);

    if format_is_available(CF_UNICODETEXT) {
        let bytes =
            copy_clipboard_block(CF_UNICODETEXT, maximum_native_utf16_bytes(MAX_TEXT_BYTES)?)?;
        let text = decode_clipboard_text(&bytes, MAX_TEXT_BYTES)?;
        formats.push(ClipboardFormatMetadata {
            format: ClipboardFormat::UnicodeText,
            byte_len: u64::try_from(text.len())
                .map_err(|_| WindowsPlatformError::ClipboardTooLarge)?,
        });
    }
    if format_is_available(html_format) {
        let encoded = copy_clipboard_block(
            html_format,
            u64::try_from(maximum_cf_html_bytes(MAX_TEXT_BYTES)?)
                .map_err(|_| WindowsPlatformError::ClipboardTooLarge)?,
        )?;
        match decode_cf_html(&encoded, MAX_TEXT_BYTES) {
            Ok(fragment) => formats.push(ClipboardFormatMetadata {
                format: ClipboardFormat::Html,
                byte_len: u64::try_from(fragment.len())
                    .map_err(|_| WindowsPlatformError::ClipboardTooLarge)?,
            }),
            Err(WindowsPlatformError::ClipboardTooLarge) => {
                return Err(WindowsPlatformError::ClipboardTooLarge);
            }
            Err(_) => {}
        }
    }
    if format_is_available(png_format) {
        let png = copy_clipboard_block(png_format, MAX_IMAGE_BYTES)?;
        match validate_png(&png, MAX_IMAGE_BYTES) {
            Ok(()) => formats.push(ClipboardFormatMetadata {
                format: ClipboardFormat::Png,
                byte_len: u64::try_from(png.len())
                    .map_err(|_| WindowsPlatformError::ClipboardTooLarge)?,
            }),
            Err(WindowsPlatformError::ClipboardTooLarge) => {
                return Err(WindowsPlatformError::ClipboardTooLarge);
            }
            Err(_) => {}
        }
    }
    match copy_canonical_bmp_from_open_clipboard(MAX_IMAGE_BYTES) {
        Ok(Some(bmp)) => formats.push(ClipboardFormatMetadata {
            format: ClipboardFormat::Bmp,
            byte_len: u64::try_from(bmp.len())
                .map_err(|_| WindowsPlatformError::ClipboardTooLarge)?,
        }),
        Ok(None) | Err(WindowsPlatformError::InvalidClipboardImage) => {}
        Err(error) => return Err(error),
    }
    drop(clipboard);
    let after = clipboard_sequence_number()?;
    if before != after {
        return Err(WindowsPlatformError::ClipboardBusy);
    }
    Ok(ClipboardMetadata {
        sequence_number: before,
        native_types_empty,
        formats,
    })
}

pub(super) fn read_clipboard_text(
    expected_sequence: u32,
    max_bytes: u64,
) -> Result<String, WindowsPlatformError> {
    ensure_sequence(expected_sequence)?;
    let clipboard = ClipboardGuard::open()?;
    let bytes = copy_clipboard_block(CF_UNICODETEXT, maximum_native_utf16_bytes(max_bytes)?)?;
    let value = decode_clipboard_text(&bytes, max_bytes)?;
    drop(clipboard);
    ensure_sequence(expected_sequence)?;
    Ok(value)
}

pub(super) fn write_clipboard_text(
    text: &str,
    max_bytes: u64,
) -> Result<u32, WindowsPlatformError> {
    if text.contains('\0') {
        return Err(WindowsPlatformError::InvalidClipboardText);
    }
    if u64::try_from(text.len()).map_err(|_| WindowsPlatformError::ClipboardTooLarge)? > max_bytes {
        return Err(WindowsPlatformError::ClipboardTooLarge);
    }
    let units: Vec<u16> = text.encode_utf16().chain([0]).collect();
    let byte_len = units
        .len()
        .checked_mul(size_of::<u16>())
        .ok_or(WindowsPlatformError::ClipboardTooLarge)?;
    if u64::try_from(byte_len).map_err(|_| WindowsPlatformError::ClipboardTooLarge)?
        > maximum_native_utf16_bytes(max_bytes)?
    {
        return Err(WindowsPlatformError::ClipboardTooLarge);
    }
    let bytes = units
        .iter()
        .flat_map(|unit| unit.to_le_bytes())
        .collect::<Vec<_>>();
    replace_clipboard_block(CF_UNICODETEXT, &bytes)?;
    clipboard_sequence_number()
}

pub(super) fn read_clipboard_html(
    expected_sequence: u32,
    max_bytes: u64,
) -> Result<String, WindowsPlatformError> {
    ensure_sequence(expected_sequence)?;
    let clipboard = ClipboardGuard::open()?;
    let encoded = copy_clipboard_block(
        registered_html_format()?,
        u64::try_from(maximum_cf_html_bytes(max_bytes)?)
            .map_err(|_| WindowsPlatformError::ClipboardTooLarge)?,
    )?;
    let fragment = Zeroizing::new(decode_cf_html(&encoded, max_bytes)?);
    let value = std::str::from_utf8(&fragment)
        .map_err(|_| WindowsPlatformError::InvalidClipboardHtml)?
        .to_owned();
    drop(clipboard);
    ensure_sequence(expected_sequence)?;
    Ok(value)
}

pub(super) fn write_clipboard_html(
    fragment: &str,
    max_bytes: u64,
) -> Result<u32, WindowsPlatformError> {
    let encoded = Zeroizing::new(encode_cf_html(fragment.as_bytes(), max_bytes)?);
    replace_clipboard_block(registered_html_format()?, &encoded)?;
    clipboard_sequence_number()
}

pub(super) fn read_clipboard_png(
    expected_sequence: u32,
    max_bytes: u64,
) -> Result<Vec<u8>, WindowsPlatformError> {
    ensure_sequence(expected_sequence)?;
    let clipboard = ClipboardGuard::open()?;
    let bytes = copy_clipboard_block(registered_png_format()?, max_bytes)?;
    validate_png(&bytes, max_bytes)?;
    let value = bytes.to_vec();
    drop(clipboard);
    ensure_sequence(expected_sequence)?;
    Ok(value)
}

pub(super) fn write_clipboard_png(png: &[u8], max_bytes: u64) -> Result<u32, WindowsPlatformError> {
    validate_png(png, max_bytes)?;
    replace_clipboard_block(registered_png_format()?, png)?;
    clipboard_sequence_number()
}

pub(super) fn read_clipboard_bmp(
    expected_sequence: u32,
    max_bytes: u64,
) -> Result<Vec<u8>, WindowsPlatformError> {
    ensure_sequence(expected_sequence)?;
    let clipboard = ClipboardGuard::open()?;
    let bmp = copy_canonical_bmp_from_open_clipboard(max_bytes)?
        .ok_or(WindowsPlatformError::ClipboardFormatUnavailable)?;
    drop(clipboard);
    ensure_sequence(expected_sequence)?;
    Ok(bmp)
}

pub(super) fn write_clipboard_bmp(bmp: &[u8], max_bytes: u64) -> Result<u32, WindowsPlatformError> {
    let dib = Zeroizing::new(bmp_to_dib(bmp, max_bytes)?);
    let header_size = u32::from_le_bytes(
        dib.get(..4)
            .ok_or(WindowsPlatformError::InvalidClipboardImage)?
            .try_into()
            .map_err(|_| WindowsPlatformError::InvalidClipboardImage)?,
    );
    let format = if header_size == 124 { CF_DIBV5 } else { CF_DIB };
    replace_clipboard_block(format, &dib)?;
    clipboard_sequence_number()
}

pub(super) fn clear_clipboard() -> Result<u32, WindowsPlatformError> {
    let clipboard = ClipboardGuard::open()?;
    // SAFETY: the clipboard is open on this thread and no HGLOBAL is retained.
    unsafe { EmptyClipboard() }.map_err(|_| WindowsPlatformError::NativeApi)?;
    drop(clipboard);
    clipboard_sequence_number()
}

pub(super) fn read_clipboard_image(
    format: ClipboardFormat,
    expected_sequence: u32,
    max_bytes: u64,
) -> Result<Vec<u8>, WindowsPlatformError> {
    ensure_sequence(expected_sequence)?;
    let clipboard = ClipboardGuard::open()?;
    let bytes = copy_clipboard_block(native_format(format)?, max_bytes)?;
    validate_dib(format, &bytes)?;
    drop(clipboard);
    ensure_sequence(expected_sequence)?;
    Ok(bytes.to_vec())
}

pub(super) fn write_clipboard_image(
    format: ClipboardFormat,
    dib: &[u8],
    max_bytes: u64,
) -> Result<u32, WindowsPlatformError> {
    if u64::try_from(dib.len()).map_err(|_| WindowsPlatformError::ClipboardTooLarge)? > max_bytes {
        return Err(WindowsPlatformError::ClipboardTooLarge);
    }
    validate_dib(format, dib)?;
    replace_clipboard_block(native_format(format)?, dib)?;
    clipboard_sequence_number()
}

fn ensure_sequence(expected: u32) -> Result<(), WindowsPlatformError> {
    if clipboard_sequence_number()? == expected {
        Ok(())
    } else {
        Err(WindowsPlatformError::ClipboardBusy)
    }
}

fn maximum_native_utf16_bytes(maximum_utf8: u64) -> Result<u64, WindowsPlatformError> {
    maximum_utf8
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(2))
        .ok_or(WindowsPlatformError::ClipboardTooLarge)
}

fn decode_clipboard_text(bytes: &[u8], maximum_utf8: u64) -> Result<String, WindowsPlatformError> {
    if bytes.len() < 2 || !bytes.len().is_multiple_of(2) {
        return Err(WindowsPlatformError::InvalidClipboardText);
    }
    let mut units = Zeroizing::new(Vec::with_capacity(bytes.len() / 2));
    for pair in bytes.chunks_exact(2) {
        units.push(u16::from_le_bytes([pair[0], pair[1]]));
    }
    let nul = units
        .iter()
        .position(|unit| *unit == 0)
        .ok_or(WindowsPlatformError::InvalidClipboardText)?;
    if units[nul + 1..].iter().any(|unit| *unit != 0) {
        return Err(WindowsPlatformError::InvalidClipboardText);
    }
    let value = String::from_utf16(&units[..nul])
        .map_err(|_| WindowsPlatformError::InvalidClipboardText)?;
    if u64::try_from(value.len()).map_err(|_| WindowsPlatformError::ClipboardTooLarge)?
        > maximum_utf8
    {
        return Err(WindowsPlatformError::ClipboardTooLarge);
    }
    Ok(value)
}

fn native_format(format: ClipboardFormat) -> Result<u32, WindowsPlatformError> {
    match format {
        ClipboardFormat::UnicodeText => Ok(CF_UNICODETEXT),
        ClipboardFormat::Dib => Ok(CF_DIB),
        ClipboardFormat::DibV5 => Ok(CF_DIBV5),
        ClipboardFormat::Html | ClipboardFormat::Png | ClipboardFormat::Bmp => {
            Err(WindowsPlatformError::InvalidClipboardImage)
        }
    }
}

fn registered_html_format() -> Result<u32, WindowsPlatformError> {
    // SAFETY: `w!` supplies a process-lifetime, NUL-terminated UTF-16 string.
    let format = unsafe { RegisterClipboardFormatW(w!("HTML Format")) };
    (format != 0)
        .then_some(format)
        .ok_or(WindowsPlatformError::NativeApi)
}

fn registered_png_format() -> Result<u32, WindowsPlatformError> {
    // SAFETY: `w!` supplies a process-lifetime, NUL-terminated UTF-16 string.
    let format = unsafe { RegisterClipboardFormatW(w!("PNG")) };
    (format != 0)
        .then_some(format)
        .ok_or(WindowsPlatformError::NativeApi)
}

fn format_is_available(format: u32) -> bool {
    // SAFETY: this query has no pointer or ownership transfer; callers hold the
    // clipboard open when consistency with a read matters.
    unsafe { IsClipboardFormatAvailable(format) }.is_ok()
}

fn copy_canonical_bmp_from_open_clipboard(
    maximum: u64,
) -> Result<Option<Vec<u8>>, WindowsPlatformError> {
    let mut advertised = false;
    for native in [CF_DIBV5, CF_DIB] {
        if !format_is_available(native) {
            continue;
        }
        advertised = true;
        let dib = copy_clipboard_block(native, maximum)?;
        match dib_to_bmp(&dib, maximum) {
            Ok(bmp) => return Ok(Some(bmp)),
            Err(WindowsPlatformError::InvalidClipboardImage) => {}
            Err(error) => return Err(error),
        }
    }
    if advertised {
        Err(WindowsPlatformError::InvalidClipboardImage)
    } else {
        Ok(None)
    }
}

fn copy_clipboard_block(
    format: u32,
    maximum: u64,
) -> Result<Zeroizing<Vec<u8>>, WindowsPlatformError> {
    // SAFETY: the clipboard is open and the handle is borrowed without taking
    // ownership. Its memory remains valid until the clipboard is closed.
    let handle = unsafe { GetClipboardData(format) }
        .map_err(|_| WindowsPlatformError::ClipboardFormatUnavailable)?;
    let global = HGLOBAL(handle.0);
    // SAFETY: `global` is the HGLOBAL-compatible handle returned above.
    let size = unsafe { GlobalSize(global) };
    if size == 0
        || u64::try_from(size).map_err(|_| WindowsPlatformError::ClipboardTooLarge)? > maximum
    {
        return Err(WindowsPlatformError::ClipboardTooLarge);
    }
    // SAFETY: `global` is valid and remains owned by the open clipboard.
    let address = unsafe { GlobalLock(global) };
    if address.is_null() {
        return Err(WindowsPlatformError::NativeApi);
    }
    // SAFETY: GlobalSize bounded the readable region before slice construction;
    // the lock remains held while the data is copied into owned Rust memory.
    let bytes =
        Zeroizing::new(unsafe { std::slice::from_raw_parts(address.cast::<u8>(), size) }.to_vec());
    // SAFETY: this unlock balances the successful GlobalLock above. A false
    // return can mean the lock count reached zero, so no error is inferred.
    let _ = unsafe { GlobalUnlock(global) };
    Ok(bytes)
}

fn replace_clipboard_block(format: u32, bytes: &[u8]) -> Result<(), WindowsPlatformError> {
    if bytes.is_empty() {
        return Err(WindowsPlatformError::InvalidClipboardImage);
    }
    let allocation = OwnedGlobal::copy_from(bytes)?;
    let clipboard = ClipboardGuard::open()?;
    // SAFETY: the clipboard is open on this thread. EmptyClipboard is called
    // before transferring the single HGLOBAL allocation below.
    unsafe { EmptyClipboard() }.map_err(|_| WindowsPlatformError::NativeApi)?;
    // SAFETY: `allocation.handle` is a moveable HGLOBAL with bytes initialized
    // for `format`. On success Windows owns it and the guard is disarmed.
    unsafe { SetClipboardData(format, Some(HANDLE(allocation.handle.0))) }
        .map_err(|_| WindowsPlatformError::NativeApi)?;
    allocation.transfer_ownership();
    drop(clipboard);
    Ok(())
}

fn validate_dib(format: ClipboardFormat, dib: &[u8]) -> Result<(), WindowsPlatformError> {
    if format == ClipboardFormat::UnicodeText || dib.len() < 4 {
        return Err(WindowsPlatformError::InvalidClipboardImage);
    }
    let header_size = u32::from_le_bytes([dib[0], dib[1], dib[2], dib[3]]);
    let minimum = if format == ClipboardFormat::DibV5 {
        124
    } else {
        40
    };
    if header_size < minimum
        || usize::try_from(header_size)
            .ok()
            .is_none_or(|header| header > dib.len())
    {
        return Err(WindowsPlatformError::InvalidClipboardImage);
    }
    Ok(())
}

struct ClipboardGuard;

impl ClipboardGuard {
    fn open() -> Result<Self, WindowsPlatformError> {
        // SAFETY: no owner HWND is supplied; the successful open is balanced by
        // this guard's Drop on the same thread.
        unsafe { OpenClipboard(None) }.map_err(|_| WindowsPlatformError::ClipboardBusy)?;
        Ok(Self)
    }
}

impl Drop for ClipboardGuard {
    fn drop(&mut self) {
        // SAFETY: this guard exists only after successful OpenClipboard and is
        // not Send, so close occurs before control leaves the calling thread.
        let _ = unsafe { CloseClipboard() };
    }
}

struct OwnedGlobal {
    handle: HGLOBAL,
    transferred: bool,
}

impl OwnedGlobal {
    fn copy_from(bytes: &[u8]) -> Result<Self, WindowsPlatformError> {
        // SAFETY: size is the exact source slice length and the returned moveable
        // allocation is owned by the guard until SetClipboardData succeeds.
        let handle = unsafe { GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, bytes.len()) }
            .map_err(|_| WindowsPlatformError::NativeApi)?;
        // SAFETY: the allocation is live and has at least `bytes.len()` bytes.
        let destination = unsafe { GlobalLock(handle) };
        if destination.is_null() {
            // SAFETY: ownership has not transferred and the handle is not locked.
            let _ = unsafe { GlobalFree(Some(handle)) };
            return Err(WindowsPlatformError::NativeApi);
        }
        // SAFETY: source and destination are valid for `bytes.len()` bytes and
        // do not overlap because the destination is a new global allocation.
        unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), destination.cast::<u8>(), bytes.len()) };
        // SAFETY: balances the successful GlobalLock. A false result may simply
        // mean the lock count reached zero and is not treated as failure.
        let _ = unsafe { GlobalUnlock(handle) };
        Ok(Self {
            handle,
            transferred: false,
        })
    }

    fn transfer_ownership(mut self) {
        self.transferred = true;
    }
}

impl Drop for OwnedGlobal {
    fn drop(&mut self) {
        if !self.transferred {
            // SAFETY: this guard owns the HGLOBAL unless SetClipboardData has
            // explicitly transferred ownership to Windows.
            let _ = unsafe { GlobalFree(Some(self.handle)) };
        }
    }
}
