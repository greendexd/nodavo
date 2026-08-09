//! Audited Win32 FFI wrappers. Unsafe code must remain in this module.

use std::cell::Cell;
use std::collections::VecDeque;
use std::ffi::c_void;
use std::mem::{size_of, size_of_val};
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::io::AsRawHandle;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use nodavo_input::DisplayId;
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows::Win32::Foundation::{
    CloseHandle, GlobalFree, HANDLE, HGLOBAL, HINSTANCE, HLOCAL, LPARAM, LRESULT, LocalFree, POINT,
    RECT, WPARAM,
};
use windows::Win32::Graphics::Gdi::{
    EnumDisplayMonitors, GetMonitorInfoW, HDC, HMONITOR, MONITORINFO,
};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
};
use windows::Win32::Security::{
    EqualSid, GetTokenInformation, IsValidSid, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
    TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows::Win32::Storage::FileSystem::{
    MOVE_FILE_FLAGS, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
};
use windows::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, GetClipboardData, GetClipboardSequenceNumber,
    IsClipboardFormatAvailable, OpenClipboard, SetClipboardData,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Memory::{
    GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalSize, GlobalUnlock,
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
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, GetCurrentThreadId, OpenProcess, OpenProcessToken,
    PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::Win32::UI::HiDpi::{GetDpiForMonitor, MDT_EFFECTIVE_DPI};
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
use windows::Win32::UI::WindowsAndMessaging::{
    CW_USEDEFAULT, CallNextHookEx, CreateWindowExW, DEVICE_NOTIFY_WINDOW_HANDLE, DefWindowProcW,
    DestroyWindow, DispatchMessageW, GIDC_ARRIVAL, GIDC_REMOVAL, GetCursorPos, GetMessageTime,
    GetMessageW, HHOOK, HWND_MESSAGE, KBDLLHOOKSTRUCT, KillTimer, LLKHF_EXTENDED, LLKHF_INJECTED,
    LLKHF_LOWER_IL_INJECTED, LLMHF_INJECTED, LLMHF_LOWER_IL_INJECTED, MSG, MSLLHOOKSTRUCT,
    PBT_APMRESUMEAUTOMATIC, PBT_APMRESUMECRITICAL, PBT_APMRESUMESUSPEND, PBT_APMSUSPEND,
    PostMessageW, PostQuitMessage, RI_KEY_BREAK, RI_KEY_E0, RI_KEY_E1, RI_MOUSE_BUTTON_1_DOWN,
    RI_MOUSE_BUTTON_1_UP, RI_MOUSE_BUTTON_2_DOWN, RI_MOUSE_BUTTON_2_UP, RI_MOUSE_BUTTON_3_DOWN,
    RI_MOUSE_BUTTON_3_UP, RI_MOUSE_BUTTON_4_DOWN, RI_MOUSE_BUTTON_4_UP, RI_MOUSE_BUTTON_5_DOWN,
    RI_MOUSE_BUTTON_5_UP, RI_MOUSE_HWHEEL, RI_MOUSE_WHEEL, RegisterClassW, SetTimer,
    SetWindowsHookExW, TranslateMessage, UnhookWindowsHookEx, UnregisterClassW, WH_KEYBOARD_LL,
    WH_MOUSE_LL, WINDOW_EX_STYLE, WINDOW_STYLE, WM_APP, WM_INPUT, WM_INPUT_DEVICE_CHANGE,
    WM_KEYDOWN, WM_KEYUP, WM_LBUTTONDOWN, WM_LBUTTONUP, WM_MBUTTONDOWN, WM_MBUTTONUP,
    WM_MOUSEHWHEEL, WM_MOUSEMOVE, WM_MOUSEWHEEL, WM_POWERBROADCAST, WM_RBUTTONDOWN, WM_RBUTTONUP,
    WM_SYSKEYDOWN, WM_SYSKEYUP, WM_TIMER, WM_WTSSESSION_CHANGE, WM_XBUTTONDOWN, WM_XBUTTONUP,
    WNDCLASSW, WTS_CONSOLE_CONNECT, WTS_CONSOLE_DISCONNECT, WTS_REMOTE_CONNECT,
    WTS_REMOTE_DISCONNECT, WTS_SESSION_LOCK, WTS_SESSION_UNLOCK,
};
use windows::core::{BOOL, PCWSTR, PWSTR, w};
use zeroize::Zeroizing;

use crate::input_runtime::{
    NativeInputEvent, NativeLifecycleEvent, NativeModifierState, native_keyboard_is_supported,
};
use crate::{
    ClipboardFormat, ClipboardFormatMetadata, ClipboardMetadata, DisplayGeometry,
    EnvironmentCapabilities, MAX_DISPLAYS, MAX_PROTECTED_SECRET_BLOB_BYTES,
    MAX_PROTECTED_SECRET_BYTES, NODAVO_INPUT_TAG, WindowsPlatformError,
};

const CF_DIB: u32 = 8;
const CF_UNICODETEXT: u32 = 13;
const CF_DIBV5: u32 = 17;
const MONITORINFOF_PRIMARY: u32 = 1;
const NO_ACTIVE_SESSION: u32 = u32::MAX;
const MAX_DESKTOP_NAME_UNITS: usize = 64;
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
const HOOK_OBSERVATION_MAX_AGE_MS: u32 = 250;
const CAPTURE_TIMER_ID: usize = 1;
const CAPTURE_TIMER_INTERVAL_MS: u32 = 500;
const WM_NODAVO_CAPTURE_STOP: u32 = WM_APP + 0x4e;
const NODAVO_INPUT_TAG_LOW32: u32 = 0x564f_5749;

thread_local! {
    static CAPTURE_CONTEXT: Cell<*mut InputCaptureContext> = const { Cell::new(ptr::null_mut()) };
}

type NativeInputCallback = dyn FnMut(NativeInputEvent) + Send + 'static;

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
}

#[allow(clippy::struct_excessive_bools)]
struct InputCaptureContext {
    callback: Box<NativeInputCallback>,
    routing_to_peer: Arc<AtomicBool>,
    observations: VecDeque<HookObservation>,
    session_active: bool,
    desktop_available: bool,
    callback_failed: bool,
    native_failed: bool,
}

impl InputCaptureContext {
    fn record_hook(&mut self, observation: HookObservation) {
        if self.observations.len() == MAX_HOOK_OBSERVATIONS {
            self.observations.pop_front();
        }
        self.observations.push_back(observation);
    }

    fn take_origin(
        &mut self,
        key: HookObservationKey,
        timestamp: u32,
    ) -> Option<crate::CaptureDisposition> {
        while self.observations.front().is_some_and(|observation| {
            timestamp.wrapping_sub(observation.timestamp) > HOOK_OBSERVATION_MAX_AGE_MS
        }) {
            self.observations.pop_front();
        }
        let mut matched = None;
        let mut index = 0;
        while index < self.observations.len() {
            if self.observations[index].key != key
                || self.observations[index].timestamp != timestamp
            {
                index += 1;
                continue;
            }
            let observation = self.observations.remove(index)?;
            if observation.disposition != crate::CaptureDisposition::AcceptPhysical {
                matched = Some(observation.disposition);
            } else if matched.is_none() {
                matched = Some(crate::CaptureDisposition::AcceptPhysical);
            }
        }
        matched
    }

    fn emit(&mut self, event: NativeInputEvent) {
        if self.callback_failed {
            return;
        }
        if catch_unwind(AssertUnwindSafe(|| (self.callback)(event))).is_err() {
            self.callback_failed = true;
            self.routing_to_peer.store(false, Ordering::Release);
            // SAFETY: this callback runs only on the capture thread and requests
            // termination of that thread's own message loop.
            unsafe { PostQuitMessage(1) };
        }
    }

    fn emit_lifecycle(&mut self, event: NativeLifecycleEvent) {
        if matches!(
            event,
            NativeLifecycleEvent::SessionLocked
                | NativeLifecycleEvent::SessionDisconnected
                | NativeLifecycleEvent::SystemSuspending
                | NativeLifecycleEvent::DefaultDesktopUnavailable
        ) {
            self.routing_to_peer.store(false, Ordering::Release);
        }
        self.emit(NativeInputEvent::Lifecycle(event));
    }

    fn fail_native(&mut self) {
        self.native_failed = true;
        self.routing_to_peer.store(false, Ordering::Release);
        // SAFETY: this method is called only while dispatching on the capture
        // thread and terminates that thread's own message loop.
        unsafe { PostQuitMessage(1) };
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
        routing_to_peer: Arc<AtomicBool>,
        callback: impl FnMut(NativeInputEvent) + Send + 'static,
    ) -> Result<Self, WindowsPlatformError> {
        probe_environment()?;
        let mut context = Box::new(InputCaptureContext {
            callback: Box::new(callback),
            routing_to_peer,
            observations: VecDeque::with_capacity(MAX_HOOK_OBSERVATIONS),
            session_active: true,
            desktop_available: true,
            callback_failed: false,
            native_failed: false,
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
        if self.context.callback_failed {
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
        self.context.routing_to_peer.store(false, Ordering::Release);
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
        WM_TIMER if wparam.0 == CAPTURE_TIMER_ID => refresh_desktop_state(context),
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
        context.record_hook(HookObservation {
            key: HookObservationKey::Keyboard {
                scan_code,
                virtual_key,
                pressed,
            },
            disposition,
            timestamp: data.time,
        });
        if disposition == crate::CaptureDisposition::AcceptPhysical
            && context.session_active
            && context.desktop_available
            && context.routing_to_peer.load(Ordering::Acquire)
            && native_keyboard_is_supported(scan_code, virtual_key, extended, virtual_key == 0x13)
        {
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
        context.record_hook(HookObservation {
            key: HookObservationKey::Mouse { message },
            disposition,
            timestamp: data.time,
        });
        if disposition == crate::CaptureDisposition::AcceptPhysical
            && context.session_active
            && context.desktop_available
            && context.routing_to_peer.load(Ordering::Acquire)
        {
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
                let _ = context.take_origin(key, timestamp);
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
            if mouse.ulExtraInformation == NODAVO_INPUT_TAG_LOW32 {
                return Ok(());
            }
            // SAFETY: RAWMOUSE always initializes its button-flags/data view.
            let buttons = unsafe { mouse.Anonymous.Anonymous };
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
    for (mask, message, button, pressed) in [
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
    ] {
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

fn emit_if_physical(
    context: &mut InputCaptureContext,
    key: HookObservationKey,
    timestamp: u32,
    event: NativeInputEvent,
) {
    if context.session_active
        && context.desktop_available
        && context.take_origin(key, timestamp) == Some(crate::CaptureDisposition::AcceptPhysical)
    {
        context.emit(event);
    }
}

#[cfg(test)]
mod capture_tests {
    use super::*;

    fn context() -> InputCaptureContext {
        InputCaptureContext {
            callback: Box::new(|_| {}),
            routing_to_peer: Arc::new(AtomicBool::new(false)),
            observations: VecDeque::new(),
            session_active: true,
            desktop_available: true,
            callback_failed: false,
            native_failed: false,
        }
    }

    #[test]
    fn ambiguous_hook_origins_fail_closed() {
        let mut context = context();
        let key = HookObservationKey::Keyboard {
            scan_code: 0x1e,
            virtual_key: 0x41,
            pressed: true,
        };
        for disposition in [
            crate::CaptureDisposition::AcceptPhysical,
            crate::CaptureDisposition::RejectOtherInjected,
        ] {
            context.record_hook(HookObservation {
                key,
                disposition,
                timestamp: 10,
            });
        }
        assert_eq!(
            context.take_origin(key, 10),
            Some(crate::CaptureDisposition::RejectOtherInjected)
        );
        assert!(context.take_origin(key, 10).is_none());
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

pub(super) fn validate_named_pipe_client(
    pipe: &NamedPipeServer,
) -> Result<u32, WindowsPlatformError> {
    let handle = HANDLE(pipe.as_raw_handle());
    let mut client_process_id = 0_u32;
    // SAFETY: the Tokio server owns a connected pipe HANDLE for the duration
    // of this call and the PID output points to a live `u32`.
    unsafe {
        GetNamedPipeClientProcessId(handle, &raw mut client_process_id)
            .map_err(|_| WindowsPlatformError::UnauthorizedLocalIpc)?;
    }
    if client_process_id == 0 {
        return Err(WindowsPlatformError::UnauthorizedLocalIpc);
    }

    // SAFETY: the PID came directly from the connected pipe. The returned
    // process handle is uniquely owned by `OwnedHandle` and closed on drop.
    let client_process =
        unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, client_process_id) }
            .map(OwnedHandle)
            .map_err(|_| WindowsPlatformError::UnauthorizedLocalIpc)?;
    let client_token = open_query_token(client_process.0)?;
    // SAFETY: GetCurrentProcess returns a process pseudo-handle that must not
    // be closed and remains valid for the current process lifetime.
    let current_token = open_query_token(unsafe { GetCurrentProcess() })?;
    let client_user = read_token_user(client_token.0)?;
    let current_user = read_token_user(current_token.0)?;
    // SAFETY: both SID pointers refer into their still-live aligned token
    // buffers and IsValidSid succeeded before this comparison.
    unsafe {
        EqualSid(client_user.sid, current_user.sid)
            .map_err(|_| WindowsPlatformError::UnauthorizedLocalIpc)?;
    }

    let client_session = process_session_id(client_process_id)?;
    let current_session = process_session_id(
        // SAFETY: no parameters and no ownership transfer.
        unsafe { GetCurrentProcessId() },
    )?;
    if client_session != current_session || current_session == 0 {
        return Err(WindowsPlatformError::UnauthorizedLocalIpc);
    }
    Ok(client_process_id)
}

pub(super) fn current_user_sid_string() -> Result<String, WindowsPlatformError> {
    // SAFETY: GetCurrentProcess returns a process pseudo-handle that must not
    // be closed and remains valid for the current process lifetime.
    let current_token = open_query_token(unsafe { GetCurrentProcess() })?;
    let current_user = read_token_user(current_token.0)?;
    let mut sid_text = PWSTR::null();
    // SAFETY: current_user retains the validated SID backing buffer for this
    // call. Windows returns a NUL-terminated LocalAlloc string on success.
    unsafe {
        ConvertSidToStringSidW(current_user.sid, &raw mut sid_text)
            .map_err(|_| WindowsPlatformError::UnauthorizedLocalIpc)?;
    }
    if sid_text.is_null() {
        return Err(WindowsPlatformError::UnauthorizedLocalIpc);
    }
    let sid_text = LocalWideString(sid_text);
    // SAFETY: ConvertSidToStringSidW returned a live NUL-terminated string
    // retained by sid_text until after this copy.
    let value = unsafe { sid_text.0.to_string() }
        .map_err(|_| WindowsPlatformError::UnauthorizedLocalIpc)?;
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
    if token.is_invalid() {
        return Err(WindowsPlatformError::UnauthorizedLocalIpc);
    }
    Ok(OwnedHandle(token))
}

fn read_token_user(token: HANDLE) -> Result<TokenUserBuffer, WindowsPlatformError> {
    let mut reported_required = 0_u32;
    // SAFETY: this documented sizing query passes no destination buffer and a
    // live size output. Failure is expected; a nonzero required size is used.
    let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &raw mut reported_required) };
    let required = usize::try_from(reported_required)
        .map_err(|_| WindowsPlatformError::UnauthorizedLocalIpc)?;
    if required < size_of::<TOKEN_USER>() || required > 64 * 1024 {
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

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: this guard uniquely owns a non-pseudo HANDLE returned by
        // OpenProcess or OpenProcessToken.
        let _ = unsafe { CloseHandle(self.0) };
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
    Button {
        number: u8,
        released: bool,
    },
    Scroll {
        horizontal: i32,
        vertical: i32,
    },
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

pub(super) fn enumerate_displays() -> Result<Vec<DisplayGeometry>, WindowsPlatformError> {
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
    displays: Vec<DisplayGeometry>,
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

unsafe fn describe_monitor(monitor: HMONITOR) -> Result<DisplayGeometry, WindowsPlatformError> {
    let mut info = MONITORINFO {
        cbSize: u32::try_from(size_of::<MONITORINFO>())
            .map_err(|_| WindowsPlatformError::NativeApi)?,
        ..Default::default()
    };
    // SAFETY: `info` has the required cbSize and remains writable for the call.
    if !unsafe { GetMonitorInfoW(monitor, &raw mut info) }.as_bool() {
        return Err(WindowsPlatformError::NativeApi);
    }
    let width = u32::try_from(info.rcMonitor.right - info.rcMonitor.left)
        .map_err(|_| WindowsPlatformError::InvalidDisplay)?;
    let height = u32::try_from(info.rcMonitor.bottom - info.rcMonitor.top)
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
    Ok(DisplayGeometry {
        id: DisplayId::new(monitor.0.addr() as u64),
        left: info.rcMonitor.left,
        top: info.rcMonitor.top,
        width_pixels: width,
        height_pixels: height,
        dpi_x,
        dpi_y,
        primary: info.dwFlags & MONITORINFOF_PRIMARY != 0,
    })
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
    let before = clipboard_sequence_number()?;
    let clipboard = ClipboardGuard::open()?;
    let mut formats = Vec::with_capacity(3);
    for format in [
        ClipboardFormat::UnicodeText,
        ClipboardFormat::Dib,
        ClipboardFormat::DibV5,
    ] {
        let native = native_format(format);
        // SAFETY: querying format availability does not return a pointer or
        // transfer ownership; the clipboard is open on this thread.
        if unsafe { IsClipboardFormatAvailable(native) }.is_ok() {
            let size = clipboard_block_size(native)?;
            validate_clipboard_size(format, size)?;
            formats.push(ClipboardFormatMetadata {
                format,
                byte_len: u64::try_from(size)
                    .map_err(|_| WindowsPlatformError::ClipboardTooLarge)?,
            });
        }
    }
    drop(clipboard);
    let after = clipboard_sequence_number()?;
    if before != after {
        return Err(WindowsPlatformError::ClipboardBusy);
    }
    Ok(ClipboardMetadata {
        sequence_number: before,
        formats,
    })
}

pub(super) fn read_clipboard_text(
    expected_sequence: u32,
    max_bytes: u64,
) -> Result<String, WindowsPlatformError> {
    ensure_sequence(expected_sequence)?;
    let clipboard = ClipboardGuard::open()?;
    let bytes = copy_clipboard_block(CF_UNICODETEXT, max_bytes)?;
    if bytes.len() < 2 || bytes.len() % 2 != 0 {
        return Err(WindowsPlatformError::InvalidClipboardText);
    }
    let mut units = Vec::with_capacity(bytes.len() / 2);
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
    let units: Vec<u16> = text.encode_utf16().chain([0]).collect();
    let byte_len = units
        .len()
        .checked_mul(size_of::<u16>())
        .ok_or(WindowsPlatformError::ClipboardTooLarge)?;
    if u64::try_from(byte_len).map_err(|_| WindowsPlatformError::ClipboardTooLarge)? > max_bytes {
        return Err(WindowsPlatformError::ClipboardTooLarge);
    }
    let bytes = units
        .iter()
        .flat_map(|unit| unit.to_le_bytes())
        .collect::<Vec<_>>();
    replace_clipboard_block(CF_UNICODETEXT, &bytes)?;
    clipboard_sequence_number()
}

pub(super) fn read_clipboard_image(
    format: ClipboardFormat,
    expected_sequence: u32,
    max_bytes: u64,
) -> Result<Vec<u8>, WindowsPlatformError> {
    ensure_sequence(expected_sequence)?;
    let clipboard = ClipboardGuard::open()?;
    let bytes = copy_clipboard_block(native_format(format), max_bytes)?;
    validate_dib(format, &bytes)?;
    drop(clipboard);
    ensure_sequence(expected_sequence)?;
    Ok(bytes)
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
    replace_clipboard_block(native_format(format), dib)?;
    clipboard_sequence_number()
}

fn ensure_sequence(expected: u32) -> Result<(), WindowsPlatformError> {
    if clipboard_sequence_number()? == expected {
        Ok(())
    } else {
        Err(WindowsPlatformError::ClipboardBusy)
    }
}

fn native_format(format: ClipboardFormat) -> u32 {
    match format {
        ClipboardFormat::UnicodeText => CF_UNICODETEXT,
        ClipboardFormat::Dib => CF_DIB,
        ClipboardFormat::DibV5 => CF_DIBV5,
    }
}

fn validate_clipboard_size(
    format: ClipboardFormat,
    size: usize,
) -> Result<(), WindowsPlatformError> {
    let maximum = match format {
        ClipboardFormat::UnicodeText => MAX_TEXT_BYTES,
        ClipboardFormat::Dib | ClipboardFormat::DibV5 => MAX_IMAGE_BYTES,
    };
    if size == 0
        || u64::try_from(size).map_err(|_| WindowsPlatformError::ClipboardTooLarge)? > maximum
    {
        return Err(WindowsPlatformError::ClipboardTooLarge);
    }
    Ok(())
}

fn clipboard_block_size(format: u32) -> Result<usize, WindowsPlatformError> {
    // SAFETY: the clipboard is open on this thread and the returned handle is
    // borrowed from the clipboard; ownership remains with Windows.
    let handle = unsafe { GetClipboardData(format) }
        .map_err(|_| WindowsPlatformError::ClipboardFormatUnavailable)?;
    // SAFETY: clipboard global-memory formats return an HGLOBAL-compatible
    // handle which remains valid while the clipboard is open.
    let size = unsafe { GlobalSize(HGLOBAL(handle.0)) };
    if size == 0 {
        Err(WindowsPlatformError::ClipboardFormatUnavailable)
    } else {
        Ok(size)
    }
}

fn copy_clipboard_block(format: u32, maximum: u64) -> Result<Vec<u8>, WindowsPlatformError> {
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
    let bytes = unsafe { std::slice::from_raw_parts(address.cast::<u8>(), size) }.to_vec();
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
        let handle = unsafe { GlobalAlloc(GMEM_MOVEABLE, bytes.len()) }
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
