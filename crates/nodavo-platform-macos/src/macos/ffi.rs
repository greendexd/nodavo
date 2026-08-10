//! The only direct native FFI boundary in this crate.

use std::ffi::c_void;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr::{self, NonNull};

use core_foundation::base::{CFGetTypeID, CFRelease, CFTypeRef, TCFType, ToVoid};
use core_foundation::boolean::CFBoolean;
use core_foundation::data::CFData;
use core_foundation::dictionary::CFMutableDictionary;
use core_foundation::string::CFString;
use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework_sys::base::{
    errSecAuthFailed, errSecDuplicateItem, errSecItemNotFound, errSecSuccess,
};
use security_framework_sys::item::{
    kSecAttrAccessControl, kSecAttrAccount, kSecAttrService, kSecAttrSynchronizable, kSecClass,
    kSecClassGenericPassword, kSecReturnData, kSecUseDataProtectionKeychain, kSecValueData,
};
use security_framework_sys::keychain_item::{
    SecItemAdd, SecItemCopyMatching, SecItemDelete, SecItemUpdate,
};

use crate::clipboard::{
    MacClipboardError, NativeClipboardRepresentation, NativeClipboardSnapshot, PasteboardTarget,
};
use crate::keychain::{KeychainError, MAX_KEYCHAIN_SECRET_BYTES, StoreDisposition};
use nodavo_clipboard::{
    MAX_HTML_BYTES, MAX_IMAGE_BYTES, MAX_TEXT_BYTES, NativeClipboardRevision, RepresentationKind,
};

const ERR_SEC_NOT_AVAILABLE: i32 = -25_291;
const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25_308;

const PASTEBOARD_OK: i32 = 0;
const PASTEBOARD_UNAVAILABLE: i32 = 1;
const PASTEBOARD_INVALID_REVISION: i32 = 2;
const PASTEBOARD_READ_REJECTED: i32 = 3;
const PASTEBOARD_TOO_LARGE: i32 = 4;
const PASTEBOARD_WRITE_REJECTED: i32 = 5;
const PASTEBOARD_EXCEPTION: i32 = 6;
const PASTEBOARD_CHANGED: i32 = 7;
const PASTEBOARD_INVALID_KIND: i32 = 8;

const PASTEBOARD_UTF8_TEXT: u8 = 1;
const PASTEBOARD_HTML: u8 = 2;
const PASTEBOARD_PNG: u8 = 3;

#[repr(C)]
struct RawPasteboardSnapshot {
    change_count: i64,
    types_empty: u8,
    utf8_text: *const c_void,
    html: *const c_void,
    png: *const c_void,
}

impl RawPasteboardSnapshot {
    const fn empty() -> Self {
        Self {
            change_count: 0,
            types_empty: 0,
            utf8_text: ptr::null(),
            html: ptr::null(),
            png: ptr::null(),
        }
    }
}

impl Drop for RawPasteboardSnapshot {
    fn drop(&mut self) {
        release_if_present(self.utf8_text);
        release_if_present(self.html);
        release_if_present(self.png);
    }
}

unsafe extern "C" {
    fn ndv_pasteboard_copy_snapshot(
        nullable_name: *const c_void,
        max_text: usize,
        max_html: usize,
        max_png: usize,
        out_snapshot: *mut RawPasteboardSnapshot,
    ) -> i32;
    fn ndv_pasteboard_write(
        nullable_name: *const c_void,
        kind: u8,
        bytes: *const u8,
        length: usize,
        out_change_count: *mut i64,
    ) -> i32;
    fn ndv_pasteboard_clear(nullable_name: *const c_void, out_change_count: *mut i64) -> i32;
    fn ndv_pasteboard_change_count(nullable_name: *const c_void, out_change_count: *mut i64)
    -> i32;
    #[cfg(test)]
    fn ndv_pasteboard_release_named(name: *const c_void);
}

pub(crate) fn clipboard_snapshot(
    target: &PasteboardTarget,
) -> Result<NativeClipboardSnapshot, MacClipboardError> {
    let name = target_name(target);
    let mut raw = RawPasteboardSnapshot::empty();
    let max_text =
        usize::try_from(MAX_TEXT_BYTES).map_err(|_| MacClipboardError::RepresentationTooLarge)?;
    let max_html =
        usize::try_from(MAX_HTML_BYTES).map_err(|_| MacClipboardError::RepresentationTooLarge)?;
    let max_png =
        usize::try_from(MAX_IMAGE_BYTES).map_err(|_| MacClipboardError::RepresentationTooLarge)?;

    // SAFETY: The optional CFString is retained by `name` for the whole call;
    // all size arguments are strict Rust-side bounds; `raw` is initialized and
    // exclusively borrowed. The Objective-C shim catches exceptions and gives
    // Rust one Copy-rule CFData reference for each non-null output.
    let status = unsafe {
        ndv_pasteboard_copy_snapshot(
            name.as_ref()
                .map_or(ptr::null(), |name| name.as_concrete_TypeRef().cast()),
            max_text,
            max_html,
            max_png,
            &raw mut raw,
        )
    };
    pasteboard_status(status)?;
    let revision = revision(raw.change_count)?;
    if !matches!(raw.types_empty, 0 | 1) {
        return Err(MacClipboardError::ReadRejected);
    }

    let mut representations = Vec::with_capacity(3);
    take_pasteboard_data(
        &mut raw.utf8_text,
        RepresentationKind::Utf8Text,
        max_text,
        &mut representations,
    )?;
    take_pasteboard_data(
        &mut raw.html,
        RepresentationKind::Html,
        max_html,
        &mut representations,
    )?;
    take_pasteboard_data(
        &mut raw.png,
        RepresentationKind::Png,
        max_png,
        &mut representations,
    )?;
    Ok(NativeClipboardSnapshot {
        revision,
        native_types_empty: raw.types_empty == 1,
        representations,
    })
}

pub(crate) fn clipboard_write(
    target: &PasteboardTarget,
    kind: RepresentationKind,
    bytes: &[u8],
) -> Result<NativeClipboardRevision, MacClipboardError> {
    let kind = pasteboard_kind(kind)?;
    let name = target_name(target);
    let mut change_count = 0_i64;
    let bytes_pointer = if bytes.is_empty() {
        ptr::null()
    } else {
        bytes.as_ptr()
    };
    // SAFETY: The optional CFString and byte slice remain live and immutable
    // for the call, the pointer is non-null whenever length is non-zero, and
    // the initialized counter is exclusively borrowed. The shim copies bytes
    // into an owned NSData before returning and catches native exceptions.
    let status = unsafe {
        ndv_pasteboard_write(
            name.as_ref()
                .map_or(ptr::null(), |name| name.as_concrete_TypeRef().cast()),
            kind,
            bytes_pointer,
            bytes.len(),
            &raw mut change_count,
        )
    };
    pasteboard_status(status)?;
    revision(change_count)
}

pub(crate) fn clipboard_clear(
    target: &PasteboardTarget,
) -> Result<NativeClipboardRevision, MacClipboardError> {
    let name = target_name(target);
    let mut change_count = 0_i64;
    // SAFETY: The optional CFString is retained across the call, and the
    // initialized output is exclusively borrowed. The shim catches native
    // exceptions and never returns a native object.
    let status = unsafe {
        ndv_pasteboard_clear(
            name.as_ref()
                .map_or(ptr::null(), |name| name.as_concrete_TypeRef().cast()),
            &raw mut change_count,
        )
    };
    pasteboard_status(status)?;
    revision(change_count)
}

pub(crate) fn clipboard_change_count(
    target: &PasteboardTarget,
) -> Result<NativeClipboardRevision, MacClipboardError> {
    let name = target_name(target);
    let mut change_count = 0_i64;
    // SAFETY: The optional CFString is retained across the call, and the
    // initialized output is exclusively borrowed. The shim catches native
    // exceptions and validates the signed native counter before returning.
    let status = unsafe {
        ndv_pasteboard_change_count(
            name.as_ref()
                .map_or(ptr::null(), |name| name.as_concrete_TypeRef().cast()),
            &raw mut change_count,
        )
    };
    pasteboard_status(status)?;
    revision(change_count)
}

#[cfg(test)]
pub(crate) fn clipboard_release_named(target: &PasteboardTarget) {
    let PasteboardTarget::Named(name) = target else {
        return;
    };
    let name = CFString::from(name.as_str());
    // SAFETY: `name` owns a valid CFString/NSString toll-free bridge through
    // the whole call. The shim catches exceptions and retains no reference.
    unsafe { ndv_pasteboard_release_named(name.as_concrete_TypeRef().cast()) };
}

fn target_name(target: &PasteboardTarget) -> Option<CFString> {
    match target {
        PasteboardTarget::General => None,
        #[cfg(test)]
        PasteboardTarget::Named(name) => Some(CFString::from(name.as_str())),
    }
}

fn take_pasteboard_data(
    raw: &mut *const c_void,
    kind: RepresentationKind,
    maximum: usize,
    output: &mut Vec<NativeClipboardRepresentation>,
) -> Result<(), MacClipboardError> {
    if raw.is_null() {
        return Ok(());
    }
    let value = *raw;
    *raw = ptr::null();

    // SAFETY: The shim returned one owned CF reference. We dynamically verify
    // its type before constructing CFData; on mismatch we release the owned
    // reference ourselves. The CFData wrapper then releases it exactly once.
    let data = unsafe {
        if CFGetTypeID(value.cast()) != CFData::type_id() {
            CFRelease(value.cast());
            return Err(MacClipboardError::ReadRejected);
        }
        CFData::wrap_under_create_rule(value.cast_mut().cast())
    };
    let length = usize::try_from(data.len()).map_err(|_| MacClipboardError::ReadRejected)?;
    if length > maximum {
        return Err(MacClipboardError::RepresentationTooLarge);
    }
    output.push(NativeClipboardRepresentation {
        kind,
        bytes: data.bytes().to_vec(),
    });
    Ok(())
}

fn release_if_present(value: *const c_void) {
    if !value.is_null() {
        // SAFETY: Raw snapshot fields are either null or one owned Copy-rule
        // CF reference returned by the shim and not yet transferred to CFData.
        unsafe { CFRelease(value.cast()) };
    }
}

fn pasteboard_kind(kind: RepresentationKind) -> Result<u8, MacClipboardError> {
    match kind {
        RepresentationKind::Utf8Text => Ok(PASTEBOARD_UTF8_TEXT),
        RepresentationKind::Html => Ok(PASTEBOARD_HTML),
        RepresentationKind::Png => Ok(PASTEBOARD_PNG),
        RepresentationKind::Bmp | RepresentationKind::FileList => {
            Err(MacClipboardError::UnsupportedRepresentation)
        }
    }
}

fn revision(value: i64) -> Result<NativeClipboardRevision, MacClipboardError> {
    u64::try_from(value)
        .map(NativeClipboardRevision::new)
        .map_err(|_| MacClipboardError::InvalidRevision)
}

fn pasteboard_status(status: i32) -> Result<(), MacClipboardError> {
    match status {
        PASTEBOARD_OK => Ok(()),
        PASTEBOARD_UNAVAILABLE => Err(MacClipboardError::Unavailable),
        PASTEBOARD_INVALID_REVISION => Err(MacClipboardError::InvalidRevision),
        PASTEBOARD_READ_REJECTED => Err(MacClipboardError::ReadRejected),
        PASTEBOARD_TOO_LARGE => Err(MacClipboardError::RepresentationTooLarge),
        PASTEBOARD_WRITE_REJECTED => Err(MacClipboardError::WriteRejected),
        PASTEBOARD_EXCEPTION => Err(MacClipboardError::NativeException),
        PASTEBOARD_CHANGED => Err(MacClipboardError::ChangedDuringRead),
        PASTEBOARD_INVALID_KIND => Err(MacClipboardError::UnsupportedRepresentation),
        other => Err(MacClipboardError::NativeStatus(other)),
    }
}

pub(crate) fn keychain_store(
    service: &str,
    account: &str,
    secret: &[u8],
) -> Result<StoreDisposition, KeychainError> {
    let search = query(service, account);
    let data = CFData::from_buffer(secret);
    let mut add = query(service, account);
    let access_control = SecAccessControl::create_with_protection(
        Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
        0,
    )
    .map_err(|error| map_status(error.code()))?;

    // SAFETY: Every pointer is a process-lifetime Security.framework or
    // CoreFoundation singleton, or is retained by `add`. The service/account
    // and secret lengths were bounded by the safe caller before this module.
    unsafe {
        add.add(&kSecValueData.to_void(), &data.to_void());
        add.add(&kSecAttrAccessControl.to_void(), &access_control.to_void());
    }

    // SAFETY: `add` is a valid retained CFDictionary for the duration of the
    // call, and no result object is requested.
    let status = unsafe { SecItemAdd(add.as_concrete_TypeRef(), ptr::null_mut()) };
    if status == errSecSuccess {
        return Ok(StoreDisposition::Created);
    }
    if status != errSecDuplicateItem {
        return Err(map_status(status));
    }

    let mut replacement = CFMutableDictionary::from_CFType_pairs(&[]);
    // SAFETY: `data` is live through `SecItemUpdate`, and the dictionary
    // retains it. Updating `kSecValueData` is Security.framework's atomic item
    // replacement operation. Reapplying the access control preserves the
    // ThisDeviceOnly policy even if another same-access-group process created
    // the namespaced item first.
    unsafe {
        replacement.add(&kSecValueData.to_void(), &data.to_void());
        replacement.add(&kSecAttrAccessControl.to_void(), &access_control.to_void());
    }
    // SAFETY: Both dictionaries are valid and retained through the call.
    let status = unsafe {
        SecItemUpdate(
            search.as_concrete_TypeRef(),
            replacement.as_concrete_TypeRef(),
        )
    };
    status_result(status)?;
    Ok(StoreDisposition::Updated)
}

pub(crate) fn keychain_load(service: &str, account: &str) -> Result<Vec<u8>, KeychainError> {
    let mut query = query(service, account);
    // SAFETY: The key is a process-lifetime Security.framework singleton and
    // the true value is retained by the query dictionary.
    unsafe {
        query.add(
            &kSecReturnData.to_void(),
            &CFBoolean::true_value().to_void(),
        );
    }

    let mut result: CFTypeRef = ptr::null();
    // SAFETY: `query` is valid for the call and `result` is an initialized
    // out-pointer. On success, the Copy rule transfers one owned reference.
    let status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &raw mut result) };
    status_result(status)?;
    if result.is_null() {
        return Err(KeychainError::MalformedItem);
    }

    // SAFETY: A successful SecItemCopyMatching returned an owned CF object.
    // We check its dynamic type before wrapping it as CFData; the wrapper then
    // releases exactly that Copy-rule reference on drop.
    let data = unsafe {
        if CFGetTypeID(result) != CFData::type_id() {
            CFRelease(result);
            return Err(KeychainError::MalformedItem);
        }
        CFData::wrap_under_create_rule(result.cast_mut().cast())
    };
    let length = usize::try_from(data.len()).map_err(|_| KeychainError::MalformedItem)?;
    if length == 0 || length > MAX_KEYCHAIN_SECRET_BYTES {
        return Err(KeychainError::MalformedItem);
    }

    // The system-owned CFData allocation necessarily exists at this point,
    // but no Rust secret buffer is allocated until after the strict bound and
    // type checks above.
    Ok(data.bytes().to_vec())
}

pub(crate) fn keychain_delete(service: &str, account: &str) -> Result<(), KeychainError> {
    let query = query(service, account);
    // SAFETY: `query` is a valid retained CFDictionary for the duration of the
    // call and contains no unbounded or caller-owned native pointers.
    let status = unsafe { SecItemDelete(query.as_concrete_TypeRef()) };
    status_result(status)
}

fn query(service: &str, account: &str) -> CFMutableDictionary {
    let service = CFString::from(service);
    let account = CFString::from(account);
    let mut query = CFMutableDictionary::from_CFType_pairs(&[]);

    // SAFETY: The `kSec*` pointers are non-null process-lifetime constants from
    // the linked Security.framework. CFDictionary retains all inserted values.
    // Selecting the Data Protection Keychain is what makes the accessibility
    // class effective on macOS without enabling synchronization.
    unsafe {
        query.add(&kSecClass.to_void(), &kSecClassGenericPassword.to_void());
        query.add(&kSecAttrService.to_void(), &service.to_void());
        query.add(&kSecAttrAccount.to_void(), &account.to_void());
        query.add(
            &kSecAttrSynchronizable.to_void(),
            &CFBoolean::false_value().to_void(),
        );
        query.add(
            &kSecUseDataProtectionKeychain.to_void(),
            &CFBoolean::true_value().to_void(),
        );
    }
    query
}

fn status_result(status: i32) -> Result<(), KeychainError> {
    if status == errSecSuccess {
        Ok(())
    } else {
        Err(map_status(status))
    }
}

fn map_status(status: i32) -> KeychainError {
    match status {
        value if value == errSecItemNotFound => KeychainError::NotFound,
        value if value == errSecAuthFailed => KeychainError::AuthenticationFailed,
        ERR_SEC_INTERACTION_NOT_ALLOWED => KeychainError::InteractionNotAllowed,
        ERR_SEC_NOT_AVAILABLE => KeychainError::Unavailable,
        -34_018 => KeychainError::MissingEntitlement,
        other => KeychainError::SecurityFramework(other),
    }
}

const INPUT_KEYBOARD: u32 = 1;
const INPUT_CONSUMER: u32 = 2;
const INPUT_POINTER_MOTION: u32 = 3;
const INPUT_POINTER_BUTTON: u32 = 4;
const INPUT_SCROLL: u32 = 5;
const INPUT_LIFECYCLE: u32 = 6;

const CALLBACK_KEEP: i32 = 0;
const CALLBACK_SUPPRESS: i32 = 1;
const CALLBACK_ABORT: i32 = 2;

const CAPTURE_STOP_REQUESTED: i32 = 0;
const CAPTURE_TAP_DISABLED_BY_TIMEOUT: i32 = 1;
const CAPTURE_TAP_DISABLED_BY_USER_INPUT: i32 = 2;
const CAPTURE_CALLBACK_FAILED: i32 = 3;

#[repr(C)]
struct RawInputEvent {
    kind: u32,
    code: u32,
    value1: i64,
    value2: i64,
    flags: u64,
    x: f64,
    y: f64,
}

type RawInputCallback = unsafe extern "C" fn(*mut c_void, *const RawInputEvent) -> i32;

unsafe extern "C" {
    fn ndv_input_capture_create(
        callback: RawInputCallback,
        callback_context: *mut c_void,
    ) -> *mut c_void;
    fn ndv_input_capture_create_stop_handle(capture: *mut c_void) -> *mut c_void;
    fn ndv_input_capture_stop(stop_handle: *mut c_void);
    fn ndv_input_capture_run(capture: *mut c_void) -> i32;
    fn ndv_input_capture_release(capture: *mut c_void);
    fn ndv_input_capture_release_stop_handle(stop_handle: *mut c_void);
    fn ndv_post_media_key(usage: u16, pressed: bool, tag: i64) -> bool;
}

#[derive(Clone, Copy)]
pub(crate) enum NativeInputEvent {
    Keyboard {
        keycode: u16,
        pressed: bool,
        modifier_bits: u16,
    },
    Consumer {
        usage: u16,
        pressed: bool,
        modifier_bits: u16,
    },
    PointerMotion {
        x: f64,
        y: f64,
        delta_x: i32,
        delta_y: i32,
    },
    PointerButton {
        button: u8,
        pressed: bool,
    },
    Scroll {
        horizontal: i32,
        vertical: i32,
        precise: bool,
    },
    Lifecycle(NativeLifecycleEvent),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeLifecycleEvent {
    SystemWillSleep,
    SystemDidWake,
    ScreensDidSleep,
    ScreensDidWake,
    SessionDidResignActive,
    SessionDidBecomeActive,
    TapDisabledByTimeout,
    TapDisabledByUserInput,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeCaptureDisposition {
    Keep,
    Suppress,
    Abort,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeCaptureExit {
    StopRequested,
    TapDisabledByTimeout,
    TapDisabledByUserInput,
    CallbackFailed,
    NativeFailure,
}

struct InputCallbackContext {
    callback: Box<dyn Fn(NativeInputEvent) -> NativeCaptureDisposition + Send + Sync>,
}

pub(crate) struct NativeInputCapture {
    raw: NonNull<c_void>,
    _callback: Box<InputCallbackContext>,
}

impl NativeInputCapture {
    pub(crate) fn new(
        callback: impl Fn(NativeInputEvent) -> NativeCaptureDisposition + Send + Sync + 'static,
    ) -> Result<Self, ()> {
        let mut callback = Box::new(InputCallbackContext {
            callback: Box::new(callback),
        });
        // SAFETY: `callback` remains pinned by its Box for the entire native
        // capture lifetime. The native shim does not retain the context after
        // `ndv_input_capture_release`, and it validates Accessibility before
        // installing the event tap.
        let raw = unsafe {
            ndv_input_capture_create(
                input_callback,
                (&raw mut *callback).cast::<InputCallbackContext>().cast(),
            )
        };
        let raw = NonNull::new(raw).ok_or(())?;
        Ok(Self {
            raw,
            _callback: callback,
        })
    }

    pub(crate) fn stop_handle(&self) -> Result<NativeInputCaptureStopHandle, ()> {
        // SAFETY: `self.raw` points to a live native capture. The native call
        // returns an independently reference-counted control block which is
        // safe to signal from another thread.
        let raw = unsafe { ndv_input_capture_create_stop_handle(self.raw.as_ptr()) };
        NonNull::new(raw)
            .map(|raw| NativeInputCaptureStopHandle { raw })
            .ok_or(())
    }

    pub(crate) fn run(&self) -> NativeCaptureExit {
        // SAFETY: The capture and boxed callback remain live for the complete
        // blocking run. The Objective-C shim disables the tap before return.
        match unsafe { ndv_input_capture_run(self.raw.as_ptr()) } {
            CAPTURE_STOP_REQUESTED => NativeCaptureExit::StopRequested,
            CAPTURE_TAP_DISABLED_BY_TIMEOUT => NativeCaptureExit::TapDisabledByTimeout,
            CAPTURE_TAP_DISABLED_BY_USER_INPUT => NativeCaptureExit::TapDisabledByUserInput,
            CAPTURE_CALLBACK_FAILED => NativeCaptureExit::CallbackFailed,
            _ => NativeCaptureExit::NativeFailure,
        }
    }
}

impl Drop for NativeInputCapture {
    fn drop(&mut self) {
        // SAFETY: `raw` is the one owned capture pointer returned by create.
        // The native release synchronously disables/removes the tap and drops
        // its borrow of `_callback` before Rust frees that Box.
        unsafe { ndv_input_capture_release(self.raw.as_ptr()) };
    }
}

pub(crate) struct NativeInputCaptureStopHandle {
    raw: NonNull<c_void>,
}

// SAFETY: The stop handle owns only a reference-counted native control block.
// Its operation is limited to atomic state plus documented thread-safe
// CFRunLoopStop/CFRunLoopWakeUp calls; it never dereferences Rust callback data.
unsafe impl Send for NativeInputCaptureStopHandle {}
// SAFETY: See the Send invariant above. Concurrent stop calls are idempotent.
unsafe impl Sync for NativeInputCaptureStopHandle {}

impl NativeInputCaptureStopHandle {
    pub(crate) fn stop(&self) {
        // SAFETY: `raw` remains retained until this handle's Drop completes;
        // the native stop operation is idempotent and accepts any thread.
        unsafe { ndv_input_capture_stop(self.raw.as_ptr()) };
    }
}

impl Drop for NativeInputCaptureStopHandle {
    fn drop(&mut self) {
        // SAFETY: This releases exactly the native control-block reference
        // acquired for this stop handle and does not access callback state.
        unsafe { ndv_input_capture_release_stop_handle(self.raw.as_ptr()) };
    }
}

pub(crate) fn post_media_key(usage: u16, pressed: bool, tag: i64) -> Result<(), ()> {
    // SAFETY: All arguments are bounded scalar values. The native shim accepts
    // only its explicit consumer-key allowlist and retains no Rust pointers.
    if unsafe { ndv_post_media_key(usage, pressed, tag) } {
        Ok(())
    } else {
        Err(())
    }
}

unsafe extern "C" fn input_callback(context: *mut c_void, raw_event: *const RawInputEvent) -> i32 {
    if context.is_null() || raw_event.is_null() {
        return CALLBACK_ABORT;
    }
    // SAFETY: The native capture calls back only while the Box supplied at
    // creation is live, and passes a pointer to an initialized event value for
    // the duration of this call. The callback never retains either pointer.
    let (context, raw_event) = unsafe { (&*context.cast::<InputCallbackContext>(), &*raw_event) };
    let Some(event) = decode_input_event(raw_event) else {
        return CALLBACK_KEEP;
    };
    match catch_unwind(AssertUnwindSafe(|| (context.callback)(event))) {
        Ok(NativeCaptureDisposition::Keep) => CALLBACK_KEEP,
        Ok(NativeCaptureDisposition::Suppress) => CALLBACK_SUPPRESS,
        Ok(NativeCaptureDisposition::Abort) | Err(_) => CALLBACK_ABORT,
    }
}

fn decode_input_event(raw: &RawInputEvent) -> Option<NativeInputEvent> {
    match raw.kind {
        INPUT_KEYBOARD => Some(NativeInputEvent::Keyboard {
            keycode: u16::try_from(raw.code).ok()?,
            pressed: decode_pressed(raw.value1)?,
            modifier_bits: u16::try_from(raw.flags).ok()?,
        }),
        INPUT_CONSUMER => Some(NativeInputEvent::Consumer {
            usage: u16::try_from(raw.code).ok()?,
            pressed: decode_pressed(raw.value1)?,
            modifier_bits: u16::try_from(raw.flags).ok()?,
        }),
        INPUT_POINTER_MOTION if raw.x.is_finite() && raw.y.is_finite() => {
            Some(NativeInputEvent::PointerMotion {
                x: raw.x,
                y: raw.y,
                delta_x: i32::try_from(raw.value1).ok()?,
                delta_y: i32::try_from(raw.value2).ok()?,
            })
        }
        INPUT_POINTER_BUTTON => Some(NativeInputEvent::PointerButton {
            button: u8::try_from(raw.code).ok()?,
            pressed: decode_pressed(raw.value1)?,
        }),
        INPUT_SCROLL => Some(NativeInputEvent::Scroll {
            horizontal: i32::try_from(raw.value1).ok()?,
            vertical: i32::try_from(raw.value2).ok()?,
            precise: match raw.code {
                0 => false,
                1 => true,
                _ => return None,
            },
        }),
        INPUT_LIFECYCLE => Some(NativeInputEvent::Lifecycle(match raw.code {
            1 => NativeLifecycleEvent::SystemWillSleep,
            2 => NativeLifecycleEvent::SystemDidWake,
            3 => NativeLifecycleEvent::ScreensDidSleep,
            4 => NativeLifecycleEvent::ScreensDidWake,
            5 => NativeLifecycleEvent::SessionDidResignActive,
            6 => NativeLifecycleEvent::SessionDidBecomeActive,
            7 => NativeLifecycleEvent::TapDisabledByTimeout,
            8 => NativeLifecycleEvent::TapDisabledByUserInput,
            _ => return None,
        })),
        _ => None,
    }
}

fn decode_pressed(value: i64) -> Option<bool> {
    match value {
        0 => Some(false),
        1 => Some(true),
        _ => None,
    }
}

#[cfg(test)]
mod input_tests {
    use super::*;

    fn raw(kind: u32) -> RawInputEvent {
        RawInputEvent {
            kind,
            code: 0,
            value1: 0,
            value2: 0,
            flags: 0,
            x: 0.0,
            y: 0.0,
        }
    }

    #[test]
    fn raw_input_decoder_rejects_unbounded_or_malformed_scalars() {
        let mut button = raw(INPUT_POINTER_BUTTON);
        button.code = u32::from(u8::MAX) + 1;
        assert!(decode_input_event(&button).is_none());

        let mut key = raw(INPUT_KEYBOARD);
        key.value1 = 2;
        assert!(decode_input_event(&key).is_none());

        let mut scroll = raw(INPUT_SCROLL);
        scroll.code = 2;
        assert!(decode_input_event(&scroll).is_none());

        let mut motion = raw(INPUT_POINTER_MOTION);
        motion.x = f64::NAN;
        assert!(decode_input_event(&motion).is_none());

        let mut motion = raw(INPUT_POINTER_MOTION);
        motion.value1 = i64::from(i32::MAX) + 1;
        assert!(decode_input_event(&motion).is_none());
    }

    #[test]
    fn raw_input_decoder_distinguishes_precise_scroll_and_tap_timeout() {
        let mut scroll = raw(INPUT_SCROLL);
        scroll.code = 1;
        scroll.value1 = -5;
        scroll.value2 = 9;
        assert!(matches!(
            decode_input_event(&scroll),
            Some(NativeInputEvent::Scroll {
                horizontal: -5,
                vertical: 9,
                precise: true,
            })
        ));

        let mut lifecycle = raw(INPUT_LIFECYCLE);
        lifecycle.code = 7;
        assert!(matches!(
            decode_input_event(&lifecycle),
            Some(NativeInputEvent::Lifecycle(
                NativeLifecycleEvent::TapDisabledByTimeout
            ))
        ));
    }
}
