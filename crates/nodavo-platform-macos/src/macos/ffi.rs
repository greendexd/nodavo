//! The only direct native FFI boundary in this crate.

use std::ffi::{CString, c_char, c_void};
use std::fs::File;
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr::{self, NonNull};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, TrySendError, sync_channel};
use std::sync::{Mutex, OnceLock};

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

use core_graphics::display::{
    CGDirectDisplayID, CGDisplayRegisterReconfigurationCallback,
    CGDisplayRemoveReconfigurationCallback, CGGetActiveDisplayList,
};

use crate::clipboard::{
    MacClipboardError, NativeClipboardRepresentation, NativeClipboardSnapshot, PasteboardTarget,
};
use crate::keychain::{KeychainError, MAX_KEYCHAIN_SECRET_BYTES, StoreDisposition};
use crate::update::MacUpdateBundlePolicy;
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

const UPDATE_VERSION_CAPACITY: usize = 129;
const UPDATE_BUILD_CAPACITY: usize = 65;
const UPDATE_CDHASH_BYTES: usize = 20;
const UPDATE_TREE_HASH_BYTES: usize = 32;
const UPDATE_CRITICAL_HANDLES: usize = 6;
const UPDATE_OK: i32 = 0;
const UPDATE_LAYOUT_REJECTED: i32 = 2;
const UPDATE_IDENTITY_REJECTED: i32 = 3;
const UPDATE_SIGNATURE_REJECTED: i32 = 4;
const UPDATE_SYSTEM_POLICY_REJECTED: i32 = 9;

const AUDIT_TOKEN_WORDS: usize = 8;
#[cfg(any(not(feature = "development-unverified-local-ipc"), test))]
const SIGNING_IDENTIFIER_CAPACITY: usize = 128;
#[cfg(any(not(feature = "development-unverified-local-ipc"), test))]
const TEAM_IDENTIFIER_CAPACITY: usize = 32;
#[cfg(any(not(feature = "development-unverified-local-ipc"), test))]
const APPLICATION_IDENTIFIER_CAPACITY: usize = 192;

#[cfg(any(not(feature = "development-unverified-local-ipc"), test))]
pub(crate) const CODE_EVIDENCE_EXTERNAL_REQUIREMENT: u8 = 1 << 0;
#[cfg(any(not(feature = "development-unverified-local-ipc"), test))]
pub(crate) const CODE_EVIDENCE_DESIGNATED_REQUIREMENT: u8 = 1 << 1;
#[cfg(any(not(feature = "development-unverified-local-ipc"), test))]
pub(crate) const CODE_EVIDENCE_CERTIFICATE_CHAIN: u8 = 1 << 2;
#[cfg(any(not(feature = "development-unverified-local-ipc"), test))]
pub(crate) const CODE_EVIDENCE_CMS: u8 = 1 << 3;
#[cfg(any(not(feature = "development-unverified-local-ipc"), test))]
pub(crate) const CODE_EVIDENCE_GET_TASK_ALLOW: u8 = 1 << 4;

#[repr(C)]
struct RawAuditToken {
    words: [u32; AUDIT_TOKEN_WORDS],
}

#[repr(C)]
#[cfg(any(not(feature = "development-unverified-local-ipc"), test))]
struct RawCodeSignatureClaims {
    static_flags: u32,
    dynamic_status: u32,
    external_requirement_valid: u8,
    designated_requirement_valid: u8,
    certificate_chain_present: u8,
    cms_present: u8,
    get_task_allow: u8,
    signing_identifier: [c_char; SIGNING_IDENTIFIER_CAPACITY],
    team_identifier: [c_char; TEAM_IDENTIFIER_CAPACITY],
    secured_bundle_identifier: [c_char; SIGNING_IDENTIFIER_CAPACITY],
    application_identifier: [c_char; APPLICATION_IDENTIFIER_CAPACITY],
}

#[cfg(any(not(feature = "development-unverified-local-ipc"), test))]
impl RawCodeSignatureClaims {
    const fn empty() -> Self {
        Self {
            static_flags: 0,
            dynamic_status: 0,
            external_requirement_valid: 0,
            designated_requirement_valid: 0,
            certificate_chain_present: 0,
            cms_present: 0,
            get_task_allow: 0,
            signing_identifier: [0; SIGNING_IDENTIFIER_CAPACITY],
            team_identifier: [0; TEAM_IDENTIFIER_CAPACITY],
            secured_bundle_identifier: [0; SIGNING_IDENTIFIER_CAPACITY],
            application_identifier: [0; APPLICATION_IDENTIFIER_CAPACITY],
        }
    }
}

pub(crate) struct NativePeerToken {
    pub(crate) words: [u32; AUDIT_TOKEN_WORDS],
    pub(crate) effective_uid: u32,
}

#[cfg(any(not(feature = "development-unverified-local-ipc"), test))]
pub(crate) struct NativeCodeSignatureClaims {
    pub(crate) signing_identifier: Option<String>,
    pub(crate) team_identifier: Option<String>,
    pub(crate) secured_bundle_identifier: Option<String>,
    pub(crate) application_identifier: Option<String>,
    pub(crate) static_flags: u32,
    pub(crate) dynamic_status: u32,
    pub(crate) evidence: u8,
}

const XPC_EVENT_REQUEST: u32 = 1;
const XPC_EVENT_LISTENER_INVALID: u32 = 2;

type RawXpcEventCallback = unsafe extern "C" fn(*mut c_void, u32, *const u8, usize, *mut c_void);

pub(crate) enum NativeXpcEvent {
    Request {
        payload: Vec<u8>,
        reply: NativeXpcReply,
    },
    ListenerInvalid,
}

struct XpcCallbackContext {
    maximum_message_bytes: usize,
    callback: Box<dyn Fn(NativeXpcEvent) + Send + Sync>,
}

pub(crate) struct NativeXpcListener {
    raw: NonNull<c_void>,
    callback_context: NonNull<XpcCallbackContext>,
    // Prevent safe code from moving the listener into a callback-accessible
    // cross-thread owner and dropping it reentrantly while the trampoline is
    // borrowing the callback context.
    _not_send_or_sync: std::marker::PhantomData<Rc<()>>,
}

pub(crate) struct NativeXpcListenerLimits {
    pub(crate) maximum_message_bytes: usize,
    pub(crate) maximum_peers: usize,
    pub(crate) maximum_peer_outstanding: usize,
    pub(crate) maximum_global_outstanding: usize,
    pub(crate) reply_deadline_milliseconds: u64,
}

pub(crate) struct NativeXpcReply {
    raw: Option<NonNull<c_void>>,
}

// SAFETY: A native reply handle is consumed exactly once by send or drop. Both
// native operations enqueue completion onto the listener's serial queue.
unsafe impl Send for NativeXpcReply {}

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

#[repr(C)]
#[derive(Clone, Copy)]
struct RawUpdateIdentity {
    device: u64,
    inode: u64,
}

#[repr(C)]
struct RawUpdateBundleClaims {
    identity: RawUpdateIdentity,
    app_code_directory_hash: [u8; UPDATE_CDHASH_BYTES],
    agent_code_directory_hash: [u8; UPDATE_CDHASH_BYTES],
    tree_hash: [u8; UPDATE_TREE_HASH_BYTES],
    tree_generation_hash: [u8; UPDATE_TREE_HASH_BYTES],
    critical_fds: [i32; UPDATE_CRITICAL_HANDLES],
    require_effective_user_owner: u8,
    version: [c_char; UPDATE_VERSION_CAPACITY],
    build: [c_char; UPDATE_BUILD_CAPACITY],
}

pub(crate) struct NativeUpdateBundleClaims {
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) app_code_directory_hash: [u8; UPDATE_CDHASH_BYTES],
    pub(crate) agent_code_directory_hash: [u8; UPDATE_CDHASH_BYTES],
    pub(crate) proof: NativeUpdateTreeProof,
    pub(crate) version: String,
    pub(crate) build: String,
}

pub(crate) struct NativeUpdateTreeProof {
    tree_hash: [u8; UPDATE_TREE_HASH_BYTES],
    tree_generation_hash: [u8; UPDATE_TREE_HASH_BYTES],
    _critical_files: Vec<File>,
    require_effective_user_owner: bool,
}

impl NativeUpdateTreeProof {
    pub(crate) fn matches(&self, other: &Self) -> bool {
        self.tree_hash == other.tree_hash
            && self.tree_generation_hash == other.tree_generation_hash
            && self.require_effective_user_owner == other.require_effective_user_owner
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeUpdateValidationError {
    Entry,
    Layout,
    Identity,
    Signature,
    SystemPolicy,
}

unsafe extern "C" {
    fn ndv_update_open_directory(
        path_utf8: *const c_char,
        require_private: bool,
        out_fd: *mut i32,
        out_identity: *mut RawUpdateIdentity,
    ) -> i32;
    fn ndv_update_validate_nodavo_bundle(
        directory_fd: i32,
        leaf_utf8: *const c_char,
        team_identifier_utf8: *const c_char,
        version_utf8: *const c_char,
        build_utf8: *const c_char,
        app_requirement_utf8: *const c_char,
        agent_requirement_utf8: *const c_char,
        keychain_access_group_utf8: *const c_char,
        require_effective_user_owner: bool,
        out_claims: *mut RawUpdateBundleClaims,
    ) -> i32;
    #[cfg(test)]
    fn ndv_update_observe_sealed_tree(
        directory_fd: i32,
        leaf_utf8: *const c_char,
        require_effective_user_owner: bool,
        out_tree_hash: *mut u8,
        out_tree_generation_hash: *mut u8,
    ) -> i32;
    #[cfg(test)]
    fn ndv_update_test_code_hash_length(path_utf8: *const c_char, out_length: *mut usize) -> i32;
    fn ndv_xpc_listener_create(
        service_name: *const c_char,
        peer_requirement: *const c_char,
        maximum_message_bytes: usize,
        maximum_peers: usize,
        maximum_peer_outstanding: usize,
        maximum_global_outstanding: usize,
        reply_deadline_milliseconds: u64,
        callback: RawXpcEventCallback,
        callback_context: *mut c_void,
    ) -> *mut c_void;
    fn ndv_xpc_listener_activate(listener: *mut c_void) -> i32;
    fn ndv_xpc_listener_destroy(listener: *mut c_void);
    fn ndv_xpc_reply_send(
        reply: *mut c_void,
        bytes: *const u8,
        length: usize,
        maximum_message_bytes: usize,
    ) -> i32;
    fn ndv_xpc_reply_abandon(reply: *mut c_void);
    fn ndv_copy_local_peer_token(
        socket_fd: i32,
        out_token: *mut RawAuditToken,
        out_effective_uid: *mut u32,
    ) -> i32;
    #[cfg(any(not(feature = "development-unverified-local-ipc"), test))]
    fn ndv_copy_peer_code_signature_claims(
        token: *const RawAuditToken,
        requirement_utf8: *const c_char,
        out_claims: *mut RawCodeSignatureClaims,
    ) -> i32;
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

pub(crate) fn update_open_directory(path: &CString, require_private: bool) -> Result<File, ()> {
    let mut fd = -1_i32;
    let mut identity = RawUpdateIdentity {
        device: 0,
        inode: 0,
    };
    // SAFETY: The path is NUL-terminated and immutable, both outputs are
    // initialized and exclusively borrowed, and native code retains nothing.
    let status = unsafe {
        ndv_update_open_directory(
            path.as_ptr(),
            require_private,
            &raw mut fd,
            &raw mut identity,
        )
    };
    if status != UPDATE_OK || fd < 0 {
        return Err(());
    }
    // SAFETY: Successful native return transfers ownership of one fresh,
    // close-on-exec descriptor to this File.
    let file = unsafe { File::from_raw_fd(fd) };
    Ok(file)
}

pub(crate) fn update_validate_nodavo_bundle(
    directory: &File,
    leaf: &CString,
    policy: &MacUpdateBundlePolicy,
    require_effective_user_owner: bool,
) -> Result<NativeUpdateBundleClaims, NativeUpdateValidationError> {
    let team = CString::new(policy.team_identifier())
        .map_err(|_| NativeUpdateValidationError::Identity)?;
    let version =
        CString::new(policy.version()).map_err(|_| NativeUpdateValidationError::Identity)?;
    let build = CString::new(policy.build()).map_err(|_| NativeUpdateValidationError::Identity)?;
    let app_requirement = CString::new(policy.app_requirement())
        .map_err(|_| NativeUpdateValidationError::Identity)?;
    let agent_requirement = CString::new(policy.agent_requirement())
        .map_err(|_| NativeUpdateValidationError::Identity)?;
    let keychain_group = CString::new(policy.keychain_access_group())
        .map_err(|_| NativeUpdateValidationError::Identity)?;
    let mut claims = RawUpdateBundleClaims {
        identity: RawUpdateIdentity {
            device: 0,
            inode: 0,
        },
        app_code_directory_hash: [0; UPDATE_CDHASH_BYTES],
        agent_code_directory_hash: [0; UPDATE_CDHASH_BYTES],
        tree_hash: [0; UPDATE_TREE_HASH_BYTES],
        tree_generation_hash: [0; UPDATE_TREE_HASH_BYTES],
        critical_fds: [-1; UPDATE_CRITICAL_HANDLES],
        require_effective_user_owner: 0,
        version: [0; UPDATE_VERSION_CAPACITY],
        build: [0; UPDATE_BUILD_CAPACITY],
    };
    // SAFETY: All strings are immutable and NUL-terminated, the retained
    // directory descriptor remains live, and the initialized output is
    // exclusively borrowed for this synchronous call.
    let status = unsafe {
        ndv_update_validate_nodavo_bundle(
            directory.as_raw_fd(),
            leaf.as_ptr(),
            team.as_ptr(),
            version.as_ptr(),
            build.as_ptr(),
            app_requirement.as_ptr(),
            agent_requirement.as_ptr(),
            keychain_group.as_ptr(),
            require_effective_user_owner,
            &raw mut claims,
        )
    };
    match status {
        UPDATE_OK => {
            let critical_files = take_update_files(&mut claims.critical_fds)
                .map_err(|()| NativeUpdateValidationError::Entry)?;
            Ok(NativeUpdateBundleClaims {
                device: claims.identity.device,
                inode: claims.identity.inode,
                app_code_directory_hash: claims.app_code_directory_hash,
                agent_code_directory_hash: claims.agent_code_directory_hash,
                proof: NativeUpdateTreeProof {
                    tree_hash: claims.tree_hash,
                    tree_generation_hash: claims.tree_generation_hash,
                    _critical_files: critical_files,
                    require_effective_user_owner: claims.require_effective_user_owner != 0,
                },
                version: decode_required_update_string(&claims.version)
                    .map_err(|()| NativeUpdateValidationError::Identity)?,
                build: decode_required_update_string(&claims.build)
                    .map_err(|()| NativeUpdateValidationError::Identity)?,
            })
        }
        UPDATE_LAYOUT_REJECTED => Err(NativeUpdateValidationError::Layout),
        UPDATE_IDENTITY_REJECTED => Err(NativeUpdateValidationError::Identity),
        UPDATE_SIGNATURE_REJECTED => Err(NativeUpdateValidationError::Signature),
        UPDATE_SYSTEM_POLICY_REJECTED => Err(NativeUpdateValidationError::SystemPolicy),
        _ => Err(NativeUpdateValidationError::Entry),
    }
}

#[cfg(test)]
pub(crate) fn update_observe_sealed_tree(
    directory: &File,
    leaf: &CString,
    require_effective_user_owner: bool,
) -> Result<NativeUpdateTreeProof, ()> {
    let mut tree_hash = [0_u8; UPDATE_TREE_HASH_BYTES];
    let mut tree_generation_hash = [0_u8; UPDATE_TREE_HASH_BYTES];
    // SAFETY: The directory and leaf remain valid for this synchronous call,
    // and both fixed-size outputs are exclusively borrowed.
    let status = unsafe {
        ndv_update_observe_sealed_tree(
            directory.as_raw_fd(),
            leaf.as_ptr(),
            require_effective_user_owner,
            tree_hash.as_mut_ptr(),
            tree_generation_hash.as_mut_ptr(),
        )
    };
    if status != UPDATE_OK {
        return Err(());
    }
    Ok(NativeUpdateTreeProof {
        tree_hash,
        tree_generation_hash,
        _critical_files: Vec::new(),
        require_effective_user_owner,
    })
}

#[cfg(test)]
pub(crate) fn update_test_code_hash_length(path: &CString) -> Result<usize, ()> {
    let mut length = 0_usize;
    // SAFETY: The path is immutable and NUL-terminated and the scalar output
    // is initialized and exclusively borrowed for this synchronous test call.
    let status = unsafe { ndv_update_test_code_hash_length(path.as_ptr(), &raw mut length) };
    if status == UPDATE_OK {
        Ok(length)
    } else {
        Err(())
    }
}

fn decode_required_update_string<const N: usize>(value: &[c_char; N]) -> Result<String, ()> {
    let bytes = value.map(i8::cast_unsigned);
    let end = bytes.iter().position(|byte| *byte == 0).ok_or(())?;
    if end == 0 {
        return Err(());
    }
    std::str::from_utf8(&bytes[..end])
        .map(str::to_owned)
        .map_err(|_| ())
}

fn take_update_files(descriptors: &mut [i32; UPDATE_CRITICAL_HANDLES]) -> Result<Vec<File>, ()> {
    let valid = descriptors.iter().all(|descriptor| *descriptor >= 0)
        && descriptors.iter().enumerate().all(|(index, descriptor)| {
            !descriptors[..index]
                .iter()
                .any(|earlier| earlier == descriptor)
        });
    if !valid {
        for index in 0..descriptors.len() {
            let descriptor = descriptors[index];
            if descriptor >= 0 && !descriptors[..index].contains(&descriptor) {
                // SAFETY: Native validation only returns owned descriptors;
                // each distinct nonnegative value is reclaimed at most once.
                drop(unsafe { File::from_raw_fd(descriptor) });
            }
            descriptors[index] = -1;
        }
        return Err(());
    }
    Ok(descriptors
        .iter_mut()
        .map(|descriptor| {
            let owned = *descriptor;
            *descriptor = -1;
            // SAFETY: Successful validation transfers each distinct descriptor
            // exactly once and the source array is invalidated immediately.
            unsafe { File::from_raw_fd(owned) }
        })
        .collect())
}

impl NativeXpcListener {
    pub(crate) fn start<F>(
        service_name: &str,
        peer_requirement: &str,
        limits: &NativeXpcListenerLimits,
        callback: F,
    ) -> Result<Self, ()>
    where
        F: Fn(NativeXpcEvent) + Send + Sync + 'static,
    {
        let service_name = CString::new(service_name).map_err(|_| ())?;
        let peer_requirement = CString::new(peer_requirement).map_err(|_| ())?;
        let context = Box::new(XpcCallbackContext {
            maximum_message_bytes: limits.maximum_message_bytes,
            callback: Box::new(callback),
        });
        let callback_context = NonNull::from(Box::leak(context));
        // SAFETY: Both strings are NUL-terminated and immutable for the call.
        // The leaked callback context remains valid until listener destruction,
        // whose native queue drain precedes reclaiming it in `Drop`.
        let raw = unsafe {
            ndv_xpc_listener_create(
                service_name.as_ptr(),
                peer_requirement.as_ptr(),
                limits.maximum_message_bytes,
                limits.maximum_peers,
                limits.maximum_peer_outstanding,
                limits.maximum_global_outstanding,
                limits.reply_deadline_milliseconds,
                native_xpc_event,
                callback_context.as_ptr().cast(),
            )
        };
        let Some(raw) = NonNull::new(raw) else {
            // SAFETY: `callback_context` came from `Box::leak` above and native
            // creation failed without retaining or invoking it.
            drop(unsafe { Box::from_raw(callback_context.as_ptr()) });
            return Err(());
        };

        // SAFETY: `raw` is one retained native listener returned by create.
        if unsafe { ndv_xpc_listener_activate(raw.as_ptr()) } != 0 {
            // SAFETY: Activation failure still leaves one valid native handle
            // that must be canceled and released before reclaiming context.
            unsafe { ndv_xpc_listener_destroy(raw.as_ptr()) };
            // SAFETY: Native destruction drains callbacks before returning.
            drop(unsafe { Box::from_raw(callback_context.as_ptr()) });
            return Err(());
        }
        Ok(Self {
            raw,
            callback_context,
            _not_send_or_sync: std::marker::PhantomData,
        })
    }
}

impl Drop for NativeXpcListener {
    fn drop(&mut self) {
        // SAFETY: This object owns the one native handle. Destruction cancels
        // and drains its serial callback queue before the Rust context is freed.
        unsafe { ndv_xpc_listener_destroy(self.raw.as_ptr()) };
        // SAFETY: The context was allocated by `Box::leak` in `start` and is
        // reclaimed exactly once after native callback quiescence.
        drop(unsafe { Box::from_raw(self.callback_context.as_ptr()) });
    }
}

impl NativeXpcReply {
    pub(crate) fn send(mut self, payload: &[u8], maximum_message_bytes: usize) -> Result<(), ()> {
        let raw = self.raw.take().ok_or(())?;
        let bytes = if payload.is_empty() {
            ptr::null()
        } else {
            payload.as_ptr()
        };
        // SAFETY: `raw` is the one owned reply reference and is transferred to
        // the native send call. The slice stays immutable for the synchronous
        // copy and is non-null whenever its length is nonzero.
        let status = unsafe {
            ndv_xpc_reply_send(raw.as_ptr(), bytes, payload.len(), maximum_message_bytes)
        };
        if status == 0 { Ok(()) } else { Err(()) }
    }
}

impl Drop for NativeXpcReply {
    fn drop(&mut self) {
        if let Some(raw) = self.raw.take() {
            // SAFETY: `raw` is the one owned native reply reference. Abandon
            // consumes it and schedules bounded peer cancellation.
            unsafe { ndv_xpc_reply_abandon(raw.as_ptr()) };
        }
    }
}

unsafe extern "C" fn native_xpc_event(
    callback_context: *mut c_void,
    event_kind: u32,
    nullable_bytes: *const u8,
    length: usize,
    nullable_reply: *mut c_void,
) {
    let reply = NonNull::new(nullable_reply).map(|raw| NativeXpcReply { raw: Some(raw) });
    let Some(context) = NonNull::new(callback_context.cast::<XpcCallbackContext>()) else {
        drop(reply);
        return;
    };

    // SAFETY: Listener creation stores this context until native destruction
    // drains the callback queue. This trampoline runs only inside that window.
    let context = unsafe { context.as_ref() };
    let event = match event_kind {
        XPC_EVENT_REQUEST => {
            let Some(reply) = reply else {
                return;
            };
            if nullable_bytes.is_null() || length == 0 || length > context.maximum_message_bytes {
                drop(reply);
                return;
            }
            // SAFETY: The XPC data storage is valid and immutable for this
            // synchronous native callback, and native code already bounded it.
            let payload = unsafe { std::slice::from_raw_parts(nullable_bytes, length) }.to_vec();
            NativeXpcEvent::Request { payload, reply }
        }
        XPC_EVENT_LISTENER_INVALID => {
            drop(reply);
            NativeXpcEvent::ListenerInvalid
        }
        _ => {
            drop(reply);
            return;
        }
    };
    let _ = catch_unwind(AssertUnwindSafe(|| (context.callback)(event)));
}

pub(crate) fn local_peer_token(socket: i32) -> Result<NativePeerToken, ()> {
    let mut token = RawAuditToken {
        words: [0; AUDIT_TOKEN_WORDS],
    };
    let mut effective_uid = 0_u32;
    // SAFETY: Both outputs are initialized, exclusively borrowed, and valid
    // for the call. The native shim validates the descriptor, exact token
    // length, and output pointers before copying bounded scalar fields.
    let status =
        unsafe { ndv_copy_local_peer_token(socket, &raw mut token, &raw mut effective_uid) };
    if status == 0 {
        Ok(NativePeerToken {
            words: token.words,
            effective_uid,
        })
    } else {
        Err(())
    }
}

#[cfg(any(not(feature = "development-unverified-local-ipc"), test))]
pub(crate) fn peer_code_signature_claims(
    token_words: [u32; AUDIT_TOKEN_WORDS],
    requirement: &str,
) -> Result<NativeCodeSignatureClaims, ()> {
    let requirement = CString::new(requirement).map_err(|_| ())?;
    let token = RawAuditToken { words: token_words };
    let mut claims = RawCodeSignatureClaims::empty();
    // SAFETY: `token`, the NUL-terminated immutable requirement, and the
    // initialized exclusive output remain valid for the synchronous call. The
    // native shim copies only fixed-capacity scalar/string claims and retains
    // no caller-owned pointer.
    let status = unsafe {
        ndv_copy_peer_code_signature_claims(&raw const token, requirement.as_ptr(), &raw mut claims)
    };
    if status != 0 {
        return Err(());
    }
    let evidence = evidence_bit(
        claims.external_requirement_valid,
        CODE_EVIDENCE_EXTERNAL_REQUIREMENT,
    )? | evidence_bit(
        claims.designated_requirement_valid,
        CODE_EVIDENCE_DESIGNATED_REQUIREMENT,
    )? | evidence_bit(
        claims.certificate_chain_present,
        CODE_EVIDENCE_CERTIFICATE_CHAIN,
    )? | evidence_bit(claims.cms_present, CODE_EVIDENCE_CMS)?
        | evidence_bit(claims.get_task_allow, CODE_EVIDENCE_GET_TASK_ALLOW)?;
    Ok(NativeCodeSignatureClaims {
        signing_identifier: decode_bounded_c_string(&claims.signing_identifier)?,
        team_identifier: decode_bounded_c_string(&claims.team_identifier)?,
        secured_bundle_identifier: decode_bounded_c_string(&claims.secured_bundle_identifier)?,
        application_identifier: decode_bounded_c_string(&claims.application_identifier)?,
        static_flags: claims.static_flags,
        dynamic_status: claims.dynamic_status,
        evidence,
    })
}

#[cfg(any(not(feature = "development-unverified-local-ipc"), test))]
fn decode_bounded_c_string<const N: usize>(value: &[c_char; N]) -> Result<Option<String>, ()> {
    let bytes = value.map(i8::cast_unsigned);
    let end = bytes.iter().position(|byte| *byte == 0).ok_or(())?;
    if end == 0 {
        return Ok(None);
    }
    std::str::from_utf8(&bytes[..end])
        .map(str::to_owned)
        .map(Some)
        .map_err(|_| ())
}

#[cfg(any(not(feature = "development-unverified-local-ipc"), test))]
const fn evidence_bit(value: u8, bit: u8) -> Result<u8, ()> {
    match value {
        0 => Ok(0),
        1 => Ok(bit),
        _ => Err(()),
    }
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

pub(crate) const DISPLAY_BEGIN_CONFIGURATION_FLAG: u32 = 1 << 0;
pub(crate) const DISPLAY_IDENTITY_CHANGE_FLAGS: u32 =
    (1 << 4) | (1 << 5) | (1 << 8) | (1 << 9) | (1 << 10) | (1 << 11);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeDisplayListError {
    CoreGraphics,
    TooMany,
}

#[derive(Default)]
struct DisplayRegistration {
    handles: usize,
    registered: bool,
    poisoned: bool,
}

impl DisplayRegistration {
    fn reserve(&mut self) -> Result<bool, ()> {
        if self.poisoned || (self.handles != 0 && !self.registered) {
            return Err(());
        }
        let register = self.handles == 0;
        self.handles = self.handles.checked_add(1).ok_or(())?;
        Ok(register)
    }

    fn rollback_reservation(&mut self) {
        self.handles = self.handles.saturating_sub(1);
    }

    fn release(&mut self) -> Result<bool, ()> {
        if self.handles == 0 || !self.registered {
            self.poisoned = true;
            return Err(());
        }
        self.handles -= 1;
        Ok(self.handles == 0)
    }
}

struct DisplayCallbackState {
    accepting: AtomicBool,
    configuring: AtomicBool,
    dirty: AtomicBool,
    generation_exhausted: AtomicBool,
    generation: AtomicU64,
    summary_flags: AtomicU32,
    notification: SyncSender<()>,
    notification_receiver: Mutex<Receiver<()>>,
    registration: Mutex<DisplayRegistration>,
}

impl DisplayCallbackState {
    fn new() -> Self {
        let (notification, notification_receiver) = sync_channel(1);
        Self {
            accepting: AtomicBool::new(false),
            configuring: AtomicBool::new(false),
            dirty: AtomicBool::new(false),
            generation_exhausted: AtomicBool::new(false),
            generation: AtomicU64::new(1),
            summary_flags: AtomicU32::new(0),
            notification,
            notification_receiver: Mutex::new(notification_receiver),
            registration: Mutex::new(DisplayRegistration::default()),
        }
    }

    fn mark_changed(&self, flags: u32) {
        if !self.accepting.load(Ordering::Acquire) {
            return;
        }
        if flags & DISPLAY_BEGIN_CONFIGURATION_FLAG != 0 {
            self.configuring.store(true, Ordering::Release);
        } else {
            self.configuring.store(false, Ordering::Release);
        }
        self.summary_flags.fetch_or(flags, Ordering::AcqRel);
        if self
            .generation
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |generation| {
                generation.checked_add(1)
            })
            .is_err()
        {
            self.generation_exhausted.store(true, Ordering::Release);
        }
        self.dirty.store(true, Ordering::Release);
        match self.notification.try_send(()) {
            Ok(()) | Err(TrySendError::Full(()) | TrySendError::Disconnected(())) => {}
        }
    }

    fn force_dirty(&self, flags: u32) {
        self.summary_flags.fetch_or(flags, Ordering::AcqRel);
        if self
            .generation
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |generation| {
                generation.checked_add(1)
            })
            .is_err()
        {
            self.generation_exhausted.store(true, Ordering::Release);
        }
        self.dirty.store(true, Ordering::Release);
        match self.notification.try_send(()) {
            Ok(()) | Err(TrySendError::Full(()) | TrySendError::Disconnected(())) => {}
        }
    }

    fn drain_notification(&self) {
        let Ok(receiver) = self.notification_receiver.lock() else {
            self.dirty.store(true, Ordering::Release);
            return;
        };
        loop {
            match receiver.try_recv() {
                Ok(()) => {}
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => return,
            }
        }
    }
}

fn display_callback_state() -> &'static DisplayCallbackState {
    static STATE: OnceLock<DisplayCallbackState> = OnceLock::new();
    STATE.get_or_init(DisplayCallbackState::new)
}

unsafe extern "C" fn display_reconfiguration_callback(
    _display: CGDirectDisplayID,
    flags: u32,
    _user_info: *const c_void,
) {
    // The callback context is process-lifetime static state. CoreGraphics may
    // invoke this function on its event thread or synchronously inside a
    // reconfiguration call, so this path performs atomics plus one nonblocking
    // capacity-one notification only. It never enumerates, locks, allocates,
    // invokes caller code, or attempts to reconfigure a display.
    display_callback_state().mark_changed(flags);
}

pub(crate) struct NativeDisplayMonitor {
    active: bool,
}

impl NativeDisplayMonitor {
    pub(crate) fn start() -> Result<Self, ()> {
        let state = display_callback_state();
        let mut registration = state.registration.lock().map_err(|_| ())?;
        let should_register = registration.reserve()?;
        if should_register {
            state.accepting.store(true, Ordering::Release);
            // SAFETY: The callback and its null user-info value are stable for
            // the process lifetime. The trampoline touches only process-static
            // atomics and a nonblocking bounded sender.
            let status = unsafe {
                CGDisplayRegisterReconfigurationCallback(
                    display_reconfiguration_callback,
                    ptr::null(),
                )
            };
            if status != 0 {
                state.accepting.store(false, Ordering::Release);
                registration.rollback_reservation();
                return Err(());
            }
            registration.registered = true;
        }
        Ok(Self { active: true })
    }

    pub(crate) fn stop(&mut self) -> Result<(), ()> {
        if !self.active {
            return Ok(());
        }
        let state = display_callback_state();
        let mut registration = state.registration.lock().map_err(|_| ())?;
        self.active = false;
        let should_remove = registration.release()?;
        if !should_remove {
            return Ok(());
        }

        // Stop accepting first. The callback context remains process-lifetime,
        // so even a callback already in flight during removal cannot observe
        // freed Rust memory or reenter user teardown.
        state.accepting.store(false, Ordering::Release);
        // SAFETY: This exactly matches the callback and null user-info used by
        // registration. Process-static callback state outlives this call and
        // any callback that was already in flight.
        let status = unsafe {
            CGDisplayRemoveReconfigurationCallback(display_reconfiguration_callback, ptr::null())
        };
        registration.registered = false;
        state.configuring.store(false, Ordering::Release);
        state.force_dirty(DISPLAY_IDENTITY_CHANGE_FLAGS);
        if status != 0 {
            registration.poisoned = true;
            return Err(());
        }
        Ok(())
    }
}

impl Drop for NativeDisplayMonitor {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

pub(crate) fn display_change_pending() -> bool {
    let state = display_callback_state();
    state.generation_exhausted.load(Ordering::Acquire)
        || state.configuring.load(Ordering::Acquire)
        || state.dirty.load(Ordering::Acquire)
}

pub(crate) fn display_monitor_active() -> bool {
    display_callback_state()
        .registration
        .lock()
        .is_ok_and(|registration| registration.handles != 0 && !registration.poisoned)
}

pub(crate) fn display_configuration_in_progress() -> bool {
    let state = display_callback_state();
    state.generation_exhausted.load(Ordering::Acquire) || state.configuring.load(Ordering::Acquire)
}

pub(crate) fn display_change_generation() -> u64 {
    display_callback_state().generation.load(Ordering::Acquire)
}

pub(crate) fn take_display_change_flags(generation: u64) -> Option<u32> {
    let state = display_callback_state();
    if state.generation_exhausted.load(Ordering::Acquire)
        || state.configuring.load(Ordering::Acquire)
        || state.generation.load(Ordering::Acquire) != generation
    {
        return None;
    }
    let flags = state.summary_flags.swap(0, Ordering::AcqRel);
    if state.generation_exhausted.load(Ordering::Acquire)
        || state.configuring.load(Ordering::Acquire)
        || state.generation.load(Ordering::Acquire) != generation
    {
        state.summary_flags.fetch_or(flags, Ordering::AcqRel);
        None
    } else {
        Some(flags)
    }
}

pub(crate) fn mark_display_change_clean(generation: u64) -> bool {
    let state = display_callback_state();
    if state.generation_exhausted.load(Ordering::Acquire)
        || state.configuring.load(Ordering::Acquire)
        || state.generation.load(Ordering::Acquire) != generation
    {
        return false;
    }
    state.dirty.store(false, Ordering::Release);
    if state.generation_exhausted.load(Ordering::Acquire)
        || state.configuring.load(Ordering::Acquire)
        || state.generation.load(Ordering::Acquire) != generation
    {
        state.dirty.store(true, Ordering::Release);
        return false;
    }
    state.drain_notification();
    true
}

pub(crate) fn force_display_change(flags: u32) {
    display_callback_state().force_dirty(flags);
}

pub(crate) fn active_display_ids_bounded(
    maximum_displays: usize,
) -> Result<Vec<CGDirectDisplayID>, NativeDisplayListError> {
    let capacity = maximum_displays
        .checked_add(1)
        .and_then(|capacity| u32::try_from(capacity).ok())
        .ok_or(NativeDisplayListError::TooMany)?;
    let mut identifiers = vec![0; capacity as usize];
    let mut count = 0_u32;
    // SAFETY: `identifiers` is initialized for exactly `capacity` values and
    // remains exclusively borrowed. CoreGraphics writes no more than capacity
    // IDs and one scalar count.
    let status =
        unsafe { CGGetActiveDisplayList(capacity, identifiers.as_mut_ptr(), &raw mut count) };
    if status != 0 {
        return Err(NativeDisplayListError::CoreGraphics);
    }
    if count as usize > maximum_displays {
        return Err(NativeDisplayListError::TooMany);
    }
    identifiers.truncate(count as usize);
    Ok(identifiers)
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
mod display_tests {
    use super::*;

    #[test]
    fn callback_signal_is_atomic_coalesced_and_never_runs_registration_work() {
        let state = DisplayCallbackState::new();
        let initial = state.generation.load(Ordering::Acquire);
        state.accepting.store(true, Ordering::Release);

        state.mark_changed(DISPLAY_BEGIN_CONFIGURATION_FLAG);
        state.mark_changed(DISPLAY_BEGIN_CONFIGURATION_FLAG);
        assert!(state.configuring.load(Ordering::Acquire));
        assert!(state.dirty.load(Ordering::Acquire));
        assert_eq!(state.generation.load(Ordering::Acquire), initial + 2);

        let receiver = state.notification_receiver.lock().unwrap();
        assert_eq!(receiver.try_recv(), Ok(()));
        assert_eq!(receiver.try_recv(), Err(TryRecvError::Empty));
        drop(receiver);

        state.mark_changed(1 << 4);
        assert!(!state.configuring.load(Ordering::Acquire));
        assert_eq!(
            state.summary_flags.load(Ordering::Acquire) & DISPLAY_BEGIN_CONFIGURATION_FLAG,
            DISPLAY_BEGIN_CONFIGURATION_FLAG
        );
        assert_eq!(
            state.summary_flags.load(Ordering::Acquire) & (1 << 4),
            1 << 4
        );
    }

    #[test]
    fn stopped_callback_state_ignores_late_native_delivery() {
        let state = DisplayCallbackState::new();
        let initial = state.generation.load(Ordering::Acquire);
        state.mark_changed(DISPLAY_BEGIN_CONFIGURATION_FLAG);
        assert_eq!(state.generation.load(Ordering::Acquire), initial);
        assert!(!state.dirty.load(Ordering::Acquire));
    }

    #[test]
    fn exhausted_callback_generation_stays_fail_closed() {
        let state = DisplayCallbackState::new();
        state.accepting.store(true, Ordering::Release);
        state.generation.store(u64::MAX, Ordering::Release);
        state.mark_changed(1 << 1);
        assert!(state.generation_exhausted.load(Ordering::Acquire));
        assert!(state.dirty.load(Ordering::Acquire));
        assert_eq!(state.generation.load(Ordering::Acquire), u64::MAX);
    }

    #[test]
    fn registration_reducer_is_restartable_and_rejects_unbalanced_teardown() {
        let mut registration = DisplayRegistration::default();
        assert_eq!(registration.reserve(), Ok(true));
        registration.registered = true;
        assert_eq!(registration.reserve(), Ok(false));
        assert_eq!(registration.release(), Ok(false));
        assert_eq!(registration.release(), Ok(true));
        registration.registered = false;
        assert_eq!(registration.reserve(), Ok(true));
        registration.rollback_reservation();
        assert_eq!(registration.handles, 0);
        assert_eq!(registration.release(), Err(()));
        assert!(registration.poisoned);
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
