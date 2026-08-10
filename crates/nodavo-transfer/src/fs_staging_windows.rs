#![allow(unsafe_code)]
//! Audited Win32 handle-only DACL boundary for private transfer staging.

use std::ffi::{OsStr, c_void};
use std::fs::File;
use std::io;
use std::mem::{offset_of, size_of, size_of_val};
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _};
use std::ptr;

use windows::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows::Wdk::Storage::FileSystem::{
    FILE_CREATE, FILE_DIRECTORY_FILE, FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT,
    NtCreateFile,
};
use windows::Win32::Foundation::{
    CloseHandle, HANDLE, HLOCAL, LocalFree, OBJ_CASE_INSENSITIVE, RtlNtStatusToDosError,
    STATUS_OBJECT_NAME_COLLISION, STATUS_SUCCESS, UNICODE_STRING,
};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SDDL_REVISION_1, SE_FILE_OBJECT, SetSecurityInfo,
};
use windows::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
    CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation,
    GetSecurityDescriptorControl, GetSecurityDescriptorDacl, GetTokenInformation, IsValidSid,
    OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows::Win32::Storage::FileSystem::{
    DELETE, FILE_ALL_ACCESS, FILE_ATTRIBUTE_DIRECTORY, FILE_DISPOSITION_INFO, FILE_GENERIC_READ,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FileDispositionInfo, READ_CONTROL,
    SetFileInformationByHandle, WRITE_DAC,
};
use windows::Win32::System::IO::IO_STATUS_BLOCK;
use windows::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::core::{BOOL, PCWSTR, PWSTR};

const MAX_TOKEN_USER_BYTES: usize = 64 * 1024;
const MAX_SID_TEXT_BYTES: usize = 184;

pub(super) fn protect_owner_only_file(file: &std::fs::File) -> io::Result<()> {
    protect_owner_only(file, false)
}

pub(super) fn verify_owner_only_directory(file: &std::fs::File) -> io::Result<()> {
    let current_user = current_user()?;
    verify_owner_only(HANDLE(file.as_raw_handle()), current_user.sid, true)
}

pub(super) fn verify_owner_only_file(file: &std::fs::File) -> io::Result<()> {
    let current_user = current_user()?;
    verify_owner_only(HANDLE(file.as_raw_handle()), current_user.sid, false)
}

/// Creates one directory component relative to a retained parent handle with
/// its protected owner-only DACL present at the instant the name is published.
pub(super) fn create_owner_only_directory(parent: &File, name: &OsStr) -> io::Result<File> {
    let encoded_name = name.encode_wide().collect::<Vec<_>>();
    if encoded_name.is_empty()
        || encoded_name
            .iter()
            .any(|unit| *unit == 0 || *unit == u16::from(b'/') || *unit == u16::from(b'\\'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "private staging directory name must be one component",
        ));
    }
    let name_bytes = encoded_name
        .len()
        .checked_mul(size_of::<u16>())
        .and_then(|bytes| u16::try_from(bytes).ok())
        .ok_or_else(invalid_acl)?;
    let object_name = UNICODE_STRING {
        Length: name_bytes,
        MaximumLength: name_bytes,
        Buffer: PWSTR(encoded_name.as_ptr().cast_mut()),
    };
    let current_user = current_user()?;
    let descriptor = owner_only_descriptor(current_user.sid, true)?;
    let object_attributes = OBJECT_ATTRIBUTES {
        Length: u32::try_from(size_of::<OBJECT_ATTRIBUTES>()).map_err(|_| invalid_acl())?,
        RootDirectory: HANDLE(parent.as_raw_handle()),
        ObjectName: &raw const object_name,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: descriptor.0.0.cast(),
        SecurityQualityOfService: ptr::null(),
    };
    let mut io_status = IO_STATUS_BLOCK::default();
    let mut handle = HANDLE::default();
    // SAFETY: the parent handle, UTF-16 name, security descriptor, object
    // attributes, and output storage all remain live for the synchronous call.
    // FILE_CREATE prevents replacing an existing name and OPEN_REPARSE_POINT
    // prevents a reparse target from being followed.
    let status = unsafe {
        NtCreateFile(
            &raw mut handle,
            FILE_GENERIC_READ | READ_CONTROL | WRITE_DAC | DELETE,
            &raw const object_attributes,
            &raw mut io_status,
            None,
            FILE_ATTRIBUTE_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_CREATE,
            FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
            None,
            0,
        )
    };
    if status != STATUS_SUCCESS {
        let kind = if status == STATUS_OBJECT_NAME_COLLISION {
            io::ErrorKind::AlreadyExists
        } else {
            io::Error::from_raw_os_error(
                // SAFETY: the conversion accepts every NTSTATUS value and has
                // no pointer or lifetime requirements.
                unsafe { RtlNtStatusToDosError(status) }.cast_signed(),
            )
            .kind()
        };
        return Err(io::Error::new(
            kind,
            "Windows could not create private staging",
        ));
    }
    if handle.is_invalid() {
        return Err(invalid_acl());
    }
    // SAFETY: successful NtCreateFile returned one uniquely owned kernel file
    // handle, which is transferred exactly once to std::fs::File.
    let file = unsafe { File::from_raw_handle(handle.0) };
    if let Err(verification) =
        verify_owner_only(HANDLE(file.as_raw_handle()), current_user.sid, true)
    {
        let cleanup = delete_created_directory(&file);
        drop(file);
        return match cleanup {
            Ok(()) => Err(verification),
            Err(_) => Err(io::Error::other(
                "Windows rejected private staging and could not remove it",
            )),
        };
    }
    Ok(file)
}

fn delete_created_directory(file: &File) -> io::Result<()> {
    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: file retains the exact newly created empty directory handle with
    // DELETE access; disposition is initialized and live for the synchronous
    // call. The directory is deleted when this handle closes.
    unsafe {
        SetFileInformationByHandle(
            HANDLE(file.as_raw_handle()),
            FileDispositionInfo,
            ptr::from_ref(&disposition).cast::<c_void>(),
            u32::try_from(size_of::<FILE_DISPOSITION_INFO>()).map_err(|_| invalid_acl())?,
        )
        .map_err(native_error)
    }
}

/// Installs and verifies a protected DACL granting full access only to the
/// current user, while also requiring that user to own the object. Directory
/// ACEs inherit to children so newly created names are never briefly exposed.
fn protect_owner_only(file: &std::fs::File, directory: bool) -> io::Result<()> {
    let current_user = current_user()?;
    let handle = HANDLE(file.as_raw_handle());
    verify_owner(handle, current_user.sid)?;
    let expected = owner_only_descriptor(current_user.sid, directory)?;
    let expected_dacl = descriptor_dacl(expected.0)?;

    // SAFETY: `handle` is retained by `file`; `expected` owns the validated
    // self-relative descriptor and DACL for the synchronous call. No pointer
    // is retained by SetSecurityInfo.
    unsafe {
        SetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(expected_dacl.cast_const()),
            None,
        )
        .ok()
        .map_err(native_error)?;
    }
    verify_owner_only(handle, current_user.sid, directory)
}

fn owner_only_descriptor(sid: PSID, directory: bool) -> io::Result<LocalSecurityDescriptor> {
    let sid_text = sid_string(sid)?;
    let inheritance = if directory { "OICI" } else { "" };
    let sddl = format!("O:{sid_text}D:P(A;{inheritance};FA;;;{sid_text})");
    let encoded = sddl
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    LocalSecurityDescriptor::from_sddl(&encoded)
}

fn verify_owner(handle: HANDLE, current_sid: PSID) -> io::Result<()> {
    let mut owner = PSID::default();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: all output pointers are live and the retained handle remains
    // valid; the returned descriptor is immediately transferred to its guard.
    unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            Some(&raw mut owner),
            None,
            None,
            None,
            Some(&raw mut descriptor),
        )
        .ok()
        .map_err(native_error)?;
    }
    let descriptor = LocalSecurityDescriptor(descriptor);
    // SAFETY: owner is backed by the live security descriptor guard.
    if descriptor.0.is_invalid() || owner.is_invalid() || !unsafe { IsValidSid(owner) }.as_bool() {
        return Err(invalid_acl());
    }
    // SAFETY: both SIDs are backed by live guards and current_sid was already
    // validated when read from the process token.
    unsafe { EqualSid(owner, current_sid).map_err(native_error)? };
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn verify_owner_only(handle: HANDLE, current_sid: PSID, directory: bool) -> io::Result<()> {
    let mut owner = PSID::default();
    let mut dacl: *mut ACL = ptr::null_mut();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: all output pointers are live, the handle remains retained by its
    // caller, and the returned descriptor is immediately owned by the guard.
    unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            Some(&raw mut owner),
            None,
            Some(&raw mut dacl),
            None,
            Some(&raw mut descriptor),
        )
        .ok()
        .map_err(native_error)?;
    }
    let descriptor = LocalSecurityDescriptor(descriptor);
    // SAFETY: owner is backed by the live security descriptor guard.
    if descriptor.0.is_invalid()
        || owner.is_invalid()
        || !unsafe { IsValidSid(owner) }.as_bool()
        || dacl.is_null()
    {
        return Err(invalid_acl());
    }
    // SAFETY: owner and current_sid are validated SIDs backed by live guards.
    unsafe {
        EqualSid(owner, current_sid).map_err(native_error)?;
    }

    let mut control = 0_u16;
    let mut revision = 0_u32;
    // SAFETY: the security descriptor guard remains live and both outputs are
    // valid initialized integers.
    unsafe {
        GetSecurityDescriptorControl(descriptor.0, &raw mut control, &raw mut revision)
            .map_err(native_error)?;
    }
    if control & SE_DACL_PROTECTED.0 == 0 {
        return Err(invalid_acl());
    }

    let mut information = ACL_SIZE_INFORMATION::default();
    // SAFETY: dacl belongs to the live descriptor and information has exactly
    // the required size and alignment for AclSizeInformation.
    unsafe {
        GetAclInformation(
            dacl,
            ptr::from_mut(&mut information).cast::<c_void>(),
            u32::try_from(size_of::<ACL_SIZE_INFORMATION>()).map_err(|_| invalid_acl())?,
            AclSizeInformation,
        )
        .map_err(native_error)?;
    }
    if information.AceCount != 1 {
        return Err(invalid_acl());
    }

    let mut raw_ace = ptr::null_mut::<c_void>();
    // SAFETY: the ACL reports one ACE and raw_ace is a live output pointer.
    unsafe {
        GetAce(dacl, 0, &raw mut raw_ace).map_err(native_error)?;
    }
    if raw_ace.is_null() {
        return Err(invalid_acl());
    }
    let list_base = dacl.cast::<u8>() as usize;
    let list_limit = list_base
        .checked_add(usize::try_from(information.AclBytesInUse).map_err(|_| invalid_acl())?)
        .ok_or_else(invalid_acl)?;
    let entry_base = raw_ace.cast::<u8>() as usize;
    let minimum_entry_base = list_base
        .checked_add(size_of::<ACL>())
        .ok_or_else(invalid_acl)?;
    if entry_base != minimum_entry_base || entry_base >= list_limit {
        return Err(invalid_acl());
    }
    let header_limit = entry_base
        .checked_add(size_of::<ACE_HEADER>())
        .ok_or_else(invalid_acl)?;
    if header_limit > list_limit {
        return Err(invalid_acl());
    }
    // SAFETY: the complete fixed ACE header is now bounded by the live ACL.
    let header = unsafe { &*raw_ace.cast::<ACE_HEADER>() };
    let ace_size = usize::from(header.AceSize);
    let entry_limit = entry_base.checked_add(ace_size).ok_or_else(invalid_acl)?;
    let sid_offset = offset_of!(ACCESS_ALLOWED_ACE, SidStart);
    let sid_header_end = sid_offset.checked_add(8).ok_or_else(invalid_acl)?;
    if ace_size < sid_header_end || entry_limit > list_limit {
        return Err(invalid_acl());
    }
    // SAFETY: all fixed ACCESS_ALLOWED_ACE fields and the fixed SID header are
    // now bounded by AceSize and the containing live ACL.
    let ace = unsafe { &*raw_ace.cast::<ACCESS_ALLOWED_ACE>() };
    let expected_flags = if directory {
        u8::try_from((OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE).0).map_err(|_| invalid_acl())?
    } else {
        0
    };
    if u32::from(header.AceType) != ACCESS_ALLOWED_ACE_TYPE
        || header.AceFlags != expected_flags
        || ace.Mask != FILE_ALL_ACCESS.0
    {
        return Err(invalid_acl());
    }
    let ace_sid_start = raw_ace.cast::<u8>().wrapping_add(sid_offset);
    // SAFETY: the complete fixed SID header lies within the bounded ACE.
    let sub_authority_count = usize::from(unsafe { *ace_sid_start.add(1) });
    let sid_size = 8_usize
        .checked_add(sub_authority_count.checked_mul(4).ok_or_else(invalid_acl)?)
        .ok_or_else(invalid_acl)?;
    if sid_offset
        .checked_add(sid_size)
        .is_none_or(|end| end != ace_size)
        || entry_limit != list_limit
    {
        return Err(invalid_acl());
    }
    let ace_sid = PSID(ace_sid_start.cast::<c_void>());
    // SAFETY: the variable-length SID is fully bounded by AceSize and the
    // containing ACL, and the descriptor remains live.
    if ace_sid.is_invalid() || !unsafe { IsValidSid(ace_sid) }.as_bool() {
        return Err(invalid_acl());
    }
    // SAFETY: both SIDs are valid and backed by live storage.
    unsafe {
        EqualSid(ace_sid, current_sid).map_err(native_error)?;
    }
    Ok(())
}

fn descriptor_dacl(descriptor: PSECURITY_DESCRIPTOR) -> io::Result<*mut ACL> {
    let mut present = BOOL::default();
    let mut defaulted = BOOL::default();
    let mut dacl = ptr::null_mut();
    // SAFETY: descriptor is a validated live LocalAlloc descriptor and all
    // outputs are live for the duration of the call.
    unsafe {
        GetSecurityDescriptorDacl(
            descriptor,
            &raw mut present,
            &raw mut dacl,
            &raw mut defaulted,
        )
        .map_err(native_error)?;
    }
    if !present.as_bool() || dacl.is_null() {
        return Err(invalid_acl());
    }
    Ok(dacl)
}

fn current_user() -> io::Result<TokenUserBuffer> {
    let mut token = HANDLE::default();
    // SAFETY: GetCurrentProcess returns a pseudo-handle that is not closed;
    // token is a live output owned by the returned guard.
    unsafe {
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token).map_err(native_error)?;
    }
    if token.is_invalid() {
        return Err(invalid_acl());
    }
    let token = OwnedHandle(token);
    let mut reported_required = 0_u32;
    // SAFETY: documented sizing query with no destination and a live size output.
    let _ = unsafe { GetTokenInformation(token.0, TokenUser, None, 0, &raw mut reported_required) };
    let required = usize::try_from(reported_required).map_err(|_| invalid_acl())?;
    if required < size_of::<TOKEN_USER>() || required > MAX_TOKEN_USER_BYTES {
        return Err(invalid_acl());
    }
    let units = required.div_ceil(size_of::<usize>());
    let mut storage = vec![0_usize; units];
    let storage_bytes =
        u32::try_from(size_of_val(storage.as_slice())).map_err(|_| invalid_acl())?;
    // SAFETY: usize storage provides sufficient size/alignment for TOKEN_USER
    // and remains owned by the returned wrapper.
    unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            Some(storage.as_mut_ptr().cast::<c_void>()),
            storage_bytes,
            &raw mut reported_required,
        )
        .map_err(native_error)?;
    }
    // SAFETY: GetTokenInformation initialized TOKEN_USER at the aligned start.
    let sid = unsafe { (*(storage.as_ptr().cast::<TOKEN_USER>())).User.Sid };
    // SAFETY: sid points into storage, which remains live in the wrapper.
    if sid.is_invalid() || !unsafe { IsValidSid(sid) }.as_bool() {
        return Err(invalid_acl());
    }
    Ok(TokenUserBuffer {
        _storage: storage,
        sid,
    })
}

fn sid_string(sid: PSID) -> io::Result<String> {
    let mut text = PWSTR::null();
    // SAFETY: sid is validated and remains backed by the current-user guard;
    // Windows returns one LocalAlloc NUL-terminated string on success.
    unsafe {
        ConvertSidToStringSidW(sid, &raw mut text).map_err(native_error)?;
    }
    if text.is_null() {
        return Err(invalid_acl());
    }
    let text = LocalWideString(text);
    // SAFETY: ConvertSidToStringSidW returned a live NUL-terminated string.
    let value = unsafe { text.0.to_string() }.map_err(|_| invalid_acl())?;
    if value.is_empty()
        || value.len() > MAX_SID_TEXT_BYTES
        || !value.is_ascii()
        || !value.starts_with("S-")
        || value
            .chars()
            .any(|character| !(character.is_ascii_digit() || matches!(character, 'S' | '-')))
    {
        return Err(invalid_acl());
    }
    Ok(value)
}

fn native_error(_error: windows::core::Error) -> io::Error {
    io::Error::other("Windows rejected the private staging security descriptor")
}

fn invalid_acl() -> io::Error {
    io::Error::other("Windows returned an invalid private staging security descriptor")
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: this guard uniquely owns a non-pseudo token handle.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

struct TokenUserBuffer {
    _storage: Vec<usize>,
    sid: PSID,
}

struct LocalSecurityDescriptor(PSECURITY_DESCRIPTOR);

impl LocalSecurityDescriptor {
    fn from_sddl(encoded: &[u16]) -> io::Result<Self> {
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: encoded is NUL-terminated and retained for the synchronous
        // call; descriptor is a live output freed by this guard.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(encoded.as_ptr()),
                SDDL_REVISION_1,
                &raw mut descriptor,
                None,
            )
            .map_err(native_error)?;
        }
        if descriptor.is_invalid() {
            return Err(invalid_acl());
        }
        Ok(Self(descriptor))
    }
}

impl Drop for LocalSecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: Win32 allocated this exact descriptor with LocalAlloc.
        let _ = unsafe { LocalFree(Some(HLOCAL(self.0.0))) };
    }
}

struct LocalWideString(PWSTR);

impl Drop for LocalWideString {
    fn drop(&mut self) {
        // SAFETY: ConvertSidToStringSidW allocated this exact LocalAlloc string.
        let _ = unsafe { LocalFree(Some(HLOCAL(self.0.0.cast::<c_void>()))) };
    }
}
