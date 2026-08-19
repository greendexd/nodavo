//! Inert macOS application-bundle validation.
//!
//! This module deliberately does not download, extract, launch, register, or
//! activate product updates. It validates an already-materialized, sealed app
//! tree and retains capabilities for exact later revalidation. Atomic exchange
//! is intentionally not exposed: a safe activation supervisor is still absent.

use std::ffi::CString;
use std::fmt;
use std::fs::File;
use std::path::Path;
use std::sync::Arc;

use thiserror::Error;

use crate::macos::ffi;

const MAX_VERSION_BYTES: usize = 128;
const MAX_BUILD_BYTES: usize = 64;
const MAX_LEAF_BYTES: usize = 255;
const TEAM_IDENTIFIER_BYTES: usize = 10;
const CODE_DIRECTORY_HASH_BYTES: usize = 20;
const ENCODED_BUNDLE_IDENTITY_BYTES: usize = 56;

/// Exact current Nodavo bundle layout protected by production validation.
pub const NODAVO_APP_BUNDLE_IDENTIFIER: &str = "dev.nodavo.macos";
pub const NODAVO_APP_EXECUTABLE: &str = "Nodavo";
pub const NODAVO_AGENT_BUNDLE_IDENTIFIER: &str = "dev.nodavo.agent";
pub const NODAVO_AGENT_EXECUTABLE: &str = "nodavo-agent";
pub const NODAVO_AGENT_BUNDLE_RELATIVE_PATH: &str = "Contents/Library/Helpers/NodavoAgent.app";
pub const NODAVO_AGENT_LAUNCH_PLIST: &str = "dev.nodavo.agent.plist";

/// Redacted updater-platform failure. Paths and signing subjects never cross
/// this public boundary.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum MacUpdateError {
    #[error("the macOS update policy is invalid")]
    InvalidPolicy,
    #[error("the update directory is unavailable or unsafe")]
    UnsafeDirectory,
    #[error("the update bundle entry is unavailable or unsafe")]
    UnsafeEntry,
    #[error("the application bundle layout is invalid")]
    InvalidBundleLayout,
    #[error("the application bundle identity does not match policy")]
    BundleIdentityMismatch,
    #[error("whole-bundle code-signing validation failed")]
    CodeSignatureRejected,
    #[error("macOS System Policy rejected the application bundle")]
    SystemPolicyRejected,
}

/// Fixed production validation inputs for one exact Nodavo release bundle.
#[derive(Clone, Eq, PartialEq)]
pub struct MacUpdateBundlePolicy {
    team_identifier: String,
    version: String,
    build: String,
    app_requirement: String,
    agent_requirement: String,
    keychain_access_group: String,
}

impl fmt::Debug for MacUpdateBundlePolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacUpdateBundlePolicy")
            .field("version", &self.version)
            .field("build", &self.build)
            .finish_non_exhaustive()
    }
}

impl MacUpdateBundlePolicy {
    /// Builds the exact Developer ID policy for the current Nodavo layout.
    ///
    /// # Errors
    ///
    /// Rejects malformed Team IDs and unbounded or unsafe version fields.
    pub fn nodavo(
        team_identifier: impl Into<String>,
        version: impl Into<String>,
        build: impl Into<String>,
    ) -> Result<Self, MacUpdateError> {
        let team_identifier = team_identifier.into();
        let version = version.into();
        let build = build.into();
        if !valid_team_identifier(&team_identifier)
            || !valid_version(&version)
            || !valid_build(&build)
        {
            return Err(MacUpdateError::InvalidPolicy);
        }
        let app_requirement =
            developer_id_requirement(&team_identifier, NODAVO_APP_BUNDLE_IDENTIFIER);
        let agent_requirement =
            developer_id_requirement(&team_identifier, NODAVO_AGENT_BUNDLE_IDENTIFIER);
        let keychain_access_group = format!("{team_identifier}.{NODAVO_AGENT_BUNDLE_IDENTIFIER}");
        Ok(Self {
            team_identifier,
            version,
            build,
            app_requirement,
            agent_requirement,
            keychain_access_group,
        })
    }

    #[must_use]
    pub fn team_identifier(&self) -> &str {
        &self.team_identifier
    }

    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    #[must_use]
    pub fn build(&self) -> &str {
        &self.build
    }

    pub(crate) fn app_requirement(&self) -> &str {
        &self.app_requirement
    }

    pub(crate) fn agent_requirement(&self) -> &str {
        &self.agent_requirement
    }

    pub(crate) fn keychain_access_group(&self) -> &str {
        &self.keychain_access_group
    }
}

/// Persistable filesystem and signed-code identity for a validation journal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MacUpdateBundleIdentity {
    device: u64,
    inode: u64,
    app_code_directory_hash: [u8; CODE_DIRECTORY_HASH_BYTES],
    agent_code_directory_hash: [u8; CODE_DIRECTORY_HASH_BYTES],
}

impl MacUpdateBundleIdentity {
    pub const ENCODED_BYTES: usize = ENCODED_BUNDLE_IDENTITY_BYTES;

    /// Decodes one exact fixed-size recovery identity.
    ///
    /// # Errors
    ///
    /// Rejects wrong lengths, zero filesystem identities, or empty code hashes.
    pub fn decode(encoded: &[u8]) -> Result<Self, MacUpdateError> {
        let encoded: &[u8; ENCODED_BUNDLE_IDENTITY_BYTES] = encoded
            .try_into()
            .map_err(|_| MacUpdateError::BundleIdentityMismatch)?;
        let mut device = [0_u8; 8];
        let mut inode = [0_u8; 8];
        let mut app_hash = [0_u8; CODE_DIRECTORY_HASH_BYTES];
        let mut agent_hash = [0_u8; CODE_DIRECTORY_HASH_BYTES];
        device.copy_from_slice(&encoded[..8]);
        inode.copy_from_slice(&encoded[8..16]);
        app_hash.copy_from_slice(&encoded[16..36]);
        agent_hash.copy_from_slice(&encoded[36..56]);
        Self::checked(
            u64::from_be_bytes(device),
            u64::from_be_bytes(inode),
            app_hash,
            agent_hash,
        )
    }

    /// Encodes an exact fixed-size recovery identity.
    #[must_use]
    pub fn encode(self) -> [u8; ENCODED_BUNDLE_IDENTITY_BYTES] {
        let mut encoded = [0_u8; ENCODED_BUNDLE_IDENTITY_BYTES];
        encoded[..8].copy_from_slice(&self.device.to_be_bytes());
        encoded[8..16].copy_from_slice(&self.inode.to_be_bytes());
        encoded[16..36].copy_from_slice(&self.app_code_directory_hash);
        encoded[36..56].copy_from_slice(&self.agent_code_directory_hash);
        encoded
    }

    #[must_use]
    pub const fn device(self) -> u64 {
        self.device
    }

    #[must_use]
    pub const fn inode(self) -> u64 {
        self.inode
    }

    #[must_use]
    pub const fn app_code_directory_hash(self) -> [u8; CODE_DIRECTORY_HASH_BYTES] {
        self.app_code_directory_hash
    }

    #[must_use]
    pub const fn agent_code_directory_hash(self) -> [u8; CODE_DIRECTORY_HASH_BYTES] {
        self.agent_code_directory_hash
    }

    const fn checked(
        device: u64,
        inode: u64,
        app_code_directory_hash: [u8; CODE_DIRECTORY_HASH_BYTES],
        agent_code_directory_hash: [u8; CODE_DIRECTORY_HASH_BYTES],
    ) -> Result<Self, MacUpdateError> {
        if device == 0
            || inode == 0
            || all_zero(&app_code_directory_hash)
            || all_zero(&agent_code_directory_hash)
        {
            return Err(MacUpdateError::BundleIdentityMismatch);
        }
        Ok(Self {
            device,
            inode,
            app_code_directory_hash,
            agent_code_directory_hash,
        })
    }
}

const fn all_zero(value: &[u8; CODE_DIRECTORY_HASH_BYTES]) -> bool {
    let mut index = 0;
    while index < value.len() {
        if value[index] != 0 {
            return false;
        }
        index += 1;
    }
    true
}

struct CapabilityDirectory {
    file: File,
}

impl fmt::Debug for CapabilityDirectory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapabilityDirectory")
            .finish_non_exhaustive()
    }
}

impl CapabilityDirectory {
    fn open(path: &Path, private: bool) -> Result<Arc<Self>, MacUpdateError> {
        let path_bytes = path.as_os_str().as_encoded_bytes();
        if path_bytes.len() > 1 && path_bytes.last() == Some(&b'/') {
            return Err(MacUpdateError::UnsafeDirectory);
        }
        let path = CString::new(path_bytes).map_err(|_| MacUpdateError::UnsafeDirectory)?;
        let file = ffi::update_open_directory(&path, private)
            .map_err(|()| MacUpdateError::UnsafeDirectory)?;
        Ok(Arc::new(Self { file }))
    }
}

/// Retained capability for the parent containing the installed application.
#[derive(Clone)]
pub struct MacUpdateInstallRoot(Arc<CapabilityDirectory>);

impl fmt::Debug for MacUpdateInstallRoot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacUpdateInstallRoot")
            .finish_non_exhaustive()
    }
}

impl MacUpdateInstallRoot {
    /// Opens and retains a no-follow directory capability.
    ///
    /// # Errors
    ///
    /// Rejects non-directories, symbolic links, and unsafe path encodings.
    pub fn open(path: &Path) -> Result<Self, MacUpdateError> {
        CapabilityDirectory::open(path, false).map(Self)
    }
}

/// Retained capability for a current-user-owned mode-0700 candidate root.
#[derive(Clone)]
pub struct MacUpdatePrivateRoot(Arc<CapabilityDirectory>);

impl fmt::Debug for MacUpdatePrivateRoot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacUpdatePrivateRoot")
            .finish_non_exhaustive()
    }
}

impl MacUpdatePrivateRoot {
    /// Opens a private candidate root without following the final component.
    ///
    /// # Errors
    ///
    /// Rejects a root not owned by the effective user or accessible by group or
    /// other users.
    pub fn open(path: &Path) -> Result<Self, MacUpdateError> {
        CapabilityDirectory::open(path, true).map(Self)
    }
}

#[derive(Clone)]
struct ValidatedBundle {
    root: Arc<CapabilityDirectory>,
    leaf: CString,
    identity: MacUpdateBundleIdentity,
    proof: Arc<ffi::NativeUpdateTreeProof>,
    require_effective_user_owner: bool,
    policy: MacUpdateBundlePolicy,
    version: String,
    build: String,
}

impl fmt::Debug for ValidatedBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedBundle")
            .field("version", &self.version)
            .field("build", &self.build)
            .finish_non_exhaustive()
    }
}

/// Whole-bundle validated installed application handle.
#[derive(Clone)]
pub struct MacValidatedInstalledBundle(ValidatedBundle);

/// Whole-bundle validated candidate handle in a private candidate root.
#[derive(Clone)]
pub struct MacValidatedCandidateBundle(ValidatedBundle);

impl fmt::Debug for MacValidatedInstalledBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacValidatedInstalledBundle")
            .field("version", &self.0.version)
            .field("build", &self.0.build)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for MacValidatedCandidateBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacValidatedCandidateBundle")
            .field("version", &self.0.version)
            .field("build", &self.0.build)
            .finish_non_exhaustive()
    }
}

impl MacValidatedInstalledBundle {
    /// Validates an installed bundle relative to a retained parent capability.
    ///
    /// # Errors
    ///
    /// Rejects path substitution, layout, secured metadata, entitlement, or
    /// whole-bundle signature mismatches.
    pub fn validate(
        root: &MacUpdateInstallRoot,
        leaf: &str,
        policy: &MacUpdateBundlePolicy,
    ) -> Result<Self, MacUpdateError> {
        validate_bundle(Arc::clone(&root.0), leaf, policy, false).map(Self)
    }

    #[must_use]
    pub const fn identity(&self) -> MacUpdateBundleIdentity {
        self.0.identity
    }

    /// Revalidates the retained installed entry without activating it.
    ///
    /// # Errors
    ///
    /// Rejects any changed path, tree, signature, policy, or retained identity.
    pub fn revalidate(&self) -> Result<(), MacUpdateError> {
        revalidate_at(&self.0.root, &self.0.leaf, &self.0)
    }
}

impl MacValidatedCandidateBundle {
    /// Validates a candidate relative to a private retained root capability.
    ///
    /// # Errors
    ///
    /// Rejects path substitution, layout, secured metadata, entitlement, or
    /// whole-bundle signature mismatches.
    pub fn validate(
        root: &MacUpdatePrivateRoot,
        leaf: &str,
        policy: &MacUpdateBundlePolicy,
    ) -> Result<Self, MacUpdateError> {
        validate_bundle(Arc::clone(&root.0), leaf, policy, true).map(Self)
    }

    #[must_use]
    pub const fn identity(&self) -> MacUpdateBundleIdentity {
        self.0.identity
    }

    /// Revalidates the retained candidate entry without activating it.
    ///
    /// # Errors
    ///
    /// Rejects any changed path, tree, signature, policy, or retained identity.
    pub fn revalidate(&self) -> Result<(), MacUpdateError> {
        revalidate_at(&self.0.root, &self.0.leaf, &self.0)
    }
}

fn revalidate_at(
    root: &Arc<CapabilityDirectory>,
    leaf: &CString,
    expected: &ValidatedBundle,
) -> Result<(), MacUpdateError> {
    let observed = validate_bundle(
        Arc::clone(root),
        leaf.to_str().map_err(|_| MacUpdateError::UnsafeEntry)?,
        &expected.policy,
        expected.require_effective_user_owner,
    )?;
    if observed.identity != expected.identity || !observed.proof.matches(&expected.proof) {
        return Err(MacUpdateError::BundleIdentityMismatch);
    }
    Ok(())
}

fn validate_bundle(
    root: Arc<CapabilityDirectory>,
    leaf: &str,
    policy: &MacUpdateBundlePolicy,
    require_effective_user_owner: bool,
) -> Result<ValidatedBundle, MacUpdateError> {
    let leaf = validated_leaf(leaf)?;
    let claims =
        ffi::update_validate_nodavo_bundle(&root.file, &leaf, policy, require_effective_user_owner)
            .map_err(native_validation_error)?;
    if claims.version != policy.version || claims.build != policy.build {
        return Err(MacUpdateError::BundleIdentityMismatch);
    }
    Ok(ValidatedBundle {
        root,
        leaf,
        identity: MacUpdateBundleIdentity::checked(
            claims.device,
            claims.inode,
            claims.app_code_directory_hash,
            claims.agent_code_directory_hash,
        )?,
        proof: Arc::new(claims.proof),
        require_effective_user_owner,
        policy: policy.clone(),
        version: claims.version,
        build: claims.build,
    })
}

fn native_validation_error(error: ffi::NativeUpdateValidationError) -> MacUpdateError {
    match error {
        ffi::NativeUpdateValidationError::Entry => MacUpdateError::UnsafeEntry,
        ffi::NativeUpdateValidationError::Layout => MacUpdateError::InvalidBundleLayout,
        ffi::NativeUpdateValidationError::Identity => MacUpdateError::BundleIdentityMismatch,
        ffi::NativeUpdateValidationError::Signature => MacUpdateError::CodeSignatureRejected,
        ffi::NativeUpdateValidationError::SystemPolicy => MacUpdateError::SystemPolicyRejected,
    }
}

fn validated_leaf(value: &str) -> Result<CString, MacUpdateError> {
    if value.is_empty()
        || value.len() > MAX_LEAF_BYTES
        || matches!(value, "." | "..")
        || value.bytes().any(|byte| byte == b'/' || byte == 0)
    {
        return Err(MacUpdateError::UnsafeEntry);
    }
    CString::new(value).map_err(|_| MacUpdateError::UnsafeEntry)
}

fn developer_id_requirement(team_identifier: &str, identifier: &str) -> String {
    format!(
        "anchor apple generic and identifier \"{identifier}\" and certificate leaf[subject.OU] = \"{team_identifier}\" and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and entitlement[\"com.apple.application-identifier\"] = \"{team_identifier}.{identifier}\" and entitlement[\"com.apple.developer.team-identifier\"] = \"{team_identifier}\" and entitlement[\"com.apple.security.get-task-allow\"] absent"
    )
}

fn valid_team_identifier(value: &str) -> bool {
    value.len() == TEAM_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

fn valid_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_VERSION_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
}

fn valid_build(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_BUILD_BYTES
        && value.bytes().all(|byte| byte.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::process::Command;
    use std::str::FromStr as _;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use security_framework::os::macos::code_signing::SecRequirement;

    static NEXT_TEMPORARY_ROOT: AtomicU64 = AtomicU64::new(0);

    fn temporary_root() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "nodavo-macos-update-test-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT_TEMPORARY_ROOT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn create_fixture_bundle(path: &Path) {
        fs::create_dir_all(path.join("Contents/MacOS")).unwrap();
        fs::write(path.join("Contents/MacOS/Nodavo"), b"first executable").unwrap();
        fs::write(path.join("Contents/Info.plist"), b"first plist").unwrap();
        seal_fixture_bundle(path);
    }

    fn seal_fixture_bundle(path: &Path) {
        fs::set_permissions(
            path.join("Contents/MacOS/Nodavo"),
            fs::Permissions::from_mode(0o444),
        )
        .unwrap();
        fs::set_permissions(
            path.join("Contents/Info.plist"),
            fs::Permissions::from_mode(0o444),
        )
        .unwrap();
        fs::set_permissions(
            path.join("Contents/MacOS"),
            fs::Permissions::from_mode(0o555),
        )
        .unwrap();
        fs::set_permissions(path.join("Contents"), fs::Permissions::from_mode(0o555)).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o555)).unwrap();
    }

    fn unseal_fixture_bundle(path: &Path) {
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(path.join("Contents"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(
            path.join("Contents/MacOS"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
    }

    fn observe_fixture(
        parent: &Path,
        leaf: &str,
        require_effective_user_owner: bool,
    ) -> Result<ffi::NativeUpdateTreeProof, ()> {
        let root = CapabilityDirectory::open(parent, false).unwrap();
        ffi::update_observe_sealed_tree(
            &root.file,
            &validated_leaf(leaf).unwrap(),
            require_effective_user_owner,
        )
    }

    #[test]
    fn policy_is_fixed_bounded_and_compiles_exact_requirements() {
        let policy = MacUpdateBundlePolicy::nodavo("ABCDE12345", "2.0.0", "42").unwrap();
        assert_eq!(policy.team_identifier(), "ABCDE12345");
        assert!(
            policy
                .app_requirement
                .contains(NODAVO_APP_BUNDLE_IDENTIFIER)
        );
        assert!(
            policy
                .agent_requirement
                .contains(NODAVO_AGENT_BUNDLE_IDENTIFIER)
        );
        SecRequirement::from_str(&policy.app_requirement).unwrap();
        SecRequirement::from_str(&policy.agent_requirement).unwrap();
        assert_eq!(crate::NODAVO_AGENT_MACH_SERVICE, "dev.nodavo.agent.ipc");
        assert!(policy.app_requirement.contains("get-task-allow\"] absent"));
        assert_eq!(policy.keychain_access_group, "ABCDE12345.dev.nodavo.agent");
        let debug = format!("{policy:?}");
        assert!(!debug.contains("ABCDE12345"));
        assert!(!debug.contains(NODAVO_APP_BUNDLE_IDENTIFIER));
        assert_eq!(
            MacUpdateBundlePolicy::nodavo("development", "2.0.0", "42"),
            Err(MacUpdateError::InvalidPolicy)
        );
        assert_eq!(
            MacUpdateBundlePolicy::nodavo("ABCDE12345", "2/0", "42"),
            Err(MacUpdateError::InvalidPolicy)
        );
        assert_eq!(
            MacUpdateBundlePolicy::nodavo("ABCDE12345", "2.0.0", "4x"),
            Err(MacUpdateError::InvalidPolicy)
        );
    }

    #[test]
    fn recovery_identity_uses_canonical_twenty_byte_cdhashes() {
        let identity = MacUpdateBundleIdentity::checked(1, 2, [3; 20], [4; 20]).unwrap();
        let encoded = identity.encode();
        assert_eq!(encoded.len(), 56);
        assert_eq!(MacUpdateBundleIdentity::decode(&encoded), Ok(identity));
        assert_eq!(
            MacUpdateBundleIdentity::decode(&[0; 80]),
            Err(MacUpdateError::BundleIdentityMismatch)
        );
    }

    #[test]
    fn native_security_framework_returns_twenty_byte_canonical_cdhash() {
        let path = CString::new("/bin/ls").unwrap();
        assert_eq!(
            ffi::update_test_code_hash_length(&path),
            Ok(CODE_DIRECTORY_HASH_BYTES)
        );
    }

    #[test]
    fn sealed_tree_observation_is_stable_and_rejects_writable_content() {
        let parent = temporary_root();
        let bundle = parent.join("candidate.app");
        fs::create_dir_all(&parent).unwrap();
        create_fixture_bundle(&bundle);
        let first = observe_fixture(&parent, "candidate.app", true).unwrap();
        let second = observe_fixture(&parent, "candidate.app", true).unwrap();
        assert!(first.matches(&second));

        fs::set_permissions(
            bundle.join("Contents/Info.plist"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(observe_fixture(&parent, "candidate.app", true).is_err());
        unseal_fixture_bundle(&bundle);
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn nested_executable_replacement_invalidates_the_sealed_proof() {
        let parent = temporary_root();
        let bundle = parent.join("candidate.app");
        fs::create_dir_all(&parent).unwrap();
        create_fixture_bundle(&bundle);
        let expected = observe_fixture(&parent, "candidate.app", true).unwrap();

        unseal_fixture_bundle(&bundle);
        fs::remove_file(bundle.join("Contents/MacOS/Nodavo")).unwrap();
        fs::write(
            bundle.join("Contents/MacOS/Nodavo"),
            b"replacement executable",
        )
        .unwrap();
        seal_fixture_bundle(&bundle);
        let replaced = observe_fixture(&parent, "candidate.app", true).unwrap();
        assert!(!expected.matches(&replaced));
        unseal_fixture_bundle(&bundle);
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn nested_plist_replacement_invalidates_the_sealed_proof() {
        let parent = temporary_root();
        let bundle = parent.join("candidate.app");
        fs::create_dir_all(&parent).unwrap();
        create_fixture_bundle(&bundle);
        let expected = observe_fixture(&parent, "candidate.app", true).unwrap();

        unseal_fixture_bundle(&bundle);
        fs::remove_file(bundle.join("Contents/Info.plist")).unwrap();
        fs::write(bundle.join("Contents/Info.plist"), b"replacement plist").unwrap();
        seal_fixture_bundle(&bundle);
        let replaced = observe_fixture(&parent, "candidate.app", true).unwrap();
        assert!(!expected.matches(&replaced));
        unseal_fixture_bundle(&bundle);
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn private_root_rejects_group_access_and_leaf_traversal() {
        let parent = temporary_root();
        fs::create_dir_all(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o750)).unwrap();
        assert!(matches!(
            MacUpdatePrivateRoot::open(&parent),
            Err(MacUpdateError::UnsafeDirectory)
        ));
        assert_eq!(
            validated_leaf("../candidate.app"),
            Err(MacUpdateError::UnsafeEntry)
        );
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn private_root_accepts_no_acl_and_rejects_any_acl_entry() {
        let parent = temporary_root();
        fs::create_dir_all(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        MacUpdatePrivateRoot::open(&parent).unwrap();

        let status = Command::new("/bin/chmod")
            .args(["+a", "everyone allow read"])
            .arg(&parent)
            .status()
            .unwrap();
        assert!(status.success());
        assert!(matches!(
            MacUpdatePrivateRoot::open(&parent),
            Err(MacUpdateError::UnsafeDirectory)
        ));
        let status = Command::new("/bin/chmod")
            .arg("-N")
            .arg(&parent)
            .status()
            .unwrap();
        assert!(status.success());
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn retained_private_root_is_not_redirected_by_ambient_path_replacement() {
        let parent = temporary_root();
        let private_parent = parent.join("private");
        let retained_parent = parent.join("retained");
        fs::create_dir_all(&private_parent).unwrap();
        fs::set_permissions(&private_parent, fs::Permissions::from_mode(0o700)).unwrap();
        create_fixture_bundle(&private_parent.join("candidate.app"));
        let retained = CapabilityDirectory::open(&private_parent, true).unwrap();
        let leaf = validated_leaf("candidate.app").unwrap();
        let expected = ffi::update_observe_sealed_tree(&retained.file, &leaf, true).unwrap();

        fs::rename(&private_parent, &retained_parent).unwrap();
        fs::create_dir(&private_parent).unwrap();
        fs::set_permissions(&private_parent, fs::Permissions::from_mode(0o700)).unwrap();
        create_fixture_bundle(&private_parent.join("candidate.app"));

        let observed = ffi::update_observe_sealed_tree(&retained.file, &leaf, true).unwrap();
        assert!(expected.matches(&observed));
        unseal_fixture_bundle(&retained_parent.join("candidate.app"));
        unseal_fixture_bundle(&private_parent.join("candidate.app"));
        fs::remove_dir_all(parent).unwrap();
    }
}
