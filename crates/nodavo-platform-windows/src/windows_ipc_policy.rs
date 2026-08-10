//! Pure policy for authorizing the packaged Windows UI over local IPC.
//!
//! Native observations are collected inside `windows::ffi`. Keeping exact
//! policy matching here makes rejection behavior testable on non-Windows
//! development hosts without introducing a second native boundary.

#[cfg(all(
    feature = "windows-ui-auth-development",
    feature = "windows-ui-auth-release"
))]
compile_error!("Windows UI authentication development and release modes are mutually exclusive");

pub(crate) const WINDOWS_UI_APPLICATION_ID: &str = "App";
pub(crate) const WINDOWS_UI_EXECUTABLE: &str = "Nodavo.Windows.exe";
const PACKAGE_ARCHITECTURE_X64: u32 = 9;
const PACKAGE_ARCHITECTURE_ARM64: u32 = 12;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsUiAuthMode {
    /// Ordinary/unpackaged builds cannot authorize the privileged local UI.
    Unconfigured,
    /// Explicit self-signed development MSIX policy.
    Development,
    /// Exact production package policy embedded by release packaging.
    Release,
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct WindowsUiPolicy {
    pub(crate) package_name: String,
    pub(crate) publisher: String,
    pub(crate) package_family_name: String,
    pub(crate) application_user_model_id: String,
    pub(crate) application_id: String,
    pub(crate) executable: String,
    pub(crate) processor_architecture: u32,
    pub(crate) signer_certificate_sha256: [u8; 32],
    pub(crate) requires_trusted_timestamp: bool,
}

impl std::fmt::Debug for WindowsUiPolicy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("WindowsUiPolicy([redacted])")
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct ObservedWindowsUi {
    pub(crate) package_full_name: String,
    pub(crate) package_name: String,
    pub(crate) publisher: String,
    pub(crate) package_family_name: String,
    pub(crate) application_user_model_id: String,
    pub(crate) package_relative_executable: String,
    pub(crate) processor_architecture: u32,
    pub(crate) resource_id: String,
    pub(crate) publisher_id: String,
}

impl std::fmt::Debug for ObservedWindowsUi {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ObservedWindowsUi([redacted])")
    }
}

#[must_use]
pub const fn compiled_windows_ui_auth_mode() -> WindowsUiAuthMode {
    #[cfg(feature = "windows-ui-auth-development")]
    {
        return WindowsUiAuthMode::Development;
    }
    #[cfg(feature = "windows-ui-auth-release")]
    {
        return WindowsUiAuthMode::Release;
    }
    #[allow(unreachable_code)]
    WindowsUiAuthMode::Unconfigured
}

pub(crate) fn compiled_windows_ui_policy(
    derived_package_family_name: &str,
) -> Option<WindowsUiPolicy> {
    let _ = derived_package_family_name;
    #[cfg(feature = "windows-ui-auth-development")]
    {
        return WindowsUiPolicy::new(
            "dev.nodavo.Nodavo.Development",
            "CN=Nodavo Development Only",
            derived_package_family_name,
            WINDOWS_UI_APPLICATION_ID,
            WINDOWS_UI_EXECUTABLE,
            env!("NODAVO_WINDOWS_AUTH_SIGNER_CERT_SHA256"),
            false,
        );
    }
    #[cfg(feature = "windows-ui-auth-release")]
    {
        let embedded_package_family_name = env!("NODAVO_WINDOWS_AUTH_PACKAGE_FAMILY_NAME");
        if embedded_package_family_name != derived_package_family_name {
            return None;
        }
        return WindowsUiPolicy::new(
            "dev.nodavo.Nodavo",
            env!("NODAVO_WINDOWS_AUTH_PUBLISHER"),
            embedded_package_family_name,
            WINDOWS_UI_APPLICATION_ID,
            WINDOWS_UI_EXECUTABLE,
            env!("NODAVO_WINDOWS_AUTH_SIGNER_CERT_SHA256"),
            true,
        );
    }
    #[allow(unreachable_code)]
    None
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) const fn compiled_windows_ui_identity() -> Option<(&'static str, &'static str)> {
    #[cfg(feature = "windows-ui-auth-development")]
    {
        return Some((
            "dev.nodavo.Nodavo.Development",
            "CN=Nodavo Development Only",
        ));
    }
    #[cfg(feature = "windows-ui-auth-release")]
    {
        return Some(("dev.nodavo.Nodavo", env!("NODAVO_WINDOWS_AUTH_PUBLISHER")));
    }
    #[allow(unreachable_code)]
    None
}

impl WindowsUiPolicy {
    #[cfg_attr(
        not(any(
            feature = "windows-ui-auth-development",
            feature = "windows-ui-auth-release",
            test
        )),
        allow(dead_code)
    )]
    fn new(
        package_name: &str,
        publisher: &str,
        package_family_name: &str,
        application_id: &str,
        executable: &str,
        signer_certificate_sha256: &str,
        requires_trusted_timestamp: bool,
    ) -> Option<Self> {
        let application_user_model_id = format!("{package_family_name}!{application_id}");
        let value = Self {
            package_name: package_name.to_owned(),
            publisher: publisher.to_owned(),
            package_family_name: package_family_name.to_owned(),
            application_user_model_id,
            application_id: application_id.to_owned(),
            executable: executable.to_owned(),
            processor_architecture: compiled_package_architecture(),
            signer_certificate_sha256: decode_sha256(signer_certificate_sha256)?,
            requires_trusted_timestamp,
        };
        value.is_well_formed().then_some(value)
    }

    fn is_well_formed(&self) -> bool {
        valid_package_name(&self.package_name)
            && valid_bounded_text(&self.publisher, 8_192)
            && valid_package_family_name(&self.package_family_name)
            && self
                .package_family_name
                .strip_prefix(&self.package_name)
                .and_then(|suffix| suffix.strip_prefix('_'))
                .is_some_and(valid_publisher_id)
            && self.application_id == WINDOWS_UI_APPLICATION_ID
            && self.application_user_model_id
                == format!("{}!{}", self.package_family_name, self.application_id)
            && self.executable == WINDOWS_UI_EXECUTABLE
            && matches!(
                self.processor_architecture,
                PACKAGE_ARCHITECTURE_X64 | PACKAGE_ARCHITECTURE_ARM64
            )
            && self.signer_certificate_sha256 != [0_u8; 32]
    }
}

#[cfg_attr(
    not(any(
        feature = "windows-ui-auth-development",
        feature = "windows-ui-auth-release",
        test
    )),
    allow(dead_code)
)]
fn decode_sha256(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut decoded = [0_u8; 32];
    for (index, output) in decoded.iter_mut().enumerate() {
        let offset = index * 2;
        *output = u8::from_str_radix(&value[offset..offset + 2], 16).ok()?;
    }
    Some(decoded)
}

pub(crate) fn authorizes_windows_ui(
    policy: &WindowsUiPolicy,
    observed: &ObservedWindowsUi,
) -> bool {
    policy.is_well_formed()
        && valid_bounded_text(&observed.package_full_name, 127)
        && valid_package_name(&observed.package_name)
        && valid_bounded_text(&observed.publisher, 8_192)
        && valid_package_family_name(&observed.package_family_name)
        && observed.package_name == policy.package_name
        && observed.publisher == policy.publisher
        && observed.package_family_name == policy.package_family_name
        && observed.application_user_model_id == policy.application_user_model_id
        && observed.package_relative_executable == policy.executable
        && observed.processor_architecture == policy.processor_architecture
        && observed.resource_id.is_empty()
        && observed.publisher_id
            == observed
                .package_family_name
                .strip_prefix(&format!("{}_", observed.package_name))
                .unwrap_or_default()
        && valid_publisher_id(&observed.publisher_id)
}

#[cfg_attr(
    not(any(
        feature = "windows-ui-auth-development",
        feature = "windows-ui-auth-release",
        test
    )),
    allow(dead_code)
)]
const fn compiled_package_architecture() -> u32 {
    if cfg!(target_arch = "x86_64") {
        PACKAGE_ARCHITECTURE_X64
    } else if cfg!(target_arch = "aarch64") {
        PACKAGE_ARCHITECTURE_ARM64
    } else {
        0
    }
}

fn valid_package_name(value: &str) -> bool {
    (3..=50).contains(&value.len())
        && !value.ends_with('.')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
}

fn valid_package_family_name(value: &str) -> bool {
    (5..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

fn valid_publisher_id(value: &str) -> bool {
    value.len() == 13
        && value.bytes().all(|byte| {
            byte.is_ascii_digit()
                || matches!(
                    byte,
                    b'a'..=b'h' | b'j'..=b'k' | b'm'..=b'n' | b'p'..=b't' | b'v'..=b'z'
                )
        })
}

fn valid_bounded_text(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> WindowsUiPolicy {
        WindowsUiPolicy::new(
            "dev.nodavo.Nodavo.Development",
            "CN=Nodavo Development Only",
            "dev.nodavo.Nodavo.Development_123456789abcd",
            "App",
            "Nodavo.Windows.exe",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            false,
        )
        .unwrap()
    }

    fn observed() -> ObservedWindowsUi {
        let policy = policy();
        ObservedWindowsUi {
            package_full_name: format!("{}_0.1.0.0_x64__123456789abcd", policy.package_name),
            package_name: policy.package_name,
            publisher: policy.publisher,
            package_family_name: policy.package_family_name,
            application_user_model_id: policy.application_user_model_id,
            package_relative_executable: policy.executable,
            processor_architecture: policy.processor_architecture,
            resource_id: String::new(),
            publisher_id: "123456789abcd".to_owned(),
        }
    }

    #[test]
    fn exact_packaged_identity_is_authorized() {
        assert!(authorizes_windows_ui(&policy(), &observed()));
    }

    #[test]
    fn unpackaged_build_has_no_runtime_bypass() {
        #[cfg(not(any(
            feature = "windows-ui-auth-development",
            feature = "windows-ui-auth-release"
        )))]
        {
            assert_eq!(
                compiled_windows_ui_auth_mode(),
                WindowsUiAuthMode::Unconfigured
            );
            assert!(compiled_windows_ui_policy("dev.nodavo.Nodavo_123456789abcd").is_none());
        }
    }

    #[test]
    fn every_semantic_identity_mismatch_is_rejected() {
        let expected = policy();
        let baseline = observed();
        let mutations: [fn(&mut ObservedWindowsUi); 8] = [
            |value| value.package_name.push_str(".Other"),
            |value| value.publisher.push_str(" Other"),
            |value| value.package_family_name.push('x'),
            |value| value.application_user_model_id.push('x'),
            |value| value.package_relative_executable = "Other.exe".to_owned(),
            |value| value.processor_architecture = 0,
            |value| value.resource_id = "resource".to_owned(),
            |value| value.publisher_id.push('x'),
        ];
        for mutate in mutations {
            let mut candidate = baseline.clone();
            mutate(&mut candidate);
            assert!(!authorizes_windows_ui(&expected, &candidate));
        }
    }

    #[test]
    fn malformed_identity_values_are_rejected() {
        let expected = policy();
        for malformed in ["", " bad", "bad\0value", "bad\nvalue"] {
            let mut candidate = observed();
            candidate.package_full_name = malformed.to_owned();
            assert!(!authorizes_windows_ui(&expected, &candidate));
        }
        assert!(
            WindowsUiPolicy::new(
                "bad_name",
                "CN=Publisher",
                "bad_name_suffix",
                "App",
                "Nodavo.Windows.exe",
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                false,
            )
            .is_none()
        );
        assert!(
            WindowsUiPolicy::new(
                "dev.nodavo.Nodavo",
                "CN=Publisher",
                "dev.nodavo.Nodavo_123456789abcd",
                "App",
                "Nodavo.Windows.exe",
                "not-a-sha256",
                true,
            )
            .is_none()
        );
    }

    #[test]
    fn debug_output_redacts_package_identity() {
        assert_eq!(format!("{:?}", policy()), "WindowsUiPolicy([redacted])");
        assert_eq!(format!("{:?}", observed()), "ObservedWindowsUi([redacted])");
    }
}
