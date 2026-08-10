//! Bounded, content-free platform readiness probing for local UI status.

use std::time::Duration;

use nodavo_local_ipc::{
    AccessibilityReadiness, InputReadiness, LocalTopologyReadiness, ReadinessSnapshot,
    SessionTopologyReadiness,
};
use thiserror::Error;
use tokio::time::timeout;

const READINESS_PROBE_DEADLINE: Duration = Duration::from_secs(3);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LocalPlatformReadiness {
    accessibility: AccessibilityReadiness,
    input: InputReadiness,
    local_topology: LocalTopologyReadiness,
}

impl Default for LocalPlatformReadiness {
    fn default() -> Self {
        Self {
            accessibility: AccessibilityReadiness::Unavailable,
            input: InputReadiness::Unavailable,
            local_topology: LocalTopologyReadiness::Unavailable,
        }
    }
}

impl LocalPlatformReadiness {
    pub(crate) const fn snapshot(
        self,
        session_topology: SessionTopologyReadiness,
    ) -> ReadinessSnapshot {
        ReadinessSnapshot {
            accessibility: self.accessibility,
            input: self.input,
            local_topology: self.local_topology,
            session_topology,
        }
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum ReadinessRequestError {
    #[cfg(not(target_os = "macos"))]
    #[error("accessibility permission requests are unsupported on this platform")]
    UnsupportedPlatform,
    #[error("the bounded platform readiness probe did not complete")]
    ProbeUnavailable,
}

pub(crate) async fn probe() -> LocalPlatformReadiness {
    run_bounded_probe(probe_sync).await.unwrap_or_default()
}

/// Prompts and rechecks in the agent process. The prompt API's return value is
/// deliberately ignored: displaying a prompt is not evidence that access was
/// granted.
#[cfg(target_os = "macos")]
pub(crate) async fn request_accessibility_permission()
-> Result<LocalPlatformReadiness, ReadinessRequestError> {
    run_bounded_probe(|| {
        let _prompt_result = nodavo_platform_macos::request_accessibility();
        probe_sync()
    })
    .await
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn request_accessibility_permission()
-> impl Future<Output = Result<LocalPlatformReadiness, ReadinessRequestError>> {
    std::future::ready(Err(ReadinessRequestError::UnsupportedPlatform))
}

async fn run_bounded_probe(
    operation: impl FnOnce() -> LocalPlatformReadiness + Send + 'static,
) -> Result<LocalPlatformReadiness, ReadinessRequestError> {
    timeout(
        READINESS_PROBE_DEADLINE,
        tokio::task::spawn_blocking(operation),
    )
    .await
    .map_err(|_| ReadinessRequestError::ProbeUnavailable)?
    .map_err(|_| ReadinessRequestError::ProbeUnavailable)
}

#[cfg(target_os = "macos")]
fn probe_sync() -> LocalPlatformReadiness {
    let probe = nodavo_platform_macos::probe_readiness();
    mac_local_readiness(
        probe.accessibility_trusted,
        probe.input_prerequisites_available,
        probe.local_topology_available,
    )
}

#[cfg(target_os = "windows")]
fn probe_sync() -> LocalPlatformReadiness {
    use nodavo_platform_windows::WindowsInputReadiness;

    let probe = nodavo_platform_windows::probe_readiness();
    let input = match probe.input {
        WindowsInputReadiness::Ready => InputReadiness::Ready,
        WindowsInputReadiness::BlockedByDesktop => InputReadiness::BlockedByDesktop,
        WindowsInputReadiness::Unavailable => InputReadiness::Unavailable,
    };
    windows_local_readiness(input, probe.local_topology_available)
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn probe_sync() -> LocalPlatformReadiness {
    LocalPlatformReadiness::default()
}

const fn local_readiness(
    accessibility: AccessibilityReadiness,
    input: InputReadiness,
    local_topology_available: bool,
) -> LocalPlatformReadiness {
    LocalPlatformReadiness {
        accessibility,
        input,
        local_topology: if local_topology_available {
            LocalTopologyReadiness::Available
        } else {
            LocalTopologyReadiness::Unavailable
        },
    }
}

#[cfg(any(target_os = "macos", test))]
const fn mac_local_readiness(
    accessibility_trusted: bool,
    input_prerequisites_available: bool,
    local_topology_available: bool,
) -> LocalPlatformReadiness {
    local_readiness(
        if accessibility_trusted {
            AccessibilityReadiness::Granted
        } else {
            AccessibilityReadiness::ActionRequired
        },
        if !accessibility_trusted {
            InputReadiness::BlockedByPermission
        } else if input_prerequisites_available {
            InputReadiness::Ready
        } else {
            InputReadiness::Unavailable
        },
        local_topology_available,
    )
}

#[cfg(any(target_os = "windows", test))]
const fn windows_local_readiness(
    input: InputReadiness,
    local_topology_available: bool,
) -> LocalPlatformReadiness {
    local_readiness(
        AccessibilityReadiness::NotApplicable,
        input,
        local_topology_available,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_loss_always_blocks_macos_input() {
        let readiness =
            mac_local_readiness(false, true, true).snapshot(SessionTopologyReadiness::NotConnected);
        assert_eq!(
            readiness.accessibility,
            AccessibilityReadiness::ActionRequired
        );
        assert_eq!(readiness.input, InputReadiness::BlockedByPermission);
        assert_eq!(readiness.local_topology, LocalTopologyReadiness::Available);
    }

    #[test]
    fn windows_desktop_block_is_public_and_fail_closed() {
        let readiness = windows_local_readiness(InputReadiness::BlockedByDesktop, false)
            .snapshot(SessionTopologyReadiness::Synchronizing);
        assert_eq!(readiness.input, InputReadiness::BlockedByDesktop);
        assert_eq!(
            readiness.local_topology,
            LocalTopologyReadiness::Unavailable
        );
        assert_eq!(
            readiness.session_topology,
            SessionTopologyReadiness::Synchronizing
        );
    }
}
