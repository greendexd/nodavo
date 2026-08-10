//! Per-message authenticated XPC transport for release UI-to-agent IPC.

use thiserror::Error;

use super::ffi;

pub const NODAVO_AGENT_MACH_SERVICE: &str = "dev.nodavo.agent.ipc";
pub const MAX_XPC_MESSAGE_BYTES: usize = 64 * 1024;
pub const MAX_XPC_PEERS: usize = 16;
pub const MAX_XPC_PEER_OUTSTANDING: usize = 4;
pub const MAX_XPC_GLOBAL_OUTSTANDING: usize = 32;
/// Hard request ceiling. This exceeds the dispatcher's longest bounded
/// operation (five-minute transfer preparation) to avoid ambiguous retries.
pub const XPC_REPLY_DEADLINE_MILLISECONDS: u64 = 360_000;

const NODAVO_UI_IDENTIFIER: &str = "dev.nodavo.macos";
const NODAVO_AGENT_IDENTIFIER: &str = "dev.nodavo.agent";
const APPLE_TEAM_ID_LENGTH: usize = 10;

/// Compile-time release/development local IPC transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacLocalIpcAuthMode {
    /// Release Mach service with reciprocal per-message XPC code requirements.
    XpcSignedMutual,
    /// Non-distributable private UDS with same-UID checks only.
    DevelopmentUnverifiedUds,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacXpcPeerIdentity {
    Ui,
    Agent,
}

/// Generic, non-identifying XPC transport failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum MacXpcError {
    #[error("the compile-time Apple Team ID is unavailable")]
    TeamIdUnavailable,
    #[error("the signed XPC listener is unavailable")]
    ListenerUnavailable,
    #[error("the XPC reply was rejected")]
    ReplyRejected,
}

pub struct MacXpcRequest {
    payload: Vec<u8>,
    reply: MacXpcReply,
}

impl MacXpcRequest {
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    #[must_use]
    pub fn into_parts(self) -> (Vec<u8>, MacXpcReply) {
        (self.payload, self.reply)
    }
}

pub struct MacXpcReply {
    native: ffi::NativeXpcReply,
}

impl MacXpcReply {
    /// Sends one bounded JSON response and consumes the reply capability.
    ///
    /// # Errors
    ///
    /// Rejects empty/oversized data or a native reply that already expired.
    pub fn send(self, payload: &[u8]) -> Result<(), MacXpcError> {
        if payload.is_empty() || payload.len() > MAX_XPC_MESSAGE_BYTES {
            return Err(MacXpcError::ReplyRejected);
        }
        self.native
            .send(payload, MAX_XPC_MESSAGE_BYTES)
            .map_err(|()| MacXpcError::ReplyRejected)
    }
}

pub enum MacXpcEvent {
    Request(MacXpcRequest),
    ListenerInvalid,
}

/// Active launchd Mach-service listener with per-message UI code enforcement.
pub struct MacXpcListener {
    _native: ffi::NativeXpcListener,
}

impl MacXpcListener {
    /// Activates the fixed Nodavo agent Mach service with the exact UI release
    /// requirement before any peer connection can be accepted.
    ///
    /// # Errors
    ///
    /// Fails closed when the Team ID is absent, the requirement is malformed,
    /// or the launchd/XPC listener cannot be created and activated.
    pub fn start<F>(callback: F) -> Result<Self, MacXpcError>
    where
        F: Fn(MacXpcEvent) + Send + Sync + 'static,
    {
        let requirement = mac_xpc_peer_requirement(MacXpcPeerIdentity::Ui)?;
        let native = ffi::NativeXpcListener::start(
            NODAVO_AGENT_MACH_SERVICE,
            &requirement,
            &ffi::NativeXpcListenerLimits {
                maximum_message_bytes: MAX_XPC_MESSAGE_BYTES,
                maximum_peers: MAX_XPC_PEERS,
                maximum_peer_outstanding: MAX_XPC_PEER_OUTSTANDING,
                maximum_global_outstanding: MAX_XPC_GLOBAL_OUTSTANDING,
                reply_deadline_milliseconds: XPC_REPLY_DEADLINE_MILLISECONDS,
            },
            move |event| {
                callback(match event {
                    ffi::NativeXpcEvent::Request { payload, reply } => {
                        MacXpcEvent::Request(MacXpcRequest {
                            payload,
                            reply: MacXpcReply { native: reply },
                        })
                    }
                    ffi::NativeXpcEvent::ListenerInvalid => MacXpcEvent::ListenerInvalid,
                });
            },
        )
        .map_err(|()| MacXpcError::ListenerUnavailable)?;
        Ok(Self { _native: native })
    }
}

/// Returns the compile-time local IPC mode.
///
/// # Errors
///
/// Signed XPC mode fails when no valid Team ID was embedded.
pub fn local_ipc_auth_mode() -> Result<MacLocalIpcAuthMode, MacXpcError> {
    #[cfg(feature = "development-unverified-local-ipc")]
    {
        Ok(MacLocalIpcAuthMode::DevelopmentUnverifiedUds)
    }
    #[cfg(not(feature = "development-unverified-local-ipc"))]
    {
        compiled_team_id()?;
        Ok(MacLocalIpcAuthMode::XpcSignedMutual)
    }
}

/// Builds the exact per-message XPC peer code-signing requirement.
///
/// # Errors
///
/// Fails if the compile-time Team ID is absent or invalid.
pub fn mac_xpc_peer_requirement(identity: MacXpcPeerIdentity) -> Result<String, MacXpcError> {
    let team_id = compiled_team_id()?;
    Ok(peer_requirement(team_id, identity))
}

fn peer_requirement(team_id: &str, identity: MacXpcPeerIdentity) -> String {
    let identifier = match identity {
        MacXpcPeerIdentity::Ui => NODAVO_UI_IDENTIFIER,
        MacXpcPeerIdentity::Agent => NODAVO_AGENT_IDENTIFIER,
    };
    format!(
        "anchor apple generic and identifier \"{identifier}\" and certificate leaf[subject.OU] = \"{team_id}\" and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and entitlement[\"com.apple.application-identifier\"] = \"{team_id}.{identifier}\" and entitlement[\"com.apple.developer.team-identifier\"] = \"{team_id}\" and entitlement[\"com.apple.security.get-task-allow\"] absent"
    )
}

fn compiled_team_id() -> Result<&'static str, MacXpcError> {
    option_env!("NODAVO_APPLE_TEAM_ID")
        .filter(|team_id| valid_team_id(team_id))
        .ok_or(MacXpcError::TeamIdUnavailable)
}

fn valid_team_id(value: &str) -> bool {
    value.len() == APPLE_TEAM_ID_LENGTH
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use core_foundation::url::CFURL;
    use security_framework::os::macos::code_signing::{Flags, SecRequirement, SecStaticCode};

    use super::*;

    #[derive(Clone, Copy)]
    enum ProvenanceGate {
        ConnectionSnapshot,
        PerMessageRequirement,
    }

    fn admits_queued_then_exec_message(
        gate: ProvenanceGate,
        queued_sender_was_signed: bool,
        peer_is_signed_at_delivery: bool,
    ) -> bool {
        match gate {
            ProvenanceGate::ConnectionSnapshot => peer_is_signed_at_delivery,
            ProvenanceGate::PerMessageRequirement => queued_sender_was_signed,
        }
    }

    #[test]
    fn prequeued_unsigned_frame_cannot_be_laundered_by_later_exec() {
        assert!(admits_queued_then_exec_message(
            ProvenanceGate::ConnectionSnapshot,
            false,
            true
        ));
        assert!(!admits_queued_then_exec_message(
            ProvenanceGate::PerMessageRequirement,
            false,
            true
        ));
    }

    #[test]
    fn both_exact_xpc_requirements_compile_and_bind_entitlements() {
        for identity in [MacXpcPeerIdentity::Ui, MacXpcPeerIdentity::Agent] {
            let requirement = peer_requirement("ABCDE12345", identity);
            SecRequirement::from_str(&requirement).expect("requirement must compile");
            assert!(requirement.contains("anchor apple generic"));
            assert!(requirement.contains("com.apple.application-identifier"));
            assert!(requirement.contains("com.apple.developer.team-identifier"));
            assert!(requirement.contains("get-task-allow\"] absent"));
            assert!(!requirement.contains(" or "));
        }
    }

    #[test]
    fn local_adhoc_fixture_fails_the_xpc_ui_requirement() {
        let path = CFURL::from_path(std::env::current_exe().unwrap(), false).unwrap();
        let code = SecStaticCode::from_path(&path, Flags::NONE).unwrap();
        let requirement =
            SecRequirement::from_str(&peer_requirement("ABCDE12345", MacXpcPeerIdentity::Ui))
                .unwrap();

        assert!(code.check_validity(Flags::NONE, &requirement).is_err());
    }

    #[test]
    fn release_mode_is_xpc_and_service_is_fixed() {
        #[cfg(not(feature = "development-unverified-local-ipc"))]
        if compiled_team_id().is_ok() {
            assert_eq!(
                local_ipc_auth_mode(),
                Ok(MacLocalIpcAuthMode::XpcSignedMutual)
            );
        } else {
            assert_eq!(local_ipc_auth_mode(), Err(MacXpcError::TeamIdUnavailable));
        }
        #[cfg(feature = "development-unverified-local-ipc")]
        assert_eq!(
            local_ipc_auth_mode(),
            Ok(MacLocalIpcAuthMode::DevelopmentUnverifiedUds)
        );
        assert_eq!(NODAVO_AGENT_MACH_SERVICE, "dev.nodavo.agent.ipc");
        assert_eq!(XPC_REPLY_DEADLINE_MILLISECONDS, 360_000);
    }
}
