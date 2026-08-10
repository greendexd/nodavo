//! Signed macOS UI authentication for the agent's local Unix socket.

use std::os::fd::RawFd;

use thiserror::Error;

use super::ffi;

#[cfg(any(not(feature = "development-unverified-local-ipc"), test))]
const NODAVO_UI_IDENTIFIER: &str = "dev.nodavo.macos";
const APPLE_TEAM_ID_LENGTH: usize = 10;

#[cfg(any(not(feature = "development-unverified-local-ipc"), test))]
const CODE_SIGNATURE_VALID: u32 = 0x0000_0001;
#[cfg(any(not(feature = "development-unverified-local-ipc"), test))]
const CODE_SIGNATURE_AD_HOC: u32 = 0x0000_0002;
#[cfg(any(not(feature = "development-unverified-local-ipc"), test))]
const CODE_SIGNATURE_GET_TASK_ALLOW: u32 = 0x0000_0004;
#[cfg(any(not(feature = "development-unverified-local-ipc"), test))]
const CODE_SIGNATURE_RUNTIME: u32 = 0x0001_0000;
#[cfg(any(not(feature = "development-unverified-local-ipc"), test))]
const CODE_STATUS_DEBUGGED: u32 = 0x1000_0000;

/// A generic, non-identifying local IPC authentication failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum MacIpcAuthError {
    #[error("the signed local UI policy has no compile-time Apple Team ID")]
    TeamIdUnavailable,
    #[error("the local IPC peer token is unavailable")]
    PeerTokenUnavailable,
    #[error("the local IPC peer does not belong to the socket owner")]
    UserMismatch,
    #[error("the local IPC peer code signature was rejected")]
    CodeSignatureRejected,
    #[error("the local IPC peer identity changed")]
    PeerIdentityChanged,
}

/// An authenticated peer identity guard bound to one accepted Unix socket.
///
/// The audit token is deliberately opaque and has no `Debug` implementation so
/// callers cannot accidentally log its process or stable audit-session fields.
pub struct MacIpcPeerGuard {
    authenticated: PeerToken,
    owner_uid: u32,
}

impl MacIpcPeerGuard {
    /// Authenticates an accepted Unix socket before any frame is decoded.
    ///
    /// The peer token is fetched again after Security.framework validation so
    /// an exec or process-identity change cannot bridge the validation window.
    ///
    /// # Errors
    ///
    /// Fails closed on a missing/changed token, user mismatch, absent production
    /// Team ID, or any code-signing claim that does not match the fixed policy.
    pub fn authenticate(socket: RawFd, owner_uid: u32) -> Result<Self, MacIpcAuthError> {
        Self::authenticate_with(&SystemPeerVerifier, socket, owner_uid, policy()?)
    }

    /// Refetches the peer audit token at one frame authorization gate.
    ///
    /// The agent invokes this both immediately before blocking frame input and
    /// after decode immediately before dispatch.
    ///
    /// # Errors
    ///
    /// Rejects a missing token, user change, or any token change since the
    /// signed identity was authenticated.
    pub fn authorize_frame_gate(&self, socket: RawFd) -> Result<(), MacIpcAuthError> {
        self.authorize_frame_gate_with(&SystemPeerVerifier, socket)
    }

    fn authenticate_with<V: PeerVerifier>(
        verifier: &V,
        socket: RawFd,
        owner_uid: u32,
        policy: VerificationPolicy,
    ) -> Result<Self, MacIpcAuthError> {
        let before = verifier.peer_token(socket)?;
        verify_owner(&before, owner_uid)?;

        match policy {
            #[cfg(any(not(feature = "development-unverified-local-ipc"), test))]
            VerificationPolicy::SignedUi { team_id } => {
                let requirement = external_requirement(team_id);
                let claims = verifier.code_signature_claims(&before, &requirement)?;
                reduce_claims(&claims, team_id)?;
            }
            #[cfg(any(feature = "development-unverified-local-ipc", test))]
            VerificationPolicy::DevelopmentUnverifiedSameUser => {}
        }

        let after = verifier.peer_token(socket)?;
        verify_owner(&after, owner_uid)?;
        if before != after {
            return Err(MacIpcAuthError::PeerIdentityChanged);
        }

        Ok(Self {
            authenticated: after,
            owner_uid,
        })
    }

    fn authorize_frame_gate_with<V: PeerVerifier>(
        &self,
        verifier: &V,
        socket: RawFd,
    ) -> Result<(), MacIpcAuthError> {
        let current = verifier.peer_token(socket)?;
        verify_owner(&current, self.owner_uid)?;
        if current != self.authenticated {
            return Err(MacIpcAuthError::PeerIdentityChanged);
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum VerificationPolicy {
    #[cfg(any(not(feature = "development-unverified-local-ipc"), test))]
    SignedUi { team_id: &'static str },
    #[cfg(any(feature = "development-unverified-local-ipc", test))]
    DevelopmentUnverifiedSameUser,
}

fn policy() -> Result<VerificationPolicy, MacIpcAuthError> {
    #[cfg(feature = "development-unverified-local-ipc")]
    {
        if option_env!("NODAVO_APPLE_TEAM_ID").is_some_and(|team_id| !valid_team_id(team_id)) {
            return Err(MacIpcAuthError::TeamIdUnavailable);
        }
        Ok(VerificationPolicy::DevelopmentUnverifiedSameUser)
    }
    #[cfg(not(feature = "development-unverified-local-ipc"))]
    {
        let team_id = option_env!("NODAVO_APPLE_TEAM_ID")
            .filter(|team_id| valid_team_id(team_id))
            .ok_or(MacIpcAuthError::TeamIdUnavailable)?;
        Ok(VerificationPolicy::SignedUi { team_id })
    }
}

fn valid_team_id(value: &str) -> bool {
    value.len() == APPLE_TEAM_ID_LENGTH
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

#[cfg(any(not(feature = "development-unverified-local-ipc"), test))]
fn external_requirement(team_id: &str) -> String {
    format!(
        "anchor apple generic and identifier \"{NODAVO_UI_IDENTIFIER}\" and certificate leaf[subject.OU] = \"{team_id}\" and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"
    )
}

fn verify_owner(token: &PeerToken, owner_uid: u32) -> Result<(), MacIpcAuthError> {
    if token.effective_uid == owner_uid {
        Ok(())
    } else {
        Err(MacIpcAuthError::UserMismatch)
    }
}

#[cfg(any(not(feature = "development-unverified-local-ipc"), test))]
fn reduce_claims(claims: &CodeSignatureClaims, team_id: &str) -> Result<(), MacIpcAuthError> {
    const REQUIRED_EVIDENCE: u8 = ffi::CODE_EVIDENCE_EXTERNAL_REQUIREMENT
        | ffi::CODE_EVIDENCE_DESIGNATED_REQUIREMENT
        | ffi::CODE_EVIDENCE_CERTIFICATE_CHAIN
        | ffi::CODE_EVIDENCE_CMS;
    let expected_application_identifier = format!("{team_id}.{NODAVO_UI_IDENTIFIER}");
    let valid = claims.evidence & REQUIRED_EVIDENCE == REQUIRED_EVIDENCE
        && claims.evidence & ffi::CODE_EVIDENCE_GET_TASK_ALLOW == 0
        && claims.signing_identifier.as_deref() == Some(NODAVO_UI_IDENTIFIER)
        && claims.team_identifier.as_deref() == Some(team_id)
        && claims.secured_bundle_identifier.as_deref() == Some(NODAVO_UI_IDENTIFIER)
        && claims.application_identifier.as_deref()
            == Some(expected_application_identifier.as_str())
        && claims.static_flags & CODE_SIGNATURE_AD_HOC == 0
        && claims.static_flags & CODE_SIGNATURE_GET_TASK_ALLOW == 0
        && claims.static_flags & CODE_SIGNATURE_RUNTIME != 0
        && claims.dynamic_status & CODE_SIGNATURE_VALID != 0
        && claims.dynamic_status & CODE_STATUS_DEBUGGED == 0;
    if valid {
        Ok(())
    } else {
        Err(MacIpcAuthError::CodeSignatureRejected)
    }
}

#[derive(Clone, Eq, PartialEq)]
struct PeerToken {
    words: [u32; 8],
    effective_uid: u32,
}

#[cfg(any(not(feature = "development-unverified-local-ipc"), test))]
struct CodeSignatureClaims {
    signing_identifier: Option<String>,
    team_identifier: Option<String>,
    secured_bundle_identifier: Option<String>,
    application_identifier: Option<String>,
    static_flags: u32,
    dynamic_status: u32,
    evidence: u8,
}

trait PeerVerifier {
    fn peer_token(&self, socket: RawFd) -> Result<PeerToken, MacIpcAuthError>;

    #[cfg(any(not(feature = "development-unverified-local-ipc"), test))]
    fn code_signature_claims(
        &self,
        token: &PeerToken,
        requirement: &str,
    ) -> Result<CodeSignatureClaims, MacIpcAuthError>;
}

struct SystemPeerVerifier;

impl PeerVerifier for SystemPeerVerifier {
    fn peer_token(&self, socket: RawFd) -> Result<PeerToken, MacIpcAuthError> {
        let token =
            ffi::local_peer_token(socket).map_err(|()| MacIpcAuthError::PeerTokenUnavailable)?;
        Ok(PeerToken {
            words: token.words,
            effective_uid: token.effective_uid,
        })
    }

    #[cfg(any(not(feature = "development-unverified-local-ipc"), test))]
    fn code_signature_claims(
        &self,
        token: &PeerToken,
        requirement: &str,
    ) -> Result<CodeSignatureClaims, MacIpcAuthError> {
        let claims = ffi::peer_code_signature_claims(token.words, requirement)
            .map_err(|()| MacIpcAuthError::CodeSignatureRejected)?;
        Ok(CodeSignatureClaims {
            signing_identifier: claims.signing_identifier,
            team_identifier: claims.team_identifier,
            secured_bundle_identifier: claims.secured_bundle_identifier,
            application_identifier: claims.application_identifier,
            static_flags: claims.static_flags,
            dynamic_status: claims.dynamic_status,
            evidence: claims.evidence,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;
    use std::os::fd::AsRawFd as _;
    use std::os::unix::net::UnixStream;

    use super::*;

    const TEAM_ID: &str = "ABCDE12345";
    const OWNER_UID: u32 = 501;
    type ClaimsMutation = Box<dyn Fn(&mut CodeSignatureClaims)>;

    fn token(value: u32) -> PeerToken {
        PeerToken {
            words: [value; 8],
            effective_uid: OWNER_UID,
        }
    }

    fn valid_claims() -> CodeSignatureClaims {
        CodeSignatureClaims {
            signing_identifier: Some(NODAVO_UI_IDENTIFIER.to_owned()),
            team_identifier: Some(TEAM_ID.to_owned()),
            secured_bundle_identifier: Some(NODAVO_UI_IDENTIFIER.to_owned()),
            application_identifier: Some(format!("{TEAM_ID}.{NODAVO_UI_IDENTIFIER}")),
            static_flags: CODE_SIGNATURE_RUNTIME,
            dynamic_status: CODE_SIGNATURE_VALID,
            evidence: ffi::CODE_EVIDENCE_EXTERNAL_REQUIREMENT
                | ffi::CODE_EVIDENCE_DESIGNATED_REQUIREMENT
                | ffi::CODE_EVIDENCE_CERTIFICATE_CHAIN
                | ffi::CODE_EVIDENCE_CMS,
        }
    }

    struct FakeVerifier {
        tokens: RefCell<VecDeque<Result<PeerToken, MacIpcAuthError>>>,
        claims: RefCell<Option<Result<CodeSignatureClaims, MacIpcAuthError>>>,
        claim_calls: Cell<usize>,
    }

    impl FakeVerifier {
        fn signed(tokens: Vec<PeerToken>, claims: CodeSignatureClaims) -> Self {
            Self {
                tokens: RefCell::new(tokens.into_iter().map(Ok).collect()),
                claims: RefCell::new(Some(Ok(claims))),
                claim_calls: Cell::new(0),
            }
        }
    }

    impl PeerVerifier for FakeVerifier {
        fn peer_token(&self, _socket: RawFd) -> Result<PeerToken, MacIpcAuthError> {
            self.tokens
                .borrow_mut()
                .pop_front()
                .unwrap_or(Err(MacIpcAuthError::PeerTokenUnavailable))
        }

        fn code_signature_claims(
            &self,
            _token: &PeerToken,
            requirement: &str,
        ) -> Result<CodeSignatureClaims, MacIpcAuthError> {
            assert!(requirement.contains(NODAVO_UI_IDENTIFIER));
            assert!(requirement.contains(TEAM_ID));
            self.claim_calls.set(self.claim_calls.get() + 1);
            self.claims
                .borrow_mut()
                .take()
                .unwrap_or(Err(MacIpcAuthError::CodeSignatureRejected))
        }
    }

    #[test]
    fn signed_policy_accepts_only_complete_release_claims() {
        assert_eq!(reduce_claims(&valid_claims(), TEAM_ID), Ok(()));

        let cases: Vec<ClaimsMutation> = vec![
            Box::new(|claims| claims.evidence &= !ffi::CODE_EVIDENCE_EXTERNAL_REQUIREMENT),
            Box::new(|claims| claims.evidence &= !ffi::CODE_EVIDENCE_DESIGNATED_REQUIREMENT),
            Box::new(|claims| claims.signing_identifier = Some("dev.example.other".to_owned())),
            Box::new(|claims| claims.team_identifier = Some("ZZZZZ99999".to_owned())),
            Box::new(|claims| claims.secured_bundle_identifier = None),
            Box::new(|claims| claims.application_identifier = None),
            Box::new(|claims| claims.evidence &= !ffi::CODE_EVIDENCE_CERTIFICATE_CHAIN),
            Box::new(|claims| claims.evidence &= !ffi::CODE_EVIDENCE_CMS),
            Box::new(|claims| claims.static_flags |= CODE_SIGNATURE_AD_HOC),
            Box::new(|claims| claims.static_flags |= CODE_SIGNATURE_GET_TASK_ALLOW),
            Box::new(|claims| claims.static_flags &= !CODE_SIGNATURE_RUNTIME),
            Box::new(|claims| claims.dynamic_status &= !CODE_SIGNATURE_VALID),
            Box::new(|claims| claims.dynamic_status |= CODE_STATUS_DEBUGGED),
            Box::new(|claims| claims.evidence |= ffi::CODE_EVIDENCE_GET_TASK_ALLOW),
        ];
        for mutate in cases {
            let mut claims = valid_claims();
            mutate(&mut claims);
            assert_eq!(
                reduce_claims(&claims, TEAM_ID),
                Err(MacIpcAuthError::CodeSignatureRejected)
            );
        }
    }

    #[test]
    fn token_change_during_authentication_fails_before_dispatch() {
        let verifier = FakeVerifier::signed(vec![token(1), token(2)], valid_claims());
        let result = MacIpcPeerGuard::authenticate_with(
            &verifier,
            -1,
            OWNER_UID,
            VerificationPolicy::SignedUi { team_id: TEAM_ID },
        );
        assert!(matches!(result, Err(MacIpcAuthError::PeerIdentityChanged)));
        assert_eq!(verifier.claim_calls.get(), 1);
    }

    #[test]
    fn token_is_refetched_at_both_frame_gates() {
        let verifier =
            FakeVerifier::signed(vec![token(7), token(7), token(7), token(8)], valid_claims());
        let guard = MacIpcPeerGuard::authenticate_with(
            &verifier,
            -1,
            OWNER_UID,
            VerificationPolicy::SignedUi { team_id: TEAM_ID },
        )
        .unwrap();
        assert_eq!(guard.authorize_frame_gate_with(&verifier, -1), Ok(()));
        assert_eq!(
            guard.authorize_frame_gate_with(&verifier, -1),
            Err(MacIpcAuthError::PeerIdentityChanged)
        );
    }

    #[test]
    fn development_bypass_is_same_user_and_skips_signature_verification() {
        let verifier = FakeVerifier {
            tokens: RefCell::new(vec![token(3), token(3)].into_iter().map(Ok).collect()),
            claims: RefCell::new(None),
            claim_calls: Cell::new(0),
        };
        MacIpcPeerGuard::authenticate_with(
            &verifier,
            -1,
            OWNER_UID,
            VerificationPolicy::DevelopmentUnverifiedSameUser,
        )
        .unwrap();
        assert_eq!(verifier.claim_calls.get(), 0);

        let other_user = FakeVerifier::signed(
            vec![PeerToken {
                words: [4; 8],
                effective_uid: OWNER_UID + 1,
            }],
            valid_claims(),
        );
        assert!(matches!(
            MacIpcPeerGuard::authenticate_with(
                &other_user,
                -1,
                OWNER_UID,
                VerificationPolicy::DevelopmentUnverifiedSameUser,
            ),
            Err(MacIpcAuthError::UserMismatch)
        ));
    }

    #[test]
    fn same_user_adhoc_fixture_is_rejected_by_production_requirement() {
        let (client, server) = UnixStream::pair().unwrap();
        let owner_uid = SystemPeerVerifier
            .peer_token(server.as_raw_fd())
            .unwrap()
            .effective_uid;
        let result = MacIpcPeerGuard::authenticate_with(
            &SystemPeerVerifier,
            server.as_raw_fd(),
            owner_uid,
            VerificationPolicy::SignedUi { team_id: TEAM_ID },
        );
        drop(client);
        assert!(matches!(
            result,
            Err(MacIpcAuthError::CodeSignatureRejected)
        ));
    }

    #[test]
    fn fixed_requirement_is_developer_id_and_exact_identity() {
        let requirement = external_requirement(TEAM_ID);
        assert!(requirement.contains("anchor apple generic"));
        assert!(requirement.contains("identifier \"dev.nodavo.macos\""));
        assert!(requirement.contains("certificate leaf[subject.OU]"));
        assert!(requirement.contains("1.2.840.113635.100.6.2.6"));
        assert!(requirement.contains("1.2.840.113635.100.6.1.13"));
        assert!(!requirement.contains(" or "));
    }

    #[test]
    fn team_id_validation_is_exact_and_ascii() {
        assert!(valid_team_id(TEAM_ID));
        assert!(!valid_team_id("ABCDE1234"));
        assert!(!valid_team_id("abcde12345"));
        assert!(!valid_team_id("ABCDE1234-"));
    }
}
