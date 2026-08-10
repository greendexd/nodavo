use std::io;
use std::os::fd::AsRawFd as _;

use nodavo_platform_macos::{MacIpcPeerGuard, MacLocalIpcAuthMode, local_ipc_auth_mode};
use tokio::net::UnixStream;

use crate::FrameAuthorization;

pub(crate) struct SignedUiFrameAuthorization {
    guard: MacIpcPeerGuard,
    socket: i32,
}

pub(crate) fn authenticate_ui_connection(
    stream: &UnixStream,
    owner_uid: u32,
) -> Result<SignedUiFrameAuthorization, ()> {
    let socket = stream.as_raw_fd();
    let guard = MacIpcPeerGuard::authenticate(socket, owner_uid).map_err(|_| ())?;
    Ok(SignedUiFrameAuthorization { guard, socket })
}

pub(crate) fn ensure_local_ipc_auth_configured() -> Result<(), String> {
    match local_ipc_auth_mode() {
        Ok(MacLocalIpcAuthMode::DevelopmentUnverifiedUds) => {
            tracing::warn!(
                code = "development_unverified_local_ipc",
                "unsafe development-only same-user UDS local IPC bypass is compiled in"
            );
            Ok(())
        }
        Ok(MacLocalIpcAuthMode::XpcSignedMutual) | Err(_) => {
            Err("development UDS local IPC is not configured".to_owned())
        }
    }
}

pub(crate) fn local_ipc_self_check() -> Result<&'static str, ()> {
    match local_ipc_auth_mode().map_err(|_| ())? {
        MacLocalIpcAuthMode::DevelopmentUnverifiedUds => {
            Ok("nodavo-agent: development-unverified-uds-local-ipc")
        }
        MacLocalIpcAuthMode::XpcSignedMutual => Err(()),
    }
}

impl FrameAuthorization for SignedUiFrameAuthorization {
    fn authorize_frame_gate(&mut self) -> io::Result<()> {
        self.guard
            .authorize_frame_gate(self.socket)
            .map_err(|_| io::Error::from(io::ErrorKind::PermissionDenied))
    }
}
