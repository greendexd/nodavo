//! Release XPC ingress for the per-user launchd Mach service.

use nodavo_platform_macos::{
    MacLocalIpcAuthMode, MacXpcEvent, MacXpcListener, MacXpcRequest, local_ipc_auth_mode,
};
use tokio::sync::{mpsc, watch};

pub(crate) struct LocalXpcServer {
    _listener: MacXpcListener,
    requests: mpsc::Receiver<MacXpcRequest>,
    invalid: watch::Receiver<bool>,
}

impl LocalXpcServer {
    pub(crate) fn start() -> Result<Self, String> {
        if local_ipc_auth_mode() != Ok(MacLocalIpcAuthMode::XpcSignedMutual) {
            return Err("signed XPC local authentication is not configured".to_owned());
        }
        let (requests_tx, requests) = mpsc::channel(32);
        let (invalid_tx, invalid) = watch::channel(false);
        let listener = MacXpcListener::start(move |event| {
            match event {
                MacXpcEvent::Request(request) => {
                    // Failure/full drops the single-use reply and cancels the
                    // peer instead of growing an unbounded Rust-side queue.
                    let _ = requests_tx.try_send(request);
                }
                MacXpcEvent::ListenerInvalid => {
                    invalid_tx.send_replace(true);
                }
            }
        })
        .map_err(|_| "signed XPC Mach service is unavailable".to_owned())?;
        Ok(Self {
            _listener: listener,
            requests,
            invalid,
        })
    }

    pub(crate) async fn receive(&mut self) -> Option<MacXpcEvent> {
        if *self.invalid.borrow() {
            return Some(MacXpcEvent::ListenerInvalid);
        }
        tokio::select! {
            changed = self.invalid.changed() => {
                let _ = changed;
                Some(MacXpcEvent::ListenerInvalid)
            }
            request = self.requests.recv() => request.map(MacXpcEvent::Request),
        }
    }
}

pub(crate) fn local_ipc_self_check() -> Result<&'static str, ()> {
    match local_ipc_auth_mode().map_err(|_| ())? {
        MacLocalIpcAuthMode::XpcSignedMutual => Ok("nodavo-agent: xpc-signed-mutual-local-ipc"),
        MacLocalIpcAuthMode::DevelopmentUnverifiedUds => Err(()),
    }
}
