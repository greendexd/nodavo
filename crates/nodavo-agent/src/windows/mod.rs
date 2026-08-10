//! Windows-only agent startup over DPAPI storage and a private named pipe.

mod platform;
mod storage;

use std::path::PathBuf;
use std::sync::Arc;

use nodavo_platform_windows::{
    create_private_named_pipe, current_user_agent_pipe_name, probe_environment,
    validate_named_pipe_client,
};
use tokio::signal;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use self::storage::WindowsDpapiStorage;
use crate::{initialize_runtime, serve_connection};

pub(crate) use self::platform::WindowsPlatformPort;

fn default_state_directory() -> Result<PathBuf, &'static str> {
    if let Some(path) = std::env::var_os("NODAVO_STATE_DIR") {
        return Ok(PathBuf::from(path));
    }
    let local_app_data = std::env::var_os("LOCALAPPDATA").ok_or("LOCALAPPDATA is not available")?;
    Ok(PathBuf::from(local_app_data).join("Nodavo"))
}

pub(super) async fn run_server() -> Result<(), String> {
    probe_environment().map_err(|_| "Windows interactive session is unavailable".to_owned())?;
    let pipe_name = current_user_agent_pipe_name()
        .map_err(|_| "failed to derive the private local IPC name".to_owned())?;
    let mut ipc_server = create_private_named_pipe(&pipe_name, true)
        .map_err(|_| "failed to create private local IPC".to_owned())?;
    let storage = Arc::new(WindowsDpapiStorage::new(
        default_state_directory().map_err(str::to_owned)?,
    ));
    let (pairing_listener, runtime, mdns) = initialize_runtime(storage).await?;

    let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
    info!("local IPC and pairing listeners are ready");
    loop {
        tokio::select! {
            signal = signal::ctrl_c() => {
                signal.map_err(|_| "failed to receive the shutdown signal".to_owned())?;
                break;
            }
            shutdown = shutdown_rx.recv() => {
                if shutdown.is_some() {
                    break;
                }
            }
            connected = ipc_server.connect() => {
                connected.map_err(|_| "local IPC accept failed".to_owned())?;
                if validate_named_pipe_client(&ipc_server).is_err() {
                    warn!(code = "local_ipc_peer_rejected", "local IPC peer was rejected");
                    ipc_server = create_private_named_pipe(&pipe_name, false)
                        .map_err(|_| "failed to renew private local IPC".to_owned())?;
                    continue;
                }

                let stream = ipc_server;
                ipc_server = create_private_named_pipe(&pipe_name, false)
                    .map_err(|_| "failed to renew private local IPC".to_owned())?;
                let runtime = Arc::clone(&runtime);
                let shutdown = shutdown_tx.clone();
                tokio::spawn(async move {
                    if let Err(error) = serve_connection(stream, runtime, shutdown).await {
                        error!(code = "local_ipc", %error, "local UI connection failed");
                    }
                });
            }
            accepted = pairing_listener.accept() => {
                let (stream, _) = accepted
                    .map_err(|_| "pairing preflight accept failed".to_owned())?;
                runtime.deliver_inbound(stream).await;
            }
        }
    }
    runtime.disconnect_all();
    drop(mdns);
    Ok(())
}
