mod input_wire;
mod native_bridge;
mod platform_port;
mod runtime;
mod session_runtime;
mod storage;
#[cfg(target_os = "windows")]
mod windows;
mod wire;

use std::net::SocketAddr;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt as _;
#[cfg(unix)]
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use nodavo_discovery::{DiscoveryRecord, MdnsRuntime};
use nodavo_identity::{Capability as TrustedCapability, CapabilityGrants};
use nodavo_local_ipc::{AgentEvent, CapabilityName, UiCommand, read_frame, write_frame};
use runtime::{AgentError, AgentRuntime, PairingOutcome};
use storage::DevelopmentStorage;
#[cfg(unix)]
use storage::FileDevelopmentStorage;
#[cfg(unix)]
use tokio::signal;
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

const PRODUCT_NAME: &str = "Nodavo";

fn print_help() {
    println!(
        "{PRODUCT_NAME} session agent\n\nUSAGE:\n    nodavo-agent [--help | --version | --self-check]\n\nPAIRING IPC:\n    begin_pairing endpoint=listen\n    begin_pairing endpoint=<IP:PORT>\n    begin_pairing endpoint=mdns:<INSTANCE>\n\nPINNED RECONNECT IPC:\n    begin_pairing endpoint=reconnect-listen:<PEER_ID>\n    begin_pairing endpoint=reconnect:<PEER_ID>[@<IP:PORT>|@mdns:<INSTANCE>]"
    );
}

fn init_logging() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .without_time()
        .compact()
        .init();
}

#[cfg(target_os = "macos")]
fn default_ipc_path() -> Result<PathBuf, &'static str> {
    if let Some(path) = std::env::var_os("NODAVO_IPC_PATH") {
        return Ok(PathBuf::from(path));
    }
    let home = std::env::var_os("HOME").ok_or("HOME is not available")?;
    Ok(PathBuf::from(home)
        .join("Library")
        .join("Application Support")
        .join("Nodavo")
        .join("agent.sock"))
}

#[cfg(all(unix, not(target_os = "macos")))]
fn default_ipc_path() -> Result<PathBuf, &'static str> {
    if let Some(path) = std::env::var_os("NODAVO_IPC_PATH") {
        return Ok(PathBuf::from(path));
    }
    let home = std::env::var_os("HOME").ok_or("HOME is not available")?;
    Ok(PathBuf::from(home)
        .join(".local")
        .join("state")
        .join("nodavo")
        .join("agent.sock"))
}

#[cfg(target_os = "macos")]
fn default_state_directory() -> Result<PathBuf, &'static str> {
    if let Some(path) = std::env::var_os("NODAVO_STATE_DIR") {
        return Ok(PathBuf::from(path));
    }
    let home = std::env::var_os("HOME").ok_or("HOME is not available")?;
    Ok(PathBuf::from(home)
        .join("Library")
        .join("Application Support")
        .join("Nodavo"))
}

#[cfg(all(unix, not(target_os = "macos")))]
fn default_state_directory() -> Result<PathBuf, &'static str> {
    if let Some(path) = std::env::var_os("NODAVO_STATE_DIR") {
        return Ok(PathBuf::from(path));
    }
    let home = std::env::var_os("HOME").ok_or("HOME is not available")?;
    Ok(PathBuf::from(home)
        .join(".local")
        .join("state")
        .join("nodavo"))
}

fn configured_pairing_address() -> Result<SocketAddr, String> {
    std::env::var("NODAVO_PAIRING_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:44310".to_owned())
        .parse()
        .map_err(|_| "NODAVO_PAIRING_ADDR is not a valid socket address".to_owned())
}

fn configured_device_name() -> Result<String, String> {
    let value = std::env::var("NODAVO_DEVICE_NAME")
        .unwrap_or_else(|_| format!("Nodavo-{}", std::process::id()));
    if value.is_empty()
        || value.len() > 63
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        Err("NODAVO_DEVICE_NAME is invalid".to_owned())
    } else {
        Ok(value)
    }
}

fn requested_grants(capabilities: &[CapabilityName]) -> CapabilityGrants {
    capabilities
        .iter()
        .fold(CapabilityGrants::NONE, |grants, capability| {
            grants.with(match capability {
                CapabilityName::Input => TrustedCapability::RemoteInput,
                CapabilityName::ClipboardRead => TrustedCapability::ClipboardRead,
                CapabilityName::ClipboardWrite => TrustedCapability::ClipboardWrite,
                CapabilityName::Files => TrustedCapability::FileTransfer,
            })
        })
}

async fn serve_connection<S>(
    mut stream: S,
    runtime: Arc<AgentRuntime>,
    shutdown: mpsc::Sender<()>,
) -> Result<(), nodavo_local_ipc::IpcError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    loop {
        let command = match read_frame::<_, UiCommand>(&mut stream).await {
            Ok(command) => command,
            Err(nodavo_local_ipc::IpcError::Closed) => return Ok(()),
            Err(error) => return Err(error),
        };

        let event = match command {
            UiCommand::GetStatus => AgentEvent::Status(runtime.status().await),
            UiCommand::BeginPairing {
                endpoint,
                capabilities,
            } => {
                if AgentRuntime::is_reconnect_request(&endpoint) {
                    match runtime.reconnect(&endpoint).await {
                        Ok(status) => AgentEvent::Status(status),
                        Err(error) => agent_error_event(&error),
                    }
                } else {
                    match runtime
                        .begin_pairing(endpoint, requested_grants(&capabilities))
                        .await
                    {
                        Ok(started) => AgentEvent::PairingCode {
                            pairing_id: started.pairing_id,
                            peer_name: started.peer_name,
                            code: started.code,
                        },
                        Err(error) => agent_error_event(&error),
                    }
                }
            }
            UiCommand::ConfirmPairing {
                pairing_id,
                accepted,
            } => match runtime.confirm_pairing(&pairing_id, accepted).await {
                Ok(PairingOutcome::Finished(paired)) => {
                    AgentEvent::PairingFinished { pairing_id, paired }
                }
                Ok(PairingOutcome::Pending | PairingOutcome::Failed) => AgentEvent::Error {
                    code: "pairing_failed".to_owned(),
                    message: "pairing did not complete".to_owned(),
                },
                Err(error) => agent_error_event(&error),
            },
            UiCommand::SetCapability { .. } => AgentEvent::Error {
                code: "not_available".to_owned(),
                message: "capability changes require a signed peer update protocol".to_owned(),
            },
            UiCommand::RevokePeer { peer_id } => match runtime.revoke_peer(&peer_id).await {
                Ok(()) => AgentEvent::Status(runtime.status().await),
                Err(error) => agent_error_event(&error),
            },
            UiCommand::RequestRemoteFocus { ttl_ms } => {
                match runtime.request_remote_focus(ttl_ms).await {
                    Ok(status) => AgentEvent::Status(status),
                    Err(error) => agent_error_event(&error),
                }
            }
            UiCommand::ReleaseFocus => match runtime.release_focus().await {
                Ok(status) => AgentEvent::Status(status),
                Err(error) => agent_error_event(&error),
            },
            UiCommand::LocalLocked => match runtime.local_locked().await {
                Ok(status) => AgentEvent::Status(status),
                Err(error) => agent_error_event(&error),
            },
            UiCommand::LocalSleeping => match runtime.local_sleeping().await {
                Ok(status) => AgentEvent::Status(status),
                Err(error) => agent_error_event(&error),
            },
            UiCommand::EmergencyStop => match runtime.emergency_stop().await {
                Ok(status) => AgentEvent::Status(status),
                Err(error) => agent_error_event(&error),
            },
            UiCommand::Shutdown => {
                runtime.disconnect_all();
                let _ = shutdown.send(()).await;
                AgentEvent::ShutdownAccepted
            }
        };
        write_frame(&mut stream, &event).await?;
        if matches!(event, AgentEvent::ShutdownAccepted) {
            return Ok(());
        }
    }
}

async fn initialize_runtime(
    storage: Arc<dyn DevelopmentStorage>,
) -> Result<
    (
        tokio::net::TcpListener,
        Arc<AgentRuntime>,
        Option<MdnsRuntime>,
    ),
    String,
> {
    let pairing_listener = tokio::net::TcpListener::bind(configured_pairing_address()?)
        .await
        .map_err(|_| "failed to bind the pairing preflight listener".to_owned())?;
    let pairing_address = pairing_listener
        .local_addr()
        .map_err(|_| "failed to read the pairing listener address".to_owned())?;
    let material = storage
        .load_or_create_identity()
        .map_err(|error| error.to_string())?;
    let peers = storage.load_peers().map_err(|error| error.to_string())?;
    let runtime = AgentRuntime::new(
        storage,
        material,
        peers,
        pairing_address,
        configured_device_name()?,
    );

    let mut mdns = None;
    if std::env::var_os("NODAVO_DISABLE_MDNS").is_none() {
        let instance = std::env::var("NODAVO_MDNS_INSTANCE")
            .unwrap_or_else(|_| format!("Nodavo-{}", std::process::id()));
        let host = std::env::var("NODAVO_MDNS_HOST").unwrap_or_else(|_| "nodavo.local.".to_owned());
        if let Ok(value) = DiscoveryRecord::new(
            instance,
            pairing_address.port(),
            wire::PAIRING_PROTOCOL_VERSION,
        )
        .and_then(|record| {
            let mut value = MdnsRuntime::new()?;
            value.advertise(&record, &host)?;
            Ok(value)
        }) {
            mdns = Some(value);
        } else {
            warn!(
                code = "mdns_unavailable",
                "mDNS advertisement is unavailable"
            );
        }
    }
    Ok((pairing_listener, runtime, mdns))
}

fn agent_error_event(error: &AgentError) -> AgentEvent {
    let code = match error {
        AgentError::Busy => "busy",
        AgentError::InvalidEndpoint => "invalid_endpoint",
        AgentError::DiscoveryUnavailable => "discovery_unavailable",
        AgentError::PairingTimedOut => "pairing_timed_out",
        AgentError::ReconnectFailed => "reconnect_failed",
        AgentError::PairingNotFound => "pairing_not_found",
        AgentError::AlreadyConfirmed => "already_confirmed",
        AgentError::PeerNotFound => "peer_not_found",
        AgentError::Storage => "storage_unavailable",
        AgentError::PairingFailed => "pairing_failed",
        AgentError::NotConnected => "not_connected",
        AgentError::FocusRejected => "focus_rejected",
        AgentError::SafetyRecoveryFailed => "safety_recovery_failed",
    };
    AgentEvent::Error {
        code: code.to_owned(),
        message: error.to_string(),
    }
}

#[cfg(unix)]
async fn run_server() -> Result<(), String> {
    let ipc_path = default_ipc_path().map_err(str::to_owned)?;
    let ipc_listener =
        nodavo_local_ipc::unix::bind_private(&ipc_path).map_err(|error| error.to_string())?;
    let ipc_owner_uid = std::fs::metadata(&ipc_path)
        .map_err(|_| "failed to validate the local IPC owner".to_owned())?
        .uid();
    let storage = Arc::new(FileDevelopmentStorage::new(
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
            accepted = ipc_listener.accept() => {
                let (stream, _) = accepted.map_err(|_| "local IPC accept failed".to_owned())?;
                let peer_uid = stream.peer_cred()
                    .map_err(|_| "failed to validate local IPC peer credentials".to_owned())?
                    .uid();
                if peer_uid != ipc_owner_uid {
                    warn!(code = "local_ipc_peer_rejected", "local IPC peer was rejected");
                    continue;
                }
                let runtime = Arc::clone(&runtime);
                let shutdown = shutdown_tx.clone();
                tokio::spawn(async move {
                    if let Err(error) = serve_connection(stream, runtime, shutdown).await {
                        error!(code = "local_ipc", %error, "local UI connection failed");
                    }
                });
            }
            accepted = pairing_listener.accept() => {
                let (stream, _) = accepted.map_err(|_| "pairing preflight accept failed".to_owned())?;
                runtime.deliver_inbound(stream).await;
            }
        }
    }
    runtime.disconnect_all();
    drop(mdns);
    let _ = std::fs::remove_file(ipc_path);
    Ok(())
}

#[cfg(target_os = "windows")]
async fn run_server() -> Result<(), String> {
    windows::run_server().await
}

#[tokio::main]
async fn main() -> ExitCode {
    let mut arguments = std::env::args().skip(1);
    match arguments.next().as_deref() {
        Some("--help" | "-h") => {
            print_help();
            return ExitCode::SUCCESS;
        }
        Some("--version" | "-V") => {
            println!("nodavo-agent {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Some("--self-check") => {
            println!("nodavo-agent: core runtime available");
            return ExitCode::SUCCESS;
        }
        Some(argument) => {
            eprintln!("unknown argument: {argument}");
            print_help();
            return ExitCode::from(2);
        }
        None => {}
    }

    init_logging();
    info!(
        version = env!("CARGO_PKG_VERSION"),
        "session agent starting"
    );
    match run_server().await {
        Ok(()) => {
            info!("session agent stopped");
            ExitCode::SUCCESS
        }
        Err(error) => {
            error!(code = "agent_startup", %error, "session agent failed");
            ExitCode::FAILURE
        }
    }
}
