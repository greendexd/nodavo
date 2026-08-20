mod clipboard_port;
mod clipboard_runtime;
mod input_wire;
#[cfg(target_os = "macos")]
mod macos;
mod native_bridge;
mod platform_port;
mod platform_readiness;
mod runtime;
mod session_runtime;
mod storage;
mod topology_runtime;
mod transfer_runtime;
mod transfer_status;
mod transfer_worker;
mod update;
#[cfg(target_os = "windows")]
mod windows;
mod wire;

#[cfg(any(
    test,
    target_os = "windows",
    all(unix, not(target_os = "macos")),
    all(target_os = "macos", feature = "development-unverified-local-ipc")
))]
use std::io;
use std::net::SocketAddr;
#[cfg(all(
    unix,
    any(not(target_os = "macos"), feature = "development-unverified-local-ipc")
))]
use std::os::unix::fs::MetadataExt as _;
#[cfg(unix)]
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

#[cfg(target_os = "macos")]
use self::macos::MacKeychainStorage;
use nodavo_discovery::{DiscoveryRecord, MdnsRuntime};
use nodavo_identity::{Capability as TrustedCapability, CapabilityGrants};
#[cfg(any(
    test,
    all(target_os = "macos", not(feature = "development-unverified-local-ipc"))
))]
use nodavo_local_ipc::MAX_IPC_MESSAGE_SIZE;
#[cfg(any(
    test,
    target_os = "windows",
    all(unix, not(target_os = "macos")),
    all(target_os = "macos", feature = "development-unverified-local-ipc")
))]
use nodavo_local_ipc::read_frame;
#[cfg(any(
    test,
    target_os = "windows",
    all(unix, not(target_os = "macos")),
    all(target_os = "macos", feature = "development-unverified-local-ipc")
))]
use nodavo_local_ipc::write_frame;
use nodavo_local_ipc::{AgentEvent, CapabilityName, UiCommand};
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

#[cfg(all(target_os = "macos", feature = "development-unverified-local-ipc"))]
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

#[cfg(target_os = "macos")]
fn configured_storage() -> Result<Arc<dyn DevelopmentStorage>, String> {
    let allow_development = std::env::var_os("NODAVO_ALLOW_INSECURE_DEVELOPMENT_STORAGE")
        .as_deref()
        == Some(std::ffi::OsStr::new("1"));
    if allow_development {
        warn!(
            code = "insecure_development_storage_enabled",
            "explicit development-only file storage is enabled"
        );
        Ok(Arc::new(FileDevelopmentStorage::new(
            default_state_directory().map_err(str::to_owned)?,
        )))
    } else {
        Ok(Arc::new(
            MacKeychainStorage::new().map_err(|error| error.to_string())?,
        ))
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
fn configured_storage() -> Result<Arc<dyn DevelopmentStorage>, String> {
    Ok(Arc::new(FileDevelopmentStorage::new(
        default_state_directory().map_err(str::to_owned)?,
    )))
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

const fn trusted_capability(capability: CapabilityName) -> TrustedCapability {
    match capability {
        CapabilityName::Input => TrustedCapability::RemoteInput,
        CapabilityName::ClipboardRead => TrustedCapability::ClipboardRead,
        CapabilityName::ClipboardWrite => TrustedCapability::ClipboardWrite,
        CapabilityName::Files => TrustedCapability::FileTransfer,
    }
}

#[cfg(any(
    test,
    target_os = "windows",
    all(unix, not(target_os = "macos")),
    all(target_os = "macos", feature = "development-unverified-local-ipc")
))]
trait FrameAuthorization {
    fn authorize_frame_gate(&mut self) -> io::Result<()>;
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
struct PreauthenticatedFrameAuthorization;

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
impl FrameAuthorization for PreauthenticatedFrameAuthorization {
    fn authorize_frame_gate(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(any(
    test,
    target_os = "windows",
    all(unix, not(target_os = "macos")),
    all(target_os = "macos", feature = "development-unverified-local-ipc")
))]
async fn read_authorized_command<S, A>(
    stream: &mut S,
    authorization: &mut A,
) -> Result<UiCommand, nodavo_local_ipc::IpcError>
where
    S: tokio::io::AsyncRead + Unpin,
    A: FrameAuthorization,
{
    authorization
        .authorize_frame_gate()
        .map_err(nodavo_local_ipc::IpcError::Io)?;
    let command = read_frame::<_, UiCommand>(stream).await?;
    authorization
        .authorize_frame_gate()
        .map_err(nodavo_local_ipc::IpcError::Io)?;
    Ok(command)
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
async fn serve_connection<S>(
    stream: S,
    runtime: Arc<AgentRuntime>,
    shutdown: mpsc::Sender<()>,
) -> Result<(), nodavo_local_ipc::IpcError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    serve_connection_authorized(
        stream,
        runtime,
        shutdown,
        PreauthenticatedFrameAuthorization,
    )
    .await
}

#[cfg(any(
    target_os = "windows",
    all(unix, not(target_os = "macos")),
    all(target_os = "macos", feature = "development-unverified-local-ipc")
))]
async fn serve_connection_authorized<S, A>(
    mut stream: S,
    runtime: Arc<AgentRuntime>,
    shutdown: mpsc::Sender<()>,
    mut authorization: A,
) -> Result<(), nodavo_local_ipc::IpcError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    A: FrameAuthorization,
{
    let event = serve_one_authorized_exchange(&mut stream, &mut authorization, |command| {
        dispatch_ui_command(command, runtime)
    })
    .await?;
    if matches!(event, AgentEvent::ShutdownAccepted) {
        let _ = shutdown.send(()).await;
    }
    Ok(())
}

#[cfg(any(
    test,
    target_os = "windows",
    all(unix, not(target_os = "macos")),
    all(target_os = "macos", feature = "development-unverified-local-ipc")
))]
async fn serve_one_authorized_exchange<S, A, D, F>(
    stream: &mut S,
    authorization: &mut A,
    dispatch: D,
) -> Result<AgentEvent, nodavo_local_ipc::IpcError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    A: FrameAuthorization,
    D: FnOnce(UiCommand) -> F,
    F: std::future::Future<Output = AgentEvent>,
{
    // Framed local transports intentionally carry exactly one request and one
    // response. Besides matching both native clients, this minimizes the
    // lifetime of an authorized Windows pipe capability and prevents a second
    // command from being appended to an already serviced connection.
    let command = read_authorized_command(stream, authorization).await?;
    let event = dispatch(command).await;
    write_frame(stream, &event).await?;
    await_framed_client_close(stream).await?;
    Ok(event)
}

#[cfg(any(
    test,
    target_os = "windows",
    all(unix, not(target_os = "macos")),
    all(target_os = "macos", feature = "development-unverified-local-ipc")
))]
async fn await_framed_client_close<S>(stream: &mut S) -> Result<(), nodavo_local_ipc::IpcError>
where
    S: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt as _;

    const CLOSE_ACK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
    let mut trailing = [0_u8; 1];
    match tokio::time::timeout(CLOSE_ACK_TIMEOUT, stream.read(&mut trailing)).await {
        Ok(Ok(0)) => Ok(()),
        Ok(Ok(_)) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "local IPC connection carried more than one request",
        )
        .into()),
        Ok(Err(error))
            if matches!(
                error.kind(),
                std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::NotConnected
                    | std::io::ErrorKind::UnexpectedEof
            ) =>
        {
            Ok(())
        }
        Ok(Err(error)) => Err(error.into()),
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "local IPC client did not close after its response",
        )
        .into()),
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "one exhaustive local IPC command dispatcher keeps authority routing auditable"
)]
async fn dispatch_ui_command(command: UiCommand, runtime: Arc<AgentRuntime>) -> AgentEvent {
    match command {
        UiCommand::GetStatus {} => AgentEvent::Status(runtime.refresh_platform_readiness().await),
        UiCommand::RequestAccessibilityPermission {} => {
            match runtime.request_accessibility_permission().await {
                Ok(status) => AgentEvent::Status(status),
                Err(error) => readiness_error_event(error),
            }
        }
        UiCommand::ListTrustedPeers {} => AgentEvent::TrustedPeers {
            peers: runtime.trusted_peers().await,
        },
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
            Ok(PairingOutcome::Pending | PairingOutcome::Failed(_)) => AgentEvent::Error {
                code: "pairing_failed".to_owned(),
                message: "pairing did not complete".to_owned(),
            },
            Err(error) => agent_error_event(&error),
        },
        UiCommand::SetCapability {
            peer_id,
            capability,
            enabled,
        } => match runtime
            .set_capability(&peer_id, trusted_capability(capability), enabled)
            .await
        {
            Ok(()) => AgentEvent::CapabilityChanged {
                peer_id,
                capability,
                enabled,
            },
            Err(error) => agent_error_event(&error),
        },
        UiCommand::SetPeerPlacement { peer_id, placement } => {
            match runtime.set_peer_placement(&peer_id, placement).await {
                Ok(()) => AgentEvent::PeerPlacementChanged { peer_id, placement },
                Err(error) => agent_error_event(&error),
            }
        }
        UiCommand::RevokePeer { peer_id } => match runtime.revoke_peer(&peer_id).await {
            Ok(()) => AgentEvent::Status(runtime.status().await),
            Err(error) => agent_error_event(&error),
        },
        UiCommand::SendFiles { paths } => match runtime.send_files(paths).await {
            Ok(transfer) => AgentEvent::TransferQueued {
                transfer_id: transfer.as_uuid().to_string(),
            },
            Err(error) => agent_error_event(&error),
        },
        UiCommand::ListTransfers {} => transfer_listing_event(runtime.transfer_listing()),
        UiCommand::CancelTransfer { transfer_id } => {
            match runtime.cancel_transfer(&transfer_id).await {
                Ok(listing) => transfer_listing_event(listing),
                Err(error) => agent_error_event(&error),
            }
        }
        UiCommand::RequestRemoteFocus { ttl_ms } => {
            match runtime.request_remote_focus(ttl_ms).await {
                Ok(status) => AgentEvent::Status(status),
                Err(error) => agent_error_event(&error),
            }
        }
        UiCommand::ReleaseFocus {} => match runtime.release_focus().await {
            Ok(status) => AgentEvent::Status(status),
            Err(error) => agent_error_event(&error),
        },
        UiCommand::LocalLocked {} => match runtime.local_locked().await {
            Ok(status) => AgentEvent::Status(status),
            Err(error) => agent_error_event(&error),
        },
        UiCommand::LocalSleeping {} => match runtime.local_sleeping().await {
            Ok(status) => AgentEvent::Status(status),
            Err(error) => agent_error_event(&error),
        },
        UiCommand::GetUpdateStatus {} => AgentEvent::UpdateStatus(update::coordinator().snapshot()),
        UiCommand::CheckForUpdate {} => {
            let coordinator = update::coordinator();
            match tokio::task::spawn_blocking(move || coordinator.check_for_update()).await {
                Ok(Ok(snapshot)) => AgentEvent::UpdateStatus(snapshot),
                Ok(Err(error)) => update_error_event(error),
                Err(_) => update_error_event(update::CoordinatorError::Internal),
            }
        }
        UiCommand::DecideUpdate { offer_id, accepted } => {
            let coordinator = update::coordinator();
            match coordinator.record_decision(&offer_id, accepted) {
                Ok(update::DecisionOutcome::Complete(snapshot)) => {
                    AgentEvent::UpdateStatus(snapshot)
                }
                Ok(update::DecisionOutcome::StartDownload { snapshot, token }) => {
                    let worker_coordinator = Arc::clone(&coordinator);
                    tokio::spawn(async move {
                        let blocking_coordinator = Arc::clone(&worker_coordinator);
                        let result = tokio::task::spawn_blocking(move || {
                            blocking_coordinator.download_offer(token)
                        })
                        .await;
                        if !matches!(result, Ok(Ok(_))) {
                            worker_coordinator.publish_internal_failure();
                        }
                    });
                    AgentEvent::UpdateStatus(snapshot)
                }
                Err(error) => update_error_event(error),
            }
        }
        UiCommand::EmergencyStop {} => match runtime.emergency_stop().await {
            Ok(status) => AgentEvent::Status(status),
            Err(error) => agent_error_event(&error),
        },
        UiCommand::Shutdown {} => match runtime.prepare_update_exit().await {
            Ok(_) => AgentEvent::ShutdownAccepted,
            Err(error) => agent_error_event(&error),
        },
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
    runtime.refresh_platform_readiness().await;

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
        AgentError::GrantEpochExhausted => "grant_epoch_exhausted",
        AgentError::ReceiveDestinationUnavailable => "receive_destination_unavailable",
        AgentError::PlacementApplyFailed => "placement_apply_failed",
        AgentError::PairingFailed => "pairing_failed",
        AgentError::NotConnected => "not_connected",
        AgentError::FocusRejected => "focus_rejected",
        AgentError::SafetyRecoveryFailed => "safety_recovery_failed",
        AgentError::TransferFailed => "transfer_failed",
        AgentError::TransferNotFound => "transfer_not_found",
        AgentError::TransferNotCancellable => "transfer_not_cancellable",
    };
    AgentEvent::Error {
        code: code.to_owned(),
        message: error.to_string(),
    }
}

fn transfer_listing_event(listing: crate::transfer_status::TransferListing) -> AgentEvent {
    AgentEvent::Transfers {
        instance_id: listing.instance_id,
        revision: listing.revision,
        truncated: listing.truncated,
        transfers: listing.transfers,
    }
}

fn readiness_error_event(error: platform_readiness::ReadinessRequestError) -> AgentEvent {
    let code = match error {
        #[cfg(not(target_os = "macos"))]
        platform_readiness::ReadinessRequestError::UnsupportedPlatform => "unsupported_platform",
        platform_readiness::ReadinessRequestError::ProbeUnavailable => "readiness_unavailable",
    };
    AgentEvent::Error {
        code: code.to_owned(),
        message: error.to_string(),
    }
}

fn update_error_event(error: update::CoordinatorError) -> AgentEvent {
    let code = match error {
        update::CoordinatorError::NotConfigured => "update_not_configured",
        update::CoordinatorError::Busy => "update_busy",
        update::CoordinatorError::OfferMismatch => "update_offer_mismatch",
        update::CoordinatorError::InvalidTransition => "update_invalid_transition",
        update::CoordinatorError::Internal => "update_internal",
    };
    AgentEvent::Error {
        code: code.to_owned(),
        message: error.to_string(),
    }
}

#[cfg(all(
    unix,
    any(not(target_os = "macos"), feature = "development-unverified-local-ipc")
))]
async fn run_server() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    macos::ensure_local_ipc_auth_configured()?;
    let storage = configured_storage()?;
    let ipc_path = default_ipc_path().map_err(str::to_owned)?;
    let ipc_listener =
        nodavo_local_ipc::unix::bind_private(&ipc_path).map_err(|error| error.to_string())?;
    let ipc_owner_uid = std::fs::metadata(&ipc_path)
        .map_err(|_| "failed to validate the local IPC owner".to_owned())?
        .uid();
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
                #[cfg(target_os = "macos")]
                let Ok(authorization) = macos::authenticate_ui_connection(&stream, ipc_owner_uid) else {
                    warn!(code = "local_ipc_peer_rejected", "local IPC peer was rejected");
                    continue;
                };
                let runtime = Arc::clone(&runtime);
                let shutdown = shutdown_tx.clone();
                #[cfg(target_os = "macos")]
                tokio::spawn(async move {
                    if let Err(error) = serve_connection_authorized(
                        stream,
                        runtime,
                        shutdown,
                        authorization,
                    ).await {
                        error!(code = "local_ipc", %error, "local UI connection failed");
                    }
                });
                #[cfg(not(target_os = "macos"))]
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

#[cfg(all(target_os = "macos", not(feature = "development-unverified-local-ipc")))]
async fn serve_xpc_request(
    request: nodavo_platform_macos::MacXpcRequest,
    runtime: Arc<AgentRuntime>,
    shutdown: mpsc::Sender<()>,
) {
    let (payload, reply) = request.into_parts();
    let Ok(command) = decode_xpc_command(&payload) else {
        return;
    };
    let event = dispatch_ui_command(command, runtime).await;
    let should_shutdown = matches!(event, AgentEvent::ShutdownAccepted);
    let Ok(payload) = serde_json::to_vec(&event) else {
        return;
    };
    if reply.send(&payload).is_err() {
        warn!(
            code = "local_xpc_reply_rejected",
            "local XPC reply was rejected"
        );
    }
    if should_shutdown {
        let _ = shutdown.send(()).await;
    }
}

#[cfg(any(
    test,
    all(target_os = "macos", not(feature = "development-unverified-local-ipc"))
))]
fn decode_xpc_command(payload: &[u8]) -> Result<UiCommand, ()> {
    if payload.is_empty() || payload.len() > MAX_IPC_MESSAGE_SIZE {
        return Err(());
    }
    serde_json::from_slice(payload).map_err(|_| ())
}

#[cfg(all(target_os = "macos", not(feature = "development-unverified-local-ipc")))]
async fn run_server() -> Result<(), String> {
    let mut xpc_server = macos::LocalXpcServer::start()?;
    let storage = configured_storage()?;
    let (pairing_listener, runtime, mdns) = initialize_runtime(storage).await?;
    let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
    let mut requests = tokio::task::JoinSet::new();
    let mut listener_failed = false;

    info!("signed XPC and pairing listeners are ready");
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
            event = xpc_server.receive() => {
                match event {
                    Some(nodavo_platform_macos::MacXpcEvent::Request(request)) => {
                        let runtime = Arc::clone(&runtime);
                        let shutdown = shutdown_tx.clone();
                        requests.spawn(async move {
                            let deadline = std::time::Duration::from_secs(350);
                            if tokio::time::timeout(
                                deadline,
                                serve_xpc_request(request, runtime, shutdown),
                            )
                            .await
                            .is_err()
                            {
                                warn!(
                                    code = "local_xpc_request_deadline",
                                    "local XPC request exceeded its hard deadline"
                                );
                            }
                        });
                    }
                    Some(nodavo_platform_macos::MacXpcEvent::ListenerInvalid) | None => {
                        listener_failed = true;
                        break;
                    }
                }
            }
            completed = requests.join_next(), if !requests.is_empty() => {
                if completed.is_some_and(|result| result.is_err()) {
                    warn!(code = "local_xpc_request_failed", "local XPC request task failed");
                }
            }
            accepted = pairing_listener.accept() => {
                let (stream, _) = accepted
                    .map_err(|_| "pairing preflight accept failed".to_owned())?;
                runtime.deliver_inbound(stream).await;
            }
        }
    }

    drop(xpc_server);
    requests.shutdown().await;
    runtime.disconnect_all();
    drop(mdns);
    if listener_failed {
        Err("signed XPC Mach service became unavailable".to_owned())
    } else {
        Ok(())
    }
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
            #[cfg(target_os = "macos")]
            {
                return if let Ok(message) = macos::local_ipc_self_check() {
                    println!("{message}");
                    ExitCode::SUCCESS
                } else {
                    eprintln!("nodavo-agent: signed XPC local authentication unavailable");
                    ExitCode::FAILURE
                };
            }
            #[cfg(target_os = "windows")]
            {
                return match nodavo_platform_windows::validate_compiled_windows_ui_auth_policy() {
                    Ok(
                        mode @ (nodavo_platform_windows::WindowsUiAuthMode::Development
                        | nodavo_platform_windows::WindowsUiAuthMode::Release),
                    ) => {
                        let mode = match mode {
                            nodavo_platform_windows::WindowsUiAuthMode::Development => {
                                "development"
                            }
                            nodavo_platform_windows::WindowsUiAuthMode::Release => "release",
                            nodavo_platform_windows::WindowsUiAuthMode::Unconfigured => {
                                unreachable!()
                            }
                        };
                        println!("nodavo-agent: core runtime available; windows-ui-auth={mode}");
                        ExitCode::SUCCESS
                    }
                    Ok(nodavo_platform_windows::WindowsUiAuthMode::Unconfigured) | Err(_) => {
                        eprintln!("nodavo-agent: packaged Windows UI authentication unavailable");
                        ExitCode::FAILURE
                    }
                };
            }
            #[cfg(not(any(target_os = "macos", target_os = "windows")))]
            {
                println!("nodavo-agent: core runtime available");
                return ExitCode::SUCCESS;
            }
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

#[cfg(test)]
mod local_ipc_authorization_tests {
    use std::cell::Cell;

    use super::*;
    use tokio::io::AsyncWriteExt as _;

    struct CountingAuthorization {
        calls: Cell<usize>,
        reject_at: usize,
    }

    impl FrameAuthorization for CountingAuthorization {
        fn authorize_frame_gate(&mut self) -> io::Result<()> {
            let next = self.calls.get() + 1;
            self.calls.set(next);
            if next == self.reject_at {
                Err(io::Error::from(io::ErrorKind::PermissionDenied))
            } else {
                Ok(())
            }
        }
    }

    fn encoded_command(command: &UiCommand) -> Vec<u8> {
        let payload = serde_json::to_vec(&command).unwrap();
        let mut frame = u32::try_from(payload.len()).unwrap().to_be_bytes().to_vec();
        frame.extend_from_slice(&payload);
        frame
    }

    #[test]
    fn receive_destination_pairing_failure_has_exact_content_free_ipc_error() {
        let event = agent_error_event(&AgentError::ReceiveDestinationUnavailable);
        let AgentEvent::Error { code, message } = event else {
            panic!("receive destination failure must remain a public error")
        };
        assert_eq!(code, "receive_destination_unavailable");
        assert_eq!(message, "the fixed receive destination is unavailable");
        assert!(!message.contains('/') && !message.contains('\\'));
    }

    #[tokio::test]
    async fn post_decode_gate_rejects_before_command_can_be_dispatched() {
        let frame = encoded_command(&UiCommand::Shutdown {});
        let mut input = frame.as_slice();
        let mut authorization = CountingAuthorization {
            calls: Cell::new(0),
            reject_at: 2,
        };

        let error = read_authorized_command(&mut input, &mut authorization)
            .await
            .expect_err("changed peer identity must block dispatch");

        assert!(matches!(
            error,
            nodavo_local_ipc::IpcError::Io(ref error)
                if error.kind() == io::ErrorKind::PermissionDenied
        ));
        assert_eq!(authorization.calls.get(), 2);
        assert!(input.is_empty());
    }

    #[tokio::test]
    async fn pre_read_gate_runs_before_untrusted_frame_decoding() {
        let frame = encoded_command(&UiCommand::Shutdown {});
        let original_length = frame.len();
        let mut input = frame.as_slice();
        let mut authorization = CountingAuthorization {
            calls: Cell::new(0),
            reject_at: 1,
        };

        let error = read_authorized_command(&mut input, &mut authorization)
            .await
            .expect_err("unauthorized peer must not reach frame decoding");

        assert!(matches!(
            error,
            nodavo_local_ipc::IpcError::Io(ref error)
                if error.kind() == io::ErrorKind::PermissionDenied
        ));
        assert_eq!(authorization.calls.get(), 1);
        assert_eq!(input.len(), original_length);
    }

    #[tokio::test]
    async fn framed_connection_services_exactly_one_exchange() {
        let first = encoded_command(&UiCommand::GetStatus {});
        let (mut client, mut server) = tokio::io::duplex(first.len() + 256);
        client.write_all(&first).await.unwrap();

        let dispatches = Cell::new(0_usize);
        let mut authorization = CountingAuthorization {
            calls: Cell::new(0),
            reject_at: usize::MAX,
        };
        let server_exchange =
            serve_one_authorized_exchange(&mut server, &mut authorization, |_| async {
                dispatches.set(dispatches.get() + 1);
                AgentEvent::ShutdownAccepted
            });
        let client_exchange = async {
            let response = nodavo_local_ipc::read_frame::<_, AgentEvent>(&mut client)
                .await
                .unwrap();
            assert_eq!(response, AgentEvent::ShutdownAccepted);
            drop(client);
        };
        let (event, ()) = tokio::join!(server_exchange, client_exchange);
        let event = event.unwrap();
        assert_eq!(event, AgentEvent::ShutdownAccepted);
        assert_eq!(dispatches.get(), 1);
        assert_eq!(authorization.calls.get(), 2);
    }

    #[tokio::test]
    async fn framed_connection_rejects_a_second_queued_request() {
        let first = encoded_command(&UiCommand::GetStatus {});
        let second = encoded_command(&UiCommand::Shutdown {});
        let (mut client, mut server) = tokio::io::duplex(first.len() + second.len() + 256);
        client.write_all(&first).await.unwrap();
        client.write_all(&second).await.unwrap();

        let dispatches = Cell::new(0_usize);
        let mut authorization = CountingAuthorization {
            calls: Cell::new(0),
            reject_at: usize::MAX,
        };
        let server_exchange =
            serve_one_authorized_exchange(&mut server, &mut authorization, |_| async {
                dispatches.set(dispatches.get() + 1);
                AgentEvent::ShutdownAccepted
            });
        let client_exchange = async {
            let response = nodavo_local_ipc::read_frame::<_, AgentEvent>(&mut client)
                .await
                .unwrap();
            assert_eq!(response, AgentEvent::ShutdownAccepted);
        };
        let (error, ()) = tokio::join!(server_exchange, client_exchange);
        let error = error.expect_err("a second request on one connection must be rejected");
        assert!(matches!(
            error,
            nodavo_local_ipc::IpcError::Io(ref error)
                if error.kind() == std::io::ErrorKind::InvalidData
        ));
        assert_eq!(dispatches.get(), 1);
        assert_eq!(authorization.calls.get(), 2);

        drop(client);
    }

    #[test]
    fn xpc_direct_decoder_rejects_unknown_fields_and_oversize() {
        assert!(decode_xpc_command(br#"{"command":"get_status"}"#).is_ok());
        assert!(
            decode_xpc_command(br#"{"command":"get_status","queued_before_exec":true}"#).is_err()
        );
        assert!(decode_xpc_command(&vec![b'x'; MAX_IPC_MESSAGE_SIZE + 1]).is_err());
    }
}
