//! Tokio/Quinn implementation of the runtime-neutral transport contract.
//!
//! Pairing certificates are ephemeral, explicitly exchanged before connecting,
//! and remain untrusted until the exporter-bound SAS is confirmed. Persistent
//! sessions consume only certificate bindings authenticated by a committed
//! pairing. There is no certificate-verification bypass or TOFU path.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use nodavo_identity::VerifiedPeerTransportBinding;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{Connection, RecvStream, SendStream, VarInt};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{RootCertStore, version::TLS13};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::{
    AuthMode, BoxFuture, ChannelDirection, ChannelId, ChannelKind, CloseReason,
    DatagramAvailability, DatagramLimit, Endpoint, MAX_DATAGRAM_PAYLOAD_BYTES,
    MAX_KEYING_MATERIAL_BYTES, MAX_OPEN_CHANNELS, MAX_RELIABLE_FRAME_BYTES,
    MIN_KEYING_MATERIAL_BYTES, PeerConnection, Transport, TransportCommand, TransportError,
    TransportEvent,
};

const FRAME_MAGIC: [u8; 4] = *b"NDVO";
const FRAME_VERSION: u8 = 1;
const CHANNEL_HEADER_BYTES: usize = 7;
const FRAME_HEADER_BYTES: usize = 5;
const END_OF_STREAM_FLAG: u8 = 1;
const EVENT_QUEUE_CAPACITY: usize = MAX_OPEN_CHANNELS * 2;
const MAX_CERTIFICATE_CHAIN_LENGTH: usize = 8;
const MAX_CERTIFICATE_DER_BYTES: usize = 64 * 1024;
const MAX_PRIVATE_KEY_DER_BYTES: usize = 16 * 1024;
const STREAM_WINDOW_BYTES: u32 = 2 * 1024 * 1024;
const CONNECTION_WINDOW_BYTES: u32 = STREAM_WINDOW_BYTES * 4;
const DATAGRAM_BUFFER_BYTES: usize = MAX_DATAGRAM_PAYLOAD_BYTES * 64;
const DEFAULT_OPERATION_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CONFIGURED_TIMEOUT: Duration = Duration::from_mins(5);
const PAIRING_ALPN_PREFIX: &[u8] = b"nodavo/pairing/";
const PINNED_ALPN: &[u8] = b"nodavo/pinned/1";

/// A DER certificate chain and PKCS#8 private key owned by the backend.
///
/// This type deliberately does not implement `Debug` or `Clone`, so private
/// key bytes are neither formatted nor duplicated accidentally.
pub struct CertificateCredentials {
    certificate_chain_der: Vec<Vec<u8>>,
    private_key_pkcs8_der: Vec<u8>,
}

impl CertificateCredentials {
    /// Creates credentials from a bounded certificate chain and PKCS#8 key.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::InvalidConfiguration`] when an input is empty
    /// or exceeds the backend's certificate, chain, or key limits.
    pub fn from_der(
        certificate_chain_der: Vec<Vec<u8>>,
        private_key_pkcs8_der: Vec<u8>,
    ) -> Result<Self, TransportError> {
        validate_certificate_chain(&certificate_chain_der)?;
        if private_key_pkcs8_der.is_empty()
            || private_key_pkcs8_der.len() > MAX_PRIVATE_KEY_DER_BYTES
        {
            return Err(TransportError::InvalidConfiguration);
        }
        Ok(Self {
            certificate_chain_der,
            private_key_pkcs8_der,
        })
    }

    fn into_rustls(self) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        let certificates = self
            .certificate_chain_der
            .into_iter()
            .map(CertificateDer::from)
            .collect();
        let private_key = PrivatePkcs8KeyDer::from(self.private_key_pkcs8_der).into();
        (certificates, private_key)
    }
}

/// Fresh self-signed TLS identity used only for an explicit pairing attempt.
pub struct EphemeralPairingIdentity {
    server_name: String,
    certificate_der: Vec<u8>,
    credentials: CertificateCredentials,
}

impl EphemeralPairingIdentity {
    /// Generates a fresh certificate and key for one pairing attempt.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::InvalidConfiguration`] for an invalid DNS
    /// name or if certificate generation fails.
    pub fn generate(server_name: impl Into<String>) -> Result<Self, TransportError> {
        let server_name = validate_server_name(server_name.into())?;
        let generated = rcgen::generate_simple_self_signed(vec![server_name.clone()])
            .map_err(|_| TransportError::InvalidConfiguration)?;
        let certificate_der = generated.cert.der().to_vec();
        let credentials = CertificateCredentials::from_der(
            vec![certificate_der.clone()],
            generated.signing_key.serialize_der(),
        )?;
        Ok(Self {
            server_name,
            certificate_der,
            credentials,
        })
    }

    /// DER leaf certificate to exchange as untrusted pairing metadata.
    #[must_use]
    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate_der
    }

    #[must_use]
    pub fn server_name(&self) -> &str {
        &self.server_name
    }
}

/// Configuration for one explicitly untrusted, exporter-bound pairing link.
pub struct EphemeralPairingConfiguration {
    protocol_version: u16,
    local_identity: EphemeralPairingIdentity,
    expected_peer_certificate_der: Vec<u8>,
    peer_server_name: String,
}

impl EphemeralPairingConfiguration {
    /// Binds a fresh local identity to the peer certificate exchanged for this
    /// explicit pairing attempt.
    ///
    /// # Errors
    ///
    /// Returns an error for protocol version zero, an invalid peer DNS name,
    /// or an empty or oversized peer certificate.
    pub fn new(
        protocol_version: u16,
        local_identity: EphemeralPairingIdentity,
        expected_peer_certificate_der: Vec<u8>,
        peer_server_name: impl Into<String>,
    ) -> Result<Self, TransportError> {
        AuthMode::pairing(protocol_version)?;
        validate_certificate(&expected_peer_certificate_der)?;
        let peer_server_name = validate_server_name(peer_server_name.into())?;
        Ok(Self {
            protocol_version,
            local_identity,
            expected_peer_certificate_der,
            peer_server_name,
        })
    }
}

/// Persistent mutual-TLS configuration for a pairing-authenticated peer.
pub struct PinnedMutualConfiguration {
    local_credentials: CertificateCredentials,
    expected_peer_certificate_der: Vec<u8>,
    expected_peer_public_key: [u8; crate::PEER_PUBLIC_KEY_BYTES],
    peer_server_name: String,
}

impl PinnedMutualConfiguration {
    /// Creates a configuration only when the supplied DER exactly matches the
    /// binding issued by committed trust.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::AuthenticationFailed`] for certificate
    /// substitution. Invalid DNS names and certificate bounds return
    /// [`TransportError::InvalidConfiguration`].
    pub fn new(
        local_credentials: CertificateCredentials,
        verified_peer: &VerifiedPeerTransportBinding,
        expected_peer_certificate_der: Vec<u8>,
        peer_server_name: impl Into<String>,
    ) -> Result<Self, TransportError> {
        validate_certificate(&expected_peer_certificate_der)?;
        if !verified_peer.matches_certificate_der(&expected_peer_certificate_der) {
            return Err(TransportError::AuthenticationFailed);
        }
        let peer_server_name = validate_server_name(peer_server_name.into())?;
        Ok(Self {
            local_credentials,
            expected_peer_certificate_der,
            expected_peer_public_key: *verified_peer.peer_identity().public_key_bytes(),
            peer_server_name,
        })
    }
}

/// Fixed hardening and deadline parameters for the Quinn backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuinnBackendOptions {
    operation_timeout: Duration,
    idle_timeout: Duration,
}

impl QuinnBackendOptions {
    /// Creates bounded operation and idle deadlines.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::InvalidConfiguration`] when either timeout is
    /// zero or exceeds five minutes.
    pub fn new(
        operation_timeout: Duration,
        idle_timeout: Duration,
    ) -> Result<Self, TransportError> {
        if operation_timeout.is_zero()
            || idle_timeout.is_zero()
            || operation_timeout > MAX_CONFIGURED_TIMEOUT
            || idle_timeout > MAX_CONFIGURED_TIMEOUT
        {
            return Err(TransportError::InvalidConfiguration);
        }
        Ok(Self {
            operation_timeout,
            idle_timeout,
        })
    }

    #[must_use]
    pub const fn operation_timeout(self) -> Duration {
        self.operation_timeout
    }

    #[must_use]
    pub const fn idle_timeout(self) -> Duration {
        self.idle_timeout
    }
}

impl Default for QuinnBackendOptions {
    fn default() -> Self {
        Self {
            operation_timeout: DEFAULT_OPERATION_TIMEOUT,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
        }
    }
}

#[derive(Clone, Copy)]
enum ConfiguredAuth {
    Pairing(u16),
    Pinned([u8; crate::PEER_PUBLIC_KEY_BYTES]),
}

impl ConfiguredAuth {
    fn matches(self, requested: &AuthMode) -> bool {
        match (self, requested) {
            (Self::Pairing(configured), AuthMode::Pairing { protocol_version }) => {
                configured == *protocol_version
            }
            (
                Self::Pinned(configured),
                AuthMode::PinnedMutual {
                    expected_peer_public_key,
                },
            ) => configured == *expected_peer_public_key,
            _ => false,
        }
    }
}

/// A bound Tokio/Quinn endpoint with one immutable inbound authentication mode.
pub struct QuinnTransport {
    endpoint: quinn::Endpoint,
    client_config: quinn::ClientConfig,
    expected_peer_certificate_der: Arc<[u8]>,
    peer_server_name: String,
    configured_auth: ConfiguredAuth,
    operation_timeout: Duration,
}

impl QuinnTransport {
    /// Binds an endpoint for one explicitly untrusted pairing attempt.
    ///
    /// # Errors
    ///
    /// Returns an error when the bind address or TLS material is invalid, or
    /// when the UDP socket cannot be bound.
    pub fn bind_ephemeral_pairing(
        bind_address: SocketAddr,
        configuration: EphemeralPairingConfiguration,
        options: QuinnBackendOptions,
    ) -> Result<Self, TransportError> {
        let alpn = pairing_alpn(configuration.protocol_version);
        let local_credentials = configuration.local_identity.credentials;
        Self::bind(
            bind_address,
            local_credentials,
            configuration.expected_peer_certificate_der,
            configuration.peer_server_name,
            ConfiguredAuth::Pairing(configuration.protocol_version),
            alpn,
            options,
        )
    }

    /// Binds an endpoint for certificate-pinned TLS 1.3 mutual authentication.
    ///
    /// # Errors
    ///
    /// Returns an error when the bind address or authenticated TLS material is
    /// invalid, or when the UDP socket cannot be bound.
    pub fn bind_pinned_mutual(
        bind_address: SocketAddr,
        configuration: PinnedMutualConfiguration,
        options: QuinnBackendOptions,
    ) -> Result<Self, TransportError> {
        Self::bind(
            bind_address,
            configuration.local_credentials,
            configuration.expected_peer_certificate_der,
            configuration.peer_server_name,
            ConfiguredAuth::Pinned(configuration.expected_peer_public_key),
            PINNED_ALPN.to_vec(),
            options,
        )
    }

    fn bind(
        bind_address: SocketAddr,
        local_credentials: CertificateCredentials,
        expected_peer_certificate_der: Vec<u8>,
        peer_server_name: String,
        configured_auth: ConfiguredAuth,
        alpn: Vec<u8>,
        options: QuinnBackendOptions,
    ) -> Result<Self, TransportError> {
        validate_bind_address(bind_address)?;
        validate_certificate(&expected_peer_certificate_der)?;
        let exact_peer_certificate_der = Arc::from(expected_peer_certificate_der.clone());

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let peer_roots = peer_root_store(expected_peer_certificate_der)?;
        let (local_chain, local_key) = local_credentials.into_rustls();
        let client_verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(peer_roots.clone()),
            Arc::clone(&provider),
        )
        .build()
        .map_err(|_| TransportError::InvalidConfiguration)?;

        let mut server_crypto = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_protocol_versions(&[&TLS13])
            .map_err(|_| TransportError::InvalidConfiguration)?
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(local_chain.clone(), local_key.clone_key())
            .map_err(|_| TransportError::InvalidConfiguration)?;
        server_crypto.alpn_protocols = vec![alpn.clone()];
        server_crypto.max_early_data_size = 0;

        let mut client_crypto = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&TLS13])
            .map_err(|_| TransportError::InvalidConfiguration)?
            .with_root_certificates(peer_roots)
            .with_client_auth_cert(local_chain, local_key)
            .map_err(|_| TransportError::InvalidConfiguration)?;
        client_crypto.alpn_protocols = vec![alpn];
        client_crypto.enable_early_data = false;

        let transport = transport_config(options)?;
        let server_crypto = QuicServerConfig::try_from(server_crypto)
            .map_err(|_| TransportError::InvalidConfiguration)?;
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(server_crypto));
        server_config.transport = Arc::clone(&transport);

        let client_crypto = QuicClientConfig::try_from(client_crypto)
            .map_err(|_| TransportError::InvalidConfiguration)?;
        let mut client_config = quinn::ClientConfig::new(Arc::new(client_crypto));
        client_config.transport_config(transport);

        let endpoint = quinn::Endpoint::server(server_config, bind_address)
            .map_err(|_| TransportError::Backend)?;
        Ok(Self {
            endpoint,
            client_config,
            expected_peer_certificate_der: exact_peer_certificate_der,
            peer_server_name,
            configured_auth,
            operation_timeout: options.operation_timeout,
        })
    }

    /// Actual bound UDP address, including an OS-assigned port when binding to port zero.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Backend`] if the socket address is unavailable.
    pub fn local_address(&self) -> Result<SocketAddr, TransportError> {
        self.endpoint
            .local_addr()
            .map_err(|_| TransportError::Backend)
    }

    fn finish_connection(
        connection: Connection,
        operation_timeout: Duration,
        expected_peer_certificate_der: &[u8],
    ) -> Result<Box<dyn PeerConnection>, TransportError> {
        if !peer_leaf_matches(&connection, expected_peer_certificate_der) {
            connection.close(
                close_code(CloseReason::AuthenticationFailed),
                close_reason_bytes(CloseReason::AuthenticationFailed),
            );
            return Err(TransportError::AuthenticationFailed);
        }
        Ok(Box::new(QuinnPeerConnection::new(
            connection,
            operation_timeout,
        )?))
    }
}

impl Transport for QuinnTransport {
    fn connect(
        &self,
        endpoint: Endpoint,
        auth: AuthMode,
    ) -> BoxFuture<'_, Result<Box<dyn PeerConnection>, TransportError>> {
        Box::pin(async move {
            if !self.configured_auth.matches(&auth) {
                return Err(TransportError::AuthenticationFailed);
            }
            let connecting = self
                .endpoint
                .connect_with(
                    self.client_config.clone(),
                    endpoint.address(),
                    &self.peer_server_name,
                )
                .map_err(|_| TransportError::InvalidConfiguration)?;
            let connection = timeout(self.operation_timeout, connecting)
                .await
                .map_err(|_| TransportError::TimedOut)?
                .map_err(|error| map_handshake_error(&error))?;
            Self::finish_connection(
                connection,
                self.operation_timeout,
                &self.expected_peer_certificate_der,
            )
        })
    }

    fn accept(&self) -> BoxFuture<'_, Result<Box<dyn PeerConnection>, TransportError>> {
        Box::pin(async move {
            let incoming = timeout(self.operation_timeout, self.endpoint.accept())
                .await
                .map_err(|_| TransportError::TimedOut)?
                .ok_or(TransportError::Closed)?;
            let connection = timeout(self.operation_timeout, incoming)
                .await
                .map_err(|_| TransportError::TimedOut)?
                .map_err(|error| map_handshake_error(&error))?;
            Self::finish_connection(
                connection,
                self.operation_timeout,
                &self.expected_peer_certificate_der,
            )
        })
    }
}

struct ChannelState {
    send: Option<SendStream>,
    receive_open: bool,
    _permit: OwnedSemaphorePermit,
}

enum Inbound {
    ChannelOpened {
        channel: ChannelId,
        kind: ChannelKind,
        direction: ChannelDirection,
        send: Option<SendStream>,
        receive_open: bool,
        permit: OwnedSemaphorePermit,
    },
    ReliableData {
        channel: ChannelId,
        payload: Bytes,
        end_of_stream: bool,
    },
    Datagram(Bytes),
    ChannelClosed(ChannelId),
    Fatal(CloseReason),
}

struct QuinnPeerConnection {
    connection: Connection,
    remote: Endpoint,
    datagrams: DatagramAvailability,
    channels: HashMap<ChannelId, ChannelState>,
    channel_permits: Arc<Semaphore>,
    inbound_tx: mpsc::Sender<Inbound>,
    inbound_rx: mpsc::Receiver<Inbound>,
    pending_events: VecDeque<TransportEvent>,
    background_tasks: Vec<JoinHandle<()>>,
    operation_timeout: Duration,
    closed: bool,
}

impl QuinnPeerConnection {
    fn new(connection: Connection, operation_timeout: Duration) -> Result<Self, TransportError> {
        let remote = Endpoint::new(connection.remote_address())?;
        let datagrams = connection
            .max_datagram_size()
            .and_then(|maximum| DatagramLimit::negotiated(maximum).ok())
            .map_or(
                DatagramAvailability::Unavailable,
                DatagramAvailability::Available,
            );
        let channel_permits = Arc::new(Semaphore::new(MAX_OPEN_CHANNELS));
        let (inbound_tx, inbound_rx) = mpsc::channel(EVENT_QUEUE_CAPACITY);
        let background_tasks = spawn_background_tasks(
            &connection,
            &inbound_tx,
            &channel_permits,
            operation_timeout,
            datagrams,
        );
        let mut pending_events = VecDeque::new();
        pending_events.push_back(TransportEvent::Connected { remote, datagrams });
        Ok(Self {
            connection,
            remote,
            datagrams,
            channels: HashMap::new(),
            channel_permits,
            inbound_tx,
            inbound_rx,
            pending_events,
            background_tasks,
            operation_timeout,
            closed: false,
        })
    }

    async fn open_channel(
        &mut self,
        kind: ChannelKind,
        direction: ChannelDirection,
    ) -> Result<(), TransportError> {
        if self.closed {
            return Err(TransportError::Closed);
        }
        let permit = Arc::clone(&self.channel_permits)
            .try_acquire_owned()
            .map_err(|_| TransportError::ChannelLimitReached)?;

        let (channel, send, receive_open) = match direction {
            ChannelDirection::SendOnly => {
                let mut send = timeout(self.operation_timeout, self.connection.open_uni())
                    .await
                    .map_err(|_| TransportError::TimedOut)?
                    .map_err(|error| map_connection_error(&error))?;
                let channel = channel_id(send.id());
                if let Err(error) =
                    write_channel_header(&mut send, kind, direction, self.operation_timeout).await
                {
                    self.close_immediately(CloseReason::TransportFailure);
                    return Err(error);
                }
                (channel, Some(send), false)
            }
            ChannelDirection::Bidirectional | ChannelDirection::ReceiveOnly => {
                let (mut send, recv) = timeout(self.operation_timeout, self.connection.open_bi())
                    .await
                    .map_err(|_| TransportError::TimedOut)?
                    .map_err(|error| map_connection_error(&error))?;
                let channel = channel_id(send.id());
                if let Err(error) =
                    write_channel_header(&mut send, kind, direction, self.operation_timeout).await
                {
                    self.close_immediately(CloseReason::TransportFailure);
                    return Err(error);
                }
                if direction == ChannelDirection::ReceiveOnly {
                    send.finish().map_err(|_| TransportError::Closed)?;
                    spawn_stream_reader(
                        self.connection.clone(),
                        recv,
                        channel,
                        self.inbound_tx.clone(),
                        self.operation_timeout,
                    );
                    (channel, None, true)
                } else {
                    spawn_stream_reader(
                        self.connection.clone(),
                        recv,
                        channel,
                        self.inbound_tx.clone(),
                        self.operation_timeout,
                    );
                    (channel, Some(send), true)
                }
            }
        };

        self.channels.insert(
            channel,
            ChannelState {
                send,
                receive_open,
                _permit: permit,
            },
        );
        self.pending_events
            .push_back(TransportEvent::ChannelOpened {
                channel,
                kind,
                direction,
            });
        Ok(())
    }

    async fn send_reliable(
        &mut self,
        channel: ChannelId,
        payload: Bytes,
        end_of_stream: bool,
    ) -> Result<(), TransportError> {
        let state = self
            .channels
            .get_mut(&channel)
            .ok_or(TransportError::InvalidChannel)?;
        let send = state.send.as_mut().ok_or(TransportError::InvalidChannel)?;
        let payload_length =
            u32::try_from(payload.len()).map_err(|_| TransportError::ReliableFrameTooLarge)?;
        let mut header = [0_u8; FRAME_HEADER_BYTES];
        header[..4].copy_from_slice(&payload_length.to_be_bytes());
        header[4] = u8::from(end_of_stream);

        let write_result = timeout(self.operation_timeout, async {
            send.write_all(&header).await?;
            send.write_all(&payload).await
        })
        .await;
        match write_result {
            Ok(Ok(())) => {}
            Ok(Err(_)) => return Err(TransportError::Closed),
            Err(_) => {
                self.close_immediately(CloseReason::TransportFailure);
                return Err(TransportError::TimedOut);
            }
        }
        if end_of_stream {
            send.finish().map_err(|_| TransportError::Closed)?;
            state.send = None;
            if !state.receive_open {
                self.channels.remove(&channel);
            }
        }
        Ok(())
    }

    fn send_datagram(&self, payload: Bytes) -> Result<(), TransportError> {
        let Some(backend_maximum) = self.connection.max_datagram_size() else {
            return Err(TransportError::DatagramsNotNegotiated);
        };
        let limit = DatagramLimit::negotiated(backend_maximum)?;
        if payload.len() > limit.max_payload_bytes() {
            return Err(TransportError::DatagramTooLarge);
        }
        self.connection
            .send_datagram(payload)
            .map_err(|error| match error {
                quinn::SendDatagramError::TooLarge => TransportError::DatagramTooLarge,
                quinn::SendDatagramError::UnsupportedByPeer
                | quinn::SendDatagramError::Disabled => TransportError::DatagramsNotNegotiated,
                quinn::SendDatagramError::ConnectionLost(_) => TransportError::Closed,
            })
    }

    fn close_immediately(&mut self, reason: CloseReason) {
        if self.closed {
            return;
        }
        self.closed = true;
        self.connection
            .close(close_code(reason), close_reason_bytes(reason));
        self.channels.clear();
        self.pending_events
            .push_back(TransportEvent::Closed(reason));
    }

    fn handle_inbound(&mut self, inbound: Inbound) -> Result<TransportEvent, TransportError> {
        match inbound {
            Inbound::ChannelOpened {
                channel,
                kind,
                direction,
                send,
                receive_open,
                permit,
            } => {
                if self.channels.contains_key(&channel) {
                    self.close_immediately(CloseReason::ProtocolViolation);
                    return Err(TransportError::Backend);
                }
                self.channels.insert(
                    channel,
                    ChannelState {
                        send,
                        receive_open,
                        _permit: permit,
                    },
                );
                Ok(TransportEvent::ChannelOpened {
                    channel,
                    kind,
                    direction,
                })
            }
            Inbound::ReliableData {
                channel,
                payload,
                end_of_stream,
            } => {
                let state = self
                    .channels
                    .get_mut(&channel)
                    .ok_or(TransportError::InvalidChannel)?;
                if !state.receive_open {
                    self.close_immediately(CloseReason::ProtocolViolation);
                    return Err(TransportError::InvalidChannel);
                }
                if end_of_stream {
                    state.receive_open = false;
                    if state.send.is_none() {
                        self.channels.remove(&channel);
                    }
                }
                let event = TransportEvent::ReliableData {
                    channel,
                    payload,
                    end_of_stream,
                };
                event.validate(self.datagrams)?;
                Ok(event)
            }
            Inbound::Datagram(payload) => {
                let event = TransportEvent::Datagram { payload };
                if let Err(error) = event.validate(self.datagrams) {
                    self.close_immediately(CloseReason::LimitExceeded);
                    return Err(error);
                }
                Ok(event)
            }
            Inbound::ChannelClosed(channel) => {
                if let Some(state) = self.channels.get_mut(&channel) {
                    state.receive_open = false;
                    if state.send.is_none() {
                        self.channels.remove(&channel);
                    }
                }
                Ok(TransportEvent::ChannelClosed { channel })
            }
            Inbound::Fatal(reason) => {
                self.close_immediately(reason);
                self.pending_events
                    .pop_front()
                    .ok_or(TransportError::Closed)
            }
        }
    }
}

impl PeerConnection for QuinnPeerConnection {
    fn remote_endpoint(&self) -> Endpoint {
        self.remote
    }

    fn datagram_availability(&self) -> DatagramAvailability {
        self.datagrams
    }

    fn export_keying_material(
        &self,
        label: &[u8],
        context: &[u8],
        output_len: usize,
    ) -> Result<Bytes, TransportError> {
        if !(MIN_KEYING_MATERIAL_BYTES..=MAX_KEYING_MATERIAL_BYTES).contains(&output_len) {
            return Err(TransportError::InvalidKeyingMaterialLength);
        }
        if label.is_empty() {
            return Err(TransportError::InvalidConfiguration);
        }
        let mut output = vec![0_u8; output_len];
        self.connection
            .export_keying_material(&mut output, label, context)
            .map_err(|_| TransportError::Backend)?;
        Ok(Bytes::from(output))
    }

    fn execute(&mut self, command: TransportCommand) -> BoxFuture<'_, Result<(), TransportError>> {
        Box::pin(async move {
            command.validate()?;
            match command {
                TransportCommand::OpenChannel { kind, direction } => {
                    self.open_channel(kind, direction).await
                }
                TransportCommand::SendReliable {
                    channel,
                    payload,
                    end_of_stream,
                } => self.send_reliable(channel, payload, end_of_stream).await,
                TransportCommand::SendDatagram { payload } => self.send_datagram(payload),
                TransportCommand::Close(reason) => {
                    self.close_immediately(reason);
                    Ok(())
                }
            }
        })
    }

    fn next_event(&mut self) -> BoxFuture<'_, Result<TransportEvent, TransportError>> {
        Box::pin(async move {
            if let Some(event) = self.pending_events.pop_front() {
                return Ok(event);
            }
            if self.closed {
                return Err(TransportError::Closed);
            }
            let inbound = timeout(self.operation_timeout, self.inbound_rx.recv())
                .await
                .map_err(|_| TransportError::TimedOut)?
                .ok_or(TransportError::Closed)?;
            self.handle_inbound(inbound)
        })
    }
}

impl Drop for QuinnPeerConnection {
    fn drop(&mut self) {
        self.connection.close(
            close_code(CloseReason::LocalShutdown),
            close_reason_bytes(CloseReason::LocalShutdown),
        );
        for task in &self.background_tasks {
            task.abort();
        }
    }
}

fn spawn_background_tasks(
    connection: &Connection,
    inbound_tx: &mpsc::Sender<Inbound>,
    channel_permits: &Arc<Semaphore>,
    operation_timeout: Duration,
    datagrams: DatagramAvailability,
) -> Vec<JoinHandle<()>> {
    let mut tasks = Vec::with_capacity(4);

    let bi_connection = connection.clone();
    let bi_tx = inbound_tx.clone();
    let bi_permits = Arc::clone(channel_permits);
    tasks.push(tokio::spawn(async move {
        accept_bidirectional(bi_connection, bi_tx, bi_permits, operation_timeout).await;
    }));

    let uni_connection = connection.clone();
    let uni_tx = inbound_tx.clone();
    let uni_permits = Arc::clone(channel_permits);
    tasks.push(tokio::spawn(async move {
        accept_unidirectional(uni_connection, uni_tx, uni_permits, operation_timeout).await;
    }));

    if datagrams != DatagramAvailability::Unavailable {
        let datagram_connection = connection.clone();
        let datagram_tx = inbound_tx.clone();
        tasks.push(tokio::spawn(async move {
            read_datagrams(datagram_connection, datagram_tx).await;
        }));
    }

    let closed_connection = connection.clone();
    let closed_tx = inbound_tx.clone();
    tasks.push(tokio::spawn(async move {
        let error = closed_connection.closed().await;
        let reason = match error {
            quinn::ConnectionError::TimedOut => CloseReason::IdleTimeout,
            _ => CloseReason::TransportFailure,
        };
        let _ = closed_tx.send(Inbound::Fatal(reason)).await;
    }));
    tasks
}

async fn accept_bidirectional(
    connection: Connection,
    inbound_tx: mpsc::Sender<Inbound>,
    channel_permits: Arc<Semaphore>,
    operation_timeout: Duration,
) {
    loop {
        let Ok((send, recv)) = connection.accept_bi().await else {
            return;
        };
        let Ok(permit) = Arc::clone(&channel_permits).try_acquire_owned() else {
            fail_connection(&connection, &inbound_tx, CloseReason::LimitExceeded).await;
            return;
        };
        let stream_connection = connection.clone();
        let stream_tx = inbound_tx.clone();
        tokio::spawn(async move {
            receive_bidirectional(
                stream_connection,
                send,
                recv,
                permit,
                stream_tx,
                operation_timeout,
            )
            .await;
        });
    }
}

async fn accept_unidirectional(
    connection: Connection,
    inbound_tx: mpsc::Sender<Inbound>,
    channel_permits: Arc<Semaphore>,
    operation_timeout: Duration,
) {
    loop {
        let Ok(recv) = connection.accept_uni().await else {
            return;
        };
        let Ok(permit) = Arc::clone(&channel_permits).try_acquire_owned() else {
            fail_connection(&connection, &inbound_tx, CloseReason::LimitExceeded).await;
            return;
        };
        let stream_connection = connection.clone();
        let stream_tx = inbound_tx.clone();
        tokio::spawn(async move {
            receive_unidirectional(
                stream_connection,
                recv,
                permit,
                stream_tx,
                operation_timeout,
            )
            .await;
        });
    }
}

async fn receive_bidirectional(
    connection: Connection,
    send: SendStream,
    mut recv: RecvStream,
    permit: OwnedSemaphorePermit,
    inbound_tx: mpsc::Sender<Inbound>,
    operation_timeout: Duration,
) {
    let channel = channel_id(recv.id());
    let Ok((kind, remote_direction)) = read_channel_header(&mut recv, operation_timeout).await
    else {
        fail_connection(&connection, &inbound_tx, CloseReason::ProtocolViolation).await;
        return;
    };
    let (direction, send, receive_open) = match remote_direction {
        ChannelDirection::Bidirectional => (ChannelDirection::Bidirectional, Some(send), true),
        ChannelDirection::ReceiveOnly => (ChannelDirection::SendOnly, Some(send), false),
        ChannelDirection::SendOnly => {
            fail_connection(&connection, &inbound_tx, CloseReason::ProtocolViolation).await;
            return;
        }
    };
    if inbound_tx
        .send(Inbound::ChannelOpened {
            channel,
            kind,
            direction,
            send,
            receive_open,
            permit,
        })
        .await
        .is_err()
    {
        return;
    }
    if receive_open {
        read_reliable_frames(connection, recv, channel, inbound_tx, operation_timeout).await;
    }
}

async fn receive_unidirectional(
    connection: Connection,
    mut recv: RecvStream,
    permit: OwnedSemaphorePermit,
    inbound_tx: mpsc::Sender<Inbound>,
    operation_timeout: Duration,
) {
    let channel = channel_id(recv.id());
    let Ok((kind, remote_direction)) = read_channel_header(&mut recv, operation_timeout).await
    else {
        fail_connection(&connection, &inbound_tx, CloseReason::ProtocolViolation).await;
        return;
    };
    if remote_direction != ChannelDirection::SendOnly {
        fail_connection(&connection, &inbound_tx, CloseReason::ProtocolViolation).await;
        return;
    }
    if inbound_tx
        .send(Inbound::ChannelOpened {
            channel,
            kind,
            direction: ChannelDirection::ReceiveOnly,
            send: None,
            receive_open: true,
            permit,
        })
        .await
        .is_err()
    {
        return;
    }
    read_reliable_frames(connection, recv, channel, inbound_tx, operation_timeout).await;
}

fn spawn_stream_reader(
    connection: Connection,
    recv: RecvStream,
    channel: ChannelId,
    inbound_tx: mpsc::Sender<Inbound>,
    operation_timeout: Duration,
) {
    tokio::spawn(async move {
        read_reliable_frames(connection, recv, channel, inbound_tx, operation_timeout).await;
    });
}

async fn read_reliable_frames(
    connection: Connection,
    mut recv: RecvStream,
    channel: ChannelId,
    inbound_tx: mpsc::Sender<Inbound>,
    operation_timeout: Duration,
) {
    loop {
        let mut header = [0_u8; FRAME_HEADER_BYTES];
        match timeout(operation_timeout, recv.read_exact(&mut header)).await {
            Ok(Ok(())) => {}
            Ok(Err(quinn::ReadExactError::FinishedEarly(0))) => {
                let _ = inbound_tx.send(Inbound::ChannelClosed(channel)).await;
                return;
            }
            Ok(Err(_)) | Err(_) => {
                fail_connection(&connection, &inbound_tx, CloseReason::ProtocolViolation).await;
                return;
            }
        }
        let payload_length = u32::from_be_bytes(header[..4].try_into().expect("fixed header"));
        let Ok(payload_length) = usize::try_from(payload_length) else {
            fail_connection(&connection, &inbound_tx, CloseReason::LimitExceeded).await;
            return;
        };
        if payload_length > MAX_RELIABLE_FRAME_BYTES || header[4] > END_OF_STREAM_FLAG {
            fail_connection(&connection, &inbound_tx, CloseReason::LimitExceeded).await;
            return;
        }
        let mut payload = vec![0_u8; payload_length];
        if !matches!(
            timeout(operation_timeout, recv.read_exact(&mut payload)).await,
            Ok(Ok(()))
        ) {
            fail_connection(&connection, &inbound_tx, CloseReason::ProtocolViolation).await;
            return;
        }
        let end_of_stream = header[4] == END_OF_STREAM_FLAG;
        if inbound_tx
            .send(Inbound::ReliableData {
                channel,
                payload: Bytes::from(payload),
                end_of_stream,
            })
            .await
            .is_err()
        {
            return;
        }
        if end_of_stream {
            return;
        }
    }
}

async fn read_datagrams(connection: Connection, inbound_tx: mpsc::Sender<Inbound>) {
    while let Ok(payload) = connection.read_datagram().await {
        if payload.is_empty() || payload.len() > MAX_DATAGRAM_PAYLOAD_BYTES {
            fail_connection(&connection, &inbound_tx, CloseReason::LimitExceeded).await;
            return;
        }
        if inbound_tx.send(Inbound::Datagram(payload)).await.is_err() {
            return;
        }
    }
}

async fn fail_connection(
    connection: &Connection,
    inbound_tx: &mpsc::Sender<Inbound>,
    reason: CloseReason,
) {
    connection.close(close_code(reason), close_reason_bytes(reason));
    let _ = inbound_tx.send(Inbound::Fatal(reason)).await;
}

async fn write_channel_header(
    send: &mut SendStream,
    kind: ChannelKind,
    direction: ChannelDirection,
    operation_timeout: Duration,
) -> Result<(), TransportError> {
    let mut header = [0_u8; CHANNEL_HEADER_BYTES];
    header[..4].copy_from_slice(&FRAME_MAGIC);
    header[4] = FRAME_VERSION;
    header[5] = encode_kind(kind);
    header[6] = encode_direction(direction);
    timeout(operation_timeout, send.write_all(&header))
        .await
        .map_err(|_| TransportError::TimedOut)?
        .map_err(|_| TransportError::Closed)
}

async fn read_channel_header(
    recv: &mut RecvStream,
    operation_timeout: Duration,
) -> Result<(ChannelKind, ChannelDirection), TransportError> {
    let mut header = [0_u8; CHANNEL_HEADER_BYTES];
    timeout(operation_timeout, recv.read_exact(&mut header))
        .await
        .map_err(|_| TransportError::TimedOut)?
        .map_err(|_| TransportError::Backend)?;
    if header[..4] != FRAME_MAGIC || header[4] != FRAME_VERSION {
        return Err(TransportError::Backend);
    }
    Ok((decode_kind(header[5])?, decode_direction(header[6])?))
}

const fn encode_kind(kind: ChannelKind) -> u8 {
    match kind {
        ChannelKind::Control => 0,
        ChannelKind::ReliableInput => 1,
        ChannelKind::PointerFallback => 2,
        ChannelKind::Clipboard => 3,
        ChannelKind::FileManifest => 4,
        ChannelKind::FileData => 5,
    }
}

fn decode_kind(encoded: u8) -> Result<ChannelKind, TransportError> {
    match encoded {
        0 => Ok(ChannelKind::Control),
        1 => Ok(ChannelKind::ReliableInput),
        2 => Ok(ChannelKind::PointerFallback),
        3 => Ok(ChannelKind::Clipboard),
        4 => Ok(ChannelKind::FileManifest),
        5 => Ok(ChannelKind::FileData),
        _ => Err(TransportError::Backend),
    }
}

const fn encode_direction(direction: ChannelDirection) -> u8 {
    match direction {
        ChannelDirection::Bidirectional => 0,
        ChannelDirection::SendOnly => 1,
        ChannelDirection::ReceiveOnly => 2,
    }
}

fn decode_direction(encoded: u8) -> Result<ChannelDirection, TransportError> {
    match encoded {
        0 => Ok(ChannelDirection::Bidirectional),
        1 => Ok(ChannelDirection::SendOnly),
        2 => Ok(ChannelDirection::ReceiveOnly),
        _ => Err(TransportError::Backend),
    }
}

fn channel_id(stream_id: quinn::StreamId) -> ChannelId {
    ChannelId::from_backend(VarInt::from(stream_id).into_inner())
}

fn pairing_alpn(protocol_version: u16) -> Vec<u8> {
    let mut alpn = Vec::with_capacity(PAIRING_ALPN_PREFIX.len() + 2);
    alpn.extend_from_slice(PAIRING_ALPN_PREFIX);
    alpn.extend_from_slice(&protocol_version.to_be_bytes());
    alpn
}

fn peer_root_store(certificate_der: Vec<u8>) -> Result<RootCertStore, TransportError> {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(certificate_der))
        .map_err(|_| TransportError::InvalidConfiguration)?;
    Ok(roots)
}

fn peer_leaf_matches(connection: &Connection, expected_certificate_der: &[u8]) -> bool {
    connection
        .peer_identity()
        .and_then(|identity| identity.downcast::<Vec<CertificateDer<'static>>>().ok())
        .and_then(|certificates| certificates.first().cloned())
        .is_some_and(|certificate| certificate.as_ref() == expected_certificate_der)
}

fn transport_config(
    options: QuinnBackendOptions,
) -> Result<Arc<quinn::TransportConfig>, TransportError> {
    let mut transport = quinn::TransportConfig::default();
    let channel_limit =
        VarInt::try_from(MAX_OPEN_CHANNELS).map_err(|_| TransportError::InvalidConfiguration)?;
    let idle_timeout = options
        .idle_timeout
        .try_into()
        .map_err(|_| TransportError::InvalidConfiguration)?;
    transport
        .max_concurrent_bidi_streams(channel_limit)
        .max_concurrent_uni_streams(channel_limit)
        .max_idle_timeout(Some(idle_timeout))
        .stream_receive_window(VarInt::from_u32(STREAM_WINDOW_BYTES))
        .receive_window(VarInt::from_u32(CONNECTION_WINDOW_BYTES))
        .send_window(u64::from(CONNECTION_WINDOW_BYTES))
        .datagram_receive_buffer_size(Some(DATAGRAM_BUFFER_BYTES))
        .datagram_send_buffer_size(DATAGRAM_BUFFER_BYTES);
    Ok(Arc::new(transport))
}

fn validate_certificate_chain(chain: &[Vec<u8>]) -> Result<(), TransportError> {
    if chain.is_empty() || chain.len() > MAX_CERTIFICATE_CHAIN_LENGTH {
        return Err(TransportError::InvalidConfiguration);
    }
    for certificate in chain {
        validate_certificate(certificate)?;
    }
    Ok(())
}

fn validate_certificate(certificate: &[u8]) -> Result<(), TransportError> {
    if certificate.is_empty() || certificate.len() > MAX_CERTIFICATE_DER_BYTES {
        Err(TransportError::InvalidConfiguration)
    } else {
        Ok(())
    }
}

fn validate_server_name(server_name: String) -> Result<String, TransportError> {
    if server_name.is_empty() || server_name.len() > 253 || !server_name.is_ascii() {
        return Err(TransportError::InvalidConfiguration);
    }
    rustls::pki_types::ServerName::try_from(server_name.clone())
        .map_err(|_| TransportError::InvalidConfiguration)?;
    Ok(server_name)
}

fn validate_bind_address(address: SocketAddr) -> Result<(), TransportError> {
    let ip = address.ip();
    if ip.is_multicast() || matches!(ip, std::net::IpAddr::V4(ipv4) if ipv4.is_broadcast()) {
        Err(TransportError::InvalidEndpoint)
    } else {
        Ok(())
    }
}

fn close_code(reason: CloseReason) -> VarInt {
    VarInt::from_u32(match reason {
        CloseReason::Requested => 0,
        CloseReason::EmergencyDisconnect => 1,
        CloseReason::AuthenticationFailed => 2,
        CloseReason::ProtocolViolation => 3,
        CloseReason::VersionMismatch => 4,
        CloseReason::LimitExceeded => 5,
        CloseReason::IdleTimeout => 6,
        CloseReason::LocalShutdown => 7,
        CloseReason::TransportFailure => 8,
    })
}

const fn close_reason_bytes(reason: CloseReason) -> &'static [u8] {
    match reason {
        CloseReason::Requested => b"requested",
        CloseReason::EmergencyDisconnect => b"emergency disconnect",
        CloseReason::AuthenticationFailed => b"authentication failed",
        CloseReason::ProtocolViolation => b"protocol violation",
        CloseReason::VersionMismatch => b"version mismatch",
        CloseReason::LimitExceeded => b"limit exceeded",
        CloseReason::IdleTimeout => b"idle timeout",
        CloseReason::LocalShutdown => b"local shutdown",
        CloseReason::TransportFailure => b"transport failure",
    }
}

fn map_handshake_error(error: &quinn::ConnectionError) -> TransportError {
    match error {
        quinn::ConnectionError::TimedOut => TransportError::TimedOut,
        quinn::ConnectionError::VersionMismatch
        | quinn::ConnectionError::TransportError(_)
        | quinn::ConnectionError::ConnectionClosed(_)
        | quinn::ConnectionError::ApplicationClosed(_)
        | quinn::ConnectionError::Reset
        | quinn::ConnectionError::LocallyClosed
        | quinn::ConnectionError::CidsExhausted => TransportError::AuthenticationFailed,
    }
}

fn map_connection_error(error: &quinn::ConnectionError) -> TransportError {
    match error {
        quinn::ConnectionError::TimedOut => TransportError::TimedOut,
        quinn::ConnectionError::LocallyClosed
        | quinn::ConnectionError::ConnectionClosed(_)
        | quinn::ConnectionError::ApplicationClosed(_)
        | quinn::ConnectionError::Reset => TransportError::Closed,
        quinn::ConnectionError::VersionMismatch
        | quinn::ConnectionError::TransportError(_)
        | quinn::ConnectionError::CidsExhausted => TransportError::Backend,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use nodavo_identity::{
        CapabilityGrants, CommittedTrust, DeviceSigner, PAIRING_NONCE_BYTES, PairingAction,
        PairingNonce, PairingRole, PairingTxn, PendingTrust, SoftwareSigner, TransportCertificate,
    };

    use super::*;

    const PAIRING_VERSION: u16 = 1;
    const EXPORTER_LABEL: &[u8] = b"EXPORTER-nodavo-pairing-v1";

    fn committed_bindings(
        initiator_certificate_der: Vec<u8>,
        responder_certificate_der: Vec<u8>,
    ) -> (
        CommittedTrust,
        CommittedTrust,
        [u8; crate::PEER_PUBLIC_KEY_BYTES],
        [u8; crate::PEER_PUBLIC_KEY_BYTES],
    ) {
        let initiator_signer = SoftwareSigner::from_secret_seed([31; 32]);
        let responder_signer = SoftwareSigner::from_secret_seed([47; 32]);
        let initiator_public_key = *initiator_signer.public_identity().public_key_bytes();
        let responder_public_key = *responder_signer.public_identity().public_key_bytes();
        let initiator = PendingTrust::new(
            initiator_signer.public_identity(),
            CapabilityGrants::NONE,
            TransportCertificate::from_der(initiator_certificate_der).unwrap(),
        );
        let responder = PendingTrust::new(
            responder_signer.public_identity(),
            CapabilityGrants::NONE,
            TransportCertificate::from_der(responder_certificate_der).unwrap(),
        );
        let mut pairing = PairingTxn::new(
            PAIRING_VERSION,
            &[0x53; nodavo_identity::MIN_TLS_EXPORTER_BYTES],
            initiator,
            PairingNonce::from_bytes([1; PAIRING_NONCE_BYTES]),
            responder,
            PairingNonce::from_bytes([2; PAIRING_NONCE_BYTES]),
        )
        .unwrap();
        let sas = pairing.sas();
        for role in [PairingRole::Initiator, PairingRole::Responder] {
            pairing
                .reduce(PairingAction::ConfirmSas { role, sas })
                .unwrap();
        }
        let initiator_acceptance = pairing
            .create_acceptance(PairingRole::Initiator, &initiator_signer)
            .unwrap();
        let responder_acceptance = pairing
            .create_acceptance(PairingRole::Responder, &responder_signer)
            .unwrap();
        pairing
            .reduce(PairingAction::SubmitAcceptance(initiator_acceptance))
            .unwrap();
        pairing
            .reduce(PairingAction::SubmitAcceptance(responder_acceptance))
            .unwrap();
        pairing
            .reduce(PairingAction::Commit {
                established_at_unix_ms: 1,
            })
            .unwrap();
        (
            pairing.committed_trust_for(PairingRole::Initiator).unwrap(),
            pairing.committed_trust_for(PairingRole::Responder).unwrap(),
            initiator_public_key,
            responder_public_key,
        )
    }

    #[tokio::test]
    async fn encrypted_loopback_exchanges_one_bounded_control_frame() {
        let client_identity =
            EphemeralPairingIdentity::generate("client.pairing.nodavo.invalid").unwrap();
        let server_identity =
            EphemeralPairingIdentity::generate("server.pairing.nodavo.invalid").unwrap();
        let client_certificate = client_identity.certificate_der().to_vec();
        let server_certificate = server_identity.certificate_der().to_vec();

        let client = QuinnTransport::bind_ephemeral_pairing(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            EphemeralPairingConfiguration::new(
                PAIRING_VERSION,
                client_identity,
                server_certificate,
                "server.pairing.nodavo.invalid",
            )
            .unwrap(),
            QuinnBackendOptions::default(),
        )
        .unwrap();
        let server = QuinnTransport::bind_ephemeral_pairing(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            EphemeralPairingConfiguration::new(
                PAIRING_VERSION,
                server_identity,
                client_certificate,
                "client.pairing.nodavo.invalid",
            )
            .unwrap(),
            QuinnBackendOptions::default(),
        )
        .unwrap();

        let server_endpoint = Endpoint::new(server.local_address().unwrap()).unwrap();
        let (client_connection, server_connection) = tokio::join!(
            client.connect(server_endpoint, AuthMode::pairing(PAIRING_VERSION).unwrap()),
            server.accept(),
        );
        let mut client_connection = client_connection.unwrap();
        let mut server_connection = server_connection.unwrap();

        assert!(matches!(
            client_connection.next_event().await.unwrap(),
            TransportEvent::Connected { .. }
        ));
        assert!(matches!(
            server_connection.next_event().await.unwrap(),
            TransportEvent::Connected { .. }
        ));
        let client_exporter = client_connection
            .export_keying_material(EXPORTER_LABEL, b"smoke", 32)
            .unwrap();
        let server_exporter = server_connection
            .export_keying_material(EXPORTER_LABEL, b"smoke", 32)
            .unwrap();
        assert_eq!(client_exporter, server_exporter);

        client_connection
            .execute(TransportCommand::OpenChannel {
                kind: ChannelKind::Control,
                direction: ChannelDirection::SendOnly,
            })
            .await
            .unwrap();
        let channel = match client_connection.next_event().await.unwrap() {
            TransportEvent::ChannelOpened {
                channel,
                kind: ChannelKind::Control,
                direction: ChannelDirection::SendOnly,
            } => channel,
            event => panic!("unexpected client event: {event:?}"),
        };
        assert!(matches!(
            server_connection.next_event().await.unwrap(),
            TransportEvent::ChannelOpened {
                kind: ChannelKind::Control,
                direction: ChannelDirection::ReceiveOnly,
                ..
            }
        ));

        let payload = Bytes::from_static(b"bounded control frame");
        client_connection
            .execute(TransportCommand::SendReliable {
                channel,
                payload: payload.clone(),
                end_of_stream: true,
            })
            .await
            .unwrap();
        assert!(matches!(
            server_connection.next_event().await.unwrap(),
            TransportEvent::ReliableData {
                payload: received,
                end_of_stream: true,
                ..
            } if received == payload
        ));
    }

    #[tokio::test]
    async fn committed_binding_permits_persistent_mutual_tls_loopback() {
        let initiator_tls =
            EphemeralPairingIdentity::generate("initiator.pinned.nodavo.invalid").unwrap();
        let responder_tls =
            EphemeralPairingIdentity::generate("responder.pinned.nodavo.invalid").unwrap();
        let initiator_certificate = initiator_tls.certificate_der().to_vec();
        let responder_certificate = responder_tls.certificate_der().to_vec();
        let (initiator_trust, responder_trust, initiator_key, responder_key) =
            committed_bindings(initiator_certificate.clone(), responder_certificate.clone());

        let initiator = QuinnTransport::bind_pinned_mutual(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            PinnedMutualConfiguration::new(
                initiator_tls.credentials,
                initiator_trust.transport_binding(),
                responder_certificate,
                "responder.pinned.nodavo.invalid",
            )
            .unwrap(),
            QuinnBackendOptions::default(),
        )
        .unwrap();
        let responder = QuinnTransport::bind_pinned_mutual(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            PinnedMutualConfiguration::new(
                responder_tls.credentials,
                responder_trust.transport_binding(),
                initiator_certificate,
                "initiator.pinned.nodavo.invalid",
            )
            .unwrap(),
            QuinnBackendOptions::default(),
        )
        .unwrap();

        let responder_endpoint = Endpoint::new(responder.local_address().unwrap()).unwrap();
        let (initiator_connection, responder_connection) = tokio::join!(
            initiator.connect(
                responder_endpoint,
                AuthMode::PinnedMutual {
                    expected_peer_public_key: responder_key,
                },
            ),
            responder.accept(),
        );
        let mut initiator_connection = initiator_connection.unwrap();
        let mut responder_connection = responder_connection.unwrap();
        assert_eq!(
            initiator_connection
                .export_keying_material(EXPORTER_LABEL, b"persistent", 32)
                .unwrap(),
            responder_connection
                .export_keying_material(EXPORTER_LABEL, b"persistent", 32)
                .unwrap()
        );
        assert!(matches!(
            initiator_connection.next_event().await.unwrap(),
            TransportEvent::Connected { .. }
        ));
        assert!(matches!(
            responder_connection.next_event().await.unwrap(),
            TransportEvent::Connected { .. }
        ));
        assert_ne!(initiator_key, responder_key);
    }

    #[test]
    fn committed_binding_rejects_certificate_substitution() {
        let local =
            EphemeralPairingIdentity::generate("local-substitution.pinned.nodavo.invalid").unwrap();
        let peer =
            EphemeralPairingIdentity::generate("peer-substitution.pinned.nodavo.invalid").unwrap();
        let replacement =
            EphemeralPairingIdentity::generate("replacement.pinned.nodavo.invalid").unwrap();
        let local_certificate = local.certificate_der().to_vec();
        let peer_certificate = peer.certificate_der().to_vec();
        let (local_trust, _, _, _) = committed_bindings(local_certificate, peer_certificate);

        assert!(matches!(
            PinnedMutualConfiguration::new(
                local.credentials,
                local_trust.transport_binding(),
                replacement.certificate_der().to_vec(),
                "replacement.pinned.nodavo.invalid",
            ),
            Err(TransportError::AuthenticationFailed)
        ));
    }
}
