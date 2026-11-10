use crate::config::ClientConfig;
use crate::config::DnsResolver;
use crate::config::ServerConfig;
use crate::connection::Connection;
use crate::driver::streams::session::StreamSession;
use crate::driver::streams::ProtoReadError;
use crate::driver::streams::ProtoWriteError;
use crate::driver::utils::varint_w2q;
use crate::driver::Driver;
use crate::error::ConnectingError;
use crate::error::ConnectionError;
use crate::VarInt;
use quinn::TokioRuntime;
use std::collections::HashMap;
use std::future::Future;
use std::future::IntoFuture;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::net::SocketAddrV6;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Context;
use std::task::Poll;
use tracing::debug;
use url::Host;
use url::Url;
use wtransport_proto::error::ErrorCode;
use wtransport_proto::frame::FrameKind;
use wtransport_proto::headers::Headers;
use wtransport_proto::session::ReservedHeader;
use wtransport_proto::session::SessionRequest as SessionRequestProto;
use wtransport_proto::session::SessionResponse as SessionResponseProto;
use wtransport_proto::settings::SettingId;
use wtransport_proto::settings::Settings;

/// Helper structure for Endpoint types.
pub mod endpoint_side {
    use super::*;

    /// Type of endpoint accepting multiple WebTransport connections.
    ///
    /// Use [`Endpoint::server`] to create and server-endpoint.
    pub struct Server {
        pub(super) _marker: PhantomData<()>,
    }

    /// Type of endpoint opening a WebTransport connection.
    ///
    /// Use [`Endpoint::client`] to create and client-endpoint.
    pub struct Client {
        pub(super) dns_resolver: Arc<dyn DnsResolver + Send + Sync>,
    }
}

/// Entrypoint for creating client or server connections.
///
/// A single endpoint can be used to accept or connect multiple connections.
/// Each endpoint internally binds an UDP socket.
///
/// # Server
/// Use [`Endpoint::server`] for creating a server-side endpoint.
/// Afterwards use the method [`Endpoint::accept`] for awaiting on incoming session request.
///
/// ```no_run
/// # use anyhow::Result;
/// # use wtransport::ServerConfig;
/// # use wtransport::Identity;
/// use wtransport::Endpoint;
///
/// # async fn run() -> Result<()> {
/// # let config = ServerConfig::builder()
/// #       .with_bind_default(4433)
/// #       .with_identity(Identity::self_signed(["doc"]).unwrap())
/// #       .build();
/// let server = Endpoint::server(config)?;
/// loop {
///     let incoming_session = server.accept().await;
///     // Spawn task that handles client incoming session...
/// }
/// # Ok(())
/// # }
/// ```
///
/// # Client
/// Use [`Endpoint::client`] for creating a client-side endpoint and use [`Endpoint::connect`]
/// to connect to a server specifying the URL.
///
/// ```no_run
/// # use anyhow::Result;
/// use wtransport::ClientConfig;
/// use wtransport::Endpoint;
///
/// # async fn run() -> Result<()> {
/// let connection = Endpoint::client(ClientConfig::default())?
///     .connect("https://localhost:4433")
///     .await?;
/// # Ok(())
/// # }
/// ```
pub struct Endpoint<Side> {
    endpoint: quinn::Endpoint,
    side: Side,
}

impl<Side> Endpoint<Side> {
    /// Closes all of this endpoint's connections immediately and cease accepting new connections.
    pub fn close(&self, error_code: VarInt, reason: &[u8]) {
        self.endpoint.close(varint_w2q(error_code), reason);
    }

    /// Waits for all connections on the endpoint to be cleanly shut down.
    pub async fn wait_idle(&self) {
        self.endpoint.wait_idle().await;
    }

    /// Gets the local [`SocketAddr`] the underlying socket is bound to.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }

    /// Get the number of connections that are currently open.
    pub fn open_connections(&self) -> usize {
        self.endpoint.open_connections()
    }
}

impl Endpoint<endpoint_side::Server> {
    /// Constructs a *server* endpoint.
    pub fn server(server_config: ServerConfig) -> std::io::Result<Self> {
        let endpoint_config = server_config.endpoint_config;
        let quic_config = server_config.quic_config;
        let socket = server_config.bind_address_config.bind_socket()?;
        let runtime = Arc::new(TokioRuntime);

        let endpoint = quinn::Endpoint::new(endpoint_config, Some(quic_config), socket, runtime)?;

        Ok(Self {
            endpoint,
            side: endpoint_side::Server {
                _marker: PhantomData,
            },
        })
    }

    /// Get the next incoming connection attempt from a client.
    pub async fn accept(&self) -> IncomingSession {
        let quic_incoming = self
            .endpoint
            .accept()
            .await
            .expect("Endpoint cannot be closed");

        debug!("New incoming QUIC connection");

        IncomingSession(quic_incoming)
    }

    /// Reloads the server configuration.
    ///
    /// Useful for e.g. refreshing TLS certificates without disrupting existing connections.
    ///
    /// # Arguments
    ///
    /// * `server_config` - The new configuration for the server.
    /// * `rebind` - A boolean indicating whether the server should rebind its socket.
    ///   If `true`, the server will bind to a new socket with the provided configuration.
    ///   If `false`, the bind address configuration will be ignored.
    pub fn reload_config(&self, server_config: ServerConfig, rebind: bool) -> std::io::Result<()> {
        if rebind {
            let socket = server_config.bind_address_config.bind_socket()?;
            self.endpoint.rebind(socket)?;
        }

        let quic_config = server_config.quic_config;
        self.endpoint.set_server_config(Some(quic_config));

        Ok(())
    }
}

impl Endpoint<endpoint_side::Client> {
    /// Constructs a *client* endpoint.
    pub fn client(client_config: ClientConfig) -> std::io::Result<Self> {
        let endpoint_config = client_config.endpoint_config;
        let quic_config = client_config.quic_config;
        let socket = client_config.bind_address_config.bind_socket()?;
        let runtime = Arc::new(TokioRuntime);

        let mut endpoint = quinn::Endpoint::new(endpoint_config, None, socket, runtime)?;

        endpoint.set_default_client_config(quic_config);

        Ok(Self {
            endpoint,
            side: endpoint_side::Client {
                dns_resolver: client_config.dns_resolver,
            },
        })
    }

    /// Establishes a WebTransport connection to a specified URL.
    ///
    /// This method initiates a WebTransport connection to the specified URL.
    /// It validates the URL, and performs necessary steps to establish a secure connection.
    ///
    /// # Arguments
    ///
    /// * `options` - Connection options specifying the URL and additional headers.
    ///   It can be simply an [URL](https://en.wikipedia.org/wiki/URL) string representing
    ///   the WebTransport endpoint to connect to. It must have an `https` scheme.
    ///   The URL can specify either an IP address or a hostname.
    ///   When specifying a hostname, the method will internally perform DNS resolution,
    ///   configured with
    ///   [`ClientConfigBuilder::dns_resolver`](crate::config::ClientConfigBuilder::dns_resolver).
    ///
    /// # Examples
    ///
    /// Connect using a URL with a hostname (DNS resolution is performed):
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use wtransport::endpoint::endpoint_side::Client;
    /// # async fn example(endpoint: wtransport::Endpoint<Client>) -> Result<()> {
    /// let url = "https://example.com:4433/webtransport";
    /// let connection = endpoint.connect(url).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Connect using a URL with an IP address:
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use wtransport::endpoint::endpoint_side::Client;
    /// # async fn example(endpoint: wtransport::Endpoint<Client>) -> Result<()> {
    /// let url = "https://127.0.0.1:4343/webtransport";
    /// let connection = endpoint.connect(url).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Connect adding an additional header:
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use wtransport::endpoint::endpoint_side::Client;
    /// # use wtransport::endpoint::ConnectOptions;
    /// # async fn example(endpoint: wtransport::Endpoint<Client>) -> Result<()> {
    /// let options = ConnectOptions::builder("https://example.com:4433/webtransport")
    ///     .add_header("Authorization", "AuthToken")
    ///     .build();
    /// let connection = endpoint.connect(options).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn connect<O>(&self, options: O) -> Result<Connection, ConnectingError>
    where
        O: IntoConnectOptions,
    {
        let options = options.into_options();

        let url = Url::parse(&options.url)
            .map_err(|parse_error| ConnectingError::InvalidUrl(parse_error.to_string()))?;

        if url.scheme() != "https" {
            return Err(ConnectingError::InvalidUrl(
                "WebTransport URL scheme must be 'https'".to_string(),
            ));
        }

        let host = url.host().expect("https scheme must have an host");
        let port = url.port().unwrap_or(443);

        let (socket_address, server_name) = match host {
            Host::Domain(domain) => {
                let socket_address = self
                    .side
                    .dns_resolver
                    .resolve(&format!("{domain}:{port}"))
                    .await
                    .map_err(ConnectingError::DnsLookup)?
                    .ok_or(ConnectingError::DnsNotFound)?;

                (socket_address, domain.to_string())
            }
            Host::Ipv4(address) => {
                let socket_address = SocketAddr::V4(SocketAddrV4::new(address, port));
                (socket_address, address.to_string())
            }
            Host::Ipv6(address) => {
                let socket_address = SocketAddr::V6(SocketAddrV6::new(address, port, 0, 0));
                (socket_address, address.to_string())
            }
        };

        let quic_connection = self
            .endpoint
            .connect(socket_address, &server_name)
            .map_err(ConnectingError::with_connect_error)?
            .await
            .map_err(|connection_error| {
                ConnectingError::ConnectionError(connection_error.into())
            })?;

        let driver = Driver::init(quic_connection.clone());

        let settings = driver.accept_settings().await.map_err(|driver_error| {
            ConnectingError::ConnectionError(ConnectionError::with_driver_error(
                driver_error,
                &quic_connection,
            ))
        })?;

        if !server_supports_webtransport(&settings) {
            return Err(ConnectingError::ConnectionError(requirements_not_met(
                &quic_connection,
            )));
        }

        let mut session_request_proto =
            SessionRequestProto::new(url.as_ref()).expect("Url has been already validate");

        for (k, v) in options.additional_headers {
            session_request_proto
                .insert(k.clone(), v)
                .map_err(|ReservedHeader| ConnectingError::ReservedHeader(k))?;
        }

        let mut stream_session = match driver.open_session(session_request_proto).await {
            Ok(stream_session) => stream_session,
            Err(driver_error) => {
                return Err(ConnectingError::ConnectionError(
                    ConnectionError::with_driver_error(driver_error, &quic_connection),
                ))
            }
        };

        let session_id = stream_session.session_id();

        match stream_session
            .write_frame(stream_session.request().headers().generate_frame())
            .await
        {
            Ok(()) => {}
            Err(ProtoWriteError::Stopped) => {
                return Err(ConnectingError::SessionRejected);
            }
            Err(ProtoWriteError::NotConnected) => {
                return Err(ConnectingError::with_no_connection(&quic_connection));
            }
        }

        let frame = loop {
            let frame = match stream_session.read_frame().await {
                Ok(frame) => frame,
                Err(ProtoReadError::H3(error_code)) => {
                    quic_connection.close(varint_w2q(error_code.to_code()), b"");
                    return Err(ConnectingError::ConnectionError(
                        ConnectionError::local_h3_error(error_code),
                    ));
                }
                Err(ProtoReadError::IO(_io_error)) => {
                    return Err(ConnectingError::with_no_connection(&quic_connection));
                }
            };

            if let FrameKind::Exercise(_) = frame.kind() {
                continue;
            }
            break frame;
        };

        if !matches!(frame.kind(), FrameKind::Headers) {
            quic_connection.close(varint_w2q(ErrorCode::FrameUnexpected.to_code()), b"");
            return Err(ConnectingError::ConnectionError(
                ConnectionError::local_h3_error(ErrorCode::FrameUnexpected),
            ));
        }

        let headers = match Headers::with_frame(&frame) {
            Ok(headers) => headers,
            Err(error_code) => {
                quic_connection.close(varint_w2q(error_code.to_code()), b"");
                return Err(ConnectingError::ConnectionError(
                    ConnectionError::local_h3_error(error_code),
                ));
            }
        };

        let Ok(session_response) = SessionResponseProto::try_from(headers) else {
            quic_connection.close(varint_w2q(ErrorCode::Message.to_code()), b"");
            return Err(ConnectingError::ConnectionError(
                ConnectionError::local_h3_error(ErrorCode::Message),
            ));
        };

        if session_response.code().is_successful() {
            match driver.register_session(stream_session).await {
                Ok(()) => {}
                Err(driver_error) => {
                    return Err(ConnectingError::ConnectionError(
                        ConnectionError::with_driver_error(driver_error, &quic_connection),
                    ))
                }
            }
        } else {
            return Err(ConnectingError::SessionRejected);
        }

        Ok(Connection::new(quic_connection, driver, session_id))
    }
}

/// Options for establishing a client WebTransport connection.
///
/// Used in [`Endpoint::connect`].
///
/// # Examples
///
/// ```no_run
/// # use anyhow::Result;
/// # use wtransport::endpoint::endpoint_side::Client;
/// # use wtransport::endpoint::ConnectOptions;
/// # async fn example(endpoint: wtransport::Endpoint<Client>) -> Result<()> {
/// let options = ConnectOptions::builder("https://example.com:4433/webtransport")
///     .add_header("Authorization", "AuthToken")
///     .build();
/// let connection = endpoint.connect(options).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct ConnectOptions {
    url: String,
    additional_headers: HashMap<String, String>,
}

impl ConnectOptions {
    /// Creates a new `ConnectOptions` using a builder pattern.
    ///
    /// # Arguments
    ///
    /// * `url` - A [URL](https://en.wikipedia.org/wiki/URL) string representing the WebTransport
    ///   endpoint to connect to. It must have an `https` scheme.
    ///   The URL can specify either an IP address or a hostname.
    ///   When specifying a hostname, the method will internally perform DNS resolution,
    ///   configured with
    ///   [`ClientConfigBuilder::dns_resolver`](crate::config::ClientConfigBuilder::dns_resolver).
    pub fn builder<S>(url: S) -> ConnectRequestBuilder
    where
        S: ToString,
    {
        ConnectRequestBuilder {
            url: url.to_string(),
            additional_headers: Default::default(),
        }
    }

    /// Gets the URL which this will connect to.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Gets the additional headers that will be passed when connecting.
    pub fn additional_headers(&self) -> &HashMap<String, String> {
        &self.additional_headers
    }
}

/// A trait for converting types into `ConnectOptions`.
pub trait IntoConnectOptions {
    /// Perform value-to-value conversion into [`ConnectOptions`].
    fn into_options(self) -> ConnectOptions;
}

/// A builder for [`ConnectOptions`].
///
/// See [`ConnectOptions::builder`].
pub struct ConnectRequestBuilder {
    url: String,
    additional_headers: HashMap<String, String>,
}

impl ConnectRequestBuilder {
    /// Adds a header to the connection options.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use wtransport::endpoint::ConnectOptions;
    ///
    /// let options = ConnectOptions::builder("https://example.com:4433/webtransport")
    ///     .add_header("Authorization", "AuthToken")
    ///     .build();
    /// ```
    pub fn add_header<K, V>(mut self, key: K, value: V) -> Self
    where
        K: ToString,
        V: ToString,
    {
        self.additional_headers
            .insert(key.to_string(), value.to_string());
        self
    }

    /// Constructs the [`ConnectOptions`] from the builder configuration.
    pub fn build(self) -> ConnectOptions {
        ConnectOptions {
            url: self.url,
            additional_headers: self.additional_headers,
        }
    }
}

impl IntoConnectOptions for ConnectRequestBuilder {
    fn into_options(self) -> ConnectOptions {
        self.build()
    }
}

impl IntoConnectOptions for ConnectOptions {
    fn into_options(self) -> ConnectOptions {
        self
    }
}

impl<S> IntoConnectOptions for S
where
    S: ToString,
{
    fn into_options(self) -> ConnectOptions {
        ConnectOptions::builder(self).build()
    }
}

type DynFutureIncomingSession =
    dyn Future<Output = Result<SessionRequest, ConnectionError>> + Send + Sync;

/// [`IntoFuture`] for an in-progress incoming connection attempt.
///
/// Created by [`Endpoint::accept`].
pub struct IncomingSession(quinn::Incoming);

impl IncomingSession {
    /// The peer's UDP address.
    pub fn remote_address(&self) -> SocketAddr {
        self.0.remote_address()
    }

    /// Whether the socket address that is initiating this connection has been validated.
    ///
    /// This means that the sender of the initial packet has proved that they can receive traffic
    /// sent to `self.remote_address()`.
    pub fn remote_address_validated(&self) -> bool {
        self.0.remote_address_validated()
    }

    /// Respond with a retry packet, requiring the client to retry with address validation
    ///
    /// # Panics
    ///
    /// If `remote_address_validated()` is true.
    pub fn retry(self) {
        self.0.retry().expect("remote address already verified");
    }

    /// Reject this incoming connection attempt.
    pub fn refuse(self) {
        self.0.refuse();
    }

    /// Ignore this incoming connection attempt, not sending any packet in response.
    pub fn ignore(self) {
        self.0.ignore();
    }
}

impl IntoFuture for IncomingSession {
    type IntoFuture = IncomingSessionFuture;
    type Output = Result<SessionRequest, ConnectionError>;

    fn into_future(self) -> Self::IntoFuture {
        IncomingSessionFuture::new(self.0)
    }
}

/// [`Future`] for an in-progress incoming connection attempt.
///
/// Created by awaiting an [`IncomingSession`]
pub struct IncomingSessionFuture(Pin<Box<DynFutureIncomingSession>>);

impl IncomingSessionFuture {
    /// Creates a future from [`quinn::Incoming`].
    ///
    /// The returned future resolves to a [`SessionRequest`] once the QUIC connection
    /// is established and the WebTransport session has been accepted.
    #[cfg(feature = "quinn")]
    #[cfg_attr(docsrs, doc(cfg(feature = "quinn")))]
    pub fn with_quic_incoming(quic_incoming: quinn::Incoming) -> Self {
        Self::new(quic_incoming)
    }

    /// Creates a future from [`quinn::Connecting`].
    ///
    /// This is useful when a [`quinn::Connecting`] is already available and needs to be
    /// driven to completion to accept an incoming WebTransport session.
    ///
    /// The returned future resolves to a [`SessionRequest`] once the QUIC connection
    /// is established and the WebTransport session has been accepted.
    #[cfg(feature = "quinn")]
    #[cfg_attr(docsrs, doc(cfg(feature = "quinn")))]
    pub fn with_quic_connecting(quic_connecting: quinn::Connecting) -> Self {
        Self(Box::pin(async move {
            let quic_connection = quic_connecting.await?;
            Self::accept(quic_connection).await
        }))
    }

    fn new(quic_incoming: quinn::Incoming) -> Self {
        Self(Box::pin(async move {
            let quic_connection = quic_incoming.await?;
            Self::accept(quic_connection).await
        }))
    }

    async fn accept(quic_connection: quinn::Connection) -> Result<SessionRequest, ConnectionError> {
        let driver = Driver::init(quic_connection.clone());

        let settings = driver.accept_settings().await.map_err(|driver_error| {
            ConnectionError::with_driver_error(driver_error, &quic_connection)
        })?;

        // Any session would be malformed, and the connection carries nothing else.
        if !client_supports_webtransport(&settings) {
            return Err(requirements_not_met(&quic_connection));
        }

        let stream_session = driver.accept_session().await.map_err(|driver_error| {
            ConnectionError::with_driver_error(driver_error, &quic_connection)
        })?;

        Ok(SessionRequest::new(quic_connection, driver, stream_session))
    }
}

impl Future for IncomingSessionFuture {
    type Output = Result<SessionRequest, ConnectionError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Future::poll(self.0.as_mut(), cx)
    }
}

/// A incoming client session request.
///
/// Server should use methods [`accept`](Self::accept), [`forbidden`](Self::forbidden),
/// or [`not_found`](Self::not_found) in order to validate or reject the client request.
pub struct SessionRequest {
    quic_connection: quinn::Connection,
    driver: Driver,
    stream_session: StreamSession,
}

impl SessionRequest {
    pub(crate) fn new(
        quic_connection: quinn::Connection,
        driver: Driver,
        stream_session: StreamSession,
    ) -> Self {
        Self {
            quic_connection,
            driver,
            stream_session,
        }
    }

    /// Returns the peer's UDP address.
    ///
    /// **Note**: as QUIC supports migration, remote address may change
    /// during connection. Furthermore, when IPv6 support is enabled, IPv4
    /// addresses may be mapped to IPv6.
    #[inline(always)]
    pub fn remote_address(&self) -> SocketAddr {
        self.quic_connection.remote_address()
    }

    /// Returns the `:authority` field of the request.
    pub fn authority(&self) -> &str {
        self.stream_session.request().authority()
    }

    /// Returns the `:path` field of the request.
    pub fn path(&self) -> &str {
        self.stream_session.request().path()
    }

    /// Returns the `origin` field of the request if present.
    pub fn origin(&self) -> Option<&str> {
        self.stream_session.request().origin()
    }

    /// Returns the `user-agent` field of the request if present.
    pub fn user_agent(&self) -> Option<&str> {
        self.stream_session.request().user_agent()
    }

    /// Returns all header fields associated with the request.
    pub fn headers(&self) -> &HashMap<String, String> {
        self.stream_session.request().headers().as_ref()
    }

    /// Accepts the client request with headers.
    pub async fn accept_with_headers<I, K, V>(
        self,
        headers: I,
    ) -> Result<Connection, ConnectionError>
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        self.accept_impl(
            headers
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
        )
        .await
    }

    /// Accepts the client request and it establishes the WebTransport session.
    pub async fn accept(self) -> Result<Connection, ConnectionError> {
        self.accept_impl(HashMap::new()).await
    }

    /// Rejects the client request by replying with `403` status code.
    pub async fn forbidden(self) {
        self.reject(SessionResponseProto::forbidden()).await;
    }

    /// Rejects the client request by replying with `404` status code.
    pub async fn not_found(self) {
        self.reject(SessionResponseProto::not_found()).await;
    }

    /// Rejects the client request by replying with `429` status code.
    pub async fn too_many_requests(self) {
        self.reject(SessionResponseProto::too_many_requests()).await;
    }

    async fn accept_impl(
        mut self,
        headers: HashMap<String, String>,
    ) -> Result<Connection, ConnectionError> {
        let mut response = SessionResponseProto::ok();

        for (key, value) in headers {
            response.add(key, value);
        }

        self.send_response(response).await?;

        let session_id = self.stream_session.session_id();

        self.driver
            .register_session(self.stream_session)
            .await
            .map_err(|driver_error| {
                ConnectionError::with_driver_error(driver_error, &self.quic_connection)
            })?;

        Ok(Connection::new(
            self.quic_connection,
            self.driver,
            session_id,
        ))
    }

    async fn reject(mut self, response: SessionResponseProto) {
        let _ = self.send_response(response).await;
        self.stream_session.finish().await;
    }

    async fn send_response(
        &mut self,
        response: SessionResponseProto,
    ) -> Result<(), ConnectionError> {
        let frame = response.headers().generate_frame();

        match self.stream_session.write_frame(frame).await {
            Ok(()) => Ok(()),
            Err(ProtoWriteError::NotConnected) => {
                Err(ConnectionError::no_connect(&self.quic_connection))
            }
            Err(ProtoWriteError::Stopped) => {
                self.quic_connection
                    .close(varint_w2q(ErrorCode::ClosedCriticalStream.to_code()), b"");

                Err(ConnectionError::local_h3_error(
                    ErrorCode::ClosedCriticalStream,
                ))
            }
        }
    }
}

/// Whether a server's SETTINGS let a client establish a WebTransport session, under
/// any of the drafts this client can speak.
fn server_supports_webtransport(settings: &Settings) -> bool {
    let value = |id| settings.get(id).map_or(0, VarInt::into_inner);

    let enabled = value(SettingId::WtEnabled) > 0 // draft-15 and later
        || value(SettingId::WtMaxSessions) > 0 // draft-13 and draft-14
        || value(SettingId::WebTransportMaxSessions) > 0; // draft-07 to draft-12
    let current = enabled
        && value(SettingId::EnableConnectProtocol) == 1
        && value(SettingId::H3Datagram) == 1;

    // SETTINGS_ENABLE_WEBTRANSPORT (draft-02 to draft-06) is enough on its own: up to
    // draft-04 it implied extended CONNECT, and Chromium still treats it that way.
    current || value(SettingId::EnableWebTransport) == 1
}

/// Whether a client's SETTINGS let a server accept its WebTransport session.
fn client_supports_webtransport(settings: &Settings) -> bool {
    settings.get(SettingId::H3Datagram) == Some(VarInt::from_u32(1))
}

/// Closes the connection with `WT_REQUIREMENTS_NOT_MET`, returning the error for it.
fn requirements_not_met(quic_connection: &quinn::Connection) -> ConnectionError {
    quic_connection.close(
        varint_w2q(ErrorCode::RequirementsNotMet.to_code()),
        b"SETTINGS do not support WebTransport",
    );
    ConnectionError::local_h3_error(ErrorCode::RequirementsNotMet)
}

#[cfg(all(test, feature = "self-signed"))]
mod tests {
    use super::*;
    use crate::tls::client::build_default_tls_config;
    use crate::tls::Identity;
    use rustls::pki_types::CertificateDer;
    use rustls::RootCertStore;
    use std::time::Duration;
    use wtransport_proto::bytes::BytesWriter;
    use wtransport_proto::frame::Frame;
    use wtransport_proto::stream_header::StreamHeader;

    /// Connects a plain QUIC client to a server [`Endpoint`], returning the server's and
    /// the client's side of the connection.
    async fn quic_connection_pair(
        transport_config: quinn::TransportConfig,
    ) -> (quinn::Connection, quinn::Connection) {
        let identity = Identity::self_signed(["localhost"]).unwrap();

        let mut root_store = RootCertStore::empty();
        for certificate in identity.certificate_chain().as_slice() {
            root_store
                .add(CertificateDer::from(certificate.der().to_vec()))
                .unwrap();
        }

        let server = Endpoint::server(
            ServerConfig::builder()
                .with_bind_address(SocketAddr::from(([127, 0, 0, 1], 0)))
                .with_identity(identity)
                .build(),
        )
        .unwrap();
        let server_address = server.local_addr().unwrap();

        let tls_config = build_default_tls_config(Arc::new(root_store), None);
        let mut client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(tls_config).unwrap(),
        ));
        client_config.transport_config(Arc::new(transport_config));

        let mut client = quinn::Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
        client.set_default_client_config(client_config);

        let connecting = client.connect(server_address, "localhost").unwrap();
        let quic_connection = server.accept().await.0.await.unwrap();
        let client_connection = connecting.await.unwrap();

        (quic_connection, client_connection)
    }

    #[tokio::test]
    async fn dropping_driver_before_settings_closes_quic_connection() {
        let mut transport_config = quinn::TransportConfig::default();
        transport_config.max_concurrent_uni_streams(0u32.into());
        transport_config.keep_alive_interval(Some(Duration::from_millis(200)));
        let (quic_connection, client_connection) = quic_connection_pair(transport_config).await;

        let driver = Driver::init(quic_connection.clone());
        drop(driver);
        drop(quic_connection);

        assert!(
            tokio::time::timeout(Duration::from_secs(5), client_connection.closed())
                .await
                .is_ok()
        );
    }

    /// Parses SETTINGS made of `(id, value)` pairs.
    fn settings(pairs: &[(u32, u32)]) -> Settings {
        let mut payload = Vec::new();
        for &(id, value) in pairs {
            payload.put_varint(VarInt::from_u32(id)).unwrap();
            payload.put_varint(VarInt::from_u32(value)).unwrap();
        }
        Settings::with_frame(&Frame::new_settings(payload.into())).unwrap()
    }

    #[test]
    fn server_settings_requirements() {
        const CONNECT: u32 = 0x08;
        const DATAGRAM: u32 = 0x33;

        // Draft-02 to draft-06.
        assert!(server_supports_webtransport(&settings(&[(0x2b60_3742, 1)])));

        // Draft-07 to draft-12, draft-13 and draft-14, and draft-15 and later.
        for id in [0xc671_706a, 0x14e9_cd29, 0x2c7c_f000] {
            let supports = |pairs: &[(u32, u32)]| server_supports_webtransport(&settings(pairs));
            assert!(supports(&[(id, 1), (CONNECT, 1), (DATAGRAM, 1)]));
            assert!(!supports(&[(id, 0), (CONNECT, 1), (DATAGRAM, 1)]));
            assert!(!supports(&[(id, 1), (DATAGRAM, 1)]));
            assert!(!supports(&[(id, 1), (CONNECT, 1)]));
        }

        assert!(!server_supports_webtransport(&settings(&[
            (CONNECT, 1),
            (DATAGRAM, 1)
        ])));
    }

    #[test]
    fn client_settings_requirements() {
        assert!(client_supports_webtransport(&settings(&[(0x33, 1)])));
        assert!(!client_supports_webtransport(&settings(&[])));
    }

    #[tokio::test]
    async fn client_without_datagrams_is_refused() {
        let (quic_connection, client_connection) =
            quic_connection_pair(quinn::TransportConfig::default()).await;

        let server = tokio::spawn(IncomingSessionFuture::accept(quic_connection));

        // SETTINGS without SETTINGS_H3_DATAGRAM, then a CONNECT request.
        let mut control = client_connection.open_uni().await.unwrap();
        let mut buffer = Vec::new();
        StreamHeader::new_control().write(&mut buffer).unwrap();
        Settings::builder()
            .enable_webtransport()
            .build()
            .generate_frame()
            .write(&mut buffer)
            .unwrap();
        control.write_all(&buffer).await.unwrap();

        let (mut request, _response) = client_connection.open_bi().await.unwrap();
        let mut buffer = Vec::new();
        SessionRequestProto::new("https://localhost/")
            .unwrap()
            .headers()
            .generate_frame()
            .write(&mut buffer)
            .unwrap();
        request.write_all(&buffer).await.unwrap();

        let reason = tokio::time::timeout(Duration::from_secs(5), client_connection.closed())
            .await
            .unwrap();
        assert!(matches!(
            reason,
            quinn::ConnectionError::ApplicationClosed(close)
                if close.error_code == varint_w2q(ErrorCode::RequirementsNotMet.to_code())
        ));
        assert!(server.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn client_and_server_accept_each_others_settings() {
        let identity = Identity::self_signed(["localhost"]).unwrap();
        let hash = identity.certificate_chain().as_slice()[0].hash();

        let server = Endpoint::server(
            ServerConfig::builder()
                .with_bind_address(SocketAddr::from(([127, 0, 0, 1], 0)))
                .with_identity(identity)
                .build(),
        )
        .unwrap();
        let url = format!("https://{}/", server.local_addr().unwrap());

        let client = Endpoint::client(
            ClientConfig::builder()
                .with_bind_address(SocketAddr::from(([127, 0, 0, 1], 0)))
                .with_server_certificate_hashes([hash])
                .build(),
        )
        .unwrap();

        let (connection, request) = tokio::join!(client.connect(url), async {
            server.accept().await.await.unwrap().accept().await
        });
        connection.unwrap();
        request.unwrap();
    }

    #[tokio::test]
    async fn settings_frame_split_by_another_stream() {
        let (quic_connection, client_connection) =
            quic_connection_pair(quinn::TransportConfig::default()).await;

        let driver = Driver::init(quic_connection.clone());

        let settings = Settings::builder()
            .qpack_max_table_capacity(VarInt::from_u32(0))
            .build();
        let frame = settings.generate_frame();
        let mut buffer = Vec::new();
        StreamHeader::new_control().write(&mut buffer).unwrap();
        frame.write(&mut buffer).unwrap();
        let (head, payload) = buffer.split_at(buffer.len() - frame.payload().len());

        // The frame's type and length, then a new stream while the driver waits for the
        // payload. Should the driver drop its read of the frame to handle the new stream,
        // the type and length are lost, and the payload is read as a HEADERS frame.
        let mut control = client_connection.open_uni().await.unwrap();
        control.write_all(head).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut reserved = client_connection.open_uni().await.unwrap();
        reserved.write_all(&[0x21]).await.unwrap(); // A reserved stream type, ignored.
        tokio::time::sleep(Duration::from_millis(100)).await;
        control.write_all(payload).await.unwrap();

        let settings = tokio::time::timeout(Duration::from_secs(5), driver.accept_settings())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            settings.get(SettingId::QPackMaxTableCapacity),
            Some(VarInt::from_u32(0))
        );
    }
}
