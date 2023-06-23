use crate::config::ClientConfig;
use crate::config::ServerConfig;
use crate::connection::Connection;
use crate::driver::streams::session::StreamSession;
use crate::driver::streams::ProtoWriteError;
use crate::driver::Driver;
use crate::error::ConnectionError;
use quinn::Endpoint as QuicEndpoint;
use std::future::Future;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;
use wtransport_proto::frame::FrameKind;
use wtransport_proto::headers::Headers;
use wtransport_proto::session::SessionRequest as SessionRequestProto;
use wtransport_proto::session::SessionResponse as SessionResponseProto;

/// Type of endpoint accepting multiple WebTransport connections.
pub struct Server;

/// Type of endpoint opening a WebTransport connection.
pub struct Client;

/// Entrypoint for creating client or server connections.
///
/// * For creating a server: [`Endpoint::server`].
/// * For creating a client: [`Endpoint::client`].
pub struct Endpoint<Side> {
    endpoint: QuicEndpoint,
    _marker: PhantomData<Side>,
}

impl Endpoint<Server> {
    /// Constructs a *server* endpoint.
    pub fn server(server_config: ServerConfig) -> std::io::Result<Self> {
        let quic_config = server_config.quic_config;
        let bind_address = server_config.bind_address;

        let endpoint = QuicEndpoint::server(quic_config, bind_address)?;

        Ok(Self {
            endpoint,
            _marker: PhantomData,
        })
    }

    /// Get the next incoming connection attempt from a client.
    pub async fn accept(&self) -> IncomingSession {
        let quic_connecting = self
            .endpoint
            .accept()
            .await
            .expect("Endpoint cannot be closed");

        IncomingSession::new(quic_connecting)
    }
}

impl Endpoint<Client> {
    /// Constructs a *client* endpoint.
    pub fn client(client_config: ClientConfig) -> std::io::Result<Self> {
        let quic_config = client_config.quic_config;
        let bind_address = client_config.bind_address;

        let mut endpoint = QuicEndpoint::client(bind_address)?;
        endpoint.set_default_client_config(quic_config);

        Ok(Self {
            endpoint,
            _marker: PhantomData,
        })
    }

    /// Connects to a remote endpoint.
    ///
    /// `server_name` must be covered by the certificate presented by the server.
    pub fn connect(
        &self,
        remote_address: SocketAddr,
        server_name: &str,
    ) -> Result<OutgoingSession, ConnectionError> {
        let quic_connecting = self.endpoint.connect(remote_address, server_name).unwrap();
        Ok(OutgoingSession::new(quic_connecting))
    }
}

type DynFutureIncomingSession = dyn Future<Output = Result<SessionRequest, ConnectionError>>;

pub struct IncomingSession(Pin<Box<DynFutureIncomingSession>>);

impl IncomingSession {
    fn new(quic_connecting: quinn::Connecting) -> Self {
        Self(Box::pin(Self::accept(quic_connecting)))
    }

    async fn accept(quic_connecting: quinn::Connecting) -> Result<SessionRequest, ConnectionError> {
        let quic_connection = quic_connecting.await?;

        let driver = Driver::init(quic_connection.clone());

        let _settings = driver.accept_settings().await.map_err(|driver_error| {
            ConnectionError::with_driver_error(driver_error, &quic_connection)
        })?;

        // TODO(biagio): validate settings

        let stream_session = driver.accept_session().await.map_err(|driver_error| {
            ConnectionError::with_driver_error(driver_error, &quic_connection)
        })?;

        Ok(SessionRequest::new(quic_connection, driver, stream_session))
    }
}

impl Future for IncomingSession {
    type Output = Result<SessionRequest, ConnectionError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Future::poll(self.0.as_mut(), cx)
    }
}

type DynFutureOutgoingSession = dyn Future<Output = Result<Connection, ConnectionError>>;

pub struct OutgoingSession(Pin<Box<DynFutureOutgoingSession>>);

impl OutgoingSession {
    fn new(quic_connecting: quinn::Connecting) -> Self {
        Self(Box::pin(Self::connect(quic_connecting)))
    }

    async fn connect(quic_connecting: quinn::Connecting) -> Result<Connection, ConnectionError> {
        let quic_connection = quic_connecting.await?;

        let driver = Driver::init(quic_connection.clone());

        let _settings = driver.accept_settings().await.map_err(|driver_error| {
            ConnectionError::with_driver_error(driver_error, &quic_connection)
        })?;

        // TODO(biagio): validate settings

        let session_request = SessionRequestProto::new("https://test.dev/").unwrap();

        let mut stream_session =
            driver
                .open_session(session_request)
                .await
                .map_err(|driver_error| {
                    ConnectionError::with_driver_error(driver_error, &quic_connection)
                })?;

        stream_session
            .write_frame(
                stream_session
                    .request()
                    .headers()
                    .generate_frame(stream_session.id()),
            )
            .await
            .map_err(|_| ConnectionError::SessionRejected)?;

        let session_id = stream_session.session_id();

        let frame = stream_session.read_frame().await.unwrap();
        if !matches!(frame.kind(), FrameKind::Headers) {
            todo!()
        }

        let session_response = SessionResponseProto::try_from(
            Headers::with_frame(&frame, stream_session.id()).unwrap(),
        )
        .unwrap();

        if session_response.code().is_successful() {
            driver.register_session(stream_session).await.unwrap();
        } else {
            todo!()
        }

        Ok(Connection::new(quic_connection, driver, session_id))
    }
}

impl Future for OutgoingSession {
    type Output = Result<Connection, ConnectionError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Future::poll(self.0.as_mut(), cx)
    }
}

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

    /// Returns the `:authority` field of the request.
    pub fn authority(&self) -> &str {
        self.stream_session.request().authority()
    }

    /// Returns the `:path` field of the request.
    pub fn path(&self) -> &str {
        self.stream_session.request().path()
    }

    /// Returns the whole headers associated with the request.
    pub fn headers(&self) -> &Headers {
        self.stream_session.request().headers()
    }

    pub async fn accept(mut self) -> Result<Connection, ConnectionError> {
        let mut response = SessionResponseProto::ok();

        // Chrome support
        if self
            .headers()
            .get("sec-webtransport-http3-draft02")
            .is_some()
        {
            response.add("sec-webtransport-http3-draft", "draft02");
        }

        let frame = response.headers().generate_frame(self.stream_session.id());

        match self.stream_session.write_frame(frame).await {
            Ok(()) => {
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
            Err(ProtoWriteError::NotConnected) => {
                todo!()
            }
            Err(ProtoWriteError::Stopped) => {
                todo!()
            }
        }
    }

    pub fn deny(self) {
        todo!()
    }
}
