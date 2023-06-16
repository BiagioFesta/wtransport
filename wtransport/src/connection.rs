use crate::datagram::Datagram;
use crate::driver::Driver;
use crate::error::ConnectionError;
use crate::error::SendDatagramError;
use crate::session::SessionInfo;
use crate::stream::OpeningBiStream;
use crate::stream::OpeningUniStream;
use crate::stream::RecvStream;
use crate::stream::SendStream;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;

/// [`Future`] for an in-progress connection attempt.
pub struct Connecting(
    Pin<Box<dyn Future<Output = Result<Connection, ConnectionError>> + Send + Sync>>,
);

impl Connecting {
    pub(crate) fn new(is_server: bool, quic_connecting: quinn::Connecting) -> Self {
        Self(Box::pin(async move {
            Self::connect(is_server, quic_connecting).await
        }))
    }

    async fn connect(
        is_server: bool,
        quic_connecting: quinn::Connecting,
    ) -> Result<Connection, ConnectionError> {
        let quic_connection = quic_connecting.await?;

        let driver = Driver::init(is_server, quic_connection.clone());

        let session_info = driver.accept_session().await.map_err(|driver_error| {
            ConnectionError::with_driver_error(driver_error, &quic_connection)
        })?;

        Ok(Connection {
            quic_connection,
            driver,
            session_info,
        })
    }
}

impl Future for Connecting {
    type Output = Result<Connection, ConnectionError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Future::poll(self.0.as_mut(), cx)
    }
}

/// A WebTransport session connection.
pub struct Connection {
    quic_connection: quinn::Connection,
    driver: Driver,
    session_info: SessionInfo,
}

impl Connection {
    /// Accepts the next uni-directional stream.
    pub async fn accept_bi(&self) -> Result<(SendStream, RecvStream), ConnectionError> {
        let stream = self
            .driver
            .accept_bi()
            .await
            .map_err(|driver_error| {
                ConnectionError::with_driver_error(driver_error, &self.quic_connection)
            })?
            .into_stream();

        Ok((SendStream::new(stream.0), RecvStream::new(stream.1)))
    }

    /// Accepts the next bi-directional stream.
    pub async fn accept_uni(&self) -> Result<RecvStream, ConnectionError> {
        let stream = self
            .driver
            .accept_uni()
            .await
            .map_err(|driver_error| {
                ConnectionError::with_driver_error(driver_error, &self.quic_connection)
            })?
            .into_stream();

        Ok(RecvStream::new(stream))
    }

    /// Initiates a new outgoing unidirectional stream.
    pub async fn open_bi(&self) -> Result<OpeningBiStream, ConnectionError> {
        self.driver
            .open_bi(self.session_info.id())
            .await
            .map_err(|driver_error| {
                ConnectionError::with_driver_error(driver_error, &self.quic_connection)
            })
    }

    /// Initiates a new outgoing bidirectional stream.
    pub async fn open_uni(&self) -> Result<OpeningUniStream, ConnectionError> {
        self.driver
            .open_uni(self.session_info.id())
            .await
            .map_err(|driver_error| {
                ConnectionError::with_driver_error(driver_error, &self.quic_connection)
            })
    }

    /// Receives an application datagram.
    pub async fn receive_datagram(&self) -> Result<Datagram, ConnectionError> {
        self.driver
            .receive_datagram(self.session_info.id())
            .await
            .map_err(|driver_error| {
                ConnectionError::with_driver_error(driver_error, &self.quic_connection)
            })
    }

    /// Sends an application datagram.
    pub fn send_datagram<D>(&self, payload: D) -> Result<(), SendDatagramError>
    where
        D: AsRef<[u8]>,
    {
        self.driver
            .send_datagram(self.session_info.id(), payload.as_ref())
    }

    /// Waits for the connection to be closed for any reason.
    pub async fn closed(&self) {
        let _ = self.quic_connection.closed().await;
    }

    /// Returns the WebTransport session information.
    #[inline(always)]
    pub fn session_info(&self) -> &SessionInfo {
        &self.session_info
    }

    /// Returns the peer's UDP address.
    ///
    /// **Note**: as QUIC supports migration, remote address may change
    /// during connection.
    #[inline(always)]
    pub fn remote_address(&self) -> SocketAddr {
        self.quic_connection.remote_address()
    }
}
