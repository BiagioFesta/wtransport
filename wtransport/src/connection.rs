use crate::datagram::Datagram;
use crate::driver::Driver;
use crate::error::ConnectionError;
use crate::error::SendDatagramError;
use crate::stream::OpeningBiStream;
use crate::stream::OpeningUniStream;
use crate::stream::RecvStream;
use crate::stream::SendStream;
use std::net::SocketAddr;
use std::time::Duration;
use wtransport_proto::ids::SessionId;

/// A WebTransport session connection.
pub struct Connection {
    quic_connection: quinn::Connection,
    driver: Driver,
    session_id: SessionId,
}

impl Connection {
    pub(crate) fn new(
        quic_connection: quinn::Connection,
        driver: Driver,
        session_id: SessionId,
    ) -> Self {
        Self {
            quic_connection,
            driver,
            session_id,
        }
    }

    /// Accepts the next bi-directional stream.
    pub async fn accept_uni(&self) -> Result<RecvStream, ConnectionError> {
        let stream = self
            .driver
            .accept_uni(self.session_id)
            .await
            .map_err(|driver_error| {
                ConnectionError::with_driver_error(driver_error, &self.quic_connection)
            })?
            .into_stream();

        Ok(RecvStream::new(stream))
    }

    /// Accepts the next uni-directional stream.
    pub async fn accept_bi(&self) -> Result<(SendStream, RecvStream), ConnectionError> {
        let stream = self
            .driver
            .accept_bi(self.session_id)
            .await
            .map_err(|driver_error| {
                ConnectionError::with_driver_error(driver_error, &self.quic_connection)
            })?
            .into_stream();

        Ok((SendStream::new(stream.0), RecvStream::new(stream.1)))
    }

    /// Initiates a new outgoing bidirectional stream.
    pub async fn open_uni(&self) -> Result<OpeningUniStream, ConnectionError> {
        self.driver
            .open_uni(self.session_id)
            .await
            .map_err(|driver_error| {
                ConnectionError::with_driver_error(driver_error, &self.quic_connection)
            })
    }

    /// Initiates a new outgoing unidirectional stream.
    pub async fn open_bi(&self) -> Result<OpeningBiStream, ConnectionError> {
        self.driver
            .open_bi(self.session_id)
            .await
            .map_err(|driver_error| {
                ConnectionError::with_driver_error(driver_error, &self.quic_connection)
            })
    }

    /// Receives an application datagram.
    pub async fn receive_datagram(&self) -> Result<Datagram, ConnectionError> {
        self.driver
            .receive_datagram(self.session_id)
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
        self.driver.send_datagram(self.session_id, payload.as_ref())
    }

    /// Waits for the connection to be closed for any reason.
    pub async fn closed(&self) {
        let _ = self.quic_connection.closed().await;
    }

    /// Returns the WebTransport session identifier.
    #[inline(always)]
    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Returns the peer's UDP address.
    ///
    /// **Note**: as QUIC supports migration, remote address may change
    /// during connection.
    #[inline(always)]
    pub fn remote_address(&self) -> SocketAddr {
        self.quic_connection.remote_address()
    }

    /// A stable identifier for this connection.
    ///
    /// Peer addresses and connection IDs can change, but this value will remain
    /// fixed for the lifetime of the connection.
    #[inline(always)]
    pub fn stable_id(&self) -> usize {
        self.quic_connection.stable_id()
    }

    /// Computes the maximum size of datagrams that may be passed to [`send_datagram`](Self::send_datagram).
    ///
    /// Returns `None` if datagrams are unsupported by the peer or disabled locally.
    ///
    /// This may change over the lifetime of a connection according to variation in the path MTU
    /// estimate. The peer can also enforce an arbitrarily small fixed limit, but if the peer's
    /// limit is large this is guaranteed to be a little over a kilobyte at minimum.
    ///
    /// Not necessarily the maximum size of received datagrams.
    #[inline(always)]
    pub fn max_datagram_size(&self) -> Option<usize> {
        self.quic_connection.max_datagram_size()
    }

    /// Current best estimate of this connection's latency (round-trip-time).
    #[inline(always)]
    pub fn rtt(&self) -> Duration {
        self.quic_connection.rtt()
    }
}
