use crate::datagram::Datagram;
use crate::engine::session::Session;
use crate::engine::Engine;
use crate::error::ConnectionError;
use crate::error::DatagramError;
use crate::stream::RecvStream;
use crate::stream::SendStream;
use std::future::Future;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;
use wtransport_proto::frame::SessionId;

/// [`Future`] for an in-progress connection attempt.
pub struct Connecting(
    Pin<Box<dyn Future<Output = Result<Connection, ConnectionError>> + Send + Sync>>,
);

impl Connecting {
    pub(crate) fn new(is_server: bool, quic_connecting: quinn::Connecting) -> Self {
        if is_server {
            Self(Box::pin(async {
                Self::connect_as_server(quic_connecting).await
            }))
        } else {
            Self(Box::pin(async {
                Self::connect_as_client(quic_connecting).await
            }))
        }
    }

    async fn connect_as_server(
        quic_connecting: quinn::Connecting,
    ) -> Result<Connection, ConnectionError> {
        let quic_connection = quic_connecting.await?;
        let engine = Engine::new(quic_connection.clone());

        let _remote_settings = engine.remote_settings().await.map_err(|worker_error| {
            ConnectionError::close_worker_error(worker_error, &quic_connection)
        })?;

        // TODO(bfesta): validate settings

        let session = engine
            .accept_session()
            .await
            .map_err(|worker_error| {
                ConnectionError::close_worker_error(worker_error, &quic_connection)
            })?
            .accept()
            .await
            .map_err(|session_error| {
                ConnectionError::close_session_error(session_error, &quic_connection)
            })?;

        Ok(Connection {
            quic_connection,
            engine,
            session,
        })
    }

    async fn connect_as_client(
        quic_connecting: quinn::Connecting,
    ) -> Result<Connection, ConnectionError> {
        let quic_connection = quic_connecting.await?;
        let engine = Engine::new(quic_connection.clone());

        let _remote_settings = engine.remote_settings().await.map_err(|worker_error| {
            ConnectionError::close_worker_error(worker_error, &quic_connection)
        })?;

        // TODO(bfesta): validate settings

        let session = engine
            .connect_session()
            .await
            .map_err(|worker_error| {
                ConnectionError::close_worker_error(worker_error, &quic_connection)
            })?
            .request()
            .await
            .map_err(|session_error| {
                ConnectionError::close_session_error(session_error, &quic_connection)
            })?
            .confirm()
            .await
            .map_err(|session_error| {
                ConnectionError::close_session_error(session_error, &quic_connection)
            })?;

        Ok(Connection {
            quic_connection,
            engine,
            session,
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
    engine: Engine,
    session: Session,
}

impl Connection {
    /// Accepts the next uni-directional stream.
    pub async fn accept_bi(&self) -> Result<(SendStream, RecvStream), ConnectionError> {
        let wtstream = self.engine.accept_bi().await.map_err(|worker_error| {
            ConnectionError::close_worker_error(worker_error, &self.quic_connection)
        })?;

        let raw_stream = wtstream.raw();

        Ok((SendStream::new(raw_stream.0), RecvStream::new(raw_stream.1)))
    }

    /// Accepts the next bi-directional stream.
    pub async fn accept_uni(&self) -> Result<RecvStream, ConnectionError> {
        let wtstream = self.engine.accept_uni().await.map_err(|worker_error| {
            ConnectionError::close_worker_error(worker_error, &self.quic_connection)
        })?;

        let raw_stream = wtstream.raw();

        Ok(RecvStream::new(raw_stream))
    }

    /// Initiates a new outgoing unidirectional stream.
    pub async fn open_bi(&self) -> Result<(SendStream, RecvStream), ConnectionError> {
        let wtstream = self
            .engine
            .open_bi(self.session.id())
            .await
            .map_err(|worker_error| {
                ConnectionError::close_worker_error(worker_error, &self.quic_connection)
            })?;

        let raw_stream = wtstream.raw();

        Ok((SendStream::new(raw_stream.0), RecvStream::new(raw_stream.1)))
    }

    /// Initiates a new outgoing bidirectional stream.
    pub async fn open_uni(&self) -> Result<SendStream, ConnectionError> {
        let wtstream = self
            .engine
            .open_uni(self.session.id())
            .await
            .map_err(|worker_error| {
                ConnectionError::close_worker_error(worker_error, &self.quic_connection)
            })?;

        let raw_stream = wtstream.raw();

        Ok(SendStream::new(raw_stream))
    }

    /// Receives an application datagram.
    pub async fn receive_datagram(&self) -> Result<Datagram, DatagramError> {
        self.engine
            .receive_datagram(self.session.id())
            .await
            .map_err(|worker_error| {
                ConnectionError::close_worker_error(worker_error, &self.quic_connection);
                DatagramError::ConnectionClosed
            })
    }

    /// Sends an application datagram.
    pub async fn send_datagram<D>(&self, data: D) -> Result<(), DatagramError>
    where
        D: AsRef<[u8]>,
    {
        self.engine
            .send_datagram(data.as_ref(), self.session.id())
            .await
    }

    /// Returns the WebTransport session identifier.
    #[inline(always)]
    pub fn session_id(&self) -> SessionId {
        self.session.id()
    }
}
