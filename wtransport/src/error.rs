use crate::driver::utils::varint_q2w;
use crate::driver::DriverError;
use crate::VarInt;
use std::borrow::Cow;
use std::fmt::Display;
use std::net::SocketAddr;
use wtransport_proto::error::ErrorCode;

/// An enumeration representing various errors that can occur during a WebTransport connection.
#[derive(thiserror::Error, Debug, Clone, Eq, PartialEq)]
pub enum ConnectionError {
    /// The connection was aborted by the peer (protocol level).
    #[error("connection aborted by peer: {0}")]
    ConnectionClosed(ConnectionClose),

    /// The connection was closed by the peer (application level).
    #[error("connection closed by peer: {0}")]
    ApplicationClosed(ApplicationClose),

    /// The connection was locally closed.
    #[error("connection locally closed")]
    LocallyClosed,

    /// The connection was locally closed because an HTTP3 protocol violation.
    #[error("connection locally aborted: {0}")]
    LocalH3Error(H3Error),

    /// The connection timed out.
    #[error("connection timed out")]
    TimedOut,

    /// The connection was closed because a QUIC protocol error.
    #[error("QUIC protocol error: {0}")]
    QuicProto(QuicProtoError),

    /// The connection could not be created because not enough of the CID space is available
    ///
    /// Try using longer connection IDs.
    #[error("CIDs exhausted")]
    CidsExhausted,
}

impl ConnectionError {
    pub(crate) fn with_driver_error(
        driver_error: DriverError,
        quic_connection: &quinn::Connection,
    ) -> Self {
        match driver_error {
            DriverError::Proto(error_code) => Self::local_h3_error(error_code),
            DriverError::ApplicationClosed(close) => Self::ApplicationClosed(close),
            DriverError::NotConnected => Self::no_connect(quic_connection),
        }
    }

    pub(crate) fn no_connect(quic_connection: &quinn::Connection) -> Self {
        quic_connection
            .close_reason()
            .expect("QUIC connection is still alive on close-cast")
            .into()
    }

    pub(crate) fn local_h3_error(error_code: ErrorCode) -> Self {
        ConnectionError::LocalH3Error(H3Error { code: error_code })
    }
}

/// An enumeration representing various errors that can occur during a WebTransport client connecting.
#[derive(thiserror::Error, Debug)]
pub enum ConnectingError {
    /// URL provided for connection is not valid.
    #[error("invalid URL: {0}")]
    InvalidUrl(String),

    /// Failure during DNS resolution.
    #[error("cannot resolve domain: {0}")]
    DnsLookup(std::io::Error),

    /// Cannot find any DNS.
    #[error("cannot resolve domain")]
    DnsNotFound,

    /// Connection error during handshaking.
    #[error(transparent)]
    ConnectionError(ConnectionError),

    /// Request rejected.
    #[error("server rejected WebTransport session request")]
    SessionRejected,

    /// Cannot use reserved key for additional headers.
    #[error("additional header '{0}' is reserved")]
    ReservedHeader(String),

    /// The endpoint can no longer create new connections
    ///
    /// Indicates that a necessary component of the endpoint has been dropped or otherwise disabled.
    #[error("endpoint stopping")]
    EndpointStopping,

    /// The connection could not be created because not enough of the CID space is available
    ///
    /// Try using longer connection IDs
    #[error("CIDs exhausted")]
    CidsExhausted,

    /// The server name supplied was malformed
    #[error("invalid server name: {0}")]
    InvalidServerName(String),

    /// The remote [`SocketAddr`] supplied was malformed.
    ///
    /// Examples include attempting to connect to port 0, or using an inappropriate address family.
    #[error("invalid remote address: {0}")]
    InvalidRemoteAddress(SocketAddr),
}

impl ConnectingError {
    pub(crate) fn with_no_connection(quic_connection: &quinn::Connection) -> Self {
        ConnectingError::ConnectionError(
            quic_connection
                .close_reason()
                .expect("QUIC connection is still alive on close-cast")
                .into(),
        )
    }

    pub(crate) fn with_connect_error(error: quinn::ConnectError) -> Self {
        match error {
            quinn::ConnectError::EndpointStopping => ConnectingError::EndpointStopping,
            quinn::ConnectError::CidsExhausted => ConnectingError::CidsExhausted,
            quinn::ConnectError::InvalidServerName(name) => {
                ConnectingError::InvalidServerName(name)
            }
            quinn::ConnectError::InvalidRemoteAddress(socket_addr) => {
                ConnectingError::InvalidRemoteAddress(socket_addr)
            }
            quinn::ConnectError::NoDefaultClientConfig => {
                unreachable!("quic client config is internally provided")
            }
            quinn::ConnectError::UnsupportedVersion => {
                unreachable!("quic version is internally configured")
            }
        }
    }
}

/// Error indicating that a stream has been already finished or reset.
#[derive(thiserror::Error, Debug)]
#[error("closed stream")]
pub struct ClosedStream;

/// An error that arise from writing to a stream.
#[derive(thiserror::Error, Debug, Clone, Eq, PartialEq)]
pub enum StreamWriteError {
    /// Connection has been dropped.
    #[error("not connected")]
    NotConnected,

    /// The stream was already finished or reset locally.
    #[error("stream closed")]
    Closed,

    /// The peer is no longer accepting data on this stream.
    #[error("stream stopped (code: {0})")]
    Stopped(VarInt),

    /// QUIC protocol error.
    #[error("QUIC protocol error")]
    QuicProto,
}

/// An error that arise from reading from a stream.
#[derive(thiserror::Error, Debug, Clone, Eq, PartialEq)]
pub enum StreamReadError {
    /// Connection has been dropped.
    #[error("not connected")]
    NotConnected,

    /// The peer abandoned transmitting data on this stream
    #[error("stream reset (code: {0})")]
    Reset(VarInt),

    /// QUIC protocol error.
    #[error("QUIC protocol error")]
    QuicProto,
}

/// An error that arise from reading from a stream.
#[derive(thiserror::Error, Debug, Clone)]
pub enum StreamReadExactError {
    /// The stream finished before all bytes were read.
    #[error("stream finished too early ({0} bytes read)")]
    FinishedEarly(usize),

    /// A read error occurred.
    #[error(transparent)]
    Read(StreamReadError),
}

/// An error that arise from sending a datagram.
#[derive(thiserror::Error, Debug, Clone, Eq, PartialEq)]
pub enum SendDatagramError {
    /// Connection has been dropped.
    #[error("not connected")]
    NotConnected,

    /// The peer does not support receiving datagram frames.
    #[error("peer does not support datagrams")]
    UnsupportedByPeer,

    /// The datagram is larger than the connection can currently accommodate.
    #[error("datagram payload too large")]
    TooLarge,
}

/// An error that arise when opening a new stream.
#[derive(thiserror::Error, Debug, Clone, Eq, PartialEq)]
pub enum StreamOpeningError {
    /// Connection has been dropped.
    #[error("not connected")]
    NotConnected,

    /// The peer refused the stream, stopping it during initialization.
    #[error("opening stream refused")]
    Refused,
}

/// Reason given by an application for closing the connection
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ApplicationClose {
    code: VarInt,
    reason: Box<[u8]>,
}

impl Display for ApplicationClose {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.reason.is_empty() {
            self.code.fmt(f)?;
        } else {
            f.write_str(&String::from_utf8_lossy(&self.reason))?;
            f.write_str(" (code ")?;
            self.code.fmt(f)?;
            f.write_str(")")?;
        }
        Ok(())
    }
}

impl ApplicationClose {
    /// Creates a new application close reason.
    pub(crate) fn new(code: VarInt, reason: Box<[u8]>) -> Self {
        Self { code, reason }
    }

    /// Application-specific code for close operation.
    pub fn code(&self) -> VarInt {
        self.code
    }

    /// Data containing the reason for closing operation.
    pub fn reason(&self) -> &[u8] {
        &self.reason
    }
}

/// Reason given by the transport for closing the connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionClose(quinn::ConnectionClose);

impl Display for ConnectionClose {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// A struct representing an error in the HTTP3 layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H3Error {
    code: ErrorCode,
}

impl Display for H3Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.code.fmt(f)
    }
}

impl From<quinn::ConnectionError> for ConnectionError {
    fn from(error: quinn::ConnectionError) -> Self {
        match error {
            quinn::ConnectionError::VersionMismatch => ConnectionError::QuicProto(QuicProtoError {
                code: None,
                reason: Cow::Borrowed("QUIC protocol version mismatched"),
            }),
            quinn::ConnectionError::TransportError(e) => {
                ConnectionError::QuicProto(QuicProtoError {
                    code: VarInt::try_from_u64(e.code.into()).ok(),
                    reason: Cow::Owned(e.reason),
                })
            }
            quinn::ConnectionError::ConnectionClosed(close) => {
                ConnectionError::ConnectionClosed(ConnectionClose(close))
            }
            quinn::ConnectionError::ApplicationClosed(close) => {
                ConnectionError::ApplicationClosed(ApplicationClose {
                    code: varint_q2w(close.error_code),
                    reason: close.reason.to_vec().into_boxed_slice(),
                })
            }
            quinn::ConnectionError::Reset => ConnectionError::QuicProto(QuicProtoError {
                code: None,
                reason: Cow::Borrowed("connection has been reset"),
            }),
            quinn::ConnectionError::TimedOut => ConnectionError::TimedOut,
            quinn::ConnectionError::LocallyClosed => ConnectionError::LocallyClosed,
            quinn::ConnectionError::CidsExhausted => ConnectionError::CidsExhausted,
        }
    }
}

/// A complete specification of an error over QUIC protocol.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct QuicProtoError {
    code: Option<VarInt>,
    reason: Cow<'static, str>,
}

impl Display for QuicProtoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let code = self
            .code
            .map(|code| format!(" (code: {})", code))
            .unwrap_or_default();

        f.write_fmt(format_args!("{}{}", self.reason, code))
    }
}

/// Error returned by [`Connection::export_keying_material`](crate::Connection::export_keying_material).
///
/// This error occurs if the requested output length is too large.
#[derive(Debug, thiserror::Error, Clone, Eq, PartialEq)]
#[error("cannot derive keying material as requested output length is too large")]
pub struct ExportKeyingMaterialError;
