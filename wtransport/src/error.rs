use crate::engine::session::SessionError;
use crate::engine::worker::WorkerError;
use std::fmt::Debug;
use std::fmt::Formatter;
use wtransport_proto::varint::VarInt;

/// HTTP3 Error code.
pub type H3Code = wtransport_proto::error::Error;

/// An enumeration representing various errors that can occur during a WebTransport connection.
#[derive(Debug)]
pub enum ConnectionError {
    /// The connection was closed by the peer.
    ConnectionClosed(ConnectionClosed),

    /// The connection timed out.
    TimedOut,

    /// The connection was locally closed.
    LocallyClosed,

    /// An error occurred in the HTTP/3 local layer.
    H3(H3Error),

    /// An error occurred in the QUIC layer.
    QuicError,
}

impl ConnectionError {
    pub(crate) fn close_worker_error(
        worker_error: WorkerError,
        quic_connection: &quinn::Connection,
    ) -> Self {
        match worker_error {
            WorkerError::LocalClosed(h3error) => {
                // SAFETY: varint conversion
                let quic_varint = unsafe {
                    debug_assert!(
                        h3error.code().to_code().into_inner() <= quinn::VarInt::MAX.into_inner()
                    );
                    quinn::VarInt::from_u64_unchecked(h3error.code().to_code().into_inner())
                };

                quic_connection.close(quic_varint, h3error.reason().as_bytes());
                ConnectionError::H3(h3error)
            }
            WorkerError::RemoteClosed => quic_connection
                .close_reason()
                .expect("Worker closed before connection ended")
                .into(),
        }
    }

    pub(crate) fn close_session_error(
        session_error: SessionError,
        quic_connection: &quinn::Connection,
    ) -> Self {
        match session_error {
            SessionError::LocalClosed(h3error) => ConnectionError::H3(h3error),
            SessionError::RemoteClosed => quic_connection
                .close_reason()
                .expect("Worker closed before connection ended")
                .into(),
        }
    }
}

/// A struct representing the details of a connection closure.
pub struct ConnectionClosed {
    code: VarInt,
    reason: Vec<u8>,
}

impl ConnectionClosed {
    /// Varint code.
    #[inline(always)]
    pub fn code(&self) -> VarInt {
        self.code
    }

    /// The reason for the closure, as a byte vector.
    #[inline(always)]
    pub fn reason(&self) -> &[u8] {
        &self.reason
    }
}

impl Debug for ConnectionClosed {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let reason = String::from_utf8_lossy(&self.reason);

        write!(
            f,
            "Code: {} ({})",
            self.code,
            if self.reason.is_empty() {
                "N/A"
            } else {
                &reason
            }
        )
    }
}

/// A struct representing an error in the HTTP/3 layer.
#[derive(Clone)]
pub struct H3Error {
    code: H3Code,
    reason: String,
}

impl H3Error {
    pub(crate) fn new<S>(error_proto: H3Code, reason: S) -> Self
    where
        S: ToString,
    {
        Self {
            code: error_proto,
            reason: reason.to_string(),
        }
    }

    /// The HTTP3 error code.
    pub fn code(&self) -> H3Code {
        self.code
    }

    /// The reason of the failure as human readable string.
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

impl Debug for H3Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Code: {} ({})", self.code, &self.reason)
    }
}

/// An enumeration representing various errors that can occur during a WebTransport stream.
#[derive(Debug)]
pub enum StreamError {
    /// The connection associated with the stream was closed.
    ConnectionClosed,

    /// The stream was stopped.
    Stopped,
}

/// Error when dealing with application datagrams.
#[derive(Debug)]
pub enum DatagramError {
    /// The connection has been closed.
    ConnectionClosed,

    /// Datagrams are not supported by peer.
    UnsupportedByPeer,

    /// Error at QUIC protocol layer.
    Protocol,
}

impl From<quinn::ConnectionError> for ConnectionError {
    fn from(error: quinn::ConnectionError) -> Self {
        match error {
            quinn::ConnectionError::VersionMismatch => ConnectionError::QuicError,
            quinn::ConnectionError::TransportError(_) => ConnectionError::QuicError,
            quinn::ConnectionError::ConnectionClosed(quic_close) => {
                ConnectionError::ConnectionClosed(ConnectionClosed {
                    code: quic_errno_to_code(quic_close.error_code),
                    reason: quic_close.reason.into(),
                })
            }
            quinn::ConnectionError::ApplicationClosed(quic_close) => {
                // SAFETY: varint conversion
                let code = unsafe {
                    debug_assert!(quic_close.error_code.into_inner() <= VarInt::MAX.into_inner());
                    VarInt::from_u64_unchecked(quic_close.error_code.into_inner())
                };

                ConnectionError::ConnectionClosed(ConnectionClosed {
                    code,
                    reason: quic_close.reason.into(),
                })
            }
            quinn::ConnectionError::Reset => ConnectionError::QuicError,
            quinn::ConnectionError::TimedOut => ConnectionError::TimedOut,
            quinn::ConnectionError::LocallyClosed => ConnectionError::LocallyClosed,
        }
    }
}

fn quic_errno_to_code(code: quinn_proto::TransportErrorCode) -> VarInt {
    match code {
        quinn_proto::TransportErrorCode::NO_ERROR => VarInt::from_u32(0x00),
        quinn_proto::TransportErrorCode::INTERNAL_ERROR => VarInt::from_u32(0x01),
        quinn_proto::TransportErrorCode::CONNECTION_REFUSED => VarInt::from_u32(0x02),
        quinn_proto::TransportErrorCode::FLOW_CONTROL_ERROR => VarInt::from_u32(0x03),
        quinn_proto::TransportErrorCode::STREAM_LIMIT_ERROR => VarInt::from_u32(0x04),
        quinn_proto::TransportErrorCode::STREAM_STATE_ERROR => VarInt::from_u32(0x05),
        quinn_proto::TransportErrorCode::FINAL_SIZE_ERROR => VarInt::from_u32(0x06),
        quinn_proto::TransportErrorCode::FRAME_ENCODING_ERROR => VarInt::from_u32(0x07),
        quinn_proto::TransportErrorCode::TRANSPORT_PARAMETER_ERROR => VarInt::from_u32(0x08),
        quinn_proto::TransportErrorCode::CONNECTION_ID_LIMIT_ERROR => VarInt::from_u32(0x09),
        quinn_proto::TransportErrorCode::PROTOCOL_VIOLATION => VarInt::from_u32(0x0a),
        quinn_proto::TransportErrorCode::INVALID_TOKEN => VarInt::from_u32(0x0b),
        quinn_proto::TransportErrorCode::APPLICATION_ERROR => VarInt::from_u32(0x0c),
        quinn_proto::TransportErrorCode::CRYPTO_BUFFER_EXCEEDED => VarInt::from_u32(0x0d),
        quinn_proto::TransportErrorCode::KEY_UPDATE_ERROR => VarInt::from_u32(0x0e),
        quinn_proto::TransportErrorCode::AEAD_LIMIT_REACHED => VarInt::from_u32(0x0f),
        quinn_proto::TransportErrorCode::NO_VIABLE_PATH => VarInt::from_u32(0x10),
        _ => VarInt::from_u32(0x0),
    }
}

impl From<quinn::WriteError> for StreamError {
    fn from(error: quinn::WriteError) -> Self {
        match error {
            quinn::WriteError::Stopped(_) => StreamError::Stopped,
            quinn::WriteError::ConnectionLost(_) => StreamError::ConnectionClosed,
            quinn::WriteError::UnknownStream => StreamError::Stopped,
            quinn::WriteError::ZeroRttRejected => StreamError::Stopped,
        }
    }
}

impl From<quinn::ReadError> for StreamError {
    fn from(error: quinn::ReadError) -> Self {
        match error {
            quinn::ReadError::Reset(_) => StreamError::Stopped,
            quinn::ReadError::ConnectionLost(_) => StreamError::ConnectionClosed,
            quinn::ReadError::UnknownStream => StreamError::Stopped,
            quinn::ReadError::IllegalOrderedRead => StreamError::Stopped,
            quinn::ReadError::ZeroRttRejected => StreamError::Stopped,
        }
    }
}

impl From<quinn::StoppedError> for StreamError {
    fn from(error: quinn::StoppedError) -> Self {
        match error {
            quinn::StoppedError::ConnectionLost(_) => StreamError::ConnectionClosed,
            quinn::StoppedError::UnknownStream => StreamError::Stopped,
            quinn::StoppedError::ZeroRttRejected => StreamError::Stopped,
        }
    }
}

impl From<quinn::SendDatagramError> for DatagramError {
    fn from(error: quinn::SendDatagramError) -> Self {
        match error {
            quinn::SendDatagramError::UnsupportedByPeer => DatagramError::UnsupportedByPeer,
            quinn::SendDatagramError::Disabled => Self::Protocol,
            quinn::SendDatagramError::TooLarge => Self::Protocol,
            quinn::SendDatagramError::ConnectionLost(_) => DatagramError::ConnectionClosed,
        }
    }
}
