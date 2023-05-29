use crate::engine::session::SessionError;
use crate::engine::worker::WorkerError;
use std::fmt::Debug;
use std::fmt::Formatter;

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
                quic_connection.close(h3error.code_varint(), h3error.reason().as_bytes());
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
    code: u64,
    reason: Vec<u8>,
}

impl ConnectionClosed {
    /// Varint code.
    pub fn code(&self) -> u64 {
        self.code
    }

    /// The reason for the closure, as a byte vector.
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

    fn code_varint(&self) -> quinn::VarInt {
        quinn::VarInt::from_u64(self.code.to_code()).expect("H3 errno is expected to fit varint")
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
                    reason: quic_close.reason.to_vec(),
                })
            }
            quinn::ConnectionError::ApplicationClosed(quic_close) => {
                ConnectionError::ConnectionClosed(ConnectionClosed {
                    code: quic_close.error_code.into_inner(),
                    reason: quic_close.reason.to_vec(),
                })
            }
            quinn::ConnectionError::Reset => ConnectionError::QuicError,
            quinn::ConnectionError::TimedOut => ConnectionError::TimedOut,
            quinn::ConnectionError::LocallyClosed => ConnectionError::LocallyClosed,
        }
    }
}

fn quic_errno_to_code(code: quinn_proto::TransportErrorCode) -> u64 {
    match code {
        quinn_proto::TransportErrorCode::NO_ERROR => 0x00,
        quinn_proto::TransportErrorCode::INTERNAL_ERROR => 0x01,
        quinn_proto::TransportErrorCode::CONNECTION_REFUSED => 0x02,
        quinn_proto::TransportErrorCode::FLOW_CONTROL_ERROR => 0x03,
        quinn_proto::TransportErrorCode::STREAM_LIMIT_ERROR => 0x04,
        quinn_proto::TransportErrorCode::STREAM_STATE_ERROR => 0x05,
        quinn_proto::TransportErrorCode::FINAL_SIZE_ERROR => 0x06,
        quinn_proto::TransportErrorCode::FRAME_ENCODING_ERROR => 0x07,
        quinn_proto::TransportErrorCode::TRANSPORT_PARAMETER_ERROR => 0x08,
        quinn_proto::TransportErrorCode::CONNECTION_ID_LIMIT_ERROR => 0x09,
        quinn_proto::TransportErrorCode::PROTOCOL_VIOLATION => 0x0a,
        quinn_proto::TransportErrorCode::INVALID_TOKEN => 0x0b,
        quinn_proto::TransportErrorCode::APPLICATION_ERROR => 0x0c,
        quinn_proto::TransportErrorCode::CRYPTO_BUFFER_EXCEEDED => 0x0d,
        quinn_proto::TransportErrorCode::KEY_UPDATE_ERROR => 0x0e,
        quinn_proto::TransportErrorCode::AEAD_LIMIT_REACHED => 0x0f,
        quinn_proto::TransportErrorCode::NO_VIABLE_PATH => 0x10,
        _ => 0x0,
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
