use crate::driver::streams::bilocal::StreamBiLocalQuic;
use crate::driver::streams::unilocal::StreamUniLocalQuic;
use crate::driver::streams::ProtoWriteError;
use crate::driver::streams::QuicRecvStream;
use crate::driver::streams::QuicSendStream;
use crate::error::StreamOpeningError;
use crate::error::StreamReadError;
use crate::error::StreamWriteError;
use std::future::Future;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;
use tokio::io::ReadBuf;
use wtransport_proto::ids::SessionId;
use wtransport_proto::ids::StreamId;
use wtransport_proto::stream_header::StreamHeader;

/// A stream that can only be used to send data.
pub struct SendStream(QuicSendStream);

impl SendStream {
    pub(crate) fn new(stream: QuicSendStream) -> Self {
        Self(stream)
    }

    /// Writes bytes to the stream.
    ///
    /// On success, returns the number of bytes written.
    /// Congestion and flow control may cause this to be shorter than `buf.len()`,
    /// indicating that only a prefix of `buf` was written.
    pub async fn write(&mut self, buf: &[u8]) -> Result<usize, StreamWriteError> {
        self.0.write(buf).await
    }

    /// Convenience method to write an entire buffer to the stream.
    pub async fn write_all(&mut self, buf: &[u8]) -> Result<(), StreamWriteError> {
        self.0.write_all(buf).await
    }

    /// Shut down the stream gracefully.
    ///
    /// No new data may be written after calling this method. Completes when the peer has
    /// acknowledged all sent data, retransmitting data as needed.
    pub async fn finish(&mut self) -> Result<(), StreamWriteError> {
        self.0.finish().await
    }

    /// Returns the [`StreamId`] associated.
    #[inline(always)]
    pub fn id(&self) -> StreamId {
        self.0.id()
    }
}

/// A stream that can only be used to receive data.
pub struct RecvStream(QuicRecvStream);

impl RecvStream {
    pub(crate) fn new(stream: QuicRecvStream) -> Self {
        Self(stream)
    }

    /// Read data contiguously from the stream.
    ///
    /// On success, returns the number of bytes read into `buf`.
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<Option<usize>, StreamReadError> {
        self.0.read(buf).await
    }

    /// Returns the [`StreamId`] associated.
    #[inline(always)]
    pub fn id(&self) -> StreamId {
        self.0.id()
    }
}

impl tokio::io::AsyncWrite for SendStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        tokio::io::AsyncWrite::poll_write(Pin::new(&mut self.0), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        tokio::io::AsyncWrite::poll_flush(Pin::new(&mut self.0), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        tokio::io::AsyncWrite::poll_shutdown(Pin::new(&mut self.0), cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<Result<usize, std::io::Error>> {
        tokio::io::AsyncWrite::poll_write_vectored(Pin::new(&mut self.0), cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        tokio::io::AsyncWrite::is_write_vectored(&self.0)
    }
}

impl tokio::io::AsyncRead for RecvStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        tokio::io::AsyncRead::poll_read(Pin::new(&mut self.0), cx, buf)
    }
}

type DynFutureUniStream = dyn Future<Output = Result<SendStream, StreamOpeningError>>;

/// [`Future`] for an in-progress opening unidirectional stream.
///
/// See [`Connection::open_uni`](crate::Connection::open_uni).
pub struct OpeningUniStream(Pin<Box<DynFutureUniStream>>);

impl OpeningUniStream {
    pub(crate) fn new(session_id: SessionId, quic_stream: StreamUniLocalQuic) -> Self {
        Self(Box::pin(async move {
            match quic_stream
                .upgrade(StreamHeader::new_webtransport(session_id))
                .await
            {
                Ok(stream) => Ok(SendStream(stream.upgrade().into_stream())),
                Err(ProtoWriteError::NotConnected) => Err(StreamOpeningError::NotConnected),
                Err(ProtoWriteError::Stopped) => Err(StreamOpeningError::Refused),
            }
        }))
    }
}

impl Future for OpeningUniStream {
    type Output = Result<SendStream, StreamOpeningError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Future::poll(self.0.as_mut(), cx)
    }
}

type DynFutureBiStream = dyn Future<Output = Result<(SendStream, RecvStream), StreamOpeningError>>;

/// [`Future`] for an in-progress opening bidirectional stream.
///
/// See [`Connection::open_bi`](crate::Connection::open_bi).
pub struct OpeningBiStream(Pin<Box<DynFutureBiStream>>);

impl OpeningBiStream {
    pub(crate) fn new(session_id: SessionId, quic_stream: StreamBiLocalQuic) -> Self {
        Self(Box::pin(async move {
            match quic_stream.upgrade().upgrade(session_id).await {
                Ok(stream) => {
                    let stream = stream.into_stream();
                    Ok((SendStream::new(stream.0), RecvStream::new(stream.1)))
                }
                Err(ProtoWriteError::NotConnected) => Err(StreamOpeningError::NotConnected),
                Err(ProtoWriteError::Stopped) => Err(StreamOpeningError::Refused),
            }
        }))
    }
}

impl Future for OpeningBiStream {
    type Output = Result<(SendStream, RecvStream), StreamOpeningError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Future::poll(self.0.as_mut(), cx)
    }
}
