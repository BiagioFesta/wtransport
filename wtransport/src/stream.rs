use crate::engine::stream::QuicRecvStream;
use crate::engine::stream::QuicSendStream;
use crate::error::StreamError;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;
use tokio::io::ReadBuf;

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
    pub async fn write(&mut self, buf: &[u8]) -> Result<usize, StreamError> {
        self.0.write(buf).await
    }

    /// Convenience method to write an entire buffer to the stream.
    pub async fn write_all(&mut self, buf: &[u8]) -> Result<(), StreamError> {
        self.0.write_all(buf).await
    }

    /// Shut down the stream gracefully.
    ///
    /// No new data may be written after calling this method. Completes when the peer has
    /// acknowledged all sent data, retransmitting data as needed.
    pub async fn finish(&mut self) -> Result<(), StreamError> {
        self.0.finish().await
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
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<Option<usize>, StreamError> {
        self.0.read(buf).await
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
