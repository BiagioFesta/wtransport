use crate::engine::stream::QuicRecvStream;
use crate::engine::stream::QuicSendStream;
use crate::error::StreamError;

/// A stream that can only be used to send data.
pub struct SendStream(QuicSendStream);

impl SendStream {
    pub(crate) fn new(stream: QuicSendStream) -> Self {
        Self(stream)
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
