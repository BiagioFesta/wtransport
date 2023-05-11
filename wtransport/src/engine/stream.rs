use crate::error::StreamError;
use quinn::VarInt;
use std::pin::Pin;
use std::task::ready;
use std::task::Context;
use std::task::Poll;
use tokio::io::ReadBuf;
use wtransport_proto::bytes::AsyncRead;
use wtransport_proto::bytes::AsyncWrite;
use wtransport_proto::bytes::IoError;
use wtransport_proto::frame::Frame;
use wtransport_proto::frame::SessionId;
use wtransport_proto::stream::StreamHeader;
use wtransport_proto::stream::StreamHeaderReadError;
use wtransport_proto::stream::StreamId;

pub(crate) struct Raw;
pub(crate) struct H3(Option<StreamHeader>);
pub(crate) struct Wt(SessionId);

pub(crate) struct BiRemote(QuicSendStream, QuicRecvStream);
pub(crate) struct BiLocal(QuicSendStream, QuicRecvStream);
pub(crate) struct UniRemote(QuicRecvStream);
pub(crate) struct UniLocal(QuicSendStream);
pub(crate) struct Bi(QuicSendStream, QuicRecvStream);

pub(crate) struct Stream<K, S> {
    kind: K,
    stage: S,
}

impl Stream<BiRemote, Raw> {
    pub(crate) async fn accept_bi(quic_connection: &quinn::Connection) -> Option<Self> {
        let stream = quic_connection.accept_bi().await.ok()?;
        Some(Self::bi_remote_raw((
            QuicSendStream(stream.0),
            QuicRecvStream(stream.1),
        )))
    }

    pub(crate) fn upgrade(self) -> Stream<BiRemote, H3> {
        Stream {
            kind: self.kind,
            stage: H3(None),
        }
    }

    pub(crate) fn stop(mut self, code: u32) {
        let _ = self.kind.1 .0.stop(VarInt::from_u32(code));
    }

    fn bi_remote_raw(stream: (QuicSendStream, QuicRecvStream)) -> Self {
        Self {
            kind: BiRemote(stream.0, stream.1),
            stage: Raw,
        }
    }
}

impl Stream<BiLocal, Raw> {
    pub(crate) async fn open_bi(quic_connection: &quinn::Connection) -> Option<Self> {
        let stream = quic_connection.open_bi().await.ok()?;
        Some(Self::bi_local_raw((
            QuicSendStream(stream.0),
            QuicRecvStream(stream.1),
        )))
    }

    pub(crate) fn upgrade(self) -> Stream<BiLocal, H3> {
        Stream {
            kind: self.kind,
            stage: H3(None),
        }
    }

    fn bi_local_raw(stream: (QuicSendStream, QuicRecvStream)) -> Self {
        Self {
            kind: BiLocal(stream.0, stream.1),
            stage: Raw,
        }
    }
}

impl Stream<UniRemote, Raw> {
    pub(crate) async fn accept_uni(quic_connection: &quinn::Connection) -> Option<Self> {
        let stream = quic_connection.accept_uni().await.ok()?;
        Some(Self::uni_remote_raw(QuicRecvStream(stream)))
    }

    pub(crate) async fn upgrade(mut self) -> Result<Stream<UniRemote, H3>, UpgradeError> {
        let header = StreamHeader::read_async(&mut self.kind.0).await?;
        Ok(Stream {
            kind: self.kind,
            stage: H3(Some(header)),
        })
    }

    pub(crate) fn stop(mut self, code: u32) {
        let _ = self.kind.0 .0.stop(VarInt::from_u32(code));
    }

    fn uni_remote_raw(stream: QuicRecvStream) -> Self {
        Self {
            kind: UniRemote(stream),
            stage: Raw,
        }
    }
}

impl Stream<UniLocal, Raw> {
    pub(crate) async fn open_uni(quic_connection: &quinn::Connection) -> Option<Self> {
        let stream = quic_connection.open_uni().await.ok()?;
        Some(Self::uni_local_raw(QuicSendStream(stream)))
    }

    pub(crate) async fn upgrade(
        mut self,
        header: StreamHeader,
    ) -> Result<Stream<UniLocal, H3>, UpgradeError> {
        header.write_async(&mut self.kind.0).await?;
        Ok(Stream {
            kind: self.kind,
            stage: H3(Some(header)),
        })
    }

    fn uni_local_raw(stream: QuicSendStream) -> Self {
        Self {
            kind: UniLocal(stream),
            stage: Raw,
        }
    }
}

impl Stream<BiRemote, H3> {
    pub(crate) async fn read_frame<'a>(&mut self) -> Result<Frame<'a>, FrameReadError> {
        let frame = Frame::read_async(&mut self.kind.1).await?;
        Ok(frame)
    }

    pub(crate) async fn write_frame(&mut self, frame: Frame<'_>) -> Result<(), FrameWriteError> {
        frame.write_async(&mut self.kind.0).await?;
        Ok(())
    }

    pub(crate) fn upgrade(self, session_id: SessionId) -> Stream<BiRemote, Wt> {
        Stream {
            kind: self.kind,
            stage: Wt(session_id),
        }
    }

    pub(crate) fn id(&self) -> StreamId {
        self.kind.0 .0.id().0
    }

    pub(crate) fn stop(mut self, code: u32) {
        let _ = self.kind.1 .0.stop(VarInt::from_u32(code));
    }

    pub(crate) fn normalize(self) -> Stream<Bi, Raw> {
        Stream {
            kind: Bi(self.kind.0, self.kind.1),
            stage: Raw,
        }
    }
}

impl Stream<BiLocal, H3> {
    pub(crate) async fn read_frame<'a>(&mut self) -> Result<Frame<'a>, FrameReadError> {
        let frame = Frame::read_async(&mut self.kind.1).await?;
        Ok(frame)
    }

    pub(crate) async fn write_frame(&mut self, frame: Frame<'_>) -> Result<(), FrameWriteError> {
        frame.write_async(&mut self.kind.0).await?;
        Ok(())
    }

    pub(crate) async fn upgrade(
        mut self,
        session_id: SessionId,
    ) -> Result<Stream<BiLocal, Wt>, UpgradeError> {
        Frame::new_webtransport(session_id)
            .write_async(&mut self.kind.0)
            .await?;
        Ok(Stream {
            kind: self.kind,
            stage: Wt(session_id),
        })
    }

    pub(crate) fn id(&self) -> StreamId {
        self.kind.0 .0.id().0
    }

    pub(crate) fn normalize(self) -> Stream<Bi, Raw> {
        Stream {
            kind: Bi(self.kind.0, self.kind.1),
            stage: Raw,
        }
    }
}

impl Stream<UniRemote, H3> {
    pub(crate) fn header(&self) -> &StreamHeader {
        self.stage
            .0
            .as_ref()
            .expect("Uni H3 stream must have header")
    }

    pub(crate) async fn read_frame<'a>(&mut self) -> Result<Frame<'a>, FrameReadError> {
        let frame = Frame::read_async(&mut self.kind.0).await?;
        Ok(frame)
    }

    pub(crate) fn upgrade(self) -> Stream<UniRemote, Wt> {
        let session_id = self
            .header()
            .session_id()
            .expect("Upgrade on not WT stream");

        Stream {
            kind: self.kind,
            stage: Wt(session_id),
        }
    }

    pub(crate) fn raw(self) -> QuicRecvStream {
        self.kind.0
    }
}

impl Stream<UniLocal, H3> {
    pub(crate) fn header(&self) -> &StreamHeader {
        self.stage
            .0
            .as_ref()
            .expect("Uni H3 stream must have header")
    }

    pub(crate) async fn write_frame(&mut self, frame: Frame<'_>) -> Result<(), FrameWriteError> {
        frame.write_async(&mut self.kind.0).await?;
        Ok(())
    }

    pub(crate) fn upgrade(self) -> Stream<UniLocal, Wt> {
        let session_id = self
            .header()
            .session_id()
            .expect("Upgrade on not WT stream");

        Stream {
            kind: self.kind,
            stage: Wt(session_id),
        }
    }

    pub(crate) async fn stopped(&mut self) -> Result<(), StreamError> {
        self.kind.0.stopped().await
    }
}

impl Stream<BiRemote, Wt> {
    pub(crate) fn raw(self) -> (QuicSendStream, QuicRecvStream) {
        (self.kind.0, self.kind.1)
    }
}

impl Stream<BiLocal, Wt> {
    pub(crate) fn raw(self) -> (QuicSendStream, QuicRecvStream) {
        (self.kind.0, self.kind.1)
    }
}

impl Stream<UniRemote, Wt> {
    pub(crate) fn raw(self) -> QuicRecvStream {
        self.kind.0
    }
}

impl Stream<UniLocal, Wt> {
    pub(crate) fn raw(self) -> QuicSendStream {
        self.kind.0
    }
}

impl Stream<Bi, Raw> {
    pub(crate) fn id(&self) -> StreamId {
        self.kind.0 .0.id().0
    }
}

pub(crate) struct QuicSendStream(quinn::SendStream);

impl QuicSendStream {
    pub(crate) async fn write_all(&mut self, buf: &[u8]) -> Result<(), StreamError> {
        self.0.write_all(buf).await?;
        Ok(())
    }

    pub(crate) async fn finish(&mut self) -> Result<(), StreamError> {
        self.0.finish().await?;
        Ok(())
    }

    pub(crate) async fn stopped(&mut self) -> Result<(), StreamError> {
        self.0.stopped().await?;
        Ok(())
    }
}

impl AsyncWrite for QuicSendStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        tokio::io::AsyncWrite::poll_write(Pin::new(&mut self.0), cx, buf)
    }
}

pub(crate) struct QuicRecvStream(quinn::RecvStream);

impl QuicRecvStream {
    pub(crate) async fn read(&mut self, buf: &mut [u8]) -> Result<Option<usize>, StreamError> {
        match self.0.read(buf).await? {
            Some(read) => Ok(Some(read)),
            None => Ok(None),
        }
    }
}

impl AsyncRead for QuicRecvStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut buffer = ReadBuf::new(buf);

        match ready!(tokio::io::AsyncRead::poll_read(
            Pin::new(&mut self.0),
            cx,
            &mut buffer
        )) {
            Ok(()) => Poll::Ready(Ok(buffer.filled().len())),
            Err(io_error) => Poll::Ready(Err(io_error)),
        }
    }
}

pub(crate) enum UpgradeError {
    UnknownStream,
    ConnectionClosed,
    EndOfStream,
}

impl From<IoError> for UpgradeError {
    fn from(error: IoError) -> Self {
        match error {
            IoError::NotConnected => UpgradeError::ConnectionClosed,
            IoError::Closed => UpgradeError::EndOfStream,
        }
    }
}

impl From<StreamHeaderReadError> for UpgradeError {
    fn from(error: StreamHeaderReadError) -> Self {
        match error {
            StreamHeaderReadError::UnknownStream => UpgradeError::UnknownStream,
            StreamHeaderReadError::Read(io_error) => io_error.into(),
        }
    }
}

pub(crate) enum FrameReadError {
    UnknownFrame,
    EndOfStream,
    ConnectionClosed,
}

impl From<IoError> for FrameReadError {
    fn from(error: IoError) -> Self {
        match error {
            IoError::NotConnected => FrameReadError::ConnectionClosed,
            IoError::Closed => FrameReadError::EndOfStream,
        }
    }
}

impl From<wtransport_proto::frame::FrameReadError> for FrameReadError {
    fn from(error: wtransport_proto::frame::FrameReadError) -> Self {
        use wtransport_proto::frame;

        match error {
            frame::FrameReadError::UnknownFrame => FrameReadError::UnknownFrame,
            frame::FrameReadError::Read(io_error) => io_error.into(),
        }
    }
}

#[derive(Debug)]
pub(crate) enum FrameWriteError {
    EndOfStream,
    ConnectionClosed,
}

impl From<IoError> for FrameWriteError {
    fn from(error: IoError) -> Self {
        match error {
            IoError::NotConnected => FrameWriteError::ConnectionClosed,
            IoError::Closed => FrameWriteError::EndOfStream,
        }
    }
}
