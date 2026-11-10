use crate::bytes::BufferReader;
use crate::bytes::BufferWriter;
use crate::bytes::BytesReader;
use crate::bytes::BytesWriter;
use crate::bytes::EndOfBuffer;
use crate::ids::InvalidSessionId;
use crate::ids::SessionId;
use crate::varint::VarInt;
use std::borrow::Cow;

#[cfg(feature = "async")]
use crate::bytes::AsyncRead;

#[cfg(feature = "async")]
use crate::bytes::AsyncWrite;

#[cfg(feature = "async")]
use crate::bytes;

#[cfg(feature = "async")]
use std::pin::Pin;

#[cfg(feature = "async")]
use std::task::{ready, Context, Poll};

/// Error frame parsing.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    /// Error for unknown frame ID.
    ///
    /// The whole frame has been consumed, so the next frame can be read right after it.
    #[error("cannot parse HTTP3 frame as ID is unknown")]
    UnknownFrame,

    /// Error for invalid session ID.
    #[error("cannot parse HTTP3 frame as session ID is invalid")]
    InvalidSessionId,

    /// Payload required too big.
    #[error("cannot parse HTTP3 frame as payload limit is reached")]
    PayloadTooBig,
}

/// An error during frame I/O read operation.
#[cfg(feature = "async")]
#[cfg_attr(docsrs, doc(cfg(feature = "async")))]
#[derive(Debug, thiserror::Error)]
pub enum IoReadError {
    /// Error during parsing a frame.
    #[error(transparent)]
    Parse(ParseError),

    /// Error due to I/O operation.
    #[error(transparent)]
    IO(bytes::IoReadError),
}

#[cfg(feature = "async")]
impl From<bytes::IoReadError> for IoReadError {
    #[inline(always)]
    fn from(io_error: bytes::IoReadError) -> Self {
        IoReadError::IO(io_error)
    }
}

/// An error during frame I/O write operation.
#[cfg(feature = "async")]
pub type IoWriteError = bytes::IoWriteError;

/// Alias for [`Frame<'static>`](Frame);
pub type FrameOwned = Frame<'static>;

/// An HTTP3 [`Frame`] type.
#[derive(Copy, Clone, Debug)]
pub enum FrameKind {
    /// DATA frame type.
    Data,

    /// HEADERS frame type.
    Headers,

    /// SETTINGS frame type.
    Settings,

    /// WebTransport frame type.
    WebTransport,

    /// Exercise frame.
    Exercise(VarInt),
}

impl FrameKind {
    /// Checks whether an `id` is valid for a [`FrameKind::Exercise`].
    #[inline(always)]
    pub const fn is_id_exercise(id: VarInt) -> bool {
        id.into_inner() >= 0x21 && (id.into_inner() - 0x21).is_multiple_of(0x1f)
    }

    const fn parse(id: VarInt) -> Option<Self> {
        match id {
            frame_kind_ids::DATA => Some(FrameKind::Data),
            frame_kind_ids::HEADERS => Some(FrameKind::Headers),
            frame_kind_ids::SETTINGS => Some(FrameKind::Settings),
            frame_kind_ids::WEBTRANSPORT_STREAM => Some(FrameKind::WebTransport),
            id if FrameKind::is_id_exercise(id) => Some(FrameKind::Exercise(id)),
            _ => None,
        }
    }

    const fn id(self) -> VarInt {
        match self {
            FrameKind::Data => frame_kind_ids::DATA,
            FrameKind::Headers => frame_kind_ids::HEADERS,
            FrameKind::Settings => frame_kind_ids::SETTINGS,
            FrameKind::WebTransport => frame_kind_ids::WEBTRANSPORT_STREAM,
            FrameKind::Exercise(id) => id,
        }
    }
}

/// An HTTP3 frame.
#[derive(Debug)]
pub struct Frame<'a> {
    kind: FrameKind,
    payload: Cow<'a, [u8]>,
    session_id: Option<SessionId>,
}

impl<'a> Frame<'a> {
    const MAX_PARSE_PAYLOAD_ALLOWED: usize = 4096;

    /// Creates a new frame of type [`FrameKind::Headers`].
    ///
    /// # Panics
    ///
    /// Panics if the `payload` size if greater than [`VarInt::MAX`].
    #[inline(always)]
    pub fn new_headers(payload: Cow<'a, [u8]>) -> Self {
        Self::new(FrameKind::Headers, payload, None)
    }

    /// Creates a new frame of type [`FrameKind::Settings`].
    ///
    /// # Panics
    ///
    /// Panics if the `payload` size if greater than [`VarInt::MAX`].
    #[inline(always)]
    pub fn new_settings(payload: Cow<'a, [u8]>) -> Self {
        Self::new(FrameKind::Settings, payload, None)
    }

    /// Creates a new frame of type [`FrameKind::WebTransport`].
    #[inline(always)]
    pub fn new_webtransport(session_id: SessionId) -> Self {
        Self::new(
            FrameKind::WebTransport,
            Cow::Owned(Default::default()),
            Some(session_id),
        )
    }

    /// Creates a new frame of type [`FrameKind::Data`].
    ///
    /// # Panics
    ///
    /// Panics if the `payload` size if greater than [`VarInt::MAX`].
    #[inline(always)]
    pub fn new_data(payload: Cow<'a, [u8]>) -> Self {
        Self::new(FrameKind::Data, payload, None)
    }

    /// Creates a new frame of type [`FrameKind::Exercise`].
    ///
    /// # Panics
    ///
    /// * Panics if the `payload` size if greater than [`VarInt::MAX`].
    /// * Panics if `id` is not a valid exercise (see [`FrameKind::is_id_exercise`]).
    #[inline(always)]
    pub fn new_exercise(id: VarInt, payload: Cow<'a, [u8]>) -> Self {
        assert!(FrameKind::is_id_exercise(id));
        Self::new(FrameKind::Exercise(id), payload, None)
    }

    /// Reads a [`Frame`] from a [`BytesReader`].
    ///
    /// It returns [`None`] if the `bytes_reader` does not contain enough bytes
    /// to parse an entire frame.
    ///
    /// An unknown frame is consumed whole before [`ParseError::UnknownFrame`] is returned,
    /// so the next frame can be read right after it. Its payload is limited in size like
    /// that of any other frame.
    ///
    /// In case [`None`] or [`Err`], `bytes_reader` might be partially read.
    pub fn read<R>(bytes_reader: &mut R) -> Result<Option<Self>, ParseError>
    where
        R: BytesReader<'a>,
    {
        let kind = match bytes_reader.get_varint() {
            Some(kind_id) => FrameKind::parse(kind_id),
            None => return Ok(None),
        };

        if matches!(kind, Some(FrameKind::WebTransport)) {
            let session_id = match bytes_reader.get_varint() {
                Some(session_id) => SessionId::try_from_varint(session_id)
                    .map_err(|InvalidSessionId| ParseError::InvalidSessionId)?,
                None => return Ok(None),
            };

            Ok(Some(Self::new_webtransport(session_id)))
        } else {
            let payload_len = match bytes_reader.get_varint() {
                Some(payload_len) => payload_len.into_inner() as usize,
                None => return Ok(None),
            };

            if payload_len > Self::MAX_PARSE_PAYLOAD_ALLOWED {
                return Err(ParseError::PayloadTooBig);
            }

            let Some(payload) = bytes_reader.get_bytes(payload_len) else {
                return Ok(None);
            };

            // Unknown frames are discarded only once their payload is consumed (RFC 9114 §9).
            let kind = kind.ok_or(ParseError::UnknownFrame)?;

            Ok(Some(Self::new(kind, Cow::Borrowed(payload), None)))
        }
    }

    /// Reads a [`Frame`] from a `reader`.
    ///
    /// An unknown frame is consumed whole before [`ParseError::UnknownFrame`] is returned,
    /// so the next frame can be read right after it. Its payload is skipped as it arrives,
    /// without being buffered, so unlike that of a known frame its size is not limited.
    ///
    /// Not cancel-safe: see [`FrameReader`] for a version that is.
    #[cfg(feature = "async")]
    #[cfg_attr(docsrs, doc(cfg(feature = "async")))]
    pub async fn read_async<R>(reader: &mut R) -> Result<Frame<'a>, IoReadError>
    where
        R: AsyncRead + Unpin + ?Sized,
    {
        FrameReader::default().read_async(reader).await
    }

    /// Reads a [`Frame`] from a [`BufferReader`].
    ///
    /// It returns [`None`] if the `buffer_reader` does not contain enough bytes
    /// to parse an entire frame.
    ///
    /// In case [`None`] or [`Err`], `buffer_reader` offset is not advanced, except
    /// for [`ParseError::UnknownFrame`], which advances it past the discarded frame.
    pub fn read_from_buffer(
        buffer_reader: &mut BufferReader<'a>,
    ) -> Result<Option<Self>, ParseError> {
        let mut buffer_reader_child = buffer_reader.child();

        match Self::read(&mut *buffer_reader_child) {
            Ok(Some(frame)) => {
                buffer_reader_child.commit();
                Ok(Some(frame))
            }
            Err(ParseError::UnknownFrame) => {
                buffer_reader_child.commit();
                Err(ParseError::UnknownFrame)
            }
            result => result,
        }
    }

    /// Writes a [`Frame`] into a [`BytesWriter`].
    ///
    /// It returns [`Err`] if the `bytes_writer` does not have enough capacity
    /// to write the entire frame.
    /// See [`Self::write_size`] to retrieve the exact amount of required capacity.
    ///
    /// In case [`Err`], `bytes_writer` might be partially written.
    ///
    /// # Panics
    ///
    /// Panics if the payload size if greater than [`VarInt::MAX`].
    pub fn write<W>(&self, bytes_writer: &mut W) -> Result<(), EndOfBuffer>
    where
        W: BytesWriter,
    {
        bytes_writer.put_varint(self.kind.id())?;

        if let Some(session_id) = self.session_id() {
            bytes_writer.put_varint(session_id.into_varint())?;
        } else {
            bytes_writer.put_varint(
                VarInt::try_from(self.payload.len() as u64)
                    .expect("Payload cannot be larger than varint max"),
            )?;
            bytes_writer.put_bytes(&self.payload)?;
        }

        Ok(())
    }

    /// Writes a [`Frame`] into a `writer`.
    ///
    /// # Panics
    ///
    /// Panics if the payload size if greater than [`VarInt::MAX`].
    #[cfg(feature = "async")]
    #[cfg_attr(docsrs, doc(cfg(feature = "async")))]
    pub async fn write_async<W>(&self, writer: &mut W) -> Result<(), IoWriteError>
    where
        W: AsyncWrite + Unpin + ?Sized,
    {
        use crate::bytes::BytesWriterAsync;

        writer.put_varint(self.kind.id()).await?;

        if let Some(session_id) = self.session_id() {
            writer.put_varint(session_id.into_varint()).await?;
        } else {
            writer
                .put_varint(
                    VarInt::try_from(self.payload.len() as u64)
                        .expect("Payload cannot be larger than varint max"),
                )
                .await?;
            writer.put_buffer(&self.payload).await?;
        }

        Ok(())
    }

    /// Writes this [`Frame`] into a buffer via [`BufferWriter`].
    ///
    /// In case [`Err`], `buffer_writer` is not advanced.
    ///
    /// # Panics
    ///
    /// Panics if the payload size if greater than [`VarInt::MAX`].
    pub fn write_to_buffer(&self, buffer_writer: &mut BufferWriter) -> Result<(), EndOfBuffer> {
        if buffer_writer.capacity() < self.write_size() {
            return Err(EndOfBuffer);
        }

        self.write(buffer_writer)
            .expect("Enough capacity for frame");

        Ok(())
    }

    /// Returns the needed capacity to write this frame into a buffer.
    pub fn write_size(&self) -> usize {
        if let Some(session_id) = self.session_id() {
            self.kind.id().size() + session_id.into_varint().size()
        } else {
            self.kind.id().size()
                + VarInt::try_from(self.payload.len() as u64)
                    .expect("Payload cannot be larger than varint max")
                    .size()
                + self.payload.len()
        }
    }

    /// Returns the [`FrameKind`] of this [`Frame`].
    #[inline(always)]
    pub const fn kind(&self) -> FrameKind {
        self.kind
    }

    /// Returns the payload of this [`Frame`].
    #[inline(always)]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Returns the [`SessionId`] if frame is [`FrameKind::WebTransport`],
    /// otherwise returns [`None`].
    #[inline(always)]
    pub fn session_id(&self) -> Option<SessionId> {
        matches!(self.kind, FrameKind::WebTransport).then(|| {
            self.session_id
                .expect("WebTransport frame contains session id")
        })
    }

    /// # Panics
    ///
    /// Panics if the `payload` size if greater than [`VarInt::MAX`].
    fn new(kind: FrameKind, payload: Cow<'a, [u8]>, session_id: Option<SessionId>) -> Self {
        if let FrameKind::Exercise(id) = kind {
            debug_assert!(FrameKind::is_id_exercise(id));
        } else if let FrameKind::WebTransport = kind {
            debug_assert!(payload.is_empty());
            debug_assert!(session_id.is_some());
        }

        assert!(payload.len() <= VarInt::MAX.into_inner() as usize);

        Self {
            kind,
            payload,
            session_id,
        }
    }

    #[cfg(test)]
    pub(crate) fn into_owned<'b>(self) -> Frame<'b> {
        Frame {
            kind: self.kind,
            payload: Cow::Owned(self.payload.into_owned()),
            session_id: self.session_id,
        }
    }

    #[cfg(test)]
    pub(crate) fn serialize_any(kind: VarInt, payload: &[u8]) -> Vec<u8> {
        let mut buffer = Vec::new();

        Self {
            kind: FrameKind::Exercise(kind),
            payload: Cow::Owned(payload.to_vec()),
            session_id: None,
        }
        .write(&mut buffer)
        .unwrap();

        buffer
    }

    #[cfg(test)]
    pub(crate) fn serialize_webtransport(session_id: SessionId) -> Vec<u8> {
        let mut buffer = Vec::new();

        Self {
            kind: FrameKind::WebTransport,
            payload: Cow::Owned(Default::default()),
            session_id: Some(session_id),
        }
        .write(&mut buffer)
        .unwrap();

        buffer
    }
}

/// Reads [`Frame`]s from a stream, keeping its progress through the current frame.
///
/// [`Frame::read_async`] keeps that progress in its future, so dropping the future part
/// way through a frame loses the bytes it has consumed and leaves the stream mid-frame.
/// Here it lives in the `FrameReader`, so [`Self::read_async`] is cancel-safe: a read
/// dropped part way through a frame resumes where it stopped when called again.
#[cfg(feature = "async")]
#[cfg_attr(docsrs, doc(cfg(feature = "async")))]
#[derive(Debug, Default)]
pub struct FrameReader {
    /// The frame type, then the payload length or, for a WebTransport frame, the session ID.
    header: [u8; 2 * VarInt::MAX_SIZE],
    header_len: usize,
    /// The payload of a known frame, allocated once its length is known.
    payload: Vec<u8>,
    /// How much of the payload has been read, or skipped for an unknown frame.
    payload_read: u64,
}

#[cfg(feature = "async")]
impl FrameReader {
    /// Reads the next frame from `reader`, which must be the stream this reader was
    /// reading if a previous call was dropped part way through a frame.
    ///
    /// Cancel-safe. Otherwise behaves as [`Frame::read_async`].
    pub async fn read_async<R>(&mut self, reader: &mut R) -> Result<Frame<'static>, IoReadError>
    where
        R: AsyncRead + Unpin + ?Sized,
    {
        std::future::poll_fn(|cx| self.poll_read(cx, reader)).await
    }

    fn poll_read<R>(
        &mut self,
        cx: &mut Context<'_>,
        reader: &mut R,
    ) -> Poll<Result<Frame<'static>, IoReadError>>
    where
        R: AsyncRead + Unpin + ?Sized,
    {
        let result = ready!(self.poll_frame(cx, reader));

        // The frame is over, read in full or failed.
        self.header_len = 0;
        self.payload = Vec::new();
        self.payload_read = 0;

        Poll::Ready(result)
    }

    fn poll_frame<R>(
        &mut self,
        cx: &mut Context<'_>,
        reader: &mut R,
    ) -> Poll<Result<Frame<'static>, IoReadError>>
    where
        R: AsyncRead + Unpin + ?Sized,
    {
        // Each varint's first byte gives its size.
        ready!(self.poll_header(cx, reader, 1))?;
        let kind_end = VarInt::parse_size(self.header[0]);
        ready!(self.poll_header(cx, reader, kind_end + 1))?;
        let header_end = kind_end + VarInt::parse_size(self.header[kind_end]);
        ready!(self.poll_header(cx, reader, header_end))?;

        let mut header = BufferReader::new(&self.header[..header_end]);
        let kind_id = header.get_varint().expect("Header is complete");
        let value = header.get_varint().expect("Header is complete");

        match FrameKind::parse(kind_id) {
            Some(FrameKind::WebTransport) => {
                let session_id = SessionId::try_from_varint(value)
                    .map_err(|InvalidSessionId| IoReadError::Parse(ParseError::InvalidSessionId))?;

                Poll::Ready(Ok(Frame::new_webtransport(session_id)))
            }
            Some(kind) => {
                if value.into_inner() > Frame::MAX_PARSE_PAYLOAD_ALLOWED as u64 {
                    return Poll::Ready(Err(IoReadError::Parse(ParseError::PayloadTooBig)));
                }

                // Does nothing once the payload is allocated.
                self.payload.resize(value.into_inner() as usize, 0);

                while self.payload_read < value.into_inner() {
                    let read = ready!(Self::poll_read_some(
                        cx,
                        reader,
                        &mut self.payload[self.payload_read as usize..]
                    ))?;
                    self.payload_read += read as u64;
                }

                let payload = std::mem::take(&mut self.payload);
                Poll::Ready(Ok(Frame::new(kind, Cow::Owned(payload), None)))
            }
            None => {
                // Unknown frames are discarded (RFC 9114 §9), so the payload is skipped
                // rather than buffered.
                let mut discard = [0; 256];

                while self.payload_read < value.into_inner() {
                    let remaining = value.into_inner() - self.payload_read;
                    let len = remaining.min(discard.len() as u64) as usize;
                    let read = ready!(Self::poll_read_some(cx, reader, &mut discard[..len]))?;
                    self.payload_read += read as u64;
                }

                Poll::Ready(Err(IoReadError::Parse(ParseError::UnknownFrame)))
            }
        }
    }

    /// Reads into the header until it holds `end` bytes.
    fn poll_header<R>(
        &mut self,
        cx: &mut Context<'_>,
        reader: &mut R,
        end: usize,
    ) -> Poll<Result<(), IoReadError>>
    where
        R: AsyncRead + Unpin + ?Sized,
    {
        while self.header_len < end {
            match ready!(Self::poll_read_some(
                cx,
                reader,
                &mut self.header[self.header_len..end]
            )) {
                Ok(read) => self.header_len += read,
                // A stream that ends between frames ends cleanly.
                Err(IoReadError::IO(bytes::IoReadError::UnexpectedFin)) if self.header_len == 0 => {
                    return Poll::Ready(Err(IoReadError::IO(bytes::IoReadError::ImmediateFin)));
                }
                Err(error) => return Poll::Ready(Err(error)),
            }
        }

        Poll::Ready(Ok(()))
    }

    /// Reads at least one byte into `buffer`, which must not be empty.
    fn poll_read_some<R>(
        cx: &mut Context<'_>,
        reader: &mut R,
        buffer: &mut [u8],
    ) -> Poll<Result<usize, IoReadError>>
    where
        R: AsyncRead + Unpin + ?Sized,
    {
        let read =
            ready!(Pin::new(reader).poll_read(cx, buffer)).map_err(bytes::IoReadError::from)?;

        if read == 0 {
            // Only ever called mid-frame, except as handled by `poll_header`.
            return Poll::Ready(Err(IoReadError::IO(bytes::IoReadError::UnexpectedFin)));
        }

        Poll::Ready(Ok(read))
    }
}

mod frame_kind_ids {
    use crate::varint::VarInt;

    pub const DATA: VarInt = VarInt::from_u32(0x00);
    pub const HEADERS: VarInt = VarInt::from_u32(0x01);
    pub const SETTINGS: VarInt = VarInt::from_u32(0x04);
    pub const WEBTRANSPORT_STREAM: VarInt = VarInt::from_u32(0x41);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::headers::Headers;
    use crate::settings::Settings;

    #[test]
    fn settings() {
        let settings = Settings::builder()
            .qpack_blocked_streams(VarInt::from_u32(1))
            .qpack_max_table_capacity(VarInt::from_u32(2))
            .enable_h3_datagrams()
            .enable_webtransport()
            .webtransport_max_sessions(VarInt::from_u32(3))
            .build();

        let frame = settings.generate_frame();
        assert!(frame.session_id().is_none());
        assert!(matches!(frame.kind(), FrameKind::Settings));

        let frame = utils::assert_serde(frame);
        Settings::with_frame(&frame).unwrap();
    }

    #[tokio::test]
    async fn settings_async() {
        let settings = Settings::builder()
            .qpack_blocked_streams(VarInt::from_u32(1))
            .qpack_max_table_capacity(VarInt::from_u32(2))
            .enable_h3_datagrams()
            .enable_webtransport()
            .webtransport_max_sessions(VarInt::from_u32(3))
            .build();

        let frame = settings.generate_frame();
        assert!(frame.session_id().is_none());
        assert!(matches!(frame.kind(), FrameKind::Settings));

        let frame = utils::assert_serde_async(frame).await;
        Settings::with_frame(&frame).unwrap();
    }

    #[test]
    fn headers() {
        let headers = Headers::from_iter([("key1", "value1")]);

        let frame = headers.generate_frame();
        assert!(frame.session_id().is_none());
        assert!(matches!(frame.kind(), FrameKind::Headers));

        let frame = utils::assert_serde(frame);
        Headers::with_frame(&frame).unwrap();
    }

    #[tokio::test]
    async fn headers_async() {
        let headers = Headers::from_iter([("key1", "value1")]);

        let frame = headers.generate_frame();
        assert!(frame.session_id().is_none());
        assert!(matches!(frame.kind(), FrameKind::Headers));

        let frame = utils::assert_serde_async(frame).await;
        Headers::with_frame(&frame).unwrap();
    }

    #[test]
    fn webtransport() {
        let session_id = SessionId::try_from_varint(VarInt::from_u32(0)).unwrap();
        let frame = Frame::new_webtransport(session_id);

        assert!(frame.payload().is_empty());
        assert!(matches!(frame.session_id(), Some(x) if x == session_id));
        assert!(matches!(frame.kind(), FrameKind::WebTransport));

        let frame = utils::assert_serde(frame);

        assert!(frame.payload().is_empty());
        assert!(matches!(frame.session_id(), Some(x) if x == session_id));
        assert!(matches!(frame.kind(), FrameKind::WebTransport));
    }

    #[tokio::test]
    async fn webtransport_async() {
        let session_id = SessionId::try_from_varint(VarInt::from_u32(0)).unwrap();
        let frame = Frame::new_webtransport(session_id);

        assert!(frame.payload().is_empty());
        assert!(matches!(frame.session_id(), Some(x) if x == session_id));
        assert!(matches!(frame.kind(), FrameKind::WebTransport));

        let frame = utils::assert_serde_async(frame).await;

        assert!(frame.payload().is_empty());
        assert!(matches!(frame.session_id(), Some(x) if x == session_id));
        assert!(matches!(frame.kind(), FrameKind::WebTransport));
    }

    #[test]
    fn read_eof() {
        let buffer = Frame::serialize_any(FrameKind::Data.id(), b"This is a test payload");
        assert!(Frame::read(&mut &buffer[..buffer.len() - 1])
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn read_eof_async() {
        let buffer = Frame::serialize_any(FrameKind::Data.id(), b"This is a test payload");

        for len in 0..buffer.len() {
            let result = Frame::read_async(&mut &buffer[..len]).await;

            match len {
                0 => assert!(matches!(
                    result,
                    Err(IoReadError::IO(bytes::IoReadError::ImmediateFin))
                )),
                _ => assert!(matches!(
                    result,
                    Err(IoReadError::IO(bytes::IoReadError::UnexpectedFin))
                )),
            }
        }
    }

    #[tokio::test]
    async fn read_eof_webtransport_async() {
        let session_id = SessionId::try_from_varint(VarInt::from_u32(0)).unwrap();
        let buffer = Frame::serialize_webtransport(session_id);

        for len in 0..buffer.len() {
            let result = Frame::read_async(&mut &buffer[..len]).await;

            match len {
                0 => assert!(matches!(
                    result,
                    Err(IoReadError::IO(bytes::IoReadError::ImmediateFin))
                )),
                _ => assert!(matches!(
                    result,
                    Err(IoReadError::IO(bytes::IoReadError::UnexpectedFin))
                )),
            }
        }
    }

    #[test]
    fn unknown_frame() {
        let mut buffer =
            Frame::serialize_any(VarInt::from_u32(0x0042_4242), b"This is a test payload");
        buffer.extend(Frame::serialize_any(FrameKind::Data.id(), b"next"));
        let mut reader = buffer.as_slice();

        assert!(matches!(
            Frame::read(&mut reader),
            Err(ParseError::UnknownFrame)
        ));

        let frame = Frame::read(&mut reader).unwrap().unwrap();
        assert!(matches!(frame.kind(), FrameKind::Data));
        assert_eq!(frame.payload(), b"next");
        assert!(reader.is_empty());
    }

    #[tokio::test]
    async fn unknown_frame_async() {
        let mut buffer =
            Frame::serialize_any(VarInt::from_u32(0x0042_4242), b"This is a test payload");
        buffer.extend(Frame::serialize_any(FrameKind::Data.id(), b"next"));
        let mut reader = buffer.as_slice();

        assert!(matches!(
            Frame::read_async(&mut reader).await,
            Err(IoReadError::Parse(ParseError::UnknownFrame))
        ));

        let frame = Frame::read_async(&mut reader).await.unwrap();
        assert!(matches!(frame.kind(), FrameKind::Data));
        assert_eq!(frame.payload(), b"next");
        assert!(reader.is_empty());
    }

    #[test]
    fn unknown_frame_from_buffer() {
        let buffer = Frame::serialize_any(VarInt::from_u32(0x0042_4242), b"This is a test payload");

        for len in 0..buffer.len() {
            let mut buffer_reader = BufferReader::new(&buffer[..len]);
            assert!(Frame::read_from_buffer(&mut buffer_reader)
                .unwrap()
                .is_none());
            assert_eq!(buffer_reader.offset(), 0);
        }

        let mut buffer_reader = BufferReader::new(&buffer);
        assert!(matches!(
            Frame::read_from_buffer(&mut buffer_reader),
            Err(ParseError::UnknownFrame)
        ));
        assert_eq!(buffer_reader.offset(), buffer.len());
    }

    #[test]
    fn invalid_session_id() {
        let invalid_session_id = SessionId::maybe_invalid(VarInt::from_u32(1));
        let buffer = Frame::serialize_webtransport(invalid_session_id);

        assert!(matches!(
            Frame::read(&mut buffer.as_slice()),
            Err(ParseError::InvalidSessionId)
        ));
    }

    #[tokio::test]
    async fn invalid_session_id_async() {
        let invalid_session_id = SessionId::maybe_invalid(VarInt::from_u32(1));
        let buffer = Frame::serialize_webtransport(invalid_session_id);

        assert!(matches!(
            Frame::read_async(&mut buffer.as_slice()).await,
            Err(IoReadError::Parse(ParseError::InvalidSessionId))
        ));
    }

    #[test]
    fn payload_too_big() {
        let mut buffer = Vec::new();
        buffer.put_varint(FrameKind::Data.id()).unwrap();
        buffer
            .put_varint(VarInt::from_u32(
                Frame::MAX_PARSE_PAYLOAD_ALLOWED as u32 + 1,
            ))
            .unwrap();

        assert!(matches!(
            Frame::read_from_buffer(&mut BufferReader::new(&buffer)),
            Err(ParseError::PayloadTooBig)
        ));
    }

    #[tokio::test]
    async fn payload_too_big_async() {
        let mut buffer = Vec::new();
        buffer.put_varint(FrameKind::Data.id()).unwrap();
        buffer
            .put_varint(VarInt::from_u32(
                Frame::MAX_PARSE_PAYLOAD_ALLOWED as u32 + 1,
            ))
            .unwrap();

        assert!(matches!(
            Frame::read_async(&mut &*buffer).await,
            Err(IoReadError::Parse(ParseError::PayloadTooBig)),
        ));
    }

    #[test]
    fn unknown_frame_payload_too_big() {
        let mut buffer = Vec::new();
        buffer.put_varint(VarInt::from_u32(0x0042_4242)).unwrap();
        buffer
            .put_varint(VarInt::from_u32(
                Frame::MAX_PARSE_PAYLOAD_ALLOWED as u32 + 1,
            ))
            .unwrap();

        assert!(matches!(
            Frame::read_from_buffer(&mut BufferReader::new(&buffer)),
            Err(ParseError::PayloadTooBig)
        ));
    }

    #[tokio::test]
    async fn unknown_frame_large_async() {
        // Skipped as it arrives, so not limited in size like the payload of a known frame.
        let payload = vec![0; Frame::MAX_PARSE_PAYLOAD_ALLOWED * 4];
        let mut buffer = Frame::serialize_any(VarInt::from_u32(0x0042_4242), &payload);
        buffer.extend(Frame::serialize_any(FrameKind::Data.id(), b"next"));
        let mut reader = buffer.as_slice();
        let mut frame_reader = FrameReader::default();

        assert!(matches!(
            frame_reader.read_async(&mut reader).await,
            Err(IoReadError::Parse(ParseError::UnknownFrame))
        ));
        let frame = frame_reader.read_async(&mut reader).await.unwrap();
        assert_eq!(frame.payload(), b"next");
        assert!(reader.is_empty());
    }

    /// Hands out its data only as far as `released`, and is pending beyond that.
    struct Trickle {
        data: Vec<u8>,
        read: usize,
        released: usize,
    }

    impl AsyncRead for Trickle {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<std::io::Result<usize>> {
            if self.read == self.released {
                return Poll::Pending;
            }

            let len = buf.len().min(self.released - self.read);
            buf[..len].copy_from_slice(&self.data[self.read..self.read + len]);
            self.read += len;
            Poll::Ready(Ok(len))
        }
    }

    #[test]
    fn frame_reader_resumes_cancelled_reads() {
        use std::future::Future;

        let mut data = Frame::serialize_any(FrameKind::Data.id(), b"first");
        data.extend(Frame::serialize_any(
            VarInt::from_u32(0x0042_4242),
            b"unknown",
        ));
        data.extend(Frame::serialize_webtransport(SessionId::maybe_invalid(
            VarInt::from_u32(0),
        )));
        data.extend(Frame::serialize_any(FrameKind::Data.id(), b"last"));

        let mut source = Trickle {
            released: 0,
            read: 0,
            data,
        };
        let mut frame_reader = FrameReader::default();
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let mut results = Vec::new();

        // One more byte at a time, each read dropped as soon as it has to wait for more.
        while source.released < source.data.len() {
            source.released += 1;
            let mut read = std::pin::pin!(frame_reader.read_async(&mut source));
            if let Poll::Ready(result) = read.as_mut().poll(&mut cx) {
                results.push(result);
            }
        }

        let [first, unknown, webtransport, last] = results.try_into().unwrap();
        assert_eq!(first.unwrap().payload(), b"first");
        assert!(matches!(
            unknown,
            Err(IoReadError::Parse(ParseError::UnknownFrame))
        ));
        assert!(matches!(
            webtransport.unwrap().kind(),
            FrameKind::WebTransport
        ));
        assert_eq!(last.unwrap().payload(), b"last");
    }

    mod utils {
        use super::*;

        pub fn assert_serde(frame: Frame) -> Frame {
            let mut buffer = Vec::new();

            frame.write(&mut buffer).unwrap();
            assert_eq!(buffer.len(), frame.write_size());

            let mut buffer = buffer.as_slice();
            let frame = Frame::read(&mut buffer).unwrap().unwrap();
            assert!(buffer.is_empty());

            frame.into_owned()
        }

        #[cfg(feature = "async")]
        pub async fn assert_serde_async(frame: Frame<'_>) -> Frame<'_> {
            let mut buffer = Vec::new();

            frame.write_async(&mut buffer).await.unwrap();
            assert_eq!(buffer.len(), frame.write_size());

            let mut buffer = buffer.as_slice();
            let frame = Frame::read_async(&mut buffer).await.unwrap();
            assert!(buffer.is_empty());

            frame.into_owned()
        }
    }
}
