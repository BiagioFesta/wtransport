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
use crate::bytes::IoError;

/// Error frame read operation.
#[derive(Debug)]
pub enum FrameReadError {
    /// Error for unknown frame ID.
    UnknownFrame,

    /// Error for invalid session ID.
    InvalidSessionId,
}

/// An error during async frame read operation.
#[cfg(feature = "async")]
#[cfg_attr(docsrs, doc(cfg(feature = "async")))]
#[derive(Debug)]
pub enum FrameReadAsyncError {
    Frame(FrameReadError),
    IO(IoError),
}

#[cfg(feature = "async")]
impl From<IoError> for FrameReadAsyncError {
    fn from(io_error: IoError) -> Self {
        FrameReadAsyncError::IO(io_error)
    }
}

/// An HTTP3 [`Frame`] type.
#[derive(Copy, Clone, Debug)]
pub enum FrameKind {
    Data,
    Headers,
    Settings,
    WebTransport,
    Exercise(VarInt),
}

impl FrameKind {
    /// Checks whether an `id` is valid for a [`FrameKind::Exercise`].
    #[inline(always)]
    pub const fn is_id_exercise(id: VarInt) -> bool {
        id.into_inner() >= 0x21 && ((id.into_inner() - 0x21) % 0x1f == 0)
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
pub struct Frame<'a> {
    kind: FrameKind,
    payload: Cow<'a, [u8]>,
    session_id: Option<SessionId>,
}

impl<'a> Frame<'a> {
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

    /// Reads a [`Frame`] from a [`BytesReader`].
    ///
    /// It returns [`None`] if the `bytes_reader` does not contain enough bytes
    /// to parse an entire frame.
    ///
    /// In case [`None`] or [`Err`], `bytes_reader` might be partially read.
    pub fn read<R>(bytes_reader: &mut R) -> Option<Result<Self, FrameReadError>>
    where
        R: BytesReader<'a>,
    {
        let kind_id = bytes_reader.get_varint()?;
        let kind = match FrameKind::parse(kind_id) {
            Some(kind) => kind,
            None => return Some(Err(FrameReadError::UnknownFrame)),
        };

        if matches!(kind, FrameKind::WebTransport) {
            let session_id = match SessionId::try_from_varint(bytes_reader.get_varint()?) {
                Ok(session_id) => session_id,
                Err(InvalidSessionId) => return Some(Err(FrameReadError::InvalidSessionId)),
            };

            Some(Ok(Self::new_webtransport(session_id)))
        } else {
            let payload_len = bytes_reader.get_varint()?.into_inner() as usize;
            let payload = bytes_reader.get_bytes(payload_len)?;

            Some(Ok(Self::new(kind, Cow::Borrowed(payload), None)))
        }
    }

    /// Reads a [`Frame`] from a `reader`.
    #[cfg(feature = "async")]
    #[cfg_attr(docsrs, doc(cfg(feature = "async")))]
    pub async fn read_async<R>(reader: &mut R) -> Result<Frame<'a>, FrameReadAsyncError>
    where
        R: AsyncRead + Unpin + ?Sized,
    {
        use crate::bytes::BytesReaderAsync;

        let kind_id = reader.get_varint().await?;
        let kind = FrameKind::parse(kind_id)
            .ok_or(FrameReadAsyncError::Frame(FrameReadError::UnknownFrame))?;

        if matches!(kind, FrameKind::WebTransport) {
            let session_id = SessionId::try_from_varint(reader.get_varint().await?).map_err(
                |InvalidSessionId| FrameReadAsyncError::Frame(FrameReadError::InvalidSessionId),
            )?;

            Ok(Self::new_webtransport(session_id))
        } else {
            let payload_len = reader.get_varint().await?.into_inner() as usize;
            let mut payload = vec![0; payload_len];

            reader.get_buffer(&mut payload).await?;

            payload.shrink_to_fit();

            Ok(Self::new(kind, Cow::Owned(payload), None))
        }
    }

    /// Reads a [`Frame`] from a [`BufferReader`].
    ///
    /// It returns [`None`] if the `buffer_reader` does not contain enough bytes
    /// to parse an entire frame.
    ///
    /// In case [`None`] or [`Err`], `buffer_reader` offset if not advanced.
    pub fn read_from_buffer(
        buffer_reader: &mut BufferReader<'a>,
    ) -> Option<Result<Self, FrameReadError>> {
        let mut buffer_reader_child = buffer_reader.child();

        match Self::read(&mut *buffer_reader_child)? {
            Ok(frame) => {
                buffer_reader_child.commit();
                Some(Ok(frame))
            }
            Err(error) => Some(Err(error)),
        }
    }

    /// Writes a [`Frame`] into a [`BytesWriter`].
    ///
    /// It returns [`Err`] if the `bytes_writer` does not have enough capacity
    /// to write the entire frame.
    /// See [`Self::write_size`] to retrieve the extact amount of required capacity.
    ///
    /// In case [`Err`], `bytes_writer` might be partially written.
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
    #[cfg(feature = "async")]
    #[cfg_attr(docsrs, doc(cfg(feature = "async")))]
    pub async fn write_async<W>(&self, writer: &mut W) -> Result<(), IoError>
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
            debug_assert!(FrameKind::is_id_exercise(id))
        } else if let FrameKind::WebTransport = kind {
            debug_assert!(payload.is_empty());
            debug_assert!(session_id.is_some())
        }

        assert!(payload.len() <= VarInt::MAX.into_inner() as usize);

        Self {
            kind,
            payload,
            session_id,
        }
    }
}

mod frame_kind_ids {
    use crate::varint::VarInt;

    pub const DATA: VarInt = VarInt::from_u32(0x00);
    pub const HEADERS: VarInt = VarInt::from_u32(0x01);
    pub const SETTINGS: VarInt = VarInt::from_u32(0x04);
    pub const WEBTRANSPORT_STREAM: VarInt = VarInt::from_u32(0x41);
}
