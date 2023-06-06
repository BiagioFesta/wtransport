use crate::bytes::BufferReader;
use crate::bytes::BufferWriter;
use crate::bytes::BytesReader;
use crate::bytes::BytesWriter;
use crate::bytes::EndOfBuffer;
use crate::ids::InvalidSessionId;
use crate::ids::SessionId;
use crate::varint::VarInt;

#[cfg(feature = "async")]
use crate::bytes::AsyncRead;

#[cfg(feature = "async")]
use crate::bytes::AsyncWrite;

#[cfg(feature = "async")]
use crate::bytes::IoError;

/// Error stream header read operation.
#[derive(Debug)]
pub enum StreamHeaderReadError {
    /// Error for unknown stream type.
    UnknownStream,

    /// Error for invalid session ID.
    InvalidSessionId,
}

/// An error during async stream header read operation.
#[cfg(feature = "async")]
#[cfg_attr(docsrs, doc(cfg(feature = "async")))]
#[derive(Debug)]
pub enum StreamHeaderReadAsyncError {
    StreamHeader(StreamHeaderReadError),
    Read(IoError),
}

#[cfg(feature = "async")]
impl From<IoError> for StreamHeaderReadAsyncError {
    fn from(io_error: IoError) -> Self {
        StreamHeaderReadAsyncError::Read(io_error)
    }
}

/// An HTTP3 stream type.
#[derive(Copy, Clone, Debug)]
pub enum StreamKind {
    Control,
    QPackEncoder,
    QPackDecoder,
    WebTransport,
    Exercise(VarInt),
}

impl StreamKind {
    /// Checks whether an `id` is valid for a [`StreamKind::Exercise`].
    #[inline(always)]
    pub const fn is_id_exercise(id: VarInt) -> bool {
        id.into_inner() >= 0x21 && ((id.into_inner() - 0x21) % 0x1f == 0)
    }

    const fn parse(id: VarInt) -> Option<Self> {
        match id {
            stream_type_ids::CONTROL_STREAM => Some(StreamKind::Control),
            stream_type_ids::QPACK_ENCODER_STREAM => Some(StreamKind::QPackEncoder),
            stream_type_ids::QPACK_DECODER_STREAM => Some(StreamKind::QPackDecoder),
            stream_type_ids::WEBTRANSPORT_STREAM => Some(StreamKind::WebTransport),
            id if StreamKind::is_id_exercise(id) => Some(StreamKind::Exercise(id)),
            _ => None,
        }
    }

    const fn id(self) -> VarInt {
        match self {
            StreamKind::Control => stream_type_ids::CONTROL_STREAM,
            StreamKind::QPackEncoder => stream_type_ids::QPACK_ENCODER_STREAM,
            StreamKind::QPackDecoder => stream_type_ids::QPACK_DECODER_STREAM,
            StreamKind::WebTransport => stream_type_ids::WEBTRANSPORT_STREAM,
            StreamKind::Exercise(id) => id,
        }
    }
}

pub struct StreamHeader {
    kind: StreamKind,
    session_id: Option<SessionId>,
}

impl StreamHeader {
    /// Maximum number of bytes a [`StreamHeader`] can take over network.
    pub const MAX_LEN: usize = 16;

    /// Creates a new [`StreamHeader`] initializing its [`StreamKind`].
    ///
    /// **Note**: if [`StreamKind::WebTransport`] then `session_id` must be [`Some`].
    ///
    /// **Note**: if [`StreamKind::Exercise`] it must contain a valid exercise id otherwise
    /// the behavior is unspecified. See [`StreamKind::is_id_exercise`].
    pub fn new(kind: StreamKind, session_id: Option<SessionId>) -> Self {
        if let StreamKind::WebTransport = kind {
            debug_assert!(
                session_id.is_some(),
                "StreamHeader is webtransport but session_id not provided"
            )
        }

        if let StreamKind::Exercise(id) = kind {
            debug_assert!(
                StreamKind::is_id_exercise(id),
                "StreamHeader is exercise but '{id}' is not valid"
            )
        }

        Self { kind, session_id }
    }

    /// Reads a [`StreamHeader`] from a [`BytesReader`].
    ///
    /// It returns [`None`] if the `bytes_reader` does not contain enough bytes
    /// to parse an entire header.
    ///
    /// In case [`None`] or [`Err`], `bytes_reader` might be partially read.
    pub fn read<'a, R>(bytes_reader: &mut R) -> Option<Result<Self, StreamHeaderReadError>>
    where
        R: BytesReader<'a>,
    {
        let kind_id = bytes_reader.get_varint()?;
        let kind = match StreamKind::parse(kind_id) {
            Some(kind) => kind,
            None => return Some(Err(StreamHeaderReadError::UnknownStream)),
        };

        let session_id = if matches!(kind, StreamKind::WebTransport) {
            let session_id = match SessionId::try_from_varint(bytes_reader.get_varint()?) {
                Ok(session_id) => session_id,
                Err(InvalidSessionId) => return Some(Err(StreamHeaderReadError::InvalidSessionId)),
            };

            Some(session_id)
        } else {
            None
        };

        Some(Ok(Self::new(kind, session_id)))
    }

    /// Reads a [`StreamHeader`] from a `reader`.
    #[cfg(feature = "async")]
    #[cfg_attr(docsrs, doc(cfg(feature = "async")))]
    pub async fn read_async<R>(reader: &mut R) -> Result<Self, StreamHeaderReadAsyncError>
    where
        R: AsyncRead + Unpin + ?Sized,
    {
        use crate::bytes::BytesReaderAsync;

        let kind_id = reader.get_varint().await?;
        let kind = StreamKind::parse(kind_id).ok_or(StreamHeaderReadAsyncError::StreamHeader(
            StreamHeaderReadError::UnknownStream,
        ))?;

        let session_id = if matches!(kind, StreamKind::WebTransport) {
            let session_id = SessionId::try_from_varint(reader.get_varint().await?).map_err(
                |InvalidSessionId| {
                    StreamHeaderReadAsyncError::StreamHeader(
                        StreamHeaderReadError::InvalidSessionId,
                    )
                },
            )?;

            Some(session_id)
        } else {
            None
        };

        Ok(Self::new(kind, session_id))
    }

    /// Reads a [`StreamHeader`] from a [`BufferReader`].
    ///
    /// It returns [`None`] if the `buffer_reader` does not contain enough bytes
    /// to parse an entire header.
    ///
    /// In case [`None`] or [`Err`], `buffer_reader` offset if not advanced.
    pub fn read_from_buffer(
        buffer_reader: &mut BufferReader,
    ) -> Option<Result<Self, StreamHeaderReadError>> {
        let mut buffer_reader_child = buffer_reader.child();

        match Self::read(&mut *buffer_reader_child)? {
            Ok(header) => {
                buffer_reader_child.commit();
                Some(Ok(header))
            }
            Err(error) => Some(Err(error)),
        }
    }

    /// Writes a [`StreamHeader`] into a [`BytesWriter`].
    ///
    /// It returns [`Err`] if the `bytes_writer` does not have enough capacity
    /// to write the entire header.
    ///
    /// In case [`Err`], `bytes_writer` might be partially written.
    pub fn write<W>(&self, bytes_writer: &mut W) -> Result<(), EndOfBuffer>
    where
        W: BytesWriter,
    {
        bytes_writer.put_varint(self.kind.id())?;

        if let Some(session_id) = self.session_id() {
            bytes_writer.put_varint(session_id.into_varint())?;
        }

        Ok(())
    }

    /// Writes a [`StreamHeader`] into a `writer`.
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
        }

        Ok(())
    }

    /// Writes this [`StreamHeader`] into a buffer via [`BufferWriter`].
    ///
    /// In case [`Err`], `buffer_writer` is not advanced.
    pub fn write_to_buffer(&self, buffer_writer: &mut BufferWriter) -> Result<(), EndOfBuffer> {
        let cap_needed = if let Some(session_id) = self.session_id() {
            self.kind.id().size() + session_id.into_varint().size()
        } else {
            self.kind.id().size()
        };

        if buffer_writer.capacity() < cap_needed {
            return Err(EndOfBuffer);
        }

        self.write(buffer_writer)
            .expect("Enough capacity for header");

        Ok(())
    }

    /// Returns the [`StreamKind`].
    #[inline(always)]
    pub const fn kind(&self) -> StreamKind {
        self.kind
    }

    /// Returns the [`SessionId`] if stream is [`StreamKind::WebTransport`],
    /// otherwise returns [`None`].
    #[inline(always)]
    pub fn session_id(&self) -> Option<SessionId> {
        matches!(self.kind, StreamKind::WebTransport).then(|| {
            self.session_id
                .expect("WebTransport stream header contains session id")
        })
    }
}

mod stream_type_ids {
    use crate::varint::VarInt;

    pub const CONTROL_STREAM: VarInt = VarInt::from_u32(0x0);
    pub const QPACK_ENCODER_STREAM: VarInt = VarInt::from_u32(0x02);
    pub const QPACK_DECODER_STREAM: VarInt = VarInt::from_u32(0x03);
    pub const WEBTRANSPORT_STREAM: VarInt = VarInt::from_u32(0x54);
}
