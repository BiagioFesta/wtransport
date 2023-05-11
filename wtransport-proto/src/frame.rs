use crate::bytes::BufferReader;
use crate::bytes::BufferWriter;
use crate::bytes::BytesReader;
use crate::bytes::BytesWriter;
use crate::bytes::EndOfBuffer;
use std::borrow::Cow;

#[cfg(feature = "async")]
use crate::bytes::AsyncRead;

#[cfg(feature = "async")]
use crate::bytes::AsyncWrite;

#[cfg(feature = "async")]
use crate::bytes::IoError;

/// A WebTransport session id.
pub type SessionId = u64;

/// An error during async read operation.
#[cfg(feature = "async")]
#[cfg_attr(docsrs, doc(cfg(feature = "async")))]
#[derive(Debug)]
pub enum FrameReadError {
    UnknownFrame,
    Read(IoError),
}

#[cfg(feature = "async")]
impl From<IoError> for FrameReadError {
    fn from(io_error: IoError) -> Self {
        FrameReadError::Read(io_error)
    }
}

/// Error for unknown frame IDs.
#[derive(Debug)]
pub struct UnknownFrame;

/// An HTTP3 [`Frame`] type.
#[derive(Copy, Clone, Debug)]
pub enum FrameKind {
    Data,
    Headers,
    Settings,
    WebTransport,
    Exercise(u64),
}

impl FrameKind {
    /// Checks whether an `id` is valid for a [`FrameKind::Exercise`].
    #[inline(always)]
    pub const fn is_id_exercise(id: u64) -> bool {
        id >= 0x21 && ((id - 0x21) % 0x1f == 0)
    }

    const fn parse(id: u64) -> Option<Self> {
        match id {
            frame_kind_ids::DATA => Some(FrameKind::Data),
            frame_kind_ids::HEADERS => Some(FrameKind::Headers),
            frame_kind_ids::SETTINGS => Some(FrameKind::Settings),
            frame_kind_ids::WEBTRANSPORT_STREAM => Some(FrameKind::WebTransport),
            id if FrameKind::is_id_exercise(id) => Some(FrameKind::Exercise(id)),
            _ => None,
        }
    }

    const fn id(self) -> u64 {
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
#[derive(Debug)] // TODO(bfesta): u want this debug?
pub struct Frame<'a> {
    kind: FrameKind,
    payload: Cow<'a, [u8]>,
}

impl<'a> Frame<'a> {
    /// Creates a new [`Frame`] specifying its kind and payload.
    ///
    /// **Note**: if [`FrameKind::Exercise`] it must contain a valid exercise id otherwise
    /// the behavior is unspecified. See [`FrameKind::is_id_exercise`].
    ///
    /// **Note**: if [`FrameKind::WebTransport`] then the payload must contain encoded
    /// [`SessionId`]. Better to use [`Self::new_webtransport`].
    pub fn new(kind: FrameKind, payload: Cow<'a, [u8]>) -> Self {
        if let FrameKind::Exercise(id) = kind {
            debug_assert!(
                FrameKind::is_id_exercise(id),
                "Frame is exercise but '{id}' is not valid"
            )
        }

        Self { kind, payload }
    }

    /// Creates a new [`Frame`] with a borrowed payload.
    ///
    /// **Note**: if [`FrameKind::Exercise`] it must contain a valid exercise id otherwise
    /// the behavior is unspecified. See [`FrameKind::is_id_exercise`].
    ///
    /// **Note**: if [`FrameKind::WebTransport`] then the payload must contain encoded
    /// [`SessionId`]. Better to use [`Self::new_webtransport`].
    pub fn with_payload_ref(kind: FrameKind, payload: &'a [u8]) -> Self {
        Self::new(kind, Cow::Borrowed(payload))
    }

    /// Creates a new [`Frame`] with a owned payload.
    ///
    /// **Note**: if [`FrameKind::Exercise`] it must contain a valid exercise id otherwise
    /// the behavior is unspecified. See [`FrameKind::is_id_exercise`].
    ///
    /// **Note**: if [`FrameKind::WebTransport`] then the payload must contain encoded
    /// [`SessionId`]. Better to use [`Self::new_webtransport`].
    pub fn with_payload_own(kind: FrameKind, payload: Box<[u8]>) -> Self {
        Self::new(kind, Cow::Owned(payload.into_vec()))
    }

    /// Creates a new [`Frame`] of type [`FrameKind::WebTransport`].
    pub fn new_webtransport(session_id: SessionId) -> Self {
        Self::with_payload_own(FrameKind::WebTransport, session_id.to_be_bytes().into())
    }

    /// Reads a [`Frame`] from a [`BytesReader`].
    ///
    /// It returns [`None`] if the `bytes_reader` does not contain enough bytes
    /// to parse an entire frame.
    ///
    /// In case [`None`] or [`Err`], `bytes_reader` might be partially read.
    pub fn read<R>(bytes_reader: &mut R) -> Option<Result<Self, UnknownFrame>>
    where
        R: BytesReader<'a>,
    {
        let kind_id = bytes_reader.get_varint()?;
        let kind = match FrameKind::parse(kind_id) {
            Some(kind) => kind,
            None => return Some(Err(UnknownFrame)),
        };

        if matches!(kind, FrameKind::WebTransport) {
            let session_id = bytes_reader.get_varint()?;

            Some(Ok(Self::new_webtransport(session_id)))
        } else {
            let payload_len = bytes_reader.get_varint()?;
            let payload = bytes_reader.get_bytes(payload_len as usize)?;

            Some(Ok(Self::with_payload_ref(kind, payload)))
        }
    }

    /// Reads a [`Frame`] from a `reader`.
    #[cfg(feature = "async")]
    #[cfg_attr(docsrs, doc(cfg(feature = "async")))]
    pub async fn read_async<R>(reader: &mut R) -> Result<Frame<'a>, FrameReadError>
    where
        R: AsyncRead + Unpin + ?Sized,
    {
        use crate::bytes::BytesReaderAsync;

        let kind_id = reader.get_varint().await?;
        let kind = FrameKind::parse(kind_id).ok_or(FrameReadError::UnknownFrame)?;

        if matches!(kind, FrameKind::WebTransport) {
            let session_id = reader.get_varint().await?;

            Ok(Self::new_webtransport(session_id))
        } else {
            let payload_len = reader.get_varint().await?;
            let mut payload = vec![0; payload_len as usize].into_boxed_slice();

            reader.get_buffer(&mut payload).await?;

            Ok(Self::with_payload_own(kind, payload))
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
    ) -> Option<Result<Self, UnknownFrame>> {
        let mut buffer_reader_child = buffer_reader.child();

        match Self::read(&mut *buffer_reader_child)? {
            Ok(frame) => {
                buffer_reader_child.commit();
                Some(Ok(frame))
            }
            Err(UnknownFrame) => Some(Err(UnknownFrame)),
        }
    }

    /// Writes a [`Frame`] into a [`BytesWriter`].
    ///
    /// It returns [`Err`] if the `bytes_writer` does not have enough capacity
    /// to write the entire frame.
    ///
    /// In case [`Err`], `bytes_writer` might be partially written.
    pub fn write<W>(&self, bytes_writer: &mut W) -> Result<(), EndOfBuffer>
    where
        W: BytesWriter,
    {
        bytes_writer.put_varint(self.kind.id())?;

        if let Some(session_id) = self.session_id() {
            bytes_writer.put_varint(session_id)?;
        } else {
            bytes_writer.put_varint(self.payload.len() as u64)?;
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
            writer.put_varint(session_id).await?;
        } else {
            writer.put_varint(self.payload.len() as u64).await?;
            writer.put_buffer(&self.payload).await?;
        }

        Ok(())
    }

    /// Writes this [`Frame`] into a buffer via [`BufferWriter`].
    ///
    /// In case [`Err`], `buffer_writer` is not advanced.
    pub fn write_to_buffer(&self, buffer_writer: &mut BufferWriter) -> Result<(), EndOfBuffer> {
        let cap_needed = if let Some(session_id) = self.session_id() {
            octets::varint_len(self.kind.id()) + octets::varint_len(session_id)
        } else {
            octets::varint_len(self.kind.id())
                + octets::varint_len(self.payload.len() as u64)
                + self.payload.len()
        };

        if buffer_writer.capacity() < cap_needed {
            return Err(EndOfBuffer);
        }

        self.write(buffer_writer)
            .expect("Enough capacity for frame");

        Ok(())
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
            debug_assert_eq!(self.payload.len(), 8);

            let mut buffer = [0; 8];
            buffer.copy_from_slice(&self.payload);

            u64::from_be_bytes(buffer)
        })
    }
}

mod frame_kind_ids {
    pub const DATA: u64 = 0x00;
    pub const HEADERS: u64 = 0x01;
    pub const SETTINGS: u64 = 0x04;
    pub const WEBTRANSPORT_STREAM: u64 = 0x41;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn foo() {
        let buffer = [0x40, 0x41, 0x1, 0x42];
        let mut reader = &buffer[..];

        let frame = Frame::read_async(&mut reader).await.unwrap();

        dbg!(frame);
        dbg!(reader);
    }
}
