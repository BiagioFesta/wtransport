use crate::bytes::BufferReader;
use crate::bytes::BufferWriter;
use crate::bytes::BytesReader;
use crate::bytes::BytesWriter;
use crate::bytes::EndOfBuffer;
use crate::stream::StreamId;

/// Error when received illegal *Quarter* Stream ID value.
#[derive(Debug)]
pub struct QStreamOB;

/// An HTTP3 datagram.
pub struct Datagram<'a> {
    qstream_id: StreamId,
    payload: &'a [u8],
}

impl<'a> Datagram<'a> {
    const MAX_QSTREAM_VALUE: u64 = 1152921504606846975;

    /// Creates a new [`Datagram`] with a given payload.
    ///
    /// **Note**: `stream_id` must be client-initiated bidirectional stream, otherwise
    /// the behavior is unspecified.
    pub fn new(stream_id: StreamId, payload: &'a [u8]) -> Self {
        debug_assert!(
            stream_id % 4 == 0,
            "H3 DGRAM can be only associated to bi client stream"
        );

        let qstream_id = stream_id >> 2;
        Self::with_qstream(qstream_id, payload)
    }

    /// Reads a [`Datagram`] from a [`BytesReader`].
    ///
    /// It returns [`None`] if the `bytes_reader` does not contain enough bytes
    /// to parse an entire frame.
    ///
    /// In case [`None`] or [`Err`], `bytes_reader` might be partially read.
    pub fn read<R>(bytes_reader: &mut R, dgram_size: usize) -> Option<Result<Self, QStreamOB>>
    where
        R: BytesReader<'a>,
    {
        let qstream_id = bytes_reader.get_varint()?;
        if qstream_id > Self::MAX_QSTREAM_VALUE {
            return Some(Err(QStreamOB));
        }

        debug_assert!(dgram_size >= octets::varint_len(qstream_id));
        let payload_size = dgram_size - octets::varint_len(qstream_id);
        let payload = bytes_reader.get_bytes(payload_size)?;

        Some(Ok(Self::with_qstream(qstream_id, payload)))
    }

    /// Reads a [`Datagram`] from a [`BufferReader`].
    ///
    /// It returns [`None`] if the `buffer_reader` does not contain enough bytes
    /// to parse an entire frame.
    ///
    /// In case [`None`] or [`Err`], `buffer_reader` offset if not advanced.
    pub fn read_from_buffer(
        buffer_reader: &mut BufferReader<'a>,
        dgram_size: usize,
    ) -> Option<Result<Self, QStreamOB>> {
        let mut buffer_reader_child = buffer_reader.child();

        match Self::read(&mut *buffer_reader_child, dgram_size)? {
            Ok(frame) => {
                buffer_reader_child.commit();
                Some(Ok(frame))
            }
            Err(QStreamOB) => Some(Err(QStreamOB)),
        }
    }

    /// Writes a [`Datagram`] into a [`BytesWriter`].
    ///
    /// It returns [`Err`] if the `bytes_writer` does not have enough capacity
    /// to write the entire frame.
    ///
    /// In case [`Err`], `bytes_writer` might be partially written.
    pub fn write<W>(&self, bytes_writer: &mut W) -> Result<(), EndOfBuffer>
    where
        W: BytesWriter,
    {
        bytes_writer.put_varint(self.qstream_id)?;
        bytes_writer.put_bytes(self.payload)?;

        Ok(())
    }

    /// Writes this [`Datagram`] into a buffer via [`BufferWriter`].
    ///
    /// In case [`Err`], `buffer_writer` is not advanced.
    pub fn write_to_buffer(&self, buffer_writer: &mut BufferWriter) -> Result<(), EndOfBuffer> {
        if buffer_writer.capacity() < self.write_capacity() {
            return Err(EndOfBuffer);
        }

        self.write(buffer_writer)
            .expect("Enough capacity for frame");

        Ok(())
    }

    /// Returns the needed capacity to write this [`Datagram`] into a buffer.
    // TODO(bfesta): you should implement this logic-method for `Frame` and `StreamHeader` as well!
    pub fn write_capacity(&self) -> usize {
        octets::varint_len(self.qstream_id) + self.payload.len()
    }

    /// Returns the payload.
    pub fn payload(&self) -> &[u8] {
        self.payload
    }

    /// Returns the `StreamId` associated.
    pub fn stream_id(&self) -> StreamId {
        self.qstream_id << 2
    }

    fn with_qstream(qstream_id: StreamId, payload: &'a [u8]) -> Self {
        debug_assert!(qstream_id <= Self::MAX_QSTREAM_VALUE);

        Self {
            qstream_id,
            payload,
        }
    }
}
