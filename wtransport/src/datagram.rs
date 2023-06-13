use bytes::Bytes;
use std::ops::Deref;
use wtransport_proto::datagram::Datagram as H3Datagram;
use wtransport_proto::error::ErrorCode;
use wtransport_proto::ids::QStreamId;
use wtransport_proto::ids::SessionId;

/// An application Datagram.
pub struct Datagram {
    quic_dgram: Bytes,
    payload_offset: usize,
}

impl Datagram {
    pub(crate) fn read(
        session_id: SessionId,
        quic_dgram: Bytes,
    ) -> Result<Option<Self>, ErrorCode> {
        let h3dgram = H3Datagram::read(&quic_dgram)?;

        let stream_id = h3dgram.qstream_id().into_stream_id();
        if session_id.session_stream() != stream_id {
            return Ok(None);
        }

        let payload_offset = quic_dgram.len() - h3dgram.payload().len();

        Ok(Some(Self {
            quic_dgram,
            payload_offset,
        }))
    }

    pub(crate) fn write(session_id: SessionId, payload: &[u8]) -> Self {
        let h3dgram = H3Datagram::new(QStreamId::from_session_id(session_id), payload);

        let mut buffer = vec![0; h3dgram.write_size()].into_boxed_slice();
        h3dgram.write(&mut buffer).expect("Preallocated capacity");

        let quic_dgram = Bytes::from(buffer);

        let payload_offset = quic_dgram.len() - payload.len();

        Self {
            quic_dgram,
            payload_offset,
        }
    }

    #[inline(always)]
    pub(crate) fn into_quic_bytes(self) -> Bytes {
        self.quic_dgram
    }
}

impl Deref for Datagram {
    type Target = [u8];

    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        &self.quic_dgram[self.payload_offset..]
    }
}
