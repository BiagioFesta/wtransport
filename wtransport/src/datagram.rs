use bytes::Bytes;
use std::ops::Deref;
use wtransport_proto::datagram::Datagram as H3Datagram;
use wtransport_proto::datagram::QStreamOB;
use wtransport_proto::frame::SessionId;

pub(crate) struct DgramError;

/// An application Datagram.
pub struct Datagram {
    quic_dgram: Bytes,
    payload_offset: usize,
}

impl Datagram {
    pub(crate) fn read(
        quic_dgram: Bytes,
        session_id: SessionId,
    ) -> Result<Option<Self>, DgramError> {
        let h3dgram = H3Datagram::read(&mut &quic_dgram[..], quic_dgram.len())
            .ok_or(DgramError)?
            .map_err(|QStreamOB| DgramError)?;

        let stream_id = h3dgram.stream_id();
        if stream_id != session_id {
            return Ok(None);
        }

        debug_assert!(quic_dgram.len() > h3dgram.payload().len());
        let payload_offset = quic_dgram.len() - h3dgram.payload().len();

        Ok(Some(Self {
            quic_dgram,
            payload_offset,
        }))
    }

    pub(crate) fn write(payload: &[u8], session_id: SessionId) -> Self {
        let mut buffer = Vec::with_capacity(payload.len() + 8);

        H3Datagram::new(session_id, payload)
            .write(&mut buffer)
            .expect("Vector cannot have EndOfBuffer");

        let quic_dgram = Bytes::from(buffer);

        debug_assert!(quic_dgram.len() > payload.len());
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
