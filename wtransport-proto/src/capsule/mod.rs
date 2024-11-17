use crate::bytes::BytesReader;
use crate::frame::Frame;
use crate::frame::FrameKind;
use crate::varint::VarInt;

/// An HTTP3 [`Capsule`] type.
#[derive(Copy, Clone, Debug)]
pub enum CapsuleKind {
    /// Close WebTransport Capsule type.
    CloseWebTransportSession,
}

impl CapsuleKind {
    const fn parse(id: VarInt) -> Option<Self> {
        match id {
            capsule_types::CAPSULE_TYPE_CLOSE_WEBTRANSPORT_SESSION => {
                Some(CapsuleKind::CloseWebTransportSession)
            }
            _ => None,
        }
    }
}

/// An HTTP3 Capsule.
#[derive(Debug)]
pub struct Capsule<'a> {
    kind: CapsuleKind,
    payload: &'a [u8],
}

impl<'a> Capsule<'a> {
    /// Parses a capsule from an HTTP3 frame.
    ///
    /// # Panics
    ///
    /// Panics if `frame` is not [`Data`](`FrameKind::Data`) type.
    pub fn with_frame(frame: &'a Frame<'a>) -> Option<Self> {
        assert!(matches!(frame.kind(), FrameKind::Data));

        let mut payload = frame.payload();
        let kind = CapsuleKind::parse(payload.get_varint()?)?;
        let payload_length = payload.get_varint()?;
        let payload = payload.get_bytes(payload_length.into_inner() as usize)?;

        Some(Self { kind, payload })
    }

    /// The [`CapsuleKind`] of this capsule.
    pub fn kind(&self) -> CapsuleKind {
        self.kind
    }

    /// Returns the payload of this `Capsule`.
    pub fn payload(&self) -> &[u8] {
        self.payload
    }
}

mod capsule_types {
    use crate::varint::VarInt;

    pub const CAPSULE_TYPE_CLOSE_WEBTRANSPORT_SESSION: VarInt = VarInt::from_u32(0x2843);
}

/// Capsules types implementations.
pub mod capsules {
    pub use super::close_wt_session::CloseWebTransportSession;
}

mod close_wt_session;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capsule_close_wt_session() {
        let frame = Frame::new_data(vec![104, 67, 4, 0, 0, 0, 0u8].into());
        let capsule = Capsule::with_frame(&frame).unwrap();
        let close =
            capsules::CloseWebTransportSession::with_capsule(&capsule).expect("Should parse");
        assert_eq!(close.error_code(), VarInt::from_u32(0));
        assert_eq!(close.reason(), "");
    }
}
