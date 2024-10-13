use crate::capsule::Capsule;
use crate::capsule::CapsuleKind;
use crate::error::ErrorCode;
use crate::varint::VarInt;

/// Capsules for WebTransport session termination.
#[derive(Debug)]
pub struct CloseWebTransportSession {
    error_code: u32,
    reason: String,
}

impl CloseWebTransportSession {
    /// Parses from [`Capsule`].
    ///
    /// # Panics
    ///
    /// Panics if `capsule` is not
    /// [`CloseWebTransportSession`](CapsuleKind::CloseWebtransportsession) type.
    pub fn with_capsule(capsule: &Capsule) -> Result<Self, ErrorCode> {
        const MAX_REASON_LEN: usize = 1024;

        assert!(matches!(
            capsule.kind(),
            CapsuleKind::CloseWebTransportSession
        ));

        let payload = capsule.payload();

        if payload.len() < 4 || payload.len() > 4 + MAX_REASON_LEN {
            return Err(ErrorCode::Datagram);
        }

        let error_code =
            u32::from_be_bytes(payload[..4].try_into().expect("4B to u32 should succeed"));
        let reason = std::str::from_utf8(&payload[4..])
            .map_err(|_| ErrorCode::Datagram)?
            .to_string();

        Ok(Self { error_code, reason })
    }

    /// Returns the error code sent over this capsule.
    pub fn error_code(&self) -> VarInt {
        VarInt::from_u32(self.error_code)
    }

    /// Returns the reason sent over this capsule.
    pub fn reason(&self) -> &str {
        &self.reason
    }
}
