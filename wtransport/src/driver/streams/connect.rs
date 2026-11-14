use tracing::debug;
use wtransport_proto::bytes::BytesWriter;
use wtransport_proto::bytes::IoReadError;
use wtransport_proto::capsule::capsules;
use wtransport_proto::capsule::Capsule;
use wtransport_proto::capsule::{self};
use wtransport_proto::error::ErrorCode;
use wtransport_proto::frame::Frame;
use wtransport_proto::frame::FrameKind;
use wtransport_proto::varint::VarInt;

use super::session::StreamSession;
use super::ProtoReadError;
use crate::driver::DriverError;
use crate::error::ApplicationClose;
use std::borrow::Cow;
use std::future::pending;
use std::time::Duration;

const CLOSE_WEBTRANSPORT_SESSION: VarInt = VarInt::from_u32(0x2843);
const MAX_CLOSE_REASON_LEN: usize = 1024;
/// How long to wait for the peer to acknowledge a `CLOSE_WEBTRANSPORT_SESSION`.
const CLOSE_ACK_TIMEOUT: Duration = Duration::from_secs(2);

pub struct ConnectStream {
    stream: Option<StreamSession>,
}

impl ConnectStream {
    pub fn empty() -> Self {
        Self { stream: None }
    }

    pub fn is_empty(&self) -> bool {
        self.stream.is_none()
    }

    pub fn set_stream(&mut self, stream: StreamSession) {
        self.stream = Some(stream);
    }

    /// Sends a `CLOSE_WEBTRANSPORT_SESSION` capsule carrying `error_code` and `reason`,
    /// ends the stream, and waits (bounded) for the peer to acknowledge both.
    pub async fn close(&mut self, error_code: u32, reason: &[u8]) {
        let Some(stream) = self.stream.as_mut() else {
            return;
        };

        let reason = String::from_utf8_lossy(reason);
        let mut reason_len = reason.len().min(MAX_CLOSE_REASON_LEN);
        while !reason.is_char_boundary(reason_len) {
            reason_len -= 1;
        }
        let reason = &reason.as_bytes()[..reason_len];

        let payload_len = VarInt::try_from(4 + reason.len() as u64).expect("Reason is bounded");
        let mut capsule = Vec::new();
        let _ = capsule.put_varint(CLOSE_WEBTRANSPORT_SESSION);
        let _ = capsule.put_varint(payload_len);
        let _ = capsule.put_bytes(&error_code.to_be_bytes());
        let _ = capsule.put_bytes(reason);

        let send = async {
            if stream
                .write_frame(Frame::new_data(Cow::Owned(capsule)))
                .await
                .is_ok()
            {
                stream.finish().await;
            }
        };
        if tokio::time::timeout(CLOSE_ACK_TIMEOUT, send).await.is_err() {
            debug!("Peer did not acknowledge CLOSE_WEBTRANSPORT_SESSION in time");
        }
    }

    pub async fn run(&mut self) -> DriverError {
        let stream = match self.stream.as_mut() {
            Some(stream) => stream,
            None => pending().await,
        };

        loop {
            return match stream.read_frame().await {
                Ok(frame) => {
                    if !matches!(frame.kind(), FrameKind::Data) {
                        debug!("Skipping non-data frame of kind {:?}", frame.kind());
                        continue;
                    }

                    let capsule = match Capsule::with_frame(&frame) {
                        Some(capsule)
                            if matches!(
                                capsule.kind(),
                                capsule::CapsuleKind::CloseWebTransportSession
                            ) =>
                        {
                            capsule
                        }
                        // Unknown capsule, skip it
                        _ => {
                            debug!(
                                "Unknown capsule of kind {:?} of {}B",
                                frame.kind(),
                                frame.payload().len()
                            );

                            continue;
                        }
                    };

                    let close_session =
                        match capsules::CloseWebTransportSession::with_capsule(&capsule) {
                            Ok(close_session) => close_session,
                            Err(error_code) => return DriverError::Proto(error_code),
                        };

                    // reset right away to avoid receiving additional data which requires resetting with ErrorCode::Message.
                    self.stream
                        .take()
                        .unwrap()
                        .reset(ErrorCode::NoError.to_code());

                    DriverError::ApplicationClosed(ApplicationClose::new(
                        close_session.error_code(),
                        close_session
                            .reason()
                            .as_bytes()
                            .to_vec()
                            .into_boxed_slice(),
                    ))
                }
                Err(ProtoReadError::H3(error_code)) => DriverError::Proto(error_code),
                Err(ProtoReadError::IO(io_error)) => match io_error {
                    // Cleanly terminating a CONNECT stream without a CLOSE_WEBTRANSPORT_SESSION
                    // capsule SHALL be semantically equivalent to terminating it with a
                    // CLOSE_WEBTRANSPORT_SESSION capsule that has an error code of 0 and an empty error string.
                    IoReadError::ImmediateFin => DriverError::ApplicationClosed(
                        ApplicationClose::new(VarInt::from_u32(0), Box::new([])),
                    ),
                    IoReadError::UnexpectedFin | IoReadError::Reset => {
                        DriverError::Proto(ErrorCode::ClosedCriticalStream)
                    }
                    IoReadError::NotConnected => DriverError::NotConnected,
                },
            };
        }
    }
}
