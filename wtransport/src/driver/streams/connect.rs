use tracing::debug;
use wtransport_proto::{
    bytes::IoReadError,
    capsule::{self, capsules, Capsule},
    error::ErrorCode,
    varint::VarInt,
};

use super::{session::StreamSession, ProtoReadError};
use crate::{driver::DriverError, error::ApplicationClose};
use std::future::pending;

pub struct ConnectStream {
    stream: Option<StreamSession>,
    /// We've received CLOSE_WEBTRANSPORT_SESSION capsule
    recv_close_ws: bool,
}

impl ConnectStream {
    pub fn empty() -> Self {
        Self {
            stream: None,
            recv_close_ws: false,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.stream.is_none()
    }

    pub fn set_stream(&mut self, stream: StreamSession) {
        self.stream = Some(stream);
    }

    pub async fn run(&mut self) -> DriverError {
        assert!(!self.recv_close_ws);
        let stream = match self.stream.as_mut() {
            Some(stream) => stream,
            None => pending().await,
        };

        loop {
            return match stream.read_frame().await {
                Ok(frame) => {
                    let capsule = match Capsule::with_frame(&frame)
                        .map(|capsule| (capsule.kind(), capsule))
                    {
                        Some((capsule::CapsuleKind::CloseWebTransportSession, capsule)) => capsule,
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

                    self.recv_close_ws = true;
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

    /// Finishes termination process.
    pub async fn finish(mut self) {
        let Some(mut stream) = self.stream.take() else {
            return;
        };

        // Handle termination procedure
        if self.recv_close_ws {
            // Finish our side
            stream.finish().await;
        }
    }
}
