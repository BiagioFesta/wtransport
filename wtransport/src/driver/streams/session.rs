use crate::driver::streams::bilocal::StreamBiLocalH3;
use crate::driver::streams::biremote::StreamBiRemoteH3;
use crate::driver::streams::ProtoReadError;
use crate::driver::DriverError;
use crate::session::SessionInfo;
use std::future::pending;
use wtransport_proto::bytes;
use wtransport_proto::error::ErrorCode;
use wtransport_proto::frame::Frame;
use wtransport_proto::frame::FrameKind;
use wtransport_proto::ids::SessionId;

pub struct SessionStream {
    info: Option<SessionInfo>,
    local: Option<StreamBiLocalH3>,
    remote: Option<StreamBiRemoteH3>,
}

impl SessionStream {
    pub fn empty() -> Self {
        Self {
            info: None,
            local: None,
            remote: None,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.info.is_none()
    }

    pub fn client(stream: StreamBiLocalH3) -> Self {
        assert!(stream.id().is_bidirectional() && stream.id().is_client_initiated());

        // SAFETY: stream is session by construction
        let session_id = unsafe {
            debug_assert!(stream.id().is_bidirectional() && stream.id().is_client_initiated());
            SessionId::from_session_stream_unchecked(stream.id())
        };

        Self {
            info: Some(SessionInfo::new(session_id)),
            local: Some(stream),
            remote: None,
        }
    }

    pub fn server(stream: StreamBiRemoteH3) -> Self {
        assert!(stream.id().is_bidirectional() && stream.id().is_client_initiated());

        // SAFETY: stream is session by construction
        let session_id = unsafe {
            debug_assert!(stream.id().is_bidirectional() && stream.id().is_client_initiated());
            SessionId::from_session_stream_unchecked(stream.id())
        };

        Self {
            info: Some(SessionInfo::new(session_id)),
            local: None,
            remote: Some(stream),
        }
    }

    pub fn session_info(&self) -> Option<&SessionInfo> {
        self.info.as_ref()
    }

    pub async fn run(&mut self) -> DriverError {
        loop {
            let frame = match self.read_frame().await {
                Ok(Some(frame)) => frame,
                Ok(None) => pending().await,
                Err(driver_error) => return driver_error,
            };

            if !matches!(frame.kind(), FrameKind::Exercise(_) | FrameKind::Data) {
                return DriverError::Proto(ErrorCode::FrameUnexpected);
            }
        }
    }

    async fn read_frame<'a>(&mut self) -> Result<Option<Frame<'a>>, DriverError> {
        let frame = match (self.local.as_mut(), self.remote.as_mut()) {
            (Some(stream), None) => stream.read_frame().await,
            (None, Some(stream)) => stream.read_frame().await,
            (None, None) => return Ok(None),
            _ => unreachable!(),
        };

        match frame {
            Ok(frame) => Ok(Some(frame)),
            Err(ProtoReadError::H3(error_code)) => Err(DriverError::Proto(error_code)),
            Err(ProtoReadError::IO(io_error)) => match io_error {
                bytes::IoReadError::ImmediateFin
                | bytes::IoReadError::UnexpectedFin
                | bytes::IoReadError::Reset => {
                    Err(DriverError::Proto(ErrorCode::ClosedCriticalStream))
                }
                bytes::IoReadError::NotConnected => Err(DriverError::NotConnected),
            },
        }
    }
}
