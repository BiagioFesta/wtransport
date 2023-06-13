use crate::driver::streams::bilocal::StreamBiLocalH3;
use crate::driver::streams::biremote::StreamBiRemoteH3;
use crate::driver::streams::ProtoReadError;
use crate::driver::DriverError;
use crate::error::StreamWriteError;
use wtransport_proto::bytes;
use wtransport_proto::error::ErrorCode;
use wtransport_proto::frame::Frame;
use wtransport_proto::frame::FrameKind;
use wtransport_proto::ids::SessionId;

pub struct RemoteSessionStream {
    stream: StreamBiRemoteH3,
}

impl RemoteSessionStream {
    pub fn new(stream: StreamBiRemoteH3) -> Self {
        assert!(stream.id().is_bidirectional() && stream.id().is_client_initiated());
        Self { stream }
    }

    pub fn session_id(&self) -> SessionId {
        let stream_id = self.stream.id();

        // SAFETY: stream is session by construction
        unsafe {
            debug_assert!(stream_id.is_bidirectional() && stream_id.is_client_initiated());
            SessionId::from_session_stream_unchecked(stream_id)
        }
    }

    pub async fn done(&mut self) -> DriverError {
        loop {
            let frame = match self.read_frame().await {
                Ok(frame) => frame,
                Err(driver_error) => return driver_error,
            };

            if !matches!(frame.kind(), FrameKind::Exercise(_) | FrameKind::Data) {
                return DriverError::LocallyClosed(ErrorCode::FrameUnexpected);
            }
        }
    }

    async fn read_frame<'a>(&mut self) -> Result<Frame<'a>, DriverError> {
        self.stream.read_frame().await.map_err(|error| match error {
            ProtoReadError::H3(error_code) => DriverError::LocallyClosed(error_code),
            ProtoReadError::IO(io_error) => match io_error {
                bytes::IoReadError::ImmediateFin
                | bytes::IoReadError::UnexpectedFin
                | bytes::IoReadError::Reset => {
                    DriverError::LocallyClosed(ErrorCode::ClosedCriticalStream)
                }
                bytes::IoReadError::NotConnected => DriverError::NotConnected,
            },
        })
    }
}

pub struct LocalSessionStream {
    stream: StreamBiLocalH3,
}

impl LocalSessionStream {
    pub fn new(stream: StreamBiLocalH3) -> Self {
        assert!(stream.id().is_bidirectional() && stream.id().is_client_initiated());
        Self { stream }
    }

    pub fn session_id(&self) -> SessionId {
        let stream_id = self.stream.id();

        // SAFETY: stream is session by construction
        unsafe {
            debug_assert!(stream_id.is_bidirectional() && stream_id.is_client_initiated());
            SessionId::from_session_stream_unchecked(stream_id)
        }
    }

    pub async fn done(&mut self) -> DriverError {
        match self.stream.stopped().await {
            StreamWriteError::NotConnected => DriverError::NotConnected,
            StreamWriteError::Stopped(_) => {
                DriverError::LocallyClosed(ErrorCode::ClosedCriticalStream)
            }
            StreamWriteError::QuicProto => {
                DriverError::LocallyClosed(ErrorCode::ClosedCriticalStream)
            }
        }
    }
}
