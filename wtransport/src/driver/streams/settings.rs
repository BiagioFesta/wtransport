use crate::driver::streams::unilocal::StreamUniLocalH3;
use crate::driver::streams::uniremote::StreamUniRemoteH3;
use crate::driver::streams::ProtoReadError;
use crate::driver::streams::ProtoWriteError;
use crate::driver::DriverError;
use crate::error::StreamWriteError;
use wtransport_proto::bytes;
use wtransport_proto::error::ErrorCode;
use wtransport_proto::frame::Frame;
use wtransport_proto::frame::FrameKind;
use wtransport_proto::settings::Settings;
use wtransport_proto::stream_header::StreamKind;
use wtransport_proto::varint::VarInt;

pub struct RemoteSettingsStream {
    stream: StreamUniRemoteH3,
    settings: Option<Settings>,
}

impl RemoteSettingsStream {
    pub fn new(stream: StreamUniRemoteH3) -> Self {
        debug_assert!(matches!(stream.kind(), StreamKind::Control));

        Self {
            stream,
            settings: None,
        }
    }

    pub async fn done(&mut self) -> DriverError {
        loop {
            let frame = match self.read_frame().await {
                Ok(frame) => frame,
                Err(driver_error) => return driver_error,
            };

            if self.settings.is_none() {
                if !matches!(frame.kind(), FrameKind::Settings) {
                    return DriverError::LocallyClosed(ErrorCode::MissingSettings);
                }

                let settings = match Settings::with_frame(&frame) {
                    Ok(settings) => settings,
                    Err(error_code) => return DriverError::LocallyClosed(error_code),
                };

                // TODO(bfesta): validate settings

                self.settings = Some(settings);
            } else if !matches!(frame.kind(), FrameKind::Exercise(_)) {
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

pub struct LocalSettingsStream {
    stream: StreamUniLocalH3,
    settings: Settings,
}

impl LocalSettingsStream {
    pub fn new(stream: StreamUniLocalH3) -> Self {
        debug_assert!(matches!(stream.kind(), StreamKind::Control));

        let settings = Settings::builder()
            .qpack_max_table_capacity(VarInt::from_u32(0))
            .qpack_blocked_streams(VarInt::from_u32(0))
            .enable_webtransport()
            .enable_h3_datagrams()
            .build();

        Self { stream, settings }
    }

    pub async fn send_settings(&mut self) -> Result<(), ProtoWriteError> {
        self.stream
            .write_frame(self.settings.generate_frame())
            .await
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
