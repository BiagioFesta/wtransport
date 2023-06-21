use crate::driver::result::DriverError;
use crate::driver::streams::unilocal::StreamUniLocalH3;
use crate::driver::streams::uniremote::StreamUniRemoteH3;
use crate::driver::streams::ProtoReadError;
use crate::driver::streams::ProtoWriteError;
use crate::error::StreamWriteError;
use std::future::pending;
use wtransport_proto::bytes;
use wtransport_proto::error::ErrorCode;
use wtransport_proto::frame::Frame;
use wtransport_proto::frame::FrameKind;
use wtransport_proto::settings::Settings;
use wtransport_proto::stream_header::StreamKind;
use wtransport_proto::varint::VarInt;

pub struct LocalSettingsStream {
    stream: Option<StreamUniLocalH3>,
    settings: Settings,
}

impl LocalSettingsStream {
    pub fn empty() -> Self {
        let settings = Settings::builder()
            .qpack_max_table_capacity(VarInt::from_u32(0))
            .qpack_blocked_streams(VarInt::from_u32(0))
            .enable_webtransport()
            .enable_h3_datagrams()
            .build();

        Self {
            stream: None,
            settings,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.stream.is_none()
    }

    pub fn set_stream(&mut self, stream: StreamUniLocalH3) {
        assert!(matches!(stream.kind(), StreamKind::Control));
        self.stream = Some(stream);
    }

    pub async fn send_settings(&mut self) -> Result<(), DriverError> {
        match self
            .stream
            .as_mut()
            .expect("Cannot send settings on empty stream")
            .write_frame(self.settings.generate_frame())
            .await
        {
            Ok(()) => Ok(()),
            Err(ProtoWriteError::NotConnected) => Err(DriverError::NotConnected),
            Err(ProtoWriteError::Stopped) => {
                Err(DriverError::Proto(ErrorCode::ClosedCriticalStream))
            }
        }
    }

    pub async fn run(&mut self) -> DriverError {
        match self.stream.as_mut() {
            Some(stream) => match stream.stopped().await {
                StreamWriteError::NotConnected => DriverError::NotConnected,
                StreamWriteError::Stopped(_) => DriverError::Proto(ErrorCode::ClosedCriticalStream),
                StreamWriteError::QuicProto => DriverError::Proto(ErrorCode::ClosedCriticalStream),
            },
            None => pending().await,
        }
    }
}

pub struct RemoteSettingsStream {
    stream: Option<StreamUniRemoteH3>,
    settings: Option<Settings>,
}

impl RemoteSettingsStream {
    pub fn empty() -> Self {
        Self {
            stream: None,
            settings: None,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.stream.is_none()
    }

    pub fn with_stream(stream: StreamUniRemoteH3) -> Self {
        assert!(matches!(stream.kind(), StreamKind::Control));

        let mut this = Self::empty();
        this.stream = Some(stream);
        this
    }

    pub async fn run(&mut self) -> Result<Settings, DriverError> {
        loop {
            let frame = match self.read_frame().await {
                Ok(Some(frame)) => frame,
                Ok(None) => pending().await,
                Err(driver_error) => return Err(driver_error),
            };

            if self.settings.is_none() {
                if !matches!(frame.kind(), FrameKind::Settings) {
                    return Err(DriverError::Proto(ErrorCode::MissingSettings));
                }

                let settings = match Settings::with_frame(&frame) {
                    Ok(settings) => settings,
                    Err(error_code) => return Err(DriverError::Proto(error_code)),
                };

                // TODO(bfesta): validate settings

                self.settings = Some(settings.clone());

                return Ok(settings);
            } else if !matches!(frame.kind(), FrameKind::Exercise(_)) {
                return Err(DriverError::Proto(ErrorCode::FrameUnexpected));
            }
        }
    }

    async fn read_frame<'a>(&mut self) -> Result<Option<Frame<'a>>, DriverError> {
        let stream = match self.stream.as_mut() {
            Some(stream) => stream,
            None => return Ok(None),
        };

        match stream.read_frame().await {
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
