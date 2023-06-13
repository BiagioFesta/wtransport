use crate::driver::streams::uniremote::StreamUniRemoteH3;
use crate::driver::DriverError;
use crate::error::StreamReadError;
use crate::error::StreamReadExactError;
use wtransport_proto::error::ErrorCode;
use wtransport_proto::stream_header::StreamKind;

pub struct RemoteQPackEncStream {
    stream: StreamUniRemoteH3,
    buffer: Box<[u8]>,
}

impl RemoteQPackEncStream {
    pub fn new(stream: StreamUniRemoteH3) -> Self {
        debug_assert!(matches!(stream.kind(), StreamKind::QPackEncoder));
        let buffer = vec![0; 64].into_boxed_slice();
        Self { stream, buffer }
    }

    pub async fn done(&mut self) -> DriverError {
        loop {
            match self.stream.stream_mut().read_exact(&mut self.buffer).await {
                Ok(()) => {}
                Err(StreamReadExactError::FinishedEarly) => {
                    return DriverError::LocallyClosed(ErrorCode::ClosedCriticalStream);
                }
                Err(StreamReadExactError::Read(StreamReadError::NotConnected)) => {
                    return DriverError::NotConnected;
                }
                Err(StreamReadExactError::Read(StreamReadError::Reset(_))) => {
                    return DriverError::LocallyClosed(ErrorCode::ClosedCriticalStream);
                }
                Err(StreamReadExactError::Read(StreamReadError::QuicProto)) => {
                    return DriverError::LocallyClosed(ErrorCode::ClosedCriticalStream);
                }
            }
        }
    }
}

pub struct RemoteQPackDecStream {
    stream: StreamUniRemoteH3,
    buffer: Box<[u8]>,
}

impl RemoteQPackDecStream {
    pub fn new(stream: StreamUniRemoteH3) -> Self {
        debug_assert!(matches!(stream.kind(), StreamKind::QPackDecoder));
        let buffer = vec![0; 64].into_boxed_slice();
        Self { stream, buffer }
    }

    pub async fn done(&mut self) -> DriverError {
        loop {
            match self.stream.stream_mut().read_exact(&mut self.buffer).await {
                Ok(()) => {}
                Err(StreamReadExactError::FinishedEarly) => {
                    return DriverError::LocallyClosed(ErrorCode::ClosedCriticalStream);
                }
                Err(StreamReadExactError::Read(StreamReadError::NotConnected)) => {
                    return DriverError::NotConnected;
                }
                Err(StreamReadExactError::Read(StreamReadError::Reset(_))) => {
                    return DriverError::LocallyClosed(ErrorCode::ClosedCriticalStream);
                }
                Err(StreamReadExactError::Read(StreamReadError::QuicProto)) => {
                    return DriverError::LocallyClosed(ErrorCode::ClosedCriticalStream);
                }
            }
        }
    }
}
