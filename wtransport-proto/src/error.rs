use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;

/// HTTP3 protocol errors.
#[derive(Clone, Copy)]
pub enum Error {
    /// H3_STREAM_CREATION_ERROR
    StreamCreation,

    /// H3_CLOSED_CRITICAL_STREAM
    ClosedCriticalStream,

    /// H3_FRAME_UNEXPECTED
    FrameUnexpected,

    /// H3_FRAME_ERROR
    Frame,

    /// H3_SETTINGS_ERROR
    Settings,

    /// QPACK_DECOMPRESSION_FAILED
    Decompression,

    /// H3_MISSING_SETTINGS
    MissingSettings,

    /// H3_MESSAGE_ERROR
    Message,
}

impl Error {
    pub fn to_code(self) -> u64 {
        match self {
            Error::StreamCreation => h3_error_codes::H3_STREAM_CREATION_ERROR,
            Error::ClosedCriticalStream => h3_error_codes::H3_CLOSED_CRITICAL_STREAM,
            Error::FrameUnexpected => h3_error_codes::H3_FRAME_UNEXPECTED,
            Error::Frame => h3_error_codes::H3_FRAME_ERROR,
            Error::Settings => h3_error_codes::H3_SETTINGS_ERROR,
            Error::Decompression => qpack_error_codes::QPACK_DECOMPRESSION_FAILED,
            Error::MissingSettings => h3_error_codes::H3_MISSING_SETTINGS,
            Error::Message => h3_error_codes::H3_MESSAGE_ERROR,
        }
    }
}

impl Debug for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (code: {})", self, self.to_code())
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::StreamCreation => write!(f, "StreamCreationError"),
            Error::ClosedCriticalStream => write!(f, "ClosedCriticalStreamError"),
            Error::FrameUnexpected => write!(f, "FrameUnexpectedError"),
            Error::Frame => write!(f, "FrameError"),
            Error::Settings => write!(f, "SettingsError"),
            Error::Decompression => write!(f, "DecompressionError"),
            Error::MissingSettings => write!(f, "MissingSettingsError"),
            Error::Message => write!(f, "MessageError"),
        }
    }
}

impl std::error::Error for Error {}

mod h3_error_codes {
    pub const H3_STREAM_CREATION_ERROR: u64 = 0x0103;
    pub const H3_CLOSED_CRITICAL_STREAM: u64 = 0x0104;
    pub const H3_FRAME_UNEXPECTED: u64 = 0x0105;
    pub const H3_FRAME_ERROR: u64 = 0x0106;
    pub const H3_SETTINGS_ERROR: u64 = 0x0109;
    pub const H3_MISSING_SETTINGS: u64 = 0x010a;
    pub const H3_MESSAGE_ERROR: u64 = 0x010e;
}

mod qpack_error_codes {
    pub const QPACK_DECOMPRESSION_FAILED: u64 = 0x0200;
}
