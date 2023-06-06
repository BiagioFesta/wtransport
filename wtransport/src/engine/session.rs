use crate::engine::stream::Bi;
use crate::engine::stream::BiLocal;
use crate::engine::stream::BiRemote;
use crate::engine::stream::FrameReadError;
use crate::engine::stream::FrameWriteError;
use crate::engine::stream::Raw;
use crate::engine::stream::Stream;
use crate::engine::stream::H3;
use crate::error::H3Code;
use crate::error::H3Error;
use wtransport_proto::frame::FrameKind;
use wtransport_proto::headers::Headers;
use wtransport_proto::ids::SessionId;

#[derive(Debug)]
pub(crate) enum SessionError {
    LocalClosed(H3Error),
    RemoteClosed,
}

pub(crate) struct SessionRemoteRequest {
    stream: Stream<BiRemote, H3>,
    headers: Headers,
}

impl SessionRemoteRequest {
    pub(super) fn new(stream: Stream<BiRemote, H3>, headers: Headers) -> Self {
        Self { stream, headers }
    }

    pub async fn accept(mut self) -> Result<Session, SessionError> {
        let response_headers = [
            (":status", "200"),
            ("sec-webtransport-http3-draft", "draft02"),
        ]
        .into_iter()
        .collect::<Headers>();

        Self::validate_headers(self.headers)?;

        self.stream
            .write_frame(response_headers.generate_frame(self.stream.id()))
            .await
            .map_err(|frame_write_error| {
                SessionError::with_frame_write_err(frame_write_error, "Unable to accept SESSION")
            })?;

        Ok(Session(self.stream.normalize()))
    }

    fn validate_headers(headers: Headers) -> Result<(), SessionError> {
        let method = headers.get(":method").unwrap_or_default();
        if method != "CONNECT" {
            return Err(SessionError::LocalClosed(H3Error::new(
                H3Code::Message,
                "Method not supported",
            )));
        }

        let protocol = headers.get(":protocol").unwrap_or_default();
        if protocol != "webtransport" {
            return Err(SessionError::LocalClosed(H3Error::new(
                H3Code::Message,
                "Protocol not supported",
            )));
        }

        let scheme = headers.get(":scheme").unwrap_or_default();
        if scheme != "https" {
            return Err(SessionError::LocalClosed(H3Error::new(
                H3Code::Message,
                "Protocol not supported",
            )));
        }

        Ok(())
    }
}

pub(crate) struct SessionLocalRequest {
    stream: Stream<BiLocal, H3>,
}

impl SessionLocalRequest {
    pub(super) fn new(stream: Stream<BiLocal, H3>) -> Self {
        Self { stream }
    }

    pub async fn request(mut self) -> Result<SessionRemoteResponse, SessionError> {
        let request_headers = [
            (":method", "CONNECT"),
            (":protocol", "webtransport"),
            (":scheme", "https"),
        ]
        .into_iter()
        .collect::<Headers>();

        self.stream
            .write_frame(request_headers.generate_frame(self.stream.id()))
            .await
            .map_err(|frame_write_error| {
                SessionError::with_frame_write_err(frame_write_error, "Unable to request SESSION")
            })?;

        Ok(SessionRemoteResponse {
            stream: self.stream,
        })
    }
}

pub(crate) struct SessionRemoteResponse {
    stream: Stream<BiLocal, H3>,
}

impl SessionRemoteResponse {
    pub async fn confirm(mut self) -> Result<Session, SessionError> {
        loop {
            let frame = self.stream.read_frame().await.map_err(|frame_read_error| {
                SessionError::with_frame_read_err(frame_read_error, "Unable to read reply SESSION")
            })?;

            let headers = match frame.kind() {
                FrameKind::Headers => match Headers::with_frame(&frame, self.stream.id()) {
                    Ok(header) => header,
                    Err(h3code) => {
                        return Err(SessionError::LocalClosed(H3Error::new(
                            h3code,
                            "Error on decoding headers on response",
                        )));
                    }
                },
                FrameKind::Exercise(_) => continue,
                _ => {
                    return Err(SessionError::LocalClosed(H3Error::new(
                        H3Code::FrameUnexpected,
                        "Unexpected frame on SESSION reply",
                    )));
                }
            };

            Self::validate_headers(headers)?;

            return Ok(Session(self.stream.normalize()));
        }
    }

    fn validate_headers(headers: Headers) -> Result<(), SessionError> {
        let method = headers.get(":status").unwrap_or_default();
        if method != "200" {
            return Err(SessionError::LocalClosed(H3Error::new(
                H3Code::Message,
                "CONNECT refused",
            )));
        }

        Ok(())
    }
}

pub(crate) struct Session(Stream<Bi, Raw>);

impl Session {
    #[inline(always)]
    pub fn id(&self) -> SessionId {
        // SAFETY: inner stream is a session stream by construction
        unsafe {
            debug_assert!(self.0.id().is_bidirectional() && self.0.id().is_client_initiated());
            SessionId::from_session_stream_unchecked(self.0.id())
        }
    }
}

impl SessionError {
    fn with_frame_write_err<S>(frame_write_error: FrameWriteError, reason: S) -> Self
    where
        S: ToString,
    {
        match frame_write_error {
            FrameWriteError::EndOfStream => {
                SessionError::LocalClosed(H3Error::new(H3Code::ClosedCriticalStream, reason))
            }
            FrameWriteError::ConnectionClosed => SessionError::RemoteClosed,
        }
    }

    fn with_frame_read_err<S>(frame_read_error: FrameReadError, reason: S) -> Self
    where
        S: ToString,
    {
        match frame_read_error {
            FrameReadError::UnknownFrame => {
                SessionError::LocalClosed(H3Error::new(H3Code::FrameUnexpected, reason))
            }
            FrameReadError::InvalidSessionId => {
                SessionError::LocalClosed(H3Error::new(H3Code::FrameUnexpected, reason))
            }
            FrameReadError::EndOfStream => {
                SessionError::LocalClosed(H3Error::new(H3Code::ClosedCriticalStream, reason))
            }
            FrameReadError::ConnectionClosed => SessionError::RemoteClosed,
        }
    }
}
