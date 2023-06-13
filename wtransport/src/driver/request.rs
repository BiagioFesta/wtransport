use crate::driver::response::Response;
use crate::driver::streams::biremote::StreamBiRemoteH3;
use crate::driver::streams::session::RemoteSessionStream;
use crate::driver::streams::ProtoWriteError;
use crate::driver::DriverError;
use wtransport_proto::error::ErrorCode;
use wtransport_proto::headers::Headers;

pub struct Request {
    headers: Headers,
}

impl Request {
    pub fn new_webtransport() -> Self {
        let headers = [
            (":method", "CONNECT"),
            (":protocol", "webtransport"),
            (":scheme", "https"),
        ]
        .into_iter()
        .collect::<Headers>();

        Self::with_headers(headers)
    }

    pub fn with_headers(headers: Headers) -> Self {
        Self { headers }
    }

    pub fn is_method_connect(&self) -> bool {
        self.headers.get(":method").unwrap_or_default() == "CONNECT"
    }

    pub fn protocol(&self) -> Result<&str, DriverError> {
        self.headers
            .get(":protocol")
            .ok_or(DriverError::LocallyClosed(ErrorCode::Message))
    }

    pub fn scheme(&self) -> Result<&str, DriverError> {
        self.headers
            .get(":scheme")
            .ok_or(DriverError::LocallyClosed(ErrorCode::Message))
    }

    pub fn headers(&self) -> &Headers {
        &self.headers
    }

    pub async fn try_accept_webtransport(
        mut stream: StreamBiRemoteH3,
        headers: Headers,
    ) -> Result<Option<RemoteSessionStream>, DriverError> {
        let request = Self::with_headers(headers);

        if !request.is_method_connect() {
            stream
                .stop(ErrorCode::RequestRejected.to_code())
                .expect("Not already stopped");

            return Ok(None);
        }

        if request.protocol()? != "webtransport" {
            return Err(DriverError::LocallyClosed(ErrorCode::Message));
        }

        if request.scheme()? != "https" {
            return Err(DriverError::LocallyClosed(ErrorCode::Message));
        }

        // TODO(bfesta): validate :authority and the :path

        let response = Response::new_webtransport(200);

        match stream
            .write_frame(response.headers().generate_frame(stream.id()))
            .await
        {
            Ok(()) => Ok(Some(RemoteSessionStream::new(stream))),
            Err(ProtoWriteError::Stopped) => {
                Err(DriverError::LocallyClosed(ErrorCode::ClosedCriticalStream))
            }
            Err(ProtoWriteError::NotConnected) => Err(DriverError::NotConnected),
        }
    }
}
