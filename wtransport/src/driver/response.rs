use crate::driver::DriverError;
use wtransport_proto::error::ErrorCode;
use wtransport_proto::headers::Headers;

pub struct Response {
    headers: Headers,
}

impl Response {
    pub fn new_webtransport(status: u32) -> Self {
        let headers = [
            (":status", status.to_string().as_str()),
            ("sec-webtransport-http3-draft", "draft02"),
        ]
        .into_iter()
        .collect::<Headers>();

        Self::with_headers(headers)
    }

    pub fn with_headers(headers: Headers) -> Self {
        Self { headers }
    }

    pub fn status(&self) -> Result<u32, DriverError> {
        let status = self
            .headers
            .get(":status")
            .ok_or(DriverError::LocallyClosed(ErrorCode::Message))?;

        status
            .parse()
            .map_err(|_| DriverError::LocallyClosed(ErrorCode::Message))
    }

    pub fn headers(&self) -> &Headers {
        &self.headers
    }
}
