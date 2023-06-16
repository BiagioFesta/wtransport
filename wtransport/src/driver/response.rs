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

    pub fn status(&self) -> Option<u32> {
        self.headers.get(":status")?.parse().ok()
    }

    pub fn headers(&self) -> &Headers {
        &self.headers
    }
}
