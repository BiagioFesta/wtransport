use wtransport_proto::headers::Headers;

#[derive(Debug)]
pub struct MalformedRequest;

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

        Self::with_headers(headers).expect("Well-formed request")
    }

    pub fn with_headers(headers: Headers) -> Result<Self, MalformedRequest> {
        if headers.get(":method").is_none() {
            return Err(MalformedRequest);
        }

        if headers.get(":method").unwrap_or_default() != "CONNECT"
            && (headers.get(":scheme").is_none() || headers.get(":path").is_none())
        {
            return Err(MalformedRequest);
        }

        Ok(Self { headers })
    }

    pub fn method(&self) -> Option<&str> {
        self.headers.get(":method")
    }

    pub fn protocol(&self) -> Option<&str> {
        self.headers.get(":protocol")
    }

    pub fn scheme(&self) -> Option<&str> {
        self.headers.get(":scheme")
    }

    pub fn headers(&self) -> &Headers {
        &self.headers
    }

    pub fn is_webtransport_connect(&self) -> bool {
        // TODO(bfesta): check path and authority
        self.method().unwrap_or_default() == "CONNECT"
            && self.protocol().unwrap_or_default() == "webtransport"
            && self.scheme().unwrap_or_default() == "https"
    }
}
