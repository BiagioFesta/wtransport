use crate::headers::Headers;
use crate::ids::InvalidStatusCode;
use crate::ids::StatusCode;
use url::Url;

/// Error when parsing URL.
#[derive(Debug)]
pub enum UrlParseError {
    /// Missing host part in the URL.
    EmptyHost,

    /// Invalid international domain name.
    IdnaError,

    /// Invalid port number.
    InvalidPort,

    /// Invalid IPv4 address
    InvalidIpv4Address,

    /// Invalid IPv6 address
    InvalidIpv6Address,

    /// Invalid domain character.
    InvalidDomainCharacter,

    /// Relative URL without a base.
    RelativeUrlWithoutBase,

    /// Relative URL with a cannot-be-a-base base
    RelativeUrlWithCannotBeABaseBase,

    /// A cannot-be-a-base URL doesn’t have a host to set
    SetHostOnCannotBeABaseUrl,

    /// URLs more than 4 GB are not supported.
    Overflow,

    /// Unknown error during URL parsing.
    Unknown,

    /// WebTransport only support HTTPS method.
    SchemeNotHttps,
}

/// Error when parsing [`Headers`].
#[derive(Debug)]
pub enum HeadersParseError {
    /// Method field is missing.
    MissingMethod,

    /// Method is not 'CONNECT'.
    MethodNotConnect,

    /// Scheme field is missing.
    MissingScheme,

    /// Scheme is not 'https'.
    SchemeNotHttps,

    /// Protocol field is missing.
    MissingProtocol,

    /// Protocol is not 'webtransport'.
    ProtocolNotWebTransport,

    /// Authority field is missing.
    MissingAuthority,

    /// Path field is missing.
    MissingPath,

    /// Status field is missing.
    MissingStatusCode,

    /// The status code value is not valid.
    InvalidStatusCode,
}

/// A CONNECT WebTransport request.
#[derive(Debug)]
pub struct SessionRequest(Headers);

impl SessionRequest {
    /// Parses an URL to build a Session request.
    pub fn new<S>(url: S) -> Result<Self, UrlParseError>
    where
        S: AsRef<str>,
    {
        let url = Url::parse(url.as_ref())?;

        if url.scheme() != "https" {
            return Err(UrlParseError::SchemeNotHttps);
        }

        let path = format!(
            "{}{}",
            url.path(),
            url.query().map(|s| format!("?{}", s)).unwrap_or_default()
        );

        let headers = [
            (":method", "CONNECT"),
            (":scheme", "https"),
            (":protocol", "webtransport"),
            (":authority", url.authority()),
            (":path", &path),
        ]
        .into_iter()
        .collect();

        Ok(Self(headers))
    }

    /// Returns the `:authority` field of the request.
    pub fn authority(&self) -> &str {
        self.0
            .get(":authority")
            .expect("Session request must contain ':authority' field")
    }

    /// Returns the `:path` field of the request.
    pub fn path(&self) -> &str {
        self.0
            .get(":path")
            .expect("Session request must contain ':path' field")
    }

    /// Gets a field from the request (if present).
    pub fn get<K>(&self, key: K) -> Option<&str>
    where
        K: AsRef<str>,
    {
        self.0.get(key)
    }

    /// Returns the whole headers associated with the request.
    pub fn headers(&self) -> &Headers {
        &self.0
    }
}

impl TryFrom<Headers> for SessionRequest {
    type Error = HeadersParseError;

    fn try_from(headers: Headers) -> Result<Self, Self::Error> {
        if headers
            .get(":method")
            .ok_or(HeadersParseError::MissingMethod)?
            != "CONNECT"
        {
            return Err(HeadersParseError::MethodNotConnect);
        }

        if headers
            .get(":scheme")
            .ok_or(HeadersParseError::MissingScheme)?
            != "https"
        {
            return Err(HeadersParseError::SchemeNotHttps);
        }

        if headers
            .get(":protocol")
            .ok_or(HeadersParseError::MissingProtocol)?
            != "webtransport"
        {
            return Err(HeadersParseError::ProtocolNotWebTransport);
        }

        headers
            .get(":authority")
            .ok_or(HeadersParseError::MissingAuthority)?;

        headers.get(":path").ok_or(HeadersParseError::MissingPath)?;

        Ok(Self(headers))
    }
}

impl From<url::ParseError> for UrlParseError {
    fn from(error: url::ParseError) -> Self {
        match error {
            url::ParseError::EmptyHost => UrlParseError::EmptyHost,
            url::ParseError::IdnaError => UrlParseError::IdnaError,
            url::ParseError::InvalidPort => UrlParseError::InvalidPort,
            url::ParseError::InvalidIpv4Address => UrlParseError::InvalidIpv4Address,
            url::ParseError::InvalidIpv6Address => UrlParseError::InvalidIpv6Address,
            url::ParseError::InvalidDomainCharacter => UrlParseError::InvalidDomainCharacter,
            url::ParseError::RelativeUrlWithoutBase => UrlParseError::RelativeUrlWithoutBase,
            url::ParseError::RelativeUrlWithCannotBeABaseBase => {
                UrlParseError::RelativeUrlWithCannotBeABaseBase
            }
            url::ParseError::SetHostOnCannotBeABaseUrl => UrlParseError::SetHostOnCannotBeABaseUrl,
            url::ParseError::Overflow => UrlParseError::Overflow,
            _ => UrlParseError::Unknown,
        }
    }
}

/// A WebTransport CONNECT response.
pub struct SessionResponse(Headers);

impl SessionResponse {
    /// Constructs from [`StatusCode`].
    pub fn with_status_code(status_code: StatusCode) -> Self {
        let headers = [(":status", status_code.to_string())].into_iter().collect();
        Self(headers)
    }

    /// Constructs with [`StatusCode::OK`].
    pub fn ok() -> Self {
        Self::with_status_code(StatusCode::OK)
    }

    /// Constructs with [`StatusCode::NOT_FOUND`].
    pub fn not_found() -> Self {
        Self::with_status_code(StatusCode::NOT_FOUND)
    }

    /// Adds a header field to the response.
    ///
    /// If the key is already present, the value is updated.
    pub fn add<K, V>(&mut self, key: K, value: V)
    where
        K: ToString,
        V: ToString,
    {
        self.0.insert(key, value)
    }

    /// Returns the whole headers associated with the request.
    pub fn headers(&self) -> &Headers {
        &self.0
    }
}

impl TryFrom<Headers> for SessionResponse {
    type Error = HeadersParseError;

    fn try_from(headers: Headers) -> Result<Self, Self::Error> {
        let status_code = headers
            .get(":status")
            .ok_or(HeadersParseError::MissingStatusCode)?
            .parse()
            .map_err(|InvalidStatusCode| HeadersParseError::InvalidStatusCode)?;

        Ok(Self::with_status_code(status_code))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_url() {
        let request = SessionRequest::new("https://localhost:4433/foo/bar?p1=1&p2=2").unwrap();
        assert_eq!(request.authority(), "localhost:4433");
        assert_eq!(request.path(), "/foo/bar?p1=1&p2=2");
        assert_eq!(request.get(":method").unwrap(), "CONNECT");
        assert_eq!(request.get(":protocol").unwrap(), "webtransport");
    }

    #[test]
    fn not_https() {
        let error = SessionRequest::new("http://localhost:4433");
        assert!(matches!(error, Err(UrlParseError::SchemeNotHttps)));
    }

    #[test]
    fn parse_headers() {
        assert!(matches!(
            SessionRequest::try_from(
                [
                    (":method", "CONNECT"),
                    (":scheme", "https"),
                    (":protocol", "webtransport"),
                    (":authority", "localhost:4433"),
                    (":path", "/")
                ]
                .into_iter()
                .collect::<Headers>()
            ),
            Ok(_),
        ));
    }

    #[test]
    fn parse_headers_error_method() {
        assert!(matches!(
            SessionRequest::try_from(
                [
                    (":scheme", "https"),
                    (":protocol", "webtransport"),
                    (":authority", "localhost:4433"),
                    (":path", "/")
                ]
                .into_iter()
                .collect::<Headers>()
            ),
            Err(HeadersParseError::MissingMethod),
        ));

        assert!(matches!(
            SessionRequest::try_from(
                [
                    (":method", "GET"),
                    (":scheme", "https"),
                    (":protocol", "webtransport"),
                    (":authority", "localhost:4433"),
                    (":path", "/")
                ]
                .into_iter()
                .collect::<Headers>()
            ),
            Err(HeadersParseError::MethodNotConnect),
        ));
    }

    #[test]
    fn parse_headers_error_scheme() {
        assert!(matches!(
            SessionRequest::try_from(
                [
                    (":method", "CONNECT"),
                    (":protocol", "webtransport"),
                    (":authority", "localhost:4433"),
                    (":path", "/")
                ]
                .into_iter()
                .collect::<Headers>()
            ),
            Err(HeadersParseError::MissingScheme),
        ));

        assert!(matches!(
            SessionRequest::try_from(
                [
                    (":method", "CONNECT"),
                    (":scheme", "http"),
                    (":protocol", "webtransport"),
                    (":authority", "localhost:4433"),
                    (":path", "/")
                ]
                .into_iter()
                .collect::<Headers>()
            ),
            Err(HeadersParseError::SchemeNotHttps),
        ));
    }
}
