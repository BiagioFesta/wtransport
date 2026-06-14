use crate::error::ErrorCode;
use crate::frame::Frame;
use crate::frame::FrameKind;
use crate::qpack::Decoder;
use crate::qpack::Encoder;
use std::borrow::Cow;
use std::collections::HashMap;

/// HTTP3 headers from the request or response.
#[derive(Debug)]
pub struct Headers(HashMap<String, String>);

impl Headers {
    /// Constructs the headers from a HTTP3 [`Frame`].
    ///
    /// # Panics
    ///
    /// Panics if `frame` is not type [`FrameKind::Headers`].
    pub fn with_frame(frame: &Frame) -> Result<Self, ErrorCode> {
        assert!(matches!(frame.kind(), FrameKind::Headers));

        let headers = Decoder::decode(frame.payload()).map_err(|_| ErrorCode::Decompression)?;

        Ok(Self(headers))
    }

    /// Generates a [`Frame`] with these headers.
    pub fn generate_frame(&self) -> Frame<'static> {
        let payload = Encoder::encode(self.ordered_fields());
        Frame::new_headers(Cow::Owned(payload.to_vec()))
    }

    /// Returns the fields ordered such that pseudo-header fields precede regular ones.
    ///
    /// Pseudo-header fields (those whose name starts with `:`) must appear before
    /// regular header fields in the encoded field section (RFC 9114, Section 4.3).
    /// The headers are stored in a [`HashMap`], whose iteration order is unspecified,
    /// so this explicitly orders pseudo-headers first. Otherwise a regular header may
    /// be serialized ahead of a pseudo-header, and a compliant peer (e.g. quic-go)
    /// rejects the field section with `H3_MESSAGE_ERROR`.
    fn ordered_fields(&self) -> Vec<(&str, &str)> {
        let mut fields = self
            .0
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect::<Vec<_>>();

        // Stable sort: pseudo-headers (`false` < `true`) first, regular fields after.
        fields.sort_by_key(|(name, _)| !name.starts_with(':'));
        fields
    }

    /// Returns a reference to the value associated with the key.
    #[inline(always)]
    pub fn get<K>(&self, key: K) -> Option<&str>
    where
        K: AsRef<str>,
    {
        self.0.get(key.as_ref()).map(|s| s.as_str())
    }

    /// Inserts a field (key, value) in the headers.
    ///
    /// If the headers did have this key present, the value is updated.
    #[inline(always)]
    pub fn insert<K, V>(&mut self, key: K, value: V)
    where
        K: ToString,
        V: ToString,
    {
        self.0.insert(key.to_string(), value.to_string());
    }
}

impl<K, V> FromIterator<(K, V)> for Headers
where
    K: ToString,
    V: ToString,
{
    fn from_iter<T: IntoIterator<Item = (K, V)>>(iter: T) -> Self {
        Self(
            iter.into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        )
    }
}

impl AsRef<HashMap<String, String>> for Headers {
    fn as_ref(&self) -> &HashMap<String, String> {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_frame_kind() {
        let headers = [("key1", "value1"), ("key2", "value2")]
            .into_iter()
            .collect::<Headers>();

        let frame = headers.generate_frame();
        assert!(matches!(frame.kind(), FrameKind::Headers));
    }

    #[test]
    fn get() {
        let headers = [("key1", "value1"), ("key2", "value2")]
            .into_iter()
            .collect::<Headers>();

        assert_eq!(headers.get("key1"), Some("value1"));
        assert_eq!(headers.get("key2"), Some("value2"));
        assert_eq!(headers.get("key3"), None);
    }

    #[test]
    fn insert() {
        let mut headers = [("key1", "value1"), ("key2", "value2")]
            .into_iter()
            .collect::<Headers>();

        assert_eq!(headers.get("key1"), Some("value1"));
        headers.insert("key1", "value1bis");
        assert_eq!(headers.get("key1"), Some("value1bis"));

        assert_eq!(headers.get("key3"), None);
        headers.insert("key3", "value3");
        assert_eq!(headers.get("key3"), Some("value3"));
    }

    #[test]
    fn pseudo_headers_first() {
        // Mix pseudo-headers and regular headers; insertion order is irrelevant since
        // the backing store is a `HashMap`. Regardless of hashing, the encoded fields
        // must place every pseudo-header before any regular header (RFC 9114 §4.3).
        let mut headers = [
            (":method", "CONNECT"),
            (":scheme", "https"),
            (":protocol", "webtransport"),
            (":authority", "example.com:443"),
            (":path", "/"),
        ]
        .into_iter()
        .collect::<Headers>();
        headers.insert("sec-webtransport-http3-draft02", "1");
        headers.insert("user-agent", "wtransport");

        let fields = headers.ordered_fields();

        let first_regular = fields
            .iter()
            .position(|(name, _)| !name.starts_with(':'))
            .expect("there are regular fields");
        let last_pseudo = fields
            .iter()
            .rposition(|(name, _)| name.starts_with(':'))
            .expect("there are pseudo fields");

        assert!(
            last_pseudo < first_regular,
            "all pseudo-headers must precede regular headers, got: {fields:?}"
        );
    }

    #[test]
    fn idempotence() {
        let headers = [("key1", "value1"), ("key2", "value2")]
            .into_iter()
            .collect::<Headers>();

        let frame = headers.generate_frame();

        assert_eq!(
            headers.as_ref(),
            Headers::with_frame(&frame).unwrap().as_ref()
        );
    }
}
