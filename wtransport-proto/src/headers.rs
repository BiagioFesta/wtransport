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
        let payload = Encoder::encode(&self.0);
        Frame::new_headers(Cow::Owned(payload.to_vec()))
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
