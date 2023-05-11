use crate::error::Error;
use crate::frame::Frame;
use crate::frame::FrameKind;
use crate::stream::StreamId;
use ls_qpack::decoder::Decoder;
use ls_qpack::decoder::DecoderOutput;
use ls_qpack::encoder::Encoder;
use ls_qpack::errors::DecoderError;
use std::collections::HashMap;

#[derive(Debug)]
pub struct Headers(HashMap<String, String>);

impl Headers {
    pub fn with_frame(frame: &Frame, stream_id: StreamId) -> Result<Self, Error> {
        debug_assert!(matches!(frame.kind(), FrameKind::Headers));

        let mut decoder = Decoder::new(0, 0);

        match decoder
            .decode(ls_qpack::StreamId::new(stream_id), frame.payload())
            .map_err(|DecoderError| Error::Decompression)?
        {
            DecoderOutput::Done(headers) => Ok(headers
                .into_iter()
                .map(|h| (h.name().to_string(), h.value().to_string()))
                .collect()),
            DecoderOutput::BlockedStream => todo!(),
        }
    }

    pub fn generate_frame(&self, stream_id: StreamId) -> Frame {
        let mut encoder = Encoder::new();

        let (enc_headers, enc_stream) = encoder
            .encode_all(ls_qpack::StreamId::new(stream_id), self.0.iter())
            .expect("Static encoding is not expected to fail")
            .take();

        debug_assert_eq!(enc_stream.len(), 0);

        Frame::with_payload_own(FrameKind::Headers, enc_headers)
    }

    pub fn get<K>(&self, key: K) -> Option<&str>
    where
        K: AsRef<str>,
    {
        self.0.get(key.as_ref()).map(|s| s.as_str())
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
