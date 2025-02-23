use crate::bytes::BufferReader;
use crate::bytes::BytesReader;
use crate::bytes::BytesWriter;
use crate::bytes::EndOfBuffer;
use std::collections::HashMap;

/// Usage: `const_assert!(Var1: Ty, Var2: Ty, ... => expression)`
macro_rules! const_assert {
    ($($list:ident : $ty:ty),* => $expr:expr) => {{
        struct Assert<$(const $list: usize,)*>;
        impl<$(const $list: $ty,)*> Assert<$($list,)*> {
            const OK: u8 = 0 - !($expr) as u8;
        }
        Assert::<$($list,)*>::OK
    }};
    ($expr:expr) => {
        const OK: u8 = 0 - !($expr) as u8;
    };
}

/// Error during decoding operation.
///
/// Generated from [`Decoder::decode`].
#[derive(Debug, thiserror::Error)]
pub enum DecodingError {
    /// During decoding input data raeched unexpected EOF.
    #[error("end of stream reached prematurely")]
    UnexpectedFin,

    /// Integer decoding produced an overflow.
    #[error("integer overflow")]
    IntegerOverflow,

    /// String decoding is invalid (UTF-8 fail or Huffman).
    #[error("invalid string decoding")]
    InvalidString,

    /// Encoded data requires dynamic table. It is not supported.
    #[error("dynamic table is not supported")]
    DynamicNotSupported,

    /// Index is out-of-bound in the static table.
    #[error("index not found in the static table")]
    IndexNotfound,
}

enum FieldLineType {
    Indexed,
    IndexedPost,
    LiteralRefName,
    LiteralPostRefName,
    LiteralLitName,
}

/// QPACK decoder.
///
/// It only supports stateless decoding, so any data requiring
/// dynamic table will end up in a [`DecodingError::DynamicNotSupported`]
/// error.
pub struct Decoder;

impl Decoder {
    /// Decodes data stream.
    ///
    /// Result is an hash-map of headers.
    pub fn decode<D>(data: D) -> Result<HashMap<String, String>, DecodingError>
    where
        D: AsRef<[u8]>,
    {
        let mut buffer_reader = BufferReader::new(data.as_ref());

        Self::decode_integer::<8, _>(&mut buffer_reader)?;
        Self::decode_integer::<7, _>(&mut buffer_reader)?;

        let mut headers = HashMap::new();

        while buffer_reader.capacity() > 0 {
            let field = buffer_reader.buffer_remaining()[0];

            match Self::decode_field_line_type(field) {
                FieldLineType::Indexed => {
                    let is_dynamic = field & 0b0100_0000 == 0;
                    if is_dynamic {
                        return Err(DecodingError::DynamicNotSupported);
                    }

                    let index = Self::decode_integer::<6, _>(&mut buffer_reader)?.1;
                    let (key, value) =
                        StaticTable::lookup_field(index).ok_or(DecodingError::IndexNotfound)?;
                    headers.insert(key.to_string(), value.to_string());
                }
                FieldLineType::IndexedPost => {
                    return Err(DecodingError::DynamicNotSupported);
                }
                FieldLineType::LiteralRefName => {
                    let is_dynamic = field & 0b0001_0000 == 0;
                    if is_dynamic {
                        return Err(DecodingError::DynamicNotSupported);
                    }

                    let index = Self::decode_integer::<4, _>(&mut buffer_reader)?.1;
                    let key = StaticTable::lookup_field(index)
                        .ok_or(DecodingError::IndexNotfound)?
                        .0;
                    let value = Self::decode_string::<7, _>(&mut buffer_reader)?;

                    headers.insert(key.to_string(), value);
                }
                FieldLineType::LiteralPostRefName => {
                    return Err(DecodingError::DynamicNotSupported);
                }
                FieldLineType::LiteralLitName => {
                    let key = Self::decode_string::<3, _>(&mut buffer_reader)?;
                    let value = Self::decode_string::<7, _>(&mut buffer_reader)?;

                    headers.insert(key, value);
                }
            }
        }

        Ok(headers)
    }

    fn decode_field_line_type(byte: u8) -> FieldLineType {
        const MASK_INDEXED: u8 = 0b0000_0001;
        const MASK_INDEXED_POST: u8 = 0b0000_0001;
        const MASK_LITERAL_REF_NAME: u8 = 0b0000_0001;
        const MASK_LITERAL_POST_REF_NAME: u8 = 0b0000_0000;
        const MASK_LITERAL_LIT_NAME: u8 = 0b0000_0001;

        if byte >> 7 == MASK_INDEXED {
            FieldLineType::Indexed
        } else if byte >> 4 == MASK_INDEXED_POST {
            FieldLineType::IndexedPost
        } else if byte >> 6 == MASK_LITERAL_REF_NAME {
            FieldLineType::LiteralRefName
        } else if byte >> 4 == MASK_LITERAL_POST_REF_NAME {
            FieldLineType::LiteralPostRefName
        } else if byte >> 5 == MASK_LITERAL_LIT_NAME {
            FieldLineType::LiteralLitName
        } else {
            unreachable!()
        }
    }

    fn decode_integer<'a, const N: usize, R>(
        bytes_reader: &mut R,
    ) -> Result<(u8, usize), DecodingError>
    where
        R: BytesReader<'a>,
    {
        const_assert!(N: usize => N <= 8 && N >= 1);

        let byte = bytes_reader
            .get_bytes(1)
            .ok_or(DecodingError::UnexpectedFin)?[0] as usize;

        let mask = (0x01 << N) - 1;
        let flags = (byte >> N) as u8;
        let mut value = byte & mask;

        if value != mask {
            return Ok((flags, value));
        }

        let mut power = 0;
        loop {
            let byte = bytes_reader
                .get_bytes(1)
                .ok_or(DecodingError::UnexpectedFin)?[0] as usize;

            value = value
                .checked_add((byte & 0x7F) << power)
                .ok_or(DecodingError::IntegerOverflow)?;

            power += 7;

            if byte & 0x80 == 0 {
                break;
            }
        }

        Ok((flags, value))
    }

    fn decode_string<'a, const N: usize, R>(bytes_reader: &mut R) -> Result<String, DecodingError>
    where
        R: BytesReader<'a>,
    {
        let (flags, string_len) = Self::decode_integer::<N, R>(bytes_reader)?;

        let is_huffman = flags & 0x1 == 0x1;

        let string_data = bytes_reader
            .get_bytes(string_len)
            .ok_or(DecodingError::UnexpectedFin)?;

        let string_data = if is_huffman {
            let mut string_dec = Vec::with_capacity(string_len);

            httlib_huffman::decode(
                string_data,
                &mut string_dec,
                httlib_huffman::DecoderSpeed::OneBit,
            )
            .map_err(|_| DecodingError::InvalidString)?;

            string_dec
        } else {
            string_data.to_vec()
        };

        String::from_utf8(string_data).map_err(|_| DecodingError::InvalidString)
    }
}

/// QPACK encoder.
///
/// It only supports stateless decoding, so all encoding
/// will be performed by means of the static table.
pub struct Encoder;

impl Encoder {
    /// Encodes headers into data to be transmitted.
    pub fn encode<H, K, V>(headers: H) -> Box<[u8]>
    where
        H: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let mut buffer = Vec::new();

        Self::encode_integer::<8, _>(0, 0, &mut buffer).expect("vec does not eof");
        Self::encode_integer::<7, _>(0, 0, &mut buffer).expect("vec does not eof");

        for (key, value) in headers.into_iter() {
            match StaticTable::lookup_index(key.as_ref(), value.as_ref()) {
                Some(LookupIndexFound::KeyValue(index)) => {
                    Self::encode_integer::<6, _>(0b11, index, &mut buffer)
                        .expect("vec does not eof");
                }
                Some(LookupIndexFound::KeyOnly(index)) => {
                    Self::encode_integer::<4, _>(0b0101, index, &mut buffer)
                        .expect("vec does not eof");
                    Self::encode_string::<7, _, _>(0, value, &mut buffer)
                        .expect("vec does not eof");
                }
                None => {
                    Self::encode_string::<3, _, _>(0b10, key, &mut buffer)
                        .expect("vec does not eof");
                    Self::encode_string::<7, _, _>(0, value, &mut buffer)
                        .expect("vec does not eof");
                }
            }
        }

        buffer.into_boxed_slice()
    }

    fn encode_integer<const N: usize, W>(
        flags: u8,
        value: usize,
        bytes_writer: &mut W,
    ) -> Result<(), EndOfBuffer>
    where
        W: BytesWriter,
    {
        const_assert!(N: usize => N <= 8 && N >= 1);

        let mask = (0x01 << N) - 1;
        let flags = ((flags as usize) << N) as u8;

        if value < mask {
            bytes_writer.put_bytes(&[flags | value as u8])?;
            return Ok(());
        }

        bytes_writer.put_bytes(&[flags | mask as u8])?;

        let mut rem = value - mask;
        while rem >= 0x80 {
            let byte = rem as u8 | 0x80;
            bytes_writer.put_bytes(&[byte])?;
            rem >>= 7;
        }

        bytes_writer.put_bytes(&[rem as u8])?;

        Ok(())
    }

    fn encode_string<const N: usize, S, W>(
        flags: u8,
        value: S,
        bytes_writer: &mut W,
    ) -> Result<(), EndOfBuffer>
    where
        S: AsRef<str>,
        W: BytesWriter,
    {
        let value = value.as_ref().as_bytes();

        let mut huffman_buffer = Vec::new();

        let (is_huffman, string_data) = match httlib_huffman::encode(value, &mut huffman_buffer) {
            Ok(()) => {
                if huffman_buffer.len() < value.len() {
                    (true, huffman_buffer.as_slice())
                } else {
                    (false, value)
                }
            }
            Err(_) => (false, value),
        };

        let flags = (flags << 1) | (is_huffman as u8);

        Self::encode_integer::<N, _>(flags, string_data.len(), bytes_writer)?;
        bytes_writer.put_bytes(string_data)
    }
}

enum LookupIndexFound {
    KeyValue(usize),
    KeyOnly(usize),
}

struct StaticTable;

impl StaticTable {
    const STATIC_TABLE: &'static [(&'static str, &'static str); 99] = &[
        (":authority", ""),
        (":path", "/"),
        ("age", "0"),
        ("content-disposition", ""),
        ("content-length", "0"),
        ("cookie", ""),
        ("date", ""),
        ("etag", ""),
        ("if-modified-since", ""),
        ("if-none-match", ""),
        ("last-modified", ""),
        ("link", ""),
        ("location", ""),
        ("referer", ""),
        ("set-cookie", ""),
        (":method", "CONNECT"),
        (":method", "DELETE"),
        (":method", "GET"),
        (":method", "HEAD"),
        (":method", "OPTIONS"),
        (":method", "POST"),
        (":method", "PUT"),
        (":scheme", "http"),
        (":scheme", "https"),
        (":status", "103"),
        (":status", "200"),
        (":status", "304"),
        (":status", "404"),
        (":status", "503"),
        ("accept", "*/*"),
        ("accept", "application/dns-message"),
        ("accept-encoding", "gzip, deflate, br"),
        ("accept-ranges", "bytes"),
        ("access-control-allow-headers", "cache-control"),
        ("access-control-allow-headers", "content-type"),
        ("access-control-allow-origin", "*"),
        ("cache-control", "max-age=0"),
        ("cache-control", "max-age=2592000"),
        ("cache-control", "max-age=604800"),
        ("cache-control", "no-cache"),
        ("cache-control", "no-store"),
        ("cache-control", "public, max-age=31536000"),
        ("content-encoding", "br"),
        ("content-encoding", "gzip"),
        ("content-type", "application/dns-message"),
        ("content-type", "application/javascript"),
        ("content-type", "application/json"),
        ("content-type", "application/x-www-form-urlencoded"),
        ("content-type", "image/gif"),
        ("content-type", "image/jpeg"),
        ("content-type", "image/png"),
        ("content-type", "text/css"),
        ("content-type", "text/html; charset=utf-8"),
        ("content-type", "text/plain"),
        ("content-type", "text/plain;charset=utf-8"),
        ("range", "bytes=0-"),
        ("strict-transport-security", "max-age=31536000"),
        (
            "strict-transport-security",
            "max-age=31536000; includesubdomains",
        ),
        (
            "strict-transport-security",
            "max-age=31536000; includesubdomains; preload",
        ),
        ("vary", "accept-encoding"),
        ("vary", "origin"),
        ("x-content-type-options", "nosniff"),
        ("x-xss-protection", "1; mode=block"),
        (":status", "100"),
        (":status", "204"),
        (":status", "206"),
        (":status", "302"),
        (":status", "400"),
        (":status", "403"),
        (":status", "421"),
        (":status", "425"),
        (":status", "500"),
        ("accept-language", ""),
        ("access-control-allow-credentials", "FALSE"),
        ("access-control-allow-credentials", "TRUE"),
        ("access-control-allow-headers", "*"),
        ("access-control-allow-methods", "get"),
        ("access-control-allow-methods", "get, post, options"),
        ("access-control-allow-methods", "options"),
        ("access-control-expose-headers", "content-length"),
        ("access-control-request-headers", "content-type"),
        ("access-control-request-method", "get"),
        ("access-control-request-method", "post"),
        ("alt-svc", "clear"),
        ("authorization", ""),
        (
            "content-security-policy",
            "script-src 'none'; object-src 'none'; base-uri 'none'",
        ),
        ("early-data", "1"),
        ("expect-ct", ""),
        ("forwarded", ""),
        ("if-range", ""),
        ("origin", ""),
        ("purpose", "prefetch"),
        ("server", ""),
        ("timing-allow-origin", "*"),
        ("upgrade-insecure-requests", "1"),
        ("user-agent", ""),
        ("x-forwarded-for", ""),
        ("x-frame-options", "deny"),
        ("x-frame-options", "sameorigin"),
    ];

    fn lookup_field(index: usize) -> Option<(&'static str, &'static str)> {
        Self::STATIC_TABLE.get(index).cloned()
    }

    fn lookup_index<K, V>(key: K, value: V) -> Option<LookupIndexFound>
    where
        K: AsRef<str>,
        V: AsRef<str>,
    {
        Self::STATIC_TABLE
            .iter()
            .enumerate()
            .find(|(_index, entry)| key.as_ref() == entry.0)
            .map(|(index, entry)| {
                if value.as_ref() == entry.1 {
                    LookupIndexFound::KeyValue(index)
                } else {
                    LookupIndexFound::KeyOnly(index)
                }
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::random;
    use rand::rng;
    use rand::Rng;

    #[test]
    fn decode_field_line_type() {
        for i in 0..=u8::MAX {
            Decoder::decode_field_line_type(i);
        }
    }

    #[test]
    fn encode_decode() {
        let headers = HashMap::from([
            ("key1", "value1"),
            (":status", "200"),
            ("key2", "value2"),
            (":status", "not_found"),
        ]);

        let enc_data = Encoder::encode(&headers);
        let headers_dec = Decoder::decode(enc_data).unwrap();
        let headers_dec = headers_dec
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        assert_eq!(headers, headers_dec);
    }

    #[test]
    fn integer() {
        const PREFIX_LEN: usize = 5;

        let mut buffer = Vec::new();

        for _ in 0..1_000_000 {
            buffer.clear();

            let flags = random::<u8>() & ((0x1 << (8 - PREFIX_LEN)) - 1);
            let value = random::<u64>() as usize;

            Encoder::encode_integer::<PREFIX_LEN, _>(flags, value, &mut buffer).unwrap();

            let (flags_dec, value_dec) =
                Decoder::decode_integer::<PREFIX_LEN, _>(&mut buffer.as_slice()).unwrap();

            assert_eq!(flags, flags_dec);
            assert_eq!(value, value_dec);
        }
    }

    #[test]
    fn integer_max() {
        let mut buffer = Vec::new();
        Encoder::encode_integer::<1, _>(0, usize::MAX, &mut buffer).unwrap();
        let (_, value) = Decoder::decode_integer::<1, _>(&mut buffer.as_slice()).unwrap();
        assert_eq!(value, usize::MAX);
    }

    #[test]
    fn integer_overflow() {
        let mut buffer = Vec::new();

        for len in 0.. {
            buffer.clear();
            buffer.resize(len, 0xFF);

            if let Err(DecodingError::IntegerOverflow) =
                Decoder::decode_integer::<1, _>(&mut buffer.as_slice())
            {
                break;
            }
        }
    }

    #[test]
    fn integer_eof() {
        assert!(matches!(
            Decoder::decode_integer::<1, _>(&mut [0b0000_0001].as_slice()),
            Err(DecodingError::UnexpectedFin)
        ));

        assert!(matches!(
            Decoder::decode_integer::<1, _>(&mut [0b0000_0001, 0b1000_0000].as_slice()),
            Err(DecodingError::UnexpectedFin)
        ));
    }

    #[test]
    fn string() {
        const PREFIX_LEN: usize = 5;

        let mut buffer = Vec::new();

        for _ in 0..10_000 {
            buffer.clear();

            let flags = random::<u8>() & ((0x1 << (8 - PREFIX_LEN)) - 1);

            let string_len = rng().random_range(0..1024);
            let value = rng()
                .sample_iter(rand::distr::Alphanumeric)
                .take(string_len)
                .map(char::from)
                .collect::<String>();

            Encoder::encode_string::<PREFIX_LEN, _, _>(flags, &value, &mut buffer).unwrap();

            let value_dec =
                Decoder::decode_string::<PREFIX_LEN, _>(&mut buffer.as_slice()).unwrap();

            assert_eq!(value, value_dec);
        }
    }
}
