use std::error::Error;
use std::fmt::Debug;
use std::fmt::Display;
use std::path::Path;
use std::path::PathBuf;
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;

/// Error during load operation of certificate.
pub enum CertificateLoadError {
    /// The certificate file does not contain a valid certificate.
    InvalidCertificate,

    /// The key file does not contain a valid private key.
    InvalidPrivateKey,

    /// Load operation failed because I/O operation on file.
    FileError {
        /// Filename of the operation.
        file: PathBuf,

        /// IO error details.
        error: std::io::Error,
    },
}

/// An error type representing an invalid certificate.
///
/// This error type is used to signal that a certificate in a chain is invalid,
/// and it provides additional information about the index in the chain.
pub struct InvalidCertificate(usize);

/// A server TLS certificate.
#[derive(Clone)]
pub struct Certificate {
    pub(crate) certificates: Vec<Vec<u8>>,
    pub(crate) private_key: Vec<u8>,
}

impl Certificate {
    /// Creates a new `Certificate` instance from encoded certificate data and a private key.
    ///
    /// This method takes a chain of certificate data and a private key in encoded form as input,
    /// and constructs a `Certificate` object for configuring TLS settings.
    ///
    /// # Arguments
    ///
    /// * `certificates`: A vector of vectors of bytes (`Vec<Vec<u8>>`) representing the certificate chain.
    ///   Each certificate data must be *DER-encoded* *X.509* format.
    ///
    /// * `private_key`: A vector of bytes (`Vec<u8>`) containing the private key. The private key must be
    ///   *DER-encoded* in one of the following formats: *PKCS#8*, *PKCS#1*, or *Sec1*.
    pub fn new<CertChain, Key, Cert>(
        certificates: CertChain,
        private_key: Key,
    ) -> Result<Self, InvalidCertificate>
    where
        CertChain: Into<Vec<Cert>>,
        Key: Into<Vec<u8>>,
        Cert: Into<Vec<u8>>,
    {
        let certificates = certificates
            .into()
            .into_iter()
            .map(|c| c.into())
            .collect::<Vec<_>>();

        let private_key = private_key.into();

        for (index, cert) in certificates.iter().enumerate() {
            if X509Certificate::from_der(cert).is_err() {
                return Err(InvalidCertificate(index));
            }
        }

        Ok(Self {
            certificates,
            private_key,
        })
    }

    /// Generates a self-signed certificate.
    ///
    /// The certificate conforms to the W3C WebTransport specifications as follows:
    ///
    /// - The certificate MUST be an *X.509v3* certificate as defined in *RFC5280*.
    /// - The key used in the Subject Public Key field MUST be one of the allowed public key algorithms.
    ///   This function uses the `ECDSA P-256` algorithm.
    /// - The current time MUST be within the validity period of the certificate as defined
    ///   in Section 4.1.2.5 of *RFC5280*.
    /// - The total length of the validity period MUST NOT exceed two weeks.
    ///
    /// # Arguments
    ///
    /// * `subject_alt_names` - An iterator of strings representing subject alternative names (SANs).
    ///                         They can be both hostnames or IP addresses.
    ///
    /// # Examples
    ///
    /// ```
    /// use wtransport::Certificate;
    ///
    /// let certificate = Certificate::self_signed(&["localhost", "127.0.0.1", "::1"]);
    /// ```
    #[cfg(feature = "self-signed")]
    #[cfg_attr(docsrs, doc(cfg(feature = "self-signed")))]
    pub fn self_signed<I, S>(subject_alt_names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        use rcgen::CertificateParams;
        use rcgen::DistinguishedName;
        use rcgen::DnType;
        use rcgen::PKCS_ECDSA_P256_SHA256;
        use time::Duration;
        use time::OffsetDateTime;

        let subject_alt_names = subject_alt_names
            .into_iter()
            .map(|s| s.as_ref().to_string())
            .collect::<Vec<_>>();

        let mut dname = DistinguishedName::new();
        dname.push(DnType::CommonName, "wtransport self-signed");

        let mut cert_params = CertificateParams::new(subject_alt_names);
        cert_params.alg = &PKCS_ECDSA_P256_SHA256;
        cert_params.distinguished_name = dname;
        cert_params.not_before = OffsetDateTime::now_utc();
        cert_params.not_after = OffsetDateTime::now_utc()
            .checked_add(Duration::days(14))
            .expect("addition does not overflow");

        let cert = rcgen::Certificate::from_params(cert_params).expect("inner params are valid");

        Self::new(
            vec![cert.serialize_der().expect("valid certificate")],
            cert.serialize_private_key_der(),
        )
        .expect("valid certificate")
    }

    /// For each certificate in this chain, computes its corresponding *hash*.
    ///
    /// The hash is the *SHA-256* of the DER encoding of the certificate.
    ///
    /// This function can be used to make a *web* client accept a self-signed
    /// certificate by using the [`WebTransportOptions.serverCertificateHashes`] W3C API.
    ///
    /// [`WebTransportOptions.serverCertificateHashes`]: https://www.w3.org/TR/webtransport/#dom-webtransportoptions-servercertificatehashes
    #[cfg(feature = "self-signed")]
    #[cfg_attr(docsrs, doc(cfg(feature = "self-signed")))]
    pub fn hashes(&self) -> Vec<Sha256Digest> {
        use ring::digest::digest;
        use ring::digest::SHA256;

        self.certificates
            .iter()
            .map(|cert| {
                Sha256Digest(
                    digest(&SHA256, cert)
                        .as_ref()
                        .try_into()
                        .expect("SHA256 digest is 32 bytes len"),
                )
            })
            .collect()
    }

    /// Loads a PEM certificates and private key from the filesystem.
    pub async fn load(
        cert_path: impl AsRef<Path>,
        key_path: impl AsRef<Path>,
    ) -> Result<Self, CertificateLoadError> {
        let certificates =
            rustls_pemfile::certs(&mut &*tokio::fs::read(cert_path.as_ref()).await.map_err(
                |io_error| CertificateLoadError::FileError {
                    file: cert_path.as_ref().to_path_buf(),
                    error: io_error,
                },
            )?)
            .map_err(|io_error| CertificateLoadError::FileError {
                file: cert_path.as_ref().to_path_buf(),
                error: io_error,
            })?;

        if certificates.is_empty() {
            return Err(CertificateLoadError::InvalidCertificate);
        }

        let private_key =
            rustls_pemfile::read_one(&mut &*tokio::fs::read(key_path.as_ref()).await.map_err(
                |io_error| CertificateLoadError::FileError {
                    file: key_path.as_ref().to_path_buf(),
                    error: io_error,
                },
            )?)
            .map_err(|io_error| CertificateLoadError::FileError {
                file: key_path.as_ref().to_path_buf(),
                error: io_error,
            })?
            .and_then(|item| match item {
                rustls_pemfile::Item::RSAKey(d) => Some(d),
                rustls_pemfile::Item::PKCS8Key(d) => Some(d),
                rustls_pemfile::Item::ECKey(d) => Some(d),
                _ => None,
            })
            .ok_or(CertificateLoadError::InvalidPrivateKey)?;

        let private_key = rustls::PrivateKey(private_key);

        if rustls::sign::any_supported_type(&private_key).is_err() {
            return Err(CertificateLoadError::InvalidPrivateKey);
        }

        Ok(Self::new(certificates, private_key.0).expect("validated certificate"))
    }

    /// Gets a reference to the certificate data chain associated with this `Certificate`.
    ///
    /// Each certificate is *DER-encoded*.
    pub fn certificates(&self) -> &[Vec<u8>] {
        &self.certificates
    }

    /// Gets a reference to the private key associated with this `Certificate`.
    ///
    /// Each certificate is *DER-encoded*.
    pub fn private_key(&self) -> &[u8] {
        &self.private_key
    }
}

impl Error for CertificateLoadError {}

impl Debug for CertificateLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidCertificate => write!(f, "no valid certificate to load found"),
            Self::InvalidPrivateKey => write!(f, "no valid private key to load found"),
            Self::FileError { file, error } => {
                write!(f, "file ('{}') error: {:?}", file.display(), error)
            }
        }
    }
}

impl Display for CertificateLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CertificateLoadError::InvalidCertificate => Debug::fmt(&self, f),
            CertificateLoadError::InvalidPrivateKey => Debug::fmt(&self, f),
            CertificateLoadError::FileError { file, error } => {
                write!(f, "file ('{}') error: {}", file.display(), error)
            }
        }
    }
}

impl Error for InvalidCertificate {}

impl Debug for InvalidCertificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "invalid certificate (chain index: {})",
            self.0
        ))
    }
}

impl Display for InvalidCertificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(self, f)
    }
}

/// Represents the formatting options for displaying a SHA-256 digest.
#[derive(Debug, Copy, Clone)]
pub enum Sha256DigestFmt {
    /// Represents the SHA-256 digest as an array of bytes.
    ///
    /// The string-format is as follows: `"[b0, b1, b2, ..., b31]"`,
    /// where `b` is the byte represented as a *decimal* integer.
    BytesArray,

    /// Represents the SHA-256 digest as a dotted hexadecimal string.
    ///
    /// The string-format is as follows: `"x0:x1:x2:...:x31"` where `x`
    /// is the byte represented as a *hexadecimal* integer.
    DottedHex,
}

/// Represents a *SHA-256* digest, which is a fixed-size array of 32 bytes.
#[derive(Debug, Clone, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    /// Creates a new instance from a given array of 32 bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use wtransport::tls::Sha256Digest;
    ///
    /// // Create a new SHA-256 digest instance.
    /// let digest = Sha256Digest::new([97; 32]);
    /// ```
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Attempts to create a new instance from a string representation.
    ///
    /// This method parses the string representation of the digest according to the provided
    /// format (`fmt`) and constructs a new `Sha256Digest` instance if the parsing is successful.
    ///
    /// # Examples
    ///
    /// ```
    /// use wtransport::tls::Sha256Digest;
    /// use wtransport::tls::Sha256DigestFmt;
    ///
    /// const HASH_ARRAY: &str = "[234, 204, 110, 153, 82, 177, 87, 232, 180, 125, \
    ///                           234, 158, 66, 129, 212, 250, 217, 48, 47, 32, 83, \
    ///                           133, 23, 44, 79, 198, 70, 118, 25, 153, 146, 142]";
    ///
    /// let digest_bytes_array = Sha256Digest::from_str_fmt(HASH_ARRAY, Sha256DigestFmt::BytesArray);
    /// assert!(digest_bytes_array.is_ok());
    ///
    /// const HASH_HEX: &str = "e3:4e:c7:de:b8:da:2d:b8:3c:86:a0:11:76:40:75:b3:\
    ///                         b9:ba:9d:00:e0:04:b3:38:72:cd:a1:af:4e:e3:11:26";
    ///
    /// let digest_dotted_hex = Sha256Digest::from_str_fmt(HASH_HEX, Sha256DigestFmt::DottedHex);
    /// assert!(digest_dotted_hex.is_ok());
    ///
    /// let invalid_digest = Sha256Digest::from_str_fmt("invalid_digest", Sha256DigestFmt::BytesArray);
    /// assert!(invalid_digest.is_err());
    /// ```
    pub fn from_str_fmt<S>(s: S, fmt: Sha256DigestFmt) -> Result<Self, InvalidDigest>
    where
        S: AsRef<str>,
    {
        let bytes = match fmt {
            Sha256DigestFmt::BytesArray => s
                .as_ref()
                .trim_start_matches('[')
                .trim_end_matches(']')
                .split(',')
                .map(|byte| byte.trim().parse::<u8>().map_err(|_| InvalidDigest))
                .collect::<Result<Vec<u8>, _>>()?,

            Sha256DigestFmt::DottedHex => s
                .as_ref()
                .split(':')
                .map(|hex| u8::from_str_radix(hex.trim(), 16).map_err(|_| InvalidDigest))
                .collect::<Result<Vec<u8>, _>>()?,
        };

        Ok(Self(bytes.try_into().map_err(|_| InvalidDigest)?))
    }

    /// Formats the digest into a human-readable representation based on the specified format.
    ///
    /// # Examples
    ///
    /// ```
    /// use wtransport::tls::Sha256Digest;
    /// use wtransport::tls::Sha256DigestFmt;
    ///
    /// let digest = Sha256Digest::new([
    ///     97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115,
    ///     116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 64,
    /// ]);
    ///
    /// // Represent the digest as a byte array string.
    /// let bytes_array_fmt = digest.fmt(Sha256DigestFmt::BytesArray);
    /// assert_eq!(
    ///     bytes_array_fmt,
    ///     "[97, 98, 99, 100, 101, 102, 103, 104, 105, 106, \
    ///       107, 108, 109, 110, 111, 112, 113, 114, 115, 116, \
    ///       117, 118, 119, 120, 121, 122, 123, 124, 125, 126, \
    ///       127, 64]"
    /// );
    ///
    /// // Represent the digest as a dotted hexadecimal string.
    /// let dotted_hex_fmt = digest.fmt(Sha256DigestFmt::DottedHex);
    /// assert_eq!(
    ///     dotted_hex_fmt,
    ///     "61:62:63:64:65:66:67:68:69:6a:6b:6c:6d:6e:6f:70:\
    ///      71:72:73:74:75:76:77:78:79:7a:7b:7c:7d:7e:7f:40"
    /// );
    /// ```
    pub fn fmt(&self, fmt: Sha256DigestFmt) -> String {
        match fmt {
            Sha256DigestFmt::BytesArray => {
                format!("{:?}", self.0)
            }
            Sha256DigestFmt::DottedHex => self
                .0
                .iter()
                .map(|byte| format!("{:02x}", byte))
                .collect::<Vec<_>>()
                .join(":"),
        }
    }
}

impl From<[u8; 32]> for Sha256Digest {
    fn from(value: [u8; 32]) -> Self {
        Self::new(value)
    }
}

impl AsRef<[u8; 32]> for Sha256Digest {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Display for Sha256Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.fmt(Sha256DigestFmt::DottedHex), f)
    }
}

/// Represents an error failure to parse a string as a [`Sha256Digest`].
///
/// See [`Sha256Digest::from_str_fmt`].
#[derive(Debug, thiserror::Error)]
#[error("cannot parse string as sha256 digest")]
pub struct InvalidDigest;

pub use rustls;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid() {
        assert!(matches!(
            Certificate::new([b"wtransport".to_vec()], b"wtransport".to_vec()),
            Err(InvalidCertificate(0))
        ));
    }

    #[cfg(feature = "self-signed")]
    #[test]
    fn valid_self() {
        let cert = Certificate::self_signed(["localhost"]);
        Certificate::new(cert.certificates, cert.private_key).unwrap();
    }

    #[test]
    fn idempotence_digest() {
        let digest = Sha256Digest::new([
            97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114,
            115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 64,
        ]);

        let d = Sha256Digest::from_str_fmt(
            digest.fmt(Sha256DigestFmt::BytesArray),
            Sha256DigestFmt::BytesArray,
        )
        .unwrap();

        assert_eq!(d, digest);

        let d = Sha256Digest::from_str_fmt(
            digest.fmt(Sha256DigestFmt::DottedHex),
            Sha256DigestFmt::DottedHex,
        )
        .unwrap();

        assert_eq!(d, digest);
    }
}
