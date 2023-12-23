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

/// Represents a *SHA-256* digest, which is a fixed-size array of 32 bytes.
///
/// See [`Certificate::hashes`].
#[cfg(feature = "self-signed")]
#[cfg_attr(docsrs, doc(cfg(feature = "self-signed")))]
pub struct Sha256Digest([u8; 32]);

#[cfg(feature = "self-signed")]
#[cfg_attr(docsrs, doc(cfg(feature = "self-signed")))]
impl Sha256Digest {
    /// Formats the digest as a string in byte array format.
    ///
    /// The format is as follows: `[b0, b1, b2, ..., b31]`,
    /// where `b` is the byte represented as a decimal integer.
    ///
    /// # Example
    ///
    /// ```
    /// use wtransport::tls::Certificate;
    ///
    /// let certificate = Certificate::self_signed(["localhost"]);
    /// println!("{}", certificate.hashes()[0].fmt_as_byte_array());
    /// // [145, 179, 40, 18, 164, ..., 232, 76, 132, 97, 129]
    /// ```
    pub fn fmt_as_byte_array(&self) -> String {
        format!("{:?}", self.0)
    }

    /// Formats the digest as a string in dotted hex format.
    ///
    /// The format is as follows: `"x0:x1:x2:...:x31"`,
    /// where `x` is the byte represented as a hexadecimal integer.
    ///
    /// # Example
    ///
    /// ```
    /// use wtransport::tls::Certificate;
    ///
    /// let certificate = Certificate::self_signed(["localhost"]);
    /// println!("{}", certificate.hashes()[0].fmt_as_dotted_hex());
    /// // 2e:6e:6f:d2:41:11:...:06:75:0c:7a:af:f6:09
    /// ```
    pub fn fmt_as_dotted_hex(&self) -> String {
        self.0
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect::<Vec<_>>()
            .join(":")
    }
}

#[cfg(feature = "self-signed")]
#[cfg_attr(docsrs, doc(cfg(feature = "self-signed")))]
impl AsRef<[u8]> for Sha256Digest {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(feature = "self-signed")]
#[cfg_attr(docsrs, doc(cfg(feature = "self-signed")))]
impl AsRef<[u8; 32]> for Sha256Digest {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

#[cfg(feature = "self-signed")]
#[cfg_attr(docsrs, doc(cfg(feature = "self-signed")))]
impl Debug for Sha256Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(&self.fmt_as_byte_array(), f)
    }
}

#[cfg(feature = "self-signed")]
#[cfg_attr(docsrs, doc(cfg(feature = "self-signed")))]
impl Display for Sha256Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.fmt_as_dotted_hex(), f)
    }
}

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
}
