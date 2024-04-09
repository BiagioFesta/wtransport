use rustls_pki_types::CertificateDer;
use rustls_pki_types::PrivateKeyDer;
use rustls_pki_types::PrivatePkcs8KeyDer;
use std::fmt::Debug;
use std::fmt::Display;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;

/// Represents an X.509 certificate.
#[derive(Clone)]
pub struct Certificate(CertificateDer<'static>);

impl Certificate {
    /// Constructs a new `Certificate` from DER-encoded binary data.
    pub fn from_der(der: Vec<u8>) -> Result<Self, InvalidCertificate> {
        X509Certificate::from_der(&der).map_err(|error| InvalidCertificate(error.to_string()))?;
        Ok(Self(CertificateDer::from(der)))
    }

    /// Returns a reference to the DER-encoded binary data of the certificate.
    pub fn der(&self) -> &[u8] {
        &self.0
    }

    /// Retrieves the serial number of the certificate as a string.
    pub fn serial(&self) -> String {
        X509Certificate::from_der(&self.0)
            .expect("valid der")
            .1
            .raw_serial_as_string()
    }

    /// Computes certificate's *hash*.
    ///
    /// The hash is the *SHA-256* of the DER encoding of the certificate.
    ///
    /// This function can be used to make a *web* client accept a self-signed
    /// certificate by using the [`WebTransportOptions.serverCertificateHashes`] W3C API.
    ///
    /// [`WebTransportOptions.serverCertificateHashes`]: https://www.w3.org/TR/webtransport/#dom-webtransportoptions-servercertificatehashes
    #[cfg(feature = "self-signed")]
    #[cfg_attr(docsrs, doc(cfg(feature = "self-signed")))]
    pub fn hash(&self) -> Sha256Digest {
        use ring::digest::digest;
        use ring::digest::SHA256;

        Sha256Digest(
            digest(&SHA256, &self.0)
                .as_ref()
                .try_into()
                .expect("SHA256 digest is 32 bytes len"),
        )
    }
}

impl Debug for Certificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Certificate")
            .field("serial", &self.serial())
            .finish()
    }
}

/// Represents a private key.
#[derive(Debug)]
pub struct PrivateKey(PrivateKeyDer<'static>);

impl PrivateKey {
    /// Constructs a new `PrivateKey` from DER-encoded PKCS#8 binary data.
    pub fn from_der_pkcs8(der: Vec<u8>) -> Self {
        PrivateKey(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der)))
    }

    /// Loads the first private key found in a PEM-encoded file.
    ///
    /// Returns a [`PemLoadError::InvalidPrivateKey`] if no private key is found in the file.
    pub async fn load_pemfile(filepath: impl AsRef<Path>) -> Result<Self, PemLoadError> {
        let file_data = tokio::fs::read(filepath.as_ref())
            .await
            .map_err(|io_error| PemLoadError::FileError {
                file: filepath.as_ref().to_path_buf(),
                error: io_error,
            })?;

        let private_key = rustls_pemfile::private_key(&mut &*file_data)
            .map_err(|io_error| PemLoadError::FileError {
                file: filepath.as_ref().to_path_buf(),
                error: io_error,
            })?
            .map(Self);

        private_key.ok_or(PemLoadError::InvalidPrivateKey)
    }

    /// Returns a reference to the DER-encoded binary data of the private key.
    pub fn secret_der(&self) -> &[u8] {
        self.0.secret_der()
    }
}

/// A collection of [`Certificate`].
#[derive(Clone, Debug)]
pub struct CertificateChain(Vec<Certificate>);

impl CertificateChain {
    /// Constructs a new `CertificateChain` from a vector of certificates.
    pub fn new(certificates: Vec<Certificate>) -> Self {
        Self(certificates)
    }

    /// Constructs a new `CertificateChain` with a single certificate.
    pub fn single(certificate: Certificate) -> Self {
        Self::new(vec![certificate])
    }

    /// Loads a certificate chain from a PEM-encoded file.
    pub async fn load_pemfile(filepath: impl AsRef<Path>) -> Result<Self, PemLoadError> {
        let file_data = tokio::fs::read(filepath.as_ref())
            .await
            .map_err(|io_error| PemLoadError::FileError {
                file: filepath.as_ref().to_path_buf(),
                error: io_error,
            })?;

        let certificates = rustls_pemfile::certs(&mut &*file_data)
            .enumerate()
            .map(|(index, maybe_cert)| match maybe_cert {
                Ok(cert) => Certificate::from_der(cert.to_vec())
                    .map_err(|error| PemLoadError::InvalidCertificateChain { index, error }),
                Err(io_error) => Err(PemLoadError::FileError {
                    file: filepath.as_ref().to_path_buf(),
                    error: io_error,
                }),
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self(certificates))
    }

    /// Returns a slice containing references to the certificates in the chain.
    pub fn as_slice(&self) -> &[Certificate] {
        &self.0
    }
}

impl AsRef<[Certificate]> for CertificateChain {
    fn as_ref(&self) -> &[Certificate] {
        self.as_slice()
    }
}

impl FromIterator<Certificate> for CertificateChain {
    fn from_iter<T: IntoIterator<Item = Certificate>>(iter: T) -> Self {
        Self(iter.into_iter().collect())
    }
}

/// Represents an TLS identity consisting of a certificate chain and a private key.
#[derive(Debug)]
pub struct Identity {
    certificate_chain: CertificateChain,
    private_key: PrivateKey,
}

impl Identity {
    /// Constructs a new `Identity` with the given certificate chain and private key.
    pub fn new(certificate_chain: CertificateChain, private_key: PrivateKey) -> Self {
        Self {
            certificate_chain,
            private_key,
        }
    }

    /// Loads an identity from PEM-encoded certificate and private key files.
    pub async fn load_pemfiles(
        cert_pemfile: impl AsRef<Path>,
        private_key_pemfile: impl AsRef<Path>,
    ) -> Result<Self, PemLoadError> {
        let certificate_chain = CertificateChain::load_pemfile(cert_pemfile).await?;
        let private_key = PrivateKey::load_pemfile(private_key_pemfile).await?;

        Ok(Self::new(certificate_chain, private_key))
    }

    /// Generates a self-signed certificate and private key for new identity.
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
    ///                         They can be both hostnames or IP addresses. An error is returned
    ///                         if DNS are not valid ASN.1 strings.
    ///
    /// # Examples
    ///
    /// ```
    /// use wtransport::Identity;
    ///
    /// let identity = Identity::self_signed(&["localhost", "127.0.0.1", "::1"]).unwrap();
    /// ```
    ///
    /// The following example will return an error as *subject alternative name* is an invalid
    /// string.
    /// ```should_panic
    /// use wtransport::Identity;
    ///
    /// Identity::self_signed(&["❤️"]).unwrap();
    /// ```
    #[cfg(feature = "self-signed")]
    #[cfg_attr(docsrs, doc(cfg(feature = "self-signed")))]
    pub fn self_signed<I, S>(subject_alt_names: I) -> Result<Self, InvalidSan>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        use rcgen::CertificateParams;
        use rcgen::KeyPair;
        use rcgen::PKCS_ECDSA_P256_SHA256;
        use time::Duration;
        use time::OffsetDateTime;

        let subject_alt_names = subject_alt_names
            .into_iter()
            .map(|s| s.as_ref().to_string())
            .collect::<Vec<_>>();

        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .expect("algorithm for key pair is supported");

        let mut cert_params = CertificateParams::new(subject_alt_names).map_err(|_| InvalidSan)?;
        cert_params.not_before = OffsetDateTime::now_utc();
        cert_params.not_after = OffsetDateTime::now_utc()
            .checked_add(Duration::days(14))
            .expect("addition does not overflow");

        let cert = cert_params
            .self_signed(&key_pair)
            .expect("inner params are valid");

        Ok(Self::new(
            CertificateChain::single(Certificate(cert.der().clone())),
            PrivateKey::from_der_pkcs8(key_pair.serialize_der()),
        ))
    }

    /// Returns a reference to the certificate chain associated with the identity.
    pub fn certificate_chain(&self) -> &[Certificate] {
        self.certificate_chain.as_slice()
    }

    /// Returns a reference to the private key associated with the identity.
    pub fn private_key(&self) -> &PrivateKey {
        &self.private_key
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
///
/// For example, you can obtain the certificate digest with [`Certificate::hash`].
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

/// Represents data related to a TLS handshake process.
#[derive(Clone, Debug)]
pub struct HandshakeData {
    pub(crate) alpn: Option<Vec<u8>>,
    pub(crate) server_name: Option<String>,
}

impl HandshakeData {
    /// Application-Layer Protocol Negotiation (ALPN) data.
    pub fn alpn(&self) -> Option<&[u8]> {
        self.alpn.as_deref()
    }

    /// The server name associated with the handshake data.
    pub fn server_name(&self) -> Option<&str> {
        self.server_name.as_deref()
    }
}

impl FromStr for Sha256Digest {
    type Err = InvalidDigest;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Sha256Digest::from_str_fmt(s, Sha256DigestFmt::BytesArray)
            .or_else(|_| Sha256Digest::from_str_fmt(s, Sha256DigestFmt::DottedHex))
    }
}

/// Represents an error indicating an invalid certificate parsing.
#[derive(Debug, thiserror::Error)]
#[error("invalid certificate: {0}")]
pub struct InvalidCertificate(String);

/// Represents an error failure to parse a string as a [`Sha256Digest`].
///
/// See [`Sha256Digest::from_str_fmt`].
#[derive(Debug, thiserror::Error)]
#[error("cannot parse string as sha256 digest")]
pub struct InvalidDigest;

/// Error during PEM load operation.
#[derive(Debug, thiserror::Error)]
pub enum PemLoadError {
    /// Invalid certificate during chain load.
    #[error("invalid certificate in the PEM chain (index: {}): {}", .index, .error)]
    InvalidCertificateChain {
        /// The index of the certificate in the PEM file.
        index: usize,
        /// Additional error information.
        error: InvalidCertificate,
    },

    /// No valid private key found in the PEM file.
    #[error("no valid private key found in the PEM file")]
    InvalidPrivateKey,

    /// Load operation failed because I/O operation on file.
    #[error("error on file '{}': {}", .file.display(), error)]
    FileError {
        /// Filename of the operation.
        file: PathBuf,

        /// io error details.
        error: std::io::Error,
    },
}

/// Certificate SANs are not valid DNS.
///
/// This error might happen during self signed certificate generation
/// [`Identity::self_signed`].
/// In particular, *Subject Alternative Names* passed for the generation of the
/// certificate are not valid DNS *IA5* strings.
///
/// DNS strings support the [International Alphabet No. 5 (IA5)] character encoding, i.e.
/// the 128 characters of the ASCII alphabet.
///
/// [International Alphabet No. 5 (IA5)]: https://en.wikipedia.org/wiki/T.50_(standard)
#[cfg(feature = "self-signed")]
#[cfg_attr(docsrs, doc(cfg(feature = "self-signed")))]
#[derive(Debug, thiserror::Error)]
#[error("invalid SANs for the self certificate")]
pub struct InvalidSan;

pub use rustls;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_certificate() {
        assert!(matches!(
            Certificate::from_der(b"invalid-certificate".to_vec()),
            Err(InvalidCertificate(_))
        ));
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

    #[test]
    fn digest_from_str() {
        assert!(matches!(
            "invalid".parse::<Sha256Digest>(),
            Err(InvalidDigest)
        ));

        assert!(matches!(
        "[97, 98, 99, 100, 101, 102, 103, 104, 105, 106, \
         107, 108, 109, 110, 111, 112, 113, 114, 115, 116, \
         117, 118, 119, 120, 121, 122, 123, 124, 125, 126, \
         127, 64]"
            .parse::<Sha256Digest>(),

        Ok(digest) if digest == Sha256Digest::new([
            97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113,
            114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 64
        ])));

        assert!(matches!(
            "61:62:63:64:65:66:67:68:69:6a:6b:6c:6d:6e:6f:70: \
          71:72:73:74:75:76:77:78:79:7a:7b:7c:7d:7e:7f:40"
                .parse::<Sha256Digest>(),

        Ok(digest) if digest == Sha256Digest::new([
            97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113,
            114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 64
        ])));
    }
}
