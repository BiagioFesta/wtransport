use error::InvalidCertificate;
use error::InvalidDigest;
use error::PemLoadError;
use pem::encode as pem_encode;
use pem::Pem;
use rustls::RootCertStore;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::PrivateKeyDer;
use rustls_pki_types::PrivatePkcs8KeyDer;
use sha2::Digest;
use sha2::Sha256;
use std::fmt::Debug;
use std::fmt::Display;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;

pub use wtransport_proto::WEBTRANSPORT_ALPN;

/// Represents an X.509 certificate.
#[derive(Clone)]
pub struct Certificate(CertificateDer<'static>);

impl Certificate {
    pub(crate) fn from_rustls_pki(cert: rustls_pki_types::CertificateDer<'static>) -> Self {
        Self(cert)
    }

    /// Constructs a new `Certificate` from DER-encoded binary data.
    pub fn from_der(der: Vec<u8>) -> Result<Self, InvalidCertificate> {
        X509Certificate::from_der(&der).map_err(|error| InvalidCertificate(error.to_string()))?;
        Ok(Self(CertificateDer::from(der)))
    }

    /// Loads the *first* certificate found in a PEM-encoded file.
    ///
    /// Filters out any PEM sections that are not certificate.
    ///
    /// Returns a [`PemLoadError::NoCertificateSection`] if no certificate is found in the file.
    pub async fn load_pemfile(filepath: impl AsRef<Path>) -> Result<Self, PemLoadError> {
        let file_data = tokio::fs::read(filepath.as_ref())
            .await
            .map_err(|io_error| PemLoadError::FileError {
                file: filepath.as_ref().to_path_buf(),
                error: io_error,
            })?;

        let cert = rustls_pemfile::certs(&mut &*file_data)
            .next()
            .ok_or(PemLoadError::NoCertificateSection)?
            .map_err(|io_error| PemLoadError::FileError {
                file: filepath.as_ref().to_path_buf(),
                error: io_error,
            })?;

        Ok(Self(cert))
    }

    /// Stores the certificate in PEM format into a file asynchronously.
    ///
    /// If the file does not exist, it will be created. If the file exists, its contents
    /// will be truncated before writing.
    pub async fn store_pemfile(&self, filepath: impl AsRef<Path>) -> std::io::Result<()> {
        use tokio::io::AsyncWriteExt;

        let mut file = tokio::fs::File::create(filepath).await?;
        file.write_all(self.to_pem().as_bytes()).await?;

        Ok(())
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

    /// Converts the X.509 certificate to the PEM (Privacy-Enhanced Mail) format.
    ///
    /// # Returns
    /// A `String` containing the PEM-encoded representation of the certificate.
    pub fn to_pem(&self) -> String {
        pem_encode(&Pem::new("CERTIFICATE", self.der()))
    }

    /// Computes certificate's *hash*.
    ///
    /// The hash is the *SHA-256* of the DER encoding of the certificate.
    ///
    /// This function can be used to make a *web* client accept a self-signed
    /// certificate by using the [`WebTransportOptions.serverCertificateHashes`] W3C API.
    ///
    /// [`WebTransportOptions.serverCertificateHashes`]: https://www.w3.org/TR/webtransport/#dom-webtransportoptions-servercertificatehashes
    pub fn hash(&self) -> Sha256Digest {
        // TODO(biagio): you might consider use crypto provider from new rustls version
        Sha256Digest(Sha256::digest(self.der()).into())
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

    /// Loads the *first* private key found in a PEM-encoded file.
    ///
    /// Filters out any PEM sections that are not private key.
    ///
    /// Returns a [`PemLoadError::NoPrivateKeySection`] if no private key is found in the file.
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

        private_key.ok_or(PemLoadError::NoPrivateKeySection)
    }

    /// Stores the private key in PEM format into a file asynchronously.
    ///
    /// If the file does not exist, it will be created. If the file exists,
    /// its contents will be truncated before writing.
    pub async fn store_secret_pemfile(&self, filepath: impl AsRef<Path>) -> std::io::Result<()> {
        tokio::fs::write(filepath, self.to_secret_pem()).await
    }

    /// Returns a reference to the DER-encoded binary data of the private key.
    pub fn secret_der(&self) -> &[u8] {
        self.0.secret_der()
    }

    /// Converts the private key to PEM format.
    pub fn to_secret_pem(&self) -> String {
        pem_encode(&Pem::new("PRIVATE KEY", self.secret_der()))
    }

    /// Clones this private key.
    ///
    /// # Note
    /// `PrivateKey` does not implement `Clone` directly to ensure that sensitive information
    /// is not cloned inadvertently.
    /// Implementing `Clone` directly could potentially lead to unintended cloning of sensitive data.
    pub fn clone_key(&self) -> Self {
        Self(self.0.clone_key())
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
    ///
    /// Filters out any PEM sections that are not certificates and yields error
    /// if a problem occurs while trying to parse any certificate.
    ///
    /// *Note*: if the PEM file does not contain any certificate section this
    /// will return an empty chain.
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

    /// Stores the certificate chain in PEM format into a file asynchronously.
    ///
    /// If the file does not exist, it will be created. If the file exists, its contents
    /// will be truncated before writing.
    pub async fn store_pemfile(&self, filepath: impl AsRef<Path>) -> std::io::Result<()> {
        use tokio::io::AsyncWriteExt;

        let mut file = tokio::fs::File::create(filepath).await?;

        for cert in self.0.iter() {
            file.write_all(cert.to_pem().as_bytes()).await?;
        }

        Ok(())
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
    ///
    /// # Features
    ///
    /// This function is only available when the `self-signed` feature is enabled.
    #[cfg(feature = "self-signed")]
    #[cfg_attr(docsrs, doc(cfg(feature = "self-signed")))]
    pub fn self_signed<I, S>(subject_alt_names: I) -> Result<Self, error::InvalidSan>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self_signed::SelfSignedIdentityBuilder::new()
            .subject_alt_names(subject_alt_names)
            .from_now_utc()
            .validity_days(14)
            .build()
    }

    /// Creates a new [`SelfSignedIdentityBuilder`][1] instance.
    ///
    /// This function provides a convenient way to create a self-signed identity
    /// builder, and thus generate a custom self-signed identity.
    ///
    /// # Example
    ///
    /// ```
    /// use wtransport::Identity;
    ///
    /// let identity = Identity::self_signed_builder()
    ///     .subject_alt_names(&["localhost", "127.0.0.1", "::1"])
    ///     .from_now_utc()
    ///     .validity_days(14)
    ///     .build()
    ///     .unwrap();
    /// ```
    ///
    /// # Features
    ///
    /// This function is only available when the `self-signed` feature is enabled.
    ///
    /// [1]: self_signed::SelfSignedIdentityBuilder
    #[cfg(feature = "self-signed")]
    #[cfg_attr(docsrs, doc(cfg(feature = "self-signed")))]
    pub fn self_signed_builder(
    ) -> self_signed::SelfSignedIdentityBuilder<self_signed::states::WantsSans> {
        self_signed::SelfSignedIdentityBuilder::new()
    }

    /// Returns a reference to the certificate chain associated with the identity.
    pub fn certificate_chain(&self) -> &CertificateChain {
        &self.certificate_chain
    }

    /// Returns a reference to the private key associated with the identity.
    pub fn private_key(&self) -> &PrivateKey {
        &self.private_key
    }

    /// Clones this identity.
    ///
    /// # Note
    /// `Identity` does not implement `Clone` directly to ensure that sensitive information,
    /// specifically the inner *private key*, is not cloned inadvertently.
    /// Implementing `Clone` directly could potentially lead to unintended cloning of sensitive data.
    pub fn clone_identity(&self) -> Self {
        Self::new(self.certificate_chain.clone(), self.private_key.clone_key())
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

/// Builds [`rustls::RootCertStore`] by using platform’s native certificate store.
///
/// This function works on a *best-effort* basis, attempting to load every possible
/// root certificate found on the platform. It skips anchors that produce errors during loading.
/// Therefore, it might produce an *empty* root store.
///
///
/// It's important to note that this function can be expensive, as it might involve loading
/// all root certificates from the filesystem platform. Therefore, it's advisable to use it
/// sporadically and judiciously.
pub fn build_native_cert_store() -> RootCertStore {
    let _vars_restore_guard = utils::remove_vars_tmp(["SSL_CERT_FILE", "SSL_CERT_DIR"]);

    let mut root_store = RootCertStore::empty();

    let rustls_native_certs::CertificateResult { certs, .. } =
        rustls_native_certs::load_native_certs();

    for c in certs {
        let _ = root_store.add(c);
    }

    root_store
}

fn default_crypto_provider() -> rustls::crypto::CryptoProvider {
    #[cfg(feature = "ring")]
    {
        rustls::crypto::ring::default_provider()
    }

    #[cfg(not(feature = "ring"))]
    {
        rustls::crypto::aws_lc_rs::default_provider()
    }
}

/// TLS configurations and utilities server-side.
pub mod server {
    use super::*;
    use rustls::ServerConfig as TlsServerConfig;

    /// Builds a default TLS server configuration with safe defaults.
    ///
    /// This function constructs a TLS server configuration with safe defaults.
    /// The configuration utilizes the identity (certificate and private key) specified
    /// in the input argument of the function.
    ///
    /// Client authentication is not required in this configuration.
    ///
    /// # Arguments
    ///
    /// - `identity`: A reference to the identity containing the certificate chain and private key.
    pub fn build_default_tls_config(identity: Identity) -> TlsServerConfig {
        let provider = Arc::new(default_crypto_provider());

        let certificates = identity
            .certificate_chain
            .0
            .into_iter()
            .map(|cert| cert.0)
            .collect();

        let private_key = identity.private_key.0;

        let mut tls_config = TlsServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("valid version")
            .with_no_client_auth()
            .with_single_cert(certificates, private_key)
            .expect("Certificate and private key should be already validated");

        tls_config.alpn_protocols = [WEBTRANSPORT_ALPN.to_vec()].to_vec();

        tls_config
    }
}

/// TLS configurations and utilities client-side.
pub mod client {
    use super::*;
    use rustls::client::danger::ServerCertVerified;
    use rustls::client::danger::ServerCertVerifier;
    use rustls::crypto::WebPkiSupportedAlgorithms;
    use rustls::ClientConfig as TlsClientConfig;

    /// Builds a default TLS client configuration with safe defaults.
    ///
    /// This function constructs a TLS client configuration with safe defaults.
    /// It utilizes the provided `RootCertStore` to validate server certificates during the TLS handshake.
    ///
    /// If a custom [`ServerCertVerifier`] is provided, it will be used for certificate validation; otherwise,
    /// it will use the standard safe default mechanism (using the Web PKI mechanism).
    ///
    /// Client authentication is not required in this configuration.
    ///
    /// # Arguments
    ///
    /// - `root_store`: An `Arc` containing the [`RootCertStore`] with trusted root certificates.
    ///                 To obtain a `RootCertStore`, one can use the [`build_native_cert_store`]
    ///                 function, which loads the platform's certificate authorities (CAs).
    /// - `custom_verifier`: An optional `Arc` containing a custom implementation of the [`ServerCertVerifier`]
    ///                      trait for custom certificate verification. If `None` is provided, the default
    ///                      Web PKI mechanism will be used.
    ///
    /// # Note
    ///
    /// If a custom `ServerCertVerifier` is provided, exercise caution as it could potentially compromise the
    /// certificate validation process if not implemented correctly.
    pub fn build_default_tls_config(
        root_store: Arc<RootCertStore>,
        custom_verifier: Option<Arc<dyn ServerCertVerifier>>,
    ) -> TlsClientConfig {
        let provider = Arc::new(default_crypto_provider());

        let mut config = TlsClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("valid version")
            .with_root_certificates(root_store)
            .with_no_client_auth();

        if let Some(custom_verifier) = custom_verifier {
            config.dangerous().set_certificate_verifier(custom_verifier);
        }

        config.alpn_protocols = [WEBTRANSPORT_ALPN.to_vec()].to_vec();
        config
    }

    /// A custom **insecure** [`ServerCertVerifier`] implementation.
    ///
    /// This verifier is configured to skip all server's certificate validation.
    ///
    /// Therefore, it's advisable to use it judiciously, and avoid using it in
    /// production environments.
    #[derive(Debug)]
    pub struct NoServerVerification {
        supported_algorithms: WebPkiSupportedAlgorithms,
    }

    impl Default for NoServerVerification {
        fn default() -> Self {
            Self::new()
        }
    }

    impl NoServerVerification {
        /// Creates a new instance of `NoServerVerification`.
        pub fn new() -> NoServerVerification {
            NoServerVerification {
                supported_algorithms: default_crypto_provider().signature_verification_algorithms,
            }
        }
    }

    impl ServerCertVerifier for NoServerVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls_pki_types::CertificateDer,
            _intermediates: &[rustls_pki_types::CertificateDer],
            _server_name: &rustls_pki_types::ServerName,
            _ocsp_response: &[u8],
            _now: rustls_pki_types::UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported_algorithms)
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported_algorithms)
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.supported_algorithms.supported_schemes()
        }
    }

    /// A custom [`ServerCertVerifier`] implementation.
    ///
    /// Configures the client to skip *some* server certificates validation.
    ///
    /// This verifier is configured to accept server certificates
    /// whose digests match the specified *SHA-256* hashes and fulfill
    /// some additional constraints (*see notes below*).
    ///
    /// This is useful for scenarios where clients need to accept known
    /// self-signed certificates or certificates from non-standard authorities.
    ///
    /// # Notes
    ///
    /// - The current time MUST be within the validity period of the certificate.
    /// - The total length of the validity period MUST NOT exceed *two* weeks.
    /// - Only certificates for which the public key algorithm is *ECDSA* with the *secp256r1* are accepted.
    #[derive(Debug)]
    pub struct ServerHashVerification {
        hashes: std::collections::BTreeSet<Sha256Digest>,
        supported_algorithms: WebPkiSupportedAlgorithms,
    }

    impl ServerHashVerification {
        const SELF_MAX_VALIDITY: time::Duration = time::Duration::days(14);

        /// Creates a new instance of `ServerHashVerification`.
        ///
        /// # Arguments
        ///
        /// - `hashes`: An iterator yielding `Sha256Digest` instances representing the
        ///             accepted certificate hashes.
        pub fn new<H>(hashes: H) -> Self
        where
            H: IntoIterator<Item = Sha256Digest>,
        {
            use std::collections::BTreeSet;

            Self {
                hashes: BTreeSet::from_iter(hashes),
                supported_algorithms: default_crypto_provider().signature_verification_algorithms,
            }
        }

        /// Adds a `digest` to the list of accepted certificates.
        pub fn add(&mut self, digest: Sha256Digest) {
            self.hashes.insert(digest);
        }
    }

    impl FromIterator<Sha256Digest> for ServerHashVerification {
        fn from_iter<T: IntoIterator<Item = Sha256Digest>>(iter: T) -> Self {
            Self::new(iter)
        }
    }

    impl ServerCertVerifier for ServerHashVerification {
        fn verify_server_cert(
            &self,
            end_entity: &rustls_pki_types::CertificateDer,
            _intermediates: &[rustls_pki_types::CertificateDer],
            _server_name: &rustls_pki_types::ServerName,
            _ocsp_response: &[u8],
            now: rustls_pki_types::UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            use time::OffsetDateTime;
            use x509_parser::oid_registry::OID_EC_P256;
            use x509_parser::oid_registry::OID_KEY_TYPE_EC_PUBLIC_KEY;
            use x509_parser::time::ASN1Time;

            let now = ASN1Time::new(
                now.as_secs()
                    .try_into()
                    .ok()
                    .and_then(|time| OffsetDateTime::from_unix_timestamp(time).ok())
                    .expect("time overflow"),
            );

            let x509 = X509Certificate::from_der(end_entity.as_ref())
                .map_err(|_| rustls::CertificateError::BadEncoding)?
                .1;

            match x509.validity() {
                x if now < x.not_before => {
                    return Err(rustls::CertificateError::NotValidYet.into());
                }
                x if now > x.not_after => {
                    return Err(rustls::CertificateError::Expired.into());
                }
                _ => {}
            }

            let validity_period = x509.validity().not_after - x509.validity.not_before;
            if !matches!(validity_period, Some(x) if x <= Self::SELF_MAX_VALIDITY) {
                return Err(rustls::CertificateError::UnknownIssuer.into());
            }

            if x509.public_key().algorithm.algorithm != OID_KEY_TYPE_EC_PUBLIC_KEY {
                return Err(rustls::CertificateError::UnknownIssuer.into());
            }

            if !matches!(x509.public_key().algorithm.parameters.as_ref().map(|any| any.as_oid()),
                         Some(Ok(oid)) if oid == OID_EC_P256)
            {
                return Err(rustls::CertificateError::UnknownIssuer.into());
            }

            // TODO: Duplicates logic in `Certificate::from_der`, to avoid allocating
            X509Certificate::from_der(end_entity.as_ref())
                .map_err(|_| rustls::CertificateError::BadEncoding)?;
            // TODO: Duplicates logic in `Certificate::hash`, to avoid allocating
            let end_entity_hash = Sha256Digest(Sha256::digest(end_entity.as_ref()).into());

            if self.hashes.contains(&end_entity_hash) {
                Ok(ServerCertVerified::assertion())
            } else {
                Err(rustls::CertificateError::UnknownIssuer.into())
            }
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported_algorithms)
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported_algorithms)
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.supported_algorithms.supported_schemes()
        }
    }
}

/// TLS errors definitions module.
pub mod error {
    use std::path::PathBuf;

    /// Represents an error indicating an invalid certificate parsing.
    #[derive(Debug, thiserror::Error)]
    #[error("invalid certificate: {0}")]
    pub struct InvalidCertificate(pub(super) String);

    /// Represents an error failure to parse a string as a [`Sha256Digest`](super::Sha256Digest).
    ///
    /// See [`Sha256Digest::from_str_fmt`](super::Sha256Digest::from_str_fmt).
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

        /// Cannot load the private key as the PEM file does not contain it.
        #[error("no private key section found in PEM file")]
        NoPrivateKeySection,

        /// Cannot load the certificate as the PEM file does not contain it.
        #[error("no certificate section found in PEM file")]
        NoCertificateSection,

        /// I/O operation encoding/decoding PEM file failed.
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
    /// [`Identity::self_signed`](super::Identity::self_signed).
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
}

/// Module for generating self-signed [`Identity`].
///
/// This module provides a builder pattern for constructing self-signed
/// identities. These certificates are primarily used for local testing or
/// development where a full certificate authority (CA) infrastructure isn't
/// necessary.
///
/// The feature is enabled when the `self-signed` feature flag is active.
#[cfg(feature = "self-signed")]
#[cfg_attr(docsrs, doc(cfg(feature = "self-signed")))]
pub mod self_signed {
    use super::*;
    use error::InvalidSan;
    use rcgen::CertificateParams;
    use rcgen::DistinguishedName;
    use rcgen::DnType;
    use rcgen::KeyPair;
    use rcgen::PKCS_ECDSA_P256_SHA256;
    use time::OffsetDateTime;

    /// The builder for creating self-signed [`Identity`].
    ///
    /// This struct uses state-based typing to enforce that the appropriate methods
    /// are called in the right order.
    pub struct SelfSignedIdentityBuilder<State>(State);

    impl SelfSignedIdentityBuilder<states::WantsSans> {
        /// Creates a new `SelfSignedIdentityBuilder` instance.
        ///
        /// The builder starts in the `WantsSans` state, meaning it requires subject
        /// alternative names (SANs) to be specified before continuing.
        ///
        /// # Example
        ///
        /// ```
        /// use wtransport::tls::self_signed::SelfSignedIdentityBuilder;
        ///
        /// let builder = SelfSignedIdentityBuilder::new();
        /// ```
        ///
        /// **Note**: You can conveniently create a new builder with [`Identity::self_signed_builder()`].
        ///
        /// # Example
        ///
        /// ```
        /// use wtransport::Identity;
        ///
        /// let builder = Identity::self_signed_builder();
        /// ```
        pub fn new() -> Self {
            Self(states::WantsSans {})
        }

        /// Specifies the subject alternative names (SANs) for the certificate.
        ///
        /// The SANs can be provided as a collection of strings, such as hostnames or IP addresses.
        ///
        /// # Arguments
        ///
        /// * `subject_alt_names` - An iterator of strings representing subject alternative names (SANs).
        ///                         They can be both hostnames or IP addresses.
        ///
        /// # Example
        ///
        /// ```
        /// use wtransport::tls::self_signed::SelfSignedIdentityBuilder;
        ///
        /// let builder =
        ///     SelfSignedIdentityBuilder::new().subject_alt_names(&["localhost", "127.0.0.1", "::1"]);
        /// ```
        pub fn subject_alt_names<I, S>(
            self,
            subject_alt_names: I,
        ) -> SelfSignedIdentityBuilder<states::WantsValidityPeriod>
        where
            I: IntoIterator<Item = S>,
            S: AsRef<str>,
        {
            let sans = subject_alt_names
                .into_iter()
                .map(|s| s.as_ref().to_string())
                .collect();

            SelfSignedIdentityBuilder(states::WantsValidityPeriod { sans })
        }
    }

    impl SelfSignedIdentityBuilder<states::WantsValidityPeriod> {
        /// Sets the certificate's `not_before` time to the current UTC time.
        ///
        /// After this, the builder is in the `WantsNotAfter` state, requiring a `not_after` time to be set.
        pub fn from_now_utc(self) -> SelfSignedIdentityBuilder<states::WantsNotAfter> {
            let not_before = OffsetDateTime::now_utc();
            self.not_before(not_before)
        }

        /// Sets the `not_before` time of the certificate.
        ///
        /// # Parameters
        ///
        /// - `not_before`: The starting time of the certificate's validity period.
        ///
        /// After this, the builder is in the `WantsNotAfter` state, requiring a `not_after` time to be set.
        pub fn not_before(
            self,
            not_before: OffsetDateTime,
        ) -> SelfSignedIdentityBuilder<states::WantsNotAfter> {
            SelfSignedIdentityBuilder(states::WantsNotAfter {
                sans: self.0.sans,
                not_before,
            })
        }

        /// Specifies the validity period for the certificate.
        ///
        /// # Parameters
        ///
        /// - `not_before`: The starting time of the certificate's validity period.
        /// - `not_after`: The ending time of the certificate's validity period.
        ///
        /// # Example
        ///
        /// ```
        /// use wtransport::tls::self_signed::time::OffsetDateTime;
        /// use wtransport::tls::self_signed::SelfSignedIdentityBuilder;
        ///
        /// let builder = SelfSignedIdentityBuilder::new()
        ///     .subject_alt_names(&["localhost"])
        ///     .validity_period(
        ///         OffsetDateTime::now_utc(),
        ///         OffsetDateTime::now_utc() + time::Duration::days(7),
        ///     );
        /// ```
        pub fn validity_period(
            self,
            not_before: OffsetDateTime,
            not_after: OffsetDateTime,
        ) -> SelfSignedIdentityBuilder<states::ReadyToBuild> {
            self.not_before(not_before).not_after(not_after)
        }
    }

    impl SelfSignedIdentityBuilder<states::WantsNotAfter> {
        /// Specifies the `not_after` time of the certificate.
        ///
        /// # Parameters
        ///
        /// - `not_after`: The ending time of the certificate's validity.
        pub fn not_after(
            self,
            not_after: OffsetDateTime,
        ) -> SelfSignedIdentityBuilder<states::ReadyToBuild> {
            SelfSignedIdentityBuilder(states::ReadyToBuild {
                sans: self.0.sans,
                not_before: self.0.not_before,
                not_after,
            })
        }

        /// Sets the `not_after` time of the certificate to an offset from the `not_before` time.
        ///
        /// # Parameters
        ///
        /// - `offset`: A time duration that specifies how far `not_after` should be from `not_before`.
        ///
        /// # Example
        ///
        /// ```
        /// use wtransport::tls::self_signed::time::OffsetDateTime;
        /// use wtransport::tls::self_signed::SelfSignedIdentityBuilder;
        ///
        /// let builder = SelfSignedIdentityBuilder::new()
        ///     .subject_alt_names(&["localhost"])
        ///     .not_before(OffsetDateTime::now_utc())
        ///     .offset_from_not_before(time::Duration::days(7)); // now + 7 days
        /// ```
        pub fn offset_from_not_before(
            self,
            offset: time::Duration,
        ) -> SelfSignedIdentityBuilder<states::ReadyToBuild> {
            let not_after = self.0.not_before + offset;
            self.not_after(not_after)
        }

        /// Sets the certificate's validity to a specified number of days from `not_before`.
        ///
        /// # Parameters
        ///
        /// - `days`: The number of days for which the certificate should be valid.
        ///
        /// # Example
        ///
        /// ```
        /// use wtransport::tls::self_signed::SelfSignedIdentityBuilder;
        ///
        /// let builder = SelfSignedIdentityBuilder::new()
        ///     .subject_alt_names(&["localhost"])
        ///     .from_now_utc()
        ///     .validity_days(14);
        /// ```
        pub fn validity_days(self, days: u32) -> SelfSignedIdentityBuilder<states::ReadyToBuild> {
            self.offset_from_not_before(time::Duration::days(days as i64))
        }
    }

    impl SelfSignedIdentityBuilder<states::ReadyToBuild> {
        /// Generates a self-signed certificate and private key for new identity.
        ///
        /// # Returns
        ///
        /// Returns an [`Identity`] containing the certificate and private key,
        /// or an error if the SANs are invalid (they are not valid *ASN.1* strings).
        ///
        /// # Specifications
        ///
        /// The certificate will be conforms to the following specifications:
        ///
        /// - The certificate is an *X.509v3* certificate as defined in *RFC5280*.
        /// - The key used in the Subject Public Key field uses `ECDSA P-256` algorithm.
        ///
        /// # Example
        ///
        /// ```
        /// use wtransport::tls::self_signed::SelfSignedIdentityBuilder;
        ///
        /// let identity = SelfSignedIdentityBuilder::new()
        ///     .subject_alt_names(&["localhost", "127.0.0.1"])
        ///     .from_now_utc()
        ///     .validity_days(7)
        ///     .build()
        ///     .unwrap();
        /// ```
        pub fn build(self) -> Result<Identity, error::InvalidSan> {
            let mut dname = DistinguishedName::new();
            dname.push(DnType::CommonName, "wtransport self-signed");

            let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
                .expect("algorithm for key pair is supported");

            let mut cert_params = CertificateParams::new(self.0.sans).map_err(|_| InvalidSan)?;
            cert_params.distinguished_name = dname;
            cert_params.not_before = self.0.not_before;
            cert_params.not_after = self.0.not_after;
            let cert = cert_params
                .self_signed(&key_pair)
                .expect("inner params are valid");

            Ok(Identity::new(
                CertificateChain::single(Certificate(cert.der().clone())),
                PrivateKey::from_der_pkcs8(key_pair.serialize_der()),
            ))
        }
    }

    impl Default for SelfSignedIdentityBuilder<states::WantsSans> {
        fn default() -> Self {
            Self::new()
        }
    }

    /// State-types for [`SelfSignedIdentityBuilder`] builder.
    pub mod states {
        use super::*;

        /// Initial state, requiring subject alternative names (SANs).
        pub struct WantsSans {}

        /// State after SANs have been set, requiring a validity period.
        pub struct WantsValidityPeriod {
            pub(super) sans: Vec<String>,
        }

        /// State after `not_before` is set, requiring `not_after` to be specified.
        pub struct WantsNotAfter {
            pub(super) sans: Vec<String>,
            pub(super) not_before: OffsetDateTime,
        }

        /// Final state where all data is ready and the certificate can be built.
        pub struct ReadyToBuild {
            pub(super) sans: Vec<String>,
            pub(super) not_before: OffsetDateTime,
            pub(super) not_after: OffsetDateTime,
        }
    }

    pub use time;
}

pub use rustls;

mod utils {
    use std::env;
    use std::ffi::OsStr;
    use std::ffi::OsString;

    pub struct VarsRestoreGuard(Vec<(OsString, Option<OsString>)>);

    impl Drop for VarsRestoreGuard {
        fn drop(&mut self) {
            for (k, v) in std::mem::take(&mut self.0) {
                if let Some(v) = v {
                    env::set_var(k, v);
                }
            }
        }
    }

    pub fn remove_vars_tmp<I, K>(keys: I) -> VarsRestoreGuard
    where
        I: IntoIterator<Item = K>,
        K: AsRef<OsStr>,
    {
        let table = keys
            .into_iter()
            .map(|k| {
                let k = k.as_ref().to_os_string();
                let v = env::var_os(&k);
                env::remove_var(&k);
                (k, v)
            })
            .collect();

        VarsRestoreGuard(table)
    }
}

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
