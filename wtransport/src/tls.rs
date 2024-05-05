use error::InvalidCertificate;
use error::InvalidDigest;
use error::PemLoadError;
use pem::encode as pem_encode;
use pem::Pem;
use rustls::RootCertStore;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::PrivateKeyDer;
use rustls_pki_types::PrivatePkcs8KeyDer;
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
    /// Filters out any PEM sections that are not private key.
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
    #[cfg(feature = "self-signed")]
    #[cfg_attr(docsrs, doc(cfg(feature = "self-signed")))]
    pub fn self_signed<I, S>(subject_alt_names: I) -> Result<Self, error::InvalidSan>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        use error::InvalidSan;
        use rcgen::CertificateParams;
        use rcgen::DistinguishedName;
        use rcgen::DnType;
        use rcgen::KeyPair;
        use rcgen::PKCS_ECDSA_P256_SHA256;
        use time::Duration;
        use time::OffsetDateTime;

        let subject_alt_names = subject_alt_names
            .into_iter()
            .map(|s| s.as_ref().to_string())
            .collect::<Vec<_>>();

        let mut dname = DistinguishedName::new();
        dname.push(DnType::CommonName, "wtransport self-signed");

        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .expect("algorithm for key pair is supported");

        let mut cert_params = CertificateParams::new(subject_alt_names).map_err(|_| InvalidSan)?;
        cert_params.distinguished_name = dname;
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
    let mut root_store = RootCertStore::empty();

    let _var_restore_guard = utils::remove_var_tmp("SSL_CERT_FILE");

    match rustls_native_certs::load_native_certs() {
        Ok(certs) => {
            for c in certs {
                let _ = root_store.add(&rustls::Certificate(c.0));
            }
        }
        Err(_error) => {}
    }

    root_store
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
    pub fn build_default_tls_config(identity: &Identity) -> TlsServerConfig {
        let certificates = identity
            .certificate_chain()
            .as_slice()
            .iter()
            .map(|cert| rustls::Certificate(cert.der().to_vec()))
            .collect();

        let private_key = rustls::PrivateKey(identity.private_key().secret_der().to_vec());

        let mut tls_config = TlsServerConfig::builder()
            .with_safe_defaults()
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
    use rustls::client::ServerCertVerified;
    use rustls::client::ServerCertVerifier;
    use rustls::ClientConfig as TlsClientConfig;

    /// Builds a default TLS client configuration with safe defaults.
    ///
    /// This function constructs a TLS client configuration with safe defaults.
    /// It utilizes the provided `RootCertStore` to validate server certificates during the TLS handshake.
    ///
    /// Client authentication is not required in this configuration.
    ///
    /// # Arguments
    ///
    /// - `root_store`: An `Arc` containing the [`RootCertStore`] with trusted root certificates.
    ///                 To obtain a `RootCertStore`, one can use the [`build_native_cert_store`]
    ///                 function, which loads the platform's certificate authorities (CAs).
    pub fn build_default_tls_config(root_store: Arc<RootCertStore>) -> TlsClientConfig {
        let mut config = TlsClientConfig::builder()
            .with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
            .with_safe_default_protocol_versions()
            .expect("Safe protocols should not error")
            .with_root_certificates(root_store)
            .with_no_client_auth();

        config.alpn_protocols = [WEBTRANSPORT_ALPN.to_vec()].to_vec();
        config
    }

    /// A custom **unsafe** [`ServerCertVerifier`] implementation.
    ///
    /// This verifier is configured to skip all server's certificate validation.
    ///
    /// Therefore, it's advisable to use it judiciously, and avoid using it in
    /// production environments.
    #[derive(Default)]
    pub struct NoServerVerification {}

    impl NoServerVerification {
        /// Creates a new instance of `NoServerVerification`.
        pub fn new() -> NoServerVerification {
            NoServerVerification {}
        }
    }

    impl ServerCertVerifier for NoServerVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::Certificate,
            _intermediates: &[rustls::Certificate],
            _server_name: &rustls::ServerName,
            _scts: &mut dyn Iterator<Item = &[u8]>,
            _ocsp_response: &[u8],
            _now: std::time::SystemTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
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
    #[cfg(feature = "self-signed")]
    #[cfg_attr(docsrs, doc(cfg(feature = "self-signed")))]
    pub struct ServerHashVerification {
        hashes: std::collections::BTreeSet<Sha256Digest>,
    }

    #[cfg(feature = "self-signed")]
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
            }
        }
    }

    #[cfg(feature = "self-signed")]
    impl ServerCertVerifier for ServerHashVerification {
        fn verify_server_cert(
            &self,
            end_entity: &rustls::Certificate,
            _intermediates: &[rustls::Certificate],
            _server_name: &rustls::ServerName,
            _scts: &mut dyn Iterator<Item = &[u8]>,
            _ocsp_response: &[u8],
            now: std::time::SystemTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            use time::OffsetDateTime;
            use x509_parser::oid_registry::OID_EC_P256;
            use x509_parser::oid_registry::OID_KEY_TYPE_EC_PUBLIC_KEY;
            use x509_parser::time::ASN1Time;

            let now = ASN1Time::new(OffsetDateTime::from(now));

            let x509 = X509Certificate::from_der(&end_entity.0)
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

            let end_entity_hash = crate::tls::Certificate::from_der(end_entity.0.to_vec())
                .map_err(|_| rustls::CertificateError::BadEncoding)?
                .hash();

            if self.hashes.contains(&end_entity_hash) {
                Ok(ServerCertVerified::assertion())
            } else {
                Err(rustls::CertificateError::UnknownIssuer.into())
            }
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
}

pub use rustls;

mod utils {
    use std::env;
    use std::ffi::OsStr;
    use std::ffi::OsString;

    pub struct VarRestoreGuard {
        key: OsString,
        value: Option<OsString>,
    }

    impl Drop for VarRestoreGuard {
        fn drop(&mut self) {
            if let Some(value) = self.value.take() {
                env::set_var(self.key.clone(), value);
            }
        }
    }

    pub fn remove_var_tmp<K: AsRef<OsStr>>(key: K) -> VarRestoreGuard {
        let value = env::var_os(key.as_ref());

        env::remove_var(key.as_ref());

        VarRestoreGuard {
            key: key.as_ref().to_os_string(),
            value,
        }
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
