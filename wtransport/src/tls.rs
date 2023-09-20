use std::error::Error;
use std::fmt::Debug;
use std::fmt::Display;
use std::path::Path;
use std::path::PathBuf;

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

/// A server TLS certificate.
pub struct Certificate {
    pub(crate) certificates: Vec<rustls::Certificate>,
    pub(crate) key: rustls::PrivateKey,
}

impl Certificate {
    /// Creates a certificate from encoded data.
    ///
    /// `certificates` is a chain where each certificate-data must be *DER-encoded* *X.509*.
    /// `private_key` is the single private key associated and it must be *DER-encoded* *ASN.1*
    /// in either *PKCS#8*, *PKCS#1*, or *Sec1* format.
    pub fn new(certificates: Vec<Vec<u8>>, private_key: Vec<u8>) -> Self {
        let certificates = certificates.into_iter().map(rustls::Certificate).collect();
        let key = rustls::PrivateKey(private_key);

        Self { certificates, key }
    }

    /// Loads a PEM certificates and private key from the filesystem.
    pub fn load(
        cert_path: impl AsRef<Path>,
        key_path: impl AsRef<Path>,
    ) -> Result<Self, CertificateLoadError> {
        let certificates =
            rustls_pemfile::certs(&mut &*std::fs::read(cert_path.as_ref()).map_err(
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
            rustls_pemfile::read_one(&mut &*std::fs::read(key_path.as_ref()).map_err(
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

        Ok(Self::new(certificates, private_key.0))
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
