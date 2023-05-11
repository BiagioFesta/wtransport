use std::path::Path;

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
    pub fn load(cert_path: impl AsRef<Path>, key_path: impl AsRef<Path>) -> std::io::Result<Self> {
        let certificates = rustls_pemfile::certs(&mut &*std::fs::read(cert_path)?)?;

        let private_key = rustls_pemfile::read_one(&mut &*std::fs::read(key_path)?)?
            .map(|item| match item {
                rustls_pemfile::Item::RSAKey(d) => d,
                rustls_pemfile::Item::PKCS8Key(d) => d,
                rustls_pemfile::Item::ECKey(d) => d,
                _ => unreachable!(),
            })
            .ok_or(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "No PEM section found for key",
            ))?;

        Ok(Self::new(certificates, private_key))
    }
}
