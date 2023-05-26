use crate::tls::Certificate;
use quinn::ClientConfig as QuicClientConfig;
use quinn::ServerConfig as QuicServerConfig;
use rustls::client::ServerCertVerified;
use rustls::client::ServerCertVerifier;
use rustls::ClientConfig as TlsClientConfig;
use rustls::RootCertStore;
use rustls::ServerConfig as TlsServerConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use wtransport_proto::WEBTRANSPORT_ALPN;

/// Server configuration.
///
/// Configuration can be created via [`ServerConfig::builder`] function.
pub struct ServerConfig {
    pub(crate) quic_config: QuicServerConfig,
    pub(crate) bind_address: SocketAddr,
}

impl ServerConfig {
    /// Creates a builder to build up the server configuration.
    ///
    /// For more information, see the [`ServerConfigBuilder`] documentation.
    pub fn builder() -> ServerConfigBuilder<WantsBindAddress> {
        ServerConfigBuilder::default()
    }
}

/// Server builder configuration.
///
/// The builder might have different state at compile time.
///
/// # Examples:
/// ```no_run
/// # use std::net::Ipv4Addr;
/// # use std::net::SocketAddr;
/// # use wtransport::tls::Certificate;
/// # use wtransport::ServerConfig;
/// let config = ServerConfig::builder()
///     .with_bind_address(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 4433))
///     .with_certificate(Certificate::load("cert.pem", "key.pem").unwrap());
/// ```
pub struct ServerConfigBuilder<State>(State);

impl ServerConfigBuilder<WantsBindAddress> {
    /// Sets the binding (local) socket address for the endpoint.
    pub fn with_bind_address(self, address: SocketAddr) -> ServerConfigBuilder<WantsCertificate> {
        ServerConfigBuilder(WantsCertificate {
            bind_address: address,
        })
    }
}

impl ServerConfigBuilder<WantsCertificate> {
    /// Sets the TLS certificate the server will present to incoming
    /// WebTransport connections.
    pub fn with_certificate(self, certificate: Certificate) -> ServerConfig {
        let tls_config = Self::build_tls_config(certificate);
        let quic_config = QuicServerConfig::with_crypto(tls_config);

        ServerConfig {
            quic_config,
            bind_address: self.0.bind_address,
        }
    }

    fn build_tls_config(certificate: Certificate) -> Arc<TlsServerConfig> {
        let mut config = TlsServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certificate.certificates, certificate.key)
            .unwrap(); // TODO(bfesta): handle this error

        config.alpn_protocols = [WEBTRANSPORT_ALPN.to_vec()].to_vec();

        Arc::new(config)
    }
}

/// Client configuration.
///
/// Configuration can be created via [`ClientConfig::builder`] function.
pub struct ClientConfig {
    pub(crate) quic_config: QuicClientConfig,
    pub(crate) bind_address: SocketAddr,
}

impl ClientConfig {
    /// Creates a builder to build up the client configuration.
    ///
    /// For more information, see the [`ClientConfigBuilder`] documentation.
    pub fn builder() -> ClientConfigBuilder<WantsBindAddress> {
        ClientConfigBuilder::default()
    }
}

/// Client builder configuration.
///
/// The builder might have different state at compile time.
///
/// # Example
/// ```no_run
/// # use std::net::Ipv4Addr;
/// # use std::net::SocketAddr;
/// # use wtransport::ClientConfig;
/// let config =
///     ClientConfig::builder().with_bind_address(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0));
/// ```
pub struct ClientConfigBuilder<State>(State);

impl ClientConfigBuilder<WantsBindAddress> {
    /// Sets the binding (local) socket address for the endpoint.
    pub fn with_bind_address(self, address: SocketAddr) -> ClientConfig {
        let tls_config = Self::build_tls_config();
        let quic_config = QuicClientConfig::new(tls_config);

        ClientConfig {
            quic_config,
            bind_address: address,
        }
    }

    fn build_tls_config() -> Arc<TlsClientConfig> {
        let mut root_store = RootCertStore::empty();
        match rustls_native_certs::load_native_certs() {
            Ok(certs) => {
                for c in certs {
                    let _ = root_store.add(&rustls::Certificate(c.0));
                }
            }
            Err(_error) => {}
        }

        let mut config = TlsClientConfig::builder()
            .with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
            .with_safe_default_protocol_versions()
            .expect("Safe protocols should not error")
            .with_root_certificates(root_store)
            .with_no_client_auth();

        config.alpn_protocols = [WEBTRANSPORT_ALPN.to_vec()].to_vec();

        config
            .dangerous()
            .set_certificate_verifier(Arc::new(NoServerVerification));

        Arc::new(config)
    }
}

impl Default for ServerConfigBuilder<WantsBindAddress> {
    fn default() -> Self {
        Self(WantsBindAddress {})
    }
}

impl Default for ClientConfigBuilder<WantsBindAddress> {
    fn default() -> Self {
        Self(WantsBindAddress {})
    }
}

/// Config builder state where the caller must supply binding address.
pub struct WantsBindAddress {}

/// Config builder state where the caller must supply TLS certificate.
pub struct WantsCertificate {
    bind_address: SocketAddr,
}

struct NoServerVerification;

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
