use crate::tls::Certificate;
use quinn::ClientConfig as QuicClientConfig;
use quinn::ServerConfig as QuicServerConfig;
use quinn::TransportConfig;
use rustls::ClientConfig as TlsClientConfig;
use rustls::RootCertStore;
use rustls::ServerConfig as TlsServerConfig;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use wtransport_proto::WEBTRANSPORT_ALPN;

/// Configuration for IP address socket bind.
pub enum IpBindConfig {
    /// Bind to LOCALHOST IPv4 address (no IPv6).
    LocalV4,

    /// Bind to LOCALHOST IPv6 address (no IPv4).
    LocalV6,

    /// Bind to LOCALHOST both IPv4 and IPv6 address (dual stack).
    LocalDual,

    /// Bind to INADDR_ANY IPv4 address (no IPv6).
    InAddrAnyV4,

    /// Bind to INADDR_ANY IPv6 address (no IPv4).
    InAddrAnyV6,

    /// Bind to INADDR_ANY both IPv4 and IPv6 address (dual stack).
    InAddrAnyDual,
}

/// Invalid idle timeout.
#[derive(Debug)]
pub struct InvalidIdleTimeout;

/// Server configuration.
///
/// Configuration can be created via [`ServerConfig::builder`] function.
pub struct ServerConfig {
    pub(crate) bind_address: SocketAddr,
    pub(crate) bind_only_ipv6: bool,
    pub(crate) quic_config: QuicServerConfig,
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
///     .with_bind_default(4433)
///     .with_certificate(Certificate::load("cert.pem", "key.pem").unwrap());
/// ```
pub struct ServerConfigBuilder<State>(State);

impl ServerConfigBuilder<WantsBindAddress> {
    /// Configures for accepting incoming connections binding ANY IP (both IPv4 and IPv6).
    ///
    /// `listening_port` is the port where the server will accept incoming connections.
    pub fn with_bind_default(self, listening_port: u16) -> ServerConfigBuilder<WantsCertificate> {
        self.with_bind_config(IpBindConfig::InAddrAnyDual, listening_port)
    }

    /// Sets the binding (local) socket address with a specific [`IpBindConfig`].
    ///
    /// `listening_port` is the port where the server will accept incoming connections.
    pub fn with_bind_config(
        self,
        ip_bind_config: IpBindConfig,
        listening_port: u16,
    ) -> ServerConfigBuilder<WantsCertificate> {
        let (ip_address, only_v6): (IpAddr, bool) = match ip_bind_config {
            IpBindConfig::LocalV4 => (Ipv4Addr::LOCALHOST.into(), true),
            IpBindConfig::LocalV6 => (Ipv4Addr::LOCALHOST.into(), true),
            IpBindConfig::LocalDual => (Ipv6Addr::LOCALHOST.into(), false),
            IpBindConfig::InAddrAnyV4 => (Ipv4Addr::UNSPECIFIED.into(), true),
            IpBindConfig::InAddrAnyV6 => (Ipv6Addr::UNSPECIFIED.into(), true),
            IpBindConfig::InAddrAnyDual => (Ipv6Addr::UNSPECIFIED.into(), false),
        };

        self.with_bind_address(SocketAddr::new(ip_address, listening_port), only_v6)
    }

    /// Sets the binding (local) socket address for the endpoint.
    pub fn with_bind_address(
        self,
        address: SocketAddr,
        only_v6: bool,
    ) -> ServerConfigBuilder<WantsCertificate> {
        ServerConfigBuilder(WantsCertificate {
            bind_address: address,
            bind_only_ipv6: only_v6,
        })
    }
}

impl ServerConfigBuilder<WantsCertificate> {
    /// Sets the TLS certificate the server will present to incoming
    /// WebTransport connections.
    pub fn with_certificate(
        self,
        certificate: Certificate,
    ) -> ServerConfigBuilder<WantsTransportConfigServer> {
        let tls_config = Self::build_tls_config(certificate);
        let transport_config = TransportConfig::default();

        ServerConfigBuilder(WantsTransportConfigServer {
            bind_address: self.0.bind_address,
            bind_only_ipv6: self.0.bind_only_ipv6,
            tls_config,
            transport_config,
            migration: true,
        })
    }

    fn build_tls_config(certificate: Certificate) -> TlsServerConfig {
        let mut tls_config = TlsServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certificate.certificates, certificate.key)
            .unwrap(); // TODO(bfesta): handle this error

        tls_config.alpn_protocols = [WEBTRANSPORT_ALPN.to_vec()].to_vec();

        tls_config
    }
}

impl ServerConfigBuilder<WantsTransportConfigServer> {
    /// Completes configuration process.
    pub fn build(self) -> ServerConfig {
        let mut quic_config = QuicServerConfig::with_crypto(Arc::new(self.0.tls_config));
        quic_config.transport_config(Arc::new(self.0.transport_config));
        quic_config.migration(self.0.migration);

        ServerConfig {
            bind_address: self.0.bind_address,
            bind_only_ipv6: self.0.bind_only_ipv6,
            quic_config,
        }
    }

    /// Maximum duration of inactivity to accept before timing out the connection.
    ///
    /// The true idle timeout is the minimum of this and the peer's own max idle timeout. `None`
    /// represents an infinite timeout.
    ///
    /// **WARNING**: If a peer or its network path malfunctions or acts maliciously, an infinite
    /// idle timeout can result in permanently hung futures!
    pub fn max_idle_timeout(
        mut self,
        idle_timeout: Option<Duration>,
    ) -> Result<Self, InvalidIdleTimeout> {
        let idle_timeout = idle_timeout
            .map(quinn::IdleTimeout::try_from)
            .transpose()
            .map_err(|_| InvalidIdleTimeout)?;

        self.0.transport_config.max_idle_timeout(idle_timeout);

        Ok(self)
    }

    /// Period of inactivity before sending a keep-alive packet
    ///
    /// Keep-alive packets prevent an inactive but otherwise healthy connection from timing out.
    ///
    /// `None` to disable, which is the default. Only one side of any given connection needs keep-alive
    /// enabled for the connection to be preserved. Must be set lower than the idle_timeout of both
    /// peers to be effective.
    pub fn keep_alive_interval(mut self, interval: Option<Duration>) -> Self {
        self.0.transport_config.keep_alive_interval(interval);
        self
    }

    /// Whether to allow clients to migrate to new addresses.
    ///
    /// Improves behavior for clients that move between different internet connections or suffer NAT
    /// rebinding. Enabled by default.
    pub fn allow_migration(mut self, value: bool) -> Self {
        self.0.migration = value;
        self
    }
}

/// Client configuration.
///
/// Configuration can be created via [`ClientConfig::builder`] function.
pub struct ClientConfig {
    pub(crate) bind_address: SocketAddr,
    pub(crate) bind_only_ipv6: bool,
    pub(crate) quic_config: QuicClientConfig,
}

impl ClientConfig {
    /// Creates a builder to build up the client configuration.
    ///
    /// For more information, see the [`ClientConfigBuilder`] documentation.
    pub fn builder() -> ClientConfigBuilder<WantsBindAddress> {
        ClientConfigBuilder::default()
    }
}

impl Default for ClientConfig {
    fn default() -> Self {
        ClientConfig::builder()
            .with_bind_default()
            .with_native_certs()
            .build()
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
/// let config = ClientConfig::builder().with_bind_default();
/// ```
pub struct ClientConfigBuilder<State>(State);

impl ClientConfigBuilder<WantsBindAddress> {
    /// Configures for connecting binding ANY IP (both IPv4 and IPv6).
    ///
    /// Bind port will be randomly picked.
    pub fn with_bind_default(self) -> ClientConfigBuilder<WantsRootStore> {
        self.with_bind_config(IpBindConfig::InAddrAnyDual)
    }

    /// Sets the binding (local) socket address with a specific [`IpBindConfig`].
    ///
    /// Bind port will be randomly picked.
    pub fn with_bind_config(
        self,
        ip_bind_config: IpBindConfig,
    ) -> ClientConfigBuilder<WantsRootStore> {
        let (ip_address, only_v6): (IpAddr, bool) = match ip_bind_config {
            IpBindConfig::LocalV4 => (Ipv4Addr::LOCALHOST.into(), true),
            IpBindConfig::LocalV6 => (Ipv4Addr::LOCALHOST.into(), true),
            IpBindConfig::LocalDual => (Ipv6Addr::LOCALHOST.into(), false),
            IpBindConfig::InAddrAnyV4 => (Ipv4Addr::UNSPECIFIED.into(), true),
            IpBindConfig::InAddrAnyV6 => (Ipv6Addr::UNSPECIFIED.into(), true),
            IpBindConfig::InAddrAnyDual => (Ipv6Addr::UNSPECIFIED.into(), false),
        };

        self.with_bind_address(SocketAddr::new(ip_address, 0), only_v6)
    }

    /// Sets the binding (local) socket address for the endpoint.
    pub fn with_bind_address(
        self,
        address: SocketAddr,
        only_v6: bool,
    ) -> ClientConfigBuilder<WantsRootStore> {
        ClientConfigBuilder(WantsRootStore {
            bind_address: address,
            bind_only_ipv6: only_v6,
        })
    }
}

impl ClientConfigBuilder<WantsRootStore> {
    /// Loads local (native) root certificate for server validation.
    pub fn with_native_certs(self) -> ClientConfigBuilder<WantsTransportConfigClient> {
        let tls_config = Self::build_tls_config(Self::native_cert_store());
        let transport_config = TransportConfig::default();

        ClientConfigBuilder(WantsTransportConfigClient {
            bind_address: self.0.bind_address,
            bind_only_ipv6: self.0.bind_only_ipv6,
            tls_config,
            transport_config,
        })
    }

    /// Skip certificate server validation.
    #[cfg(feature = "dangerous-configuration")]
    #[cfg_attr(docsrs, doc(cfg(feature = "dangerous-configuration")))]
    pub fn with_no_cert_validation(self) -> ClientConfigBuilder<WantsTransportConfigClient> {
        let mut tls_config = Self::build_tls_config(RootCertStore::empty());
        tls_config
            .dangerous()
            .set_certificate_verifier(Arc::new(dangerous_configuration::NoServerVerification));

        let transport_config = TransportConfig::default();

        ClientConfigBuilder(WantsTransportConfigClient {
            bind_address: self.0.bind_address,
            bind_only_ipv6: self.0.bind_only_ipv6,
            tls_config,
            transport_config,
        })
    }

    fn native_cert_store() -> RootCertStore {
        let mut root_store = RootCertStore::empty();

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

    fn build_tls_config(root_store: RootCertStore) -> TlsClientConfig {
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
}

impl ClientConfigBuilder<WantsTransportConfigClient> {
    /// Completes configuration process.
    pub fn build(self) -> ClientConfig {
        let mut quic_config = QuicClientConfig::new(Arc::new(self.0.tls_config));
        quic_config.transport_config(Arc::new(self.0.transport_config));

        ClientConfig {
            bind_address: self.0.bind_address,
            bind_only_ipv6: self.0.bind_only_ipv6,
            quic_config,
        }
    }

    /// Maximum duration of inactivity to accept before timing out the connection.
    ///
    /// The true idle timeout is the minimum of this and the peer's own max idle timeout. `None`
    /// represents an infinite timeout.
    ///
    /// **WARNING**: If a peer or its network path malfunctions or acts maliciously, an infinite
    /// idle timeout can result in permanently hung futures!
    pub fn max_idle_timeout(
        mut self,
        idle_timeout: Option<Duration>,
    ) -> Result<Self, InvalidIdleTimeout> {
        let idle_timeout = idle_timeout
            .map(quinn::IdleTimeout::try_from)
            .transpose()
            .map_err(|_| InvalidIdleTimeout)?;

        self.0.transport_config.max_idle_timeout(idle_timeout);

        Ok(self)
    }

    /// Period of inactivity before sending a keep-alive packet
    ///
    /// Keep-alive packets prevent an inactive but otherwise healthy connection from timing out.
    ///
    /// `None` to disable, which is the default. Only one side of any given connection needs keep-alive
    /// enabled for the connection to be preserved. Must be set lower than the idle_timeout of both
    /// peers to be effective.
    pub fn keep_alive_interval(mut self, interval: Option<Duration>) -> Self {
        self.0.transport_config.keep_alive_interval(interval);
        self
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
    bind_only_ipv6: bool,
}

/// Config builder state where the caller must supply TLS root store.
pub struct WantsRootStore {
    bind_address: SocketAddr,
    bind_only_ipv6: bool,
}

/// Config builder state where transport properties can be set.
pub struct WantsTransportConfigServer {
    bind_address: SocketAddr,
    bind_only_ipv6: bool,
    tls_config: TlsServerConfig,
    transport_config: quinn::TransportConfig,
    migration: bool,
}

/// Config builder state where transport properties can be set.
pub struct WantsTransportConfigClient {
    bind_address: SocketAddr,
    bind_only_ipv6: bool,
    tls_config: TlsClientConfig,
    transport_config: quinn::TransportConfig,
}

#[cfg(feature = "dangerous-configuration")]
mod dangerous_configuration {
    use rustls::client::ServerCertVerified;
    use rustls::client::ServerCertVerifier;

    pub(super) struct NoServerVerification;

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
}
