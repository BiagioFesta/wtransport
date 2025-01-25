//!
//! This module defines configurations for the WebTransport server and client.
//!
//! It provides builders for creating server and client configurations with various options.
//!
//! The module includes:
//! - [`ServerConfig`]: Configuration for the WebTransport server.
//! - [`ClientConfig`]: Configuration for the WebTransport client.
//!
//! Example for creating a server configuration:
//!
//! ```no_run
//! # async fn run() -> anyhow::Result<()> {
//! use wtransport::Identity;
//! use wtransport::ServerConfig;
//!
//! let server_config = ServerConfig::builder()
//!     .with_bind_default(443)
//!     .with_identity(Identity::load_pemfiles("cert.pem", "key.pem").await?)
//!     .build();
//!
//! # Ok(())
//! # }
//! ```
//!
//! Example for creating a client configuration:
//!
//! ```no_run
//! use wtransport::ClientConfig;
//!
//! let client_config = ClientConfig::builder()
//!     .with_bind_default()
//!     .with_native_certs()
//!     .build();
//! ```

use crate::tls::build_native_cert_store;
use crate::tls::Identity;
use quinn::EndpointConfig;
use quinn::TransportConfig;
use socket2::Domain as SocketDomain;
use socket2::Protocol as SocketProtocol;
use socket2::Socket;
use socket2::Type as SocketType;
use std::fmt::Debug;
use std::fmt::Display;
use std::future::Future;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::net::SocketAddrV6;
use std::net::UdpSocket;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

/// Alias of [`crate::tls::rustls::ServerConfig`].
pub type TlsServerConfig = crate::tls::rustls::ServerConfig;

/// Alias of [`crate::tls::rustls::ClientConfig`].
pub type TlsClientConfig = crate::tls::rustls::ClientConfig;

/// Alias of [`crate::quinn::TransportConfig`].
#[cfg(feature = "quinn")]
#[cfg_attr(docsrs, doc(cfg(feature = "quinn")))]
pub type QuicTransportConfig = crate::quinn::TransportConfig;

/// Alias of [`crate::quinn::ServerConfig`].
#[cfg(feature = "quinn")]
#[cfg_attr(docsrs, doc(cfg(feature = "quinn")))]
pub type QuicServerConfig = crate::quinn::ServerConfig;

/// Alias of [`crate::quinn::ClientConfig`].
#[cfg(feature = "quinn")]
#[cfg_attr(docsrs, doc(cfg(feature = "quinn")))]
pub type QuicClientConfig = crate::quinn::ClientConfig;

/// Configuration for IP address socket bind.
#[derive(Debug, Copy, Clone)]
pub enum IpBindConfig {
    /// Bind to LOCALHOST IPv4 address (no IPv6).
    LocalV4,

    /// Bind to LOCALHOST IPv6 address (no IPv4).
    LocalV6,

    /// Bind to LOCALHOST both IPv4 and IPv6 address (dual stack, if supported).
    LocalDual,

    /// Bind to `INADDR_ANY` IPv4 address (no IPv6).
    InAddrAnyV4,

    /// Bind to `INADDR_ANY` IPv6 address (no IPv4).
    InAddrAnyV6,

    /// Bind to `INADDR_ANY` both IPv4 and IPv6 address (dual stack, if supported).
    InAddrAnyDual,
}

impl IpBindConfig {
    fn into_ip(self) -> IpAddr {
        match self {
            IpBindConfig::LocalV4 => Ipv4Addr::LOCALHOST.into(),
            IpBindConfig::LocalV6 => Ipv6Addr::LOCALHOST.into(),
            IpBindConfig::LocalDual => Ipv6Addr::LOCALHOST.into(),
            IpBindConfig::InAddrAnyV4 => Ipv4Addr::UNSPECIFIED.into(),
            IpBindConfig::InAddrAnyV6 => Ipv6Addr::UNSPECIFIED.into(),
            IpBindConfig::InAddrAnyDual => Ipv6Addr::UNSPECIFIED.into(),
        }
    }

    fn into_dual_stack_config(self) -> Ipv6DualStackConfig {
        match self {
            IpBindConfig::LocalV4 | IpBindConfig::InAddrAnyV4 => Ipv6DualStackConfig::OsDefault,
            IpBindConfig::LocalV6 | IpBindConfig::InAddrAnyV6 => Ipv6DualStackConfig::Deny,
            IpBindConfig::LocalDual | IpBindConfig::InAddrAnyDual => Ipv6DualStackConfig::Allow,
        }
    }
}

/// Configuration for IPv6 dual stack.
#[derive(Debug, Copy, Clone)]
pub enum Ipv6DualStackConfig {
    /// Do not configure dual stack. Use OS's default.
    OsDefault,

    /// Deny dual stack. This is equivalent to `IPV6_V6ONLY`.
    ///
    /// Socket will only bind for IPv6 (IPv4 port will still be available).
    Deny,

    /// Allow dual stack.
    ///
    /// Please note that not all configurations/platforms support dual stack.
    Allow,
}

/// Invalid idle timeout.
pub struct InvalidIdleTimeout;

/// Server configuration.
///
/// You can create an instance of `ServerConfig` using its builder pattern by calling
/// the [`builder()`](Self::builder) method.
/// Once you have an instance, you can further customize it by chaining method calls
/// to set various configuration options.
///
/// ## Configuration Builder States
///
/// The configuration process follows a *state-based builder pattern*, where the server
/// configuration progresses through *3* states.
///
/// ### 1. `WantsBindAddress`
///
/// The caller must supply a binding address for the server. This is where to specify
/// the listening port of the server.
/// The following options are mutually exclusive:
///
///   - [`with_bind_default`](ServerConfigBuilder::with_bind_default): the simplest
///     configuration where only the port will be specified.
///   - [`with_bind_config`](ServerConfigBuilder::with_bind_config): configures
///     binding to an address determined by a configuration preset.
///   - [`with_bind_address`](ServerConfigBuilder::with_bind_address): configures
///     binding to a custom-specified socket address.
///   - [`with_bind_address_v6`](ServerConfigBuilder::with_bind_address_v6): configures
///     binding to a custom-specified socket address for *IPv6*, along with the [dual stack
///     configuration](Ipv6DualStackConfig).
///   - [`with_bind_socket`](ServerConfigBuilder::with_bind_socket): configures
///     binding directly to a custom-specified socket.
///
/// Only one of these options can be selected during the client configuration process.
///
/// #### Examples:
///
/// ```
/// use wtransport::ServerConfig;
///
/// // Configuration for accepting incoming connection on port 443
/// ServerConfig::builder().with_bind_default(443);
/// ```
///
/// ### 2. `WantsIdentity`
///
/// The caller must supply a TLS identity for the server.
///
/// - [`with_identity`](ServerConfigBuilder::with_identity): configures
///   a TLS [`Identity`] for the server.
/// - [`with_custom_tls`](ServerConfigBuilder::with_custom_tls): sets the TLS
///   server configuration manually.
/// - [`with_custom_transport`](ServerConfigBuilder::with_custom_transport): sets the QUIC
///   transport configuration manually (using default TLS).
/// - [`with_custom_tls_and_transport`](ServerConfigBuilder::with_custom_tls_and_transport): sets both
///   a custom TLS and QUIC transport configuration.
/// - [`build_with_quic_config`](ServerConfigBuilder::build_with_quic_config): directly builds
///   [`ServerConfig`] providing both TLS and QUIC transport configuration given by
///   [`quic_config`](QuicServerConfig).
///
/// #### Examples:
/// ```
/// # use anyhow::Result;
/// use wtransport::Identity;
/// use wtransport::ServerConfig;
///
/// # async fn run() -> Result<()> {
/// ServerConfig::builder()
///     .with_bind_default(443)
///     .with_identity(Identity::load_pemfiles("cert.pem", "key.pem").await?);
/// # Ok(())
/// # }
/// ```
///
/// ### 3. `WantsTransportConfigServer`
///
/// The caller can supply *additional* transport configurations.
/// Multiple options can be given at this stage. Once the configuration is completed, it is possible
/// to finalize with the method [`build()`](ServerConfigBuilder::build).
///
/// All these options can be omitted in the configuration; default values will be used.
///
/// - [`max_idle_timeout`](ServerConfigBuilder::max_idle_timeout)
/// - [`keep_alive_interval`](ServerConfigBuilder::keep_alive_interval)
/// - [`allow_migration`](ServerConfigBuilder::allow_migration)
///
/// #### Examples:
/// ```
/// # use anyhow::Result;
/// use wtransport::ServerConfig;
/// use wtransport::Identity;
/// use std::time::Duration;
///
/// # async fn run() -> Result<()> {
/// let server_config = ServerConfig::builder()
///     .with_bind_default(443)
///     .with_identity(Identity::load_pemfiles("cert.pem", "key.pem").await?)
///     .keep_alive_interval(Some(Duration::from_secs(3)))
///     .build();
/// # Ok(())
/// # }
#[derive(Debug)]
pub struct ServerConfig {
    pub(crate) bind_address_config: BindAddressConfig,
    pub(crate) endpoint_config: quinn::EndpointConfig,
    pub(crate) quic_config: quinn::ServerConfig,
}

impl ServerConfig {
    /// Creates a builder to build up the server configuration.
    ///
    /// For more information, see the [`ServerConfigBuilder`] documentation.
    pub fn builder() -> ServerConfigBuilder<states::WantsBindAddress> {
        ServerConfigBuilder::default()
    }

    /// Returns a reference to the inner QUIC endpoint configuration.
    #[cfg(feature = "quinn")]
    #[cfg_attr(docsrs, doc(cfg(feature = "quinn")))]
    pub fn quic_endpoint_config(&self) -> &quinn::EndpointConfig {
        &self.endpoint_config
    }

    /// Returns a mutable reference to the inner QUIC endpoint configuration.
    #[cfg(feature = "quinn")]
    #[cfg_attr(docsrs, doc(cfg(feature = "quinn")))]
    pub fn quic_endpoint_config_mut(&mut self) -> &mut quinn::EndpointConfig {
        &mut self.endpoint_config
    }

    /// Returns a reference to the inner QUIC configuration.
    #[cfg(feature = "quinn")]
    #[cfg_attr(docsrs, doc(cfg(feature = "quinn")))]
    pub fn quic_config(&self) -> &quinn::ServerConfig {
        &self.quic_config
    }

    /// Returns a mutable reference to the inner QUIC configuration.
    #[cfg(feature = "quinn")]
    #[cfg_attr(docsrs, doc(cfg(feature = "quinn")))]
    pub fn quic_config_mut(&mut self) -> &mut quinn::ServerConfig {
        &mut self.quic_config
    }
}

/// Server builder configuration.
///
/// The builder might have different state at compile time.
///
/// # Examples:
/// ```no_run
/// # async fn run() -> anyhow::Result<()> {
/// # use std::net::Ipv4Addr;
/// # use std::net::SocketAddr;
/// # use wtransport::Identity;
/// # use wtransport::ServerConfig;
/// let config = ServerConfig::builder()
///     .with_bind_default(4433)
///     .with_identity(Identity::load_pemfiles("cert.pem", "key.pem").await?);
/// # Ok(())
/// # }
/// ```
#[must_use]
pub struct ServerConfigBuilder<State>(State);

impl ServerConfigBuilder<states::WantsBindAddress> {
    /// Configures for accepting incoming connections binding ANY IP (allowing IP dual-stack).
    ///
    /// `listening_port` is the port where the server will accept incoming connections.
    ///
    /// This is equivalent to: [`Self::with_bind_config`] with [`IpBindConfig::InAddrAnyDual`].
    pub fn with_bind_default(
        self,
        listening_port: u16,
    ) -> ServerConfigBuilder<states::WantsIdentity> {
        self.with_bind_config(IpBindConfig::InAddrAnyDual, listening_port)
    }

    /// Sets the binding (local) socket address with a specific [`IpBindConfig`].
    ///
    /// `listening_port` is the port where the server will accept incoming connections.
    pub fn with_bind_config(
        self,
        ip_bind_config: IpBindConfig,
        listening_port: u16,
    ) -> ServerConfigBuilder<states::WantsIdentity> {
        let ip_address: IpAddr = ip_bind_config.into_ip();

        match ip_address {
            IpAddr::V4(ip) => self.with_bind_address(SocketAddr::new(ip.into(), listening_port)),
            IpAddr::V6(ip) => self.with_bind_address_v6(
                SocketAddrV6::new(ip, listening_port, 0, 0),
                ip_bind_config.into_dual_stack_config(),
            ),
        }
    }

    /// Sets the binding (local) socket address for the endpoint.
    pub fn with_bind_address(
        self,
        address: SocketAddr,
    ) -> ServerConfigBuilder<states::WantsIdentity> {
        ServerConfigBuilder(states::WantsIdentity {
            bind_address_config: BindAddressConfig::from(address),
        })
    }

    /// Sets the binding (local) socket address for the endpoint with Ipv6 address.
    ///
    /// `dual_stack_config` allows/denies dual stack port binding.
    pub fn with_bind_address_v6(
        self,
        address: SocketAddrV6,
        dual_stack_config: Ipv6DualStackConfig,
    ) -> ServerConfigBuilder<states::WantsIdentity> {
        ServerConfigBuilder(states::WantsIdentity {
            bind_address_config: BindAddressConfig::AddressV6(address, dual_stack_config),
        })
    }

    /// Configures the server to bind to a pre-existing [`UdpSocket`].
    ///
    /// This allows the server to use an already created socket, which may be beneficial
    /// for scenarios where socket reuse or specific socket configuration is needed.
    pub fn with_bind_socket(self, socket: UdpSocket) -> ServerConfigBuilder<states::WantsIdentity> {
        ServerConfigBuilder(states::WantsIdentity {
            bind_address_config: BindAddressConfig::Socket(socket),
        })
    }
}

impl ServerConfigBuilder<states::WantsIdentity> {
    /// Configures TLS with safe defaults and a TLS [`Identity`].
    ///
    /// # Example
    /// ```no_run
    /// use wtransport::Identity;
    /// use wtransport::ServerConfig;
    /// # use anyhow::Result;
    ///
    /// # async fn run() -> Result<()> {
    /// let identity = Identity::load_pemfiles("cert.pem", "key.pem").await?;
    ///
    /// let server_config = ServerConfig::builder()
    ///     .with_bind_default(4433)
    ///     .with_identity(identity)
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_identity(
        self,
        identity: Identity,
    ) -> ServerConfigBuilder<states::WantsTransportConfigServer> {
        use crate::tls::server::build_default_tls_config;

        let tls_config = build_default_tls_config(identity);
        let quic_endpoint_config = EndpointConfig::default();
        let quic_transport_config = TransportConfig::default();

        self.with(tls_config, quic_endpoint_config, quic_transport_config)
    }

    /// Allows for manual configuration of a custom TLS setup using a provided
    /// [`rustls::ServerConfig`], which must support
    /// [`rustls::CipherSuite::TLS13_AES_128_GCM_SHA256`]. A suitable configuration
    /// can be obtained using the `ring` crypto provider with a set of versions containing
    /// [`rustls::version::TLS13`].
    ///
    /// This method is provided for advanced users who need fine-grained control over the
    /// TLS configuration. It allows you to pass a preconfigured [`rustls::ServerConfig`]
    /// instance to customize the TLS settings according to your specific requirements.
    ///
    /// Generally, it is recommended to use the [`with_identity`](Self::with_identity) method
    /// to configure TLS with safe defaults and an TLS [`Identity`].
    ///
    /// # Example
    ///
    /// ```no_run
    /// use wtransport::tls::rustls;
    /// use wtransport::ServerConfig;
    ///
    /// // Create a custom rustls::ServerConfig with specific TLS settings
    /// let custom_tls_config = rustls::ServerConfig::builder();
    /// // Customize TLS settings here...
    /// # let custom_tls_config = custom_tls_config
    /// #          .with_no_client_auth()
    /// #          .with_single_cert(todo!(), todo!()).unwrap();
    ///
    /// // Create a ServerConfigBuilder with the custom TLS configuration
    /// let server_config = ServerConfig::builder()
    ///     .with_bind_default(4433)
    ///     .with_custom_tls(custom_tls_config)
    ///     .build();
    /// ```
    pub fn with_custom_tls(
        self,
        tls_config: TlsServerConfig,
    ) -> ServerConfigBuilder<states::WantsTransportConfigServer> {
        let quic_endpoint_config = EndpointConfig::default();
        let quic_transport_config = TransportConfig::default();

        self.with(tls_config, quic_endpoint_config, quic_transport_config)
    }

    /// Configures the server with a custom QUIC transport configuration and a default TLS setup
    /// using the provided [`Identity`].
    ///
    /// This method is useful for scenarios where you need to customize the transport settings
    /// while relying on a default TLS configuration built from an [`Identity`]. It gives you
    /// control over the transport layer while maintaining safe and standard TLS settings.
    ///
    /// **See**: [`with_identity`](Self::with_identity)
    /// for a simpler configuration option that does not require custom transport settings.
    ///
    /// # Parameters
    ///
    /// - `identity`: A reference to an [`Identity`] that contains the server's certificate and
    ///   private key. This will be used to generate the default TLS configuration.
    /// - `quic_transport_config`: A custom [`QuicTransportConfig`] instance that allows you to specify
    ///   various QUIC transport-layer settings according to your requirements.
    ///
    /// # Example
    ///
    /// ```
    /// use wtransport::config::QuicTransportConfig;
    /// use wtransport::Identity;
    /// use wtransport::ServerConfig;
    ///
    /// // Generate a server identity (self signed certificate and private key)
    /// let identity = Identity::self_signed(["localhost", "127.0.0.1", "::1"]).unwrap();
    ///
    /// // Create a custom QuicTransportConfig with specific settings
    /// let mut custom_transport_config = QuicTransportConfig::default();
    /// custom_transport_config.datagram_send_buffer_size(1024);
    ///
    /// // Create a ServerConfigBuilder with the custom transport configuration and default TLS settings
    /// let server_config = ServerConfig::builder()
    ///     .with_bind_default(4433)
    ///     .with_custom_transport(identity, custom_transport_config)
    ///     .build();
    /// ```
    #[cfg(feature = "quinn")]
    #[cfg_attr(docsrs, doc(cfg(feature = "quinn")))]
    pub fn with_custom_transport(
        self,
        identity: Identity,
        quic_transport_config: QuicTransportConfig,
    ) -> ServerConfigBuilder<states::WantsTransportConfigServer> {
        use crate::tls::server::build_default_tls_config;

        let tls_config = build_default_tls_config(identity);
        let quic_endpoint_config = EndpointConfig::default();

        self.with(tls_config, quic_endpoint_config, quic_transport_config)
    }

    /// Configures the server with both a custom TLS configuration and a custom QUIC transport
    /// configuration.
    ///
    /// This method is designed for advanced users who require full control over both the TLS
    /// and transport settings. It allows you to pass a preconfigured [`TlsServerConfig`] and
    /// a custom [`QuicTransportConfig`] to fine-tune both layers of the server configuration.
    ///
    /// # Parameters
    ///
    /// - `tls_config`: A custom [`TlsServerConfig`] instance that allows you to specify
    ///   detailed TLS settings, such as ciphersuites, certificate verification, and more. It must
    ///   support TLS 1.3 (see the documentation of [`Self::with_custom_tls`]).
    /// - `quic_transport_config`: A custom [`QuicTransportConfig`] instance that allows you to specify
    ///   various QUIC transport-layer settings according to your requirements.
    #[cfg(feature = "quinn")]
    #[cfg_attr(docsrs, doc(cfg(feature = "quinn")))]
    pub fn with_custom_tls_and_transport(
        self,
        tls_config: TlsServerConfig,
        quic_transport_config: QuicTransportConfig,
    ) -> ServerConfigBuilder<states::WantsTransportConfigServer> {
        let quic_endpoint_config = EndpointConfig::default();
        self.with(tls_config, quic_endpoint_config, quic_transport_config)
    }

    /// Directly builds [`ServerConfig`] skipping TLS and transport configuration.
    ///
    /// Both TLS and transport configuration is given by [`quic_config`](QuicServerConfig).
    #[cfg(feature = "quinn")]
    #[cfg_attr(docsrs, doc(cfg(feature = "quinn")))]
    pub fn build_with_quic_config(self, quic_config: QuicServerConfig) -> ServerConfig {
        ServerConfig {
            bind_address_config: self.0.bind_address_config,
            endpoint_config: EndpointConfig::default(),
            quic_config,
        }
    }

    fn with(
        self,
        tls_config: TlsServerConfig,
        endpoint_config: EndpointConfig,
        transport_config: TransportConfig,
    ) -> ServerConfigBuilder<states::WantsTransportConfigServer> {
        ServerConfigBuilder(states::WantsTransportConfigServer {
            bind_address_config: self.0.bind_address_config,
            tls_config,
            endpoint_config,
            transport_config,
            migration: true,
        })
    }
}

impl ServerConfigBuilder<states::WantsTransportConfigServer> {
    /// Completes configuration process.
    ///
    /// # Panics
    ///
    /// See the documentation of [`Self::with_custom_tls`] for the TLS 1.3 requirement.
    #[must_use]
    pub fn build(self) -> ServerConfig {
        let crypto: Arc<quinn::crypto::rustls::QuicServerConfig> = Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(self.0.tls_config)
                .expect("CipherSuite::TLS13_AES_128_GCM_SHA256 missing"),
        );

        let mut quic_config = quinn::ServerConfig::with_crypto(crypto);

        quic_config.transport_config(Arc::new(self.0.transport_config));
        quic_config.migration(self.0.migration);

        ServerConfig {
            bind_address_config: self.0.bind_address_config,
            endpoint_config: self.0.endpoint_config,
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
    /// enabled for the connection to be preserved. Must be set lower than the
    /// [`max_idle_timeout`](Self::max_idle_timeout) of both peers to be effective.
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
///
/// You can create an instance of `ClientConfig` using its builder pattern by calling
/// the [`builder()`](Self::builder) method.
/// Once you have an instance, you can further customize it by chaining method calls
/// to set various configuration options.
///
/// ## Configuration Builder States
///
/// The configuration process follows a *state-based builder pattern*, where the client
/// configuration progresses through *3* states.
///
/// ### 1. `WantsBindAddress`
///
/// The caller must supply a binding address for the client.
/// The following options are mutually exclusive:
///
///   - [`with_bind_default`](ClientConfigBuilder::with_bind_default): configures to use
///     the default bind address. This is generally the *default* choice for a client.
///   - [`with_bind_config`](ClientConfigBuilder::with_bind_config): configures
///     binding to an address determined by a configuration preset.
///   - [`with_bind_address`](ClientConfigBuilder::with_bind_address): configures
///     binding to a custom-specified socket address.
///   - [`with_bind_address_v6`](ClientConfigBuilder::with_bind_address_v6): configures
///     binding to a custom-specified socket address for *IPv6*, along with the [dual stack
///     configuration](Ipv6DualStackConfig).
///   - [`with_bind_socket`](ClientConfigBuilder::with_bind_socket): configures
///     binding directly to a custom-specified socket.
///
/// Only one of these options can be selected during the client configuration process.
///
/// #### Examples:
///
/// ```
/// use wtransport::ClientConfig;
///
/// ClientConfig::builder().with_bind_default();
/// ```
///
/// ### 2. `WantsRootStore`
///
/// The caller must supply a TLS root store configuration for server certificate validation.
/// The following options are mutually exclusive:
///
/// - [`with_native_certs`](ClientConfigBuilder::with_native_certs): configures to use
///   root certificates found in the platform's native certificate store. This is the *default*
///   configuration as it uses root store installed on the current machine.
/// - [`with_server_certificate_hashes`][cert_hashes]: configures the client to accept
///   *some* certificates mapped to hashes. This can be used to connect to self signed
///   certificates securely, where the hash of the certificate is shared in advance
///   through some other mechanism (such as an invite link).
/// - (**insecure**) [`with_no_cert_validation`](ClientConfigBuilder::with_no_cert_validation):
///   configure to skip server certificate validation. This might be handy for testing purpose
///   to accept *self-signed* certificate, but you should almost always prefer
///   [`with_server_certificate_hashes`][cert_hashes] for that use case.
/// - [`with_custom_tls`](ClientConfigBuilder::with_custom_tls): sets the TLS client
///   configuration manually.
/// - [`with_custom_transport`](ClientConfigBuilder::with_custom_transport): sets the QUIC
///   transport configuration manually (using default TLS).
/// - [`with_custom_tls_and_transport`](ClientConfigBuilder::with_custom_tls_and_transport): sets both
///   a custom TLS and QUIC transport configuration.
/// - [`build_with_quic_config`](ClientConfigBuilder::build_with_quic_config): directly builds
///   [`ClientConfig`] providing both TLS and QUIC transport configuration given by
///   [`quic_config`](QuicClientConfig).
///
/// Only one of these options can be selected during the client configuration process.
///
/// [cert_hashes]: ClientConfigBuilder::with_server_certificate_hashes
///
/// #### Examples:
/// ```
/// use wtransport::ClientConfig;
///
/// ClientConfig::builder()
///     .with_bind_default()
///     .with_native_certs();
/// ```
///
/// ### 3. `WantsTransportConfigClient`
///
/// The caller can supply *additional* transport configurations.
/// Multiple options can be given at this stage. Once the configuration is completed, it is possible
/// to finalize with the method [`build()`](ClientConfigBuilder::build).
///
/// All these options can be omitted in the configuration; default values will be used.
///
/// - [`max_idle_timeout`](ClientConfigBuilder::max_idle_timeout)
/// - [`keep_alive_interval`](ClientConfigBuilder::keep_alive_interval)
/// - [`dns_resolver`](ClientConfigBuilder::dns_resolver)
///
/// #### Examples:
/// ```
/// use std::time::Duration;
/// use wtransport::ClientConfig;
///
/// let client_config = ClientConfig::builder()
///     .with_bind_default()
///     .with_native_certs()
///     .max_idle_timeout(Some(Duration::from_secs(30)))
///     .unwrap()
///     .keep_alive_interval(Some(Duration::from_secs(3)))
///     .build();
/// ```
#[derive(Debug)]
pub struct ClientConfig {
    pub(crate) bind_address_config: BindAddressConfig,
    pub(crate) endpoint_config: quinn::EndpointConfig,
    pub(crate) quic_config: quinn::ClientConfig,
    pub(crate) dns_resolver: Arc<dyn DnsResolver + Send + Sync>,
}

impl ClientConfig {
    /// Creates a builder to build up the client configuration.
    ///
    /// For more information, see the [`ClientConfigBuilder`] documentation.
    pub fn builder() -> ClientConfigBuilder<states::WantsBindAddress> {
        ClientConfigBuilder::default()
    }

    /// Allows setting a custom [`DnsResolver`] for this configuration.
    ///
    /// Default resolver is [`TokioDnsResolver`].
    pub fn set_dns_resolver<R>(&mut self, dns_resolver: R)
    where
        R: DnsResolver + Send + Sync + 'static,
    {
        self.dns_resolver = Arc::new(dns_resolver);
    }

    /// Returns a reference to the inner QUIC endpoint configuration.
    #[cfg(feature = "quinn")]
    #[cfg_attr(docsrs, doc(cfg(feature = "quinn")))]
    pub fn quic_endpoint_config(&self) -> &quinn::EndpointConfig {
        &self.endpoint_config
    }

    /// Returns a mutable reference to the inner QUIC endpoint configuration.
    #[cfg(feature = "quinn")]
    #[cfg_attr(docsrs, doc(cfg(feature = "quinn")))]
    pub fn quic_endpoint_config_mut(&mut self) -> &mut quinn::EndpointConfig {
        &mut self.endpoint_config
    }

    /// Returns a reference to the inner QUIC configuration.
    #[cfg(feature = "quinn")]
    #[cfg_attr(docsrs, doc(cfg(feature = "quinn")))]
    pub fn quic_config(&self) -> &quinn::ClientConfig {
        &self.quic_config
    }

    /// Returns a mutable reference to the inner QUIC configuration.
    #[cfg(feature = "quinn")]
    #[cfg_attr(docsrs, doc(cfg(feature = "quinn")))]
    pub fn quic_config_mut(&mut self) -> &mut quinn::ClientConfig {
        &mut self.quic_config
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
#[must_use]
pub struct ClientConfigBuilder<State>(State);

impl ClientConfigBuilder<states::WantsBindAddress> {
    /// Configures for connecting binding ANY IP (allowing IP dual-stack).
    ///
    /// Bind port will be randomly picked.
    ///
    /// This is equivalent to: [`Self::with_bind_config`] with [`IpBindConfig::InAddrAnyDual`].
    pub fn with_bind_default(self) -> ClientConfigBuilder<states::WantsRootStore> {
        self.with_bind_config(IpBindConfig::InAddrAnyDual)
    }

    /// Sets the binding (local) socket address with a specific [`IpBindConfig`].
    ///
    /// Bind port will be randomly picked.
    pub fn with_bind_config(
        self,
        ip_bind_config: IpBindConfig,
    ) -> ClientConfigBuilder<states::WantsRootStore> {
        let ip_address: IpAddr = ip_bind_config.into_ip();

        match ip_address {
            IpAddr::V4(ip) => self.with_bind_address(SocketAddr::new(ip.into(), 0)),
            IpAddr::V6(ip) => self.with_bind_address_v6(
                SocketAddrV6::new(ip, 0, 0, 0),
                ip_bind_config.into_dual_stack_config(),
            ),
        }
    }

    /// Sets the binding (local) socket address for the endpoint.
    pub fn with_bind_address(
        self,
        address: SocketAddr,
    ) -> ClientConfigBuilder<states::WantsRootStore> {
        ClientConfigBuilder(states::WantsRootStore {
            bind_address_config: BindAddressConfig::from(address),
        })
    }

    /// Sets the binding (local) socket address for the endpoint.
    ///
    /// `dual_stack_config` allows/denies dual stack port binding.
    pub fn with_bind_address_v6(
        self,
        address: SocketAddrV6,
        dual_stack_config: Ipv6DualStackConfig,
    ) -> ClientConfigBuilder<states::WantsRootStore> {
        ClientConfigBuilder(states::WantsRootStore {
            bind_address_config: BindAddressConfig::AddressV6(address, dual_stack_config),
        })
    }

    /// Configures the client to bind to a pre-existing [`UdpSocket`].
    ///
    /// This allows the client to use an already created socket, which can be useful in cases
    /// where socket reuse or specific socket configurations are necessary.
    pub fn with_bind_socket(
        self,
        socket: UdpSocket,
    ) -> ClientConfigBuilder<states::WantsRootStore> {
        ClientConfigBuilder(states::WantsRootStore {
            bind_address_config: BindAddressConfig::Socket(socket),
        })
    }
}

impl ClientConfigBuilder<states::WantsRootStore> {
    /// Configures the client to use native (local) root certificates for server validation.
    ///
    /// This method loads trusted root certificates from the system's certificate store,
    /// ensuring that your client can trust certificates signed by well-known authorities.
    ///
    /// It configures safe default TLS configuration.
    pub fn with_native_certs(self) -> ClientConfigBuilder<states::WantsTransportConfigClient> {
        use crate::tls::client::build_default_tls_config;

        let tls_config = build_default_tls_config(Arc::new(build_native_cert_store()), None);
        let endpoint_config = EndpointConfig::default();
        let transport_config = TransportConfig::default();

        self.with(tls_config, endpoint_config, transport_config)
    }

    /// Configures the client to skip server certificate validation, potentially
    /// compromising security.
    ///
    /// This method is intended for advanced users and should be used with caution. It
    /// configures the client to bypass server certificate validation during the TLS
    /// handshake, effectively trusting any server certificate presented, even if it is
    /// not signed by a trusted certificate authority (CA). Using this method can expose
    /// your application to security risks.
    ///
    /// # Safety Note
    ///
    /// Using [`with_no_cert_validation`] should only be considered when you have a
    /// specific need to disable certificate validation. In most cases, it is strongly
    /// recommended to validate server certificates using trusted root certificates
    /// (e.g., [`with_native_certs`]) to ensure secure communication.
    ///
    /// However, this method can be useful in testing environments or situations where
    /// you intentionally want to skip certificate validation for specific use cases.
    ///
    /// [`with_native_certs`]: #method.with_native_certs
    /// [`with_no_cert_validation`]: #method.with_no_cert_validation
    #[cfg(feature = "dangerous-configuration")]
    #[cfg_attr(docsrs, doc(cfg(feature = "dangerous-configuration")))]
    pub fn with_no_cert_validation(
        self,
    ) -> ClientConfigBuilder<states::WantsTransportConfigClient> {
        use crate::tls::client::build_default_tls_config;
        use crate::tls::client::NoServerVerification;
        use rustls::RootCertStore;

        let tls_config = build_default_tls_config(
            Arc::new(RootCertStore::empty()),
            Some(Arc::new(NoServerVerification::new())),
        );

        let endpoint_config = EndpointConfig::default();
        let transport_config = TransportConfig::default();

        self.with(tls_config, endpoint_config, transport_config)
    }

    /// Configures the client to skip *some* server certificates validation.
    ///
    /// This method configures the client to accept server certificates
    /// whose digests match the specified *SHA-256* hashes and fulfill
    /// some additional constraints (*see notes below*).
    ///
    /// This is useful for scenarios where clients need to accept known
    /// self-signed certificates or certificates from non-standard authorities.
    ///
    /// This method configuration is similar to the
    /// [browser W3C WebTransport API](https://www.w3.org/TR/webtransport/#dom-webtransportoptions-servercertificatehashes).
    ///
    /// # Notes
    ///
    /// - The current time MUST be within the validity period of the certificate.
    /// - The total length of the validity period MUST NOT exceed *two* weeks.
    /// - Only certificates for which the public key algorithm is *ECDSA* with the *secp256r1* are accepted.
    pub fn with_server_certificate_hashes<I>(
        self,
        hashes: I,
    ) -> ClientConfigBuilder<states::WantsTransportConfigClient>
    where
        I: IntoIterator<Item = crate::tls::Sha256Digest>,
    {
        use crate::tls::client::build_default_tls_config;
        use crate::tls::client::ServerHashVerification;
        use rustls::RootCertStore;

        let tls_config = build_default_tls_config(
            Arc::new(RootCertStore::empty()),
            Some(Arc::new(ServerHashVerification::new(hashes))),
        );

        let endpoint_config = EndpointConfig::default();
        let transport_config = TransportConfig::default();

        self.with(tls_config, endpoint_config, transport_config)
    }

    /// Allows for manual configuration of a custom TLS setup using a provided
    /// [`rustls::ClientConfig`], which must support
    /// [`rustls::CipherSuite::TLS13_AES_128_GCM_SHA256`]. A suitable configuration
    /// can be obtained using the `ring` crypto provider with a set of versions containing
    /// [`rustls::version::TLS13`].
    ///
    /// This method is provided for advanced users who need fine-grained control over the
    /// TLS configuration. It allows you to pass a preconfigured [`rustls::ClientConfig`]
    /// instance to customize the TLS settings according to your specific requirements.
    ///
    /// For most use cases, it is recommended to use the [`with_native_certs`](Self::with_native_certs)
    /// method to configure TLS with safe defaults.
    pub fn with_custom_tls(
        self,
        tls_config: TlsClientConfig,
    ) -> ClientConfigBuilder<states::WantsTransportConfigClient> {
        let endpoint_config = EndpointConfig::default();
        let transport_config = TransportConfig::default();

        self.with(tls_config, endpoint_config, transport_config)
    }

    /// Similar to [`with_native_certs`](Self::with_native_certs), but it allows specifying a custom
    /// QUIC transport configuration.
    ///
    /// # Parameters
    ///
    /// - `quic_transport_config`: A custom [`QuicTransportConfig`] instance that allows you to specify
    ///   various QUIC transport-layer settings according to your requirements.
    ///
    /// # Example
    ///
    /// ```
    /// use wtransport::config::QuicTransportConfig;
    /// use wtransport::ClientConfig;
    ///
    /// // Create a custom QuicTransportConfig with specific settings
    /// let mut custom_transport_config = QuicTransportConfig::default();
    /// custom_transport_config.datagram_send_buffer_size(1024);
    ///
    /// // Create a ClientConfigBuilder with the custom transport configuration and default TLS settings
    /// let client_config = ClientConfig::builder()
    ///     .with_bind_default()
    ///     .with_custom_transport(custom_transport_config)
    ///     .build();
    /// ```
    #[cfg(feature = "quinn")]
    #[cfg_attr(docsrs, doc(cfg(feature = "quinn")))]
    pub fn with_custom_transport(
        self,
        quic_transport_config: QuicTransportConfig,
    ) -> ClientConfigBuilder<states::WantsTransportConfigClient> {
        use crate::tls::client::build_default_tls_config;

        let tls_config = build_default_tls_config(Arc::new(build_native_cert_store()), None);
        let quic_endpoint_config = EndpointConfig::default();

        self.with(tls_config, quic_endpoint_config, quic_transport_config)
    }

    /// Configures the client with both a custom TLS configuration and a custom QUIC transport
    /// configuration.
    ///
    /// This method is designed for advanced users who require full control over both the TLS
    /// and transport settings. It allows you to pass a preconfigured [`TlsClientConfig`] and
    /// a custom [`QuicTransportConfig`] to fine-tune both layers of the server configuration.
    ///
    /// # Parameters
    ///
    /// - `tls_config`: A custom [`TlsClientConfig`] instance that allows you to specify
    ///   detailed TLS settings, such as ciphersuites, certificate verification, and more. It must
    ///   support TLS 1.3 (see the documentation of [`Self::with_custom_tls`]).
    /// - `quic_transport_config`: A custom [`QuicTransportConfig`] instance that allows you to specify
    ///   various QUIC transport-layer settings according to your requirements.
    #[cfg(feature = "quinn")]
    #[cfg_attr(docsrs, doc(cfg(feature = "quinn")))]
    pub fn with_custom_tls_and_transport(
        self,
        tls_config: TlsClientConfig,
        quic_transport_config: QuicTransportConfig,
    ) -> ClientConfigBuilder<states::WantsTransportConfigClient> {
        let quic_endpoint_config = EndpointConfig::default();
        self.with(tls_config, quic_endpoint_config, quic_transport_config)
    }

    /// Directly builds [`ClientConfig`] skipping TLS and transport configuration.
    ///
    /// Both TLS and transport configuration is given by [`quic_config`](QuicClientConfig).
    #[cfg(feature = "quinn")]
    #[cfg_attr(docsrs, doc(cfg(feature = "quinn")))]
    pub fn build_with_quic_config(self, quic_config: QuicClientConfig) -> ClientConfig {
        ClientConfig {
            bind_address_config: self.0.bind_address_config,
            endpoint_config: EndpointConfig::default(),
            quic_config,
            dns_resolver: Arc::<TokioDnsResolver>::default(),
        }
    }

    fn with(
        self,
        tls_config: TlsClientConfig,
        endpoint_config: EndpointConfig,
        transport_config: TransportConfig,
    ) -> ClientConfigBuilder<states::WantsTransportConfigClient> {
        ClientConfigBuilder(states::WantsTransportConfigClient {
            bind_address_config: self.0.bind_address_config,
            tls_config,
            endpoint_config,
            transport_config,
            dns_resolver: Arc::<TokioDnsResolver>::default(),
        })
    }
}

impl ClientConfigBuilder<states::WantsTransportConfigClient> {
    /// Completes configuration process.
    ///
    /// # Panics
    ///
    /// See the documentation of [`Self::with_custom_tls`] for the TLS 1.3 requirement.
    #[must_use]
    pub fn build(self) -> ClientConfig {
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(self.0.tls_config)
            .expect("CipherSuite::TLS13_AES_128_GCM_SHA256 missing");

        let mut quic_config = quinn::ClientConfig::new(Arc::new(crypto));
        quic_config.transport_config(Arc::new(self.0.transport_config));

        ClientConfig {
            bind_address_config: self.0.bind_address_config,
            endpoint_config: self.0.endpoint_config,
            quic_config,
            dns_resolver: self.0.dns_resolver,
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
    /// enabled for the connection to be preserved. Must be set lower than the
    /// [`max_idle_timeout`](Self::max_idle_timeout) of both peers to be effective.
    pub fn keep_alive_interval(mut self, interval: Option<Duration>) -> Self {
        self.0.transport_config.keep_alive_interval(interval);
        self
    }

    /// Sets the *DNS* resolver used during [`Endpoint::connect`](crate::Endpoint::connect).
    ///
    /// Default configuration uses [`TokioDnsResolver`].
    pub fn dns_resolver<R>(mut self, dns_resolver: R) -> Self
    where
        R: DnsResolver + Send + Sync + 'static,
    {
        self.0.dns_resolver = Arc::new(dns_resolver);
        self
    }
}

impl Default for ServerConfigBuilder<states::WantsBindAddress> {
    fn default() -> Self {
        Self(states::WantsBindAddress {})
    }
}

impl Default for ClientConfigBuilder<states::WantsBindAddress> {
    fn default() -> Self {
        Self(states::WantsBindAddress {})
    }
}

#[derive(Debug)]
pub(crate) enum BindAddressConfig {
    AddressV4(SocketAddrV4),
    AddressV6(SocketAddrV6, Ipv6DualStackConfig),
    Socket(UdpSocket),
}

impl BindAddressConfig {
    pub(crate) fn bind_socket(self) -> std::io::Result<UdpSocket> {
        let (bind_address, dual_stack_config) = match self {
            BindAddressConfig::AddressV4(address) => {
                (SocketAddr::from(address), Ipv6DualStackConfig::OsDefault)
            }
            BindAddressConfig::AddressV6(address, ipv6_dual_stack_config) => {
                (SocketAddr::from(address), ipv6_dual_stack_config)
            }
            BindAddressConfig::Socket(socket) => {
                return Ok(socket);
            }
        };

        let domain = match bind_address {
            SocketAddr::V4(_) => SocketDomain::IPV4,
            SocketAddr::V6(_) => SocketDomain::IPV6,
        };

        let socket = Socket::new(domain, SocketType::DGRAM, Some(SocketProtocol::UDP))?;

        match dual_stack_config {
            Ipv6DualStackConfig::OsDefault => {}
            Ipv6DualStackConfig::Deny => socket.set_only_v6(true)?,
            Ipv6DualStackConfig::Allow => socket.set_only_v6(false)?,
        }

        socket.bind(&bind_address.into())?;

        Ok(UdpSocket::from(socket))
    }
}

impl From<SocketAddr> for BindAddressConfig {
    fn from(value: SocketAddr) -> Self {
        match value {
            SocketAddr::V4(address) => BindAddressConfig::AddressV4(address),
            SocketAddr::V6(address) => {
                BindAddressConfig::AddressV6(address, Ipv6DualStackConfig::OsDefault)
            }
        }
    }
}

/// State-types for client/server builder.
pub mod states {
    use super::*;

    /// Config builder state where the caller must supply binding address.
    pub struct WantsBindAddress {}

    /// Config builder state where the caller must supply TLS certificate.
    pub struct WantsIdentity {
        pub(super) bind_address_config: BindAddressConfig,
    }

    /// Config builder state where the caller must supply TLS root store.
    pub struct WantsRootStore {
        pub(super) bind_address_config: BindAddressConfig,
    }

    /// Config builder state where transport properties can be set.
    pub struct WantsTransportConfigServer {
        pub(super) bind_address_config: BindAddressConfig,
        pub(super) tls_config: TlsServerConfig,
        pub(super) endpoint_config: quinn::EndpointConfig,
        pub(super) transport_config: quinn::TransportConfig,
        pub(super) migration: bool,
    }

    /// Config builder state where transport properties can be set.
    pub struct WantsTransportConfigClient {
        pub(super) bind_address_config: BindAddressConfig,
        pub(super) tls_config: TlsClientConfig,
        pub(super) endpoint_config: quinn::EndpointConfig,
        pub(super) transport_config: quinn::TransportConfig,
        pub(super) dns_resolver: Arc<dyn DnsResolver + Send + Sync>,
    }
}

/// Future resolving domain name.
///
/// See [`DnsResolver::resolve`].
pub trait DnsLookupFuture: Future<Output = std::io::Result<Option<SocketAddr>>> + Send {}

impl<F> DnsLookupFuture for F where F: Future<Output = std::io::Result<Option<SocketAddr>>> + Send {}

/// A trait for asynchronously resolving domain names to IP addresses using DNS.
pub trait DnsResolver: Debug {
    /// Resolves a domain name to one IP address.
    fn resolve(&self, host: &str) -> Pin<Box<dyn DnsLookupFuture>>;
}

/// A DNS resolver implementation using the *Tokio* asynchronous runtime.
///
/// Internally, it uses [`tokio::net::lookup_host`].
#[derive(Default)]
pub struct TokioDnsResolver;

impl DnsResolver for TokioDnsResolver {
    fn resolve(&self, host: &str) -> Pin<Box<dyn DnsLookupFuture>> {
        let host = host.to_string();

        Box::pin(async move { Ok(tokio::net::lookup_host(host).await?.next()) })
    }
}

impl Debug for TokioDnsResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokioDnsResolver").finish()
    }
}

impl std::error::Error for InvalidIdleTimeout {}

impl Debug for InvalidIdleTimeout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("idle timeout value configuration is invalid")
    }
}

impl Display for InvalidIdleTimeout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(self, f)
    }
}
