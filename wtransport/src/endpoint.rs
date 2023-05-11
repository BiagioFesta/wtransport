use crate::config::ClientConfig;
use crate::config::ServerConfig;
use crate::connection::Connecting;
use crate::error::ConnectionError;
use quinn::Endpoint as QuicEndpoint;
use std::marker::PhantomData;
use std::net::SocketAddr;

/// Type of endpoint accepting multiple WebTransport connections.
pub struct Server;

/// Type of endpoint opening a WebTransport connection.
pub struct Client;

/// Entrypoint for creating client or server connections.
///
/// * For creating a server: [`Endpoint::server`].
/// * For creating a client: [`Endpoint::client`].
pub struct Endpoint<Side> {
    endpoint: QuicEndpoint,
    _marker: PhantomData<Side>,
}

impl Endpoint<Server> {
    /// Constructs a *server* endpoint.
    pub fn server(server_config: ServerConfig) -> std::io::Result<Self> {
        let quic_config = server_config.quic_config;
        let bind_address = server_config.bind_address;

        let endpoint = QuicEndpoint::server(quic_config, bind_address)?;

        Ok(Self {
            endpoint,
            _marker: PhantomData,
        })
    }

    /// Get the next incoming connection attempt from a client.
    ///
    /// Returns `None` if the endpoint has been closed.
    pub async fn accept(&self) -> Option<Connecting> {
        self.endpoint
            .accept()
            .await
            .map(|quic_connecting| Connecting::new(true, quic_connecting))
    }
}

impl Endpoint<Client> {
    /// Constructs a *client* endpoint.
    pub fn client(client_config: ClientConfig) -> std::io::Result<Self> {
        let quic_config = client_config.quic_config;
        let bind_address = client_config.bind_address;

        let mut endpoint = QuicEndpoint::client(bind_address)?;
        endpoint.set_default_client_config(quic_config);

        Ok(Self {
            endpoint,
            _marker: PhantomData,
        })
    }

    /// Connects to a remote endpoint.
    ///
    /// `server_name` must be covered by the certificate presented by the server.
    pub fn connect(
        &self,
        remote_address: SocketAddr,
        server_name: &str,
    ) -> Result<Connecting, ConnectionError> {
        let quic_connecting = self.endpoint.connect(remote_address, server_name).unwrap();
        Ok(Connecting::new(false, quic_connecting))
    }
}
