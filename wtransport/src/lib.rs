//! WebTransport protocol implementation.
//!
//! The entry point of this crate is [`Endpoint`].
//!
//! # Server
//! ```no_run
//! # use std::net::Ipv6Addr;
//! # use std::net::SocketAddr;
//! use wtransport::tls::Certificate;
//! use wtransport::Endpoint;
//! use wtransport::ServerConfig;
//!
//! # async fn run() {
//! let config = ServerConfig::builder()
//!     .with_bind_address(SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 4433))
//!     .with_certificate(Certificate::load("cert.pem", "key.pem").unwrap())
//!     .build();
//!
//! let server = Endpoint::server(config).unwrap();
//! let connection = server.accept().await.unwrap().await.unwrap();
//! # }
//! ```
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]

/// Client and server configurations.
pub mod config;

/// WebTransport connection.
pub mod connection;

/// Errors definitions module.
pub mod error;

/// Interfaces for sending and receiving data.
pub mod stream;

/// TLS specific configurations.
pub mod tls;

/// Datagrams module.
pub mod datagram;

/// Session information.
pub mod session;

#[doc(inline)]
pub use config::ClientConfig;

#[doc(inline)]
pub use config::ServerConfig;

#[doc(inline)]
pub use endpoint::Endpoint;

#[doc(inline)]
pub use connection::Connection;

#[doc(inline)]
pub use stream::RecvStream;

#[doc(inline)]
pub use stream::SendStream;

mod driver;
mod endpoint;
