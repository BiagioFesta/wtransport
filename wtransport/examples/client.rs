use std::net::Ipv6Addr;
use std::net::SocketAddr;
use wtransport::ClientConfig;
use wtransport::Endpoint;

#[tokio::main]
async fn main() {
    let config =
        ClientConfig::builder().with_bind_address(SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0));

    let connection = Endpoint::client(config)
        .unwrap()
        .connect(
            SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 4433),
            "localhost",
        )
        .unwrap()
        .await
        .unwrap();

    let mut stream = connection.open_bi().await.unwrap();
    stream.0.write_all(b"HELLO").await.unwrap();
    stream.0.finish().await.unwrap();
}
