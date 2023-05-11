use std::net::Ipv6Addr;
use std::net::SocketAddr;
use wtransport::tls::Certificate;
use wtransport::Endpoint;
use wtransport::ServerConfig;

#[tokio::main]
async fn main() {
    let mut buffer = [0; 65536];

    let config = ServerConfig::builder()
        .with_bind_address(SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 4433))
        .with_certificate(Certificate::load("cert.pem", "key.pem").unwrap());

    let server = Endpoint::server(config).unwrap();

    loop {
        println!("Waiting for incoming connection...");
        let connection = server.accept().await.unwrap().await.unwrap();
        println!("Waiting for data from client...");

        loop {
            tokio::select! {
                stream = connection.accept_bi() => {
                    let mut stream = stream.unwrap();
                    println!("Accepted BI stream");

                    let bytes_read = stream.1.read(&mut buffer).await.unwrap().unwrap();
                    let str_data = std::str::from_utf8(&buffer[..bytes_read]).unwrap();

                    println!("Received (bi) '{str_data}' from client");

                    stream.0.write_all(b"ACK").await.unwrap();
                }
                stream = connection.accept_uni() => {
                    let mut stream = stream.unwrap();
                    println!("Accepted UNI stream");

                    let bytes_read = stream.read(&mut buffer).await.unwrap().unwrap();
                    let str_data = std::str::from_utf8(&buffer[..bytes_read]).unwrap();

                    println!("Received (uni) '{str_data}' from client");

                    let mut stream = connection.open_uni().await.unwrap();
                    stream.write_all(b"ACK").await.unwrap();
                }
            }
        }
    }
}
