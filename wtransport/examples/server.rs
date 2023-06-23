use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::time::Duration;
use wtransport::tls::Certificate;
use wtransport::Endpoint;
use wtransport::ServerConfig;

#[tokio::main]
async fn main() {
    let mut buffer = [0; 65536];

    let config = ServerConfig::builder()
        .with_bind_address(SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 4433))
        .with_certificate(Certificate::load("cert.pem", "key.pem").unwrap())
        .keep_alive_interval(Some(Duration::from_secs(3)))
        .build();

    let server = Endpoint::server(config).unwrap();

    loop {
        println!("Waiting for incoming connection...");
        let incoming_request = server.accept().await.await.unwrap();

        println!(
            "Incoming request\n \
               Authority: {}\n \
               Path: {}",
            incoming_request.authority(),
            incoming_request.path()
        );

        let connection = incoming_request.accept().await.unwrap();

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

                    let mut stream = connection.open_uni().await.unwrap().await.unwrap();
                    stream.write_all(b"ACK").await.unwrap();
                }
                dgram = connection.receive_datagram() => {
                    let dgram = dgram.unwrap();
                    let str_data = std::str::from_utf8(&dgram).unwrap();

                    println!("Received (dgram) '{str_data}' from client");

                    connection.send_datagram(b"ACK").unwrap();
                }
            }
        }
    }
}
