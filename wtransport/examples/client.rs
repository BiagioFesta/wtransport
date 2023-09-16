use wtransport::ClientConfig;
use wtransport::Endpoint;

#[tokio::main]
async fn main() {
    let connection = Endpoint::client(ClientConfig::default())
        .unwrap()
        .connect("https://[::1]:4433")
        .await
        .unwrap();

    let mut stream = connection.open_bi().await.unwrap().await.unwrap();
    stream.0.write_all(b"HELLO").await.unwrap();
    stream.0.finish().await.unwrap();
}
