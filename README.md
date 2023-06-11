<p align="center">
  <img src="https://raw.githubusercontent.com/BiagioFesta/wtransport/master/imgs/logo.svg" alt="WTransport Logo" />
</p>

[![Documentation](https://docs.rs/wtransport/badge.svg)](https://docs.rs/wtransport/)
[![Crates.io](https://img.shields.io/crates/v/wtransport.svg)](https://crates.io/crates/wtransport)
[![RustCI](https://github.com/BiagioFesta/wtransport/actions/workflows/rust.yml/badge.svg?branch=master)](https://github.com/BiagioFesta/wtransport/actions/workflows/rust.yml)

# WTransport
[WebTransport](https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3/) protocol, pure-*rust*, *async*-friendly.

## Introduction

WebTransport is a new protocol being developed to enable *low-latency*, *bidirectional* communication between clients and servers over the web.
It aims to address the limitations of existing protocols like *HTTP* and *WebSocket* by offering a more *efficient* and *flexible* transport layer.

### Benefits of WebTransport
* :rocket: **Low latency**: WebTransport is designed to minimize latency, making it suitable for real-time applications such as gaming, video streaming, and collaborative editing.
* :arrows_counterclockwise: **Bidirectional communication**: WebTransport allows simultaneous data exchange between the client and server, enabling efficient back-and-forth communication without the need for multiple requests.
* :twisted_rightwards_arrows: **Multiplexing**: With WebTransport, multiple streams can be multiplexed over a single connection, reducing overhead and improving performance.
* :lock: **Security**: WebTransport benefits from the security features provided by the web platform, including transport encryption and same-origin policy.

### Notes
Please be aware that WebTransport is still a *draft* and not yet standardized.
The *WTransport* library, while functional, is not considered completely production-ready.
It should be used with caution and may undergo changes as the WebTransport specification evolves.

## Simple API
```rust
async fn server() -> Result<(), Error> {
    let config = ServerConfig::builder()
        .with_bind_address(SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 4433))
        .with_certificate(Certificate::load("cert.pem", "key.pem")?)
        .build();

    let server = Endpoint::server(config)?;

    println!("Waiting for incoming connections...");
    loop {
        let connecting = server.accept().await?;

        tokio::spawn(async move {
           println!("New connection");
           let connection = connecting.await?;
           let stream = connection.accept_bi().await?
           // ...
        });
    }
}
```

## Getting Started
### 0. Clone the Repository
```bash
git clone https://github.com/BiagioFesta/wtransport.git
```
```bash
cd wtransport/
```

### 1. Generate TLS Certificate
```bash
cargo run --example gencert
```

This will generate `cert.pem` and `key.pem` in the current working directory.

Moreover, the program will also output the *fingerprint* of the certificate. Something like this:
```
Certificate generated
Fingerprint: OjyqTe//WoGnvBrgiO37tkOQJyuN1r7hhyBzwX0gotg=
```

Please take note of the fingerprint, as you will need it to verify the certificate on the client side.

### 2. Run Example Server
```bash
cargo run --example server
```

### 3. Run Client on Browser
[Latest versions](https://chromestatus.com/feature/4854144902889472) of *Google Chrome* started
supporting some implementations of the protocol.

Since the generated certificate is self-signed, it cannot be directly accepted by the browser at the moment.
In order to allow the local certificate, you need to launch Google Chrome with two additional options:
```
google-chrome \
  --origin-to-force-quic-on=localhost:4433 \
  --ignore-certificate-errors-spki-list=FINGERPRINT
```

Replace `FINGERPRINT` with the value obtained in *step 1*.
For example, `OjyqTe//WoGnvBrgiO37tkOQJyuN1r7hhyBzwX0gotg=`.

### 4. Connect to the Server
Open the website https://webtransport.day/ on Google Chrome instace. Use the *URL*: `https://localhost:4433`, and click on *Connect*.

Enjoy!

## Examples
* https://github.com/BiagioFesta/wtransport-examples
* [Local Examples](wtransport/examples/)
