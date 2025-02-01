<p align="center">
  <img src="https://raw.githubusercontent.com/BiagioFesta/wtransport/master/imgs/logo.svg" alt="WTransport Logo" />
</p>

[![Documentation](https://docs.rs/wtransport/badge.svg)](https://docs.rs/wtransport/)
[![Crates.io](https://img.shields.io/crates/v/wtransport.svg)](https://crates.io/crates/wtransport)
[![CI](https://github.com/BiagioFesta/wtransport/actions/workflows/ci.yml/badge.svg)](https://github.com/BiagioFesta/wtransport/actions/workflows/ci.yml)
[![Chat](https://img.shields.io/badge/chat-join-blue?logo=discord)](https://discord.gg/KPrrbWe5zg)

# WTransport
[WebTransport](https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3/) protocol, pure-*rust*, *async*-friendly.

## Introduction

WebTransport is a new protocol being developed to enable *low-latency*, *bidirectional* communication between clients and servers over the web.
It aims to address the limitations of existing protocols like *HTTP* and *WebSocket* by offering a more *efficient* and *flexible* transport layer.

### Benefits of WebTransport
* 🚀 **Low latency**: WebTransport is designed to minimize latency, making it suitable for real-time applications such as gaming, video streaming, and collaborative editing.
* 🔄 **Bidirectional communication**: WebTransport allows simultaneous data exchange between the client and server, enabling efficient back-and-forth communication without the need for multiple requests.
* 🔀 **Multiplexing**: With WebTransport, multiple streams can be multiplexed over a single connection, reducing overhead and improving performance.
* 🔒 **Security**: WebTransport benefits from the security features provided by the web platform, including transport encryption and same-origin policy.
* 🌐 **Native Browser Support**: WebTransport is natively supported in modern web browsers, ensuring seamless integration and enhanced performance for web applications.

 <p align="center">
   <a href="https://docs.rs/wtransport/latest/wtransport/">Check Library Documentation</a>
 </p>

### Notes
Please be aware that WebTransport is still a *draft* and not yet standardized.
The *WTransport* library, while functional, is not considered completely production-ready.
It should be used with caution and may undergo changes as the WebTransport specification evolves.

## Simple API
<table>
<tr>
<th> Server </th>
<th> Client </th>
</tr>
<tr>
<td>

```rust
#[tokio::main]
async fn main() -> Result<()> {
    let config = ServerConfig::builder()
        .with_bind_default(4433)
        .with_identity(&identity)
        .build();

    let connection = Endpoint::server(config)?
        .accept()
        .await     // Awaits connection
        .await?    // Awaits session request
        .accept()  // Accepts request
        .await?;   // Awaits ready session

    let stream = connection.accept_bi().await?;
    // ...
}
```

</td>
<td>

```rust
#[tokio::main]
async fn main() -> Result<()> {
    let config = ClientConfig::default();

    let connection = Endpoint::client(config)?
        .connect("https://[::1]:4433")
        .await?;

    let stream = connection.open_bi().await?.await?;
    // ...
}
```

</td>
</tr>
</table>

## Browser Integration
WebTransport [is supported](https://caniuse.com/mdn-api_webtransport) in modern browsers,
enhancing the capabilities of web applications.

For instance, you can create a native *browser WebTransport* client connecting to a *Rust
server* using the following JavaScript code:

```javascript
// Create a WebTransport instance connecting to the Rust server
let transport = new WebTransport('https://[::1]:4433');
await transport.ready;

// Create a bidirectional stream
let stream = await transport.createBidirectionalStream();

// Send data from the client to the server
await stream.writable.getWriter().write(new TextEncoder().encode("hello"));

// Read data reply from the server
let data = await stream.readable.getReader().read();
console.log(data);
```

Check out the [W3C WebTransport API documentation](https://w3c.github.io/webtransport/) for more details and to
explore the full capabilities of WebTransport in the browser.

## Getting Started
### Clone the Repository
```bash
git clone https://github.com/BiagioFesta/wtransport.git
```
```bash
cd wtransport/
```

### Run `Full` Example

The [`examples/full.rs`](wtransport/examples/full.rs) is a minimal but complete server example that demonstrates the usage of WebTransport.

You can run this example using [*Cargo*](https://rustup.rs/), Rust's package manager, with the following command:
```bash
cargo run --example full
```

This example initiates an *echo* WebTransport server that can receive messages. It also includes an integrated HTTP server.

Open [a supported web browser](https://caniuse.com/mdn-api_webtransport) and navigate to the page http://127.0.0.1:8080.

## Examples
* [Local Examples](https://github.com/BiagioFesta/wtransport/tree/master/wtransport/examples)

## Other Languages

WTransport has bindings for the following languages:

- Elixir: [wtransport-elixir](https://github.com/bugnano/wtransport-elixir)
- Node.js: [node-wtransport](https://github.com/krulod/node-wtransport)
