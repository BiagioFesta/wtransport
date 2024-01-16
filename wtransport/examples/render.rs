use anyhow::Context;
use anyhow::Result;
use http::HttpServer;
use tracing::error;
use tracing::info;
use tracing::info_span;
use tracing::Instrument;
use webtransport::WebTransportServer;
use wtransport::tls::Identity;
use wtransport::tls::Sha256Digest;

#[tokio::main]
async fn main() -> Result<()> {
    utils::init_logging();

    let identity = Identity::self_signed(["localhost", "127.0.0.1", "::1"]).unwrap();
    let cert_digest = identity.certificate_chain().as_slice()[0].hash();

    let webtransport_server = WebTransportServer::new(identity)?;
    let http_server = HttpServer::new(&cert_digest, webtransport_server.local_port()).await?;

    info!(
        "Open Google Chrome and go to: http://127.0.0.1:{}",
        http_server.local_port()
    );

    tokio::select! {
        result = http_server.serve() => {
            error!("HTTP server: {:?}", result);
        }
        result = webtransport_server.serve() => {
            error!("WebTransport server: {:?}", result);
        }
    }

    Ok(())
}

mod webtransport {
    use super::*;
    use std::time::Duration;
    use tokio::time::interval;
    use wtransport::endpoint::endpoint_side::Server;
    use wtransport::endpoint::IncomingSession;
    use wtransport::Endpoint;
    use wtransport::ServerConfig;

    pub struct WebTransportServer {
        endpoint: Endpoint<Server>,
    }

    impl WebTransportServer {
        pub fn new(identity: Identity) -> Result<Self> {
            let config = ServerConfig::builder()
                .with_bind_default(0)
                .with_identity(identity)
                .keep_alive_interval(Some(Duration::from_secs(3)))
                .build();

            let endpoint = Endpoint::server(config)?;

            Ok(Self { endpoint })
        }

        pub fn local_port(&self) -> u16 {
            self.endpoint.local_addr().unwrap().port()
        }

        pub async fn serve(self) -> Result<()> {
            info!("Server running on port {}", self.local_port());

            for id in 0.. {
                let incoming_session = self.endpoint.accept().await;

                tokio::spawn(
                    Self::handle_incoming_session(incoming_session)
                        .instrument(info_span!("Connection", id)),
                );
            }

            Ok(())
        }

        async fn handle_incoming_session(incoming_session: IncomingSession) {
            async fn handle_incoming_session_impl(incoming_session: IncomingSession) -> Result<()> {
                const FPS: usize = 120;

                info!("Waiting for session request...");

                let session_request = incoming_session.await?;

                info!(
                    "New session: Authority: '{}', Path: '{}'",
                    session_request.authority(),
                    session_request.path()
                );

                let connection = session_request.accept().await?;
                let mut period_frame = interval(Duration::from_secs_f64(1.0 / FPS as f64));

                let mut frame_generator = frame_generator::FrameGenerator::new(800, 600);
                loop {
                    let mut stream = connection.open_uni().await.unwrap().await.unwrap();
                    let frame = frame_generator.next_frame();
                    period_frame.tick().await;
                    stream.write_all(frame.as_ref()).await.unwrap();
                }
            }

            let result = handle_incoming_session_impl(incoming_session).await;
            info!("Result: {:?}", result);
        }
    }

    mod frame_generator {
        use openh264::encoder::EncodedBitStream;
        use openh264::encoder::Encoder;
        use openh264::encoder::EncoderConfig;
        use openh264::formats::YUVBuffer;
        use openh264::OpenH264API;
        use std::f32::consts::PI;
        use std::time::Instant;
        use tiny_skia::Paint;
        use tiny_skia::Pixmap;
        use tiny_skia::Rect;
        use tiny_skia::Transform;

        pub struct FrameGenerator {
            width: u32,
            height: u32,
            time: Instant,
            encoder: Encoder,
        }

        impl FrameGenerator {
            pub fn new(width: u32, height: u32) -> Self {
                let time = Instant::now();
                let encoder = Encoder::with_config(
                    OpenH264API::from_source(),
                    EncoderConfig::new(width, height),
                )
                .unwrap();

                Self {
                    width,
                    height,
                    time,
                    encoder,
                }
            }

            pub fn next_frame(&mut self) -> Frame {
                let rgb = self.draw_frame();
                let yuv_buffer =
                    YUVBuffer::with_rgb(self.width as usize, self.height as usize, &rgb);

                let bitstream = self.encoder.encode(&yuv_buffer).unwrap();
                Frame::with_bitstream(bitstream)
            }

            fn draw_frame(&mut self) -> Box<[u8]> {
                const PERIOD: f32 = 10.0;

                let delta = self.time.elapsed();

                let size = std::cmp::min(self.width, self.height) as f32
                    * (delta.as_secs_f32() * PI / PERIOD).sin().abs();

                let rect = Rect::from_xywh(0.0, 0.0, size, size).unwrap();

                let mut paint = Paint::default();
                paint.set_color_rgba8(255, 0, 0, 255);

                let mut pixmap = Pixmap::new(self.width, self.height).unwrap();
                pixmap.fill_rect(rect, &paint, Transform::identity(), None);

                pixmap
                    .take()
                    .into_iter()
                    .enumerate()
                    .filter_map(|(index, pixel)| (((index + 1) % 4) != 0).then_some(pixel))
                    .collect()
            }
        }

        pub struct Frame(Box<[u8]>);

        impl Frame {
            fn with_bitstream(bitstream: EncodedBitStream) -> Self {
                Frame(bitstream.to_vec().into_boxed_slice())
            }
        }

        impl AsRef<[u8]> for Frame {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }
    }
}

mod http {
    use super::*;
    use axum::http::header::CONTENT_TYPE;
    use axum::response::Html;
    use axum::routing::get;
    use axum::serve;
    use axum::serve::Serve;
    use axum::Router;
    use std::net::Ipv4Addr;
    use std::net::SocketAddr;
    use tokio::net::TcpListener;
    use wtransport::tls::Sha256DigestFmt;

    pub struct HttpServer {
        serve: Serve<Router, Router>,
        local_port: u16,
    }

    impl HttpServer {
        const PORT: u16 = 8080;

        pub async fn new(cert_digest: &Sha256Digest, webtransport_port: u16) -> Result<Self> {
            let router = Self::build_router(cert_digest, webtransport_port);

            let listener =
                TcpListener::bind(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), Self::PORT))
                    .await
                    .context("Cannot bind TCP listener for HTTP server")?;

            let local_port = listener
                .local_addr()
                .context("Cannot get local port")?
                .port();

            Ok(HttpServer {
                serve: serve(listener, router),
                local_port,
            })
        }

        pub fn local_port(&self) -> u16 {
            self.local_port
        }

        pub async fn serve(self) -> Result<()> {
            info!("Server running on port {}", self.local_port());

            self.serve.await.context("HTTP server error")?;

            Ok(())
        }

        fn build_router(cert_digest: &Sha256Digest, webtransport_port: u16) -> Router {
            let cert_digest = cert_digest.fmt(Sha256DigestFmt::BytesArray);

            let root = move || async move { Html(http_data::INDEX_DATA) };

            let client = move || async move {
                (
                    [(CONTENT_TYPE, "application/javascript")],
                    http_data::CLIENT_DATA
                        .replace("${CERT_HASH}", &cert_digest)
                        .replace("${WT_PORT}", &webtransport_port.to_string()),
                )
            };

            Router::new()
                .route("/", get(root))
                .route("/client.js", get(client))
        }
    }
}

mod utils {
    use tracing_subscriber::filter::LevelFilter;
    use tracing_subscriber::EnvFilter;

    pub fn init_logging() {
        let env_filter = EnvFilter::builder()
            .with_default_directive(LevelFilter::INFO.into())
            .from_env_lossy();

        tracing_subscriber::fmt()
            .with_target(true)
            .with_level(true)
            .with_env_filter(env_filter)
            .init();
    }
}

mod http_data {

    pub const INDEX_DATA: &str = r#"

<!doctype html>
<html lang="en">
  <title>WTransport Example - Render</title>
  <meta charset="utf-8">
  <script type="text/javascript" src="client.js?2"></script>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <body>
    <h1>WTransport Example Render</h1>

    <div>
        <canvas id="canvas"></canvas>
    </div>

  </body>
</html>
"#;

    pub const CLIENT_DATA: &str = r#"
const CERT_HASH = new Uint8Array(${CERT_HASH});

async function run() {
    let videoDecoder = new VideoDecoder({
        output: handleDecodedFrame,
        error: err => { console.log(err); }
    });

    videoDecoder.configure({
        codec: "avc1.42E01E",
    });

    const url = "https://127.0.0.1:${WT_PORT}";

    console.log("WebTransport connecting...");
    let transport = new WebTransport(url, { serverCertificateHashes: [ { algorithm: "sha-256", value: CERT_HASH.buffer } ] } );

    await transport.ready;
    console.log("WebTransport connected");

    let streams = transport.incomingUnidirectionalStreams.getReader();

    while (true) {
        var { value, done } = await streams.read();

        if (done) {
            break;
        }

        var stream = value.getReader();

        var { value, done } = await stream.read();

        if (done) {
            break;
        }

        let encodedChunk = new EncodedVideoChunk({
            type: 'key',
            data: value,
            timestamp: performance.now(),
        });

        videoDecoder.decode(encodedChunk);
    }
}

function handleDecodedFrame(decodedFrame) {
    const canvasElement = document.getElementById('canvas');
    const ctx = canvasElement.getContext('2d');
    const width = decodedFrame.displayWidth;
    const height = decodedFrame.displayHeight;

    canvasElement.width = width;
    canvasElement.height = height;
    ctx.drawImage(decodedFrame, 0, 0);
    decodedFrame.close();
}

run();

"#;
}
